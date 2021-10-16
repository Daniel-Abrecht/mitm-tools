#!/usr/bin/env python3

import logging
import argparse
import socket, struct, random
import ssl, threading, socks, ctypes
from socksproxy import SocksProxy, ThreadingTCPServer, pipe_sockets, str2ipport, setprocname
from tempfile import TemporaryFile
from OpenSSL import crypto
from contextlib import contextmanager
from socketserver import ThreadingMixIn, TCPServer


def readfile(file):
  with open(file,"rt") as f:
    return f.read()


class Cert:
  def __init__(self, cert, key):
    self.ref = 1
    self.cert = cert
    self.key = key
    with TemporaryFile(mode='w+b') as chain_file:
      chain_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
      chain_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
      chain_file.flush()
      chain_fd_path = '/proc/self/fd/'+str(chain_file.fileno())
      context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
      context.load_verify_locations(CA.ca_cert_path);
      context.load_cert_chain(chain_fd_path)
      self.context = context


class CertGen:
  def __init__(self, ca_cert, ca_key):
    self.certs = {}
    self.ca_cert_path = ca_cert
    self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, readfile(ca_cert))
    self.ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, readfile(ca_key))

  @contextmanager
  def get(self, name):
    try:
      ex = self.certs.get(name)
      if ex:
        ex.ref += 1
        yield ex
      else:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(random.randint(50000000,100000000))

        cert.get_subject().commonName = name

        cert.add_extensions([
          crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
          crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
        ])

        cert.add_extensions([
          crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=self.ca_cert),
          crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
          crypto.X509Extension(b"keyUsage", False, b"digitalSignature"),
        ])

        cert.set_issuer(self.ca_cert.get_subject())
        cert.set_pubkey(key)

        cert.gmtime_adj_notBefore(-24*60*60)
        cert.gmtime_adj_notAfter(7*24*60*60)

        cert.sign(self.ca_key, 'sha256')

        c = Cert(cert, key)
        self.certs[name] = c
        yield c
    finally:
      ex = self.certs[name]
      ex.ref -= 1
      # TODO: Add the below to a timer, and add an expiry date check
      #if ex.ref <= 0:
      #  del self.certs[name]


def kill_thread(thread):
    thread_id = thread.ident
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, ctypes.py_object(SystemExit))
    if res > 1:
      ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
      logging.error('Exception raise failure')


class TLSStripper(SocksProxy):
  data = b''

  def crecv(self, l):
    assert len(self.data) + l < 1024 * 10 # Arbitrary limit, if we have to read more than 10K, something's probably off
    res = self.connection.recv(l)
    self.data += res
    return res

  def remote_connect(self):
    self.sdirect = None
    logging.info(f'{self.id}: Connecting to remote {self.remote_address} :{self.remote_port}')
    # Note: This is for non-mitm-ed / direct connections. We do this early, so we can refuse connections early too.
    s = self.mksocket(args.via)
    self.rconnect(s, args.via)
    self.sdirect = s

  def handle_socks(self):
    logging.info(f'{self.id}: Socks5 connection established')
    try:

      # TLSPlaintext
      ptype = ord(self.crecv(1))
      assert ptype == 22 # TLSPlaintext::type == ContentType::handshake
      struct.unpack("!H", self.crecv(2)) # TLSPlaintext::legacy_record_version. Per spec: field is deprecated and MUST be ignored for all purposes
      plength, = struct.unpack("!H", self.crecv(2)) # TLSPlaintext::length. Only includes following bytes.
      assert plength <= 2**24 # Per spec: The length MUST NOT exceed 2^14 bytes.
      assert plength >= 54 # Impossible to be shorter

      # Handshake
      htype = ord(self.crecv(1))
      assert htype == 1 # Handshake::type == HandshakeType::client_hello
      hlength, = struct.unpack("!I", b'\0' + self.crecv(3)) # Handshake::length, remaining bytes in message
      assert hlength <= plength-4 # Handshake::type and Handshake::length are 4 bytes, so Handshake data must be at least 4 bytes smaller than fragment data
      assert hlength >= 50 # Impossible to be shorter

      # ClientHello
      vversion, = struct.unpack("!H", self.crecv(2))
      assert vversion == 0x0303 # ClientHello::version == TLS v1.2. Should also cover newer versions, since this field was deprecated for better backwards compat
      self.crecv(32) # ClientHello::random
      sid_len = ord(self.crecv(1))
      assert sid_len <= 32
      hlength -= 35 + sid_len + 2
      assert hlength >= 13 # Impossible to be shorter
      if sid_len:
        self.crecv(sid_len)
      vsciphersuite_len, = struct.unpack("!H", self.crecv(2))
      hlength -= vsciphersuite_len + 1
      assert hlength >= 12 # Impossible to be shorter
      if vsciphersuite_len:
        self.crecv(vsciphersuite_len)
      vcompression_method_len = ord(self.crecv(1))
      hlength -= vcompression_method_len + 2
      assert hlength >= 10 # Impossible to be shorter
      if vcompression_method_len:
        self.crecv(vcompression_method_len)

      # Extensions, this is what we're looking for
      ext_len, = struct.unpack("!H", self.crecv(2))
      assert hlength >= ext_len # Impossible to be shorter
      sni=b''
      while ext_len > 0:
        ext_len -= 4
        assert ext_len >= 0
        etype, elength = struct.unpack("!HH", self.crecv(4))
        ext_len -= elength
        assert ext_len >= 0 # Impossible to be shorter
        buf = self.crecv(elength)
        off = 0
        if etype == 0: # Extension::type == ExtensionType::server_name
          sllen, = struct.unpack("!H", buf[off:off+2])
          off += 2
          while sllen > 0:
            stype = ord(buf[off:off+1])
            off += 1
            slen, = struct.unpack("!H", buf[off:off+2])
            off += 2
            if slen == 0:
              continue
            name = buf[off:off+slen]
            off += slen
            if stype == 0: # ServerName::name_type, 0 = host_name
              sni = name
              break
            name = None
          break
      assert sni
      sni = sni.decode()

    except:
      logging.info(f'{self.id}: Couldn\'t extract SNI, assuming plain connection')
      pipe_sockets(self.sdirect, self.connection, self.data, logprefix=f'{self.id}: client <=> remote: ')
      self.data = None
      return

    logging.info(f'{self.id}: Got SNI: {sni}')

    self.sdirect.close()

    # Create certificate
    with CA.get(sni) as crt:
      sa, sb = socket.socketpair()
      try:
        t1 = threading.Thread(target=pipe_sockets, args=(sa, self.connection, self.data, None, f'{self.id}: client <=> mitm ssl in: '))
        self.data = None
        t1.daemon = True
        t1.start()
        with crt.context.wrap_socket(sb, server_side=True) as ssock:
          s = self.mksocket(args.tls_via)
          self.rconnect(s, args.via, sni)
          pipe_sockets(s, ssock, logprefix=f'{self.id}: mitm decrypted out <=> remote: ')
      finally:
        sb.close()
        if t1:
          kill_thread(t1)
        sa.close()

  def cleanup(self):
    if self.sdirect:
      self.sdirect.close()


if __name__ == '__main__':
  logging.root.setLevel(logging.NOTSET)
  setprocname(__file__)
  parser = argparse.ArgumentParser(description='socks plain to tls proxy', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument('-l', '--listen', type=str2ipport('0.0.0.0',1666, False), help='IP:PORT to listen on', default='0.0.0.0:1666')
  parser.add_argument('-c', '--via', type=str2ipport(), help='IP:PORT of socks proxy to connect to for undecryptable traffic, or "direct" for none', default='127.0.0.1:2666')
  parser.add_argument('-t', '--tls-via', type=str2ipport(), help='IP:PORT of socks proxy to connect to for decrypted traffic', default='127.0.0.1:3666')
  parser.add_argument('--ca', default="/etc/ssl/CA/CA.pem")
  parser.add_argument('--ca-key', default="/etc/ssl/CA/CA.key")
  args = parser.parse_args()
  CA = CertGen(args.ca, args.ca_key)
  with ThreadingTCPServer(args.listen, TLSStripper) as server:
    server.serve_forever()
