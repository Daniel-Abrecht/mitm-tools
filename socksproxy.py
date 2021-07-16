#!/usr/bin/env python3

import logging
import ctypes, os, sys, errno
import traceback, argparse
import select, socket, socks, struct, random
import ssl
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler


SOCKS_VERSION = 5
SO_ORIGINAL_DST = 80


def setprocname(file):
  name = os.path.basename(file)
  ctypes.CDLL(None).prctl(15, name.encode(), 0, 0, 0)


def str2ipport(addr=None, dport=None, ad=True):
  def parse(s):
    if s == 'direct':
      if not ad:
        raise argparse.ArgumentTypeError("mode 'direct' not valid for this parameter")
      return None
    ipport = s.rsplit(':',1)
    if len(ipport) != 2:
      if ipport[0].isnumeric():
        if not addr:
          raise argparse.ArgumentTypeError("address required")
        return (addr, int(ipport[0]))
      else:
        if not dport:
          raise argparse.ArgumentTypeError("port required")
        return (ipport[0], dport)
    if not ipport[1].isnumeric():
      raise argparse.ArgumentTypeError("invalid port")
    return (ipport[0],int(ipport[1]))
  return parse

def mksocket(via):
  if not via:
    return socket.socket()
  else:
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, via[0], via[1])
    return s

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
  pass
ThreadingTCPServer.allow_reuse_address = True


class SocksProxy(StreamRequestHandler):
  def rconnect(self, s, via):
    if not via or self.remote_address == self.remote_domain:
      s.connect((self.remote_address, self.remote_port))
    else:
      s.connect((self.remote_domain+'>'+self.remote_address, self.remote_port))

  def handle(self):
    self.sdirect = None
    SocksProxy.id = SocksProxy.id + 1
    self.id = SocksProxy.id
    self.logger = logging.getLogger(f's{self.id}')
    self.logger.info(f'Accepting connection from {self.client_address[0]}:{self.client_address[1]}')

    transparent = False
    try:
      # Currently only dealing with IPv4
      sockaddr_in = self.connection.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
      (proto, port) = struct.unpack('!HH', sockaddr_in[:4])
      assert proto == 512
      self.remote_address = socket.inet_ntoa(sockaddr_in[4:8])
      self.remote_port = port
      (draddr,drport) = self.connection.getsockname()
      assert draddr != self.remote_address ## If original destination was the same as packet destination, probably no transparent proxying using iptables
      transparent = True
    except:
      pass

    if transparent:
      assert self.remote_address
      try:
        self.remote_connect()
        self.handle_socks()
      except:
        # If an error occured, reset the conection instead of just closing it
        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        raise
      finally:
        self.cleanup()
        self.logger.info(f'done')
      return

    header = self.connection.recv(2)
    version, nmethods = struct.unpack("!BB", header)
    assert version == SOCKS_VERSION
    assert nmethods > 0
    methods = [ord(self.connection.recv(1)) for i in range(nmethods)]
    assert 0 in methods
    self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0))

    version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
    assert version == SOCKS_VERSION
    assert cmd == 1 # Only allow connect

    if address_type == 1:  # ipv4
      rawaddr = self.connection.recv(4)
      self.remote_address = socket.inet_ntoa(rawaddr)
    elif address_type == 3:  # domain
      rawaddr = self.connection.recv(1)
      domain_length = ord(rawaddr)
      self.remote_address = self.connection.recv(domain_length)
      rawaddr = rawaddr + self.remote_address
      self.remote_address = self.remote_address.decode()
    self.remote_port = struct.unpack('!H', self.connection.recv(2))[0]

    res = self.remote_address.split('>', 1)
    if len(res) == 2:
      self.remote_address = res[1]
      self.remote_domain = res[0]
    else:
      self.remote_domain = self.remote_address
    res = None

    assert self.remote_address

    try:
      try:
        self.remote_connect()
        reply = struct.pack("!BBBB", SOCKS_VERSION, 0, 0, address_type) + rawaddr + struct.pack("!H", self.remote_port)
      except:
        reply = struct.pack("!BBBBIH", SOCKS_VERSION, 5, 0, address_type, 0, 0)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        self.logger.error(f"{exc_value}");
      self.connection.sendall(reply)
      if reply[1] != 0:
        return
      try:
        self.handle_socks()
      except:
        # If an error occured, reset the conection instead of just closing it
        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        raise
    finally:
      self.cleanup()
      self.logger.info(f'done')
SocksProxy.id = 0


def pipe_sockets(sa, sb, b2a_buf=None, a2b_buf=None, logprefix='', logger=logging):
  logger.info(f"{logprefix}pipe_sockets started")
  try:
    sa.setblocking(False)
    sb.setblocking(False)
    a2b = True
    b2a = True
    if a2b_buf is None:
      a2b_buf = b''
    if b2a_buf is None:
      b2a_buf = b''
    while a2b or b2a:
      rsl = set()
      if a2b and len(a2b_buf) == 0: rsl.add(sa)
      if b2a and len(b2a_buf) == 0: rsl.add(sb)
      wsl = set()
      if len(a2b_buf) != 0: wsl.add(sb)
      if len(b2a_buf) != 0: wsl.add(sa)
      pending = set()
      if hasattr(sa, 'pending') and sa in rsl and sa.pending():
        pending.add(sa)
      if hasattr(sb, 'pending') and sb in rsl and sb.pending():
        pending.add(sb)
      rs, ws, es = select.select(rsl, wsl, [], 0 if len(pending) != 0 else None)
      rs = {*rs, *pending}
      ws = {*ws}
      if len(es):
        break
      if sa in rs:
        try:
          a2b_buf = sa.recv(16 * 4096)
        except ssl.SSLWantReadError: pass
        except ssl.SSLWantWriteError: pass
        except OSError as e:
          no = e.args[0]
          if no != errno.EAGAIN and no != errno.EWOULDBLOCK:
            raise
          logger.info(f"{logprefix}pipe_sockets sa -> sb expected data, but there was none")
        else:
          if len(a2b_buf) == 0:
            a2b = False
            logger.info(f"{logprefix}pipe_sockets sa -> sb EOF")
            try:
              sb.shutdown(socket.SHUT_WR)
            except OSError as error:
              pass
      if sb in rs:
        try:
          b2a_buf = sb.recv(16 * 4096)
        except ssl.SSLWantReadError: pass
        except ssl.SSLWantWriteError: pass
        except OSError as e:
          no = e.args[0]
          if no != errno.EAGAIN and no != errno.EWOULDBLOCK:
            raise
          logger.info(f"{logprefix}pipe_sockets sb -> sa expected data, but there was none")
        else:
          if len(b2a_buf) == 0:
            b2a = False
            logger.info(f"{logprefix}pipe_sockets sb -> sa EOF")
            try:
              sa.shutdown(socket.SHUT_WR)
            except OSError as error:
              pass
      if len(a2b_buf) != 0 and sb in ws:
        try:
          nbytes = sb.send(a2b_buf)
        except ssl.SSLWantReadError: pass
        except ssl.SSLWantWriteError: pass
        except OSError as e:
          no = e.args[0]
          if no != errno.EAGAIN and no != errno.EWOULDBLOCK:
            raise
        else:
          if nbytes > 0:
            a2b_buf = a2b_buf[nbytes:]
      if len(b2a_buf) != 0 and sa in ws:
        try:
          nbytes = sa.send(b2a_buf)
        except ssl.SSLWantReadError: pass
        except ssl.SSLWantWriteError: pass
        except OSError as e:
          no = e.args[0]
          if no != errno.EAGAIN and no != errno.EWOULDBLOCK:
            raise
        else:
          if nbytes > 0:
            b2a_buf = b2a_buf[nbytes:]
  #except OSError as e: pass
  finally:
    try:
      sa.close()
    except: pass
    try:
      sb.close()
    except: pass
    logger.info(f"{logprefix}pipe_sockets done")


class Transparent(SocksProxy):
  def remote_connect(self):
    self.logger.info(f'{self.id}: Connecting to remote {self.remote_address}:{self.remote_port}')
    s = mksocket(args.via)
    self.rconnect(s, args.via)
    self.sdirect = s

  def handle_socks(self):
    self.logger.info(f'{self.id}: Socks5 connection established')
    pipe_sockets(self.sdirect, self.connection, logger=self.logger)

  def cleanup(self):
    if self.sdirect:
      self.sdirect.close()


if __name__ == '__main__':
  logging.root.setLevel(logging.NOTSET)
  setprocname(__file__)
  parser = argparse.ArgumentParser(description='socks plain to tls proxy', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument('-l', '--listen', type=str2ipport('127.0.0.1', 2666, False), help='IP:PORT to listen on', default='127.0.0.1:2666')
  parser.add_argument('-c', '--via', type=str2ipport(), help='IP:PORT of socks proxy to connect to, or "direct" for none', default='direct')
  args = parser.parse_args()
  with ThreadingTCPServer(args.listen, Transparent) as server:
    server.serve_forever()
