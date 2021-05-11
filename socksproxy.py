#!/usr/local/bin/logenv python3

import logging
import traceback
import select, socket, struct, random
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler


SOCKS_VERSION = 5
SO_ORIGINAL_DST = 80


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
  pass
ThreadingTCPServer.allow_reuse_address = True


class SocksProxy(StreamRequestHandler):
  def handle(self):
    self.sdirect = None
    SocksProxy.id = SocksProxy.id + 1
    self.id = SocksProxy.id
    logging.info(f'{self.id}: Accepting connection from {self.client_address[0]}:{self.client_address[1]}')

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
      self.remote_connect()
      self.handle_socks()
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

    res = self.remote_address.split('>', 2)
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
        traceback.print_exc()
      self.connection.sendall(reply)
      if reply[1] != 0:
        return
      self.handle_socks()
    finally:
      self.cleanup()
SocksProxy.id = 0


def pipe_sockets(sa, sb, b2a_buf=None, a2b_buf=None, logprefix=''):
  logging.info(f"{logprefix}pipe_sockets started")
  try:
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
      rs, ws, es = select.select(rsl, wsl, [])
      if len(es):
        logging.info()
        break
      if sa in rs:
        a2b_buf = sa.recv(16 * 4096)
        if len(a2b_buf) == 0:
          a2b = False
          logging.info(f"{logprefix}pipe_sockets sa -> sb EOF")
          sb.shutdown(socket.SHUT_WR)
      if sb in rs:
        b2a_buf = sb.recv(16 * 4096)
        if len(b2a_buf) == 0:
          b2a = False
          logging.info(f"{logprefix}pipe_sockets sb -> sa EOF")
          sa.shutdown(socket.SHUT_WR)
      if len(a2b_buf) != 0 and sb in ws:
        nbytes = sb.send(a2b_buf)
        if nbytes > 0:
          a2b_buf = a2b_buf[nbytes:]
      if len(b2a_buf) != 0 and sa in ws:
        nbytes = sa.send(b2a_buf)
        if nbytes > 0:
          b2a_buf = b2a_buf[nbytes:]
  finally:
    sa.close()
    sb.close()
    logging.info(f"{logprefix}pipe_sockets done")


class Transparent(SocksProxy):
  def remote_connect(self):
    logging.info(f'{self.id}: Connecting to remote {self.remote_address}:{self.remote_port}')
    s = socket.socket()
    s.connect((self.remote_address, self.remote_port))
    self.sdirect = s

  def handle_socks(self):
    logging.info(f'{self.id}: Socks5 connection established')
    pipe_sockets(self.sdirect, self.connection, logprefix=f"{self.id}: ")

  def cleanup(self):
    if self.sdirect:
      self.sdirect.close()


if __name__ == '__main__':
  logging.root.setLevel(logging.NOTSET)
  with ThreadingTCPServer(('127.0.0.1', 2666), Transparent) as server:
    server.serve_forever()
