#!/usr/bin/env python3

import logging
import argparse
import ssl, select, socket, struct, random
from socksproxy import SocksProxy, pipe_sockets, str2ipport, mksocket
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
  pass
ThreadingTCPServer.allow_reuse_address = True


class ReTLS(SocksProxy):
  def remote_connect(self):
    logging.info(f'{self.id}: Connecting to remote {self.remote_domain}:{self.remote_port} via {self.remote_address}')
    with mksocket(args.via) as s:
      ssock = context.wrap_socket(s, server_hostname=self.remote_domain)
      ssock.connect((self.remote_address, self.remote_port))
      self.sdirect = ssock

  def handle_socks(self):
    logging.info(f'{self.id}: Socks5 connection established')
    pipe_sockets(self.sdirect, self.connection, logprefix=f"{self.id}: ")

  def cleanup(self):
    if self.sdirect:
      self.sdirect.close()


if __name__ == '__main__':
  logging.root.setLevel(logging.NOTSET)
  parser = argparse.ArgumentParser(description='socks plain to tls proxy', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument('-l', '--listen', type=str2ipport('127.0.0.1', 3666, False), help='IP:PORT to listen on', default='127.0.0.1:3666')
  parser.add_argument('-c', '--via', type=str2ipport(), help='IP:PORT of socks proxy to connect to, or "direct" for none', default='direct')
  args = parser.parse_args()
  context = ssl.create_default_context()
  with ThreadingTCPServer(args.listen, ReTLS) as server:
    server.serve_forever()
