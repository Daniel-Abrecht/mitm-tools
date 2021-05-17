#!/usr/bin/env python3

import logging
import argparse
import ssl, select, socket, struct, random
from socksproxy import SocksProxy, pipe_sockets, str2ipport, mksocket, setprocname
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
  pass
ThreadingTCPServer.allow_reuse_address = True


class ReTLS(SocksProxy):
  def remote_connect(self):
    self.logger.info(f'Connecting to remote {self.remote_domain}:{self.remote_port} via {self.remote_address}')
    with mksocket(args.via) as s:
      ssock = context.wrap_socket(s, server_hostname=self.remote_domain)
      self.rconnect(ssock, args.via)
      self.sdirect = ssock

  def handle_socks(self):
    self.logger.info(f'Socks5 connection established')
    pipe_sockets(self.sdirect, self.connection, logger=self.logger)

  def cleanup(self):
    if self.sdirect:
      self.sdirect.close()


if __name__ == '__main__':
  logging.root.setLevel(logging.NOTSET)
  setprocname(__file__)
  parser = argparse.ArgumentParser(description='socks plain to tls proxy', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument('-l', '--listen', type=str2ipport('127.0.0.1', 3666, False), help='IP:PORT to listen on', default='127.0.0.1:3666')
  parser.add_argument('-c', '--via', type=str2ipport(), help='IP:PORT of socks proxy to connect to, or "direct" for none', default='direct')
  args = parser.parse_args()
  context = ssl.create_default_context()
  with ThreadingTCPServer(args.listen, ReTLS) as server:
    server.serve_forever()
