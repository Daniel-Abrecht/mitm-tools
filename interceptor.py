#!/usr/bin/env python3

import re
import bisect
import logging
import asyncio
import os, sys, signal, argparse, traceback
import ssl, select, socket, struct, random
from functools import total_ordering
from socksproxy import SocksProxy, pipe_sockets, str2ipport, mksocket, setprocname
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from importlib.machinery import SourceFileLoader

R32 = 0xFFFFFFFF
ARBITRARY_BUFFER_LIMIT = 1024 * 10 # 10 KiB

config = {}
mods = {}

root = os.path.dirname(os.path.realpath(__file__))

def reload_mods():
  global mods
  moddir = os.path.join(root, "interceptor")
  mods = {}
  for mod in os.listdir(moddir):
    if not mod.endswith('.py'):
      continue
    try:
      logging.info('Trying to load interceptor "'+mod[:-3]+'"...');
      m = SourceFileLoader('interceptor.'+mod[:-3], os.path.join(moddir, mod)).load_module()
      m.I = sys.modules[__name__]
      m.init()
      mods[mod[:-3]] = m
      logging.info('Interceptor "'+mod[:-3]+'" loaded');
    except:
      traceback.print_exc()


def reload_all():
  reload_mods()

def sighup(a,b):
  reload_all()

@total_ordering
class ReadJob:
  def __init__(self, min, SP):
    self.future = asyncio.get_event_loop().create_future()
    self.min = min & R32
    self.SP = SP

  def __lt__(self, other):
    offset = self.SP.offset
    return ((self.min - offset) & R32) < ((other.min - offset) & R32)

  def __eq__(self, other):
    offset = self.SP.offset
    return self.min == other.min


class ProtocolValidationException(Exception):
  pass

class MismatchException(ProtocolValidationException):
  pass

class ShadowProcessor:
  def __init__(self, I, socket):
    self.EOF = False
    self.data = b'';
    self.offset = 0 # Offset of start of data in a 32bit unsigned integer ring
    self.socket = socket
    self.parsejobs = []
    self.I = I
    self.to_be_sent = b''
    self.recv_waiting = asyncio.get_event_loop().create_future()
    self.D = None

  def send_ready(self):
    return len(self.to_be_sent)

  def flush_some(self):
    if len(self.to_be_sent) == 0:
      return
    nbytes = self.socket.send(self.to_be_sent)
    if nbytes > 0:
      self.to_be_sent = self.to_be_sent[nbytes:]
      if len(self.to_be_sent) == 0:
        self.to_be_sent = b''

  # Stuff needed before any data manipulation
  def pre_flush(self):
    assert len(self.I.PIs) == 1 and next(iter(self.I.PIs)).matched
    SPW = self.get_all_wrappers()[0]
    assert not SPW.transparent
    diff = (SPW.replied - SPW.consumed) & R32
    if diff < 0x80000000:
      SPW.consume(SPW.consumed + diff)
    self.move_stuff_to_reply_queue()
    return SPW

  def discard(self, o):
    SPW = self.pre_flush()
    diff = (self.offset - o) & R32
    self.data = self.data[diff:]
    self.offset = o
    diff = (o - SPW.consumed) & R32
    if diff < 0x80000000:
      SPW.consume(SPW.consumed + diff)

  def send(self, buf):
    self.D.pre_flush()
    self.to_be_sent += buf

  def recv_ready(self):
    return not self.EOF and (len(self.data) == 0 or len(self.parsejobs) != 0) and len(self.I.PIs) != 0

  def get_all_wrappers(self):
    if len(self.I.PIs) == 0:
      return []
    any_PI = next(iter(self.I.PIs))
    if any_PI.S.SP == self:
      return [PI.S for PI in self.I.PIs]
    elif any_PI.C.SP == self:
      return [PI.C for PI in self.I.PIs]
    else:
      raise Exception("Invalid ShadowProcessor")

  def move_stuff_to_reply_queue(self):
    offset = self.offset
    replied_min  = min(((x.replied  - offset) & R32 for x in self.get_all_wrappers()), default=0)
    consumed_min = min(((x.consumed - offset) & R32 for x in self.get_all_wrappers()), default=0)
    replyable = min(replied_min, consumed_min)
    self.D.to_be_sent += self.data[0:replyable]
    self.data = self.data[replyable:]
    if len(self.data) == 0:
      self.data = b''
    self.offset = (offset + replyable) & R32

  def recv(self):
    assert len(self.data) < ARBITRARY_BUFFER_LIMIT, len(self.data)
    res = self.socket.recv(4096)
    if len(res) == 0:
      self.EOF = True
      self.I.logger.info('C->S EOF' if self.socket == self.I.C.socket else 'S->C EOF')
      jobs = self.parsejobs
      self.parsejobs = None
      for job in jobs:
        job.queued = False
        job.future.cancel()
      for W in self.get_all_wrappers():
        try:
          W.onEOF()
        except:
          traceback.print_exc()
    else:
      self.data += res
      n = len(self.data)
      while len(self.parsejobs):
        job = self.parsejobs[0]
        if ((job.min - self.offset) & R32) > n:
          break
        del self.parsejobs[0]
        job.queued = False
        job.future.set_result(None)
      if len(self.parsejobs) == 0:
        self.recv_waiting = asyncio.get_event_loop().create_future()

  async def read(self, o, mi, ma):
    assert mi <= ma
    if ((o - self.offset) & R32) + mi > len(self.data):
      assert ((o - self.offset) & R32) + mi < ARBITRARY_BUFFER_LIMIT, "0x%0.8X + 0x%x" % ( ((o - self.offset) & R32), mi )
      assert not self.EOF
      job = ReadJob(o+mi, self)
      bisect.insort(self.parsejobs, job)
      job.queued = True
      if not self.recv_waiting.done():
        self.recv_waiting.set_result(None)
      try:
        await job.future
      finally:
        if self.parsejobs is not None and job.queued:
          self.parsejobs.remove(job)
          job.queued = False
    o = (o - self.offset) & R32
    end = min(len(self.data), o+ma)
    assert o < end, '0x%0.8X < 0x%X' % (o, end)
    assert end >= mi, f'{mi} >= {end}'
    return self.data[o:end]

  def validate_silence(self):
    if not self.data:
      return
    for W in self.get_all_wrappers():
      if not W.silence_expected:
        continue
      if len(self.data) - ((W.consumed - self.offset) & R32) != 0:
        W.PI.logger.debug(f'got data while expecting silence')
        W.PI.cancel()


def ellide(s, n=20):
  if n < 3: n = 3
  if len(s) <= n:
    return s
  return s[0:n-3] + (b'...' if isinstance(s, bytes) else '...')

class ShadowProcessorWrapper:
  def __init__(self, SP, PI):
    self.SP = SP
    self.PI = PI
    self.I = PI.I
    self.transparent = False
    # The following 2 variables are always clamped to a 32 unsigned integer ring range
    self.consumed = self.SP.offset # Data before this offset won't be read anymore
    self.replied  = self.SP.offset # Data before this offset can be replied or has already been discarded. Offset can be smaller than self.consumed!
    self.onEOF = self.PI.cancel
    self.silence_expected = True

  def expect_silence(self, silent):
    self.silence_expected = silent

  def discard(self, o):
    self.SP.discard(o)
    self.replied = o & R32

  def send(self, buf):
    self.SP.send(buf)

  def reply(self, o):
    if o <= self.replied:
      return
    assert ((o - self.replied) & R32) < ARBITRARY_BUFFER_LIMIT, "0x%0.8X" % ((o - self.replied) & R32)
    self.replied = o & R32

  def consume(self, o):
    assert ((o - self.consumed) & R32) < ARBITRARY_BUFFER_LIMIT, "0x%0.8X" % ((o - self.consumed) & R32)
    self.PI.logger.debug(('consume', self.consumed, ((o - self.consumed) & R32), ellide(self.SP.data[(self.consumed-self.SP.offset)&R32:(o-self.SP.offset)&R32]), ellide(self.SP.data[(o-self.SP.offset)&R32:])))
    self.consumed = o & R32
    if self.transparent:
      self.reply(o)

  def setTransparent(self, transparent):
    self.transparent = transparent
    if transparent:
      diff = (self.consumed - self.replied) & R32
      if diff >= 0x80000000:
        return
      self.reply(self.replied + diff)

  async def read(self, o, mi, ma, consume=True):
    ret = await self.SP.read(o, mi, ma)
    end = o + len(ret)
    if consume:
      self.consume(end)
    return ret

  async def match(self, o, search, max=None, min=None, consume=True):
    if isinstance(search, bytes):
      if max is None:
        max = len(search)
      sstr = search
      search = lambda x, i: x == sstr[i]
    if min is None:
      min = max
    i = 0
    rmi = min
    buf = b''
    while i < max:
      buf += await self.read(o + i, rmi - i, max, consume=False)
      while i < len(buf):
        if not search(buf[i], i):
          if i < min:
            raise MismatchException()
          if consume:
            self.consume(o + i)
          return o + i, buf[0:i]
        i += 1
      rmi = i + 1
      if consume:
        self.consume(o + i)
    return (o + i) & R32, buf[0:i]

  async def match_CRLF(self, o):
    o, _  = await self.match(o, lambda x, i: x == 13 or x == 10, max=1)
    if _ == b'\r':
      o, _ = await self.match(o, b'\n')
    return o


class ProtocolInterceptor:
  def __init__(self, name, mod, S, C, I, logger=logging):
    self.name = name
    self.mod = mod
    self.I = I
    self.S = ShadowProcessorWrapper(S, self)
    self.C = ShadowProcessorWrapper(C, self)
    self.future = None
    self.logger = logger
    self.matched = False

  def identified(self):
    if self.matched:
      return
    self.logger.info("MATCH")
    self.matched = True
    for PI in self.I.PIs:
      if PI != self:
        PI.cancel()

  def protocol_changed(self, name=None):
    assert self.matched
    for PI in self.I.PIs:
      if PI != self:
        PI.cancel()
    self.start_interceptors(name=name)
    self.cancel()

  def intercept(self):
    def remove():
      self.I.PIs.remove(self)
    async def waiter():
      try:
        try:
          await self.mod.intercept(self, self.C, self.S)
        finally:
          remove()
          self.logger.info("DONE")
      except asyncio.CancelledError:
        pass
      except (ProtocolValidationException, AssertionError):
        if self.matched:
          traceback.print_exc()
      except:
        traceback.print_exc()
    self.future = asyncio.ensure_future(waiter())
    self.I.PIs.add(self)

  def cancel(self):
    self.logger.debug("cancel")
    if self.future and not self.future.done():
      self.future.cancel()

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
  pass
ThreadingTCPServer.allow_reuse_address = True

class Interceptor(SocksProxy):
  def remote_connect(self):
    self.logger.info(f'Connecting to remote {self.remote_domain}:{self.remote_port} via {self.remote_address}')
    s = mksocket(args.via)
    self.rconnect(s, args.via)
    self.sdirect = s

  async def process_stuff(self, S,C):
    while True:
      rsl = set()
      wsl = set()
      if not S.send_ready() and not C.send_ready():
        wait_list = [self.PIs_done]
        if not S.EOF: wait_list.append(S.recv_waiting)
        if not C.EOF: wait_list.append(C.recv_waiting)
        await asyncio.wait(wait_list, return_when=asyncio.FIRST_COMPLETED);
        S.move_stuff_to_reply_queue()
        C.move_stuff_to_reply_queue()
        if self.PIs_done.done() and not S.send_ready() and not C.send_ready():
          # All protocol interceptors exited. They won't need any data anymore. We're done.
          break
      # There should be at least one protocol interceptor which is waiting for data
      if S.recv_ready() and not C.send_ready():
        rsl.add(S.socket)
      if C.recv_ready() and not S.send_ready():
        rsl.add(C.socket)
      if S.send_ready():
        wsl.add(S.socket)
      if C.send_ready():
        wsl.add(C.socket)
      if len(rsl) == 0 and len(wsl) == 0:
        # We can't get any data anymore. We probably got EOF from all connections. We're done
        break
#      print(3, [s.fileno() for s in rsl], [s.fileno() for s in wsl], S.recv_ready(), S.send_ready());
      # Wait for new data. .recv() will also process the data by fulfilling all completed futures
      rs, ws, es = select.select(rsl, wsl, [])
#      print(4, [s.fileno() for s in rs], [s.fileno() for s in ws]);
      if S.socket in rs:
        S.recv()
      if C.socket in rs:
        C.recv()
      if S.socket in ws:
        S.flush_some()
      if C.socket in ws:
        C.flush_some()
      C.validate_silence()
      S.validate_silence()

    self.logger.info("Done with connection, can't intercept anything else here")
    # Cancel any remaining protocol interceptors. There shouldn't be any, but just in case...
    for PI in self.PIs:
      PI.cancel()

  def start_interceptors(self, fname=None):
    for name, mod in mods.items():
      if fname is not None:
        if fname != name:
          continue
      pi = ProtocolInterceptor(name, mod, self.S, self.C, self, logger=logging.getLogger(f's{self.id}:{name}'))
      pi.intercept()
    self.PIs_done = asyncio.ensure_future(asyncio.wait([PI.future for PI in self.PIs]))

  def handle_socks(self):
    self.logger.info(f'Socks5 connection established')
    self.quit = False
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    self.S = S = ShadowProcessor(self, self.sdirect)
    self.C = C = ShadowProcessor(self, self.connection)
    S.D = C
    C.D = S
    self.PIs = set()
    self.start_interceptors()
    loop.run_until_complete(self.process_stuff(S, C))
    loop.close()
    toS = S.to_be_sent + C.data
    toC = C.to_be_sent + S.data
    C.data = b''
    S.data = b''
    if not self.quit:
      pipe_sockets(S.socket, C.socket, toS, toC, logger=self.logger)

  def cleanup(self):
    if self.sdirect:
      self.sdirect.close()


if __name__ == '__main__':
  logging.root.setLevel(logging.NOTSET if os.environ.get('DEBUG') is not None else logging.INFO)
  setprocname(__file__)
  parser = argparse.ArgumentParser(description='socks <=> socks proxy for live traffic introspection, interception & manipulation', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument('-l', '--listen', type=str2ipport(ad=False), help='IP:PORT to listen on', required=True)
  parser.add_argument('-c', '--via', type=str2ipport(), help='IP:PORT of socks proxy to connect to, or "direct" for none', required=True)
  reload_all();
  signal.signal(signal.SIGHUP, sighup)
  args = parser.parse_args()
  with ThreadingTCPServer(args.listen, Interceptor) as server:
    server.serve_forever()
