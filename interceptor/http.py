import json, re
import zlib, brotli
import os, subprocess, traceback
from async_generator import aclosing

data_processor = None

def init():
  global data_processor
  data_processor = os.path.join(I.root, 'save_http_files.sh')

async def parse_first_request_line(self, o, C):
  o, method   = await C.match(o, lambda x, i: 65<=x<=90, min=3, max=10) # A-Z
  o, _        = await C.match(o, b' ')
  o, location = await C.match(o, lambda x, i: 33<=x<=126, min=1, max=2048) # Any printable ascii character, excluding space
  o, _        = await C.match(o, b' HTTP/1.')
  o, version  = await C.match(o, lambda x, i: x == 48 or x == 49, max=1) # 0 or 1
  o           = await C.match_CRLF(o)
  return o, method, location, b'HTTP/1.' + version

async def parse_response_line(self, o, S):
  o, _        = await S.match(o, b'HTTP/1.')
  o, version  = await S.match(o, lambda x, i: x == 48 or x == 49, max=1) # 0 or 1
  o, _        = await S.match(o, b' ')
  o, code     = await S.match(o, lambda x, i: 48<=x<=57, min=1, max=3) # 0-9
  o, _        = await S.match(o, b' ')
  o, location = await S.match(o, lambda x, i: 32<=x<=126, min=0, max=2048) # Any printable ascii character
  o           = await S.match_CRLF(o)
  return o, b'HTTP/1.' + version, int(code), location

async def parse_header(self, o, X):
  header_value = None
  while True:
    c = await X.read(o, 1, 1, consume=False); o += 1
    if c == b' ':
      X.consume(o)
      assert header_value is not None
      o, header_value_continuation = await X.match(o, lambda x, i: 32<=x<=126, min=1, max=1024 * 8 - len(header_value))
      header_value += header_value_continuation
      header_value_continuation = None
      o = await X.match_CRLF(o)
      continue
    if header_value is not None:
      header_value = header_value.strip()
      if header_value[0] == b'"'[0] and header_value[-1] == b'"'[0]:
        header_value = json.loads(header_value)
      return o-1, (header_name, header_value)
    X.consume(o)
    if c == b'\r':
      o, _ = await X.match(o, b'\n')
      return o, None
    if c == b'\n':
      return o, None
    assert 33<=c[0]<=126
    o, header_name = await X.match(o, lambda x, i: 33<=x<=126 and x != 58, min=1, max=255)
    header_name = c + header_name
    o, _ = await X.match(o, b':')
    o, header_value = await X.match(o, lambda x, i: 32<=x<=126, min=1, max=1024 * 8)
    o = await X.match_CRLF(o)

async def read_content_length(self, X, o, remaining):
  while remaining > 0:
    chunk_size = min(remaining, 4096)
    chunk = await X.read(o[0], chunk_size, chunk_size)
    remaining -= len(chunk)
    o[0] += len(chunk)
    yield chunk

async def read_chunks(self, X, o):
  while True:
    o[0], remaining = await X.match(o[0], lambda x, i: 48<=x<=57 or 65<=x<=90 or 97<=x<=122, min=1, max=8) # 0-9A-Za-z
    remaining = int(remaining, 16)
    o[0] = await X.match_CRLF(o[0])
    if remaining == 0:
      break
    async for chunk in read_content_length(self, X, o, remaining):
      yield chunk
    o[0] = await X.match_CRLF(o[0])



def decode_gzip(reader):
  async def decode():
    decoder = zlib.decompressobj(zlib.MAX_WBITS|16)
    async for chunk in reader():
      while len(chunk) != 0:
        yield decoder.decompress(chunk, max_length=4096)
        chunk = decoder.unconsumed_tail
    if not decoder.eof:
      raise I.ProtocolValidationException("gzip compressed data incomplete")
  return decode

def decode_deflate(reader):
  async def decode():
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    async for chunk in reader():
      while len(chunk) != 0:
        yield decoder.decompress(chunk, max_length=4096)
        chunk = decoder.unconsumed_tail
    if not decoder.eof:
      raise I.ProtocolValidationException("deflate compressed data incomplete")
  return decode

def decode_brotli(reader):
  async def decode():
    decoder = brotli.Decompressor()
    async for chunk in reader():
      yield decoder.process(chunk)
    if not decoder.is_finished():
      raise I.ProtocolValidationException("brotli compressed data incomplete")
  return decode

decoders = {
  b'gzip'   : decode_gzip,
  b'deflate': decode_deflate,
  b'br'     : decode_brotli,
}

async def read_response_content(self, S, o, stransfer_encoding, scontent_encoding, scontent_length, has_trailer):

  chunked = False
  has_trailer[0] = False
  if len(stransfer_encoding):
    if b'chunked' != stransfer_encoding[0].lower():
      raise I.ProtocolValidationException("First Transfer-Encoding isn't \"chunked\"")
    has_trailer[0] = True
    chunked = True
    stransfer_encoding = stransfer_encoding[1:]

  async def read_response_content_sub():
    if chunked:
      async for chunk in read_chunks(self, S, o):
        yield chunk
    elif scontent_length:
      async for chunk in read_content_length(self, S, o, scontent_length):
        yield chunk
    else:
      while not S.EOF:
        chunk = S.read(o[0], 1, 4096)
        o[0] += chunk
        yield chunk

  reader = read_response_content_sub
  for encoding in [*stransfer_encoding, *scontent_encoding]:
    encoding = encoding.lower()
    if encoding == 'identity':
      continue
    decoder = decoders.get(encoding)
    if not decoder:
      self.logger.info(f'Unsupported encoding "{encoding}"')
      raise I.ProtocolValidationException(f'Unsupported encoding "{encoding}"')
    reader = decoder(reader)

  async for chunk in reader():
    yield chunk


async def intercept(self, C, S):
  Co = C.replied
  So = S.replied

  # We aren't changeing the traffic. This tells the stream managers that all data can be replied as soon as it arrives
  # Otherwise, we would have to explicitly call S.reply(So) and C.reply(Co). This also allows replying some traffic slightly sooner
  C.setTransparent(True)
  S.setTransparent(True)

  while True:
    ### REQUEST ###
    S.expect_silence(True)
    C.expect_silence(False)

    Co, method, location, cversion = await parse_first_request_line(self, Co, C)
    self.identified()

  #  self.logger.info((method, location, cversion))

    host = b''
    upgrade = b''
    ccontent_length = 0

  #  request_headers = []
    while True:
      Co, header = await parse_header(self, Co, C)
      if header is None:
        break
      if header[0].lower() == b'upgrade':
        upgrade = header[1]
      if header[0].lower() == b'host':
        host = header[1]
      if header[0].lower() == b'content-length':
        ccontent_length = int(header[1])
  #    request_headers.append(header)

  #  self.logger.info(('All headers:', request_headers))

    _Co=[Co]
    async with aclosing(read_content_length(self, C, _Co, ccontent_length)) as ag:
      async for chunk in ag:
        pass
#        print(b'    ',chunk)
    Co = _Co[0]

    ### RESPONSE ###
    C.expect_silence(True)
    S.expect_silence(False)

    while True:
      So, sversion, code, message = await parse_response_line(self, So, S)

      if method == b'CONNECT' and int(code/100) == 2:
        return self.protocol_changed()

      scontent_length = 0
      stransfer_encoding = []
      scontent_encoding = []

      has_content_range = False

  #    response_headers = []
      while True:
        So, header = await parse_header(self, So, S)
  #      print(header)
        if header is None:
          break
        if header[0].lower() == b'content-length':
          scontent_length = int(header[1])
        if header[0].lower() == b'transfer-encoding':
          stransfer_encoding += (x.strip() for x in header[1].split(b','))
        if header[0].lower() == b'content-encoding':
          scontent_encoding += (x.strip() for x in header[1].split(b','))
        if code == 206 and header[0].lower() == b'content-range' and header[1].startswith(b'bytes '):
          cr = re.match(b'^([0-9]+)-([0-9]+)/([0-9]+|\*)$', header[1][6:].strip())
          if cr:
            cr_start  = int(cr[1])
            cr_end    = int(cr[2]) + 1
            cr_length = int(cr[3]) if cr[3] != b'*' else None
            if cr_start < cr_end and (cr_length is None or cr_end <= cr_length):
              has_content_range = True
  #      response_headers.append(header)

      if upgrade and code == 101:
        return self.protocol_changed(name=upgrade)
      upgrade = None

      if int(code/100) != 1:
        break

    dp = None

    try:
      if int(code/100) == 2 and data_processor:
        try:
          dpenv = {**os.environ}
          if has_content_range: # and cr_end != cr_length:
            dpenv["start"] = str(cr_start)
            dpenv["end"]   = str(cr_end)
            dpenv["full"]  = str(cr_length)
          dp = subprocess.Popen([data_processor, host, location], stdin=subprocess.PIPE, env=dpenv)
        except:
          traceback.print_exc()

      _So = [So]
      has_trailer = [0]
      async with aclosing(read_response_content(self, S, _So, stransfer_encoding, scontent_encoding, scontent_length, has_trailer)) as ag:
        async for chunk in ag:
          if dp:
            try:
              dp.stdin.write(chunk)
            except:
              traceback.print_exc()
              dp = None
      So = _So[0]

    finally:
      try:
        dp.stdin.close()
      except: pass

    if has_trailer[0]:
      #response_trailer = []
      while True:
        So, trailer = await parse_header(self, So, S)
        if trailer is None:
          break
        #response_trailer.append(trailer)

    print('request done')
