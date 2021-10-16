# DPA MITM Tools

These are some quickly hacked together tools I use for SSL MITM. All the tools are actually simple socks proxies,
which can also be used as transparent proxies, and transform the traffic in some way. The idea is to make it simple
to chain socks proxies to analyze & manipulate traffic. It's also great for annalyzing stuff with existing network
capturing tools such as wireshark.

I'm doing a small extension to the domain format, though. If the socks connection destination is a domain, I
differentiate between the target domain and the connection domain or address, and combine them with `>` if they differ.
So, for example, if retls.py gets instructed to connect to `example.com>127.0.0.1`, it'll connect to `127.0.0.1`,
it'll send `example.com` as TLS SNI, and it'll check that the TLS Cert is for that domain.

## Overview

```
Client  ---->  1666:0.0.0.0 untls.py
                               |
                               |------->  127.0.0.1:3666 retls.py ---------->  Server
                               |    (tls decrypted)
                               |
                               |------->  127.0.0.1:2666 socksproxy.py  ---->  Server
                           (forwarded unchanged if not decryptable)
```

## Caveats
TLS traffic not containing an SNI and non-TLS traffic aren't decrypted by untls.py, but forwarded unchanged to `127.0.0.1:2666` using socks.

If you want to use that extended domain format with other existing socks proxies and tools directly, you may sometimes need
to either change those tools or maybe make an nsswitch hostname module, depending on how the domain is used by those tools.

If you use it as a transparent proxy, it can't reject connections early, as there are no unix syscalls for that. It'll close
the connections directly after accepting them instead.

To determine if transparent proxying is needed, it compares the original tcp destination address (whatever it was before any
iptables rules and such) to the tcp destination address, and if they differ, assumes it's transparent proxying. So, if you
have some strange dnat rules and see it responding in socks when it shouldn't or vice versa, that's probably it.

## untls.py

```
usage: untls.py [-h] [-l LISTEN] [-c VIA] [-t TLS_VIA] [--ca CA] [--ca-key CA_KEY]

socks plain to tls proxy

optional arguments:
  -h, --help            show this help message and exit
  -l LISTEN, --listen LISTEN
                        IP:PORT to listen on (default: 0.0.0.0:1666)
  -c VIA, --via VIA     IP:PORT of socks proxy to connect to for undecryptable traffic, or "direct" for none (default: 127.0.0.1:2666)
  -t TLS_VIA, --tls-via TLS_VIA
                        IP:PORT of socks proxy to connect to for decrypted traffic (default: 127.0.0.1:3666)
  --ca CA
  --ca-key CA_KEY
```

Listens on port `0.0.0.0:1666`. After a connection, it first tries to connect to the destination over socks on `127.0.0.1:2666`. Only if that
works, it'll accept the socks connection, otherwise, it rejects it. It then just reads from the connection, and tries to figure out
if it's TLS using lot's of checks, so it can figure out if it isn't as early as possible, and tries to parse the SNI.
If it isn't TLS, or it doesn't get an SNI, it'll forward everything on the already establisched connection via `127.0.0.1:2666` unchanged.
Otherwise (if it is TLS and it got an SNI), it'll forge a certificate for the SNI, and use that to establish a TLS connection with the client.
It then connects to `127.0.0.1:3666`, and sends the unencrypted content over there using socks. When doing that, it uses the extended
domain format explained above (ex. `example.com>127.0.0.1`) if necessary. This is how rentls.py will know which hostname to expect and
which SNI to send the target address.

The root CA for signing the forged certificated is loaded from `/etc/ssl/CA/CA.pem` and `/etc/ssl/CA/CA.key`. Make sure to create them and
install `/etc/ssl/CA/CA.pem` on the device to be MITMd.

## socksproxy.py

```
usage: socksproxy.py [-h] [-l LISTEN] [-c VIA]

socks plain to tls proxy

optional arguments:
  -h, --help            show this help message and exit
  -l LISTEN, --listen LISTEN
                        IP:PORT to listen on (default: 127.0.0.1:2666)
  -c VIA, --via VIA     IP:PORT of socks proxy to connect to, or "direct" for none (default: direct)
```

Per default, this listens on port `127.0.0.1:2666`, and is just a normal socks proxy.

## retls.py

```
usage: retls.py [-h] [-l LISTEN] [-c VIA]

socks plain to tls proxy

optional arguments:
  -h, --help            show this help message and exit
  -l LISTEN, --listen LISTEN
                        IP:PORT to listen on (default: 127.0.0.1:3666)
  -c VIA, --via VIA     IP:PORT of socks proxy to connect to, or "direct" for none (default: direct)
```

Listens on port `127.0.0.1:3666`. This is a socks proxy, but which takes a plain connection and connects to it's target using TLS.
It can use the extended domain format explained above (ex. `example.com>127.0.0.1`) for getting the address to connect to and
the server name for the TLS connection.

## Usage as transparent proxy

Just redirect all traffic to the socks proxy using tcpdump (excluding traffic for the own host, 10.60.10.12 in this example.).
```
iptables -t nat -A PREROUTING -d 10.60.10.12 -i eth0 -j RETURN
iptables -t nat -A PREROUTING -s 10.60.10.12 -i eth0 -j RETURN
iptables -t nat -A PREROUTING -i eth0 -p tcp -j REDIRECT --to-ports 1666
```

Then, set the host on which the proxy runs and the iptables rules where added as the gataway for the host whose traffic is to be MITMd.

# interceptor.py

```
usage: interceptor.py [-h] -l LISTEN -c VIA
```

This socks proxy can be put between the other socks proxies above.
It loads all the interceptor modules from the interceptor directory.
If no interceptor is able to make sense of the traffic, or if all
interceptors agree they won't alter it, it is let through unaltered.

## interceptor/http.py

This is currenlt the only interceptor available. It transparently intercepts
http traffic, any byte it analyxes will be forwarded unchanged basically immediately.
It can analyze & decode variouse transfer & content encodings, and should be able
to handle http proxies, http upgrades, and such stuff.

When any file or part of file is requested, calls `save_http_files.sh`, which stores
it insode the directory `intercepted/http/`. save_http_files.sh tries to reassemble
the files. Files being written to or incomplete are in directories named
`d:<host>-<hashoflocation>/<byteoffset>.part`. Consecutive or overlapping parts are
consolidated. If a file has been stored & is continous starting from the first byte,
it is assumed to be complete until later bytes for the same file are requested. It'll
be available under the name `f:<host>-<hashoflocation>`. If the file is determined
to be a m3u playlist file, it will parse it and create/update an additional playlist
named `m3u:<host>-<hashoflocation>.m3u8`, the files in which will match the final
names of the referenced files after / if they are intercepted/stored.

## Remotely capturing traffic using wireshark

There are many ways to do that, but I like to use tcpdump and xinetd for this. This will be insecure, though, so don't set
this up if that's a concern.

1) Install xinetd
2) Add `tcpdump 666/tcp` to `/etc/services`
3) Add a helper script to `/usr/local/sbin/mitmdump`:
```
#!/bin/sh
exec /usr/sbin/tcpdump -f -i lo -w - port 2666 or port 3666 <&- 2>&-
```

4) Configure xinetd. `/etc/xinetd.d/tcpdump`:
```
{
  disable     = no
  socket_type = stream
  protocol    = tcp
  port        = 666
  wait        = no
  user        = root
  server      = /usr/local/sbin/mitmdump
}
```

5) restart xinetd
6) Start wireshark: `wireshark -k -i TCP@10.60.10.12:666`
