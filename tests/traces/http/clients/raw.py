#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# М0 trace-corpus client for everything curl cannot express: pipelining, a
# 16 KB header block, byte-at-a-time writes, tunnels and upgrades, and the
# deliberately malformed framings (CL+TE, LF-only, torn body) the М2 framer has
# to survive without desyncing.
#
#   raw.py SCENARIO HOST PORT [ARG...]
#
# Everything here writes bytes literally — no http.client, no requests: the
# point is to control the wire, including what a well-behaved library refuses
# to send.
import socket
import sys
import time

CRLF = b"\r\n"


def connect(host, port, timeout=10.0):
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def drain(s, budget=8.0, limit=1 << 24):
    """Read until EOF or the budget expires; return what arrived."""
    out = bytearray()
    deadline = time.time() + budget
    s.settimeout(0.5)
    while time.time() < deadline and len(out) < limit:
        try:
            b = s.recv(65536)
        except socket.timeout:
            break
        except OSError:
            break
        if not b:
            break
        out += b
    return bytes(out)


def report(name, sent, got):
    head = got.split(b"\r\n", 1)[0][:80].decode("latin1")
    print("%-14s sent=%d recv=%d first-line=%r" % (name, sent, len(got), head))


def req(method, target, host, headers=(), body=b"", version="HTTP/1.1"):
    lines = ["%s %s %s" % (method, target, version), "Host: %s" % host]
    lines += list(headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin1") + body


# --- scenarios --------------------------------------------------------------

def sc_pipelined(host, port, *_):
    """Four requests written in one syscall: in-flight depth > 1 (РH6)."""
    hp = "%s:%s" % (host, port)
    blob = b"".join([
        req("GET", "/hello.txt", hp),
        req("GET", "/json/42", hp),
        req("HEAD", "/hello.txt", hp),
        req("GET", "/hello.txt", hp, ["Connection: close"]),
    ])
    s = connect(host, port)
    s.sendall(blob)
    got = drain(s)
    s.close()
    report("pipelined", len(blob), got)


def sc_huge_head(host, port, size=16384, *_):
    """A header block larger than the capture budget (cookies in real life)."""
    size = int(size)
    pad = []
    n = 0
    i = 0
    while n < size:
        h = "X-Pad-%03d: %s" % (i, "a" * 200)
        pad.append(h)
        n += len(h) + 2
        i += 1
    blob = req("GET", "/hello.txt", "%s:%s" % (host, port),
               pad + ["Connection: close"])
    s = connect(host, port)
    s.sendall(blob)
    got = drain(s)
    s.close()
    report("huge-head", len(blob), got)


def sc_slow_client(host, port, *_):
    """Byte at a time: one request head spread over dozens of capture events."""
    blob = req("POST", "/echo", "%s:%s" % (host, port),
               ["Content-Type: text/plain", "Content-Length: 20",
                "Connection: close"], b"slow-body-0123456789")
    s = connect(host, port)
    for i in range(0, len(blob)):
        s.sendall(blob[i:i + 1])
        if i % 8 == 0:
            time.sleep(0.002)
    got = drain(s)
    s.close()
    report("slow-client", len(blob), got)


def sc_abort_midbody(host, port, *_):
    """Client walks away in the middle of a 1 MB response body."""
    blob = req("GET", "/big?n=1048576", "%s:%s" % (host, port))
    s = connect(host, port)
    s.sendall(blob)
    s.settimeout(2.0)
    got = b""
    try:
        got = s.recv(4096)
    except OSError:
        pass
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
    s.close()  # RST, server is still writing
    time.sleep(0.2)
    report("abort-midbody", len(blob), got)


def sc_connect(host, port, target=None, *_):
    """CONNECT tunnel: opaque bytes on an HTTP connection (blind zone, РH4)."""
    target = target or "example.invalid:443"
    blob = ("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target)).encode()
    s = connect(host, port)
    s.sendall(blob)
    time.sleep(0.2)
    s.sendall(b"\x16\x03\x01\x00\x2a" + b"\xde\xad\xbe\xef" * 8)  # tunnelled junk
    got = drain(s, budget=3.0)
    s.close()
    report("connect", len(blob), got)


def sc_websocket(host, port, *_):
    """101 Switching Protocols, then frames we deliberately do not parse."""
    blob = req("GET", "/ws", "%s:%s" % (host, port),
               ["Upgrade: websocket", "Connection: Upgrade",
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version: 13"])
    s = connect(host, port)
    s.sendall(blob)
    time.sleep(0.2)
    s.sendall(b"\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58")  # masked "Hello"
    got = drain(s, budget=3.0)
    s.close()
    report("websocket", len(blob), got)


def sc_h2c_upgrade(host, port, *_):
    """Upgrade: h2c — the h1 way of asking for HTTP/2 (nginx 1.25.1+ ignores it)."""
    blob = req("GET", "/hello.txt", "%s:%s" % (host, port),
               ["Connection: Upgrade, HTTP2-Settings", "Upgrade: h2c",
                "HTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA"])
    s = connect(host, port)
    s.sendall(blob)
    got = drain(s, budget=3.0)
    s.close()
    report("h2c-upgrade", len(blob), got)


def sc_h2_preface(host, port, *_):
    """Prior-knowledge HTTP/2 preface + SETTINGS, by hand."""
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"          # empty SETTINGS
    s = connect(host, port)
    s.sendall(preface + settings)
    got = drain(s, budget=3.0)
    s.close()
    report("h2-preface", len(preface) + len(settings), got)


def sc_absolute_form(host, port, *_):
    """Proxy-style request-target: the Host lives in the URL (§scope)."""
    hp = "%s:%s" % (host, port)
    blob = req("GET", "http://%s/hello.txt" % hp, hp, ["Connection: close"])
    s = connect(host, port)
    s.sendall(blob)
    got = drain(s)
    s.close()
    report("absolute-form", len(blob), got)


def sc_keepalive(host, port, n=50, *_):
    """N sequential requests on one connection (РH6 unit boundaries)."""
    n = int(n)
    hp = "%s:%s" % (host, port)
    s = connect(host, port)
    sent = 0
    for i in range(n):
        blob = req("GET", "/json/%d" % i, hp)
        s.sendall(blob)
        sent += len(blob)
        s.settimeout(5.0)
        try:
            s.recv(65536)
        except OSError:
            break
    got = drain(s, budget=1.0)
    s.close()
    report("keepalive", sent, got or b"HTTP/1.1 (drained)")


def sc_chunked_req(host, port, *_):
    """Chunked request body with a trailer — sizes live in the stream (РH4)."""
    hp = "%s:%s" % (host, port)
    head = req("POST", "/echo", hp,
               ["Content-Type: text/plain", "Transfer-Encoding: chunked",
                "Trailer: X-Checksum", "Connection: close"])
    s = connect(host, port)
    s.sendall(head)
    sent = len(head)
    for i in range(4):
        payload = ("chunk-%d-%s" % (i, "x" * (100 * (i + 1)))).encode()
        frame = b"%x\r\n%s\r\n" % (len(payload), payload)
        s.sendall(frame)
        sent += len(frame)
        time.sleep(0.01)
    tail = b"0\r\nX-Checksum: deadbeef\r\n\r\n"
    s.sendall(tail)
    got = drain(s)
    s.close()
    report("chunked-req", sent + len(tail), got)


def sc_continue(host, port, *_):
    """Expect: 100-continue — an interim response before the real one (РH3 'I')."""
    body = b"y" * 4096
    head = req("POST", "/echo", "%s:%s" % (host, port),
               ["Content-Type: application/octet-stream",
                "Content-Length: %d" % len(body), "Expect: 100-continue",
                "Connection: close"])
    s = connect(host, port)
    s.sendall(head)
    s.settimeout(3.0)
    interim = b""
    try:
        interim = s.recv(4096)
    except OSError:
        pass
    time.sleep(0.05)
    s.sendall(body)
    got = interim + drain(s)
    s.close()
    report("continue", len(head) + len(body), got)


def sc_cl_te(host, port, *_):
    """Content-Length *and* Transfer-Encoding: the desync shape (М2 rejects)."""
    hp = "%s:%s" % (host, port)
    head = req("POST", "/echo", hp,
               ["Content-Length: 6", "Transfer-Encoding: chunked",
                "Connection: close"])
    s = connect(host, port)
    s.sendall(head + b"0\r\n\r\nGET /hello.txt HTTP/1.1\r\nHost: %s\r\n\r\n"
              % hp.encode())
    got = drain(s, budget=3.0)
    s.close()
    report("cl-te", len(head), got)


def sc_lf_only(host, port, *_):
    """Bare LF line endings — legal to accept per RFC 9112, never to send."""
    blob = ("GET /hello.txt HTTP/1.1\nHost: %s:%s\nConnection: close\n\n"
            % (host, port)).encode()
    s = connect(host, port)
    s.sendall(blob)
    got = drain(s)
    s.close()
    report("lf-only", len(blob), got)


def sc_torn_body(host, port, *_):
    """Promise 4096 body bytes, send 100, hang up: request body never completes."""
    head = req("POST", "/echo", "%s:%s" % (host, port),
               ["Content-Length: 4096", "Connection: close"])
    s = connect(host, port)
    s.sendall(head + b"z" * 100)
    time.sleep(0.1)
    got = drain(s, budget=1.5)
    s.close()
    report("torn-body", len(head) + 100, got)


def sc_traceparent(host, port, *_):
    """W3C trace context + X-Request-Id: what РH11 latches onto."""
    hp = "%s:%s" % (host, port)
    blob = b"".join([
        req("GET", "/json/00000000-0000-4000-8000-000000000abc?token=s3cr3t&page=2", hp,
            ["traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
             "tracestate: rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",
             "X-Request-Id: 8f14e45fceea167a5a36dedd4bea2543",
             "User-Agent: latkit-corpus/1.0",
             "Authorization: Basic YWRtaW46aHVudGVyMg==",
             "Cookie: session=deadbeefcafe; theme=dark"]),
        req("GET", "/hello.txt", hp,
            ["traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00",
             "Connection: close"]),
    ])
    s = connect(host, port)
    s.sendall(blob)
    got = drain(s)
    s.close()
    report("traceparent", len(blob), got)


def sc_bad_request(host, port, *_):
    """Garbage where a start line should be: 400 and a closed connection."""
    blob = b"\x00\x01\x02NOT-A-METHOD /x\r\nHost: x\r\n\r\n"
    s = connect(host, port)
    s.sendall(blob)
    got = drain(s, budget=3.0)
    s.close()
    report("bad-request", len(blob), got)


SCENARIOS = {name[3:].replace("_", "-"): fn
             for name, fn in sorted(globals().items()) if name.startswith("sc_")}

if __name__ == "__main__":
    if len(sys.argv) < 4 or sys.argv[1] not in SCENARIOS:
        sys.exit("usage: raw.py {%s} HOST PORT [ARG...]" % "|".join(SCENARIOS))
    SCENARIOS[sys.argv[1]](sys.argv[2], sys.argv[3], *sys.argv[4:])
