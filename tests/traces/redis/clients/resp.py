#!/usr/bin/env python3
"""RESP2/RESP3 over a raw socket — encoder, decoder, connection.

Shared by raw.py (the scenario driver) and tap.py (the logging proxy). Small on
purpose: it has to be readable next to notes-redisproto.md, because it is the
executable half of what that file claims about the wire.

The decoder understands every type of both versions and returns a tagged tuple
(type_byte, value) so a caller can tell `+OK` from `$2\r\nOK`, a RESP3 push from
an array, and a null bulk from an empty one — distinctions the wire makes and
every client library throws away.
"""
import os
import socket
import sys

CRLF = b"\r\n"


# --- encoding ---------------------------------------------------------------

def enc(*args):
    """A command as a RESP array of bulk strings — what every client sends."""
    out = [b"*%d\r\n" % len(args)]
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        elif not isinstance(a, (bytes, bytearray)):
            a = str(a).encode()
        out.append(b"$%d\r\n" % len(a))
        out.append(bytes(a))
        out.append(CRLF)
    return b"".join(out)


def inline(text):
    """An inline command: a bare line, no type bytes. telnet, healthchecks."""
    if isinstance(text, str):
        text = text.encode()
    return text + CRLF


# --- decoding ---------------------------------------------------------------

class Decoder:
    """Incremental RESP2/RESP3 decoder over a buffer.

    `value()` returns (type_byte, python_value) or None if the buffer does not
    hold a complete top-level value yet. Aggregates recurse; a null of either
    spelling (`$-1`, `*-1`, `_`) is a None value with its own type byte kept.
    """

    def __init__(self):
        self.buf = b""

    def feed(self, data):
        self.buf += data

    def value(self):
        v, n = self._parse(self.buf, 0)
        if v is _INCOMPLETE:
            return None
        self.buf = self.buf[n:]
        return v

    def _line(self, b, i):
        j = b.find(CRLF, i)
        if j < 0:
            return None, i
        return b[i:j], j + 2

    def _parse(self, b, i):
        if i >= len(b):
            return _INCOMPLETE, i
        t = b[i:i + 1]
        line, j = self._line(b, i + 1)
        if line is None:
            return _INCOMPLETE, i
        if t in (b"+", b"-", b":", b",", b"(", b"#"):
            return (t, line.decode("latin1")), j
        if t == b"_":                                    # RESP3 null
            return (t, None), j
        if t in (b"$", b"=", b"!"):                      # bulk / verbatim / blob error
            n = int(line)
            if n < 0:
                return (t, None), j                      # RESP2 null bulk
            if len(b) < j + n + 2:
                return _INCOMPLETE, i
            return (t, b[j:j + n]), j + n + 2
        if t in (b"*", b"~", b">", b"%", b"|"):          # aggregates
            n = int(line)
            if n < 0:
                return (t, None), j                      # RESP2 null array
            if t in (b"%", b"|"):
                n *= 2                                   # map/attribute: n pairs
            out = []
            k = j
            for _ in range(n):
                v, k = self._parse(b, k)
                if v is _INCOMPLETE:
                    return _INCOMPLETE, i
                out.append(v)
            return (t, out), k
        raise ValueError("not RESP at offset %d: %r" % (i, b[i:i + 32]))


_INCOMPLETE = object()


def brief(v, depth=0):
    """One-line rendering of a decoded value, for the scenario logs."""
    if v is None:
        return "<none>"
    t, val = v
    ts = t.decode()
    if val is None:
        return ts + "(null)"
    if isinstance(val, list):
        if depth >= 2:
            return "%s[%d …]" % (ts, len(val))
        inner = ", ".join(brief(x, depth + 1) for x in val[:6])
        more = ", …" if len(val) > 6 else ""
        return "%s[%d: %s%s]" % (ts, len(val), inner, more)
    if isinstance(val, bytes):
        s = val[:48].decode("latin1")
        return "%s(%d)%r%s" % (ts, len(val), s, "…" if len(val) > 48 else "")
    return "%s%s" % (ts, val)


# --- connection -------------------------------------------------------------

class Conn:
    def __init__(self, host=None, port=None, log=True, timeout=20.0):
        self.host = host or os.environ.get("REDIS_HOST", "127.0.0.1")
        self.port = int(port or os.environ.get("REDIS_PORT", "6399"))
        self.log = log
        self.dec = Decoder()
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # raw wire access — scenarios need to send things no client library will
    def send(self, data):
        self.sock.sendall(data)

    def cmd(self, *args):
        self.send(enc(*args))
        return self

    def read(self, n=1):
        """Read n top-level values, returning them decoded."""
        out = []
        while len(out) < n:
            v = self.dec.value()
            if v is None:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise EOFError("server closed with %d/%d values read" % (len(out), n))
                self.dec.feed(chunk)
                continue
            out.append(v)
        return out

    def do(self, *args, **kw):
        """Send one command, read one reply, log the pair."""
        n = kw.pop("nreplies", 1)
        self.cmd(*args)
        vs = self.read(n)
        if self.log:
            shown = " ".join(str(a)[:40] for a in args)
            say("  %-46s -> %s" % (shown[:46], " | ".join(brief(v) for v in vs)))
        return vs[0] if n == 1 else vs

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def say(*a):
    print(*a, flush=True)
