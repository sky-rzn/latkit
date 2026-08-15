#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""МS0 (PLAN-MINIO.md): a logging TCP tap in front of MinIO.

The trace corpus is recorded by the agent itself; this is the *reading* tool of
the reconnaissance — it prints the head of every request and response, plus the
first bytes of each body, so the claims in docs/notes-s3proto.md (what an SDK
really puts on the wire: `aws-chunked`, `Expect: 100-continue`, the SigV4
credential scope, the XML error prefix) can be quoted from a real exchange
rather than from documentation.

    ./tap.py 9990 127.0.0.1 9900 [--body N] > heads.txt

It frames HTTP/1.1 for real — the body-length decision list of RFC 9112 in the
short form MinIO needs (`Content-Length`, `chunked`, HEAD/204/304, 1xx, and the
method queue that tells the response side which request it is answering) —
because the naive "split on the first CRLFCRLF" tap finds header blocks inside
binary object bodies and reports 1 MB heads. The head sizes it prints feed the
capture-budget table in README.md, so they have to be the real ones.

Not a proxy in any useful sense: no pooling, one thread per direction, and it
is honest about the bytes and nothing else.
"""
import socket
import sys
import threading
import time

BODY_KEEP = 512
T0 = time.monotonic()
lock = threading.Lock()


def emit(lines):
    with lock:
        sys.stdout.write("".join(lines))
        sys.stdout.flush()


class Side:
    """One direction of one connection: framing state plus what it prints."""

    def __init__(self, tag, conn_id, peer):
        self.tag = tag
        self.conn_id = conn_id
        self.peer = peer          # the other direction, for the method queue
        self.buf = b""
        self.body_left = 0        # bytes of body still to skip (-1: until close)
        self.chunked = False
        self.chunk_left = 0
        self.body_shown = 0
        self.methods = []         # requests seen, oldest first (response side reads it)

    def feed(self, data):
        self.buf += data
        while self.buf:
            if self.body_left or self.chunked:
                if not self.eat_body():
                    return
                continue
            i = self.buf.find(b"\r\n\r\n")
            if i < 0:
                if len(self.buf) > 1 << 20:      # not a head; give up on this stream
                    self.buf = b""
                return
            head, self.buf = self.buf[:i], self.buf[i + 4 :]
            self.on_head(head, i + 4)

    def eat_body(self):
        """Consume body bytes, printing a prefix. False = need more data."""
        if self.chunked:
            while self.buf:
                if self.chunk_left:
                    take = min(self.chunk_left, len(self.buf))
                    self.show(self.buf[:take])
                    self.buf = self.buf[take:]
                    self.chunk_left -= take
                    if self.chunk_left:
                        return False
                    continue
                if b"\r\n" not in self.buf:
                    return False
                line, rest = self.buf.split(b"\r\n", 1)
                if not line and rest[:0] == b"":
                    pass
                try:
                    n = int(line.split(b";")[0] or b"0", 16)
                except ValueError:
                    self.chunked = False
                    return True
                self.buf = rest
                if n == 0:
                    self.chunked = False
                    return True
                self.chunk_left = n + 2   # payload + the CRLF after it
            return False
        take = min(self.body_left, len(self.buf)) if self.body_left > 0 else len(self.buf)
        self.show(self.buf[:take])
        self.buf = self.buf[take:]
        if self.body_left > 0:
            self.body_left -= take
        return self.body_left == 0 and take > 0

    def show(self, data):
        if BODY_KEEP and self.body_shown < BODY_KEEP:
            take = data[: BODY_KEEP - self.body_shown]
            self.body_shown += len(take)
            emit(["    %s body| %s\n" % (self.tag, repr(take)[2:-1])])

    def on_head(self, head, head_len):
        lines = head.split(b"\r\n")
        emit(["\n--- %8.3f conn%d %s (%d B head) ---\n"
              % (time.monotonic() - T0, self.conn_id, self.tag, head_len)]
             + ["    " + l.decode("latin1") + "\n" for l in lines])
        h = {}
        for l in lines[1:]:
            k, _, v = l.partition(b":")
            h.setdefault(k.strip().lower().decode("latin1"), v.strip().decode("latin1"))
        self.body_shown = 0
        first = lines[0].split()
        is_response = first and first[0].upper().startswith(b"HTTP/")
        status = int(first[1]) if is_response and len(first) > 1 and first[1].isdigit() else 0

        if is_response:
            if 100 <= status < 200:
                return                       # interim: no body, the unit continues
            method = self.peer.methods.pop(0) if self.peer.methods else b"GET"
            if method == b"HEAD" or status in (204, 304):
                return                       # a length that describes no body
        else:
            self.methods.append(first[0].upper() if first else b"GET")

        if "chunked" in h.get("transfer-encoding", "").lower():
            self.chunked, self.chunk_left = True, 0
        elif "content-length" in h:
            try:
                self.body_left = int(h["content-length"])
            except ValueError:
                self.body_left = 0
        elif is_response and status >= 200:
            self.body_left = -1              # until close (rule 6 of the list)


def pump(src, dst, side):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            # Frame before forwarding, never after: the response side reads the
            # request side's method queue to know whether a `Content-Length`
            # describes a body (HEAD), and a request handed to MinIO first can
            # be answered before this thread has recorded its method.
            side.feed(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def serve(lport, rhost, rport):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", lport))
    srv.listen(64)
    emit(["# tap on 127.0.0.1:%d -> %s:%d\n" % (lport, rhost, rport)])
    n = 0
    while True:
        cli, _ = srv.accept()
        n += 1
        up = socket.create_connection((rhost, rport))
        req = Side("C->S", n, None)
        resp = Side("S->C", n, req)
        req.peer = resp
        for a, b, side in ((cli, up, req), (up, cli, resp)):
            threading.Thread(target=pump, args=(a, b, side), daemon=True).start()


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--body" in args:
        i = args.index("--body")
        BODY_KEEP = int(args[i + 1])
        del args[i : i + 2]
    lport = int(args[0]) if args else 9990
    rhost = args[1] if len(args) > 1 else "127.0.0.1"
    rport = int(args[2]) if len(args) > 2 else 9900
    serve(lport, rhost, rport)
