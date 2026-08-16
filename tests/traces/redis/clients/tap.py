#!/usr/bin/env python3
"""A logging RESP proxy: what a client actually puts on the wire.

Listens on --listen, forwards to --upstream, and decodes both directions well
enough to answer the two reconnaissance questions of МR0 that no client's
documentation answers honestly:

  * does it send `HELLO 3` when nobody asked it to (item 2), and
  * how many commands does it put in one write(2) (item 3) — which is the
    pipeline depth the agent will see as one batch.

The counting is per *read from the socket*, which is the same boundary the
kprobes see (one `tcp_sendmsg` on the client side is one read here, TCP
coalescing aside), so the depth histogram this prints is the one
`latkit_redis_pipeline_depth` will produce.

  python3 tap.py --listen 6499 --upstream 127.0.0.1:6399 [--quiet]
"""
import argparse
import collections
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resp import Decoder, brief  # noqa: E402

STATS = collections.Counter()
DEPTHS = collections.Counter()
FIRST = []
LOCK = threading.Lock()


def pump(src, dst, tag, quiet):
    """Forward src→dst, decoding whatever whole values each read contains."""
    dec = Decoder()
    inline_ok = tag == "C>S"
    while True:
        try:
            chunk = src.recv(65536)
        except OSError:
            break
        if not chunk:
            break
        try:
            dst.sendall(chunk)
        except OSError:
            break
        dec.feed(chunk)
        n = 0
        try:
            while True:
                # An inline command is not a typed value; count the line and move on.
                if inline_ok and dec.buf and dec.buf[0:1] not in b"*+-:$_#,(!=%~>|":
                    j = dec.buf.find(b"\n")
                    if j < 0:
                        break
                    line = dec.buf[:j].strip()
                    dec.buf = dec.buf[j + 1:]
                    if line:
                        n += 1
                        note(tag, "inline " + line.decode("latin1")[:60], quiet)
                    continue
                v = dec.value()
                if v is None:
                    break
                n += 1
                if tag == "C>S":
                    cmd = ""
                    if v[0] == b"*" and v[1]:
                        parts = [p[1].decode("latin1") for p in v[1][:3]
                                 if isinstance(p[1], bytes)]
                        cmd = " ".join(parts)
                    with LOCK:
                        STATS[cmd.split(" ")[0].upper()] += 1
                        if len(FIRST) < 12:
                            FIRST.append(cmd)
                    note(tag, cmd[:70], quiet)
                else:
                    note(tag, brief(v)[:70], quiet)
        except ValueError as e:
            note(tag, "not RESP: %s" % e, quiet)
            dec.buf = b""
        if n and tag == "C>S":
            with LOCK:
                DEPTHS[n] += 1
    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def note(tag, text, quiet):
    if not quiet:
        print("%s %s" % (tag, text), flush=True)


def serve(listen_port, upstream, quiet):
    up_host, up_port = upstream.split(":")
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen_port))
    srv.listen(64)
    while True:
        cs, _ = srv.accept()
        us = socket.create_connection((up_host, int(up_port)))
        for a, b, tag in ((cs, us, "C>S"), (us, cs, "S>C")):
            threading.Thread(target=pump, args=(a, b, tag, quiet), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, default=6499)
    ap.add_argument("--upstream", default="127.0.0.1:6399")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--summary-on", default="/tmp/lkt-tap-summary",
                    help="write the summary here when this file is touched (SIGUSR1 too)")
    a = ap.parse_args()

    import signal

    def summary(*_):
        with LOCK:
            total = sum(DEPTHS.values())
            print("\n--- client writes: %d, commands: %d" % (total, sum(STATS.values())))
            print("--- first commands: %s" % " | ".join(FIRST))
            print("--- batch depth histogram (commands per client write):")
            for depth in sorted(DEPTHS):
                print("      %6d commands/write  ×%d" % (depth, DEPTHS[depth]))
            print("--- command counts: %s" % dict(STATS.most_common(12)))
        sys.stdout.flush()

    signal.signal(signal.SIGUSR1, summary)
    signal.signal(signal.SIGTERM, lambda *_: (summary(), sys.exit(0)))
    try:
        serve(a.listen, a.upstream, a.quiet)
    except KeyboardInterrupt:
        summary()


if __name__ == "__main__":
    main()
