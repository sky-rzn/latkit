#!/usr/bin/env python3
"""How deep does a Redis reply nest, at worst?

РR2 sizes the framer's aggregate stack (`LK_REDIS_MAX_DEPTH`) and treats an
overflow as evidence that we are reading the wrong bytes. That is only true if
the bound is above what a stock server can produce — so this measures it instead
of assuming it. An aggregate carries a *count*, not a length, so a value the
framer cannot descend into is a value it cannot skip either.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resp import Conn, enc  # noqa: E402
from wirestats import depth, reply_bytes  # noqa: E402

PROBES = [
    ("COMMAND", "DOCS"),                 # every command, every argument, recursively
    ("COMMAND",),
    ("COMMAND", "INFO"),
    ("COMMAND", "INFO", "GET"),
    ("COMMAND", "DOCS", "GET"),
    ("XINFO", "STREAM", "lk:depth:xs", "FULL"),
    ("XPENDING", "lk:depth:xs", "g"),
    ("CLUSTER", "SLOTS"),
    ("ACL", "GETUSER", "default"),
    ("MEMORY", "STATS"),
    ("SLOWLOG", "GET"),
    ("FUNCTION", "STATS"),
    ("CONFIG", "GET", "*"),
    ("CLIENT", "LIST"),
    ("INFO", "everything"),
    # A script returns whatever it likes, so the protocol's depth is unbounded
    # in principle; this is only the shape of the argument.
    ("EVAL", "return {1,{2,{3,{4,{5,{6,{7,{8,{9,10}}}}}}}}}", "0"),
]


def main():
    c = Conn(log=False)
    proto = 3 if "--resp2" not in sys.argv else 2
    if proto == 3:
        c.do("HELLO", "3")
    for setup in (("DEL", "lk:depth:xs"),
                  ("XADD", "lk:depth:xs", "*", "f", "v"),
                  ("XADD", "lk:depth:xs", "*", "f", "v2"),
                  ("XGROUP", "CREATE", "lk:depth:xs", "g", "0"),
                  ("XREADGROUP", "GROUP", "g", "c1", "COUNT", "5",
                   "STREAMS", "lk:depth:xs", ">")):
        c.send(enc(*setup))
        c.read(1)
    rows = []
    for p in PROBES:
        c.send(enc(*p))
        try:
            v = c.read(1)[0]
        except Exception as e:                      # a subcommand this server lacks
            rows.append((-1, 0, " ".join(p[:3]) + "  (" + str(e)[:40] + ")"))
            continue
        rows.append((depth(v), reply_bytes(v), " ".join(p[:3])))
    print("RESP%d" % proto)
    print("%5s  %10s  %s" % ("depth", "bytes", "command"))
    for d, b, name in sorted(rows, reverse=True):
        print("%5d  %10d  %s" % (d, b, name))


if __name__ == "__main__":
    main()
