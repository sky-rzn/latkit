#!/usr/bin/env python3
"""How big is a command, how big is a reply, and how deep does a reply nest.

The three numbers behind РR13 (a 512-byte per-port capture budget), РR2
(`LK_REDIS_MAX_DEPTH`) and the plan's risk 1 (a hole inside an aggregate is not
recoverable). Measured against a live server rather than assumed, because "the
command is tens of bytes and the reply is megabytes" is exactly the kind of
claim that decides a budget and is never checked.

  python3 wirestats.py            command/reply sizes and nesting depth
"""
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resp import Conn, enc  # noqa: E402

# A load that looks like an application: the shapes a cache actually sees, plus
# the three "big reply" outliers that the budget has to survive.
PROBE = [
    ("GET", "lk:ws:k"),
    ("SET", "lk:ws:k", "v" * 64),
    ("SET", "lk:ws:big", "v" * 65536),
    ("GET", "lk:ws:big"),
    ("INCR", "lk:ws:n"),
    ("EXPIRE", "lk:ws:k", "60"),
    ("HSET", "lk:ws:h", "field", "value"),
    ("HGETALL", "lk:ws:h"),
    ("LPUSH", "lk:ws:l", "item"),
    ("LRANGE", "lk:ws:l", "0", "-1"),
    ("ZADD", "lk:ws:z", "1", "member"),
    ("ZRANGE", "lk:ws:z", "0", "-1", "WITHSCORES"),
    ("SADD", "lk:ws:s", "member"),
    ("SMEMBERS", "lk:ws:s"),
    ("MGET", "lk:ws:k", "lk:ws:n"),
    ("PING",),
    ("EXISTS", "lk:ws:k"),
    ("DEL", "lk:ws:gone"),
    ("TTL", "lk:ws:k"),
    ("TYPE", "lk:ws:k"),
    ("SCAN", "0", "COUNT", "10"),
    ("XADD", "lk:ws:xs", "*", "f", "v"),
    ("XRANGE", "lk:ws:xs", "-", "+"),
    ("XINFO", "STREAM", "lk:ws:xs", "FULL"),
    ("CONFIG", "GET", "maxmemory"),
    ("CONFIG", "GET", "*"),
    ("CLIENT", "INFO"),
    ("CLIENT", "LIST"),
    ("COMMAND", "INFO", "GET"),
    ("COMMAND", "DOCS", "GET"),
    ("INFO",),
    ("EVAL", "return {1,2,{3,{4,'five'}}}", "0"),
]


def depth(v, d=1):
    t, val = v
    if not isinstance(val, list) or not val:
        return d
    return max(depth(x, d + 1) for x in val)


def main():
    c = Conn(log=False)
    c.do("HELLO", "3")
    rows = []
    for cmd in PROBE:
        wire = enc(*cmd)
        c.send(wire)
        v = c.read(1)[0]
        # The reply's byte size is what the socket carried, so re-encode it the
        # cheap way: measure the buffer the decoder consumed.
        rows.append((" ".join(cmd[:2]), len(wire), reply_bytes(v), depth(v)))
    w = max(len(r[0]) for r in rows)
    print("%-*s  %8s  %10s  %5s" % (w, "command", "cmd B", "reply B", "depth"))
    for name, cb, rb, d in rows:
        print("%-*s  %8d  %10d  %5d" % (w, name, cb, rb, d))
    cmds = [r[1] for r in rows]
    reps = [r[2] for r in rows]
    print()
    print("command bytes: min %d median %d max %d" %
          (min(cmds), statistics.median(cmds), max(cmds)))
    print("reply bytes:   min %d median %d max %d" %
          (min(reps), statistics.median(reps), max(reps)))
    print("max depth:     %d (%s)" % (max(r[3] for r in rows),
                                      max(rows, key=lambda r: r[3])[0]))
    print()
    print("under a 512-byte budget: %d/%d commands fit whole, %d/%d replies do"
          % (sum(1 for x in cmds if x <= 512), len(cmds),
             sum(1 for x in reps if x <= 512), len(reps)))
    print("the head of every reply — type byte, error name, declared length — "
          "fits in the first 64 bytes by construction")


def reply_bytes(v):
    """Re-encode a decoded value to count what the wire carried."""
    t, val = v
    if val is None:
        return 5 if t in b"$*" else 3
    if isinstance(val, list):
        return len(t) + len(str(len(val))) + 2 + sum(reply_bytes(x) for x in val)
    if isinstance(val, bytes):
        return len(t) + len(str(len(val))) + 2 + len(val) + 2
    return len(t) + len(str(val)) + 2


if __name__ == "__main__":
    main()
