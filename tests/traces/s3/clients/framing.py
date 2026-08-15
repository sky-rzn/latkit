#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""МS0 reconnaissance item 4: how MinIO frames its response bodies, and how big
the heads are.

Reads a `tap.py` log and tallies, per direction, `Content-Length` against
`Transfer-Encoding: chunked` — the number that decides whether the HTTP framer's
chunked path is a main path or a rarity on an S3 port (risk 4 of PLAN-HTTP.md,
inherited here) — plus the head-size percentiles the capture budget of РH14 has
to be judged against.

    ./tap.py 9990 127.0.0.1 9900 --body 0 > tap.log & ; <load> ; ./framing.py tap.log
"""
import collections
import re
import sys

HEAD_RE = re.compile(r"^--- +[\d.]+ conn(\d+) (C->S|S->C) \((\d+) B head\) ---$")


def main(paths):
    sizes = collections.defaultdict(list)
    framing = collections.Counter()
    ops = collections.Counter()
    status = collections.Counter()
    cur = None
    body_hdrs = {}
    for path in paths:
        for line in open(path, errors="replace"):
            line = line.rstrip("\n")
            m = HEAD_RE.match(line)
            if m:
                if cur:
                    close(cur, body_hdrs, framing)
                cur, body_hdrs = m.group(2), {}
                sizes[cur].append(int(m.group(3)))
                continue
            if not cur or not line.startswith("    "):
                continue
            t = line[4:]
            if cur == "C->S" and re.match(r"^[A-Z]{3,10} \S+ HTTP/1\.[01]$", t):
                ops[t.split()[0]] += 1
            elif cur == "S->C" and t.startswith("HTTP/1."):
                status[t.split()[1]] += 1
            k, _, v = t.partition(":")
            if k.lower() in ("content-length", "transfer-encoding", "content-encoding",
                             "x-amz-decoded-content-length", "x-amz-content-sha256"):
                body_hdrs[k.lower()] = v.strip()
    if cur:
        close(cur, body_hdrs, framing)

    print("--- response framing (S->C, final responses) ---")
    tot = sum(n for (d, _), n in framing.items() if d == "S->C") or 1
    for (d, kind), n in sorted(framing.items()):
        if d == "S->C":
            print("  %-24s %5d  %5.1f%%" % (kind, n, 100.0 * n / tot))
    print("--- request body framing (C->S) ---")
    tot = sum(n for (d, _), n in framing.items() if d == "C->S") or 1
    for (d, kind), n in sorted(framing.items()):
        if d == "C->S":
            print("  %-24s %5d  %5.1f%%" % (kind, n, 100.0 * n / tot))
    print("--- head sizes (bytes) ---")
    for d, v in sorted(sizes.items()):
        v = sorted(v)
        q = lambda p: v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))]
        print("  %s n=%d min=%d p50=%d p90=%d p99=%d max=%d"
              % (d, len(v), v[0], q(50), q(90), q(99), v[-1]))
        for cap in (2048, 4096, 8192):
            over = sum(1 for x in v if x > cap)
            print("      over %5d B: %d/%d (%.1f%%)" % (cap, over, len(v), 100.0 * over / len(v)))
    print("--- methods --- " + " ".join("%s=%d" % kv for kv in ops.most_common()))
    print("--- statuses --- " + " ".join("%s=%d" % kv for kv in status.most_common()))


def close(direction, h, framing):
    if "transfer-encoding" in h and "chunked" in h["transfer-encoding"].lower():
        framing[(direction, "chunked")] += 1
    elif h.get("x-amz-content-sha256", "").startswith("STREAMING-"):
        framing[(direction, "aws-chunked (streaming)")] += 1
    elif "content-length" in h:
        framing[(direction, "Content-Length")] += 1
    else:
        framing[(direction, "no length header")] += 1


if __name__ == "__main__":
    main(sys.argv[1:] or ["-"])
