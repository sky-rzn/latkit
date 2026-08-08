#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# М0 reconnaissance probe (PLAN-HTTP.md, items 2 and 5): for one server, walk a
# route sweep with several client header profiles and report, per request, how
# the response was framed (Content-Length / chunked / until-close) and how big
# the request and response header blocks were.
#
#   probe.py sweep NAME HOST PORT      -> TSV rows on stdout
#   probe.py summary FILE...           -> framing table + header-size percentiles
#
# Raw sockets again: an HTTP library would hide exactly the framing we measure.
import socket
import sys
import time

# Header profiles a server sees in the wild. The browser profile is the header
# set Chromium 150 sends (copied from a real request), plus a session cookie —
# the realistic worst case for РH14's capture budget.
PROFILES = {
    "minimal": [],
    "curl": ["User-Agent: curl/8.5.0", "Accept: */*"],
    "sdk": [  # a typical service-to-service client (Go/Java/python SDK)
        "User-Agent: Go-http-client/1.1",
        "Accept-Encoding: gzip",
        "X-Request-Id: 8f14e45fceea167a5a36dedd4bea2543",
        "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ],
    "browser": [
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, "
        "like Gecko) Chrome/150.0.0.0 Safari/537.36",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding: gzip, deflate, br, zstd",
        "Accept-Language: en-GB,en-US;q=0.9,en;q=0.8,ru;q=0.7",
        "Cache-Control: no-cache",
        "Pragma: no-cache",
        "Sec-Ch-Ua: \"Chromium\";v=\"150\", \"Not(A:Brand\";v=\"24\"",
        "Sec-Ch-Ua-Mobile: ?0",
        "Sec-Ch-Ua-Platform: \"Linux\"",
        "Sec-Fetch-Dest: document",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Site: none",
        "Sec-Fetch-User: ?1",
        "Upgrade-Insecure-Requests: 1",
        "Cookie: sessionid=8f14e45fceea167a5a36dedd4bea2543; csrftoken="
        "Ck7QoJ2vXn1sTf9pLmR3yBd5eHgUwZaN; _ga=GA1.2.1234567890.1700000000; "
        "_gid=GA1.2.9876543210.1700000000; consent=eyJhZHMiOnRydWUsImFuYWx5dGljcyI6dHJ1ZX0; "
        "cart=%5B%7B%22sku%22%3A%22A-1%22%2C%22qty%22%3A2%7D%5D",
    ],
}

# The size sweep looks for the point where a server stops computing
# Content-Length itself; the fixed routes are the shapes a real handler has.
ROUTES = (["/auto?n=%d" % n for n in (64, 512, 1024, 2048, 4096, 8192, 16384, 65536)]
          + ["/hello", "/json/42", "/chunked?n=3", "/big?n=262144", "/boom",
             "/redirect", "/nope"])


def head_of(blob):
    i = blob.find(b"\r\n\r\n")
    return blob[:i + 4] if i >= 0 else blob


def framing(head):
    low = head.lower()
    if b"\r\ntransfer-encoding:" in low and b"chunked" in low:
        return "chunked"
    if b"\r\ncontent-length:" in low:
        return "content-length"
    if b" 304 " in head[:16] or b" 204 " in head[:16]:
        return "no-body"
    return "until-close"


def status(head):
    parts = head.split(b" ", 2)
    return parts[1].decode() if len(parts) > 1 else "?"


def sweep(name, host, port):
    for profile, extra in PROFILES.items():
        for route in ROUTES:
            lines = ["GET %s HTTP/1.1" % route, "Host: %s:%s" % (host, port)]
            lines += extra + ["Connection: close"]
            blob = ("\r\n".join(lines) + "\r\n\r\n").encode()
            try:
                s = socket.create_connection((host, int(port)), timeout=10)
                s.sendall(blob)
                got = bytearray()
                s.settimeout(5)
                deadline = time.time() + 10
                while time.time() < deadline:
                    try:
                        b = s.recv(65536)
                    except OSError:
                        break
                    if not b:
                        break
                    got += b
                    if len(got) > (1 << 20) and b"\r\n\r\n" in got:
                        break
                s.close()
            except OSError as e:
                print("%s\t%s\t%s\tERROR\t%s\t0\t0" % (name, profile, route, e))
                continue
            head = head_of(bytes(got))
            print("%s\t%s\t%s\t%s\t%s\t%d\t%d"
                  % (name, profile, route, framing(head), status(head),
                     len(blob), len(head)))


def summary(paths):
    rows = []
    for p in paths:
        with open(p) as fh:
            for line in fh:
                f = line.rstrip("\n").split("\t")
                if len(f) == 7:
                    rows.append(f)
    servers = sorted({r[0] for r in rows})

    print("== response framing by server (all profiles, %d requests) ==" % len(rows))
    kinds = ["content-length", "chunked", "until-close", "no-body", "ERROR"]
    print("%-10s %s" % ("server", " ".join("%14s" % k for k in kinds)))
    for srv in servers:
        sub = [r for r in rows if r[0] == srv]
        cells = []
        for k in kinds:
            n = sum(1 for r in sub if r[3] == k)
            cells.append("%6d (%4.1f%%)" % (n, 100.0 * n / len(sub)))
        print("%-10s %s" % (srv, " ".join("%14s" % c for c in cells)))

    print("\n== /auto?n= sweep: where Content-Length stops being computed ==")
    print("%-10s %s" % ("server", " ".join("%7d" % n for n in
                                           (64, 512, 1024, 2048, 4096, 8192, 16384, 65536))))
    for srv in servers:
        cells = []
        for n in (64, 512, 1024, 2048, 4096, 8192, 16384, 65536):
            hit = [r for r in rows if r[0] == srv and r[2] == "/auto?n=%d" % n
                   and r[1] == "curl"]
            cells.append({"content-length": "CL", "chunked": "chunk"}.get(
                hit[0][3] if hit else "", hit[0][3] if hit else "-"))
        print("%-10s %s" % (srv, " ".join("%7s" % c for c in cells)))

    print("\n== request header block, bytes (per client profile) ==")
    pct(rows, key=lambda r: int(r[5]), group=lambda r: r[1])
    print("\n== response header block, bytes (per server) ==")
    pct([r for r in rows if r[3] != "ERROR"], key=lambda r: int(r[6]),
        group=lambda r: r[0])


def pct(rows, key, group):
    groups = {}
    for r in rows:
        groups.setdefault(group(r), []).append(key(r))
    print("%-10s %6s %6s %6s %6s %6s %6s" % ("", "n", "min", "p50", "p90", "p99", "max"))
    allv = []
    for g in sorted(groups):
        v = sorted(groups[g])
        allv += v
        print("%-10s %6d %6d %6d %6d %6d %6d"
              % (g, len(v), v[0], q(v, 50), q(v, 90), q(v, 99), v[-1]))
    v = sorted(allv)
    print("%-10s %6d %6d %6d %6d %6d %6d"
          % ("ALL", len(v), v[0], q(v, 50), q(v, 90), q(v, 99), v[-1]))


def q(sorted_vals, p):
    if not sorted_vals:
        return 0
    i = min(len(sorted_vals) - 1, int(round((p / 100.0) * (len(sorted_vals) - 1))))
    return sorted_vals[i]


if __name__ == "__main__":
    if len(sys.argv) >= 5 and sys.argv[1] == "sweep":
        sweep(sys.argv[2], sys.argv[3], sys.argv[4])
    elif len(sys.argv) >= 3 and sys.argv[1] == "summary":
        summary(sys.argv[2:])
    else:
        sys.exit("usage: probe.py sweep NAME HOST PORT | probe.py summary FILE...")
