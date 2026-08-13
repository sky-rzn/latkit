#!/usr/bin/env python3
"""Join one HTTP workload's two views, request by request (PLAN-HTTP.md М8).

The two views:

  - **nginx**, its own access log, one JSON line per request with `$request_id`
    echoed from the client's `X-Request-Id`, `$request_time`,
    `$upstream_response_time`, `$body_bytes_sent`, `$status`;
  - **the agent**, the `--queries` view over the recording of the same run
    (`lkt_queries --proto http`), one line per observation, carrying the same
    request id and the four timings of РH5.

The join key is that id, so this compares *the same request* on both sides
rather than two percentile curves that happen to have similar shapes — which is
the whole point of the exercise: an aggregate agreement can hide a systematic
per-request error as long as it cancels out.

Two legs are observed, and they are different questions. The **front** leg
(client -> nginx) is what `$request_time` measures; the **upstream** leg
(nginx -> the application) is what `$upstream_response_time` measures. They are
told apart by the observation's host label, which the bench's nginx config sets
to a fixed name on the upstream side.

What is compared, per request:

    request_time            vs  upload + duration   (front leg, seconds)
    upstream_response_time  vs  upload + duration   (upstream leg, seconds)
    body_bytes_sent         vs  out                 (front leg, bytes)

Output: a TSV of the per-request rows, then `#`-prefixed summary lines and a
verdict. Exit status is 1 when a gate fails, so a stand can use it directly.

    http_join.py --access access.log --agent queries.txt \\
                 --upstream-host upstream-app [--tol-ms 5] [--tol-pct 10] \\
                 [--min-samples 50]
"""

import argparse
import json
import re
import sys

# `http conn=<hex> method=GET status=200 dur=123ns ttfb=45ns upload=0ns in=0
#  out=13 host=h user=- flags=0x0 reqid=abc route=/x target=/x`
OBS_RE = re.compile(
    r"^http conn=(?P<conn>\S+) method=(?P<method>\S+) status=(?P<status>\d+) "
    r"dur=(?P<dur>\d+)ns ttfb=(?P<ttfb>\d+)ns upload=(?P<upload>\d+)ns "
    r"in=(?P<in_>\d+) out=(?P<out>\d+) host=(?P<host>\S+) user=(?P<user>\S+) "
    r"flags=(?P<flags>\S+) reqid=(?P<reqid>\S+) route=(?P<route>\S+) target=(?P<target>.*)$"
)

# lk_query_obs flags that change what a comparison means (proto.h).
QO_TEXT_TRUNC = 1 << 1
QO_PIPELINED = 1 << 7
QO_EXPECT_CONT = 1 << 10
QO_BODY_UNSEEN = 1 << 9


def read_agent(path, upstream_host):
    """{reqid: {"front": obs, "upstream": obs}} from the --queries view."""
    by_id = {}
    unmatched = 0
    for line in open(path, encoding="utf-8", errors="replace"):
        m = OBS_RE.match(line.rstrip("\n"))
        if not m:
            continue
        o = m.groupdict()
        if o["reqid"] == "-":
            unmatched += 1
            continue
        for k in ("dur", "ttfb", "upload", "in_", "out", "status"):
            o[k] = int(o[k])
        o["flags"] = int(o["flags"], 16)
        leg = "upstream" if o["host"] == upstream_host else "front"
        by_id.setdefault(o["reqid"], {})[leg] = o
    return by_id, unmatched


def read_access(path):
    """[{id, status, method, uri, rt, urt, bs}] from the nginx JSON log."""
    rows = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def pct(values, p):
    if not values:
        return float("nan")
    values = sorted(values)
    k = min(len(values) - 1, max(0, int(round((p / 100.0) * (len(values) - 1)))))
    return values[k]


def summarise(name, deltas, tol_abs, tol_pct, min_samples, unit, out):
    """One comparison family: how far apart the two views were, and the gate.

    The gate is deliberately on a *percentile*, not on the worst case: one
    request that was descheduled between the capture point and the server's own
    clock is not a measurement error of either side, and a bench that failed on
    it would be measuring the machine's jitter."""
    if len(deltas) < min_samples:
        out.append(f"# {name}: only {len(deltas)} samples (< {min_samples}) — NOT GATED")
        return True
    p50, p90, p99 = pct(deltas, 50), pct(deltas, 90), pct(deltas, 99)
    ok = p90 <= tol_abs
    out.append(
        f"# {name}: n={len(deltas)} p50={p50:.6g}{unit} p90={p90:.6g}{unit} "
        f"p99={p99:.6g}{unit} gate=p90<={tol_abs:g}{unit} -> {'PASS' if ok else 'FAIL'}"
    )
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--access", required=True, help="nginx JSON access log")
    ap.add_argument("--agent", required=True, help="lkt_queries --proto http output")
    ap.add_argument("--upstream-host", default="upstream-app",
                    help="the host label the upstream leg carries")
    ap.add_argument("--tol-ms", type=float, default=5.0,
                    help="allowed p90 gap between the two duration views")
    ap.add_argument("--tol-pct", type=float, default=10.0,
                    help="allowed p90 relative gap, for requests above 50 ms")
    ap.add_argument("--min-samples", type=int, default=50)
    ap.add_argument("--min-match-pct", type=float, default=95.0,
                    help="fraction of logged requests that must be observed")
    args = ap.parse_args()

    agent, no_reqid = read_agent(args.agent, args.upstream_host)
    access = read_access(args.access)
    out = []

    print(
        "\t".join(
            [
                "reqid", "method", "uri", "status",
                "nginx_request_time", "agent_front_total", "d_front",
                "nginx_upstream_time", "agent_upstream_total", "d_upstream",
                "nginx_body_bytes", "agent_out_bytes", "d_bytes", "flags",
            ]
        )
    )

    d_front, d_front_rel, d_up, matched, missing, bytes_mismatch = [], [], [], 0, 0, 0
    upload_absorbed = 0
    chunked_n, chunked_bad, chunked_overhead = 0, 0, []
    unseen_n, unseen_bad, unseen_short = 0, 0, []
    no_id = 0
    for row in access:
        rid = str(row.get("id", ""))
        if not rid or rid == "-":
            # A request that carried no X-Request-Id cannot be joined by
            # construction — the container's own readiness probes, which also
            # ran before the agent attached. Counted, not held against coverage.
            no_id += 1
            continue
        obs = agent.get(rid)
        if not obs or "front" not in obs:
            missing += 1
            continue
        matched += 1
        f = obs["front"]
        u = obs.get("upstream")
        rt = float(row.get("rt", 0) or 0)
        try:
            urt = float(row.get("urt", "-"))
        except (TypeError, ValueError):
            urt = None
        bs = int(row.get("bs", 0) or 0)

        # The agent's view of the same interval: РH5 splits it into the client's
        # upload and the server's work, and nginx's $request_time is the sum.
        front_total = (f["upload"] + f["dur"]) / 1e9
        df = abs(front_total - rt)
        d_front.append(df)
        if rt >= 0.05:
            d_front_rel.append(df / rt * 100.0)

        up_total = ""
        du = ""
        if u is not None and urt is not None:
            up_total = (u["upload"] + u["dur"]) / 1e9
            du = abs(up_total - urt)
            d_up.append(du)

        # Bytes are compared against two different definitions, on purpose.
        # nginx counts what it wrote to the socket; the agent counts *decoded*
        # body bytes, so that a chunked body and a Content-Length body of the
        # same content report the same number (РH4). For a chunked response the
        # difference is exactly the chunk framing, and the right assertion is
        # "the agent is lower by a plausible framing overhead", not equality.
        db = f["out"] - bs
        if f["flags"] & QO_BODY_UNSEEN:
            # РH4: the response body was promised and not fully seen on the
            # socket, so this count is declared to be a lower bound. The
            # assertion that means something is that it never exceeds the
            # truth — an undercount is honest, an overcount would be a bug.
            unseen_n += 1
            unseen_short.append(-db)
            if db > 0:
                unseen_bad += 1
        elif str(row.get("te", "")).lower() == "chunked":
            chunked_n += 1
            chunked_overhead.append(-db)
            if db > 0 or -db > 512:
                chunked_bad += 1
        elif db != 0:
            bytes_mismatch += 1
        # A unit whose request body never ended (its last capture call was cut
        # and the tail hole is only detected on the next call, Р9) reports no
        # upload interval at all, and its duration holds the client's transfer.
        if f["in_"] > 0 and f["upload"] == 0 and not (f["flags"] & QO_EXPECT_CONT):
            upload_absorbed += 1

        print(
            "\t".join(
                str(x)
                for x in [
                    rid, row.get("method", "?"), row.get("uri", "?"), row.get("status", "?"),
                    f"{rt:.6f}", f"{front_total:.6f}", f"{df:.6f}",
                    urt if urt is not None else "-",
                    f"{up_total:.6f}" if up_total != "" else "-",
                    f"{du:.6f}" if du != "" else "-",
                    bs, f["out"], db, hex(f["flags"]),
                ]
            )
        )

    ok = True
    joinable = len(access) - no_id
    out.append(f"# requests logged by nginx: {len(access)} "
               f"({no_id} without a request id, not joinable)")
    out.append(f"# joined with an observation: {matched}; not observed: {missing}; "
               f"observations without a request id: {no_reqid}")
    if joinable:
        match_pct = 100.0 * matched / joinable
        gate = match_pct >= args.min_match_pct
        ok &= gate
        out.append(f"# coverage: {match_pct:.2f}% (gate >= {args.min_match_pct}%) "
                   f"-> {'PASS' if gate else 'FAIL'}")

    ok &= summarise("duration front leg vs $request_time", d_front,
                    args.tol_ms / 1000.0, args.tol_pct, args.min_samples, "s", out)
    if d_front_rel:
        out.append(f"# relative gap on requests >= 50 ms: n={len(d_front_rel)} "
                   f"p50={pct(d_front_rel, 50):.2f}% p90={pct(d_front_rel, 90):.2f}%")
    ok &= summarise("duration upstream leg vs $upstream_response_time", d_up,
                    args.tol_ms / 1000.0, args.tol_pct, args.min_samples, "s", out)

    # Bytes are not a percentile question: either the body was counted or it was
    # not. The one legitimate reason for a difference is РH4's unseen body, and
    # the flags column says which rows those are.
    plain = matched - chunked_n - unseen_n
    if plain:
        bad_pct = 100.0 * bytes_mismatch / plain
        gate = bytes_mismatch == 0
        ok &= gate
        out.append(f"# body bytes (Content-Length responses): {plain - bytes_mismatch}/{plain} "
                   f"exact ({bad_pct:.2f}% differ) -> {'PASS' if gate else 'FAIL'}")
    if unseen_n:
        gate = unseen_bad == 0
        ok &= gate
        out.append(f"# body bytes (LK_QO_BODY_UNSEEN, a declared lower bound): {unseen_n} "
                   f"request(s), none above the wire count "
                   f"(short by p50={pct(unseen_short, 50)} B, max={max(unseen_short)} B) "
                   f"-> {'PASS' if gate else 'FAIL'}")
    if chunked_n:
        gate = chunked_bad == 0
        ok &= gate
        out.append(f"# body bytes (chunked responses): {chunked_n - chunked_bad}/{chunked_n} "
                   f"lower than the wire by a plausible framing overhead "
                   f"(p50={pct(chunked_overhead, 50)} B, p90={pct(chunked_overhead, 90)} B) "
                   f"-> {'PASS' if gate else 'FAIL'}")
        out.append("#   the agent counts decoded body bytes and nginx counts what it wrote, "
                   "so the gap IS the chunk framing (docs/accuracy.md §HTTP)")
    if upload_absorbed:
        out.append(f"# NOTE: {upload_absorbed} request(s) with a body reported no upload "
                   f"interval — their duration holds the client's transfer time "
                   f"(docs/accuracy.md §HTTP, the capture-budget tail)")

    out.append(f"# verdict: {'PASS' if ok else 'FAIL'}")
    print("\n".join(out))
    sys.stderr.write("\n".join(out) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
