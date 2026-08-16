#!/usr/bin/env python3
"""Join one S3 workload's two views, request by request (PLAN-MINIO.md МS4).

The two views:

  - **MinIO**, through `mc admin trace -v --json --call s3`: one object per S3
    request, carrying the server's own `callStats` (duration, time to first
    byte, bytes in and out), the operation *it* thinks the request was, its
    status, and the `X-Amz-Request-Id` it answered with;
  - **the agent**, the `--queries` view over the recording of the same run
    (`lkt_queries --proto s3`), one line per observation, carrying the same
    request id and the four timings of РH5.

The join key is that id, so this compares *the same request* on both sides
rather than two percentile curves of similar shape — an aggregate agreement can
hide a systematic per-request error as long as it cancels out. It is also the
one thing an S3 accuracy bench can do that the HTTP one could not: the reference
here is not a log line the server wrote about latency, it is the server naming
the operation, so `op` can be checked against the authority on what `op` means.

What is compared, per request:

    callStats.duration        vs  upload + dur     (ns)
    callStats.timeToFirstByte vs  upload + ttfb    (ns)
    callStats.tx              vs  out              (bytes, exact)
    api ("s3.GetObject")      vs  route            (the taxonomy, РS2)
    statusCode                vs  status           (exact)

Two of those need a word about *why* the left and right sides are shaped the way
they are.

**The timings.** MinIO measures both of its numbers from the same origin — the
moment the request arrived — so its `timeToFirstByte` includes the time it spent
reading the request body. РH5 splits that interval in two on purpose (`upload`
is the client's, `dur` and `ttfb` are the server's), because on an object store
a slow uploader and a slow server are different incidents. Adding `upload` back
is therefore not a fudge to make the numbers agree: it is the statement that the
split is exact, and a bench that compared `ttfb` against `timeToFirstByte`
directly would be asserting that MinIO makes the same distinction, which it does
not.

**The bytes.** `callStats.tx` is the response body and matches `out` exactly.
`callStats.rx` is *not* the request's wire bytes — MinIO adds a fixed ~93-byte
estimate for the head and counts the aws-chunked stream as it decodes it — so it
is reported for information and never gated. The object-size claim of РS6 is
checked where it can be: in the e2e stand's exposition, against the wire counter.

Output: a TSV of the per-request rows, then `#`-prefixed summary lines and a
verdict. Exit status is 1 when a gate fails, so a stand can use it directly.

    s3_join.py --trace trace.json --agent queries.txt [--tol-ms 5]
               [--min-samples 50] [--min-match-pct 95]
"""

import argparse
import json
import re
import sys

# `http conn=<hex> method=GET status=200 dur=123ns ttfb=45ns upload=0ns in=0
#  out=13 obj=13 host=b user=u flags=0x0 err=- reqid=ABC route=GetObject
#  target=/b/k`
OBS_RE = re.compile(
    r"^http conn=(?P<conn>\S+) method=(?P<method>\S+) status=(?P<status>\d+) "
    r"dur=(?P<dur>\d+)ns ttfb=(?P<ttfb>\d+)ns upload=(?P<upload>\d+)ns "
    r"in=(?P<in_>\d+) out=(?P<out>\d+) obj=(?P<obj>\d+) host=(?P<host>\S+) "
    r"user=(?P<user>\S+) flags=(?P<flags>\S+) err=(?P<err>\S+) reqid=(?P<reqid>\S+) "
    r"route=(?P<route>\S+) target=(?P<target>.*)$"
)

QO_BODY_UNSEEN = 1 << 9
QO_PIPELINED = 1 << 7

# MinIO's internal name for an operation is not always the S3 API's name, and
# the difference is the server's, not ours: `s3.GetBucketObjectLockConfig` is
# what MinIO calls the handler, `GetObjectLockConfiguration` is what the S3 API
# calls the request. Listed here rather than papered over inside the classifier,
# because the classifier's contract is to produce the *API's* names — those are
# what an operator reads in AWS documentation and in an IAM policy.
#
# A pair that is not on this list and does not match is a real disagreement, and
# the report prints it: that is the "the S3 API grew and the table did not"
# signal of risk 5, arriving from the server itself rather than from a rising
# `op="other"` share.
MINIO_API_ALIASES = {
    "GetBucketObjectLockConfig": "GetObjectLockConfiguration",
    "PutBucketObjectLockConfig": "PutObjectLockConfiguration",
    "DeleteMultipleObjects": "DeleteObjects",
    "NewMultipartUpload": "CreateMultipartUpload",
    "CompleteMultipartUpload": "CompleteMultipartUpload",
    "AbortMultipartUpload": "AbortMultipartUpload",
    "PutObjectPart": "UploadPart",
    "ListObjectPartsHandler": "ListParts",
    "ListObjectParts": "ListParts",
    "ListMultipartUploads": "ListMultipartUploads",
    "GetBucketVersioning": "GetBucketVersioning",
    "GetBucketReplicationConfig": "GetBucketReplication",
    "GetBucketEncryption": "GetBucketEncryption",
    "GetBucketLifecycleConfig": "GetBucketLifecycleConfiguration",
    "PutBucketLifecycleConfig": "PutBucketLifecycleConfiguration",
    "GetBucketNotification": "GetBucketNotificationConfiguration",
    "PutBucketNotification": "PutBucketNotificationConfiguration",
    "GetBucketTagging": "GetBucketTagging",
    "DeleteBucketTagging": "DeleteBucketTagging",
    "GetObjectTagging": "GetObjectTagging",
    "PutObjectTagging": "PutObjectTagging",
    "DeleteObjectTagging": "DeleteObjectTagging",
    "GetBucketPolicy": "GetBucketPolicy",
    "HeadBucket": "HeadBucket",
    "ListObjectsV1": "ListObjects",
    "ListObjectsV2M": "ListObjectsV2",
    "ListObjectVersions": "ListObjectVersions",
    "ListBuckets": "ListBuckets",
}


def read_trace(path):
    """{request-id: {...}} from `mc admin trace -v --json`.

    The stream is a sequence of JSON objects, pretty-printed by recent `mc`
    rather than one per line, so it is decoded with raw_decode over the whole
    text instead of line by line. Nothing but the fields below is retained —
    verbose mode includes response *bodies*, and an error body carries the
    object key (РS5), which has no business in a bench artefact.
    """
    txt = open(path, encoding="utf-8", errors="replace").read()
    dec = json.JSONDecoder()
    rows, i, bad = {}, 0, 0
    while i < len(txt):
        while i < len(txt) and txt[i] in " \r\n\t":
            i += 1
        if i >= len(txt):
            break
        try:
            obj, i = dec.raw_decode(txt, i)
        except ValueError:
            bad += 1
            break
        if obj.get("type") != "S3":
            continue
        resp = obj.get("response") or {}
        hdrs = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        rid = hdrs.get("x-amz-request-id")
        if not rid:
            continue
        cs = obj.get("callStats") or {}
        api = str(obj.get("api", ""))
        rows[rid] = {
            "api": api[3:] if api.startswith("s3.") else api,
            "method": (obj.get("request") or {}).get("method", "?"),
            "path": obj.get("path", ""),
            "status": int(resp.get("statusCode") or obj.get("statusCode") or 0),
            "duration": int(cs.get("duration") or 0),
            "ttfb": int(cs.get("timeToFirstByte") or 0),
            "rx": int(cs.get("rx") or 0),
            "tx": int(cs.get("tx") or 0),
        }
    return rows, bad


def read_agent(path):
    """{request-id: obs} from the --queries view; also the count with no id."""
    by_id, no_id, internal = {}, 0, 0
    for line in open(path, encoding="utf-8", errors="replace"):
        m = OBS_RE.match(line.rstrip("\n"))
        if not m:
            continue
        o = m.groupdict()
        if o["route"] == "internal":
            internal += 1
            continue
        if o["reqid"] == "-":
            no_id += 1
            continue
        for k in ("dur", "ttfb", "upload", "in_", "out", "obj", "status"):
            o[k] = int(o[k])
        o["flags"] = int(o["flags"], 16)
        by_id[o["reqid"]] = o
    return by_id, no_id, internal


def pct(values, p):
    if not values:
        return float("nan")
    values = sorted(values)
    k = min(len(values) - 1, max(0, int(round((p / 100.0) * (len(values) - 1)))))
    return values[k]


def summarise(name, deltas, tol_abs, min_samples, unit, out):
    """One comparison family: how far apart the two views were, and the gate.

    On a percentile, not the worst case: one request descheduled between the
    capture point and the server's own clock is not a measurement error of
    either side, and a bench that failed on it would be measuring the machine."""
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
    ap.add_argument("--trace", required=True, help="mc admin trace -v --json output")
    ap.add_argument("--agent", required=True, help="lkt_queries --proto s3 output")
    ap.add_argument("--tol-ms", type=float, default=5.0)
    ap.add_argument("--min-samples", type=int, default=50)
    ap.add_argument("--min-match-pct", type=float, default=95.0)
    ap.add_argument("--min-op-pct", type=float, default=99.0,
                    help="fraction of joined requests whose operation must agree "
                         "with MinIO's own name for it")
    args = ap.parse_args()

    trace, bad = read_trace(args.trace)
    agent, no_id, internal = read_agent(args.agent)
    out = []

    print("\t".join([
        "reqid", "minio_api", "agent_op", "method", "status_minio", "status_agent",
        "minio_duration_s", "agent_total_s", "d_duration",
        "minio_ttfb_s", "agent_ttfb_s", "d_ttfb",
        "minio_tx", "agent_out", "d_bytes", "flags",
    ]))

    d_dur, d_ttfb, d_dur_rel = [], [], []
    matched = missing = bytes_mismatch = status_mismatch = 0
    unseen_n = unseen_bad = 0
    op_ok = 0
    op_disagree = {}
    for rid, t in trace.items():
        o = agent.get(rid)
        if not o:
            missing += 1
            continue
        matched += 1

        # The agent's view of the same interval: РH5 splits it into the client's
        # upload and the server's work; MinIO measures the whole thing.
        total = o["upload"] + o["dur"]
        ttfb = o["upload"] + o["ttfb"]
        dd = abs(total - t["duration"]) / 1e9
        dt = abs(ttfb - t["ttfb"]) / 1e9
        d_dur.append(dd)
        d_ttfb.append(dt)
        if t["duration"] >= 50e6:
            d_dur_rel.append(dd / (t["duration"] / 1e9) * 100.0)

        db = o["out"] - t["tx"]
        if o["flags"] & QO_BODY_UNSEEN:
            unseen_n += 1
            if db > 0:
                unseen_bad += 1
        elif db != 0:
            bytes_mismatch += 1
        if o["status"] != t["status"]:
            status_mismatch += 1

        want = MINIO_API_ALIASES.get(t["api"], t["api"])
        if o["route"] == want or o["route"] == t["api"]:
            op_ok += 1
        else:
            op_disagree[(t["api"], o["route"])] = op_disagree.get((t["api"], o["route"]), 0) + 1

        print("\t".join(str(x) for x in [
            rid, t["api"], o["route"], t["method"], t["status"], o["status"],
            "%.6f" % (t["duration"] / 1e9), "%.6f" % (total / 1e9), "%.6f" % dd,
            "%.6f" % (t["ttfb"] / 1e9), "%.6f" % (ttfb / 1e9), "%.6f" % dt,
            t["tx"], o["out"], db, hex(o["flags"]),
        ]))

    ok = True
    out.append(f"# S3 requests traced by MinIO: {len(trace)}"
               + (f" (trace stream truncated after {bad} bad object(s))" if bad else ""))
    out.append(f"# joined with an observation: {matched}; not observed: {missing}; "
               f"observations with no request id: {no_id}; "
               f"internal (/minio/..., never an operation): {internal}")
    if trace:
        match_pct = 100.0 * matched / len(trace)
        gate = match_pct >= args.min_match_pct
        ok &= gate
        out.append(f"# coverage: {match_pct:.2f}% (gate >= {args.min_match_pct}%) "
                   f"-> {'PASS' if gate else 'FAIL'}")

    ok &= summarise("duration vs callStats.duration", d_dur,
                    args.tol_ms / 1000.0, args.min_samples, "s", out)
    if d_dur_rel:
        out.append(f"# relative gap on requests >= 50 ms: n={len(d_dur_rel)} "
                   f"p50={pct(d_dur_rel, 50):.2f}% p90={pct(d_dur_rel, 90):.2f}%")
    ok &= summarise("upload+ttfb vs callStats.timeToFirstByte", d_ttfb,
                    args.tol_ms / 1000.0, args.min_samples, "s", out)

    plain = matched - unseen_n
    if plain:
        gate = bytes_mismatch == 0
        ok &= gate
        out.append(f"# response bytes vs callStats.tx: {plain - bytes_mismatch}/{plain} "
                   f"exact -> {'PASS' if gate else 'FAIL'}")
    if unseen_n:
        gate = unseen_bad == 0
        ok &= gate
        out.append(f"# response bytes (LK_QO_BODY_UNSEEN, a declared lower bound): "
                   f"{unseen_n} request(s), none above the server's count "
                   f"-> {'PASS' if gate else 'FAIL'}")
    gate = status_mismatch == 0
    ok &= gate
    out.append(f"# status: {matched - status_mismatch}/{matched} exact "
               f"-> {'PASS' if gate else 'FAIL'}")

    if matched:
        op_pct = 100.0 * op_ok / matched
        gate = op_pct >= args.min_op_pct
        ok &= gate
        out.append(f"# operation agrees with MinIO's own name: {op_pct:.2f}% "
                   f"(gate >= {args.min_op_pct}%) -> {'PASS' if gate else 'FAIL'}")
        for (api, route), n in sorted(op_disagree.items(), key=lambda kv: -kv[1]):
            out.append(f"#   disagreement x{n}: MinIO says {api}, we say {route}")
        if op_disagree:
            out.append("#   ^ each of these is either a row missing from the table in "
                       "docs/notes-s3proto.md or a name MinIO spells its own way "
                       "(MINIO_API_ALIASES in this file)")

    out.append(f"# verdict: {'PASS' if ok else 'FAIL'}")
    print("\n".join(out))
    sys.stderr.write("\n".join(out) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
