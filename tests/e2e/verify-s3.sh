#!/usr/bin/env bash
#
# Plaintext S3 e2e check (PLAN-MINIO.md МS4): MinIO, `mc` driving a fixed
# sequence with deliberate failures in it, optionally warp for volume, and one
# agent on `-p 9402=s3`.
#
# The plan's acceptance list for this stand, one assertion each:
#
#   - `latkit_s3_requests_total` grows;
#   - durations and TTFB are non-zero and plausible, and the two are different
#     numbers rather than one printed twice (РH5);
#   - the injected 404 and 403 are visible **with the right S3 code** — which is
#     the assertion the HTTP stand cannot make, because at the HTTP level a
#     missing key and a missing bucket are the same `404` (РS5);
#   - the bucket and the access key are correct, and both are labels (РS3/РS4);
#   - no object key appears anywhere in the exposition (РS2, РH12) — and the
#     load deliberately creates keys named after a counter so their absence is
#     checkable rather than assumed;
#   - the blind zones are zero on an HTTP/1.1 run (РH4, and МS0 recon item 1:
#     MinIO selects http/1.1 for every real client's ALPN offer).
#
# Two more the stand is uniquely able to make:
#
#   - the health probes MinIO answers all day are counted as `internal` and
#     appear in no family that says "requests" (РS2) — on this stand they are a
#     handful, on a distributed pool they are four fifths of the port;
#   - `op="other"` is zero: every request this load makes is a row of the
#     operation table, which is the claim the table exists to support.
#
# Needs Docker and BPF privileges. Like the other stands, this is a manual /
# optional check where a runner lacks them.
#
#   ./verify-s3.sh              # build, up, assert, down
#   KEEP=1 ./verify-s3.sh       # leave the stand running
#   WARP=1 ./verify-s3.sh       # also run the warp profile and re-assert
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)
COMPOSE="docker compose -p latkit-s3 -f docker-compose.s3.yml"
PROM=http://localhost:19094
fails=0

tmp=$(mktemp -d)

log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
pass() { printf '  ok   - %s\n' "$*"; }
fail() { printf '  FAIL - %s\n' "$*"; fails=$((fails + 1)); }

cleanup() {
    rm -rf "$tmp"
    if [ "${KEEP:-0}" = "1" ]; then
        log "KEEP=1 — leaving the stand up ('$COMPOSE down -v' to stop)"
        return
    fi
    log "tearing down"
    $COMPOSE --profile warp down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

promql() { curl -sG "$PROM/api/v1/query" --data-urlencode "query=$1"; }
scalar_of() {
    promql "$1" | python3 -c '
import json, sys
r = json.load(sys.stdin).get("data", {}).get("result", [])
print(r[0]["value"][1] if r else "")
'
}
# All values of one label across a family, one per line.
labels_of() {
    promql "$1" | python3 -c '
import json, sys
key = sys.argv[1]
res = json.load(sys.stdin).get("data", {}).get("result", [])
print("\n".join(sorted({m["metric"].get(key, "") for m in res})))
' "$2"
}
gt() { [ -n "$1" ] && python3 -c "import sys; sys.exit(0 if float('$1')>${2:-0} else 1)"; }
is0() { python3 -c "import sys; sys.exit(0 if float('${1:-0}') == 0 else 1)"; }

# --- 0. build the agent -----------------------------------------------------
log "building the agent"
cmake --build "$REPO_ROOT/build" --target latkit -j"$(nproc)" >/dev/null
note "built $REPO_ROOT/build/latkit"

# --- 1. up ------------------------------------------------------------------
log "bringing the S3 stand up (MinIO :9402, mc load, agent -p 9402=s3)"
$COMPOSE up -d --build
note "waiting for load to accumulate and Prometheus to scrape"
sleep 30

if ! $COMPOSE ps latkit | grep -q ' Up\| running'; then
    fail "latkit container is not running (BPF privileges? see '$COMPOSE logs latkit')"
    $COMPOSE logs --tail=30 latkit || true
    exit 1
fi

[ "$(scalar_of 'up{job="latkit"}')" = "1" ] && pass "target up{job=latkit} == 1" \
    || fail "Prometheus cannot scrape the agent (up != 1)"

# --- 2. observations exist and grow -----------------------------------------
log "S3 observations"
r1=$(scalar_of 'sum(latkit_s3_requests_total)')
note "sum(latkit_s3_requests_total) = ${r1:-<none>}"
gt "$r1" && pass "S3 operations observed" || fail "no S3 observations at all"

sleep 8
r2=$(scalar_of 'sum(latkit_s3_requests_total)')
note "sum after +8s = ${r2:-<none>}"
if [ -n "$r2" ] && python3 -c "import sys; sys.exit(0 if float('$r2')>float('$r1') else 1)"; then
    pass "requests_total increasing under load"
else
    fail "requests_total did not grow"
fi

# --- 3. the operation label is a table value, everywhere --------------------
log "operations (РS2)"
ops=$(labels_of 'latkit_s3_requests_total' op)
note "operations: $(echo "$ops" | tr '\n' ' ')"
# DeleteObjects, not DeleteObject: `mc rm` batches its deletions into a single
# `POST ?delete`, which is one operation and not N deletions (§1 of the plan —
# the keys are in a request body we do not read).
for want in PutObject GetObject HeadObject ListObjectsV2 DeleteObjects; do
    echo "$ops" | grep -qx "$want" && pass "$want observed" || fail "$want missing from the load"
done
if echo "$ops" | grep -qE '[/%?]'; then
    fail "an operation label carries a path: $ops"
else
    pass "no operation label contains a slash, a query or an escape"
fi
# `op` is bounded by construction (a closed table), so this is not a
# cardinality warning like the HTTP stand's route check — it is an ageing one.
other=$(scalar_of 'sum(latkit_s3_requests_total{op="other"})')
note "op=\"other\" = ${other:-0}"
is0 "$other" && pass "every request the load makes is a row of the table" \
    || fail "op=\"other\" is non-zero ($other) — the taxonomy has a hole"

# --- 4. bucket and access key (РS3/РS4) -------------------------------------
log "the two dimensions of an S3 request"
buckets=$(labels_of 'latkit_s3_requests_total' bucket)
note "buckets: $(echo "$buckets" | tr '\n' ' ')"
echo "$buckets" | grep -qx lkbucket && pass "the bucket is a label" \
    || fail "bucket=lkbucket not found (path-style extraction, РS3)"
users=$(labels_of 'latkit_s3_requests_total' user)
note "access keys: $(echo "$users" | tr '\n' ' ')"
echo "$users" | grep -qx lkroot && pass "the access key is a label" \
    || fail "user=lkroot not found (SigV4 Credential=, РS4)"
echo "$users" | grep -qx - && pass "the anonymous request is \`-\`, not an invented identity" \
    || note "no anonymous request observed in this window (wget missing from the mc image?)"

# --- 5. the failures have names, not just statuses (РS5) --------------------
log "S3 error codes"
codes=$(labels_of 'latkit_s3_errors_total' s3code)
note "codes: $(echo "$codes" | tr '\n' ' ')"
for want in NoSuchKey NoSuchBucket; do
    gt "$(scalar_of "sum(latkit_s3_errors_total{s3code=\"$want\"})")" \
        && pass "$want distinguished behind its 404" \
        || fail "$want missing — the error body was not read (РS5)"
done
if gt "$(scalar_of 'sum(latkit_s3_errors_total{s3code=~"SignatureDoesNotMatch|AccessDenied|InvalidAccessKeyId"})')"; then
    pass "the refused caller's failure is named"
else
    fail "no 403 code observed — the bad-credential load did not land"
fi
# The numeric fallback is what a server that sent no code would produce. On
# MinIO every failure carries one, so seeing a status here means a body (or the
# x-minio-error-code header) was missed.
if echo "$codes" | grep -qE '^[0-9]+$'; then
    fail "a failure fell back to its numeric status: $(echo "$codes" | grep -E '^[0-9]+$' | tr '\n' ' ')"
else
    pass "no failure fell back to a bare HTTP status"
fi
# The access key that sent the bad signature is on the error series: РS4's
# actual use case, and the one thing a status-only view cannot answer.
gt "$(scalar_of 'sum(latkit_s3_errors_total{user="lkbad"})')" \
    && pass "the failed authentication is attributed to its access key" \
    || note "no error series under user=lkbad (MinIO may refuse before reading the key)"

# --- 6. the timings (РH5), and that they are two numbers --------------------
log "timings"
p95=$(scalar_of 'histogram_quantile(0.95, sum(rate(latkit_s3_request_duration_seconds_bucket[3m])) by (le))')
note "p95 duration = ${p95:-<none>} s"
if [ -n "$p95" ] && python3 -c "import sys; v=float('$p95'); sys.exit(0 if 0<=v<60 else 1)" 2>/dev/null; then
    pass "duration p95 is a plausible latency (0..60 s)"
else
    fail "p95 missing or out of range"
fi
gt "$(scalar_of 'sum(latkit_s3_ttfb_seconds_count)')" \
    && pass "TTFB is recorded separately from the duration" || fail "no TTFB series"
# The 1 MB upload is the one shape where the client's transfer is a measurable
# interval of its own, and it is the reason the upload family exists.
up=$(scalar_of 'sum(latkit_s3_request_upload_seconds_count{op="PutObject"})')
note "upload intervals on PutObject = ${up:-0}"
gt "${up:-0}" && pass "the client's upload time is measured apart from the server's work" \
    || fail "no upload series — РH5's third timing is missing on an object store"

# --- 7. РS6: the object size, not the wire size -----------------------------
log "object sizes (РS6)"
osz=$(scalar_of 'sum(latkit_s3_object_size_bytes_count)')
note "object-size samples = ${osz:-0}"
gt "${osz:-0}" && pass "the size distribution has samples" || fail "no object-size histogram"

# The discriminating measurement of РS6, and it needs no knowledge of the load
# beyond "mc uploads through aws-chunked": the *object* bytes must be strictly
# fewer than the *wire* bytes, and by the framing's own small margin. If the
# histogram were fed from the wire count the ratio would be exactly 1; if
# something double-counted, it would exceed it.
ratio=$(scalar_of 'sum(latkit_s3_object_size_bytes_sum{op="PutObject"}) / sum(latkit_s3_bytes_total{op="PutObject",direction="in"})')
note "object bytes / wire bytes on PutObject = ${ratio:-<none>}"
if [ -n "$ratio" ] && python3 -c "import sys; r=float('$ratio'); sys.exit(0 if 0.90 < r < 1.0 else 1)"; then
    pass "the object is smaller than the stream that carried it — the aws-chunked discount (РS6)"
else
    fail "object/wire ratio $ratio: 1.0 means the histogram is fed from the wire count"
fi
# And the distribution sits where the objects are: the load's largest is exactly
# 1 MiB, so on an octave grid a wire-fed histogram would put it one bucket up.
p90=$(scalar_of 'histogram_quantile(0.9, sum(rate(latkit_s3_object_size_bytes_bucket{op="PutObject"}[3m])) by (le))')
note "p90 object size = ${p90:-<none>} B"
if [ -n "$p90" ] && python3 -c "import sys; v=float('$p90'); sys.exit(0 if 524288 < v <= 1048576 else 1)" 2>/dev/null; then
    pass "the 1 MiB upload is one mebibyte in the distribution, not 1 MiB + chunk framing"
else
    fail "p90 object size is $p90, not the 1 MiB the load uploads"
fi
gt "$(scalar_of 'sum(latkit_s3_bytes_total{direction="in"})')" 1000000 \
    && pass "request body bytes accounted (> 1 MB uploaded)" || fail "request bytes not accounted"
gt "$(scalar_of 'sum(latkit_s3_bytes_total{direction="out"})')" 1000000 \
    && pass "response body bytes accounted (> 1 MB downloaded)" || fail "response bytes not accounted"

# --- 8. MinIO's own surface is counted and nothing else (РS2) ---------------
log "the server's own API"
int=$(scalar_of 'latkit_s3_internal_requests_total')
note "latkit_s3_internal_requests_total = ${int:-0}"
gt "${int:-0}" && pass "the health probes are counted as internal" \
    || fail "no internal requests counted — is the healthcheck running?"
is0 "$(scalar_of 'sum(latkit_s3_requests_total{op="internal"})')" \
    && pass "and appear in no family that says \"requests\"" \
    || fail "an internal request reached latkit_s3_requests_total"
is0 "$(scalar_of 'sum(latkit_s3_requests_total{bucket="minio"})')" \
    && pass "no /minio/... path was read as a bucket called minio" \
    || fail "the /minio/ prefix was checked after the bucket rules, not before"

# --- 9. the privacy invariant, on live traffic ------------------------------
log "no object key in the exposition (РS2, РH12)"
if curl -s "http://localhost:9757/metrics" > "$tmp/metrics.txt"; then
    # The load names every object after a counter, so `obj-<n>` / `big-<n>` are
    # exactly the strings that must not be there.
    if grep -qE '(obj|big)-[0-9]+' "$tmp/metrics.txt"; then
        fail "an object key reached the exposition"
        grep -m3 -E '(obj|big)-[0-9]+' "$tmp/metrics.txt" | sed 's/^/      /'
    else
        pass "no object key in $(wc -l < "$tmp/metrics.txt") exposition lines"
    fi
    # Structural, like the trace-corpus check: every s3 label value is an
    # operation, a method, a validated bucket, an access key or a bounded enum,
    # and none of those alphabets contains a slash, a space or an escape.
    if grep '^latkit_s3_' "$tmp/metrics.txt" | grep -oE '[a-z0-9_]+="[^"]*"' | sort -u |
       grep -qE '="[^"]*([/% ]|\.\.)'; then
        fail "a metric label carries a path byte:"
        grep '^latkit_s3_' "$tmp/metrics.txt" | grep -oE '[a-z0-9_]+="[^"]*"' | sort -u |
            grep -E '="[^"]*([/% ]|\.\.)' | head -3 | sed 's/^/      /'
    else
        pass "no label value contains a slash, a space or a percent-escape"
    fi
else
    fail "could not scrape the agent directly"
fi

# --- 10. nothing went blind, nothing was lost -------------------------------
log "health"
blind=$(scalar_of 'sum(latkit_ignored_conns_total{proto="s3"})')
note "ignored_conns{proto=s3} = ${blind:-0}"
is0 "$blind" && pass "no connection fell into a blind zone (HTTP/1.1 throughout, МS0 item 1)" \
    || fail "a connection went blind ($blind) — h2 over ALPN, or an upgrade?"

pe=$(scalar_of 'sum(latkit_parse_errors_total)')
note "parse_errors_total = ${pe:-0}"
is0 "$pe" && pass "no parse errors on clean traffic" || fail "parse errors on clean traffic ($pe)"

drops=$(scalar_of 'sum(latkit_ringbuf_dropped_total)')
note "ringbuf_dropped_total = ${drops:-0}"
is0 "$drops" && pass "no ringbuf drops at this rate" \
    || note "ringbuf drops: $drops (rate-dependent, not fatal at this stage)"

# --- 11. optional: the same stand under warp --------------------------------
# Volume, and the one place the МS4 drop-rate claim can be looked at without the
# full perf bench: warp mixed at 1 MiB objects is real object-store traffic.
if [ "${WARP:-0}" = "1" ]; then
    log "warp (mixed, 4 concurrent, 1 MiB objects)"
    if $COMPOSE --profile warp run --rm warp 2>&1 | tail -8; then
        sleep 10
        r3=$(scalar_of 'sum(latkit_s3_requests_total)')
        note "sum after warp = ${r3:-<none>}"
        if [ -n "$r3" ] && python3 -c "import sys; sys.exit(0 if float('$r3')>float('$r2')+1000 else 1)"; then
            pass "warp's operations were observed too"
        else
            fail "warp did not move requests_total by a warp-sized amount"
        fi
        pe2=$(scalar_of 'sum(latkit_parse_errors_total)')
        is0 "$pe2" && pass "still no parse errors after warp" \
            || fail "warp produced parse errors ($pe2)"
        d2=$(scalar_of 'sum(latkit_ringbuf_dropped_total)')
        ev=$(scalar_of 'sum(latkit_events_total)')
        note "ringbuf drops=${d2:-0} of events=${ev:-0}"
        if python3 -c "import sys; d=float('${d2:-0}'); e=float('${ev:-0}'); sys.exit(0 if e>0 and d <= 0.01*e else 1)"; then
            pass "drop rate under 1 % at warp volume (the РH14 budget holding)"
        else
            fail "drop rate above 1 % — see tests/bench/run-s3.sh for the real measurement"
        fi
    else
        note "warp image unavailable — volume leg skipped (the checks above stand)"
    fi
fi

# --- verdict -----------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  S3 (plaintext, MinIO) e2e: all checks passed"
    exit 0
fi
echo "  S3 (plaintext, MinIO) e2e: $fails check(s) failed"
exit 1
