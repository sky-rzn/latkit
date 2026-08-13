#!/usr/bin/env bash
#
# Plaintext HTTP e2e check (PLAN-HTTP.md М8): nginx in front of a Go backend,
# both legs observed, load from curl, latkit with two http ports.
#
# The plan's acceptance list for this leg, one assertion each:
#
#   - latkit_http_requests_total exists and grows;
#   - the durations and TTFB are non-zero and plausible, and /slow proves the
#     two are different numbers (РH5) rather than the same one printed twice;
#   - the injected 500 and 404 are both visible and told apart (РH10);
#   - every route label is templated — not one raw id survives anywhere in the
#     exposition (РH7), which is the check that keeps cardinality bounded;
#   - on an HTTP/1.1-only stand the blind zones are zero (РH4): whatever the
#     agent did not report, it was not because it stopped looking.
#
# Two more the stand is uniquely able to make, and the trace corpus cannot:
#
#   - the two legs of a reverse proxy do not merge into one series;
#   - a body sent with `sendfile on` is accounted to the byte on this kernel —
#     М0 measured that claim on 6.5+, and here it meets a live agent.
#
# Needs Docker, BPF privileges and a Go toolchain (the backend is built on the
# host, like the Go-TLS stand's server). Like the other stands, this is a
# manual/optional check where a runner lacks them.
#
#   ./verify-http.sh              # build, up, assert, down
#   KEEP=1 ./verify-http.sh       # leave the stand running
#   BURST=1 ./verify-http.sh      # also run the wrk burst profile
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)
COMPOSE="docker compose -p latkit-http -f docker-compose.http.yml"
PROM=http://localhost:19092
fails=0

log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
pass() { printf '  ok   - %s\n' "$*"; }
fail() { printf '  FAIL - %s\n' "$*"; fails=$((fails + 1)); }

cleanup() {
    if [ "${KEEP:-0}" = "1" ]; then
        log "KEEP=1 — leaving the stand up ('$COMPOSE down -v' to stop)"
        return
    fi
    log "tearing down"
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

promql() { curl -sG "$PROM/api/v1/query" --data-urlencode "query=$1"; }
scalar_of() {
    promql "$1" | python3 -c '
import json, sys
d = json.load(sys.stdin)
r = d.get("data", {}).get("result", [])
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

# --- 0. build the agent and the backend on the host --------------------------
log "building the agent and the backend on the host"
cmake --build "$REPO_ROOT/build" --target latkit -j"$(nproc)" >/dev/null
note "built $REPO_ROOT/build/latkit"
if ! command -v go >/dev/null; then
    echo "  go toolchain not found — the backend cannot be built" >&2
    exit 1
fi
(cd httpbackend && CGO_ENABLED=0 go build -o "$REPO_ROOT/build/httpbackend" .)
note "built $REPO_ROOT/build/httpbackend"

# --- 1. bring the stand up ---------------------------------------------------
log "bringing the HTTP stand up (nginx 8080 -> Go backend 8081)"
$COMPOSE up -d --build
note "waiting for load to accumulate and Prometheus to scrape"
sleep 30

if ! $COMPOSE ps latkit | grep -q ' Up\| running'; then
    fail "latkit container is not running (BPF privileges? see '$COMPOSE logs latkit')"
    $COMPOSE logs --tail=30 latkit || true
    exit 1
fi

# --- 2. observations exist and grow ------------------------------------------
log "HTTP observations"
[ "$(scalar_of 'up{job="latkit"}')" = "1" ] && pass "target up{job=latkit} == 1" \
    || fail "Prometheus cannot scrape the agent (up != 1)"

r1=$(scalar_of 'sum(latkit_http_requests_total)')
note "sum(latkit_http_requests_total) = ${r1:-<none>}"
gt "$r1" && pass "HTTP exchanges observed" || fail "no HTTP observations at all"

sleep 6
r2=$(scalar_of 'sum(latkit_http_requests_total)')
note "sum after +6s = ${r2:-<none>}"
if [ -n "$r2" ] && python3 -c "import sys; sys.exit(0 if float('$r2')>float('$r1') else 1)"; then
    pass "requests_total increasing under load"
else
    fail "requests_total did not grow"
fi

# --- 3. the route label is a template, everywhere ----------------------------
log "route templating (РH7)"
routes=$(labels_of 'latkit_http_requests_total' route)
note "routes: $(echo "$routes" | tr '\n' ' ')"
echo "$routes" | grep -q '^/json/{id}$' \
    && pass "the id-bearing path came back as /json/{id}" \
    || fail "no templated route — the id survived into the label, or nothing was observed"
if echo "$routes" | grep -qE '/[0-9]+($|/)'; then
    fail "a raw numeric segment reached a route label: $routes"
else
    pass "no raw id in any route label"
fi
if echo "$routes" | grep -q '?'; then
    fail "a query string reached a route label: $routes"
else
    pass "no query string in any route label"
fi
# The whole point of the third layer (top-K + doorkeeper): the label set stays
# small however many distinct paths the load walks through.
nroutes=$(echo "$routes" | grep -c .)
note "distinct routes: $nroutes"
[ "$nroutes" -le 32 ] && pass "route cardinality bounded ($nroutes series keys)" \
    || fail "route cardinality is running away ($nroutes)"

# --- 4. statuses: 4xx and 5xx are different things (РH10) --------------------
log "status classes"
gt "$(scalar_of 'sum(latkit_http_requests_total{status="5xx"})')" \
    && pass "5xx observed (the /boom route)" || fail "no 5xx observed"
gt "$(scalar_of 'sum(latkit_http_requests_total{status="4xx"})')" \
    && pass "4xx observed (the /nope route)" || fail "no 4xx observed"
gt "$(scalar_of 'latkit_http_errors_total{code="500"}')" \
    && pass "errors_total{code=500} > 0" || fail "the 500 was not counted under its code"
# The latency series is where the two part company: a 404 is a successful unit
# of work, a 500 is not.
gt "$(scalar_of 'sum(latkit_http_request_duration_seconds_count{code="error"})')" \
    && pass "the 5xx units are in the error latency series" \
    || fail "no error-coded latency series"

# --- 5. the four timings (РH5) ------------------------------------------------
log "timings"
p95=$(scalar_of 'histogram_quantile(0.95, sum(rate(latkit_http_request_duration_seconds_bucket[3m])) by (le))')
note "p95 duration = ${p95:-<none>} s"
if [ -n "$p95" ] && python3 -c "import sys; v=float('$p95'); sys.exit(0 if 0<=v<60 else 1)" 2>/dev/null; then
    pass "duration p95 is a plausible latency (0..60 s)"
else
    fail "p95 missing or out of range"
fi

# /slow sleeps 50 ms before the first response byte: TTFB must see it. This is
# the assertion that TTFB is measured rather than copied from the duration.
slow=$(scalar_of 'histogram_quantile(0.9, sum(rate(latkit_http_ttfb_seconds_bucket{route="/slow"}[3m])) by (le))')
note "p90 TTFB on /slow = ${slow:-<none>} s"
if gt "${slow:-0}" 0.03; then
    pass "the deliberate 50 ms delay is visible in TTFB"
else
    fail "TTFB on /slow is not where the server's own delay is ($slow)"
fi

# The upload family: the interval that belongs to the client, kept apart from
# the server's duration. The load sends the same body twice — once from a
# rate-limited client, once in a single call — so this checks both halves of
# the rule at once: the family has the uploads that took measurable time, and
# it does not have the ones with no interval to report.
up_n=$(scalar_of 'sum(latkit_http_request_upload_seconds_count{route="/upload"})')
req_n=$(scalar_of 'sum(latkit_http_requests_total{route="/upload"})')
note "upload series: $up_n of $req_n /upload observations"
gt "${up_n:-0}" \
    && pass "the upload interval is reported for /upload" \
    || fail "no upload series — РH5's third timing is missing"
if [ -n "$up_n" ] && [ -n "$req_n" ] &&
   python3 -c "import sys; sys.exit(0 if float('$up_n') < float('$req_n') else 1)"; then
    pass "the 100-continue uploads are excluded from the family (РH5)"
else
    fail "every /upload unit reached the upload family — the Expect rule is not applied"
fi
gt "$(scalar_of 'sum(latkit_http_bytes_total{route="/upload",direction="in"})')" 100000 \
    && pass "request body bytes accounted (>100 KB uploaded)" \
    || fail "request body bytes not accounted"
# The upload interval must be the client's transfer, not a rounding artefact:
# the trickling client above takes ~0.5 s, and nothing else in the load does.
up_p90=$(scalar_of 'histogram_quantile(0.9, sum(rate(latkit_http_request_upload_seconds_bucket{route="/upload"}[3m])) by (le))')
note "p90 upload interval = ${up_p90:-<none>} s"
gt "${up_p90:-0}" 0.1 \
    && pass "the slow client's upload time is measured, not attributed to the server" \
    || fail "the upload interval does not hold the slow client's transfer ($up_p90)"

# --- 6. both legs of the proxy, separately -----------------------------------
log "the two legs"
hosts=$(labels_of 'latkit_http_requests_total' host)
note "hosts: $(echo "$hosts" | tr '\n' ' ')"
nhosts=$(echo "$hosts" | grep -c .)
[ "$nhosts" -ge 2 ] \
    && pass "front and upstream legs carry distinct host labels ($nhosts)" \
    || fail "the two legs merged into one series (host labels: $hosts)"

# --- 7. sendfile: the body is accounted even when it bypasses the socket ------
log "sendfile accounting (РH4)"
big=$(scalar_of 'sum(latkit_http_bytes_total{route=~"/static/big.*",direction="out"})')
note "bytes out on /static/big.bin = ${big:-<none>}"
if gt "${big:-0}" 8000000; then
    pass "an 8 MB sendfile body is accounted (kernel routes splice through sendmsg)"
else
    # Not a failure of the agent on an older kernel: РH4 says the unit is then
    # closed by the next head with LK_QO_BODY_UNSEEN and the count is a lower
    # bound. Say which world we are in rather than passing quietly.
    fail "the sendfile body was not accounted ($big) — pre-6.5 kernel? check LK_QO_BODY_UNSEEN"
fi

# --- 8. nothing went blind, nothing was lost ---------------------------------
log "health"
blind=$(scalar_of 'sum(latkit_ignored_conns_total{proto="http"})')
note "ignored_conns{proto=http} = ${blind:-0}"
python3 -c "import sys; sys.exit(0 if float('${blind:-0}') == 0 else 1)" \
    && pass "no connection fell into a blind zone (HTTP/1.1 throughout)" \
    || fail "a connection went blind ($blind) — h2 or an upgrade on an h1-only stand?"

pe=$(scalar_of 'sum(latkit_parse_errors_total)')
note "parse_errors_total = ${pe:-0}"
python3 -c "import sys; sys.exit(0 if float('${pe:-0}') == 0 else 1)" \
    && pass "no parse errors on clean traffic" || fail "parse errors on clean traffic ($pe)"

drops=$(scalar_of 'sum(latkit_ringbuf_dropped_total)')
note "ringbuf_dropped_total = ${drops:-0}"
python3 -c "import sys; sys.exit(0 if float('${drops:-0}') == 0 else 1)" \
    && pass "no ringbuf drops at this rate" || note "ringbuf drops: $drops (rate-dependent, not fatal)"

# --- 9. optional: the same stand under a load generator ----------------------
if [ "${BURST:-0}" = "1" ]; then
    log "burst (wrk profile)"
    if $COMPOSE --profile burst run --rm wrk 2>&1 | tail -5; then
        sleep 8
        r3=$(scalar_of 'sum(latkit_http_requests_total)')
        note "sum after the burst = ${r3:-<none>}"
        if [ -n "$r3" ] && python3 -c "import sys; sys.exit(0 if float('$r3')>float('$r2')+1000 else 1)"; then
            pass "the burst's requests were observed too"
        else
            fail "the burst did not move requests_total by a burst-sized amount"
        fi
        pe2=$(scalar_of 'sum(latkit_parse_errors_total)')
        python3 -c "import sys; sys.exit(0 if float('${pe2:-0}') == 0 else 1)" \
            && pass "still no parse errors after the burst" \
            || fail "the burst produced parse errors ($pe2)"
    else
        note "wrk image unavailable — burst skipped (correctness checks above stand)"
    fi
fi

# --- verdict -----------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  HTTP (plaintext) e2e: all checks passed"
    exit 0
fi
echo "  HTTP (plaintext) e2e: $fails check(s) failed"
exit 1
