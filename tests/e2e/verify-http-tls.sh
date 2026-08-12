#!/usr/bin/env bash
#
# HTTPS e2e check, OpenSSL half (PLAN-HTTP.md М7, РH13/РH13.1): nginx serving
# HTTP/1.1 over TLS, load from curl, latkit with `--tls auto`.
#
# The claim under test is the stage's acceptance criterion: a TLS run yields the
# same observations as a plaintext one. So the assertions are not "some TLS
# metric moved" but the ordinary HTTP ones —
#
#   - latkit_http_requests_total exists, grows, and carries a *templated* route
#     (no raw id survived into a label);
#   - the status classes are split the way РH10 says (a 404 is not an error, a
#     500 is), and both are present;
#   - the durations are plausible;
#   - and only then the TLS-specific proof: the connections went TLS, the
#     uprobes are attached, decrypted events flowed, correlation misses are
#     negligible, and no connection fell into a blind zone (which is how an
#     accidental h2 negotiation would show up).
#
# Needs Docker and BPF privileges, plus /proc of the nginx workers (pid: host)
# for the uprobes. Like the other stands, this is a manual/optional check where
# a runner lacks them.
#
#   ./verify-http-tls.sh          # build agent, up, assert, down
#   KEEP=1 ./verify-http-tls.sh   # leave the stand running afterwards
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)
COMPOSE="docker compose -p latkit-http-tls -f docker-compose.http-tls.yml"
PROM=http://localhost:19091
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

promql()   { curl -sG "$PROM/api/v1/query" --data-urlencode "query=$1"; }
scalar_of() {
    promql "$1" | python3 -c '
import json, sys
d = json.load(sys.stdin)
r = d.get("data", {}).get("result", [])
print(r[0]["value"][1] if r else "")
'
}
gt() { [ -n "$1" ] && python3 -c "import sys; sys.exit(0 if float('$1')>${2:-0} else 1)"; }

# --- 0. build the agent on the host -----------------------------------------
log "building the agent on the host"
cmake --build "$REPO_ROOT/build" --target latkit -j"$(nproc)" >/dev/null
note "built $REPO_ROOT/build/latkit"

# --- 1. bring the stand up ---------------------------------------------------
log "bringing the HTTPS stand up (nginx TLS, --tls auto)"
$COMPOSE up -d --build
note "waiting for the agent to attach libssl and Prometheus to scrape"
sleep 35

if ! $COMPOSE ps latkit | grep -q ' Up\| running'; then
    fail "latkit container is not running (BPF privileges? see '$COMPOSE logs latkit')"
    $COMPOSE logs --tail=30 latkit || true
    exit 1
fi
$COMPOSE logs latkit 2>/dev/null | grep -iE 'tls|libssl|uprobe' | tail -5 || true

# --- 2. the HTTP pipeline works over TLS ------------------------------------
log "HTTP observations over TLS"
[ "$(scalar_of 'up{job="latkit"}')" = "1" ] && pass "target up{job=latkit} == 1" \
    || fail "Prometheus cannot scrape the agent (up != 1)"

r1=$(scalar_of 'sum(latkit_http_requests_total)')
note "sum(latkit_http_requests_total) = ${r1:-<none>}"
gt "$r1" && pass "HTTP exchanges observed through the TLS channel" \
    || fail "no HTTP observations — decrypted plaintext is not reaching the framer"

sleep 6
r2=$(scalar_of 'sum(latkit_http_requests_total)')
note "sum after +6s = ${r2:-<none>}"
if [ -n "$r2" ] && python3 -c "import sys; sys.exit(0 if float('$r2')>float('$r1') else 1)"; then
    pass "requests_total increasing under load"
else
    fail "requests_total did not grow (uprobe channel stalled?)"
fi

# The route label is the templated one, on every series (РH7 through TLS).
routes=$(promql 'latkit_http_requests_total' | python3 -c '
import json, re, sys
res = json.load(sys.stdin).get("data", {}).get("result", [])
print("\n".join(sorted({m["metric"].get("route", "") for m in res})))
')
note "routes seen: $(echo "$routes" | tr "\n" " ")"
if echo "$routes" | grep -q '^/json/{id}$'; then
    pass "the id-bearing path came back templated as /json/{id}"
else
    fail "no templated route — the id survived into the label or nothing was observed"
fi
if echo "$routes" | grep -qE '/[0-9]+($|/)'; then
    fail "a raw numeric segment reached a route label: $routes"
else
    pass "no raw id in any route label"
fi

# Statuses (РH10): the 500 is an error, the 404 is a client's problem — both
# observed, neither confused for the other.
gt "$(scalar_of 'sum(latkit_http_requests_total{status="5xx"})')" \
    && pass "5xx observed" || fail "no 5xx observed (the /boom route)"
gt "$(scalar_of 'sum(latkit_http_requests_total{status="4xx"})')" \
    && pass "4xx observed" || fail "no 4xx observed (the /nope route)"
gt "$(scalar_of 'latkit_http_errors_total{code="500"}')" \
    && pass "latkit_http_errors_total{code=500} > 0" || fail "the 500 was not counted as an error"

p95=$(scalar_of 'histogram_quantile(0.95, sum(rate(latkit_http_request_duration_seconds_bucket{job="latkit"}[2m])) by (le))')
note "p95 duration = ${p95:-<none>} s"
if [ -n "$p95" ] && python3 -c "import sys; v=float('$p95'); sys.exit(0 if 0<=v<60 else 1)" 2>/dev/null; then
    pass "duration p95 is a plausible latency (0..60 s)"
else
    fail "p95 missing or out of range"
fi

# --- 3. the TLS path is provably the data source ----------------------------
log "TLS observability metrics"
gt "$(scalar_of 'latkit_tls_connections_total')" \
    && pass "connections went TLS" || fail "latkit_tls_connections_total is zero"

attached=$(scalar_of 'latkit_tls_attached{state="ok"}')
if [ "$attached" = "1" ]; then
    pass "latkit_tls_attached{state=ok} == 1 (uprobes on nginx's libssl)"
elif [ "$(scalar_of 'latkit_tls_attached{state="partial"}')" = "1" ]; then
    pass "latkit_tls_attached{state=partial} == 1 (some symbols attached)"
else
    fail "libssl uprobes not attached — is nginx in the derived scan set (РH13.1)?"
fi

uevents=$(scalar_of 'latkit_tls_uprobe_events_total')
note "latkit_tls_uprobe_events_total = ${uevents:-<none>}"
gt "$uevents" && pass "decrypted events flowed" || fail "no decrypted events"

miss=$(scalar_of 'latkit_tls_correlation_misses_total')
note "latkit_tls_correlation_misses_total = ${miss:-0}"
if python3 -c "import sys; m=float('${miss:-0}'); e=float('${uevents:-0}'); sys.exit(0 if e>0 and m <= 0.05*e + 5 else 1)"; then
    pass "correlation misses negligible vs events"
else
    fail "too many correlation misses ($miss)"
fi

# A blind zone here would mean h2 slipped in (the stand is configured against
# it) — the number that tells "we read everything" from "we read what was left".
blind=$(scalar_of 'sum(latkit_ignored_conns_total{proto="http"})')
note "sum(latkit_ignored_conns_total{proto=http}) = ${blind:-0}"
if python3 -c "import sys; sys.exit(0 if float('${blind:-0}') == 0 else 1)"; then
    pass "no connection fell into a blind zone (HTTP/1.1 throughout)"
else
    fail "a connection went blind ($blind) — h2 negotiated despite the config?"
fi

# --- verdict -----------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  HTTPS (nginx/libssl) e2e: all checks passed"
    exit 0
fi
echo "  HTTPS (nginx/libssl) e2e: $fails check(s) failed"
exit 1
