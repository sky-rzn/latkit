#!/usr/bin/env bash
#
# M3 e2e check (STAGE5.md task 5.4): brings up postgres + pgbench + latkit +
# prometheus + otel-collector, then asserts the milestone exit criteria:
#
#   - Prometheus scrapes the agent and sees the stage-4 series (queries_total
#     grows, the duration histogram yields a plausible p95);
#   - the OTel Collector receives the same metrics over OTLP (Sum +
#     ExponentialHistogram) and the sampled spans (db.query.text);
#   - the pull path (/metrics) and the push path (collector re-export) agree
#     within an export interval.
#
# Needs Docker and BPF privileges on the host (the agent loads/attaches BPF).
# Where the runner has neither, this is a manual check — CI marks it optional.
#
#   ./verify.sh          # build agent, up, assert, down
#   KEEP=1 ./verify.sh   # leave the stand running afterwards
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)
COMPOSE="docker compose"
PROM=http://localhost:19090
fails=0

log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
pass() { printf '  ok   - %s\n' "$*"; }
fail() { printf '  FAIL - %s\n' "$*"; fails=$((fails + 1)); }

cleanup() {
    if [ "${KEEP:-0}" = "1" ]; then
        log "KEEP=1 — leaving the stand up (docker compose down to stop)"
        return
    fi
    log "tearing down"
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# promql QUERY -> instant-vector result as JSON (via the Prometheus HTTP API).
promql() {
    curl -sG "$PROM/api/v1/query" --data-urlencode "query=$1"
}

# scalar_of QUERY -> the first sample's value, or empty if none.
scalar_of() {
    promql "$1" | python3 -c '
import json, sys
d = json.load(sys.stdin)
r = d.get("data", {}).get("result", [])
print(r[0]["value"][1] if r else "")
'
}

# --- 0. build the agent on the host (Dockerfile.latkit COPYs the binary) -----
log "building the agent on the host"
cmake --build "$REPO_ROOT/build" --target latkit -j"$(nproc)" >/dev/null
note "built $REPO_ROOT/build/latkit"

# --- 1. bring the stand up ---------------------------------------------------
log "bringing the stand up"
$COMPOSE up -d --build
note "waiting for the agent to attach and Prometheus to scrape several times"
sleep 35

if ! $COMPOSE ps latkit | grep -q ' Up\| running'; then
    fail "latkit container is not running (BPF privileges? see 'docker compose logs latkit')"
    $COMPOSE logs --tail=30 latkit || true
    exit 1
fi

# --- 2. Prometheus sees the pull path ---------------------------------------
log "Prometheus pull path (/metrics)"
if [ "$(scalar_of 'up{job="latkit"}')" = "1" ]; then
    pass "target up{job=latkit} == 1 (no failed scrape)"
else
    fail "Prometheus cannot scrape the agent (up != 1)"
fi

q1=$(scalar_of 'sum(latkit_queries_total)')
note "sum(latkit_queries_total) = ${q1:-<none>}"
if [ -n "$q1" ] && python3 -c "import sys; sys.exit(0 if float('$q1')>0 else 1)"; then
    pass "latkit_queries_total present and > 0"
else
    fail "latkit_queries_total missing or zero"
fi

# count must grow across a 6 s window (pgbench is running)
sleep 6
q2=$(scalar_of 'sum(latkit_queries_total)')
note "sum(latkit_queries_total) after +6s = ${q2:-<none>}"
if [ -n "$q2" ] && python3 -c "import sys; sys.exit(0 if float('$q2')>float('$q1') else 1)"; then
    pass "queries_total is increasing under load"
else
    fail "queries_total did not grow (pipeline stalled?)"
fi

# job="latkit" only: the collector re-exports the same histogram on a different
# le grid, and summing the two by (le) yields a broken cumulative histogram
# (histogram_quantile then reports the top bucket bound, e.g. a flat "32").
p95=$(scalar_of 'histogram_quantile(0.95, sum(rate(latkit_query_duration_seconds_bucket{job="latkit"}[2m])) by (le))')
note "p95 latency = ${p95:-<none>} s"
if [ -n "$p95" ] && python3 -c "import sys; v=float('$p95'); sys.exit(0 if 0<=v<60 else 1)" 2>/dev/null; then
    pass "histogram_quantile(0.95) is a plausible latency (0..60 s)"
else
    fail "p95 missing or out of range"
fi

# --- 3. OTLP push path reaches the collector --------------------------------
# The collector re-exports what it received on :8889, so a latkit series under
# job=otel-collector is authoritative proof the OTLP metrics landed (a malformed
# protobuf would 400 at the collector and never appear — Р31). The debug log
# (grepped in full, not tailed — spans can flood a tail window) confirms the
# ExponentialHistogram mapping and the sampled spans.
log "OTLP push path (collector)"
mpush=$(scalar_of 'sum(latkit_queries_total{job="otel-collector"})')
note "collector re-exported sum(latkit_queries_total) = ${mpush:-<none>}"
if [ -n "$mpush" ] && python3 -c "import sys; sys.exit(0 if float('$mpush')>0 else 1)"; then
    pass "collector received latkit metrics over OTLP (re-exported)"
else
    fail "collector has no latkit metrics (OTLP push not landing / rejected?)"
fi
# Dump the collector log to a file once and grep the file — piping `docker
# compose logs` into `grep -q` would SIGPIPE the producer on the first match,
# which `set -o pipefail` would report as a (false) failure.
clog=$(mktemp)
$COMPOSE logs otel-collector >"$clog" 2>/dev/null || true
if grep -q 'ExponentialHistogram' "$clog"; then
    pass "collector shows an ExponentialHistogram (duration mapping)"
else
    fail "no ExponentialHistogram in the collector log"
fi
if grep -qE 'db\.query\.text|db\.system' "$clog"; then
    pass "collector received sampled spans (db.query.text / db.system)"
else
    fail "no spans in the collector log (spans not exported?)"
fi
rm -f "$clog"

# --- 4. pull vs push agree ---------------------------------------------------
log "pull vs push cross-check"
pull=$(scalar_of 'sum(latkit_queries_total{job="latkit"})')
push=$mpush
note "pull=${pull:-<none>} push=${push:-<none>}"
if [ -n "$pull" ] && [ -n "$push" ]; then
    # Allow a generous window: the two paths sample at different instants.
    if python3 -c "import sys; a=float('$pull'); b=float('$push'); sys.exit(0 if a>0 and b>0 and abs(a-b) <= 0.3*max(a,b)+50 else 1)"; then
        pass "pull and push counts agree within an export interval"
    else
        fail "pull and push counts diverge more than an interval explains"
    fi
else
    fail "missing pull or push series for the cross-check"
fi

# --- verdict -----------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  M3 e2e: all checks passed"
    exit 0
fi
echo "  M3 e2e: $fails check(s) failed"
exit 1
