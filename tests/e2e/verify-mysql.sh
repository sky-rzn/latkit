#!/usr/bin/env bash
#
# Plaintext MySQL e2e check (MYSQL.md М7): mysqld (no TLS) + a mysql-CLI load
# loop + latkit with `-p 3306=mysql` — the MySQL analogue of verify.sh and the
# plaintext twin of verify-mysql-tls.sh.
#
# Asserts the М7 e2e acceptance:
#   - Prometheus scrapes the agent (up{job=latkit} == 1);
#   - latkit_queries_total is present, grows under load, and its series carry
#     proto="mysql";
#   - the duration histogram yields a plausible p95;
#   - the sessions carry the workload's db/user labels (latkit / latkit);
#   - the injected missing-table statement lands in latkit_query_errors_total
#     under SQLSTATE 42S02;
#   - the same latkit_queries_total reaches the OTel Collector over OTLP, and
#     the spans carry db.system=mysql.
#
# Needs Docker and BPF privileges on the host (the agent loads/attaches BPF).
# Where the runner lacks them this is a manual check — CI marks it optional,
# like verify.sh.
#
#   ./verify-mysql.sh          # build agent, up, assert, down
#   KEEP=1 ./verify-mysql.sh   # leave the stand running afterwards
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)
COMPOSE="docker compose -f docker-compose.mysql.yml"
PROM=http://localhost:19090
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

promql() {
    curl -sG "$PROM/api/v1/query" --data-urlencode "query=$1"
}

scalar_of() {
    promql "$1" | python3 -c '
import json, sys
d = json.load(sys.stdin)
r = d.get("data", {}).get("result", [])
print(r[0]["value"][1] if r else "")
'
}

gt() { [ -n "$1" ] && python3 -c "import sys; sys.exit(0 if float('$1')>${2:-0} else 1)"; }

# --- 0. build the agent on the host (Dockerfile.latkit COPYs the binary) -----
log "building the agent on the host"
cmake --build "$REPO_ROOT/build" --target latkit -j"$(nproc)" >/dev/null
note "built $REPO_ROOT/build/latkit"

# --- 1. bring the stand up ---------------------------------------------------
log "bringing the plaintext MySQL stand up"
$COMPOSE up -d --build
note "waiting for the agent to attach and Prometheus to scrape several times"
sleep 35

if ! $COMPOSE ps latkit | grep -q ' Up\| running'; then
    fail "latkit container is not running (BPF privileges? see '$COMPOSE logs latkit')"
    $COMPOSE logs --tail=30 latkit || true
    exit 1
fi

# --- 2. Prometheus pull path -------------------------------------------------
log "Prometheus pull path (/metrics)"
if [ "$(scalar_of 'up{job="latkit"}')" = "1" ]; then
    pass "target up{job=latkit} == 1 (no failed scrape)"
else
    fail "Prometheus cannot scrape the agent (up != 1)"
fi

q1=$(scalar_of 'sum(latkit_queries_total{proto="mysql"})')
note "sum(latkit_queries_total{proto=mysql}) = ${q1:-<none>}"
if gt "$q1"; then
    pass "latkit_queries_total{proto=mysql} present and > 0"
else
    fail "latkit_queries_total{proto=mysql} missing or zero (parser not fed?)"
fi

sleep 6
q2=$(scalar_of 'sum(latkit_queries_total{proto="mysql"})')
note "after +6s = ${q2:-<none>}"
if [ -n "$q2" ] && python3 -c "import sys; sys.exit(0 if float('$q2')>float('$q1') else 1)"; then
    pass "queries_total is increasing under load"
else
    fail "queries_total did not grow (pipeline stalled?)"
fi

p95=$(scalar_of 'histogram_quantile(0.95, sum(rate(latkit_query_duration_seconds_bucket{job="latkit",proto="mysql"}[2m])) by (le))')
note "p95 latency = ${p95:-<none>} s"
if [ -n "$p95" ] && python3 -c "import sys; v=float('$p95'); sys.exit(0 if 0<=v<60 else 1)" 2>/dev/null; then
    pass "histogram_quantile(0.95) is a plausible latency (0..60 s)"
else
    fail "p95 missing or out of range"
fi

# --- 3. session labels + injected error --------------------------------------
log "session labels and the injected error"
lbl=$(scalar_of 'sum(latkit_query_duration_seconds_count{proto="mysql",db="latkit",user="latkit"})')
note "series with db=latkit user=latkit = ${lbl:-<none>}"
if gt "$lbl"; then
    pass "query series carry the workload's db/user (from the HandshakeResponse)"
else
    fail "no query series with db=latkit user=latkit (session labels lost?)"
fi

# The load loop runs `SELECT * FROM this_table_does_not_exist` every iteration:
# errno 1146, SQLSTATE 42S02.
err=$(scalar_of 'sum(latkit_query_errors_total{proto="mysql",sqlstate="42S02"})')
note "errors_total{sqlstate=42S02} = ${err:-<none>}"
if gt "$err"; then
    pass "the injected missing-table error is observed (42S02)"
else
    fail "no 42S02 errors (error path not captured?)"
fi

# --- 4. OTLP push path reaches the collector ---------------------------------
log "OTLP push path (collector)"
mpush=$(scalar_of 'sum(latkit_queries_total{job="otel-collector",proto="mysql"})')
note "collector re-exported sum(latkit_queries_total{proto=mysql}) = ${mpush:-<none>}"
if gt "$mpush"; then
    pass "collector received latkit metrics over OTLP (re-exported)"
else
    fail "collector has no mysql latkit metrics (OTLP push not landing?)"
fi
clog=$(mktemp)
$COMPOSE logs otel-collector >"$clog" 2>/dev/null || true
if grep -q 'ExponentialHistogram' "$clog"; then
    pass "collector shows an ExponentialHistogram (duration mapping)"
else
    fail "no ExponentialHistogram in the collector log"
fi
if grep -qE 'db\.system.*mysql|mysql' "$clog"; then
    pass "collector received mysql spans (db.system=mysql)"
else
    fail "no mysql spans in the collector log"
fi
rm -f "$clog"

# --- verdict -----------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  M7 mysql e2e: all checks passed"
    exit 0
fi
echo "  M7 mysql e2e: $fails check(s) failed"
exit 1
