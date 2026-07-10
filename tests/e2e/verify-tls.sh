#!/usr/bin/env bash
#
# TLS e2e check (STAGE6.md task 6.5): the plaintext M3 stand with ssl=on and
# pgbench on sslmode=require, plus latkit --tls auto. It asserts that a fully
# encrypted workload produces the *same* query observability as plaintext —
# because latkit reads the decrypted plaintext from the libssl SSL_* uprobes —
# and that the TLS path is provably the data source:
#
#   - the stage-4 series are present and grow under load (queries_total, a
#     plausible duration p95) — identical to the plaintext verify.sh;
#   - latkit_tls_connections > 0 and latkit_tls_connections_total > 0 (the
#     backends went TLS);
#   - latkit_tls_attached{state="ok"} == 1 (uprobes attached to libssl);
#   - latkit_tls_uprobe_events_total > 0 (decrypted events actually flowed);
#   - latkit_tls_correlation_misses_total stays ~0 on a clean session (Р37);
#   - the same latkit_queries_total lands at the OTel Collector over OTLP.
#
# Needs Docker and BPF privileges on the host, plus /proc access to the
# postgres backends (pid:host) for the uprobes. Where the runner lacks these,
# this is a manual check — CI marks it optional, like verify.sh.
#
#   ./verify-tls.sh          # build agent, up, assert, down
#   KEEP=1 ./verify-tls.sh   # leave the stand running afterwards
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.tls.yml"
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
log "bringing the TLS stand up (ssl=on, sslmode=require, --tls auto)"
$COMPOSE up -d --build
note "waiting for the agent to attach libssl and Prometheus to scrape"
sleep 35

if ! $COMPOSE ps latkit | grep -q ' Up\| running'; then
    fail "latkit container is not running (BPF privileges? see '$COMPOSE logs latkit')"
    $COMPOSE logs --tail=30 latkit || true
    exit 1
fi

# The agent logs the libssl it attached; surface it for debugging.
$COMPOSE logs latkit 2>/dev/null | grep -iE 'tls|libssl|uprobe' | tail -5 || true

# --- 2. the query pipeline works over TLS (same series as plaintext) --------
log "query pipeline over TLS"
if [ "$(scalar_of 'up{job="latkit"}')" = "1" ]; then
    pass "target up{job=latkit} == 1"
else
    fail "Prometheus cannot scrape the agent (up != 1)"
fi

q1=$(scalar_of 'sum(latkit_queries_total)')
note "sum(latkit_queries_total) = ${q1:-<none>}"
if gt "$q1"; then
    pass "latkit_queries_total present and > 0 (decrypted queries parsed)"
else
    fail "latkit_queries_total missing or zero — TLS plaintext not reaching the parser"
fi

sleep 6
q2=$(scalar_of 'sum(latkit_queries_total)')
note "sum(latkit_queries_total) after +6s = ${q2:-<none>}"
if [ -n "$q2" ] && python3 -c "import sys; sys.exit(0 if float('$q2')>float('$q1') else 1)"; then
    pass "queries_total increasing under TLS load"
else
    fail "queries_total did not grow (uprobe channel stalled?)"
fi

p95=$(scalar_of 'histogram_quantile(0.95, sum(rate(latkit_query_duration_seconds_bucket[2m])) by (le))')
note "p95 latency = ${p95:-<none>} s"
if [ -n "$p95" ] && python3 -c "import sys; v=float('$p95'); sys.exit(0 if 0<=v<60 else 1)" 2>/dev/null; then
    pass "duration p95 is a plausible latency (0..60 s)"
else
    fail "p95 missing or out of range"
fi

# --- 3. the TLS path is provably the data source ----------------------------
log "TLS observability metrics (Р41)"
tconn=$(scalar_of 'latkit_tls_connections')
note "latkit_tls_connections = ${tconn:-<none>}"
if gt "$tconn"; then
    pass "latkit_tls_connections > 0 (backends went TLS)"
else
    fail "latkit_tls_connections is zero — no connection flipped to TLS"
fi

ttot=$(scalar_of 'latkit_tls_connections_total')
note "latkit_tls_connections_total = ${ttot:-<none>}"
gt "$ttot" && pass "latkit_tls_connections_total > 0" || fail "latkit_tls_connections_total zero"

attached=$(scalar_of 'latkit_tls_attached{state="ok"}')
note "latkit_tls_attached{state=ok} = ${attached:-<none>}"
if [ "$attached" = "1" ]; then
    pass "latkit_tls_attached{state=ok} == 1 (uprobes on libssl)"
else
    part=$(scalar_of 'latkit_tls_attached{state="partial"}')
    if [ "$part" = "1" ]; then
        pass "latkit_tls_attached{state=partial} == 1 (some symbols attached)"
    else
        fail "libssl uprobes not attached (state is none)"
    fi
fi

uevents=$(scalar_of 'latkit_tls_uprobe_events_total')
note "latkit_tls_uprobe_events_total = ${uevents:-<none>}"
gt "$uevents" && pass "decrypted uprobe events flowed (> 0)" \
    || fail "no uprobe events — SSL_read/SSL_write not captured"

miss=$(scalar_of 'latkit_tls_correlation_misses_total')
note "latkit_tls_correlation_misses_total = ${miss:-0}"
# A few misses at startup (a read served from OpenSSL's buffer before the first
# tcp_* correlates) are tolerable; they must be a tiny fraction of the events.
if [ -z "$miss" ]; then
    fail "correlation-miss counter absent"
elif python3 -c "import sys; m=float('$miss'); e=float('${uevents:-0}'); sys.exit(0 if e>0 and m <= 0.05*e + 5 else 1)"; then
    pass "correlation misses are negligible vs events (Р37 bridge holds)"
else
    fail "too many correlation misses ($miss) — SSL*->cookie bridge is failing"
fi

# --- 4. OTLP push path carries the TLS-sourced metrics ----------------------
log "OTLP push path (collector)"
mpush=$(scalar_of 'sum(latkit_queries_total{job="otel-collector"})')
note "collector re-exported sum(latkit_queries_total) = ${mpush:-<none>}"
gt "$mpush" && pass "collector received the TLS-sourced metrics over OTLP" \
    || fail "collector has no latkit metrics (OTLP push not landing?)"

# --- verdict -----------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  TLS e2e: all checks passed"
    exit 0
fi
echo "  TLS e2e: $fails check(s) failed"
exit 1
