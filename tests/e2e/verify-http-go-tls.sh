#!/usr/bin/env bash
#
# HTTPS e2e check, Go half (PLAN-HTTP.md М7, РH13.3): a net/http server that
# terminates TLS in-process, load from curl, latkit with `--tls-go`.
#
# There is no libssl in the observed process, so every assertion below is about
# code written for this stage: the ELF symbol lookup, the x86-64 instruction
# decode that finds the return sites, the Go register ABI, and the per-goroutine
# correlation that turns a plaintext buffer into "this connection". The check
# that matters most is the *ratio*: the agent must observe essentially every
# request the load generator made, not merely some. A correlation that works
# only for the second request on a connection would still light up a counter —
# and would be wrong.
#
# Needs Docker, BPF privileges, a Go toolchain on the host, and /proc of the
# server (pid: host). Optional in CI like the other stands.
#
#   ./verify-http-go-tls.sh          # build agent + server, up, assert, down
#   KEEP=1 ./verify-http-go-tls.sh   # leave the stand running afterwards
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)
COMPOSE="docker compose -p latkit-http-go-tls -f docker-compose.http-go-tls.yml"
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

# --- 0. build the agent and the server on the host --------------------------
log "building the agent and the Go server on the host"
cmake --build "$REPO_ROOT/build" --target latkit -j"$(nproc)" >/dev/null
command -v go >/dev/null || { echo "  go toolchain not found — this stand needs it"; exit 77; }
# CGO_ENABLED=0 so the binary runs on the alpine image.
#
# STRIP=1 builds it the way every Go server in the wild is shipped — `-s -w`,
# no ELF symbol table at all (М0 recon: Caddy, Traefik and MinIO are all like
# this) — which makes the agent resolve crypto/tls through Go's own function
# table instead. Same stand, same assertions, the other resolution path.
GOLDFLAGS=""
[ "${STRIP:-0}" = "1" ] && GOLDFLAGS="-s -w"
( cd gotls && CGO_ENABLED=0 GOFLAGS=-mod=mod go build -ldflags "$GOLDFLAGS" \
      -o "$REPO_ROOT/build/gotls" . )
note "built $REPO_ROOT/build/gotls${GOLDFLAGS:+ (stripped: $GOLDFLAGS)}"
# One of the two tables must be there, or there is nothing to resolve through.
# Counted rather than `grep -q`'d: under `set -o pipefail` a quiet grep exits
# early, the writer takes a SIGPIPE, and the pipeline reports *that* instead of
# the match.
nsyms=$(nm "$REPO_ROOT/build/gotls" 2>/dev/null | grep -c 'crypto/tls\.(\*Conn)\.Write' || true)
npcln=$(readelf -SW "$REPO_ROOT/build/gotls" 2>/dev/null | grep -c '\.gopclntab' || true)
note "resolution tables: symtab=$nsyms entries, gopclntab section=$npcln"
if [ "$nsyms" = "0" ] && [ "$npcln" = "0" ]; then
    fail "the built server has neither a symbol table nor a .gopclntab"
    exit 1
fi

# --- 1. bring the stand up ---------------------------------------------------
log "bringing the Go HTTPS stand up (--tls-go /srv/gotls)"
$COMPOSE up -d --build
note "waiting for the uprobes to attach and Prometheus to scrape"
sleep 35

if ! $COMPOSE ps latkit | grep -q ' Up\| running'; then
    fail "latkit container is not running (BPF privileges? see '$COMPOSE logs latkit')"
    $COMPOSE logs --tail=30 latkit || true
    exit 1
fi
# The agent logs one line per hooked function with the number of return sites it
# decoded — the most useful thing in the log when this stand fails.
$COMPOSE logs latkit 2>/dev/null | grep -iE 'go tls|uprobe' | tail -5 || true

# --- 2. the Go channel delivers ordinary HTTP observations ------------------
log "HTTP observations through the Go crypto/tls uprobes"
[ "$(scalar_of 'up{job="latkit"}')" = "1" ] && pass "target up{job=latkit} == 1" \
    || fail "Prometheus cannot scrape the agent (up != 1)"

r1=$(scalar_of 'sum(latkit_http_requests_total)')
note "sum(latkit_http_requests_total) = ${r1:-<none>}"
gt "$r1" && pass "HTTP exchanges observed with no libssl in the process" \
    || fail "nothing observed — symbols, return sites, ABI or correlation"

sleep 10
r2=$(scalar_of 'sum(latkit_http_requests_total)')
note "sum after +10s = ${r2:-<none>}"
if [ -n "$r2" ] && python3 -c "import sys; sys.exit(0 if float('$r2')>float('$r1') else 1)"; then
    pass "requests_total increasing under load"
else
    fail "requests_total did not grow"
fi

# The load generator sends three requests per iteration in a fixed ratio, so the
# three routes must appear in comparable numbers. A correlation that only ever
# caught the *later* requests of a connection would show a lopsided split here
# even though every counter is non-zero.
hello=$(scalar_of 'sum(latkit_http_requests_total{route="/hello"})')
json=$(scalar_of 'sum(latkit_http_requests_total{route="/json/{id}"})')
boom=$(scalar_of 'sum(latkit_http_requests_total{route="/boom"})')
note "per-route counts: /hello=${hello:-0} /json/{id}=${json:-0} /boom=${boom:-0}"
if python3 -c "
import sys
v = [float('${hello:-0}'), float('${json:-0}'), float('${boom:-0}')]
sys.exit(0 if min(v) > 0 and max(v) <= 1.5 * min(v) else 1)"; then
    pass "all three routes observed in comparable numbers (no systematic loss)"
else
    fail "the per-route split is lopsided — some position in the connection is being missed"
fi

gt "$(scalar_of 'sum(latkit_http_requests_total{status="5xx"})')" \
    && pass "5xx observed" || fail "no 5xx observed (the /boom route)"

p95=$(scalar_of 'histogram_quantile(0.95, sum(rate(latkit_http_request_duration_seconds_bucket{job="latkit"}[2m])) by (le))')
note "p95 duration = ${p95:-<none>} s"
if [ -n "$p95" ] && python3 -c "import sys; v=float('$p95'); sys.exit(0 if 0<=v<60 else 1)" 2>/dev/null; then
    pass "duration p95 is a plausible latency (0..60 s)"
else
    fail "p95 missing or out of range"
fi

# --- 3. the Go channel is provably the data source --------------------------
log "Go TLS channel state"
if [ "$(scalar_of 'latkit_tls_attached{state="go"}')" = "1" ]; then
    pass 'latkit_tls_attached{state="go"} == 1'
else
    fail "the attach state is not \"go\" — the probes did not land on crypto/tls"
fi

gt "$(scalar_of 'latkit_tls_connections_total')" \
    && pass "connections were recognised as TLS" || fail "no connection went TLS"

uevents=$(scalar_of 'latkit_tls_uprobe_events_total')
note "latkit_tls_uprobe_events_total = ${uevents:-<none>}"
gt "$uevents" && pass "decrypted events flowed from the Go probes" || fail "no decrypted events"

# The correlation counter is the honest measure of the one assumption in
# РH13.3 — a goroutine's socket activity naming its connection. It is allowed to
# be non-zero (a call whose entry predates the attach), but not to be a
# meaningful fraction of the traffic.
miss=$(scalar_of 'latkit_tls_correlation_misses_total')
note "latkit_tls_correlation_misses_total = ${miss:-0}"
if python3 -c "import sys; m=float('${miss:-0}'); e=float('${uevents:-0}'); sys.exit(0 if e>0 and m <= 0.05*e + 5 else 1)"; then
    pass "correlation misses negligible vs events"
else
    fail "too many correlation misses ($miss) — the goroutine-to-connection link is failing"
fi

blind=$(scalar_of 'sum(latkit_ignored_conns_total{proto="http"})')
note "sum(latkit_ignored_conns_total{proto=http}) = ${blind:-0}"
if python3 -c "import sys; sys.exit(0 if float('${blind:-0}') == 0 else 1)"; then
    pass "no connection fell into a blind zone (HTTP/1.1 throughout)"
else
    fail "a connection went blind ($blind) — h2 despite TLSNextProto?"
fi

# --- verdict -----------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  HTTPS (Go crypto/tls) e2e: all checks passed"
    exit 0
fi
echo "  HTTPS (Go crypto/tls) e2e: $fails check(s) failed"
exit 1
