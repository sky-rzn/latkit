#!/usr/bin/env bash
#
# HTTP overhead benchmark (PLAN-HTTP.md М8 — the http analogue of run.sh /
# task 8.1, Р49, and run-mysql.sh).
#
# One load at a **capped rate**, paired ABAB runs against a baseline, medians
# compared so machine drift is smeared over both sides:
#
#   A  no agent                     baseline
#   B  agent up, http capture       fentry probes + ringbuf + stream framer +
#                                    the HTTP handler + the route templater
#
# The cap is the method, not a detail (Р49, and the same choice tests/bench/
# run.sh makes for PostgreSQL): at saturation the load generator and the agent
# compete for the same cores, so a throughput difference measures the
# scheduler. Held below saturation both sides deliver the same rate, and what
# is left to compare is the client's latency and the agent's own CPU — which is
# the number a deployment actually pays. wrk paces itself through
# tests/bench/wrk-pace.lua (wrk has no -R; wrk2 does).
#
# Three loads, because HTTP's cost is not one number:
#
#   small   many small responses through nginx           — per-request cost:
#                                                          two heads and a
#                                                          route lookup per
#                                                          exchange, the worst
#                                                          case per byte
#   proxy   the same through nginx to a Go backend       — two observed legs
#                                                          per client request,
#                                                          which is what a real
#                                                          deployment costs
#   big     a 1 MB static file with `sendfile on`        — per-byte cost, and
#                                                          the claim of РH14:
#                                                          at multi-gigabit
#                                                          delivery the 2048 B
#                                                          per-call budget is
#                                                          what keeps the
#                                                          ringbuf from
#                                                          dropping
#
# The `big` load is run twice under the agent — at the default budget and at a
# deliberately fat one — so the budget's effect on drop rate is measured rather
# than asserted. That comparison is the whole reason РH14 exists.
#
# A run is VALID only if the agent dump shows zero latkit_ringbuf_dropped_total
# during it: an agent that drops events looks cheaper than one that works (Р49).
# The fat-budget run is expected to be invalid — that is its purpose.
#
# Usage:
#   tests/bench/run-http.sh up      # start the stand (once)
#   tests/bench/run-http.sh run     # the benchmark (default)
#   tests/bench/run-http.sh down    # remove the stand
#
# Knobs (env): PAIRS=3, DURATION=15, CONNS=32, THREADS=4, RATE=20000 (rps,
#   the small/proxy cap), BIG_RATE=800 (rps of 1 MB bodies ~ 6.7 Gbit/s),
#   FAT_BUDGET=32768, AGENT_BIN=build-rel/latkit, OUT=tests/bench/out/http-<ts>
#
# Requirements: docker (nginx, alpine, williamyeh/wrk images), a Go toolchain
# (the backend), passwordless sudo for the agent (BPF), an OPTIMISED agent
# build (build-rel), python3.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
AGENT_BIN=${AGENT_BIN:-$REPO_ROOT/build-rel/latkit}

NET=latkit-bench-http-net
NGINX=latkit-bench-nginx
BACKEND=latkit-bench-backend
WRK_IMAGE=${WRK_IMAGE:-williamyeh/wrk:latest}

PAIRS=${PAIRS:-3}
DURATION=${DURATION:-15}
CONNS=${CONNS:-32}
THREADS=${THREADS:-4}
BIG_CONNS=${BIG_CONNS:-8}
RATE=${RATE:-20000}
BIG_RATE=${BIG_RATE:-800}
FAT_BUDGET=${FAT_BUDGET:-32768}
OUT=${OUT:-$HERE/out/http-$(date -u +%Y%m%dT%H%M%SZ)}

log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die()  { printf '  FATAL: %s\n' "$*" >&2; exit 1; }

container_ip() {
    docker inspect "$NGINX" --format \
        '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
}

agent_pid() { pgrep -x latkit || true; }
AGENT_JOB=
# $1 = dump path, $2 = the front port's capture budget ("" = the http default)
agent_start() {
    local front=8080=http
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    [ -n "$2" ] && front="8080=http:$2"
    sudo -n "$AGENT_BIN" -p "$front" -p 8081=http --dump-metrics="$1" \
        >>"$OUT/agent.log" 2>&1 &
    AGENT_JOB=$!
    sleep 3
    [ -n "$(agent_pid)" ] || die "agent did not come up (see $OUT/agent.log)"
}
agent_stop() {
    local pid; pid=$(agent_pid)
    if [ -n "$pid" ]; then
        sudo -n kill -INT "$pid"
        for _ in $(seq 100); do [ -z "$(agent_pid)" ] && break; sleep 0.2; done
        [ -z "$(agent_pid)" ] || sudo -n kill -KILL "$(agent_pid)" 2>/dev/null || true
    fi
    [ -n "$AGENT_JOB" ] && { wait "$AGENT_JOB" 2>/dev/null || true; }
    AGENT_JOB=
}

stack_down() {
    docker rm -f "$NGINX" "$BACKEND" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}

stack_up() {
    stack_down
    command -v go >/dev/null || die "a Go toolchain is required (the backend)"
    (cd "$REPO_ROOT/tests/e2e/httpbackend" &&
        CGO_ENABLED=0 go build -o "$REPO_ROOT/build/httpbackend" .) || die "backend build failed"
    docker network create "$NET" >/dev/null
    docker run -d --name "$BACKEND" --network "$NET" --network-alias backend \
        -v "$REPO_ROOT/build/httpbackend:/srv/httpbackend:ro" \
        -e LISTEN=":8081" alpine:3.20 /srv/httpbackend >/dev/null
    # access_log off: the benchmark measures the agent, not nginx's logging.
    docker run -d --name "$NGINX" --network "$NET" \
        -v "$REPO_ROOT/tests/e2e/nginx-http.conf:/etc/nginx/nginx.conf:ro" \
        --entrypoint sh nginx:1.27-alpine -c '
            mkdir -p /www/static
            head -c 1048576 /dev/urandom > /www/static/big.bin
            printf small > /www/static/small.txt
            exec nginx -g "daemon off;"' >/dev/null
    for _ in $(seq 60); do
        docker exec "$NGINX" wget -q -O- http://127.0.0.1:8080/hello >/dev/null 2>&1 && break
        sleep 1
    done
    docker exec "$NGINX" wget -q -O- http://127.0.0.1:8080/hello >/dev/null 2>&1 \
        || die "nginx never became ready"
}

# wrk <url> <conns> <target-rps> -> "<req/s> <MB/s> <p99-ms>"; driven at the
# container IP, never 127.0.0.1 (docker-proxy would splice the payload past the
# capture point). The pacing script holds the fleet at the target rate.
wrk_run() {
    local delay_ms
    delay_ms=$(python3 -c "print(max(0, 1000.0 * $2 / float($3)))")
    docker run --rm --network "$NET" -e WRK_DELAY_MS="$delay_ms" \
        -v "$REPO_ROOT/tests/bench/wrk-pace.lua:/pace.lua:ro" "$WRK_IMAGE" \
        -t"$THREADS" -c"$2" -d"${DURATION}s" --latency -s /pace.lua "$1" 2>/dev/null |
        python3 -c '
import re, sys
txt = sys.stdin.read()
rps = re.search(r"Requests/sec:\s+([0-9.]+)", txt)
xfer = re.search(r"Transfer/sec:\s+([0-9.]+)(\w+)", txt)
p99 = re.search(r"\s+99%\s+([0-9.]+)(\w+)", txt)
mb = 0.0
if xfer:
    v, u = float(xfer.group(1)), xfer.group(2).upper()
    mb = v * {"B": 1e-6, "KB": 1e-3, "MB": 1.0, "GB": 1e3}.get(u, 1.0)
ms = 0.0
if p99:
    v, u = float(p99.group(1)), p99.group(2).lower()
    ms = v * {"us": 1e-3, "ms": 1.0, "s": 1e3, "m": 6e4}.get(u, 1.0)
print("%s %.1f %.2f" % (rps.group(1) if rps else "0", mb, ms))
'
}

metric() {
    awk -v m="$2" '$1==m || substr($1,1,length(m)+1)==m"{" {s+=$NF} END{printf "%.0f",s+0}' "$1"
}

case "${1:-run}" in
down) stack_down; exit 0 ;;
up)   mkdir -p "$OUT"; stack_up; note "up: $NGINX at $(container_ip)"; exit 0 ;;
run)  ;;
*)    die "usage: $0 [up|run|down]" ;;
esac

trap 'agent_stop; [ "${KEEP:-0}" = 1 ] || stack_down' EXIT
mkdir -p "$OUT"
[ -x "$AGENT_BIN" ] || die "agent not built (RelWithDebInfo): $AGENT_BIN"
docker ps --format '{{.Names}}' | grep -qx "$NGINX" || stack_up
IP=$(container_ip)
note "nginx at $IP:8080 (static + proxy to the Go backend on 8081)"
note "pairs: $PAIRS, duration: ${DURATION}s, threads: $THREADS"

declare -A URL CONNS_FOR RATE_FOR
URL[small]="http://$IP:8080/static/small.txt"
URL[proxy]="http://$IP:8080/json/1"   # proxied to the backend; the id is templated away
URL[big]="http://$IP:8080/static/big.bin"
# The budget comparison needs a body the probe can actually copy: a sendfile
# body arrives at tcp_sendmsg as a page iterator and is never captured, budget
# or no budget (М0 recon item 1), so `sendfile off` is where РH14 is visible.
URL[write]="http://$IP:8080/nosendfile/big.bin"
CONNS_FOR[small]=$CONNS
CONNS_FOR[proxy]=$CONNS
CONNS_FOR[big]=$BIG_CONNS
RATE_FOR[small]=$RATE
RATE_FOR[proxy]=$RATE
RATE_FOR[big]=$BIG_RATE

log "warmup"
wrk_run "${URL[small]}" "$CONNS" "$RATE" >/dev/null

printf 'load\tpair\tA_rps\tB_rps\tdRPS%%\tA_p99ms\tB_p99ms\tB_MBs\tagent_cores\tdrops\tresyncs\tparse_err\n' \
    >"$OUT/runs.tsv"

for load in small proxy big; do
    log "$load: paired A (no agent) / B (agent) runs at ${RATE_FOR[$load]} rps"
    for p in $(seq 1 "$PAIRS"); do
        read -r a_rps _ a_p99 <<<"$(wrk_run "${URL[$load]}" "${CONNS_FOR[$load]}" "${RATE_FOR[$load]}")"
        agent_start "$OUT/agent-$load-$p.prom" ""
        read -r b_rps b_mb b_p99 <<<"$(wrk_run "${URL[$load]}" "${CONNS_FOR[$load]}" "${RATE_FOR[$load]}")"
        agent_stop
        dump=$OUT/agent-$load-$p.prom
        drops=$(metric "$dump" latkit_ringbuf_dropped_total)
        resyncs=$(metric "$dump" latkit_resync_total)
        perr=$(metric "$dump" latkit_parse_errors_total)
        # The agent's own CPU over its lifetime (startup included, ~3 s), in
        # cores: the number a deployment pays, and the one the PG stand gates.
        cpu=$(awk '$1 == "latkit_process_seconds_total" { print $2 }' "$dump" 2>/dev/null)
        cores=$(python3 -c "print('%.3f' % (float('${cpu:-0}') / ($DURATION + 3)))" 2>/dev/null || echo "?")
        d=$(python3 -c "print('%.1f'%(100*(float('$a_rps')-float('$b_rps'))/float('$a_rps')))" \
             2>/dev/null || echo "?")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$load" "$p" "$a_rps" "$b_rps" "$d" "$a_p99" "$b_p99" "$b_mb" "$cores" \
            "$drops" "$resyncs" "$perr" | tee -a "$OUT/runs.tsv"
    done
done

# --- РH14: the budget is what keeps a multi-gigabit body from dropping -------
# This one leg is deliberately *uncapped*: it is a saturation probe, not an
# overhead measurement. The question is what happens to the ringbuf when the
# delivery rate is as high as the machine can make it, and a cap would answer
# a different one.
# A 1 MB body written *through the socket* (`sendfile off`), once at the default
# per-port budget and once at a fat one. The claim is not "the agent is fast"
# but "the agent stays lossless at this rate *because* it only captures the
# head" — so the comparison has to be run where the budget decides how many
# bytes are copied, which a sendfile body never does.
log "budget comparison on the big-body load (РH14)"
agent_start "$OUT/agent-big-default.prom" ""
read -r rps_def mb_def _ <<<"$(wrk_run "${URL[write]}" "$BIG_CONNS" 1000000)"
agent_stop
agent_start "$OUT/agent-big-fat.prom" "$FAT_BUDGET"
read -r rps_fat mb_fat _ <<<"$(wrk_run "${URL[write]}" "$BIG_CONNS" 1000000)"
agent_stop
d_def=$(metric "$OUT/agent-big-default.prom" latkit_ringbuf_dropped_total)
d_fat=$(metric "$OUT/agent-big-fat.prom" latkit_ringbuf_dropped_total)
{
    printf 'budget\trps\tMB/s\tringbuf_drops\n'  # uncapped, /nosendfile/big.bin
    printf 'default(2048)\t%s\t%s\t%s\n' "$rps_def" "$mb_def" "$d_def"
    printf 'fat(%s)\t%s\t%s\t%s\n' "$FAT_BUDGET" "$rps_fat" "$mb_fat" "$d_fat"
} | tee "$OUT/budget.tsv"

log "verdict"
python3 - "$OUT/runs.tsv" "$OUT/budget.tsv" <<'PY'
import sys, statistics as st

rows = {}
for line in open(sys.argv[1]):
    f = line.rstrip("\n").split("\t")
    if len(f) < 12 or f[0] == "load":
        continue
    try:
        rows.setdefault(f[0], []).append(
            (float(f[2]), float(f[3]), float(f[5]), float(f[6]), float(f[8]),
             int(f[9]), int(f[10])))
    except ValueError:
        pass
if not rows:
    print("  no runs")
    sys.exit(1)
for load, rs in rows.items():
    ma = st.median([r[0] for r in rs])
    mb = st.median([r[1] for r in rs])
    pa = st.median([r[2] for r in rs])
    pb = st.median([r[3] for r in rs])
    cores = st.median([r[4] for r in rs])
    drops = sum(r[5] for r in rs)
    resyncs = sum(r[6] for r in rs)
    valid = "valid" if drops == 0 else "INVALID (the agent dropped events)"
    print("  %-6s rps A=%8.1f B=%8.1f (%+.1f%%)  p99 %6.2f>%6.2f ms  "
          "agent=%.3f cores  drops=%d resyncs=%d  [%s]"
          % (load, ma, mb, 100 * (mb - ma) / ma, pa, pb, cores, drops, resyncs, valid))

budget = [l.rstrip("\n").split("\t") for l in open(sys.argv[2])][1:]
print("  budget on the big-body load:")
for name, rps, mb, drops in budget:
    print("    %-14s %9s rps  %8s MB/s  ringbuf drops=%s" % (name, rps, mb, drops))
PY
note "per-run table: $OUT/runs.tsv; budget table: $OUT/budget.tsv"
