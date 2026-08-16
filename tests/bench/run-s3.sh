#!/usr/bin/env bash
#
# S3 overhead benchmark (PLAN-MINIO.md МS4 — the object-store analogue of
# run.sh / run-mysql.sh / run-http.sh, Р49).
#
# One load at a **capped rate**, paired ABAB runs against a baseline, medians
# compared so machine drift is smeared over both sides:
#
#   A  no agent                     baseline
#   B  agent up, s3 capture         fentry probes + ringbuf + stream framer +
#                                    the HTTP handler + the S3 dialect
#
# The load is `warp`, MinIO's own benchmark, because an object store's cost is
# not a request rate — it is bytes. `--rps-limit` holds each run below
# saturation for the reason Р49 gives: at saturation the load generator and the
# agent compete for the same cores and a throughput difference measures the
# scheduler.
#
# Two things this stand measures that the three before it could not:
#
#   1. **Ringbuf pressure at object-store volume** (risk 2 of the plan). Every
#      64 KiB of object body is a `write(2)`, hence an event, and the per-port
#      budget of РH14 decides how many bytes each carries. The `budget`
#      comparison at the end runs the byte-heavy load twice — at the default
#      2048 and at a deliberately fat budget — so the claim "2048 keeps the
#      drop-rate at the database stands' level" is measured rather than
#      asserted. The fat run is *expected* to be invalid; that is its purpose.
#
#   2. **The distributed case** (МS0 recon item 6). On a four-node pool four
#      fifths of what arrives on the S3 port is the cluster talking to itself,
#      so the same client load costs the agent about five times as much. A
#      benchmark run only against a single node measures the easy case, which is
#      why `MODE=dist` exists and why the report prints the internal share.
#
# A run is VALID only if the agent dump shows zero latkit_ringbuf_dropped_total
# during it: an agent that drops events looks cheaper than one that works.
#
# Usage:
#   tests/bench/run-s3.sh up        # start the stand (once)
#   tests/bench/run-s3.sh run       # the benchmark (default)
#   tests/bench/run-s3.sh down      # remove the stand
#   MODE=dist tests/bench/run-s3.sh # the four-node pool instead of a single node
#
# Knobs (env): PAIRS=3, DURATION=20, CONCURRENT=8, RPS=400 (the mixed cap),
#   OBJ_SIZE=1MiB, OBJECTS=200, FAT_BUDGET=32768, MODE=single|dist,
#   AGENT_BIN=build-rel/latkit, OUT=tests/bench/out/s3-<ts>
#
# Requirements: docker (minio/minio, minio/warp images), passwordless sudo for
# the agent (BPF), an OPTIMISED agent build (build-rel), python3.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
AGENT_BIN=${AGENT_BIN:-$REPO_ROOT/build-rel/latkit}

MINIO_IMAGE=${MINIO_IMAGE:-minio/minio:latest}
WARP_IMAGE=${WARP_IMAGE:-minio/warp:latest}
NET=latkit-bench-s3-net
MODE=${MODE:-single}
PORT=${PORT:-9404}
AK=lkroot
SK=lkrootpass123

PAIRS=${PAIRS:-3}
DURATION=${DURATION:-20}
CONCURRENT=${CONCURRENT:-8}
RPS=${RPS:-400}
OBJ_SIZE=${OBJ_SIZE:-1MiB}
OBJECTS=${OBJECTS:-200}
FAT_BUDGET=${FAT_BUDGET:-32768}
OUT=${OUT:-$HERE/out/s3-$(date -u +%Y%m%dT%H%M%SZ)}

log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die()  { printf '  FATAL: %s\n' "$*" >&2; exit 1; }

nodes() { if [ "$MODE" = dist ]; then echo "1 2 3 4"; else echo "1"; fi; }
node_name() { echo "latkit-bench-minio$1"; }
# The endpoint warp is pointed at. On the pool it is node 1; the fan-out to the
# other three is the traffic this stand exists to measure.
endpoint() { echo "$(node_name 1):$PORT"; }

stack_down() {
    for n in 1 2 3 4; do docker rm -f "$(node_name "$n")" >/dev/null 2>&1 || true; done
    docker network rm "$NET" >/dev/null 2>&1 || true
}

stack_up() {
    stack_down
    docker network create "$NET" >/dev/null
    if [ "$MODE" = dist ]; then
        # A four-node erasure pool. MinIO refuses to form a cluster out of
        # 127.0.0.1 endpoints, so the members address each other by container
        # name on a user-defined bridge — the same arrangement the МS0 corpus
        # was recorded on, and the reason nothing is published.
        local args=""
        for n in $(nodes); do
            args="$args http://$(node_name "$n"):$PORT/data"
        done
        for n in $(nodes); do
            docker run -d --name "$(node_name "$n")" --network "$NET" \
                --network-alias "$(node_name "$n")" \
                -e MINIO_ROOT_USER="$AK" -e MINIO_ROOT_PASSWORD="$SK" \
                -e MINIO_UPDATE=off -e MINIO_PROMETHEUS_AUTH_TYPE=public \
                "$MINIO_IMAGE" server $args --address ":$PORT" >/dev/null
        done
    else
        docker run -d --name "$(node_name 1)" --network "$NET" \
            --network-alias "$(node_name 1)" \
            -e MINIO_ROOT_USER="$AK" -e MINIO_ROOT_PASSWORD="$SK" \
            -e MINIO_UPDATE=off -e MINIO_PROMETHEUS_AUTH_TYPE=public \
            "$MINIO_IMAGE" server /data --address ":$PORT" >/dev/null
    fi
    # `live` answers as soon as the process is up; on a pool that is *before*
    # the members have found each other, and warp's first run then dies with
    # "Server not initialized yet" and reports nothing. `cluster` is the
    # endpoint that waits for quorum, so it is the one to gate on.
    local probe=/minio/health/live
    [ "$MODE" = dist ] && probe=/minio/health/cluster
    for _ in $(seq 180); do
        docker exec "$(node_name 1)" curl -fsS "http://127.0.0.1:$PORT$probe" \
            >/dev/null 2>&1 && break
        sleep 1
    done
    docker exec "$(node_name 1)" curl -fsS "http://127.0.0.1:$PORT$probe" \
        >/dev/null 2>&1 || die "MinIO never became ready ($MODE, $probe)"
}

agent_pid() { pgrep -x latkit || true; }
AGENT_JOB=
# $1 = dump path, $2 = the port's capture budget ("" = the s3 default)
agent_start() {
    local spec="$PORT=s3"
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    [ -n "$2" ] && spec="$PORT=s3:$2"
    sudo -n "$AGENT_BIN" -p "$spec" --dump-metrics="$1" >>"$OUT/agent.log" 2>&1 &
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

# warp <bucket> <rps-limit> -> "<obj/s> <MiB/s> <p99-ms>"; parsed out of warp's
# own summary, which reports throughput per operation and a latency table.
warp_run() {
    docker run --rm --network "$NET" "$WARP_IMAGE" mixed \
        --host="$(endpoint)" --access-key="$AK" --secret-key="$SK" \
        --bucket="$1" --duration="${DURATION}s" --obj.size="$OBJ_SIZE" \
        --objects="$OBJECTS" --concurrent="$CONCURRENT" --rps-limit="$2" \
        --noclear --no-color 2>&1 | tee -a "$OUT/warp.log" |
        python3 -c '
import re, sys
# warp prints a per-operation report and then a "Report: Total" block whose
# Average line carries both rates:
#   Report: Total. Concurrency: 8. Ran: 17s
#    * Average: 238.88 MiB/s, 399.05 obj/s
# The latency is per operation (" * Reqs: ... 99%: 7.2ms"), and there is no
# total for it, so the worst operation is reported — on a mixed run that is the
# PUT, and it is the one a regression would show up in first.
txt = sys.stdin.read()
obj = mib = p99 = 0.0
tail = txt.split("Report: Total", 1)
m = re.search(r"Average:\s*([0-9.]+)\s*MiB/s,\s*([0-9.]+)\s*obj/s", tail[-1])
if m:
    mib, obj = float(m.group(1)), float(m.group(2))
elif len(tail) > 1:
    m = re.search(r"Average:\s*([0-9.]+)\s*obj/s", tail[-1])
    obj = float(m.group(1)) if m else 0.0
ms = {"ms": 1.0, "s": 1e3, "us": 1e-3, "µs": 1e-3, "m": 6e4}
for v, u in re.findall(r"99%:\s*([0-9.]+)(ms|us|µs|s|m)\b", txt):
    p99 = max(p99, float(v) * ms.get(u, 1.0))
print("%.1f %.1f %.2f" % (obj, mib, p99))
'
}

metric() {
    awk -v m="$2" '$1==m || substr($1,1,length(m)+1)==m"{" {s+=$NF} END{printf "%.0f",s+0}' "$1"
}

case "${1:-run}" in
down) stack_down; exit 0 ;;
up)   mkdir -p "$OUT"; stack_up; note "up: $MODE, endpoint $(endpoint)"; exit 0 ;;
run)  ;;
*)    die "usage: $0 [up|run|down]  (MODE=single|dist)" ;;
esac

trap 'agent_stop; [ "${KEEP:-0}" = 1 ] || stack_down' EXIT
mkdir -p "$OUT"
[ -x "$AGENT_BIN" ] || die "agent not built (RelWithDebInfo): $AGENT_BIN"
sudo -n true 2>/dev/null || die "passwordless sudo required"
docker ps --format '{{.Names}}' | grep -qx "$(node_name 1)" || stack_up
note "stand: $MODE ($(nodes | wc -w) node(s)), endpoint $(endpoint)"
note "pairs: $PAIRS, duration: ${DURATION}s, concurrent: $CONCURRENT, cap: ${RPS} rps"
note "objects: $OBJECTS x $OBJ_SIZE"

log "warmup (also uploads the object set warp reuses with --noclear)"
warp_run lkwarp "$RPS" >/dev/null

printf 'pair\tA_objs\tB_objs\tdOBJ%%\tA_MiBs\tB_MiBs\tA_p99ms\tB_p99ms\tagent_cores\tdrops\tevents\tresyncs\tparse_err\n' \
    >"$OUT/runs.tsv"

for p in $(seq 1 "$PAIRS"); do
    log "pair $p: A (no agent) / B (agent) at ${RPS} rps"
    read -r a_obj a_mb a_p99 <<<"$(warp_run lkwarp "$RPS")"
    agent_start "$OUT/agent-$p.prom" ""
    read -r b_obj b_mb b_p99 <<<"$(warp_run lkwarp "$RPS")"
    agent_stop
    dump=$OUT/agent-$p.prom
    drops=$(metric "$dump" latkit_ringbuf_dropped_total)
    events=$(metric "$dump" latkit_events_total)
    resyncs=$(metric "$dump" latkit_resync_total)
    perr=$(metric "$dump" latkit_parse_errors_total)
    cpu=$(awk '$1 == "latkit_process_seconds_total" { print $2 }' "$dump" 2>/dev/null)
    cores=$(python3 -c "print('%.3f' % (float('${cpu:-0}') / ($DURATION + 3)))" 2>/dev/null || echo "?")
    d=$(python3 -c "print('%.1f'%(100*(float('$a_obj')-float('$b_obj'))/float('$a_obj')))" \
         2>/dev/null || echo "?")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$p" "$a_obj" "$b_obj" "$d" "$a_mb" "$b_mb" "$a_p99" "$b_p99" "$cores" \
        "$drops" "$events" "$resyncs" "$perr" | tee -a "$OUT/runs.tsv"
    # What the agent made of the load, and — on the pool — how much of the port
    # was the cluster rather than the client (МS0 recon item 6).
    obs=$(metric "$dump" latkit_s3_requests_total)
    int=$(metric "$dump" latkit_s3_internal_requests_total)
    printf '%s\t%s\t%s\n' "$p" "$obs" "$int" >>"$OUT/share.tsv"
    note "observed: $obs operations, $int internal"
done

# --- РH14 on an object store: the budget is what keeps the ringbuf alive ------
# Deliberately *uncapped*: a saturation probe, not an overhead measurement. The
# question is what happens to the ringbuf when the delivery rate is as high as
# the machine can make it, and a cap would answer a different one.
log "budget comparison at saturation (РH14, risk 2)"
agent_start "$OUT/agent-default.prom" ""
read -r rps_def mb_def _ <<<"$(warp_run lkwarp 0)"
agent_stop
agent_start "$OUT/agent-fat.prom" "$FAT_BUDGET"
read -r rps_fat mb_fat _ <<<"$(warp_run lkwarp 0)"
agent_stop
{
    printf 'budget\tobj/s\tMiB/s\tringbuf_drops\tevents\n'
    printf 'default(2048)\t%s\t%s\t%s\t%s\n' "$rps_def" "$mb_def" \
        "$(metric "$OUT/agent-default.prom" latkit_ringbuf_dropped_total)" \
        "$(metric "$OUT/agent-default.prom" latkit_events_total)"
    printf 'fat(%s)\t%s\t%s\t%s\t%s\n' "$FAT_BUDGET" "$rps_fat" "$mb_fat" \
        "$(metric "$OUT/agent-fat.prom" latkit_ringbuf_dropped_total)" \
        "$(metric "$OUT/agent-fat.prom" latkit_events_total)"
} | tee "$OUT/budget.tsv"

log "verdict"
python3 - "$OUT/runs.tsv" "$OUT/budget.tsv" "$MODE" <<'PY'
import sys, statistics as st

rows, dropped = [], 0
for line in open(sys.argv[1]):
    f = line.rstrip("\n").split("\t")
    if len(f) < 13 or f[0] == "pair":
        continue
    try:
        r = tuple(float(x) for x in (f[1], f[2], f[4], f[5], f[6], f[7], f[8])) \
            + (int(f[9]), int(f[10]), int(f[11]))
    except ValueError:
        continue
    # A pair whose load generator reported nothing is not a slow pair, it is a
    # failed run (warp refusing a pool that has not reached quorum, say).
    # Averaging a zero into the baseline would report the agent as making the
    # server twice as fast; say how many were dropped instead.
    if r[0] <= 0 or r[1] <= 0:
        dropped += 1
        continue
    rows.append(r)
if dropped:
    print("  %d pair(s) dropped: the load generator reported no throughput" % dropped)
if not rows:
    print("  no valid runs")
    sys.exit(1)
med = lambda i: st.median([r[i] for r in rows])
drops = sum(r[7] for r in rows)
events = sum(r[8] for r in rows)
resyncs = sum(r[9] for r in rows)
valid = "valid" if drops == 0 else "INVALID (the agent dropped events)"
print("  %-6s obj/s A=%8.1f B=%8.1f (%+.1f%%)  MiB/s A=%8.1f B=%8.1f  "
      "p99 %6.1f>%6.1f ms" % (sys.argv[3], med(0), med(1),
                              100 * (med(1) - med(0)) / max(med(0), 1e-9),
                              med(2), med(3), med(4), med(5)))
print("  agent=%.3f cores  events=%d  drops=%d (%.4f%%)  resyncs=%d  [%s]"
      % (med(6), events, drops, 100.0 * drops / max(events, 1), resyncs, valid))

print("  budget at saturation:")
for line in list(open(sys.argv[2]))[1:]:
    name, obj, mib, dr, ev = line.rstrip("\n").split("\t")
    print("    %-14s %9s obj/s  %9s MiB/s  drops=%s of %s events" % (name, obj, mib, dr, ev))
PY
note "per-run table: $OUT/runs.tsv; budget table: $OUT/budget.tsv; warp log: $OUT/warp.log"
