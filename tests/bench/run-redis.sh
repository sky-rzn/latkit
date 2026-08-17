#!/usr/bin/env bash
#
# Redis overhead benchmark and the МR8 perf gate (PLAN-REDIS.md; the cache
# analogue of run.sh / run-mysql.sh / run-http.sh / run-s3.sh, Р49).
#
# This stand is different from the four before it in one respect, and it is the
# respect the whole track's риск 2 is about: **Redis is an order of magnitude
# faster than anything the agent has watched**. A single instance answers
# 100–200k ops/s from one core, and without pipelining every one of those is two
# syscalls, hence two ringbuf records — 400k events/s from one server process,
# more than ten busy PostgreSQL put together. So the question here is not "what
# does the agent cost the server" (it is a probe on a syscall; it costs what it
# costs) but "does the delivery path survive the rate at all".
#
# Two loads, because the worst case is two different things:
#
#   A. **memtier without pipelining** — the worst case *by event count*. Every
#      command is its own recvmsg and its own sendmsg. This is the gate.
#   B. **memtier with `--pipeline 100`** — the worst case *by bytes*, and the
#      pleasant surprise of the track: a hundred commands arrive in one call, so
#      the event rate collapses while the byte rate rises. Pipelining works in
#      the agent's favour, and this leg is what says by how much.
#
# Each leg is a paired ABAB run against a baseline, medians compared, so machine
# drift is smeared over both sides:
#
#   A  no agent                      baseline
#   B  agent up, redis capture       fentry probes + ringbuf + RESP framer +
#                                     the unit queue + the command table
#
# A run is VALID only if the agent dump shows zero latkit_ringbuf_dropped_total
# during it: an agent that drops events looks cheaper than one that works.
#
# **The gate** (МR8): on the non-pipelined leg the drop rate must stay at zero
# with the per-port budget of РR13 (512 bytes). If it does not, the plan's
# fallback is kernel-side connection sampling — take 1 in N by socket hash,
# statistically honest for distributions and documented as such — which is a
# separate decision and a separate risk, deliberately not taken in advance.
#
# The budget comparison at the end is what makes the 512 a measurement rather
# than a preference, and it is run **pipelined**, which is where the number
# decides anything at all: unpipelined, a 64-byte command and its reply fit
# inside 512 bytes whatever the budget is. With a batch of 100 the budget
# decides how much of each batch is *seen*, so the table reports coverage —
# commands observed against commands sent — beside the drop rate.
#
# Usage:
#   tests/bench/run-redis.sh up        # start the stand (once)
#   tests/bench/run-redis.sh run       # the benchmark (default)
#   tests/bench/run-redis.sh down      # remove the stand
#
# Knobs (env): PAIRS=3, DURATION=20, CLIENTS=25, THREADS=4, PIPELINE=100,
#   DATA_SIZE=64, RATE=500 (per connection, paired runs only), FAT_BUDGET=32768,
#   AGENT_BIN=build-rel/latkit, OUT=tests/bench/out/redis-<ts>
#
# Requirements: docker (redis, memtier images), passwordless sudo for the agent
# (BPF), an OPTIMISED agent build (build-rel), python3.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
AGENT_BIN=${AGENT_BIN:-$REPO_ROOT/build-rel/latkit}

REDIS_IMAGE=${REDIS_IMAGE:-redis:7.4}
MEMTIER_IMAGE=${MEMTIER_IMAGE:-redislabs/memtier_benchmark:latest}
NET=latkit-bench-redis-net
NODE=latkit-bench-redis
PORT=${PORT:-6578}

PAIRS=${PAIRS:-3}
DURATION=${DURATION:-20}
CLIENTS=${CLIENTS:-25}
THREADS=${THREADS:-4}
PIPELINE=${PIPELINE:-100}
DATA_SIZE=${DATA_SIZE:-64}
# Per-connection cap for the paired runs (Р49): 100 connections x 500 = ~50k
# ops/s, well under this stand's ~230k saturation point. Uncapped pairs would
# measure the scheduler — the agent, the server and memtier competing for the
# same cores — which is a real effect and not the agent's overhead. The
# saturation question has its own section at the end.
RATE=${RATE:-500}
FAT_BUDGET=${FAT_BUDGET:-32768}
OUT=${OUT:-$HERE/out/redis-$(date -u +%Y%m%dT%H%M%SZ)}

log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die()  { printf '  FATAL: %s\n' "$*" >&2; exit 1; }

stack_down() {
    docker rm -f "$NODE" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}

stack_up() {
    stack_down
    docker network create "$NET" >/dev/null
    # No persistence and no eviction: a background save or an eviction sweep
    # would be measured as the agent's cost.
    docker run -d --name "$NODE" --network "$NET" --network-alias redis \
        "$REDIS_IMAGE" redis-server --port "$PORT" --save "" --appendonly no \
        --maxmemory 0 >/dev/null
    for _ in $(seq 60); do
        docker exec "$NODE" redis-cli -p "$PORT" ping 2>/dev/null | grep -q PONG && break
        sleep 1
    done
    docker exec "$NODE" redis-cli -p "$PORT" ping 2>/dev/null | grep -q PONG \
        || die "Redis never became ready"
}

agent_pid() { pgrep -x latkit || true; }
AGENT_JOB=
# $1 = dump path, $2 = the port's capture budget ("" = the redis default, 512)
agent_start() {
    local spec="$PORT=redis"
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    [ -n "$2" ] && spec="$PORT=redis:$2"
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

# memtier <pipeline> [rate-per-conn] -> "<ops/s> <p50-ms> <p99-ms>"; parsed out
# of its Totals line, the one row that covers both Sets and Gets. A rate of 0
# means uncapped (the saturation probe).
memtier_run() {
    local rate=${2:-0} cap=()

    [ "$rate" -gt 0 ] 2>/dev/null && cap=("--rate-limiting=$rate")
    docker run --rm --network "$NET" "$MEMTIER_IMAGE" \
        --server=redis --port="$PORT" --protocol=redis \
        --clients="$CLIENTS" --threads="$THREADS" --pipeline="$1" \
        --ratio=1:4 --data-size="$DATA_SIZE" --key-prefix=lk:b- \
        "${cap[@]}" \
        --test-time="$DURATION" --hide-histogram 2>&1 | tee -a "$OUT/memtier.log" |
        python3 -c '
import re, sys
# memtier prints a per-type table and a Totals row:
#   Totals    156820.96   487.48   124969.14   0.39994   0.34300   1.59900 ...
# columns: Ops/sec Hits/sec Misses/sec Avg p50 p99 p99.9 KB/sec
txt = sys.stdin.read()
m = re.search(r"^Totals\s+([\d.]+)\s+\S+\s+\S+\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", txt, re.M)
print("%s %s %s" % (m.group(1), m.group(3), m.group(4)) if m else "0 0 0")
'
}

metric() {
    awk -v m="$2" '$1==m || substr($1,1,length(m)+1)==m"{" {s+=$NF} END{printf "%.0f",s+0}' "$1"
}

case "${1:-run}" in
down) stack_down; exit 0 ;;
up)   mkdir -p "$OUT"; stack_up; note "up: redis on :$PORT"; exit 0 ;;
run)  ;;
*)    die "usage: $0 [up|run|down]" ;;
esac

trap 'agent_stop; [ "${KEEP:-0}" = 1 ] || stack_down' EXIT
mkdir -p "$OUT"
[ -x "$AGENT_BIN" ] || die "agent not built (RelWithDebInfo): $AGENT_BIN"
sudo -n true 2>/dev/null || die "passwordless sudo required"
docker ps --format '{{.Names}}' | grep -qx "$NODE" || stack_up
note "stand: $REDIS_IMAGE on :$PORT"
note "pairs: $PAIRS, duration: ${DURATION}s, clients: $CLIENTS x $THREADS threads"
note "data size: $DATA_SIZE B; pipelined leg: --pipeline $PIPELINE"

log "warmup (also populates the key space memtier reuses)"
memtier_run 1 0 >/dev/null

printf 'leg\tpair\tA_ops\tB_ops\tdOPS%%\tA_p50\tB_p50\tA_p99\tB_p99\tagent_cores\tdrops\tevents\tcmds\tresyncs\tparse_err\n' \
    >"$OUT/runs.tsv"

for leg in nopipe pipe100; do
    pl=1
    [ "$leg" = pipe100 ] && pl=$PIPELINE
    for p in $(seq 1 "$PAIRS"); do
        log "$leg pair $p: A (no agent) / B (agent), pipeline=$pl, cap ${RATE}/conn"
        read -r a_ops a_p50 a_p99 <<<"$(memtier_run "$pl" "$RATE")"
        agent_start "$OUT/agent-$leg-$p.prom" ""
        read -r b_ops b_p50 b_p99 <<<"$(memtier_run "$pl" "$RATE")"
        agent_stop
        dump=$OUT/agent-$leg-$p.prom
        drops=$(metric "$dump" latkit_ringbuf_dropped_total)
        events=$(metric "$dump" latkit_events_total)
        cmds=$(metric "$dump" latkit_redis_commands_total)
        resyncs=$(metric "$dump" latkit_resync_total)
        perr=$(metric "$dump" latkit_parse_errors_total)
        cpu=$(awk '$1 == "latkit_process_seconds_total" { print $2 }' "$dump" 2>/dev/null)
        cores=$(python3 -c "print('%.3f' % (float('${cpu:-0}') / ($DURATION + 3)))" 2>/dev/null || echo "?")
        d=$(python3 -c "print('%.1f'%(100*(float('$a_ops')-float('$b_ops'))/float('$a_ops')))" \
             2>/dev/null || echo "?")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$leg" "$p" "$a_ops" "$b_ops" "$d" "$a_p50" "$b_p50" "$a_p99" "$b_p99" \
            "$cores" "$drops" "$events" "$cmds" "$resyncs" "$perr" | tee -a "$OUT/runs.tsv"
        note "observed: $cmds commands from $events events"
    done
done

# --- РR13 measured: what 512 bytes buys and what it costs --------------------
# Uncapped and **pipelined**, which is where the budget actually decides
# something. Unpipelined, a 64-byte command and its reply fit inside 512 bytes
# whatever the budget is, and the two configurations are indistinguishable
# (measured: 143 962 vs 142 382 ops/s, zero drops on both). With `--pipeline
# 100` one write carries ~7 KB of commands, so the budget decides how much of
# each batch is *seen* — and that is a coverage question, not a drop-rate one.
#
# The table therefore reports both: the drops the plan's риск 2 is about, and
# the share of the commands the client sent that reached an observation.
log "budget comparison at saturation, pipelined (РR13, risk 1 and risk 2)"
agent_start "$OUT/agent-default.prom" ""
read -r ops_def p50_def _ <<<"$(memtier_run "$PIPELINE" 0)"
agent_stop
agent_start "$OUT/agent-fat.prom" "$FAT_BUDGET"
read -r ops_fat p50_fat _ <<<"$(memtier_run "$PIPELINE" 0)"
agent_stop
# ... and the same comparison unpipelined, to show that there it is a
# non-question: one command per call, and 512 bytes already holds it.
agent_start "$OUT/agent-nopipe-default.prom" ""
read -r ops_np p50_np _ <<<"$(memtier_run 1 0)"
agent_stop
{
    printf 'load\tbudget\tops/s\tsent\tobserved\tcoverage%%\tringbuf_drops\tevents\tresyncs\n'
    for row in "pipe$PIPELINE|default(512)|$ops_def|$OUT/agent-default.prom" \
               "pipe$PIPELINE|fat($FAT_BUDGET)|$ops_fat|$OUT/agent-fat.prom" \
               "nopipe|default(512)|$ops_np|$OUT/agent-nopipe-default.prom"; do
        IFS='|' read -r load budget ops dump <<<"$row"
        obs=$(metric "$dump" latkit_redis_commands_total)
        sent=$(python3 -c "print(int(float('$ops') * $DURATION))")
        cov=$(python3 -c "print('%.1f' % (100.0 * $obs / max($sent, 1)))")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$load" "$budget" "$ops" \
            "$sent" "$obs" "$cov" \
            "$(metric "$dump" latkit_ringbuf_dropped_total)" \
            "$(metric "$dump" latkit_events_total)" \
            "$(metric "$dump" latkit_resync_total)"
    done
} | tee "$OUT/budget.tsv"

log "verdict"
python3 - "$OUT/runs.tsv" "$OUT/budget.tsv" <<'PY'
import sys, statistics as st

legs = {}
for line in open(sys.argv[1]):
    f = line.rstrip("\n").split("\t")
    if len(f) < 15 or f[0] == "leg":
        continue
    try:
        row = tuple(float(x) for x in f[2:10]) + tuple(int(x) for x in f[10:15])
    except ValueError:
        continue
    if row[0] <= 0 or row[1] <= 0:
        continue
    legs.setdefault(f[0], []).append(row)

gate_ok = True
for leg, rows in legs.items():
    med = lambda i: st.median([r[i] for r in rows])
    drops = sum(r[8] for r in rows)
    events = sum(r[9] for r in rows)
    cmds = sum(r[10] for r in rows)
    resyncs = sum(r[11] for r in rows)
    perr = sum(r[12] for r in rows)
    rate = 100.0 * drops / max(events, 1)
    print("  %-8s ops/s A=%9.0f B=%9.0f (%+.1f%%)  p50 %5.3f>%5.3f ms  p99 %5.3f>%5.3f ms"
          % (leg, med(0), med(1), 100 * (med(1) - med(0)) / max(med(0), 1e-9),
             med(3), med(4), med(5), med(6)))
    print("           agent=%.3f cores  events=%d  commands=%d  drops=%d (%.4f%%)  "
          "resyncs=%d  parse_errors=%d" % (med(7), events, cmds, drops, rate, resyncs, perr))
    # The gate is the unpipelined leg: it is the one with the event rate.
    if leg == "nopipe" and (drops or perr):
        gate_ok = False

print("  budget at saturation (what 512 bytes buys, and what it costs):")
for line in list(open(sys.argv[2]))[1:]:
    load, budget, ops, sent, obs, cov, dr, ev, rs = line.rstrip("\n").split("\t")
    print("    %-9s %-14s %10s ops/s  observed %s of %s (%s%%)  drops=%s of %s  resyncs=%s"
          % (load, budget, ops, obs, sent, cov, dr, ev, rs))

print("  GATE (МR8): %s" % ("passed — no drops and no parse errors on the unpipelined leg"
                            if gate_ok else
                            "FAILED — see risk 2 of PLAN-REDIS.md (connection sampling)"))
sys.exit(0 if gate_ok else 1)
PY
rc=$?
note "per-run table: $OUT/runs.tsv; budget table: $OUT/budget.tsv; memtier log: $OUT/memtier.log"
exit "$rc"
