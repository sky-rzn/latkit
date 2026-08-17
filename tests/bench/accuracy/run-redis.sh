#!/usr/bin/env bash
#
# Redis accuracy validation stand (PLAN-REDIS.md МR8).
#
# One controlled workload, four views of it — and unlike the three stands before
# it, the references here disagree with each other *by design*, which is what
# makes them worth having all three:
#
#   - the agent's observations       (--record, replayed through lkt_queries);
#   - `INFO commandstats`            how many times each command ran, and its
#                                    mean service time inside the server;
#   - `SLOWLOG GET` at threshold 0   the per-command execution time, not an
#                                    average — the strongest reference of the
#                                    three, and the only one that can be paired
#                                    with ours command by command;
#   - `memtier_benchmark`            the client's own latency, which contains
#                                    ours plus a network hop.
#
# Two inequalities and one equality (§2 of the plan, made checkable):
#
#     SLOWLOG(cmd_k)  <=  latkit(cmd_k)  <=  memtier(client)
#     count(commandstats)  ==  count(latkit)
#
# The middle term is the whole argument of the track. `commandstats` measures
# the command's execution *inside* a single-threaded server; latkit measures
# network-to-network on the server's host, so the difference is the time spent
# reading the command off the socket, writing the reply, and waiting in the
# event loop behind somebody else's slow command. That last one is the reason
# `DEBUG SLEEP` is in the workload: a `GET` queued behind it is fast by the
# server's own account and slow by the application's, and only one of the two
# views can see it.
#
# The workload is deliberately **serial** — `redis-cli -r N`, one connection,
# one command outstanding at a time — because the pairing above needs the k-th
# entry on each side to be the same execution. A pipelined workload would make
# the server's duration and ours describe different intervals (queueing is ours
# and not the server's), which is a real fact about pipelining and not something
# to smuggle into an accuracy number.
#
# Usage:
#   tests/bench/accuracy/run-redis.sh          # run the campaign
#   tests/bench/accuracy/run-redis.sh down     # remove a leftover stand
#
# Knobs (env): REPEAT=200, SLEEP_MS=50, MIN_SAMPLES=100, AGENT_BIN=build-rel/latkit,
#   PORT=6577, MEMTIER=1, OUT=tests/bench/accuracy/out/redis-<ts>
#
# Requirements: an optimised agent build (an -O0 agent can drop under burst and
# invalidate the run), docker, passwordless sudo.

set -euo pipefail

cd "$(dirname "$0")/../../.."       # repo root

CMD=${1:-run}
REPEAT=${REPEAT:-200}
SLEEP_MS=${SLEEP_MS:-50}
MIN_SAMPLES=${MIN_SAMPLES:-100}
AGENT_BIN=${AGENT_BIN:-build-rel/latkit}
PORT=${PORT:-6577}
RUN_MEMTIER=${MEMTIER:-1}
OUT=${OUT:-tests/bench/accuracy/out/redis-$(date -u +%Y%m%dT%H%M%SZ)}
case "$OUT" in /*) ;; *) OUT=$PWD/$OUT ;; esac

REDIS_IMAGE=${REDIS_IMAGE:-redis:7.4}
MEMTIER_IMAGE=${MEMTIER_IMAGE:-redislabs/memtier_benchmark:latest}
NET=latkit-acc-redis-net
REDIS=latkit-acc-redis

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

stack_down() {
    docker rm -f "$REDIS" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}

agent_pid() { pgrep -x latkit || true; }

AGENT_JOB=
agent_start() {   # $1 = run dir
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    # --record rather than --queries because the join wants the *replayed*
    # view, which is reproducible from the artefact this leaves behind.
    sudo -n "$AGENT_BIN" -p "$PORT=redis" \
        --record "$1/run.lkt" --dump-metrics="$1/agent.prom" \
        >>"$1/agent.log" 2>&1 &
    AGENT_JOB=$!
    sleep 3
    [ -n "$(agent_pid)" ] || die "agent did not come up (see $1/agent.log)"
}

agent_stop() {
    local pid; pid=$(agent_pid)
    if [ -n "$pid" ]; then
        sudo -n kill -INT "$pid"
        for _ in $(seq 100); do
            [ -z "$(agent_pid)" ] && break
            sleep 0.2
        done
        [ -z "$(agent_pid)" ] || sudo -n kill -KILL "$(agent_pid)" || true
    fi
    [ -n "$AGENT_JOB" ] && { wait "$AGENT_JOB" 2>/dev/null || true; }
    AGENT_JOB=
}

cleanup() { agent_stop; stack_down; }

stack_up() {
    stack_down
    docker network create "$NET" >/dev/null
    # `--slowlog-log-slower-than 0` logs every command with its execution time,
    # which is the reference this stand is built on; the log is a ring, so it
    # has to be long enough to hold the whole workload. No persistence: a
    # background save would put a fork into the numbers.
    docker run -d --name "$REDIS" --network "$NET" --network-alias redis \
        "$REDIS_IMAGE" redis-server \
        --port "$PORT" --save "" --appendonly no \
        --slowlog-log-slower-than 0 --slowlog-max-len 16384 \
        --enable-debug-command yes >/dev/null
    for _ in $(seq 60); do
        docker exec "$REDIS" redis-cli -p "$PORT" ping 2>/dev/null | grep -q PONG && break
        sleep 1
    done
    docker exec "$REDIS" redis-cli -p "$PORT" ping 2>/dev/null | grep -q PONG \
        || die "Redis never became ready"
}

# One serial run of a command, N times on one connection. `-r N` is what makes
# it serial: redis-cli sends the command, waits for the reply, and only then
# sends the next — which is the property the pairing below needs, and the one a
# pipelined client would take away.
rcli() { docker run --rm --network "$NET" "$REDIS_IMAGE" \
             redis-cli -h redis -p "$PORT" "$@"; }

case $CMD in
    down) stack_down; exit 0 ;;
    run)  ;;
    *)    die "unknown command '$CMD' (run|down)" ;;
esac

[ -x "$AGENT_BIN" ] || die "no agent binary at $AGENT_BIN (build-rel recipe in tests/bench/run.sh)"
BUILD_DIR=$(dirname "$AGENT_BIN")
BUILD_TYPE=$(sed -n 's/^CMAKE_BUILD_TYPE:STRING=//p' "$BUILD_DIR/CMakeCache.txt" 2>/dev/null || echo unknown)
case "$BUILD_TYPE" in
    Release|RelWithDebInfo) ;;
    *) die "$AGENT_BIN is not an optimised build (CMAKE_BUILD_TYPE='$BUILD_TYPE')" ;;
esac
sudo -n true 2>/dev/null || die "passwordless sudo required"

log "building lkt_queries"
cmake --build build --target lkt_queries -j >/dev/null

mkdir -p "$OUT"
trap cleanup EXIT INT TERM

log "bringing the stand up (Redis on :$PORT, slowlog threshold 0)"
stack_up

# Seed the keys the workload reads, before the agent attaches: a `SET` of a
# fixture is not part of what is being measured.
rcli set lk:k1 value1 >/dev/null
rcli rpush lk:list a b c d e f g h i j >/dev/null
rcli hset lk:hash f1 v1 f2 v2 >/dev/null
rcli set lk:str notalist >/dev/null

agent_start "$OUT"

log "driving the workload ($REPEAT x each shape, serial)"
# Both server-side references are reset *after* the agent attached, so the three
# views cover exactly the same interval: the keys were seeded before, and a
# fixture's `SET` is not part of what is being measured. The two reset commands
# and the two that read the references are themselves logged at threshold 0 and
# are excluded by name in the join — counting the measurement as part of the
# measurement is how a bench lies to itself.
rcli config resetstat >/dev/null
rcli slowlog reset >/dev/null

for spec in \
    "get lk:k1" \
    "set lk:k2 value2" \
    "incr lk:counter" \
    "mget lk:k1 lk:k2 lk:missing" \
    "hgetall lk:hash" \
    "lrange lk:list 0 -1" \
    "lpush lk:str x" \
    "ping"
do
    # shellcheck disable=SC2086
    rcli -r "$REPEAT" $spec >/dev/null 2>&1 || true
done
# The event loop is single-threaded, and this is the one shape where our number
# and the server's own *must* differ: `DEBUG SLEEP` occupies the loop, so the
# commands behind it wait — for the application they are slow, for
# `commandstats` they are as fast as ever. The join reports the gap; this leg is
# what makes the gap large enough to see.
( rcli debug sleep "$(python3 -c "print($SLEEP_MS/1000.0)")" >/dev/null 2>&1 || true ) &
sleeper=$!
sleep 0.02
rcli -r 20 get lk:k1 >/dev/null 2>&1 || true
# By pid, not a bare `wait`: the agent itself is a background job of this shell
# (agent_start launches it with &), and a bare wait would block on a process
# that is meant to outlive this step.
wait "$sleeper" 2>/dev/null || true

sleep 1
agent_stop

log "collecting the server's own views"
docker exec "$REDIS" redis-cli -p "$PORT" info commandstats > "$OUT/commandstats.txt" 2>/dev/null
docker exec "$REDIS" redis-cli -p "$PORT" --json slowlog get 16384 > "$OUT/slowlog.json" 2>/dev/null

[ -s "$OUT/run.lkt" ] || die "the agent recorded nothing"
[ -s "$OUT/slowlog.json" ] || die "SLOWLOG produced nothing (threshold not 0?)"
sudo -n chmod a+r "$OUT/run.lkt" "$OUT/agent.prom" 2>/dev/null || true

log "replaying the recording through the handler"
build/tests/replay/lkt_queries --proto redis "$OUT/run.lkt" >"$OUT/queries.txt" 2>&1

# The third reference: the client's own latency, on a load of its own. Run
# after the paired workload so it cannot disturb the pairing, and read only in
# aggregate — memtier reports percentiles, not per-command times.
if [ "$RUN_MEMTIER" = 1 ]; then
    log "memtier leg (client-side latency)"
    mkdir -p "$OUT/mt"
    agent_start "$OUT/mt"
    docker run --rm --network "$NET" "$MEMTIER_IMAGE" \
        --server=redis --port="$PORT" --protocol=redis \
        --clients=2 --threads=1 --pipeline=1 --ratio=1:4 --data-size=64 \
        --key-prefix=lk:mt- --test-time=15 --hide-histogram \
        >"$OUT/memtier.txt" 2>&1 || true
    sleep 1
    agent_stop
    sudo -n chmod a+r "$OUT/mt/run.lkt" 2>/dev/null || true
    build/tests/replay/lkt_queries --proto redis "$OUT/mt/run.lkt" \
        >"$OUT/mt-queries.txt" 2>&1 || true
fi

log "joining"
RC=0
python3 tests/bench/accuracy/redis_join.py \
    --agent "$OUT/queries.txt" --slowlog "$OUT/slowlog.json" \
    --commandstats "$OUT/commandstats.txt" --min-samples "$MIN_SAMPLES" \
    >"$OUT/join.tsv" 2>"$OUT/join.summary" || RC=$?

# The memtier inequality is joined separately: it is a different workload, so
# it has its own agent recording and its own summary.
if [ -s "${OUT}/mt-queries.txt" ]; then
    python3 tests/bench/accuracy/redis_join.py \
        --agent "$OUT/mt-queries.txt" --slowlog "$OUT/slowlog.json" \
        --commandstats "$OUT/commandstats.txt" --memtier "$OUT/memtier.txt" \
        --memtier-only --min-samples 0 \
        >"$OUT/memtier-join.tsv" 2>"$OUT/memtier.summary" || RC=$?
fi

REPORT=$OUT/report.txt
{
    echo "latkit Redis accuracy validation (PLAN-REDIS.md МR8)"
    echo "===================================================="
    echo "date     : $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "commit   : $(git rev-parse --short HEAD)$(git diff --quiet || echo -dirty)"
    echo "agent    : $("$AGENT_BIN" --version) [$BUILD_TYPE, $AGENT_BIN]"
    echo "kernel   : $(uname -r)"
    echo "stand    : $REDIS_IMAGE on :$PORT, slowlog-log-slower-than 0"
    echo "workload : $REPEAT x {get, set, incr, mget, hgetall, lrange, lpush(WRONGTYPE), ping},"
    echo "           serial, one connection per shape"
    echo "reference: INFO commandstats (counts + mean), SLOWLOG GET (per command),"
    echo "           memtier_benchmark (client latency)"
    echo "gates    : counts equal commandstats exactly; <= 1 % of paired durations"
    echo "           below the server's own execution time; our p50 <= memtier's"
    echo
    cat "$OUT/join.summary"
    [ -s "$OUT/memtier.summary" ] && { echo; cat "$OUT/memtier.summary"; }
    echo
    echo "counters from the run:"
    grep -E '^latkit_(parse_errors_total|resync_total|ringbuf_dropped_total|queries_dropped_total)' \
        "$OUT/agent.prom" 2>/dev/null | sed 's/^/  /' || true
    echo
    echo "per-command table: $OUT/join.tsv"
} >"$REPORT"

# A run with drops or resyncs is not a valid measurement — the same rule the
# three stands before it apply (Р49/Р50): "the count matches exactly" means
# nothing on a lossy capture.
drops=$(awk '$1 == "latkit_ringbuf_dropped_total" { print $2 }' "$OUT/agent.prom" 2>/dev/null)
resyncs=$(awk '$1 == "latkit_resync_total" { print $2 }' "$OUT/agent.prom" 2>/dev/null)
{
    printf 'validity : ringbuf_dropped=%s resync_total=%s -> ' "${drops:-?}" "${resyncs:-?}"
    if [ "${drops:-1}" = "0" ] && [ "${resyncs:-1}" = "0" ]; then
        echo "VALID"
    else
        echo "INVALID (the run is not lossless; the join numbers do not stand)"
        RC=1
    fi
} >>"$REPORT"

log "done; report: $REPORT"
cat "$REPORT"
exit "$RC"
