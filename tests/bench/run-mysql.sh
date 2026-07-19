#!/usr/bin/env bash
#
# MySQL overhead benchmark (MYSQL.md М7 — the mysql analogue of run.sh /
# task 8.1, Р49).
#
# One load, paired ABAB runs against a baseline, medians compared so machine
# drift is smeared over both sides:
#
#   A  no agent                          baseline
#   B  agent up, plaintext capture       fentry probes + ringbuf + pipeline +
#                                         the classic-protocol parser
#
# The load is `mysqlslap` (ships in the mysql image — no external sysbench
# dependency), a read-mostly point-query mix at fixed concurrency, driven at the
# container IP (never 127.0.0.1 — the docker-proxy relay would pollute the
# capture). A run is VALID only if the agent dump shows zero
# latkit_ringbuf_dropped_total and zero latkit_resync_total during it: an agent
# that drops events looks cheaper than one that works (Р49). The mysqld is tuned
# CPU-bound (the dataset fits in the buffer pool, durability relaxed) so the
# load measures the agent, not the disk.
#
# Usage:
#   tests/bench/run-mysql.sh up      # start + seed the container (once)
#   tests/bench/run-mysql.sh run     # the benchmark (default)
#   tests/bench/run-mysql.sh down    # remove the container
#
# Knobs (env): PAIRS=5, CONCURRENCY=32, ITERATIONS=20, NUMBER_QUERIES=2000,
#   SCALE=10000, AGENT_BIN=build-rel/latkit, OUT=tests/bench/out/mysql-<ts>.
#
# Requirements: docker; passwordless sudo for the agent (BPF); an OPTIMISED
# agent build (build-rel), python3. Mirrors run.sh's caveats.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
AGENT_BIN=${AGENT_BIN:-$REPO_ROOT/build-rel/latkit}
IMAGE=mysql:8.4
MY=latkit-bench-mysql
DB_NAME=bench
DB_PW=pw
PROM=http://127.0.0.1:9752/metrics

PAIRS=${PAIRS:-5}
CONCURRENCY=${CONCURRENCY:-32}
ITERATIONS=${ITERATIONS:-20}
NUMBER_QUERIES=${NUMBER_QUERIES:-2000}
SCALE=${SCALE:-10000}
OUT=${OUT:-$HERE/out/mysql-$(date -u +%Y%m%dT%H%M%SZ)}

log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die()  { printf '  FATAL: %s\n' "$*" >&2; exit 1; }

myx() { docker exec -i "$MY" mysql -uroot -p"$DB_PW" "$@" 2>/dev/null; }
container_ip() {
    docker inspect "$MY" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
}

agent_pid() { pgrep -x latkit || true; }
AGENT_JOB=
agent_start() {
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    sudo -n "$AGENT_BIN" -p 3306=mysql --dump-metrics="$1" \
        --prom-listen 127.0.0.1:9752 >>"$OUT/agent.log" 2>&1 &
    AGENT_JOB=$!
    for _ in $(seq 100); do curl -fsS -o /dev/null "$PROM" 2>/dev/null && return 0; sleep 0.2; done
    die "agent did not come up (see $OUT/agent.log)"
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

stack_up() {
    docker rm -f "$MY" >/dev/null 2>&1 || true
    docker run -d --name "$MY" \
        -e MYSQL_ROOT_PASSWORD="$DB_PW" -e MYSQL_DATABASE="$DB_NAME" \
        "$IMAGE" mysqld --skip-ssl \
        --innodb_buffer_pool_size=512M --innodb_flush_log_at_trx_commit=0 \
        --sync_binlog=0 --skip-log-bin --max_connections=256 >/dev/null
    for _ in $(seq 90); do myx -e 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
    myx -e 'SELECT 1' >/dev/null 2>&1 || die "mysqld did not become ready"
    note "seeding $SCALE rows"
    myx "$DB_NAME" <<SQL
CREATE TABLE IF NOT EXISTS accounts (id INT PRIMARY KEY, abalance INT NOT NULL, filler CHAR(84));
SET SESSION cte_max_recursion_depth = $((SCALE + 1));
INSERT INTO accounts (id, abalance, filler)
    SELECT n, 0, 'x' FROM (
        WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < $SCALE)
        SELECT n FROM seq) s
ON DUPLICATE KEY UPDATE abalance = accounts.abalance;
SQL
}

# One mysqlslap run at the container IP; prints "seconds to run all queries".
slap() {
    docker run --rm --network host "$IMAGE" mysqlslap \
        --no-defaults -h "$1" -uroot -p"$DB_PW" --create-schema="$DB_NAME" \
        --concurrency="$CONCURRENCY" --iterations="$ITERATIONS" \
        --number-of-queries="$NUMBER_QUERIES" --delimiter=';' \
        --query="SELECT abalance FROM accounts WHERE id = FLOOR(1+RAND()*$SCALE)" 2>/dev/null \
        | awk '/seconds to run all queries/ { print $(NF-4) }' | head -1
}

metric() { awk -v m="$2" '$1==m || substr($1,1,length(m)+1)==m"{" {s+=$NF} END{printf "%.0f",s+0}' "$1"; }

case "${1:-run}" in
down) docker rm -f "$MY" >/dev/null 2>&1 || true; exit 0 ;;
up)   mkdir -p "$OUT"; stack_up; note "up: $MY at $(container_ip)"; exit 0 ;;
run)  ;;
*)    die "usage: $0 [up|run|down]" ;;
esac

trap 'agent_stop; [ "${KEEP:-0}" = 1 ] || docker rm -f "$MY" >/dev/null 2>&1 || true' EXIT
mkdir -p "$OUT"
[ -x "$AGENT_BIN" ] || die "agent not built (RelWithDebInfo): $AGENT_BIN"
docker ps --format '{{.Names}}' | grep -qx "$MY" || stack_up
IP=$(container_ip)
note "container IP: $IP, pairs: $PAIRS, concurrency: $CONCURRENCY"

log "warmup"
slap "$IP" >/dev/null || true

log "paired A (no agent) / B (agent) runs"
printf 'pair\tA_secs\tB_secs\toverhead%%\n' >"$OUT/runs.tsv"
As=(); Bs=()
for p in $(seq 1 "$PAIRS"); do
    a=$(slap "$IP")
    agent_start "$OUT/agent-$p.prom"
    b=$(slap "$IP")
    agent_stop
    drops=$(metric "$OUT/agent-$p.prom" latkit_ringbuf_dropped_total)
    resyncs=$(metric "$OUT/agent-$p.prom" latkit_resync_total)
    valid="ok"; [ "${drops:-0}" -ne 0 ] || [ "${resyncs:-0}" -ne 0 ] && valid="INVALID(drops=$drops resyncs=$resyncs)"
    ov=$(python3 -c "print('%.1f'%(100*(float('$b')-float('$a'))/float('$a')))" 2>/dev/null || echo "?")
    printf '%s\t%s\t%s\t%s\t%s\n' "$p" "$a" "$b" "$ov" "$valid" | tee -a "$OUT/runs.tsv"
    As+=("$a"); Bs+=("$b")
done

log "verdict"
python3 - "$OUT/runs.tsv" <<'PY'
import sys, statistics as st
A=[]; B=[]
for line in open(sys.argv[1]):
    f=line.rstrip("\n").split("\t")
    if len(f)<3 or f[0] in ("pair",): continue
    try: A.append(float(f[1])); B.append(float(f[2]))
    except ValueError: pass
if not A:
    print("  no runs"); sys.exit(1)
ma, mb = st.median(A), st.median(B)
print("  median A (no agent) = %.4f s" % ma)
print("  median B (agent)    = %.4f s" % mb)
print("  overhead            = %+.1f%% (median-to-median)" % (100*(mb-ma)/ma))
PY
note "per-run table: $OUT/runs.tsv"
