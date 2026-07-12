#!/usr/bin/env bash
#
# Accuracy validation stand (STAGE8.md task 8.2, decision Р50).
#
# One controlled workload, three views of it:
#
#   - the agent's histograms  (--dump-metrics at exit);
#   - PostgreSQL csvlog       (log_min_duration_statement=0 — per-statement
#                              duration lines, honest raw percentiles);
#   - pg_stat_statements      (calls/mean sanity only: its normalisation is
#                              not ours, so it never enters the join — Р50).
#
# The join and the comparison live in logjoin (same directory): csvlog text ->
# the agent's own lk_norm_sql -> fp -> the agent's series. This script owns the
# stand: a fresh postgres:16 container per protocol run (fresh pgss, fresh log
# directory — no rotation bookkeeping), the workload, and the assertions whose
# expected values only the stand knows (exact counts, rows, injected errors).
#
# Workload per run: pgbench select-only and tpcb-like with EXACT transaction
# counts (-t, not -T: `count matches exactly` is the acceptance), plus special
# queries: pg_sleep 2 ms / 50 ms (a bimodal tail on ONE fp — both spellings
# normalise to `select pg_sleep ( ? )`, deliberate), a 100-row generate_series
# (known rows_total), a ~1 M-row aggregate (a real >= 1 ms query), and injected
# errors: SELECT 1/0 -> SQLSTATE 22012, a unique violation -> 23505 (via psql:
# pgbench aborts a client on SQL errors, psql carries on).
#
# Protocol matters (Р50): the `simple` run is the primary comparison (csvlog
# `duration:` covers the whole statement, same model as the agent's Q->Z).
# The `extended` run compares the agent against the SUM of parse/bind/execute
# lines (logjoin does the summing) — PG logs the phases separately while the
# agent times first-frontend-message -> ReadyForQuery; the delta additionally
# contains the inter-message gaps. Documented in docs/accuracy.md.
#
# Control plane (psql/pgbench-init inside the container) goes over the unix
# socket: invisible to the agent by design and skipped by logjoin ([local]),
# so both views see exactly the same statements. The workload itself is driven
# at the container IP — never 127.0.0.1, the docker-proxy would pollute the
# capture (no ports are published at all).
#
# A run is VALID only if the agent dump shows zero ringbuf drops and zero
# resyncs (Р49/Р50: `count matches exactly` is only meaningful on a lossless
# run); logjoin enforces that from the dump itself.
#
# Usage:
#   tests/bench/accuracy/run.sh          # full campaign (simple + extended)
#   tests/bench/accuracy/run.sh down     # remove a leftover container
#
# Knobs (env): PROTOCOLS="simple extended", SCALE=10, CLIENTS=8, JOBS=4,
#   TXNS=2500, TPCB_CLIENTS=4, TPCB_TXNS=500, SLEEP2_N=300, SLEEP50_N=200,
#   ROWS_N=200, SUM_N=100, ERR_N=200, TOL=5 (percent), MIN_MS=1,
#   MIN_SAMPLES=50, AGENT_BIN=build-rel/latkit, OUT=tests/bench/accuracy/out/<ts>
#
# Requirements: an optimised agent build (same reason as tests/bench/run.sh:
# a -O0 agent may drop under burst and invalidate every run), docker,
# passwordless sudo for the agent, curl.

set -euo pipefail

cd "$(dirname "$0")/../../.."       # repo root

CMD=${1:-run}

PROTOCOLS=${PROTOCOLS:-"simple extended"}
SCALE=${SCALE:-10}
CLIENTS=${CLIENTS:-8}
JOBS=${JOBS:-4}
TXNS=${TXNS:-2500}
TPCB_CLIENTS=${TPCB_CLIENTS:-4}
TPCB_TXNS=${TPCB_TXNS:-500}
SLEEP2_N=${SLEEP2_N:-300}
SLEEP50_N=${SLEEP50_N:-200}
ROWS_N=${ROWS_N:-200}
SUM_N=${SUM_N:-100}
ERR_N=${ERR_N:-200}
TOL=${TOL:-5}
MIN_MS=${MIN_MS:-1}
MIN_SAMPLES=${MIN_SAMPLES:-50}
AGENT_BIN=${AGENT_BIN:-build-rel/latkit}
OUT=${OUT:-tests/bench/accuracy/out/$(date -u +%Y%m%dT%H%M%SZ)}
case "$OUT" in /*) ;; *) OUT=$PWD/$OUT ;; esac   # docker -v needs it absolute

PG=latkit-acc-pg
DB_USER=latkit DB_NAME=latkit
export PGPASSWORD=latkit
PROM=http://127.0.0.1:9752/metrics

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

# ------------------------------------------------------------------ clients
# Native pgbench/psql when available; otherwise the postgres:16 image in the
# host netns with the repo mounted at the same absolute path (script files
# under $OUT resolve identically). Same recipe as tests/bench/run.sh.
if pgbench --version >/dev/null 2>&1 && psql --version >/dev/null 2>&1; then
    CLIENT_KIND="native ($(pgbench --version))"
    run_pgbench() { pgbench "$@"; }
    run_psql() { psql "$@"; }
else
    CLIENT_KIND="docker postgres:16 (--network host)"
    run_pgbench() {
        docker run --rm --network host -v "$PWD:$PWD" -w "$PWD" \
            -e PGPASSWORD postgres:16 pgbench "$@"
    }
    run_psql() {
        docker run --rm --network host -v "$PWD:$PWD" -w "$PWD" \
            -e PGPASSWORD postgres:16 psql "$@"
    }
fi

container_ip() {
    docker inspect "$PG" \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
}

cpsql() {  # control-plane psql: unix socket inside the container ([local])
    docker exec "$PG" psql -U "$DB_USER" -d "$DB_NAME" "$@"
}

# ------------------------------------------------------------------ the agent

agent_pid() { pgrep -x latkit || true; }

AGENT_JOB=
agent_start() {
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    sudo -n "$AGENT_BIN" -p 5432 --dump-metrics="$RUNDIR/agent.prom" \
        --prom-listen 127.0.0.1:9752 >>"$RUNDIR/agent.log" 2>&1 &
    AGENT_JOB=$!
    for _ in $(seq 100); do
        curl -fsS -o /dev/null "$PROM" 2>/dev/null && return 0
        sleep 0.2
    done
    die "agent did not come up (see $RUNDIR/agent.log)"
}

agent_stop() {  # SIGINT -> drain -> the exit dump this whole stand is about
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

cleanup() {
    agent_stop
    docker rm -f "$PG" >/dev/null 2>&1 || true
}

# ------------------------------------------------------------------ container

stack_up() {  # $1 = run dir; a FRESH container per run — clean pgss, clean log
    docker rm -f "$PG" >/dev/null 2>&1 || true
    mkdir -p "$1/pglog"
    chmod 777 "$1/pglog"           # postgres (uid 999) writes csv logs here
    docker run -d --name "$PG" \
        -e POSTGRES_USER=$DB_USER -e POSTGRES_PASSWORD=$PGPASSWORD \
        -e POSTGRES_DB=$DB_NAME \
        -v "$1/pglog:/pglog" \
        postgres:16 postgres \
        -c shared_preload_libraries=pg_stat_statements \
        -c logging_collector=on -c log_destination=csvlog \
        -c log_directory=/pglog -c log_min_duration_statement=0 \
        -c log_rotation_age=0 -c log_rotation_size=0 -c log_file_mode=0644 \
        -c shared_buffers=512MB -c fsync=off -c synchronous_commit=off \
        -c full_page_writes=off >/dev/null
    for _ in $(seq 60); do
        docker exec "$PG" pg_isready -q -U "$DB_USER" -d "$DB_NAME" \
            2>/dev/null && break
        sleep 1
    done
    docker exec "$PG" pg_isready -q -U "$DB_USER" -d "$DB_NAME" \
        || die "$PG never became ready"

    # Control plane below runs on the unix socket ([local] in csvlog):
    # invisible to the agent, skipped by logjoin — see the header.
    cpsql -q -c 'CREATE EXTENSION IF NOT EXISTS pg_stat_statements' \
          -c 'CREATE TABLE IF NOT EXISTS uniq_t(id int PRIMARY KEY)' \
          -c 'INSERT INTO uniq_t VALUES (1) ON CONFLICT DO NOTHING'
    log "  pgbench -i -s $SCALE (over the unix socket)"
    docker exec "$PG" pgbench -i -s "$SCALE" -U "$DB_USER" "$DB_NAME" \
        >/dev/null 2>&1
    cpsql -q -c 'SELECT pg_stat_statements_reset()' >/dev/null
}

# ------------------------------------------------------------------ workload

write_scripts() {  # $1 = run dir
    printf 'SELECT pg_sleep(0.002);\n'                  >"$1/sleep2.sql"
    printf 'SELECT pg_sleep(0.05);\n'                   >"$1/sleep50.sql"
    printf 'SELECT i FROM generate_series(1,100) i;\n'  >"$1/rows100.sql"
    printf 'SELECT sum(abalance) FROM pgbench_accounts;\n' >"$1/sum.sql"
    {   # errors: autocommit on purpose — no aborted-transaction statements,
        # so csvlog ERROR lines and agent code="error" count the same thing
        for _ in $(seq "$ERR_N"); do printf 'SELECT 1/0;\n'; done
        for _ in $(seq "$ERR_N"); do printf 'INSERT INTO uniq_t VALUES (1);\n'; done
    } >"$1/err.sql"
}

drive() {  # $1 = protocol (simple|extended), $2 = run dir; exact counts via -t
    local ip; ip=$(container_ip)
    local pgb=(-h "$ip" -p 5432 -U "$DB_USER" -n -M "$1")

    log "  pgbench select-only: $((CLIENTS * TXNS)) txns"
    run_pgbench "${pgb[@]}" -S -c "$CLIENTS" -j "$JOBS" -t "$TXNS" $DB_NAME \
        >"$2/pgbench-select.out" 2>&1 || die "pgbench select failed"
    log "  pgbench tpcb-like: $((TPCB_CLIENTS * TPCB_TXNS)) txns"
    run_pgbench "${pgb[@]}" -c "$TPCB_CLIENTS" -j 2 -t "$TPCB_TXNS" $DB_NAME \
        >"$2/pgbench-tpcb.out" 2>&1 || die "pgbench tpcb failed"
    log "  special queries (sleep/rows/aggregate)"
    run_pgbench "${pgb[@]}" -f "$2/sleep2.sql"  -c 2 -t $((SLEEP2_N / 2))  $DB_NAME \
        >"$2/pgbench-sleep2.out" 2>&1 || die "pgbench sleep2 failed"
    run_pgbench "${pgb[@]}" -f "$2/sleep50.sql" -c 2 -t $((SLEEP50_N / 2)) $DB_NAME \
        >"$2/pgbench-sleep50.out" 2>&1 || die "pgbench sleep50 failed"
    run_pgbench "${pgb[@]}" -f "$2/rows100.sql" -c 2 -t $((ROWS_N / 2))    $DB_NAME \
        >"$2/pgbench-rows.out" 2>&1 || die "pgbench rows failed"
    run_pgbench "${pgb[@]}" -f "$2/sum.sql"     -c 2 -t $((SUM_N / 2))     $DB_NAME \
        >"$2/pgbench-sum.out" 2>&1 || die "pgbench sum failed"
    log "  injected errors: ${ERR_N}x 22012 + ${ERR_N}x 23505 (psql, simple proto)"
    run_psql -h "$ip" -p 5432 -U "$DB_USER" -d "$DB_NAME" -q \
        -f "$2/err.sql" >/dev/null 2>"$2/psql-err.log" || die "psql errors failed"
}

# ---------------------------------------------------------------- assertions

# tsv_field <file> <label-substring> <column>: one matching data row or
# "missing". Substring, not regex — canonical labels are full of ( ? ) /.
tsv_field() {
    awk -F'\t' -v s="$2" -v col="$3" \
        'NR > 1 && index($1, s) { print $col; found = 1; exit }
         END { if (!found) print "missing" }' "$1"
}

# tsv_sum: like tsv_field but summing over every matching row. Needed where
# one statement spells out as several fps: simple-protocol tpcb substitutes
# the +-delta literal, and `abalance + -3455` lexes as `+ - ?` while
# `abalance + 3455` lexes as `+ ?` — two fingerprints for one script line
# (the lexer sees an operator, pg_stat_statements' parse tree sees one
# constant; a documented normaliser difference, not a capture error).
tsv_sum() {
    awk -F'\t' -v s="$2" -v col="$3" \
        'NR > 1 && index($1, s) && $col != "-" { sum += $col; found = 1 }
         END { print found ? sum : "missing" }' "$1"
}

FAILED=0
check() {  # name actual expected
    if [ "$2" = "$3" ]; then
        printf '  ok    %-34s %s\n' "$1" "$2"
    else
        printf '  FAIL  %-34s %s (expected %s)\n' "$1" "$2" "$3"
        FAILED=1
    fi
}

assert_run() {  # $1 = run dir, $2 = protocol; stdout goes into the report
    local tsv=$1/join.tsv

    # tpcb-like contains the very same abalance SELECT as select-only — one
    # fp, so its expected count is the sum over both workloads.
    check "abalance SELECT count" "$(tsv_field "$tsv" 'abalance from pgbench_accounts where' 2)" \
                                 "$((CLIENTS * TXNS + TPCB_CLIENTS * TPCB_TXNS))"
    check "tpcb UPDATE count"    "$(tsv_sum "$tsv" 'update pgbench_accounts' 2)" \
                                 "$((TPCB_CLIENTS * TPCB_TXNS))"
    check "pg_sleep count (2ms+50ms fp)" "$(tsv_field "$tsv" 'select pg_sleep' 2)" \
                                 "$((SLEEP2_N + SLEEP50_N))"
    check "generate_series count" "$(tsv_field "$tsv" 'generate_series' 2)" "$ROWS_N"
    check "generate_series rows"  "$(tsv_field "$tsv" 'generate_series' 21)" \
                                 "$((ROWS_N * 100))"
    check "aggregate count"       "$(tsv_field "$tsv" 'select sum ( abalance )' 2)" "$SUM_N"
    check "aggregate rows"        "$(tsv_field "$tsv" 'select sum ( abalance )' 21)" "$SUM_N"
    check "division errors (fp)"  "$(tsv_field "$tsv" 'select ? / ?' 4)" "$ERR_N"
    check "unique-violation errors (fp)" "$(tsv_field "$tsv" 'insert into uniq_t' 4)" "$ERR_N"
    check "sqlstate 22012 agent"  "$(awk '/^# sqlstate 22012/ { sub(/agent=/, "", $5); print $5 }' \
                                        "$tsv")" "$ERR_N"
    check "sqlstate 23505 agent"  "$(awk '/^# sqlstate 23505/ { sub(/agent=/, "", $5); print $5 }' \
                                        "$tsv")" "$ERR_N"
    check "zero ringbuf drops"    "$(awk '$1 == "latkit_ringbuf_dropped_total" { print $2 }' \
                                        "$1/agent.prom")" 0
    check "zero resyncs"          "$(awk '$1 == "latkit_resync_total" { print $2 }' \
                                        "$1/agent.prom")" 0
    check "logjoin verdict"       "$(awk '/^# verdict:/ { print $3 }' "$tsv")" "PASS"

    # pg_stat_statements sanity (Р50: sanity, not the join): exact calls on the
    # top query; means are printed for the offset ladder, not gated — pgss
    # times the executor only, csvlog the whole statement, the agent adds the
    # server-side socket path on top.
    local pgss_calls
    pgss_calls=$(cpsql -Atqc "SELECT calls FROM pg_stat_statements
                              WHERE query LIKE '%abalance FROM pgbench_accounts%'
                                AND query NOT LIKE '%sum%'" | head -1)
    check "pgss calls (abalance SELECT)" "${pgss_calls:-missing}" \
          "$((CLIENTS * TXNS + TPCB_CLIENTS * TPCB_TXNS))"
}

# --------------------------------------------------------------------- main

case $CMD in
    down) docker rm -f "$PG" >/dev/null 2>&1 || true; exit 0 ;;
    run)  ;;
    *)    die "unknown command '$CMD' (run|down)" ;;
esac

[ -x "$AGENT_BIN" ] || die "no agent binary at $AGENT_BIN (build-rel recipe" \
                          "in tests/bench/run.sh header)"
BUILD_DIR=$(dirname "$AGENT_BIN")
BUILD_TYPE=$(sed -n 's/^CMAKE_BUILD_TYPE:STRING=//p' "$BUILD_DIR/CMakeCache.txt" \
             2>/dev/null || echo unknown)
case "$BUILD_TYPE" in
    Release|RelWithDebInfo) ;;
    *) die "$AGENT_BIN is not an optimised build (CMAKE_BUILD_TYPE=" \
           "'$BUILD_TYPE') — an -O0 agent can drop under burst and every" \
           "run comes back invalid" ;;
esac
sudo -n true 2>/dev/null || die "passwordless sudo required"
log "building logjoin"
cmake --build "$BUILD_DIR" --target logjoin -j >/dev/null
LOGJOIN=$BUILD_DIR/logjoin

mkdir -p "$OUT"
trap cleanup EXIT INT TERM

REPORT=$OUT/report.txt
{
    echo "latkit accuracy validation (STAGE8.md 8.2, Р50)"
    echo "==============================================="
    echo "date        : $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "commit      : $(git rev-parse --short HEAD)$(git diff --quiet || echo -dirty)"
    echo "agent       : $("$AGENT_BIN" --version) [$BUILD_TYPE, $AGENT_BIN]"
    echo "kernel      : $(uname -r)"
    echo "postgres    : postgres:16 image, pg_stat_statements, csvlog," \
         "log_min_duration_statement=0, fsync=off, shared_buffers=512MB"
    echo "clients     : $CLIENT_KIND"
    echo "workload    : select-only -c $CLIENTS -t $TXNS; tpcb-like" \
         "-c $TPCB_CLIENTS -t $TPCB_TXNS; pg_sleep 2ms x$SLEEP2_N /" \
         "50ms x$SLEEP50_N; 100-row x$ROWS_N; aggregate x$SUM_N;" \
         "errors ${ERR_N}x22012 + ${ERR_N}x23505 (scale $SCALE)"
    echo "acceptance  : count exact; offset-adjusted p50/p95 within ${TOL}%" \
         "for queries >= ${MIN_MS} ms and >= $MIN_SAMPLES samples;" \
         "zero drops/resyncs (else the run is invalid)"
    echo "join        : logjoin — csvlog text -> lk_norm_sql (the agent's own)" \
         "-> fp; [local] control sessions excluded; extended = sum of" \
         "parse/bind/execute phases per execute"
    echo
} >"$REPORT"

CAMPAIGN_RC=0
for proto in $PROTOCOLS; do
    RUNDIR=$OUT/$proto
    mkdir -p "$RUNDIR"
    log "=== $proto protocol run ==="
    stack_up "$RUNDIR"
    write_scripts "$RUNDIR"
    agent_start
    drive "$proto" "$RUNDIR"
    sleep 2                       # let the pipeline drain and csvlog flush
    cpsql -Atq -c "SELECT calls, rows, round(mean_exec_time::numeric, 3),
                          round(stddev_exec_time::numeric, 3), query
                   FROM pg_stat_statements ORDER BY calls DESC LIMIT 20" \
        >"$RUNDIR/pgss.txt"
    RC=0
    {
        echo "--- $proto ---"
        agent_stop                # SIGINT -> exit dump
        [ -s "$RUNDIR/agent.prom" ] || die "agent wrote no dump"
        "$LOGJOIN" -d "$RUNDIR/agent.prom" -m "$MIN_MS" -t "$TOL" \
            -n "$MIN_SAMPLES" -c "$RUNDIR"/pglog/*.csv >"$RUNDIR/join.tsv" \
            || RC=$?
        FAILED=0
        assert_run "$RUNDIR" "$proto"
        [ "$RC" = 0 ] || FAILED=1
        echo
        echo "  join table: $RUNDIR/join.tsv; pgss sanity: $RUNDIR/pgss.txt"
        grep '^#' "$RUNDIR/join.tsv" | sed 's/^/  /'
        echo
    } >>"$REPORT" 2>&1
    docker rm -f "$PG" >/dev/null 2>&1 || true
    [ "$FAILED" = 0 ] || CAMPAIGN_RC=1
    log "=== $proto done (failed=$FAILED) ==="
done

{
    echo "campaign verdict: $([ "$CAMPAIGN_RC" = 0 ] && echo PASS || echo FAIL)"
} >>"$REPORT"
log "done; report: $REPORT"
cat "$REPORT"
exit "$CAMPAIGN_RC"
