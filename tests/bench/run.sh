#!/usr/bin/env bash
#
# Overhead benchmark (STAGE8.md task 8.1, decision Р49).
#
# One load, five environments — paired ABAB runs against a baseline:
#
#   A  no agent                                  baseline
#   B  agent up, filter miss (--port 1)          fentry probes alone
#   C  agent, plaintext capture                  probes + ringbuf + pipeline
#   D  agent, TLS capture (sslmode=require)      + the uprobe channel (Р40)
#   E  C + OTLP spans 1:100 to a dummy sink      + the export path (Р31/Р32)
#
# For every configuration X the script alternates A,X,A,X,... (PAIRS pairs):
# machine drift is smeared over both sides, medians are compared. A run is
# VALID only if latkit_ringbuf_dropped_total and latkit_resync_total did not
# grow during it — overhead numbers from a degraded capture are meaningless
# (an agent that drops events looks cheaper than one that works).
#
# The load is rate-capped at the Р49 target (~50k queries/s: select at
# -R 50000, TPC-B at -R 7000 tx/s = ~49k statements/s) rather than run flat
# out: this stand's uncapped ceiling (~170k qps) is >3x the target and
# saturates the agent's pipeline thread outright — every uncapped run is
# invalid by the drop rule, and the gate is defined at ~50k qps anyway.
# RATE_SELECT=0 / RATE_TPCB=0 lifts the cap for a saturation probe (expect
# invalid runs; the numbers document the ceiling, they are not the gate).
#
# The stand is self-contained: the script starts its own postgres:16
# containers (plaintext + TLS), tuned to be CPU-bound (the dataset fits in
# shared_buffers, fsync off) so that pgbench measures the agent, not the
# disk. Load is always driven at the container IP, never 127.0.0.1 — the
# docker-proxy also listens on published ports and its splice() relay would
# pollute the capture (extra conns, iter_unsupported); here nothing is
# published at all.
#
# Usage:
#   tests/bench/run.sh up            # start + init the containers (once)
#   tests/bench/run.sh run           # the benchmark itself (default)
#   tests/bench/run.sh down          # remove the containers
#
# Knobs (env): CONFIGS="B C D E", WORKLOADS="select tpcb", PAIRS=5,
#   RUN_SECS=60, WARMUP_SECS=30, SCALE=100, CLIENTS_SELECT=128,
#   CLIENTS_TPCB=100, RATE_SELECT=50000, RATE_TPCB=7000 (0 = uncapped),
#   JOBS=$(nproc), PERF=1 (perf record -g on C/D runs),
#   AGENT_BIN=build-rel/latkit, OUT=tests/bench/out/<utc-ts>, FORCE=1
#   (skip the idle-host check).
#
# Requirements: an OPTIMISED agent build —
#   cmake -B build-rel -DCMAKE_BUILD_TYPE=RelWithDebInfo \
#         -DCMAKE_C_FLAGS=-fno-omit-frame-pointer
#   cmake --build build-rel --target latkit -j
# (-fno-omit-frame-pointer keeps `perf record -g` frame-pointer unwinding
# usable at -O2); docker; passwordless sudo for the agent/cpupower/perf;
# pgbench (native if present, else the postgres:16 image with --network
# host); python3 for the OTLP sink; curl.
#
# Results land in $OUT: report.txt (conditions header + per-series medians,
# deltas and the Р49 gate verdicts via report.awk), runs.tsv (one row per
# run), per-run pgbench/agent logs, /metrics snapshots, perf.data + stdio
# reports for C/D.

set -euo pipefail

cd "$(dirname "$0")/../.."          # repo root
BENCH_DIR=tests/bench

CMD=${1:-run}

CONFIGS=${CONFIGS:-"B C D E"}
WORKLOADS=${WORKLOADS:-"select tpcb"}
PAIRS=${PAIRS:-5}
RUN_SECS=${RUN_SECS:-60}
WARMUP_SECS=${WARMUP_SECS:-30}
SCALE=${SCALE:-100}
CLIENTS_SELECT=${CLIENTS_SELECT:-128}
CLIENTS_TPCB=${CLIENTS_TPCB:-100}
RATE_SELECT=${RATE_SELECT:-50000}
RATE_TPCB=${RATE_TPCB:-7000}
JOBS=${JOBS:-$(nproc)}
PERF=${PERF:-0}
PERF_FREQ=${PERF_FREQ:-499}
AGENT_BIN=${AGENT_BIN:-build-rel/latkit}
FORCE=${FORCE:-0}
OUT=${OUT:-$BENCH_DIR/out/$(date -u +%Y%m%dT%H%M%SZ)}

PG_PLAIN=latkit-bench-pg
PG_TLS=latkit-bench-pg-tls
DB_USER=latkit DB_NAME=latkit
export PGPASSWORD=latkit
PROM=http://127.0.0.1:9752/metrics
SINK_PORT=43181                     # dummy OTLP collector for E

# CPU-bound on purpose (Р49): the whole scale-100 dataset (~1.6 GB) sits in
# shared_buffers, and fsync/synchronous_commit/full_page_writes are off so
# TPC-B measures CPU cost, not the disk. max_connections covers -c 128.
PG_TUNING=(-c shared_buffers=2GB -c max_connections=300
           -c fsync=off -c synchronous_commit=off -c full_page_writes=off)

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

# ---------------------------------------------------------------- containers

container_ip() {
    docker inspect "$1" \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
}

wait_pg() {  # name
    for _ in $(seq 60); do
        docker exec "$1" pg_isready -q -U "$DB_USER" -d "$DB_NAME" \
            2>/dev/null && return 0
        sleep 1
    done
    die "$1 never became ready"
}

stack_up() {
    if ! docker inspect "$PG_PLAIN" >/dev/null 2>&1; then
        log "starting $PG_PLAIN"
        docker run -d --name "$PG_PLAIN" \
            -e POSTGRES_USER=$DB_USER -e POSTGRES_PASSWORD=$PGPASSWORD \
            -e POSTGRES_DB=$DB_NAME \
            postgres:16 postgres -c ssl=off "${PG_TUNING[@]}" >/dev/null
    fi
    if ! docker inspect "$PG_TLS" >/dev/null 2>&1; then
        log "starting $PG_TLS"
        # Self-signed cert generated before the entrypoint, key owned by the
        # postgres uid — same recipe as tests/e2e/docker-compose.tls.yml.
        docker run -d --name "$PG_TLS" \
            -e POSTGRES_USER=$DB_USER -e POSTGRES_PASSWORD=$PGPASSWORD \
            -e POSTGRES_DB=$DB_NAME \
            postgres:16 bash -c "
                set -e; mkdir -p /certs
                openssl req -new -x509 -days 365 -nodes \
                    -out /certs/server.crt -keyout /certs/server.key \
                    -subj /CN=postgres 2>/dev/null
                chmod 600 /certs/server.key
                chown postgres:postgres /certs/server.key /certs/server.crt
                exec docker-entrypoint.sh postgres -c ssl=on \
                    -c ssl_cert_file=/certs/server.crt \
                    -c ssl_key_file=/certs/server.key \
                    $(printf '%s ' "${PG_TUNING[@]}")
            " >/dev/null
    fi
    wait_pg "$PG_PLAIN"; wait_pg "$PG_TLS"

    local name ip mode scale_now
    for name in "$PG_PLAIN" "$PG_TLS"; do
        ip=$(container_ip "$name")
        mode=disable; [ "$name" = "$PG_TLS" ] && mode=require
        scale_now=$(docker exec "$name" psql -U $DB_USER -d $DB_NAME -Atqc \
            "select coalesce((select count(*) from pgbench_branches), -1)" \
            2>/dev/null || echo -1)
        if [ "$scale_now" != "$SCALE" ]; then
            log "pgbench -i -s $SCALE on $name ($ip, sslmode=$mode)"
            PGSSLMODE=$mode run_pgbench -h "$ip" -p 5432 -U $DB_USER \
                -i -s "$SCALE" $DB_NAME >/dev/null 2>&1
        fi
    done
    log "stack up: $PG_PLAIN=$(container_ip "$PG_PLAIN")" \
        "$PG_TLS=$(container_ip "$PG_TLS")"
}

stack_down() {
    docker rm -f "$PG_PLAIN" "$PG_TLS" >/dev/null 2>&1 || true
    log "stack removed"
}

# ------------------------------------------------------------------- pgbench

# Native pgbench when available; otherwise the postgres:16 image in the host
# netns (so the traffic path to the container IP is identical). The docker
# variant mounts the repo at the same absolute path — -l log files land where
# the native ones would.
if pgbench --version >/dev/null 2>&1; then
    PGBENCH_KIND="native ($(pgbench --version))"
    run_pgbench() { pgbench "$@"; }
else
    PGBENCH_KIND="docker postgres:16 (--network host)"
    run_pgbench() {
        docker run --rm --network host -v "$PWD:$PWD" -w "$PWD" \
            -e PGPASSWORD -e PGSSLMODE postgres:16 pgbench "$@"
    }
fi

# ----------------------------------------------------------------- the agent

agent_pid() { pgrep -x latkit || true; }

AGENT_JOB=
agent_start() {  # flags...
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    sudo -n "$AGENT_BIN" --prom-listen 127.0.0.1:9752 "$@" \
        >>"$RUNDIR/agent.log" 2>&1 &
    AGENT_JOB=$!
    for _ in $(seq 100); do
        curl -fsS -o /dev/null "$PROM" 2>/dev/null && return 0
        sleep 0.2
    done
    die "agent did not come up (see $RUNDIR/agent.log)"
}

agent_stop() {
    local pid; pid=$(agent_pid)
    if [ -n "$pid" ]; then
        # Signal the latkit process itself, not the backgrounded sudo
        # wrapper — SIGSTOP/SIGINT to the sudo job would not reach it.
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

# Sum every series of a family from a /metrics snapshot: bare name or any
# label set. An explicit label set (name{...}) selects that one series.
metric() {  # file name[-with-labels]
    awk -v m="$1" '
        /^#/ { next }
        $1 == m || substr($1, 1, length(m) + 1) == m "{" { s += $NF }
        END { printf "%.10g\n", s + 0 }' "$2"
}

mdelta() {  # name -> integer-formatted delta between m0 and m1 snapshots
    awk -v a="$(metric "$1" "$RUNDIR/m0")" \
        -v b="$(metric "$1" "$RUNDIR/m1")" 'BEGIN { printf "%.0f\n", b - a }'
}

snap_metrics() { curl -fsS "$PROM" -o "$1"; }

# D only: the libssl scan/attach is asynchronous; measuring before the
# uprobes are in place would time an agent that is not capturing yet.
wait_tls_attach() {
    local t
    for _ in $(seq 75); do
        t=$(curl -fsS "$PROM" 2>/dev/null \
            | awk '$1 == "latkit_tls_attached{state=\"ok\"}" { print $2 }')
        [ "$t" = 1 ] && return 0
        sleep 0.2
    done
    die "TLS uprobes never attached (see $RUNDIR/agent.log)"
}

# --------------------------------------------------------------- environment

GOV_SAVED= NOTURBO_SAVED=
fix_conditions() {
    GOV_SAVED=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
    sudo -n cpupower frequency-set -g performance >/dev/null \
        || log "WARN: cpupower failed, governor stays $GOV_SAVED"
    # NOTURBO=1 additionally pins the clocks to base frequency. Off by
    # default: on laptop-class CPUs the base clock is a fraction of the
    # sustained turbo clock and the stand loses the very capacity the ~50k
    # target needs (measured here: TLS and TPC-B saturate the host and every
    # agent run drowns in drops). Thermal drift is what the ABAB alternation
    # and the reported spread are for.
    if [ "${NOTURBO:-0}" = 1 ] \
        && [ -e /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
        NOTURBO_SAVED=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)
        echo 1 | sudo -n tee /sys/devices/system/cpu/intel_pstate/no_turbo \
            >/dev/null || true
    fi
}

restore_conditions() {
    [ -z "$GOV_SAVED" ] \
        || sudo -n cpupower frequency-set -g "$GOV_SAVED" >/dev/null 2>&1 \
        || true
    [ -z "$NOTURBO_SAVED" ] || echo "$NOTURBO_SAVED" \
        | sudo -n tee /sys/devices/system/cpu/intel_pstate/no_turbo \
          >/dev/null 2>&1 || true
}

SINK_PID=
cleanup() {
    agent_stop
    [ -z "$SINK_PID" ] || kill "$SINK_PID" 2>/dev/null || true
    restore_conditions
}

preflight() {
    [ -x "$AGENT_BIN" ] || die "no agent binary at $AGENT_BIN" \
        "(build recipe in the header of this script)"
    local cache="${AGENT_BIN%/*}/CMakeCache.txt"
    BUILD_TYPE=unknown
    if [ -r "$cache" ]; then
        BUILD_TYPE=$(sed -n 's/^CMAKE_BUILD_TYPE:STRING=//p' "$cache")
        case "$BUILD_TYPE" in
            Release|RelWithDebInfo) ;;
            *) die "$AGENT_BIN is not an optimised build" \
                   "(CMAKE_BUILD_TYPE='$BUILD_TYPE') — a -O0 agent produces" \
                   "numbers about nothing" ;;
        esac
    else
        log "WARN: no CMakeCache.txt next to $AGENT_BIN, build type unknown"
    fi
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    sudo -n true 2>/dev/null || die "passwordless sudo required"
    # A suspend can leave the ACPI platform profile in low-power, which caps
    # the package power (observed: ~700 MHz under all-core load at 65°C) and
    # silently halves the stand's capacity — every agent run then drowns in
    # drops that have nothing to do with the agent.
    if [ -r /sys/firmware/acpi/platform_profile ]; then
        local prof; prof=$(cat /sys/firmware/acpi/platform_profile)
        case "$prof" in
            low-power|quiet)
                die "ACPI platform profile is '$prof' — the package power cap" \
                    "starves the stand; echo performance | sudo tee" \
                    "/sys/firmware/acpi/platform_profile" ;;
        esac
    fi
    local load1; load1=$(awk '{print int($1)}' /proc/loadavg)
    if [ "$load1" -ge 2 ] && [ "$FORCE" != 1 ]; then
        die "host is not idle (loadavg $(cut -d' ' -f1-3 /proc/loadavg));" \
            "stop the noise or rerun with FORCE=1"
    fi
}

# ------------------------------------------------------------------ one run

pg_cpu_usec() {  # container -> cumulative usage_usec of its cgroup
    local id; id=$(docker inspect --format '{{.Id}}' "$1")
    awk '/^usage_usec/ { print $2 }' \
        "/sys/fs/cgroup/system.slice/docker-$id.scope/cpu.stat"
}

percentile() {  # p file-with-µs-in-field-3 -> ms (empty if no samples)
    awk '{ print $3 }' "$2" | sort -n | awk -v p="$1" '
        { v[NR] = $1 }
        END {
            if (!NR) exit
            r = int(p / 100 * NR + 0.5); if (r < 1) r = 1; if (r > NR) r = NR
            printf "%.3f\n", v[r] / 1000
        }'
}

# one_run WORKLOAD CONFIG PAIR ROLE — appends a row to $TSV
one_run() {
    local wl=$1 cfg=$2 pair=$3 role=$4 secs=${5:-$RUN_SECS}
    local tag="$wl-$cfg-$pair$role"
    RUNDIR="$OUT/$tag"; mkdir -p "$RUNDIR"

    local pg=$PG_PLAIN sslmode=disable
    [ "$cfg" = D ] && { pg=$PG_TLS; sslmode=require; }
    local ip; ip=$(container_ip "$pg")

    local bench_args=(-h "$ip" -p 5432 -U $DB_USER -T "$secs" -j "$JOBS"
                      -P 10 -r -l --sampling-rate=0.1
                      --log-prefix="$RUNDIR/lat")
    case $wl in
        select) bench_args+=(-S -M prepared -c "$CLIENTS_SELECT")
                [ "$RATE_SELECT" -gt 0 ] && bench_args+=(-R "$RATE_SELECT") ;;
        tpcb)   bench_args+=(-c "$CLIENTS_TPCB")
                [ "$RATE_TPCB" -gt 0 ] && bench_args+=(-R "$RATE_TPCB") ;;
        *)      die "unknown workload '$wl'" ;;
    esac

    local agent_on=0 perf_job=
    if [ "$role" = X ]; then
        agent_on=1
        case $cfg in
            B) agent_start -p 1 ;;
            C) agent_start -p 5432 ;;
            D) agent_start -p 5432 --tls auto; wait_tls_attach ;;
            E) agent_start -p 5432 \
                   --otlp-endpoint "http://127.0.0.1:$SINK_PORT" \
                   --otlp-spans 0.01 ;;
            *) die "unknown config '$cfg'" ;;
        esac
        snap_metrics "$RUNDIR/m0"
        if [ "$PERF" = 1 ] && { [ "$cfg" = C ] || [ "$cfg" = D ]; }; then
            sudo -n perf record -F "$PERF_FREQ" -g -p "$(agent_pid)" \
                -o "$RUNDIR/perf.data" >/dev/null 2>"$RUNDIR/perf.log" &
            perf_job=$!
            sleep 0.5
        fi
    fi

    local c0 t0 t1 c1
    c0=$(pg_cpu_usec "$pg"); t0=$(date +%s.%N)
    PGSSLMODE=$sslmode run_pgbench "${bench_args[@]}" $DB_NAME \
        >"$RUNDIR/pgbench.out" 2>&1 \
        || die "pgbench failed, see $RUNDIR/pgbench.out"
    t1=$(date +%s.%N); c1=$(pg_cpu_usec "$pg")

    local wall pg_cores
    wall=$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f", b - a }')
    pg_cores=$(awk -v a="$c0" -v b="$c1" -v w="$wall" \
        'BEGIN { printf "%.3f", (b - a) / 1e6 / w }')

    local tps lat_avg
    tps=$(awk '/^tps = /{ v = $3 } END { print v }' "$RUNDIR/pgbench.out")
    lat_avg=$(awk '/^latency average/{ print $4 }' "$RUNDIR/pgbench.out")
    [ -n "$tps" ] || die "no tps in $RUNDIR/pgbench.out"

    # p50/p95 out of the sampled per-transaction latency log (µs, field 3);
    # the raw logs are large and reproducible, so they are not kept.
    cat "$RUNDIR"/lat.* >"$RUNDIR/latencies" 2>/dev/null || true
    local p50 p95
    p50=$(percentile 50 "$RUNDIR/latencies")
    p95=$(percentile 95 "$RUNDIR/latencies")
    rm -f "$RUNDIR"/lat.* "$RUNDIR/latencies"

    local acpu=0 acores=0 dropped=0 resync=0 queries=0 valid=1 reason=ok
    if [ "$agent_on" = 1 ]; then
        if [ -n "$perf_job" ]; then
            sudo -n pkill -INT -x perf || true
            wait "$perf_job" 2>/dev/null || true
        fi
        snap_metrics "$RUNDIR/m1"
        acpu=$(awk -v a="$(metric process_cpu_seconds_total "$RUNDIR/m0")" \
                   -v b="$(metric process_cpu_seconds_total "$RUNDIR/m1")" \
                   'BEGIN { printf "%.2f", b - a }')
        acores=$(awk -v c="$acpu" -v w="$wall" 'BEGIN { printf "%.3f", c/w }')
        dropped=$(mdelta latkit_ringbuf_dropped_total)
        resync=$(mdelta latkit_resync_total)
        queries=$(mdelta latkit_queries_total)

        # Validity (Р49): a degraded or dead capture invalidates the number.
        # The first failed check names the run's reason. (TLS ciphertext-drop
        # counters are NOT checked: dropping ciphertext socket events on a TLS
        # conn is the design, the uprobe channel is the data source there.)
        inval() { if [ "$valid" = 1 ]; then valid=0; reason=$1; fi; }
        [ "$dropped" -eq 0 ] || inval ringbuf-drops
        [ "$resync" -eq 0 ] || inval resync
        case $cfg in
            B) [ "$queries" -eq 0 ] || inval filter-leak ;;
            C|E) [ "$queries" -gt 0 ] || inval no-capture ;;
            D)
                local tlsok tconn
                tlsok=$(metric 'latkit_tls_attached{state="ok"}' "$RUNDIR/m1")
                tconn=$(mdelta latkit_tls_connections_total)
                [ "$queries" -gt 0 ] || inval no-capture
                [ "$tlsok" = 1 ] && [ "$tconn" -gt 0 ] || inval tls-not-attached
                ;;
        esac
        agent_stop
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$wl" "$cfg" "$pair" "$role" "$valid" "$tps" "$lat_avg" \
        "${p50:-0}" "${p95:-0}" "$wall" "$acpu" "$acores" "$pg_cores" \
        "$dropped" "$resync" "$queries" "$reason" >>"$TSV"
    log "  $tag: tps=$tps p95=${p95:-?}ms agent=${acores} pg=${pg_cores}" \
        "cores, valid=$valid($reason)"
    sleep 3
}

series() {  # workload config
    local wl=$1 cfg=$2
    log "series $wl/$cfg: ${WARMUP_SECS}s warmup + $PAIRS ABAB pairs" \
        "x ${RUN_SECS}s"
    # TPC-B writes bloat the dataset across a campaign (dead tuples, longer
    # HOT chains -> postgres CPU per txn creeps up); a fresh init per series
    # keeps every series' baseline comparable. select-only does not mutate.
    if [ "$wl" = tpcb ]; then
        local pg=$PG_PLAIN mode=disable
        [ "$cfg" = D ] && { pg=$PG_TLS; mode=require; }
        log "  re-init pgbench dataset on $pg (tpcb bloat reset)"
        PGSSLMODE=$mode run_pgbench -h "$(container_ip "$pg")" -p 5432 \
            -U $DB_USER -i -s "$SCALE" $DB_NAME >/dev/null 2>&1
    fi
    if [ "$cfg" = E ] && [ -z "$SINK_PID" ]; then
        python3 "$BENCH_DIR/otlp_sink.py" "$SINK_PORT" \
            >"$OUT/otlp-sink.log" 2>&1 &
        SINK_PID=$!
        sleep 0.5
    fi
    # Warm PG caches under the X environment; the row goes to warmup.tsv.
    local keep=$TSV
    TSV=$OUT/warmup.tsv
    one_run "$wl" "$cfg" 0 X "$WARMUP_SECS"
    TSV=$keep
    local pair
    for pair in $(seq "$PAIRS"); do
        one_run "$wl" "$cfg" "$pair" A
        one_run "$wl" "$cfg" "$pair" X
    done
}

# -------------------------------------------------------------------- report

write_header() {
    local pgver
    pgver=$(docker exec "$PG_PLAIN" psql -U $DB_USER -d $DB_NAME -Atqc \
            'select version()')
    cat >"$OUT/report.txt" <<EOF
latkit overhead benchmark (STAGE8.md 8.1, Р49)
==============================================
date        : $(date -u '+%Y-%m-%d %H:%M UTC')
commit      : $(git rev-parse --short HEAD)$(git diff --quiet || echo -dirty)
agent       : $("$AGENT_BIN" --version) [$BUILD_TYPE, $AGENT_BIN]
kernel      : $(uname -r)
cpu         : $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs), $(nproc) hw threads
governor    : performance (was $GOV_SAVED), no_turbo=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a) (turbo left on: base clocks starve the stand below the ~50k target; drift is handled by ABAB + spread)
memory      : $(awk '/MemTotal/{ printf "%.0f GiB", $2 / 1048576 }' /proc/meminfo)
postgres    : $pgver
pg tuning   : ${PG_TUNING[*]}
containers  : $PG_PLAIN=$(container_ip "$PG_PLAIN") $PG_TLS=$(container_ip "$PG_TLS") (load at container IP — no docker-proxy in the path)
pgbench     : $PGBENCH_KIND
workloads   : select = -S -M prepared -c $CLIENTS_SELECT -R $RATE_SELECT; tpcb = -c $CLIENTS_TPCB -R $RATE_TPCB (0=uncapped); both -j $JOBS -T $RUN_SECS -P 10 -r -l --sampling-rate=0.1, scale $SCALE
protocol    : per config ${WARMUP_SECS}s warmup (discarded) + $PAIRS ABAB pairs, medians compared; tpcb dataset re-inited per series (bloat reset)
validity    : invalid if ringbuf drops/resyncs grew (D: also TLS attach/drops; B: filter must miss; C/D/E: capture must see queries)
agent cpu   : delta process_cpu_seconds_total / wall; postgres CPU from the container cgroup (cross-check)
perf        : PERF=$PERF (perf record -F $PERF_FREQ -g on C/D agent runs)
configs     : A none | B --port 1 | C -p 5432 | D -p 5432 --tls auto + sslmode=require | E = C + --otlp-spans 0.01 --otlp-endpoint http://127.0.0.1:$SINK_PORT

EOF
}

# ---------------------------------------------------------------------- main

case $CMD in
    up)   stack_up; exit 0 ;;
    down) stack_down; exit 0 ;;
    run)  ;;
    *)    die "unknown command '$CMD' (up|run|down)" ;;
esac

preflight
stack_up
mkdir -p "$OUT"
TSV=$OUT/runs.tsv
printf 'workload\tconfig\tpair\trole\tvalid\ttps\tlat_avg_ms\tp50_ms\tp95_ms\twall_s\tagent_cpu_s\tagent_cores\tpg_cores\tdropped\tresync\tqueries\treason\n' >"$TSV"

trap cleanup EXIT INT TERM
fix_conditions
write_header

for wl in $WORKLOADS; do
    for cfg in $CONFIGS; do
        series "$wl" "$cfg"
    done
done

# perf.data -> stdio reports next to the data: a flat symbol list (the
# readable summary) and the call-graph top for drill-down.
if [ "$PERF" = 1 ]; then
    for pd in "$OUT"/*/perf.data; do
        [ -e "$pd" ] || continue
        sudo -n perf report --stdio --no-children -g none \
            --percent-limit 0.5 -i "$pd" 2>/dev/null \
            >"${pd%.data}-flat.txt" || true
        sudo -n perf report --stdio --no-children --percent-limit 2 \
            -i "$pd" 2>/dev/null | head -200 >"${pd%.data}-graph.txt" || true
    done
    sudo -n chown -R "$(id -u):$(id -g)" "$OUT"
fi

# report.awk exits 1 on a gate failure — the report itself is still the
# deliverable either way (a localised failure feeds task 8.6 via Р54).
awk -f "$BENCH_DIR/report.awk" "$TSV" >>"$OUT/report.txt" || true
log "done; report: $OUT/report.txt"
cat "$OUT/report.txt"
