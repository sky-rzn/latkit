#!/usr/bin/env bash
#
# Long-run soak test (STAGE8.md task 8.5, decision Р53).
#
# Runs the agent for DURATION_H hours (default 24) under continuous connection
# churn, a parallel TLS workload, hourly induced event loss, and periodic
# postgres restarts, while a witness scrapes the agent's self-metrics plus its
# fd count into a timeseries. The point is not throughput — it is that nothing
# drifts: RSS reaches a plateau and stays there, fds do not grow, kernel maps
# do not grow, the series count stays bounded, and dropped/resync grow ONLY
# inside the induced-loss windows and recover to zero afterwards.
#
# Load (all via pgbench, each wrapped in a restart-on-exit loop so a postgres
# bounce does not kill the generator):
#
#   steady_plain  pgbench -S -M prepared, persistent conns   steady baseline load
#   steady_tpcb   pgbench TPC-B (writes), persistent conns   write path, txn metrics
#   churn_plain   pgbench -C (reconnect per txn), plaintext  LRU + idle-sweep pressure
#                                                            on the conn table (Р12)
#   churn_tls     pgbench -C, sslmode=require                uprobe attach/detach in a
#                                                            long cycle + the Р37 bridge
#
# Disturbances on a schedule:
#
#   induced loss   pkill -STOP latkit; sleep; pkill -CONT    the ringbuf overflows while
#                  every INDUCE_EVERY seconds                the agent is frozen -> the
#                                                            "gap -> resync -> recovery"
#                                                            path (Р10/Р19), tested dozens
#                                                            of times, not once. This is
#                                                            the only way to provoke loss
#                                                            deterministically (real
#                                                            overload is covered by the
#                                                            bench peak configs).
#   pg restart     docker restart of the TLS postgres        synthetic OPEN, libssl rescan
#                  every RESTART_EVERY seconds               (Р39), cgroup re-resolve (Р48)
#                                                            in one shot.
#
# Witness: every SAMPLE_EVERY seconds a row is appended to samples.tsv with the
# phase (steady | recovery | restart), RSS, series count, active conns, fd
# count and the dropped/resync/tls counters. `bpftool map show` for the agent's
# maps is captured before and after the run (maps-before/after.txt) — a map that
# grew or appeared is a leak. At the end the script analyses samples.tsv against
# the Р53 criteria and writes report.txt (+ an ASCII RSS sparkline); plot.py
# renders the PNG for docs/perf.md.
#
# Usage:
#   tests/longrun/run.sh up       # start + init the postgres containers (once)
#   tests/longrun/run.sh run      # the soak itself (default), DURATION_H hours
#   tests/longrun/run.sh down     # remove the containers
#
# A 5-minute harness self-check before committing to 24 h:
#   SMOKE=1 tests/longrun/run.sh run
# (short durations/cadences so every disturbance fires a few times; the PASS/FAIL
# analysis and outputs are identical, just too short to judge a real plateau.)
#
# Knobs (env): DURATION_H=24, SAMPLE_EVERY=15, INDUCE_EVERY=3600,
#   INDUCE_HOLD=5, RECOVER_SECS=90, RESTART_EVERY=14400, RESTART_SETTLE=90,
#   RATE_STEADY=5000, RATE_TPCB=800, RATE_CHURN=400, RATE_CHURN_TLS=80,
#   IDLE_TIMEOUT=45, K_CEIL=2000, RSS_PLATEAU_PCT=5, FD_GROWTH_PCT=20,
#   AGENT_BIN=build-rel/latkit, PROM_PORT=9753, OUT=tests/longrun/out/<utc-ts>,
#   FORCE=1 (skip the idle-host check).
#
# Requirements: an optimised agent build (build-rel, same recipe as
# tests/bench/run.sh); docker; passwordless sudo (agent + pkill + bpftool +
# reading the root process's /proc/<pid>/fd); pgbench (native or the postgres:16
# image, --network host); curl. python3 only for the optional plot.

set -euo pipefail

cd "$(dirname "$0")/../.."          # repo root
LR_DIR=tests/longrun

CMD=${1:-run}

SMOKE=${SMOKE:-0}
if [ "$SMOKE" = 1 ]; then
    # Everything fires within ~5 minutes so the harness itself is exercised.
    DURATION_H=${DURATION_H:-0}          # 0 => use DURATION_SECS
    DURATION_SECS=${DURATION_SECS:-300}
    SAMPLE_EVERY=${SAMPLE_EVERY:-5}
    INDUCE_EVERY=${INDUCE_EVERY:-60}
    RECOVER_SECS=${RECOVER_SECS:-20}
    RESTART_EVERY=${RESTART_EVERY:-120}
    RESTART_SETTLE=${RESTART_SETTLE:-20}
else
    DURATION_H=${DURATION_H:-24}
    DURATION_SECS=${DURATION_SECS:-0}    # 0 => DURATION_H * 3600
    SAMPLE_EVERY=${SAMPLE_EVERY:-15}
    INDUCE_EVERY=${INDUCE_EVERY:-3600}
    RECOVER_SECS=${RECOVER_SECS:-90}
    RESTART_EVERY=${RESTART_EVERY:-14400}
    RESTART_SETTLE=${RESTART_SETTLE:-90}
fi
[ "$DURATION_SECS" -gt 0 ] || DURATION_SECS=$((DURATION_H * 3600))

INDUCE_HOLD=${INDUCE_HOLD:-5}
RATE_STEADY=${RATE_STEADY:-5000}
RATE_TPCB=${RATE_TPCB:-800}
RATE_CHURN=${RATE_CHURN:-400}
RATE_CHURN_TLS=${RATE_CHURN_TLS:-80}
IDLE_TIMEOUT=${IDLE_TIMEOUT:-45}
K_CEIL=${K_CEIL:-2000}
RSS_PLATEAU_PCT=${RSS_PLATEAU_PCT:-5}
FD_GROWTH_PCT=${FD_GROWTH_PCT:-20}
SCALE=${SCALE:-50}
AGENT_BIN=${AGENT_BIN:-build-rel/latkit}
PROM_PORT=${PROM_PORT:-9753}
FORCE=${FORCE:-0}
OUT=${OUT:-$LR_DIR/out/$(date -u +%Y%m%dT%H%M%SZ)}

PG_PLAIN=latkit-longrun-pg
PG_TLS=latkit-longrun-pg-tls
DB_USER=latkit DB_NAME=latkit
export PGPASSWORD=latkit
PROM="http://127.0.0.1:$PROM_PORT/metrics"

PG_TUNING=(-c shared_buffers=1GB -c max_connections=400
           -c fsync=off -c synchronous_commit=off -c full_page_writes=off)

# The agent's BPF maps (src/bpf/latkit.bpf.c) — the set whose growth we watch.
AGENT_MAPS='conns|capmode|recv_state|cursor|stats|ports|cgroups|cgroup_on|active_ssl_wr|active_ssl_rd|ssl_to_conn|tls_seq'

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

# ---------------------------------------------------------------- containers

container_ip() {
    docker inspect "$1" \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
}

wait_pg() {  # name
    for _ in $(seq 90); do
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
        # Self-signed cert, key owned by the postgres uid — same recipe as
        # tests/bench/run.sh and tests/e2e/docker-compose.tls.yml.
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
            # A freshly-created container can pass pg_isready (local socket)
            # a beat before it serves TCP/SSL, so the first init can race the
            # listener — retry a few times before giving up.
            local try
            for try in 1 2 3 4 5; do
                PGSSLMODE=$mode run_pgbench -h "$ip" -p 5432 -U $DB_USER \
                    -i -s "$SCALE" $DB_NAME >/dev/null 2>&1 && break
                [ "$try" = 5 ] && die "pgbench -i failed on $name after 5 tries"
                sleep 2
            done
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

if pgbench --version >/dev/null 2>&1; then
    PGBENCH_KIND="native ($(pgbench --version))"
    run_pgbench() { pgbench "$@"; }
else
    PGBENCH_KIND="docker postgres:16 (--network host)"
    run_pgbench() {
        docker run --rm --network host -e PGPASSWORD -e PGSSLMODE \
            postgres:16 pgbench "$@"
    }
fi

# ----------------------------------------------------------------- the agent

agent_pid() { pgrep -x latkit || true; }

# Launch the agent DETACHED via setsid: latkit becomes its own session leader
# and is reparented to init the moment the sudo/sh shim exits, so there is no
# sudo parent monitoring it. That matters because the induced-loss SIGSTOP would
# otherwise make the sudo parent mirror the stop onto itself (sudo's job-control
# behaviour) and, being stopped, never reap the agent — deadlocking shutdown.
# Reparented to init, SIGSTOP/SIGCONT hit only latkit, exactly as under systemd
# in production. We track it by name (agent_pid), no wait/pidfile needed.
AGENT_ARGS=
agent_start() {
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    sudo -n sh -c \
        "setsid '$AGENT_ABS' --prom-listen '127.0.0.1:$PROM_PORT' $AGENT_ARGS \
             >>'$OUT/agent.log' 2>&1 </dev/null &"
    for _ in $(seq 150); do
        curl -fsS -o /dev/null "$PROM" 2>/dev/null && return 0
        sleep 0.2
    done
    die "agent did not come up (see $OUT/agent.log)"
}

agent_stop() {
    local pid; pid=$(agent_pid)
    [ -n "$pid" ] || return 0
    sudo -n kill -CONT "$pid" 2>/dev/null || true       # never leave it STOPped
    sudo -n kill -INT "$pid" 2>/dev/null || true
    for _ in $(seq 100); do
        pid=$(agent_pid); [ -z "$pid" ] && return 0
        sleep 0.2
    done
    sudo -n kill -KILL "$pid" 2>/dev/null || true
}

wait_tls_attach() {
    for _ in $(seq 150); do
        [ "$(curl -fsS "$PROM" 2>/dev/null \
            | awk '$1 == "latkit_tls_attached{state=\"ok\"}" { print $2 }')" \
            = 1 ] && return 0
        sleep 0.2
    done
    log "WARN: TLS uprobes not attached yet (see $OUT/agent.log)"
}

# Sum a metric family from a /metrics snapshot (bare name or any label set;
# an explicit name{...} selects that one series). Same helper as bench/run.sh.
metric() {  # file name[-with-labels]
    awk -v m="$1" '
        /^#/ { next }
        $1 == m || substr($1, 1, length(m) + 1) == m "{" { s += $NF }
        END { printf "%.10g\n", s + 0 }' "$2"
}

# ----------------------------------------------------------------- load jobs

LOAD_PIDS=()

# Wrap a pgbench invocation in a restart-on-exit loop: a postgres bounce (or a
# -C connection failure during one) aborts pgbench, and we just start it again.
run_load() {  # ip sslmode label -- pgbench-args...
    local ip=$1 sslmode=$2 label=$3; shift 3; [ "$1" = -- ] && shift
    (
        trap 'exit 0' TERM INT
        while :; do
            PGSSLMODE=$sslmode run_pgbench -h "$ip" -p 5432 -U "$DB_USER" \
                "$@" "$DB_NAME" >>"$OUT/load-$label.log" 2>&1 || true
            sleep 1
        done
    ) &
    LOAD_PIDS+=($!)
}

start_load() {
    local ip_plain ip_tls
    ip_plain=$(container_ip "$PG_PLAIN"); ip_tls=$(container_ip "$PG_TLS")
    local T=$((DURATION_SECS + 120))     # outlive the soak; cleanup kills them

    # Persistent-connection baseline (plaintext): select-only + TPC-B writes.
    run_load "$ip_plain" disable steady -- \
        -S -M prepared -c 16 -j 4 -T "$T" -R "$RATE_STEADY" --progress=60
    run_load "$ip_plain" disable tpcb -- \
        -c 8 -j 4 -T "$T" -R "$RATE_TPCB" --progress=60
    # Reconnect-per-transaction churn: constant conn open/close -> LRU eviction
    # and idle-sweep pressure on the conn table.
    run_load "$ip_plain" disable churn -- \
        -C -S -c 8 -j 4 -T "$T" -R "$RATE_CHURN"
    # Same, over TLS: every reconnect is a fresh SSL handshake on a forked
    # backend -> uprobe attach/detach churn + the fd->sock->cookie bridge (Р37).
    run_load "$ip_tls" require churn-tls -- \
        -C -S -c 4 -j 2 -T "$T" -R "$RATE_CHURN_TLS"
    log "load: 4 pgbench generators up (steady+tpcb plaintext, churn plain+TLS)"
}

# ------------------------------------------------------------------ witness

agent_fds() {  # -> open fd count of the (root) agent process, 0 if gone
    local pid; pid=$(agent_pid)
    [ -n "$pid" ] || { echo 0; return; }
    sudo -n sh -c "ls /proc/$pid/fd 2>/dev/null | wc -l" 2>/dev/null || echo 0
}

# Agent maps only, id-stripped and sorted so a benign id reshuffle is not a
# diff — only type/name/key/value/max_entries changes (a grown or leaked map)
# show up.
snap_maps() {  # outfile
    sudo -n bpftool map show 2>/dev/null \
        | grep -E "  name ($AGENT_MAPS)  " \
        | sed -E 's/^[0-9]+: //' \
        | sort >"$1" || true
}

# Append one witness row. Phase is set by the main loop.
SAMPLE_N=0
sample() {  # phase
    local phase=$1 f="$OUT/.metrics"
    local rss=0 series=0 conns=0 dropped=0 resync=0 tlsconn=0 tlsdrop=0 queries=0
    if curl -fsS "$PROM" -o "$f" 2>/dev/null; then
        rss=$(metric process_resident_memory_bytes "$f")
        series=$(metric latkit_metric_series "$f")
        conns=$(metric latkit_connections_active "$f")
        dropped=$(metric latkit_ringbuf_dropped_total "$f")
        resync=$(metric latkit_resync_total "$f")
        tlsconn=$(metric latkit_tls_connections "$f")
        tlsdrop=$(metric latkit_tls_socket_events_dropped_total "$f")
        queries=$(metric latkit_queries_total "$f")
    else
        phase=${phase}-noscrape       # agent frozen/gone at scrape time
    fi
    local fds; fds=$(agent_fds)
    printf '%d\t%d\t%s\t%.0f\t%.0f\t%.0f\t%s\t%.0f\t%.0f\t%.0f\t%.0f\t%.0f\n' \
        "$SAMPLE_N" "$(date +%s)" "$phase" "$rss" "$series" "$conns" \
        "$fds" "$dropped" "$resync" "$tlsconn" "$tlsdrop" "$queries" >>"$TSV"
    SAMPLE_N=$((SAMPLE_N + 1))
}

# --------------------------------------------------------------- disturbances

induce_loss() {
    local pid; pid=$(agent_pid)
    [ -n "$pid" ] || { log "induce: no agent, skipped"; return; }
    log "induce: SIGSTOP latkit for ${INDUCE_HOLD}s (ringbuf will overflow)"
    sudo -n kill -STOP "$pid"
    sleep "$INDUCE_HOLD"
    sudo -n kill -CONT "$pid"
}

restart_pg() {
    log "restart: docker restart $PG_TLS (synthetic OPEN, libssl/cgroup re-resolve)"
    docker restart -t 5 "$PG_TLS" >/dev/null 2>&1 || true
    wait_pg "$PG_TLS" || true
}

# --------------------------------------------------------------- environment

GOV_SAVED=
fix_conditions() {
    GOV_SAVED=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "")
    sudo -n cpupower frequency-set -g performance >/dev/null 2>&1 \
        || log "WARN: cpupower failed, governor stays ${GOV_SAVED:-unknown}"
}
restore_conditions() {
    [ -z "$GOV_SAVED" ] \
        || sudo -n cpupower frequency-set -g "$GOV_SAVED" >/dev/null 2>&1 || true
}

cleanup() {
    log "cleanup"
    local p
    for p in "${LOAD_PIDS[@]:-}"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
    pkill -f 'pgbench -h ' 2>/dev/null || true
    agent_stop
    restore_conditions
}

preflight() {
    [ -x "$AGENT_BIN" ] || die "no agent binary at $AGENT_BIN (build recipe: see tests/bench/run.sh)"
    local cache="${AGENT_BIN%/*}/CMakeCache.txt"
    BUILD_TYPE=unknown
    if [ -r "$cache" ]; then
        BUILD_TYPE=$(sed -n 's/^CMAKE_BUILD_TYPE:STRING=//p' "$cache")
        case "$BUILD_TYPE" in
            Release|RelWithDebInfo) ;;
            *) log "WARN: $AGENT_BIN is not an optimised build (CMAKE_BUILD_TYPE='$BUILD_TYPE');" \
                   "a 24h soak on a -O0 agent still finds leaks, but RSS/CPU numbers are off" ;;
        esac
    fi
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    sudo -n true 2>/dev/null || die "passwordless sudo required"
    sudo -n bpftool version >/dev/null 2>&1 || die "bpftool (via sudo) required for the map snapshots"
    if [ -r /sys/firmware/acpi/platform_profile ]; then
        local prof; prof=$(cat /sys/firmware/acpi/platform_profile)
        case "$prof" in low-power|quiet)
            die "ACPI platform profile is '$prof' — echo performance | sudo tee /sys/firmware/acpi/platform_profile" ;;
        esac
    fi
    local load1; load1=$(awk '{print int($1)}' /proc/loadavg)
    if [ "$load1" -ge 2 ] && [ "$FORCE" != 1 ]; then
        die "host is not idle (loadavg $(cut -d' ' -f1-3 /proc/loadavg)); FORCE=1 to override"
    fi
}

# -------------------------------------------------------------------- report

write_header() {
    local pgver
    pgver=$(docker exec "$PG_PLAIN" psql -U $DB_USER -d $DB_NAME -Atqc 'select version()' 2>/dev/null || echo '?')
    cat >"$OUT/report.txt" <<EOF
latkit long-run soak (STAGE8.md 8.5, Р53)
==========================================
date        : $(date -u '+%Y-%m-%d %H:%M UTC')
commit      : $(git rev-parse --short HEAD)$(git diff --quiet || echo -dirty)
agent       : $("$AGENT_BIN" --version 2>/dev/null) [$BUILD_TYPE, $AGENT_BIN]
kernel      : $(uname -r)
cpu         : $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs), $(nproc) hw threads
postgres    : $pgver
pgbench     : $PGBENCH_KIND
duration    : ${DURATION_SECS}s ($(awk -v s="$DURATION_SECS" 'BEGIN{printf "%.1f", s/3600}') h), sample every ${SAMPLE_EVERY}s, smoke=$SMOKE
load        : steady -S -M prepared -c16 -R $RATE_STEADY; tpcb -c8 -R $RATE_TPCB; churn -C -c8 -R $RATE_CHURN; churn-tls -C -c4 -R $RATE_CHURN_TLS (sslmode=require)
disturbance : induced loss (SIGSTOP ${INDUCE_HOLD}s) every ${INDUCE_EVERY}s; $PG_TLS restart every ${RESTART_EVERY}s
agent flags : -p 5432 --tls auto --conn-idle-timeout $IDLE_TIMEOUT
criteria    : RSS plateau <${RSS_PLATEAU_PCT}% over 2nd half; fd growth <${FD_GROWTH_PCT}%; series <= $K_CEIL; dropped/resync grow only in induced/recovery/restart windows; maps unchanged

EOF
}

analyse() {  # writes the verdict block to report.txt, returns 0 on PASS
    awk -v plateau="$RSS_PLATEAU_PCT" -v fdgrow="$FD_GROWTH_PCT" -v kceil="$K_CEIL" '
        BEGIN { FS = "\t"; fail = 0 }
        /^#/ || NF < 12 { next }
        {
            n++; phase[n] = $3; rss[n] = $4; series[n] = $5
            fd[n] = $7; dropped[n] = $8; resync[n] = $9
            if ($4 > 0) { rssn++; rss_last = $4 }
        }
        END {
            if (n < 4) { print "  INSUFFICIENT SAMPLES (" n ")"; exit 1 }

            # --- RSS plateau over the second half -------------------------
            half = int(n / 2) + 1
            rmin = 1e18; rmax = 0; rsum = 0; rc = 0
            for (i = half; i <= n; i++) if (rss[i] > 0) {
                if (rss[i] < rmin) rmin = rss[i]
                if (rss[i] > rmax) rmax = rss[i]
                rsum += rss[i]; rc++
            }
            rmed = rc ? rsum / rc : 0
            rpct = rmed ? (rmax - rmin) / rmed * 100 : 0
            printf "  RSS 2nd-half : min %.1f MiB  max %.1f MiB  spread %.2f%% (limit %s%%)  %s\n",
                rmin/1048576, rmax/1048576, rpct, plateau, (rpct <= plateau ? "OK" : "FAIL")
            if (rpct > plateau) fail = 1

            # --- fd growth: 2nd-half max vs 1st-sample --------------------
            fd0 = fd[1]; fdmax = 0
            for (i = half; i <= n; i++) if (fd[i] > fdmax) fdmax = fd[i]
            fdpct = fd0 ? (fdmax - fd0) / fd0 * 100 : 0
            printf "  fd count     : start %d  2nd-half max %d  growth %.1f%% (limit %s%%)  %s\n",
                fd0, fdmax, fdpct, fdgrow, (fdpct <= fdgrow ? "OK" : "FAIL")
            if (fdpct > fdgrow) fail = 1

            # --- series ceiling ------------------------------------------
            smax = 0; for (i = 1; i <= n; i++) if (series[i] > smax) smax = series[i]
            printf "  metric_series: max %d (ceiling %d)  %s\n",
                smax, kceil, (smax <= kceil ? "OK" : "FAIL")
            if (smax > kceil) fail = 1

            # --- dropped/resync grow only in disturbance windows ----------
            # A steady-phase sample whose counter rose over the previous
            # sample is an unexpected loss. recovery/restart/*-noscrape are
            # expected disturbance windows.
            bad = 0
            for (i = 2; i <= n; i++) {
                # A failed scrape wrote 0 counters (unknown, not a reset); a
                # delta touching one is not evidence of loss.
                if (phase[i] ~ /noscrape/ || phase[i-1] ~ /noscrape/) continue
                dd = dropped[i] - dropped[i-1]; rd = resync[i] - resync[i-1]
                if ((dd > 0 || rd > 0) && phase[i] == "steady") {
                    bad++
                    if (bad <= 5)
                        printf "  UNEXPECTED loss at sample %d (phase steady): +%d dropped +%d resync\n",
                            i-1, dd, rd
                }
            }
            printf "  induced only : %d steady-phase loss events (must be 0)  %s\n",
                bad, (bad == 0 ? "OK" : "FAIL")
            if (bad > 0) fail = 1

            # --- recovery: last sample shows no in-flight disturbance -----
            printf "  totals       : dropped %d  resync %d  over %d samples\n",
                dropped[n], resync[n], n
            printf "\n  VERDICT: %s\n", (fail ? "FAIL" : "PASS")
            exit fail
        }' "$TSV" >>"$OUT/report.txt"
}

ascii_rss() {  # a coarse sparkline of RSS over the run, into report.txt
    awk 'BEGIN{FS="\t"} /^#/||NF<12{next} $4>0{v[++n]=$4; if($4>mx)mx=$4; if(mn==0||$4<mn)mn=$4}
        END{
            if(n<2)exit
            printf "\nRSS over time (%.1f..%.1f MiB, %d samples):\n", mn/1048576, mx/1048576, n
            b="_.-~=#"; cols=60; step=(n>cols)?n/cols:1
            line=""
            for(i=1;i<=n;i+=step){ r=(mx>mn)?(v[i]-mn)/(mx-mn):0; k=int(r*5)+1; line=line substr(b,k,1) }
            print line
        }' "$TSV" >>"$OUT/report.txt"
}

# ---------------------------------------------------------------------- main

case $CMD in
    up)   stack_up; exit 0 ;;
    down) stack_down; exit 0 ;;
    run)  ;;
    *)    die "unknown command '$CMD' (up|run|down)" ;;
esac

preflight
mkdir -p "$OUT"
OUT=$(readlink -f "$OUT")            # absolute: the detached agent runs via sudo sh
AGENT_ABS=$(readlink -f "$AGENT_BIN")
AGENT_ARGS="-p 5432 --tls auto --conn-idle-timeout $IDLE_TIMEOUT"
TSV="$OUT/samples.tsv"
printf '#sample\tepoch\tphase\trss_bytes\tseries\tconns\tfds\tdropped\tresync\ttls_conns\ttls_drop\tqueries\n' >"$TSV"

trap cleanup EXIT INT TERM
fix_conditions
stack_up
write_header

log "starting agent"
agent_start
wait_tls_attach
snap_maps "$OUT/maps-before.txt"
start_load

START=$(date +%s)
END=$((START + DURATION_SECS))
next_sample=$START
next_induce=$((START + INDUCE_EVERY))
next_restart=$((START + RESTART_EVERY))
recover_until=0
restart_until=0

log "soak: ${DURATION_SECS}s, sampling every ${SAMPLE_EVERY}s"
while :; do
    now=$(date +%s)
    [ "$now" -ge "$END" ] && break

    if [ "$now" -ge "$next_induce" ]; then
        induce_loss
        now=$(date +%s)
        recover_until=$((now + RECOVER_SECS))
        next_induce=$((next_induce + INDUCE_EVERY))
    fi
    if [ "$now" -ge "$next_restart" ]; then
        restart_pg
        now=$(date +%s)
        restart_until=$((now + RESTART_SETTLE))
        next_restart=$((next_restart + RESTART_EVERY))
    fi
    if [ "$now" -ge "$next_sample" ]; then
        phase=steady
        [ "$now" -lt "$restart_until" ] && phase=restart
        [ "$now" -lt "$recover_until" ] && phase=recovery
        sample "$phase"
        next_sample=$((next_sample + SAMPLE_EVERY))
        # If we fell behind (a long restart), don't burst-catch-up.
        [ "$next_sample" -lt "$now" ] && next_sample=$((now + SAMPLE_EVERY))
    fi
    sleep 1
done

log "soak done, final snapshot"
sample steady
snap_maps "$OUT/maps-after.txt"

# Map diff: an added or grown map is a leak (Р53). Empty diff => OK.
if diff -u "$OUT/maps-before.txt" "$OUT/maps-after.txt" >"$OUT/maps.diff" 2>&1; then
    MAPS_OK=1
else
    MAPS_OK=0
fi

agent_stop

{
    echo "analysis"
    echo "--------"
} >>"$OUT/report.txt"
if [ "$MAPS_OK" = 1 ]; then
    echo "  bpftool maps : unchanged before/after  OK" >>"$OUT/report.txt"
else
    echo "  bpftool maps : CHANGED (see maps.diff)  FAIL" >>"$OUT/report.txt"
fi

set +e
analyse
verdict=$?
ascii_rss
set -e
[ "$MAPS_OK" = 1 ] || verdict=1

log "done; report: $OUT/report.txt"
cat "$OUT/report.txt"
[ "$verdict" = 0 ] && log "VERDICT: PASS" || log "VERDICT: FAIL"
exit "$verdict"
