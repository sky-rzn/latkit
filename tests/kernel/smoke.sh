#!/usr/bin/env bash
#
# Kernel-matrix smoke (task 8.4, Р52): agent + pgstream (plaintext) and, when
# tlspipe is built, agent + tlspipe (TLS via real libssl) on a loopback port.
# The same script runs on a live host and inside a vmtest VM (kernels.yml) —
# it does not know or care which; everything it needs (agent binary, replayers,
# their shared libraries) comes from the build tree on the shared rootfs.
#
# Asserts, against the replayers' printed expectations:
#   - OPEN/CLOSE: connections_opened == conns replayed, active == 0 at exit;
#   - exactly N queries recognised (sum latkit_queries_total), errors match;
#   - 0 parse errors, 0 unknown messages, 0 resyncs, 0 ringbuf drops;
#   - 0 iter_unsupported — the CO-RE-regression detector (Р52): a wrong
#     iter_type relocation turns every send/recv into "unsupported";
#   - TLS: uprobe events flowed, correlation misses == 0, tls conns == conns;
#     plus (with bpftool) the SSL_set_fd walk check — ssl_to_conn must be
#     populated during tlspipe's post-handshake pause, before any data call
#     could have triggered the nested-syscall fallback (Р37).
#
#   sudo tests/kernel/smoke.sh [--port N] [--repeat N] [--no-tls] [--build DIR]
set -u

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BUILD=${BUILD_DIR:-$REPO_ROOT/build}
PORT=5499
REPEAT=3
DO_TLS=1

while [ $# -gt 0 ]; do
    case "$1" in
    --port) PORT=$2; shift 2 ;;
    --repeat) REPEAT=$2; shift 2 ;;
    --no-tls) DO_TLS=0; shift ;;
    --build) BUILD=$2; shift 2 ;;
    *) echo "usage: $0 [--port N] [--repeat N] [--no-tls] [--build DIR]" >&2; exit 2 ;;
    esac
done

AGENT=$BUILD/latkit
PGSTREAM=$BUILD/tests/kernel/pgstream
TLSPIPE=$BUILD/tests/kernel/tlspipe
TMP=$(mktemp -d)
fails=0
agent_pid=

log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
pass() { printf '  ok   - %s\n' "$*"; }
fail() { printf '  FAIL - %s\n' "$*"; fails=$((fails + 1)); }

cleanup() {
    [ -n "$agent_pid" ] && kill "$agent_pid" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

# Sum every series of one metric family in a text exposition.
metric() { # metric FILE NAME
    awk -v m="$2" '$1 == m || substr($1, 1, length(m) + 1) == m"{" { s += $NF }
                   END { printf "%.0f\n", s + 0 }' "$1"
}

assert_eq() { # assert_eq LABEL GOT WANT
    if [ "$2" = "$3" ]; then pass "$1 = $2"; else fail "$1 = $2 (expected $3)"; fi
}

assert_gt0() { # assert_gt0 LABEL GOT
    if [ "${2:-0}" -gt 0 ] 2>/dev/null; then pass "$1 = $2 (> 0)"; else fail "$1 = ${2:-?} (expected > 0)"; fi
}

start_agent() { # start_agent NAME EXTRA_ARGS...
    local name=$1; shift
    "$AGENT" -p "$PORT" --prom-listen none --dump-metrics="$TMP/$name.prom" \
        "$@" 2>"$TMP/$name.log" &
    agent_pid=$!
    for _ in $(seq 1 40); do
        grep -q 'attached, capturing' "$TMP/$name.log" && return 0
        kill -0 "$agent_pid" 2>/dev/null || break
        sleep 0.25
    done
    fail "agent did not attach (see below)"
    tail -5 "$TMP/$name.log" | sed 's/^/  | /'
    agent_pid=
    return 1
}

stop_agent() { # stop_agent NAME -> 0 if clean exit
    local rc
    sleep 2 # let CLOSE events and the final ringbuf drain land
    kill -TERM "$agent_pid" 2>/dev/null
    wait "$agent_pid"
    rc=$?
    agent_pid=
    return "$rc"
}

# Common asserts over one phase: NAME, and the replayer's summary line
# "<tool>: done conns=N queries=N sessions=N errors=N".
assert_phase() { # assert_phase NAME SUMMARY_LINE
    local name=$1 summary=$2 conns queries errors prom=$TMP/$1.prom log=$TMP/$1.log
    conns=$(sed -n 's/.*conns=\([0-9]*\).*/\1/p' <<<"$summary")
    queries=$(sed -n 's/.*queries=\([0-9]*\).*/\1/p' <<<"$summary")
    errors=$(sed -n 's/.*errors=\([0-9]*\).*/\1/p' <<<"$summary")

    [ -s "$prom" ] || { fail "$name: no metrics dump ($prom)"; return; }
    assert_eq "$name: connections_opened_total" "$(metric "$prom" latkit_connections_opened_total)" "$conns"
    assert_eq "$name: connections_active" "$(metric "$prom" latkit_connections_active)" 0
    assert_eq "$name: queries_total" "$(metric "$prom" latkit_queries_total)" "$queries"
    assert_eq "$name: query_errors_total" "$(metric "$prom" latkit_query_errors_total)" "$errors"
    assert_eq "$name: parse_errors_total" "$(metric "$prom" latkit_parse_errors_total)" 0
    assert_eq "$name: unknown_msgs_total" "$(metric "$prom" latkit_unknown_msgs_total)" 0
    assert_eq "$name: resync_total" "$(metric "$prom" latkit_resync_total)" 0
    assert_eq "$name: ringbuf_dropped_total" "$(metric "$prom" latkit_ringbuf_dropped_total)" 0

    # The CO-RE detector: read from the final kernel-stats line on stderr —
    # iter_unsupported is deliberately not a metric (Р27 keeps the exposition
    # to actionable series), but the stats line always carries it.
    local iu
    iu=$(grep 'latkit: stats' "$log" | tail -1 | sed -n 's/.*iter_unsupported=\([0-9]*\).*/\1/p')
    assert_eq "$name: iter_unsupported" "${iu:-missing}" 0
}

log "environment"
note "kernel: $(uname -r), port: $PORT, repeat: $REPEAT, build: $BUILD"
[ -e /sys/kernel/btf/vmlinux ] || { fail "/sys/kernel/btf/vmlinux missing (kernel without BTF?)"; exit 1; }
[ -x "$AGENT" ] || { fail "agent binary not found: $AGENT (build first)"; exit 1; }
[ -x "$PGSTREAM" ] || { fail "pgstream not found: $PGSTREAM (build first)"; exit 1; }
ip link set lo up 2>/dev/null || true # a fresh VM may come up with lo down

# --- plaintext: agent + pgstream ---------------------------------------------
log "plaintext smoke (pgstream)"
if start_agent plain; then
    if summary=$("$PGSTREAM" -p "$PORT" -r "$REPEAT" 2>"$TMP/pgstream.log"); then
        note "$summary"
        if stop_agent plain; then
            assert_phase plain "$summary"
        else
            fail "agent exited non-zero after plaintext phase"
            tail -5 "$TMP/plain.log" | sed 's/^/  | /'
        fi
    else
        fail "pgstream failed"
        tail -5 "$TMP/pgstream.log" | sed 's/^/  | /'
        stop_agent plain || true
    fi
fi

# --- TLS: agent + tlspipe ------------------------------------------------------
if [ "$DO_TLS" = 1 ] && [ -x "$TLSPIPE" ]; then
    log "TLS smoke (tlspipe)"
    # The libssl tlspipe actually maps is the uprobe target; resolving it here
    # beats --tls auto's 30 s rescan cadence for a short-lived test process.
    LIBSSL=$(ldd "$TLSPIPE" | awk '/libssl/ { print $3; exit }')
    if [ -z "$LIBSSL" ]; then
        fail "cannot resolve tlspipe's libssl (ldd)"
    elif start_agent tls --libssl "$LIBSSL" --tls-comm tlspipe; then
        # Walk-check window (Р37): pause needs bpftool to be worth the wait.
        PAUSE=0
        command -v bpftool >/dev/null && bpftool map show >/dev/null 2>&1 && PAUSE=3
        "$TLSPIPE" -p "$PORT" -r "$REPEAT" -P "$PAUSE" >"$TMP/tlspipe.out" 2>"$TMP/tlspipe.log" &
        tlspipe_pid=$!
        if [ "$PAUSE" -gt 0 ]; then
            for _ in $(seq 1 40); do
                grep -q 'pausing' "$TMP/tlspipe.out" 2>/dev/null && break
                kill -0 "$tlspipe_pid" 2>/dev/null || break
                sleep 0.25
            done
            if bpftool map dump name ssl_to_conn 2>/dev/null | grep -q key; then
                pass "tls: ssl_to_conn populated before first data (SSL_set_fd walk works)"
            else
                fail "tls: ssl_to_conn empty during handshake pause (Р37 walk broken?)"
            fi
        else
            note "bpftool unavailable — skipping the SSL_set_fd walk check"
        fi
        if wait "$tlspipe_pid"; then
            summary=$(grep 'done conns=' "$TMP/tlspipe.out")
            note "$summary"
            if stop_agent tls; then
                assert_phase tls "$summary"
                prom=$TMP/tls.prom
                assert_eq "tls: tls_connections_total" "$(metric "$prom" latkit_tls_connections_total)" \
                    "$(sed -n 's/.*conns=\([0-9]*\).*/\1/p' <<<"$summary")"
                assert_gt0 "tls: tls_uprobe_events_total" "$(metric "$prom" latkit_tls_uprobe_events_total)"
                assert_eq "tls: tls_correlation_misses_total" \
                    "$(metric "$prom" latkit_tls_correlation_misses_total)" 0
            else
                fail "agent exited non-zero after TLS phase"
                tail -5 "$TMP/tls.log" | sed 's/^/  | /'
            fi
        else
            fail "tlspipe failed"
            tail -5 "$TMP/tlspipe.log" | sed 's/^/  | /'
            stop_agent tls || true
        fi
    fi
else
    log "TLS smoke skipped ($([ "$DO_TLS" = 1 ] && echo 'tlspipe not built' || echo '--no-tls'))"
fi

# --- verdict -------------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  kernel smoke ($(uname -r)): all checks passed"
    exit 0
fi
echo "  kernel smoke ($(uname -r)): $fails check(s) failed"
exit 1
