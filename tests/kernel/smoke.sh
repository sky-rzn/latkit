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
#     could have triggered the nested-syscall fallback (Р37);
#   - the comm filter's wildcard entry (РR12): `--comm 'pgstre*'` sees the whole
#     plaintext phase and `--comm 'pgstreamx*'` sees nothing — the kernel-side
#     half of the rule that lets one entry cover Redis' `io_thd_1…N`;
#   - UDP (РH16): datagrams on the captured port are counted and TCP capture is
#     untouched by them. These are the М7 fentries on udp_sendmsg / udpv6_sendmsg
#     / skb_consume_udp, whose targets are ordinary kernel internals — exactly
#     the kind of attach that a kernel change breaks silently, which is why the
#     matrix runs them.
#
#   sudo tests/kernel/smoke.sh [--port N] [--repeat N] [--no-tls] [--mysql|--http]
#                              [--build DIR]
set -u

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BUILD=${BUILD_DIR:-$REPO_ROOT/build}
PORT=5499
REPEAT=3
DO_TLS=1
PROTO=pg

while [ $# -gt 0 ]; do
    case "$1" in
    --port) PORT=$2; shift 2 ;;
    --repeat) REPEAT=$2; shift 2 ;;
    --no-tls) DO_TLS=0; shift ;;
    # Stream the mysql fixtures with the agent framing the port as mysql
    # (МYSQL.md М7: BPF is unchanged, so one plaintext replay confirms the
    # classic protocol over a real socket). TLS is the M5 e2e stand's job.
    --mysql) PROTO=mysql; DO_TLS=0; shift ;;
    # Stream the http fixtures with the agent framing the port as http
    # (PLAN-HTTP.md М8). Worth its own matrix run even though М7 added no BPF
    # for plaintext HTTP: the stream mode of РH1 takes a different path through
    # lk_reasm_data than the two message-framed protocols, and a capture-layer
    # regression that only bites there would otherwise show up nowhere.
    --http) PROTO=http; DO_TLS=0; shift ;;
    # Stream the s3 fixtures with the agent framing the port as s3
    # (PLAN-MINIO.md МS4). The capture layer is the http one byte for byte, so
    # this run is not about BPF: it is about the registry entry and the dialect
    # surviving a real socket, and about the s3 profile's counters being the
    # ones a live agent then exports.
    --s3) PROTO=s3; DO_TLS=0; shift ;;
    --build) BUILD=$2; shift 2 ;;
    *) echo "usage: $0 [--port N] [--repeat N] [--no-tls] [--mysql|--http|--s3] [--build DIR]" >&2; exit 2 ;;
    esac
done

# The agent frames the loopback port as pg by default; the replayer is told to
# match (-m / -H / -S), so both sides agree on which fixture set travels the
# socket.
case "$PROTO" in
mysql) PORT_SPEC="$PORT=mysql"; PGSTREAM_PROTO="-m" ;;
http)  PORT_SPEC="$PORT=http";  PGSTREAM_PROTO="-H" ;;
s3)    PORT_SPEC="$PORT=s3";    PGSTREAM_PROTO="-S"
       # The one fixture that addresses its bucket through the Host needs the
       # server's domain, exactly as a deployment with MINIO_DOMAIN set does
       # (РS3); without it that request is read path-style and classifies as
       # something else entirely — correctly, but not as what it is.
       PROTO_ARGS="--s3-domain minio.lktest" ;;
*)     PORT_SPEC="$PORT";       PGSTREAM_PROTO="" ;;
esac
PROTO_ARGS=${PROTO_ARGS:-}

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

# metric_lbl FILE NAME LABEL-SUBSTRING — the same sum, over the series whose
# label set contains the given text. One profile's families are keyed by labels
# the other does not have, so an assertion about a status class needs this.
metric_lbl() {
    awk -v m="$2" -v l="$3" \
        'substr($1, 1, length(m) + 1) == m"{" && index($1, l) { s += $NF }
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
    "$AGENT" -p "$PORT_SPEC" --prom-listen none --dump-metrics="$TMP/$name.prom" \
        $PROTO_ARGS "$@" 2>"$TMP/$name.log" &
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
    # The observation counters live in the profile's own families (РH10), so
    # which two lines are read depends on the protocol under test. For http the
    # error count is the 5xx class rather than latkit_http_errors_total, which
    # РH9 defines as every status >= 400 — a 404 is counted there and is
    # deliberately not an error.
    if [ "$PROTO" = http ]; then
        assert_eq "$name: http_requests_total" "$(metric "$prom" latkit_http_requests_total)" "$queries"
        assert_eq "$name: http 5xx" "$(metric_lbl "$prom" latkit_http_requests_total 'status="5xx"')" "$errors"
    elif [ "$PROTO" = s3 ]; then
        # The s3 profile counts MinIO's own API apart and in no family that says
        # "requests" (РS2), so the fixtures' internal-path connection is in the
        # observation total the replayer reports but not in requests_total. The
        # two lines together are the assertion.
        assert_eq "$name: s3 requests + internal" \
            "$(( $(metric "$prom" latkit_s3_requests_total) + \
                 $(metric "$prom" latkit_s3_internal_requests_total) ))" "$queries"
        assert_eq "$name: s3 5xx" "$(metric_lbl "$prom" latkit_s3_requests_total 'status="5xx"')" "$errors"
    else
        assert_eq "$name: queries_total" "$(metric "$prom" latkit_queries_total)" "$queries"
        assert_eq "$name: query_errors_total" "$(metric "$prom" latkit_query_errors_total)" "$errors"
    fi
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
    if summary=$("$PGSTREAM" -p "$PORT" -r "$REPEAT" $PGSTREAM_PROTO 2>"$TMP/pgstream.log"); then
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

# --- UDP counters (РH16) -------------------------------------------------------
# HTTP/3 is QUIC over UDP and never reaches the TCP capture point; the counters
# below are what turns "the dashboard is empty" into "this port speaks a protocol
# we do not parse". Here they are driven with a plain datagram echo: one send and
# one receive on the captured port, in both directions.
log "UDP counters (РH16)"
if start_agent udp; then
    if python3 - "$PORT" <<'EOF' >"$TMP/udp.out" 2>&1
import socket, sys, time
port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(("127.0.0.1", port))
cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(5):
    cli.sendto(b"x" * 100, ("127.0.0.1", port))
    data, addr = srv.recvfrom(2048)
    srv.sendto(b"y" * 50, addr)
    cli.recv(2048)
    time.sleep(0.01)
print("udp: done packets=5 in_bytes=500 out_bytes=250")
EOF
    then
        note "$(tail -1 "$TMP/udp.out")"
        if stop_agent udp; then
            prom=$TMP/udp.prom
            assert_eq "udp: packets in" \
                "$(metric "$prom" 'latkit_udp_packets_total{port="'"$PORT"'",dir="in"}')" 5
            assert_eq "udp: bytes in" \
                "$(metric "$prom" 'latkit_udp_bytes_total{port="'"$PORT"'",dir="in"}')" 500
            assert_eq "udp: packets out" \
                "$(metric "$prom" 'latkit_udp_packets_total{port="'"$PORT"'",dir="out"}')" 5
            # Datagrams are counted and nothing else: no connection, no event, no
            # parse. A UDP packet that reached the TCP pipeline would show here.
            assert_eq "udp: connections_opened_total" \
                "$(metric "$prom" latkit_connections_opened_total)" 0
            assert_eq "udp: parse_errors_total" "$(metric "$prom" latkit_parse_errors_total)" 0
        else
            fail "agent exited non-zero after UDP phase"
            tail -5 "$TMP/udp.log" | sed 's/^/  | /'
        fi
    else
        fail "udp driver failed"
        tail -5 "$TMP/udp.out" | sed 's/^/  | /'
        stop_agent udp || true
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

# --- comm-filter scope: plaintext traffic while TLS capture is on --------------
# The regression for PLAN-HTTP.md М9. Enabling TLS gives the agent a derived comm
# list (here `--tls-comm tlspipe`, in production the libssl scan set), and that
# list is the uprobe gate: a uprobe on a shared libssl fires for every process
# mapping it, so something must say which one is the server.
#
# It must NOT gate the socket path, which is already scoped to the configured
# port. Until М9 one list did both, and the cost was silent: with TLS on, a
# captured port served by any other process — a Go/Node/Python app behind nginx
# — produced no observations at all. Here pgstream plays that process: its comm
# is `pgstream`, the filter says `tlspipe`, and every query must still be seen.
if [ "$DO_TLS" = 1 ] && [ -x "$TLSPIPE" ]; then
    log "comm-filter scope (plaintext under --tls)"
    LIBSSL=$(ldd "$TLSPIPE" | awk '/libssl/ { print $3; exit }')
    if [ -z "$LIBSSL" ]; then
        fail "cannot resolve tlspipe's libssl (ldd)"
    elif start_agent scope --libssl "$LIBSSL" --tls-comm tlspipe; then
        if summary=$("$PGSTREAM" -p "$PORT" -r "$REPEAT" $PGSTREAM_PROTO 2>"$TMP/pgstream2.log"); then
            note "$summary (driver comm: pgstream, TLS comm filter: tlspipe)"
            if stop_agent scope; then
                assert_phase scope "$summary"
            else
                fail "agent exited non-zero after comm-scope phase"
                tail -5 "$TMP/scope.log" | sed 's/^/  | /'
            fi
        else
            fail "pgstream failed"
            tail -5 "$TMP/pgstream2.log" | sed 's/^/  | /'
            stop_agent scope || true
        fi
    fi
fi

# --- comm wildcard: a prefix entry in the comm filter (РR12, МR7) -------------
# A comm filter entry may end in `*` and then matches a prefix. Exactly one
# server asked for it: Redis with `io-threads N` does its socket work — SSL_read
# and SSL_write included — on threads named `io_thd_1` … `io_thd_N`, where N is
# a config setting, so no list of literals can be written in advance. The rule
# lives in the kernel matcher, which makes it a matrix concern rather than a
# unit-test one, and pgstream stands in for the io threads: `pgstre*` must admit
# it exactly as its full name does, and a prefix that does not match must let
# nothing through (a wildcard that matches everything would pass the first half
# of this test and mean nothing).
log "comm filter, wildcard entry"
if start_agent wild --comm 'pgstre*'; then
    if summary=$("$PGSTREAM" -p "$PORT" -r "$REPEAT" $PGSTREAM_PROTO 2>"$TMP/pgstream3.log"); then
        note "$summary (driver comm: pgstream, filter: pgstre*)"
        if stop_agent wild; then
            assert_phase wild "$summary"
        else
            fail "agent exited non-zero after wildcard phase"
            tail -5 "$TMP/wild.log" | sed 's/^/  | /'
        fi
    else
        fail "pgstream failed"
        tail -5 "$TMP/pgstream3.log" | sed 's/^/  | /'
        stop_agent wild || true
    fi
fi
if start_agent nowild --comm 'pgstreamx*'; then
    "$PGSTREAM" -p "$PORT" -r "$REPEAT" $PGSTREAM_PROTO >/dev/null 2>&1 || true
    if stop_agent nowild; then
        # Observations, not connections: the filter is checked where the comm is
        # the calling thread's, and the connection lifecycle tracepoint is not
        # such a place (it can fire in softirq, where comm is somebody else's) —
        # so a filtered-out server still opens and closes its connections here
        # and simply says nothing about what travelled them.
        assert_eq "nowild: observations" \
            "$(( $(metric "$TMP/nowild.prom" latkit_queries_total) + \
                 $(metric "$TMP/nowild.prom" latkit_http_requests_total) + \
                 $(metric "$TMP/nowild.prom" latkit_s3_requests_total) + \
                 $(metric "$TMP/nowild.prom" latkit_redis_commands_total) ))" 0
    else
        fail "agent exited non-zero after the non-matching wildcard phase"
        tail -5 "$TMP/nowild.log" | sed 's/^/  | /'
    fi
fi

# --- verdict -------------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  kernel smoke ($(uname -r)): all checks passed"
    exit 0
fi
echo "  kernel smoke ($(uname -r)): $fails check(s) failed"
exit 1
