#!/usr/bin/env bash
#
# HTTP accuracy validation stand (PLAN-HTTP.md М8).
#
# One controlled workload, two views of it, joined **one request at a time**:
#
#   - the agent's observations   (--record, replayed through lkt_queries);
#   - nginx's access log         ($request_time, $upstream_response_time,
#                                 $body_bytes_sent), keyed by the client's
#                                 X-Request-Id, which the agent reports too.
#
# Per-request rather than in aggregate, because that is the only way to catch a
# systematic error that cancels out in a percentile: two curves of the same
# shape can still be two different sets of requests. The join and the gates live
# in http_join.py; this script owns the stand, the workload and the assertions
# whose expected values only the stand knows.
#
# The workload is deliberately a spread of the shapes РH4/РH5 are about, not a
# uniform flood: a small GET, an id-bearing GET, a chunked response (Go's
# default when it does not know the length), a slow route (TTFB far from the
# duration), a trickled upload (an upload interval that belongs to the client),
# a single-call upload (no interval to report), a static file through sendfile,
# a 404 and a 500. Every request carries its own X-Request-Id.
#
# Usage:
#   tests/bench/accuracy/run-http.sh          # run the campaign
#   tests/bench/accuracy/run-http.sh down     # remove a leftover stand
#
# Knobs (env): PASSES=40, TOL_MS=5, MIN_SAMPLES=50, AGENT_BIN=build-rel/latkit,
#   OUT=tests/bench/accuracy/out/http-<ts>
#
# Requirements: an optimised agent build (an -O0 agent can drop under burst and
# invalidate the run), docker, a Go toolchain (the backend), passwordless sudo.

set -euo pipefail

cd "$(dirname "$0")/../../.."       # repo root

CMD=${1:-run}
PASSES=${PASSES:-40}
TOL_MS=${TOL_MS:-5}
MIN_SAMPLES=${MIN_SAMPLES:-50}
AGENT_BIN=${AGENT_BIN:-build-rel/latkit}
OUT=${OUT:-tests/bench/accuracy/out/http-$(date -u +%Y%m%dT%H%M%SZ)}
case "$OUT" in /*) ;; *) OUT=$PWD/$OUT ;; esac

NET=latkit-acc-http-net
NGINX=latkit-acc-nginx
BACKEND=latkit-acc-backend
UPSTREAM_HOST=upstream-app

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

stack_down() {
    docker rm -f "$NGINX" "$BACKEND" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}

agent_pid() { pgrep -x latkit || true; }

AGENT_JOB=
agent_start() {   # $1 = run dir
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    # Both legs are captured: 8080 is client -> nginx, 8081 nginx -> backend.
    # --record rather than --queries because the join wants the *replayed*
    # view, which is reproducible from the artefact this leaves behind.
    sudo -n "$AGENT_BIN" -p 8080=http -p 8081=http \
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

stack_up() {   # $1 = run dir
    stack_down
    docker network create "$NET" >/dev/null
    # The alias is what nginx's `upstream app { server backend:8081; }` resolves
    # — without it nginx refuses to start ("host not found in upstream").
    docker run -d --name "$BACKEND" --network "$NET" --network-alias backend \
        -v "$PWD/build/httpbackend:/srv/httpbackend:ro" \
        -e LISTEN=":8081" alpine:3.20 /srv/httpbackend >/dev/null
    mkdir -p "$1/nginxlog"
    chmod 777 "$1/nginxlog"
    docker run -d --name "$NGINX" --network "$NET" \
        -v "$PWD/tests/bench/accuracy/nginx-accuracy.conf:/etc/nginx/nginx.conf:ro" \
        -v "$1/nginxlog:/var/log/nginx" \
        --entrypoint sh nginx:1.27-alpine -c '
            mkdir -p /www/static
            head -c 1048576 /dev/urandom > /www/static/big.bin
            exec nginx -g "daemon off;"' >/dev/null
    for _ in $(seq 60); do
        docker exec "$NGINX" wget -q -O- http://127.0.0.1:8080/hello >/dev/null 2>&1 && break
        sleep 1
    done
    docker exec "$NGINX" wget -q -O- http://127.0.0.1:8080/hello >/dev/null 2>&1 \
        || die "nginx never became ready"
}

nginx_ip() {
    docker inspect "$NGINX" --format \
        '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
}

# The workload. Driven from the host against the container IP — never
# 127.0.0.1, where docker-proxy would splice the payload past the capture point
# (the same rule the PostgreSQL accuracy stand follows).
drive() {   # $1 = run dir
    local ip=$2 i url
    local curlopts=(-s -o /dev/null --max-time 30)

    for i in $(seq "$PASSES"); do
        for url in /hello "/json/$i" /chunked /slow /nope /boom \
                   /static/big.bin; do
            curl "${curlopts[@]}" -H "X-Request-Id: r-$i-$(echo "$url" | tr -c 'a-zA-Z0-9' '-')" \
                "http://$ip:8080$url"
        done
        # A client that trickles its body: the upload interval is real, and it
        # is the client's (РH5). Small writes, deliberately under the per-port
        # capture budget — see docs/accuracy.md §HTTP for what happens above it.
        (for _ in 1 2 3 4 5 6; do head -c 512 /dev/zero; sleep 0.05; done) |
            curl "${curlopts[@]}" -H "X-Request-Id: r-$i-upload-slow" \
                 -H 'Expect:' -T - "http://$ip:8080/upload"
        # A client that hands the kernel everything in one call: no interval.
        head -c 4096 /dev/zero |
            curl "${curlopts[@]}" -H "X-Request-Id: r-$i-upload-fast" \
                 -H 'Expect:' --data-binary @- "http://$ip:8080/upload"
    done >"$1/curl.log" 2>&1
}

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
command -v go >/dev/null || die "a Go toolchain is required (the backend)"

log "building lkt_queries and the backend"
cmake --build build --target lkt_queries -j >/dev/null
(cd tests/e2e/httpbackend && CGO_ENABLED=0 go build -o "$PWD/../../../build/httpbackend" .)

mkdir -p "$OUT"
trap cleanup EXIT INT TERM

log "bringing the stand up"
stack_up "$OUT"
IP=$(nginx_ip)
log "nginx at $IP:8080, backend behind it on 8081"

agent_start "$OUT"
log "driving $PASSES passes"
drive "$OUT" "$IP"
sleep 2
agent_stop
[ -s "$OUT/run.lkt" ] || die "the agent recorded nothing"
sudo -n chmod a+r "$OUT/run.lkt" "$OUT/agent.prom" 2>/dev/null || true

log "replaying the recording through the handler"
build/tests/replay/lkt_queries --proto http "$OUT/run.lkt" >"$OUT/queries.txt" 2>&1

log "joining by X-Request-Id"
RC=0
python3 tests/bench/accuracy/http_join.py \
    --access "$OUT/nginxlog/acc.log" --agent "$OUT/queries.txt" \
    --upstream-host "$UPSTREAM_HOST" --tol-ms "$TOL_MS" \
    --min-samples "$MIN_SAMPLES" >"$OUT/join.tsv" 2>"$OUT/join.summary" || RC=$?

REPORT=$OUT/report.txt
{
    echo "latkit HTTP accuracy validation (PLAN-HTTP.md М8)"
    echo "================================================="
    echo "date     : $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "commit   : $(git rev-parse --short HEAD)$(git diff --quiet || echo -dirty)"
    echo "agent    : $("$AGENT_BIN" --version) [$BUILD_TYPE, $AGENT_BIN]"
    echo "kernel   : $(uname -r)"
    echo "stand    : nginx:1.27-alpine (sendfile on) -> Go net/http backend"
    echo "workload : $PASSES passes x {hello, json/{id}, chunked, slow, 404,"
    echo "           500, 1 MB static, trickled upload, single-call upload}"
    echo "reference: nginx access log — \$request_time, \$upstream_response_time,"
    echo "           \$body_bytes_sent, joined on the client's X-Request-Id"
    echo "gates    : p90 duration gap <= ${TOL_MS} ms per leg; body bytes exact;"
    echo "           >= 95% of logged requests observed"
    echo
    cat "$OUT/join.summary"
    echo
    echo "counters from the run:"
    grep -E '^latkit_(parse_errors_total|resync_total|ringbuf_dropped_total|ignored_conns_total)' \
        "$OUT/agent.prom" 2>/dev/null | sed 's/^/  /' || true
    echo
    echo "per-request table: $OUT/join.tsv"
} >"$REPORT"

# A run with drops or resyncs is not a valid measurement — the same rule the
# PostgreSQL stand applies (Р49/Р50): "count matches exactly" means nothing on
# a lossy capture.
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
