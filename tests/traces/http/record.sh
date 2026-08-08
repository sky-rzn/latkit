#!/usr/bin/env bash
#
# М0 (PLAN-HTTP.md): record the reference HTTP/1.x trace corpus with the stock
# capture pipeline (`latkit --record`, LKT1 format). No HTTP protocol code
# exists yet — the capture layer is protocol-independent, the agent runs with
# its default (pg) framer and only the raw ringbuf records are kept.
#
# Matrix: {nginx (static + reverse proxy), Go net/http, node/express,
#          Python gunicorn}
#       × {GET, large GET, POST, chunked request, chunked response,
#          100-continue, keep-alive x50, pipelining, 404, 500, redirect, HEAD,
#          OPTIONS, TRACE-like odd methods, websocket upgrade, h2c upgrade,
#          h2 preface, CONNECT, 16 KB header block, byte-at-a-time client,
#          body cut mid-flight, CL+TE desync, LF-only, absolute-form,
#          traceparent}
#
# nginx runs as a container on the *host* network (nothing else is installed
# on the host), the other three servers are host processes. Host networking
# rather than published ports on purpose: docker-proxy would put a second
# socket with the same local port in the middle and double every connection in
# the capture. Everything is therefore dialled on 127.0.0.1 — only the server
# side matches, the BPF filter is on the *local* port and a client's local port
# is ephemeral.
#
# Requirements: docker, sudo (BPF), go, node+npm, python3, curl, openssl.
#
#   ./record.sh              # ensure stand, record everything into ./<server>/
#   ./record.sh go           # one server only
#   KEEP=1 ./record.sh       # leave the stand running afterwards
set -uo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../../.. && pwd)
LATKIT=${LATKIT:-$REPO_ROOT/build-rel/latkit}
WORK=${WORK:-$PWD/.work}          # venv, node_modules, static files, certs, logs
ONLY=${1:-}

NGINX_IMAGE=${NGINX_IMAGE:-nginx:1.29-alpine}
PORT_NGINX=8080; PORT_H2C=8081; PORT_GO=8082; PORT_NODE=8083; PORT_GUNICORN=8084
PORT_TLS=8443

fails=0; recorded=0; skipped=0
log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }

# --- stand ------------------------------------------------------------------

ensure_static() {
    mkdir -p "$WORK/static"
    [ -f "$WORK/static/hello.txt" ] || printf 'hello from nginx\n' > "$WORK/static/hello.txt"
    [ -f "$WORK/static/index.html" ] || printf '<html><body>corpus</body></html>\n' \
        > "$WORK/static/index.html"
    # 1 MB and 8 MB: the second one is what makes sendfile(2) unmistakable in
    # the strace evidence of reconnaissance item 1.
    [ -f "$WORK/static/big.bin" ]  || head -c 1048576 /dev/urandom > "$WORK/static/big.bin"
    [ -f "$WORK/static/huge.bin" ] || head -c 8388608 /dev/urandom > "$WORK/static/huge.bin"
}

ensure_certs() {
    [ -f "$WORK/tls/server-key.pem" ] && return
    log "generating TLS certs (nginx 8443)"
    mkdir -p "$WORK/tls"
    # SAN is not decoration: java.net.http verifies the endpoint identity even
    # with a permissive trust manager, so without it the JVM half of
    # reconnaissance item 4 cannot connect at all.
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=lkt-http' \
        -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' \
        -keyout "$WORK/tls/server-key.pem" -out "$WORK/tls/server-cert.pem" 2>/dev/null
    chmod 644 "$WORK/tls/server-cert.pem" "$WORK/tls/server-key.pem"
}

ensure_clients() {
    mkdir -p "$WORK/node"
    if [ ! -d "$WORK/node/node_modules/express" ]; then
        log "npm install express"
        (cd "$WORK/node" && npm install --silent --no-fund --no-audit express) || return 1
    fi
    if [ ! -x "$WORK/venv/bin/gunicorn" ]; then
        log "creating python venv (flask, gunicorn)"
        python3 -m venv "$WORK/venv"
        "$WORK/venv/bin/pip" -q install flask gunicorn
    fi
    if [ ! -x "$WORK/bin/go-backend" ]; then
        log "building the Go backend"
        mkdir -p "$WORK/bin"
        (cd backends/go && go build -o "$WORK/bin/go-backend" .)
    fi
}

pidfile() { echo "$WORK/$1.pid"; }

start_host_server() { # start_host_server NAME PORT COMMAND...
    local name=$1 port=$2; shift 2
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$port/hello"; then return 0; fi
    log "starting $name on :$port"
    "$@" >"$WORK/$name.log" 2>&1 &
    echo $! > "$(pidfile "$name")"
    for _ in $(seq 100); do
        curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$port/hello" && return 0
        sleep 0.1
    done
    note "FAIL: $name did not come up (see $WORK/$name.log)"
    return 1
}

ensure_nginx() {
    if ! docker inspect lkt-http-nginx >/dev/null 2>&1; then
        log "starting lkt-http-nginx ($NGINX_IMAGE)"
        docker run -d --name lkt-http-nginx --network host \
            -v "$PWD/backends/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
            -v "$WORK/static:/srv/static:ro" \
            -v "$WORK/tls:/etc/nginx/tls:ro" \
            "$NGINX_IMAGE" >/dev/null || return 1
    fi
    for _ in $(seq 60); do
        curl -s -o /dev/null --max-time 1 "http://$(nginx_ip):$PORT_NGINX/hello.txt" && return 0
        sleep 0.5
    done
    note "FAIL: nginx did not come up"
    docker logs lkt-http-nginx 2>&1 | tail -5
    return 1
}

nginx_ip() { echo 127.0.0.1; }   # --network host

ensure_stand() {
    ensure_static
    ensure_certs
    ensure_clients || return 1
    start_host_server go       "$PORT_GO"       "$WORK/bin/go-backend" -addr ":$PORT_GO"
    NODE_PATH="$WORK/node/node_modules" \
        start_host_server node "$PORT_NODE" node backends/node/app.js --addr "$PORT_NODE"
    start_host_server gunicorn "$PORT_GUNICORN" "$WORK/venv/bin/gunicorn" \
        -w 2 -b "127.0.0.1:$PORT_GUNICORN" --chdir backends/gunicorn app:app
    ensure_nginx
}

stop_stand() {
    for name in go node gunicorn; do
        local pf; pf=$(pidfile "$name")
        [ -f "$pf" ] && kill "$(cat "$pf")" 2>/dev/null; rm -f "$pf"
    done
    docker rm -f lkt-http-nginx >/dev/null 2>&1
}

# --- recording --------------------------------------------------------------

# record SERVER TRACE "AGENT_FLAGS" -- client command...
# AGENT_FLAGS must contain the --port options (a trace may capture two legs,
# e.g. the front and upstream side of the nginx reverse proxy).
record() {
    local srv=$1 name=$2 flags=$3; shift 3; shift # swallow "--"
    local out=$PWD/$srv/$name.lkt alog=$WORK/agent-$srv-$name.log
    mkdir -p "$srv"
    sudo "$LATKIT" $flags --record "$out" --prom-listen none >"$alog" 2>&1 &
    local apid=$!
    for _ in $(seq 100); do grep -q 'capturing local port' "$alog" 2>/dev/null && break; sleep 0.1; done
    if ! grep -q 'capturing local port' "$alog"; then
        note "FAIL $srv/$name: agent did not attach (see $alog)"
        sudo kill "$apid" 2>/dev/null; wait "$apid" 2>/dev/null
        fails=$((fails+1)); return 1
    fi
    local rc=0
    "$@" >"$WORK/client-$srv-$name.log" 2>&1 || rc=$?
    sleep 0.7
    sudo kill -INT "$apid" 2>/dev/null; wait "$apid" 2>/dev/null
    sudo chown "$(id -u):$(id -g)" "$out" 2>/dev/null
    # Deliberately broken scenarios make curl/python exit nonzero — the trace is
    # the point, so only a missing/empty trace is a failure.
    if [ ! -s "$out" ]; then
        note "skip $srv/$name: no events captured (client rc=$rc, see $WORK/client-$srv-$name.log)"
        rm -f "$out"; skipped=$((skipped+1)); return 1
    fi
    note "ok   $srv/$name ($(stat -c %s "$out") bytes, client rc=$rc)"
    recorded=$((recorded+1))
}

CURL="curl -sS -o /dev/null --max-time 20"
raw() { python3 clients/raw.py "$@"; }

# The scenarios every backend implements, on the shared route contract.
record_common() { # record_common SERVER HOST PORT
    local srv=$1 host=$2 port=$3 base="http://$2:$3" p="--port $3"

    record "$srv" get "$p" -- $CURL "$base/hello"
    record "$srv" get-large "$p" -- $CURL "$base/big?n=1048576"
    record "$srv" post "$p" -- $CURL -X POST --data-binary @"$WORK/static/post64k.bin" \
        -H 'Content-Type: application/octet-stream' -H 'Expect:' "$base/echo"
    record "$srv" chunked-resp "$p" -- $CURL "$base/chunked?n=5"
    record "$srv" chunked-req "$p" -- raw chunked-req "$host" "$port"
    record "$srv" continue "$p" -- raw continue "$host" "$port"
    record "$srv" keepalive-50 "$p" -- raw keepalive "$host" "$port" 50
    record "$srv" pipelined "$p" -- raw pipelined "$host" "$port"
    record "$srv" statuses "$p" -- $CURL "$base/nope" "$base/boom" "$base/redirect"
    record "$srv" head "$p" -- $CURL -I "$base/hello"
    record "$srv" options "$p" -- $CURL -X OPTIONS "$base/hello"
    record "$srv" slow-response "$p" -- $CURL "$base/slow?ms=250"
    record "$srv" huge-head "$p" -- raw huge-head "$host" "$port" 16384
    # The same 16 KB head under the capture budget РH14 proposes for http
    # ports: what the framer will really see once 2048 is the default.
    record "$srv" huge-head-cap2048 "$p --capture-limit 2048" -- \
        raw huge-head "$host" "$port" 16384
    record "$srv" slow-client "$p" -- raw slow-client "$host" "$port"
    record "$srv" abort-midbody "$p" -- raw abort-midbody "$host" "$port"
    record "$srv" torn-body "$p" -- raw torn-body "$host" "$port"
    record "$srv" truncated-resp "$p" -- $CURL "$base/truncate?n=65536"
    record "$srv" absolute-form "$p" -- raw absolute-form "$host" "$port"
    record "$srv" cl-te "$p" -- raw cl-te "$host" "$port"
    record "$srv" lf-only "$p" -- raw lf-only "$host" "$port"
    record "$srv" bad-request "$p" -- raw bad-request "$host" "$port"
    record "$srv" traceparent "$p" -- raw traceparent "$host" "$port"
    record "$srv" h2c-upgrade "$p" -- raw h2c-upgrade "$host" "$port"
    record "$srv" h2-preface "$p" -- raw h2-preface "$host" "$port"
    record "$srv" websocket "$p" -- raw websocket "$host" "$port"
}

record_nginx() {
    local ip; ip=$(nginx_ip)
    log "recording nginx ($ip)"
    record_common nginx "$ip" "$PORT_NGINX"

    # Static served with sendfile(2), nginx's default. The body never goes
    # through a socket write — on kernels past the splice→sendmsg conversion it
    # still reaches tcp_sendmsg, with an honest length and a payload the probe
    # cannot copy (recon.sh item 1, and РH4).
    record nginx sendfile-static "--port $PORT_NGINX" -- \
        $CURL "http://$ip:$PORT_NGINX/huge"
    # Same bytes with sendfile off: the control trace.
    record nginx nosendfile-static "--port $PORT_NGINX" -- \
        $CURL "http://$ip:$PORT_NGINX/nosendfile/huge.bin"
    # Reverse proxy: both legs in one trace (front 8080 + upstream 8082).
    record nginx proxy-both-legs "--port $PORT_NGINX --port $PORT_GO" -- \
        $CURL "http://$ip:$PORT_NGINX/proxy/hello" \
              "http://$ip:$PORT_NGINX/proxy/chunked?n=4" \
              "http://$ip:$PORT_NGINX/proxy/json/1234"
    # Cleartext h2 by prior knowledge: preface + HPACK, the §8 blind zone.
    record nginx h2c-prior "--port $PORT_H2C" -- \
        curl -sS -o /dev/null --http2-prior-knowledge --max-time 20 \
             "http://$ip:$PORT_H2C/hello"
    # TLS on the socket: ciphertext only (М7 material).
    record nginx tls "--port $PORT_TLS" -- \
        curl -sS -ko /dev/null --max-time 20 "https://$ip:$PORT_TLS/hello"
    # Same load through the libssl uprobes: plaintext, and with ALPN the
    # negotiated protocol is visible in the decrypted stream (h2 preface!).
    local libssl; libssl=$(nginx_libssl)
    if [ -n "$libssl" ]; then
        record nginx tls-decrypted "--port $PORT_TLS --libssl $libssl --tls-comm nginx" -- \
            curl -sS -ko /dev/null --max-time 20 \
                 "https://$ip:$PORT_TLS/hello" "https://$ip:$PORT_TLS/big"
        record nginx tls-decrypted-h1 \
            "--port $PORT_TLS --libssl $libssl --tls-comm nginx" -- \
            curl -sS -ko /dev/null --http1.1 --max-time 20 \
                 "https://$ip:$PORT_TLS/hello" "https://$ip:$PORT_TLS/json/7"
    else
        note "skip nginx/tls-decrypted: libssl not found in the container"
        skipped=$((skipped+2))
    fi
}

nginx_libssl() {
    local pid; pid=$(docker inspect -f '{{.State.Pid}}' lkt-http-nginx 2>/dev/null) || return
    [ -n "$pid" ] || return
    sudo sh -c "ls /proc/$pid/root/lib/libssl.so.3* /proc/$pid/root/usr/lib/libssl.so.3* \
                2>/dev/null" | head -1
}

record_go() {
    log "recording go (127.0.0.1:$PORT_GO)"
    record_common go 127.0.0.1 "$PORT_GO"
    # CONNECT tunnel to the node backend: after 200 the bytes are opaque.
    record go connect "--port $PORT_GO" -- \
        raw connect 127.0.0.1 "$PORT_GO" "127.0.0.1:$PORT_NODE"
    # Go's chunked default: no Content-Length set by the handler at all.
    record go chunked-default "--port $PORT_GO" -- \
        $CURL "http://127.0.0.1:$PORT_GO/chunked?n=1"
}

record_node()     { log "recording node (127.0.0.1:$PORT_NODE)"
                    record_common node 127.0.0.1 "$PORT_NODE"; }
record_gunicorn() { log "recording gunicorn (127.0.0.1:$PORT_GUNICORN)"
                    record_common gunicorn 127.0.0.1 "$PORT_GUNICORN"; }

# --- main -------------------------------------------------------------------

[ -x "$LATKIT" ] || { echo "agent binary not found: $LATKIT (build it or set LATKIT=)"; exit 1; }
ensure_stand || { echo "stand did not come up"; exit 1; }
[ -f "$WORK/static/post64k.bin" ] || head -c 65536 /dev/urandom > "$WORK/static/post64k.bin"

for srv in nginx go node gunicorn; do
    [ -n "$ONLY" ] && [ "$ONLY" != "$srv" ] && continue
    "record_$srv"
done

if [ "${KEEP:-0}" != "1" ]; then
    log "stopping the stand (KEEP=1 to keep)"
    stop_stand
fi

log "done: $recorded recorded, $skipped skipped, $fails failed"
[ "$fails" -eq 0 ]
