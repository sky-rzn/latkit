#!/usr/bin/env bash
#
# МR0 (PLAN-REDIS.md): record the reference Redis/RESP trace corpus with the
# stock capture pipeline (`latkit --record`, LKT1 format). No Redis code exists
# yet — the capture layer is protocol-independent, so the agent runs with a
# plain `--port N` (the default pg framer finds nothing, which is fine) and only
# the raw ringbuf records are kept.
#
# Five stands, because the questions are different:
#
#   redis/    single node Redis 7.4, :6399      — the protocol matrix (clients/raw.py)
#   libs/     the same node, five real client   — what a library puts on the wire
#             libraries + redis-cli + memtier     when nobody configures it
#   valkey/   Valkey 8, :6398                   — the fork, on the same matrix
#   cluster/  three nodes, :6390–6392           — MOVED, ASK, CROSSSLOT
#   server/   traffic the *server* makes        — replication, MONITOR, io-threads 4
#
# Ports: PLAN-REDIS.md writes `--port 6379=redis`, and 6379 is what a Redis
# deployment uses; the corpus is recorded on 639x only because the recording
# host already had a Redis on 6379/6380. The port is the capture filter, not
# part of what a trace means.
#
# Requirements: docker, passwordless sudo (BPF), python3; the agent binary from
# build-rel (or LATKIT=path); the client images built by clients/*/Dockerfile
# (this script builds them if they are missing).
#
#   ./record.sh              # ensure the stands, record everything
#   ./record.sh redis        # one stand only (redis | libs | valkey | cluster | server)
#   KEEP=1 ./record.sh       # leave the stands running afterwards
set -uo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../../.. && pwd)
LATKIT=${LATKIT:-$REPO_ROOT/build-rel/latkit}
WORK=${WORK:-$PWD/.work}
ONLY=${1:-}

REDIS_IMAGE=${REDIS_IMAGE:-redis:7.4}
VALKEY_IMAGE=${VALKEY_IMAGE:-valkey/valkey:8}
MEMTIER_IMAGE=${MEMTIER_IMAGE:-redislabs/memtier_benchmark:latest}

PORT=${PORT:-6399}            # the matrix node
PORT_IO=${PORT_IO:-6396}      # the same server with io-threads 4 (РR12)
PORT_REPLICA=${PORT_REPLICA:-6397}
PORT_VALKEY=${PORT_VALKEY:-6398}
PORT_C0=6390; PORT_C1=6391; PORT_C2=6392
SOCK_DIR=$WORK/sock
ACL_USER=lkuser; ACL_PASS=lkpass

export REDIS_HOST=127.0.0.1 REDIS_PORT=$PORT

fails=0; recorded=0; skipped=0
log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
cli()  { local p=$1; shift; docker run --rm --network host "$REDIS_IMAGE" redis-cli -p "$p" "$@"; }

# --- stands -----------------------------------------------------------------

wait_ping() { # wait_ping PORT
    for _ in $(seq 60); do
        [ "$(cli "$1" ping 2>/dev/null)" = "PONG" ] && return 0
        sleep 0.5
    done
    return 1
}

# A stand that exists but is stopped is not a stand: record_redis stops the
# replica so its heartbeat stays out of the other traces, and the server stand
# has to bring it back.
resume() { # resume NAME  -> 0 if it exists (started or already running)
    docker inspect "$1" >/dev/null 2>&1 || return 1
    [ "$(docker inspect -f '{{.State.Running}}' "$1")" = "true" ] || \
        docker start "$1" >/dev/null
    return 0
}

ensure_redis() {
    mkdir -p "$SOCK_DIR"; chmod 777 "$SOCK_DIR"
    resume lkt-redis || {
        log "starting lkt-redis ($REDIS_IMAGE) on :$PORT"
        # enable-debug-command: DEBUG PROTOCOL is the only way to see every
        # RESP3 type on demand, and DEBUG SLEEP is the only way to occupy the
        # event loop on purpose (the head-of-line trace). Both are off in a real
        # deployment, and neither changes the wire format of anything else.
        # unixsocket: so the blind zone can be demonstrated rather than asserted.
        docker run -d --name lkt-redis --network host -v "$SOCK_DIR:/sock" \
            "$REDIS_IMAGE" redis-server --port $PORT --save '' --appendonly no \
            --protected-mode no --enable-debug-command yes \
            --unixsocket /sock/redis.sock --unixsocketperm 777 >/dev/null || return 1
    }
    wait_ping $PORT || { note "FAIL: redis did not come up"; return 1; }
    cli $PORT acl setuser $ACL_USER on ">$ACL_PASS" '~*' '+@all' >/dev/null
}

ensure_io() {
    resume lkt-redis-io || {
        log "starting lkt-redis-io (io-threads 4) on :$PORT_IO"
        docker run -d --name lkt-redis-io --network host "$REDIS_IMAGE" \
            redis-server --port $PORT_IO --save '' --appendonly no --protected-mode no \
            --io-threads 4 --io-threads-do-reads yes >/dev/null || return 1
    }
    wait_ping $PORT_IO || { note "FAIL: io-threads redis did not come up"; return 1; }
}

ensure_replica() {
    resume lkt-redis-replica || {
        log "starting lkt-redis-replica on :$PORT_REPLICA (replicaof :$PORT)"
        docker run -d --name lkt-redis-replica --network host "$REDIS_IMAGE" \
            redis-server --port $PORT_REPLICA --save '' --appendonly no \
            --protected-mode no --replicaof 127.0.0.1 $PORT >/dev/null || return 1
    }
    wait_ping $PORT_REPLICA || { note "FAIL: replica did not come up"; return 1; }
}

ensure_valkey() {
    resume lkt-valkey || {
        log "starting lkt-valkey ($VALKEY_IMAGE) on :$PORT_VALKEY"
        docker run -d --name lkt-valkey --network host "$VALKEY_IMAGE" \
            valkey-server --port $PORT_VALKEY --save '' --appendonly no \
            --protected-mode no --enable-debug-command yes >/dev/null || return 1
    }
    wait_ping $PORT_VALKEY || { note "FAIL: valkey did not come up"; return 1; }
    cli $PORT_VALKEY acl setuser $ACL_USER on ">$ACL_PASS" '~*' '+@all' >/dev/null
}

ensure_cluster() {
    local up=1
    for i in 0 1 2; do
        local p=$((6390 + i))
        resume "lkt-redis-c$i" || {
            log "starting lkt-redis-c$i (cluster node) on :$p"
            docker run -d --name "lkt-redis-c$i" --network host "$REDIS_IMAGE" \
                redis-server --port $p --cluster-enabled yes \
                --cluster-config-file "/tmp/n$i.conf" --save '' --appendonly no \
                --protected-mode no >/dev/null || return 1
            up=0
        }
    done
    wait_ping $PORT_C0 || { note "FAIL: cluster node did not come up"; return 1; }
    if [ "$(cli $PORT_C0 cluster info | grep -c cluster_state:ok)" != 1 ]; then
        log "forming the cluster"
        yes yes | docker run --rm -i --network host "$REDIS_IMAGE" redis-cli --cluster create \
            127.0.0.1:$PORT_C0 127.0.0.1:$PORT_C1 127.0.0.1:$PORT_C2 >/dev/null 2>&1
        sleep 2
    fi
    [ "$(cli $PORT_C0 cluster info | grep -c cluster_state:ok)" = 1 ] || {
        note "FAIL: cluster did not form"; return 1; }
}

ensure_images() {
    for d in py go node java php; do
        docker image inspect "lkt-redis-$d" >/dev/null 2>&1 && continue
        log "building lkt-redis-$d"
        docker build -q -t "lkt-redis-$d" "clients/$d" >/dev/null || return 1
    done
}

stop_stand() {
    docker rm -f lkt-redis lkt-redis-io lkt-redis-replica lkt-valkey >/dev/null 2>&1
    for i in 0 1 2; do docker rm -f "lkt-redis-c$i" >/dev/null 2>&1; done
}

# --- recording --------------------------------------------------------------

start_agent() { # start_agent LOGFILE OUT FLAGS…
    local alog=$1 out=$2; shift 2
    sudo "$LATKIT" "$@" --record "$out" --prom-listen none >"$alog" 2>&1 &
    AGENT_PID=$!
    for _ in $(seq 150); do
        grep -q 'capturing local port' "$alog" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

stop_agent() {
    sudo kill -INT "$AGENT_PID" 2>/dev/null
    wait "$AGENT_PID" 2>/dev/null
}

# record DIR NAME "AGENT_FLAGS" -- client command…
record() {
    local dir=$1 name=$2 flags=$3; shift 3; shift   # swallow "--"
    local out=$PWD/$dir/$name.lkt alog=$WORK/agent-$dir-$name.log
    mkdir -p "$dir"
    if ! start_agent "$alog" "$out" $flags; then
        note "FAIL $dir/$name: agent did not attach (see $alog)"
        stop_agent; fails=$((fails + 1)); return 1
    fi
    local rc=0
    "$@" >"$WORK/client-$dir-$name.log" 2>&1 || rc=$?
    sleep 0.8
    stop_agent
    sudo chown "$(id -u):$(id -g)" "$out" 2>/dev/null
    # Deliberately broken scenarios make the client exit nonzero — the trace is
    # the point, so only a missing or empty trace is a failure.
    if [ ! -s "$out" ]; then
        note "skip $dir/$name: no events captured (client rc=$rc)"
        rm -f "$out"; skipped=$((skipped + 1)); return 1
    fi
    note "ok   $dir/$name ($(stat -c %s "$out") bytes, client rc=$rc)"
    recorded=$((recorded + 1))
}

# record_mid DIR NAME "AGENT_FLAGS" -- client command…
# The client starts *first*: by the time the agent attaches the connection is
# already open and its SELECT/AUTH are already gone. That is the only way to
# produce a synthetic connection on purpose (РR5, `db="?"`).
record_mid() {
    local dir=$1 name=$2 flags=$3; shift 3; shift
    local out=$PWD/$dir/$name.lkt alog=$WORK/agent-$dir-$name.log
    mkdir -p "$dir"
    "$@" >"$WORK/client-$dir-$name.log" 2>&1 &
    local cpid=$!
    sleep 1.2
    if ! start_agent "$alog" "$out" $flags; then
        note "FAIL $dir/$name: agent did not attach (see $alog)"
        kill $cpid 2>/dev/null; stop_agent; fails=$((fails + 1)); return 1
    fi
    wait $cpid 2>/dev/null
    sleep 0.8
    stop_agent
    sudo chown "$(id -u):$(id -g)" "$out" 2>/dev/null
    [ -s "$out" ] || { note "skip $dir/$name: no events"; rm -f "$out"
                       skipped=$((skipped + 1)); return 1; }
    note "ok   $dir/$name ($(stat -c %s "$out") bytes, mid-stream)"
    recorded=$((recorded + 1))
}

raw() { python3 clients/raw.py "$@"; }

# --- the protocol matrix ----------------------------------------------------

record_redis() {
    log "recording redis (127.0.0.1:$PORT, $REDIS_IMAGE)"
    local p="--port $PORT"
    # A live replica keeps a connection to this port open and REPLCONF ACKs it
    # once a second, which would appear in every trace here as traffic nobody
    # asked for. The replication traces belong to the `server` stand, which
    # starts it again.
    docker stop lkt-redis-replica >/dev/null 2>&1
    for s in basic types types3 bigvalue mget100 pipeline100 pipeline-depths \
             multi watch-abort eval-scripts pubsub pubsub3 tracking blocking \
             scan errors acl-errors auth-forms select-db inline-cmds containers \
             nested torn-bulk slow-client garbage monitor replica head-of-line \
             hello-probe; do
        record redis "$s" "$p" -- raw "$s"
    done
    # A thousand round trips on one socket, and a million keys in one reply:
    # both under the budget РR13 proposes, because at the default 8 KB the
    # KEYS trace alone is tens of megabytes.
    record redis keepalive1000 "$p --capture-limit 512" -- raw keepalive 1000
    record redis keys-1m "$p --capture-limit 512" -- raw keys-big 1000000
    # The same ordinary shapes at the proposed budget, to have truncated heads
    # to develop against.
    record redis basic-cap512 "$p --capture-limit 512" -- raw basic
    record redis bigvalue-cap512 "$p --capture-limit 512" -- raw bigvalue
    record redis pipeline100-cap512 "$p --capture-limit 512" -- raw pipeline100
    # A connection the agent did not see open (РR5).
    record_mid redis midstream "$p" -- raw midstream 4
    # The blind zone, demonstrated rather than asserted: the same three commands
    # over the unix socket while the agent is capturing the TCP port. The result
    # is an empty capture, so it is evidence and not a trace — it goes to
    # .work/recon/, not into the corpus.
    log "unix socket (the blind zone of §1): expecting an empty capture"
    mkdir -p "$WORK/recon"
    local uout=$WORK/recon/05-unixsocket.lkt
    if start_agent "$WORK/recon/05-unixsocket.agent.log" "$uout" $p; then
        raw unixsocket "$SOCK_DIR/redis.sock" >"$WORK/recon/05-unixsocket.txt" 2>&1
        sleep 0.8
        stop_agent
        sudo chown "$(id -u):$(id -g)" "$uout" 2>/dev/null
        note "unix-socket capture: $(stat -c %s "$uout" 2>/dev/null || echo 0) bytes \
($(grep -c '^  unix' "$WORK/recon/05-unixsocket.txt") commands ran over AF_UNIX)"
    else
        stop_agent; note "FAIL: agent did not attach for the unix-socket check"
        fails=$((fails + 1))
    fi
}

# --- what real client libraries do ------------------------------------------

record_libs() {
    log "recording libs (127.0.0.1:$PORT)"
    local p="--port $PORT"
    for sc in basic pipeline multi err; do
        record libs "py-$sc" "$p" -- docker run --rm --network host \
            -e REDIS_PORT=$PORT lkt-redis-py "$sc"
        record libs "go-$sc" "$p" -- docker run --rm --network host \
            -e REDIS_PORT=$PORT lkt-redis-go "$sc"
    done
    record libs py-resp3 "$p" -- docker run --rm --network host -e REDIS_PORT=$PORT lkt-redis-py resp3
    record libs py-pool "$p" -- docker run --rm --network host -e REDIS_PORT=$PORT lkt-redis-py pool
    record libs py-pubsub "$p" -- docker run --rm --network host -e REDIS_PORT=$PORT lkt-redis-py pubsub
    record libs py-block "$p" -- docker run --rm --network host -e REDIS_PORT=$PORT lkt-redis-py block
    record libs py-auth "$p" -- docker run --rm --network host -e REDIS_PORT=$PORT lkt-redis-py auth
    record libs go-pool "$p" -- docker run --rm --network host -e REDIS_PORT=$PORT lkt-redis-go pool
    record libs go-pubsub "$p" -- docker run --rm --network host -e REDIS_PORT=$PORT lkt-redis-go pubsub
    record libs go-block "$p" -- docker run --rm --network host -e REDIS_PORT=$PORT lkt-redis-go block
    record libs go-resp2 "$p" -- docker run --rm --network host -e REDIS_PORT=$PORT lkt-redis-go resp2
    for sc in basic pipeline multi err; do
        record libs "node-$sc" "$p" -- docker run --rm --network host \
            -e REDIS_PORT=$PORT lkt-redis-node "$sc"
    done
    record libs node-resp3 "$p" -- docker run --rm --network host -e REDIS_PORT=$PORT lkt-redis-node resp3
    for sc in basic pipeline multi block err resp2; do
        record libs "java-$sc" "$p" -- docker run --rm --network host \
            -e REDIS_PORT=$PORT lkt-redis-java "$sc"
    done
    for sc in basic pipeline multi; do
        record libs "php-$sc" "$p" -- docker run --rm --network host \
            -e REDIS_PORT=$PORT lkt-redis-php "$sc"
    done
    # redis-cli, which is what a human and a healthcheck use.
    record libs cli-resp2 "$p" -- docker run --rm --network host "$REDIS_IMAGE" \
        redis-cli -p $PORT set cli:k v
    record libs cli-resp3 "$p" -- docker run --rm --network host "$REDIS_IMAGE" \
        redis-cli -3 -p $PORT config get maxmemory
    record libs cli-inline "$p" -- sh -c \
        "printf 'PING\r\nINFO server\r\n' | timeout 3 nc -q1 127.0.0.1 $PORT || true"
    # memtier: the load the perf gate of МR8 will be measured on, at the budget
    # РR13 proposes. Bounded by request count rather than by time — one second
    # at full rate is 150k operations and 56 MB of trace even at a 256-byte
    # budget, which is a benchmark result, not a corpus entry. 2000 requests per
    # connection is the same shape in two megabytes.
    record libs memtier-nopipe "$p --capture-limit 256" -- docker run --rm --network host \
        "$MEMTIER_IMAGE" -s 127.0.0.1 -p $PORT -t 1 -c 2 -n 2000 \
        --hide-histogram --pipeline 1
    record libs memtier-pipe100 "$p --capture-limit 256" -- docker run --rm --network host \
        "$MEMTIER_IMAGE" -s 127.0.0.1 -p $PORT -t 1 -c 2 -n 2000 \
        --hide-histogram --pipeline 100
}

# --- the fork ---------------------------------------------------------------

record_valkey() {
    log "recording valkey (127.0.0.1:$PORT_VALKEY, $VALKEY_IMAGE)"
    local p="--port $PORT_VALKEY"
    for s in basic types types3 multi errors auth-forms select-db containers \
             pubsub blocking inline-cmds; do
        record valkey "$s" "$p" -- env REDIS_PORT=$PORT_VALKEY python3 clients/raw.py "$s"
    done
    record valkey cli "$p" -- docker run --rm --network host "$VALKEY_IMAGE" \
        valkey-cli -p $PORT_VALKEY info server
}

# --- the cluster ------------------------------------------------------------

record_cluster() {
    log "recording cluster (127.0.0.1:$PORT_C0…$PORT_C2)"
    record cluster moved "--port $PORT_C0" -- \
        env REDIS_PORT=$PORT_C0 python3 clients/raw.py cluster
    # ASK needs a slot in flight, and both nodes on the capture list.
    record cluster ask "--port $PORT_C0 --port $PORT_C1 --port $PORT_C2" -- \
        env REDIS_PORT=$PORT_C0 python3 clients/raw.py ask
    # The cluster bus is a different port (+10000) and a different protocol —
    # recorded once so the README can say what it is not.
    record cluster bus "--port $((PORT_C0 + 10000))" -- sleep 3
    record cluster cli-c "--port $PORT_C0" -- docker run --rm --network host \
        "$REDIS_IMAGE" redis-cli -c -p $PORT_C0 set foo bar
}

# --- what the server itself does --------------------------------------------

record_server() {
    log "recording server (replication, MONITOR, io-threads)"
    # A real replica reconnecting: REPLCONF, PSYNC, the RDB transfer and then
    # the propagation stream, all on the port we capture (РR14).
    record server replication "--port $PORT" -- sh -c \
        "docker restart lkt-redis-replica >/dev/null; sleep 4;
         docker run --rm --network host $REDIS_IMAGE redis-cli -p $PORT set repl:k v >/dev/null;
         docker run --rm --network host $REDIS_IMAGE redis-cli -p $PORT incr repl:n >/dev/null;
         docker run --rm --network host $REDIS_IMAGE redis-cli -p $PORT expire repl:k 60 >/dev/null;
         sleep 1"
    record server monitor "--port $PORT" -- raw monitor
    # io-threads 4: reads and writes of one connection are served by different
    # threads, which is the assumption МR7 has to check (РR12).
    for s in basic pipeline100 bigvalue; do
        record server "io-$s" "--port $PORT_IO" -- \
            env REDIS_PORT=$PORT_IO python3 clients/raw.py "$s"
    done
    # Twenty connections, because Redis only engages its io threads when there
    # are more clients than io-threads × 2 (recon item 4).
    record server io-memtier "--port $PORT_IO --capture-limit 256" -- \
        docker run --rm --network host "$MEMTIER_IMAGE" -s 127.0.0.1 -p $PORT_IO \
        -t 2 -c 10 -n 200 --hide-histogram
    note "io-threads thread names: $(ps -L -o comm= -p \
        "$(docker inspect -f '{{.State.Pid}}' lkt-redis-io)" | sort -u | tr '\n' ' ')"
}

# --- main -------------------------------------------------------------------

[ -x "$LATKIT" ] || { echo "agent binary not found: $LATKIT (build it or set LATKIT=)"; exit 1; }
mkdir -p "$WORK"
ensure_images || { echo "could not build the client images"; exit 1; }

for stand in redis libs valkey cluster server; do
    [ -n "$ONLY" ] && [ "$ONLY" != "$stand" ] && continue
    case $stand in
        redis)   ensure_redis && record_redis ;;
        libs)    ensure_redis && record_libs ;;
        valkey)  ensure_valkey && record_valkey ;;
        cluster) ensure_cluster && record_cluster ;;
        server)  ensure_redis && ensure_replica && ensure_io && record_server ;;
    esac
done

if [ "${KEEP:-0}" != "1" ]; then
    log "stopping the stands (KEEP=1 to keep)"
    stop_stand
fi

log "done: $recorded recorded, $skipped skipped, $fails failed"
[ "$fails" -eq 0 ]
