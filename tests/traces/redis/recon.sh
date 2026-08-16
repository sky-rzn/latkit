#!/usr/bin/env bash
#
# МR0 (PLAN-REDIS.md): the five reconnaissance questions, each answered against
# live servers and real clients, each leaving its evidence in .work/recon/ so
# the numbers in README.md can be re-derived rather than believed:
#
#   1. how much of a typical deployment talks over a unix socket — the size of
#      the blind zone the plan names first, and the material for the README;
#   2. does a stock client send `HELLO 3` — whether RESP3 is the main path or a
#      curiosity (risk 5 of the plan decides the order of work inside МR2);
#   3. how deep clients and benchmarks actually pipeline — the input parameter
#      of LK_REDIS_MAX_INFLIGHT and of the pipeline_depth grid (РR3, РR11);
#   4. what the io-threads of a real server are called and how much of the
#      traffic a comm filter would drop (РR12, and the МR7 gate);
#   5. whether redis-server is dynamically linked against libssl — whether the
#      existing libssl channel works at all (РR12, the МR7 gate).
#
# Plus one the plan did not ask for and the wire made unavoidable:
#
#   6. how big a command and a reply actually are, how deep a reply nests, and
#      how far `INFO commandstats` is from what the client experiences — the
#      numbers behind РR13 (a 512-byte budget), РR2 (LK_REDIS_MAX_DEPTH) and §2
#      of the plan.
#
# Uses the same stands as record.sh (run that first, or STAND=1 here to bring
# them up and leave them running).
#
#   ./recon.sh            # all six items
#   ./recon.sh 2 4        # selected items
set -uo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../../.. && pwd)
LATKIT=${LATKIT:-$REPO_ROOT/build-rel/latkit}
LKT_INFO=${LKT_INFO:-$REPO_ROOT/build/tests/replay/lkt_info}
WORK=${WORK:-$PWD/.work}
OUT=$WORK/recon
mkdir -p "$OUT"

REDIS_IMAGE=${REDIS_IMAGE:-redis:7.4}
VALKEY_IMAGE=${VALKEY_IMAGE:-valkey/valkey:8}
MEMTIER_IMAGE=${MEMTIER_IMAGE:-redislabs/memtier_benchmark:latest}
PORT=${PORT:-6399}; PORT_IO=${PORT_IO:-6396}; TAP_PORT=${TAP_PORT:-6499}
export REDIS_HOST=127.0.0.1 REDIS_PORT=$PORT

ITEMS=${*:-1 2 3 4 5 6}
log()  { printf '\n=== %s ===\n' "$*"; }
want() { case " $ITEMS " in *" $1 "*) return 0;; *) return 1;; esac; }

[ "${STAND:-0}" = 1 ] && KEEP=1 ./record.sh none >/dev/null 2>&1

# Run a client through the logging proxy and print its summary: which protocol
# it negotiates (item 2) and how many commands it puts in one write (item 3).
tap() { # tap NAME command…
    local name=$1; shift
    pkill -f "tap.py --listen $TAP_PORT" 2>/dev/null   # a leftover holds the port
    for _ in $(seq 20); do
        ss -ltn 2>/dev/null | grep -q ":$TAP_PORT " || break
        sleep 0.2
    done
    python3 clients/tap.py --listen $TAP_PORT --upstream "127.0.0.1:$PORT" --quiet \
        >"$OUT/tap-$name.txt" 2>&1 &
    local tp=$!
    sleep 0.5
    "$@" >"$OUT/tap-$name.client.txt" 2>&1
    sleep 0.4
    kill -TERM $tp 2>/dev/null; wait $tp 2>/dev/null
    printf '\n--- %s\n' "$name"
    grep -E 'first commands|commands/write|client writes' "$OUT/tap-$name.txt" \
        || sed 's/^/    /' "$OUT/tap-$name.txt"        # the tap failed: say why
}

lib() { # lib IMAGE SCENARIO
    docker run --rm --network host -e REDIS_PORT=$TAP_PORT "$1" "$2"
}

interactive_cli() {
    printf 'ping\nquit\n' | timeout 20 script -qec \
        "docker run --rm -i -t --network host $REDIS_IMAGE redis-cli -p $TAP_PORT" /dev/null
}

# --- 1. the unix socket -----------------------------------------------------
if want 1; then
    log "item 1: does a typical deployment listen on a unix socket?"
    {
        echo "--- what the packaged configurations say (uncommented = it listens) ---"
        for spec in "debian:12|apt-get -qq update >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get -qq install -y redis-server >/dev/null 2>&1|/etc/redis/redis.conf" \
                    "ubuntu:24.04|apt-get -qq update >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get -qq install -y redis-server >/dev/null 2>&1|/etc/redis/redis.conf" \
                    "alpine:3.20|apk add -q redis >/dev/null 2>&1|/etc/redis.conf"; do
            IFS='|' read -r img install conf <<<"$spec"
            echo "# $img"
            docker run --rm "$img" sh -c "$install; redis-server --version | cut -d' ' -f1-3;
                grep -nE '^ *#? *(unixsocket|io-threads) ' $conf | head -4;
                ldd \$(which redis-server) 2>/dev/null | grep -c libssl | sed 's/^/  libssl linkage: /'"
            echo
        done
        echo "# $REDIS_IMAGE (the official image)"
        docker run --rm --entrypoint sh "$REDIS_IMAGE" -c \
            'find / -maxdepth 5 -name redis.conf 2>/dev/null | head -1 || true; \
             echo "  (no redis.conf in the image: it is configured by flags only)"'
        echo
        echo "--- and what the running stand answers ---"
        docker run --rm --network host "$REDIS_IMAGE" redis-cli -p $PORT config get unixsocket port
        echo
        echo "--- the bitnami helm chart, which is how Redis reaches most clusters ---"
        curl -sS --max-time 30 -o "$OUT/bitnami-values.yaml" \
            https://raw.githubusercontent.com/bitnami/charts/main/bitnami/redis/values.yaml \
            && echo "values.yaml: $(wc -l <"$OUT/bitnami-values.yaml") lines, unix-socket settings: \
$(grep -ciE 'unixsocket|\.sock' "$OUT/bitnami-values.yaml")" \
            || echo "(chart fetch failed — offline)"
        echo
        echo "--- the demonstration: three commands over AF_UNIX under a live capture ---"
        cat "$OUT/05-unixsocket.txt" 2>/dev/null || echo "(run ./record.sh redis first)"
        [ -f "$OUT/05-unixsocket.lkt" ] && "$LKT_INFO" "$OUT/05-unixsocket.lkt"
    } 2>&1 | tee "$OUT/01-unixsocket.txt"
fi

# --- 2. HELLO 3 -------------------------------------------------------------
if want 2; then
    log "item 2: which clients speak RESP3 without being asked?"
    {
        tap py-basic   lib lkt-redis-py basic
        tap go-basic   lib lkt-redis-go basic
        tap node-basic lib lkt-redis-node basic
        tap java-basic lib lkt-redis-java basic
        tap php-basic  lib lkt-redis-php basic
        tap cli-default docker run --rm --network host "$REDIS_IMAGE" \
            redis-cli -p $TAP_PORT ping
        tap cli-3 docker run --rm --network host "$REDIS_IMAGE" \
            redis-cli -3 -p $TAP_PORT ping
        # An interactive redis-cli is a different client: it asks for the whole
        # command table before it lets you type (item 6 measures that reply).
        # It needs a pty to go interactive at all, and a `quit` to come back.
        tap cli-interactive interactive_cli
    } 2>&1 | tee "$OUT/02-hello3.txt"
fi

# --- 3. pipeline depth ------------------------------------------------------
if want 3; then
    log "item 3: how deep does a real client pipeline?"
    {
        tap py-pipeline   lib lkt-redis-py pipeline
        tap go-pipeline   lib lkt-redis-go pipeline
        tap node-pipeline lib lkt-redis-node pipeline
        tap java-pipeline lib lkt-redis-java pipeline
        tap php-pipeline  lib lkt-redis-php pipeline
        tap py-pool       lib lkt-redis-py pool
        tap go-pool       lib lkt-redis-go pool
        for depth in 1 8 100; do
            tap "memtier-p$depth" docker run --rm --network host "$MEMTIER_IMAGE" \
                -s 127.0.0.1 -p $TAP_PORT -t 1 -c 2 --test-time 2 --hide-histogram \
                --pipeline $depth
        done
    } 2>&1 | tee "$OUT/03-pipeline.txt"
fi

# --- 4. io-threads ----------------------------------------------------------
if want 4; then
    log "item 4: io-threads — thread names, and what a comm filter costs"
    {
        echo "--- thread names of a server with io-threads 4 ---"
        pid=$(docker inspect -f '{{.State.Pid}}' lkt-redis-io 2>/dev/null)
        if [ -n "$pid" ]; then
            ps -L -o comm= -p "$pid" | sort | uniq -c
        else
            echo "(no lkt-redis-io stand: run ./record.sh server)"
        fi
        echo
        echo "--- and the same for the default (io-threads 1) server ---"
        ps -L -o comm= -p "$(docker inspect -f '{{.State.Pid}}' lkt-redis)" | sort | uniq -c
        echo
        echo "--- what a --comm filter keeps: same load, three filters ---"
        # Redis only turns its io threads on when there are enough clients to
        # justify it (clients > io-threads * 2), so this needs a wide load.
        for filter in "" "--comm redis-server" "--comm io_thd_1"; do
            f=$(echo "${filter:-none}" | tr -d ' -')
            sudo "$LATKIT" --port $PORT_IO --capture-limit 256 $filter \
                --record "$OUT/04-io-$f.lkt" --prom-listen none >"$OUT/04-io-$f.log" 2>&1 &
            ap=$!
            for _ in $(seq 100); do
                grep -q 'capturing local port' "$OUT/04-io-$f.log" 2>/dev/null && break
                sleep 0.1
            done
            docker run --rm --network host "$MEMTIER_IMAGE" -s 127.0.0.1 -p $PORT_IO \
                -t 4 -c 25 -n 1000 --hide-histogram --pipeline 1 >/dev/null 2>&1
            sleep 0.5; sudo kill -INT $ap 2>/dev/null; wait $ap 2>/dev/null
            sudo chown "$(id -u):$(id -g)" "$OUT/04-io-$f.lkt" 2>/dev/null
            printf '%-24s ' "${filter:-(no filter)}"
            "$LKT_INFO" "$OUT/04-io-$f.lkt" | sed 's/.*records=/records=/'
            rm -f "$OUT/04-io-$f.lkt"     # tens of megabytes; the count is the evidence
        done
    } 2>&1 | tee "$OUT/04-iothreads.txt"
fi

# --- 5. libssl --------------------------------------------------------------
if want 5; then
    log "item 5: is redis-server linked against libssl, and is TLS compiled in?"
    {
        for img in "$REDIS_IMAGE" redis:7.4-alpine redis:6.2-alpine "$VALKEY_IMAGE" \
                   bitnami/redis:latest; do
            echo "# $img"
            docker run --rm --entrypoint sh "$img" -c '
                bin=$(command -v redis-server || command -v valkey-server \
                      || echo /opt/bitnami/redis/bin/redis-server)
                echo "  binary:  $bin"
                ldd $bin 2>/dev/null | grep -E "libssl|libcrypto" | sed "s/^/  /" \
                    || echo "  (statically linked or no libssl)"
                $bin --version | cut -d" " -f1-3 | sed "s/^/  /"
                echo "  tls support: $($bin --port 0 --tls-port 1 2>&1 | \
                    grep -qi "No tls-cert-file configured" && echo "compiled in" \
                    || echo "NOT compiled in")"' 2>&1
            echo
        done
    } 2>&1 | tee "$OUT/05-libssl.txt"
fi

# --- 6. the wire, measured --------------------------------------------------
if want 6; then
    log "item 6: command and reply sizes, nesting depth, and commandstats"
    {
        python3 clients/wirestats.py
        echo
        echo "--- the deepest replies a stock server can produce ---"
        python3 clients/depth.py
        echo
        echo "--- the command table, from the server itself (РR4) ---"
        python3 clients/cmdtable.py --stats
        echo
        echo "--- the same table on Valkey, for the fork question ---"
        REDIS_PORT=${PORT_VALKEY:-6398} python3 clients/cmdtable.py --stats 2>/dev/null \
            || echo "(no valkey stand)"
        echo
        echo "--- INFO commandstats against the wire (§2 of the plan) ---"
        python3 clients/commandstats.py
    } 2>&1 | tee "$OUT/06-wire.txt"
fi

log "evidence in $OUT"
