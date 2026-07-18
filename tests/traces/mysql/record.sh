#!/usr/bin/env bash
#
# М0 (MYSQL.md): record the reference MySQL/MariaDB trace corpus with the
# stock capture pipeline (`latkit --record`, LKT1 format) — no protocol code
# involved, the capture layer is protocol-independent.
#
# Matrix: {MySQL 8.4, MySQL 5.7, MariaDB 10.11}
#       × {mysql/mariadb CLI (libmysqlclient/libmariadb),
#          mysql-connector-python (pure-python), Connector/J}
#       × {simple, prepared, multi-statement, LOAD DATA LOCAL, error,
#          transaction, big resultset, TLS, compression, cursor fetch}
#
# Servers run as docker containers; clients connect to the *container IP*
# directly (docker-proxy on localhost would duplicate every connection).
# The agent runs on the host with sudo and captures port 3306.
#
# Requirements: docker, sudo, python3 (venv), java 17+, curl, openssl.
#
#   ./record.sh              # ensure stand, record everything into ./<server>/
#   ./record.sh my84         # one server only
#   KEEP=1 ./record.sh       # leave the containers running afterwards
set -uo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../../.. && pwd)
LATKIT=${LATKIT:-$REPO_ROOT/build-rel/latkit}
WORK=${WORK:-$PWD/.work}          # venv, jar, certs, csv — not committed
ONLY=${1:-}

JDBC_VER=9.3.0
JDBC_URL=https://repo1.maven.org/maven2/com/mysql/mysql-connector-j/$JDBC_VER/mysql-connector-j-$JDBC_VER.jar

fails=0; recorded=0; skipped=0
log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }

# --- stand ------------------------------------------------------------------

ensure_clients() {
    mkdir -p "$WORK"
    if [ ! -x "$WORK/venv/bin/python" ]; then
        log "creating python venv (mysql-connector-python)"
        python3 -m venv "$WORK/venv"
        "$WORK/venv/bin/pip" -q install mysql-connector-python
    fi
    if [ ! -f "$WORK/mysql-connector-j.jar" ]; then
        log "fetching Connector/J $JDBC_VER"
        curl -fsSL -o "$WORK/mysql-connector-j.jar" "$JDBC_URL"
    fi
    if [ ! -f "$WORK/jclasses/Scenarios.class" ]; then
        javac -cp "$WORK/mysql-connector-j.jar" -d "$WORK/jclasses" clients/Scenarios.java
    fi
    if [ ! -f "$WORK/data/rows.csv" ]; then
        mkdir -p "$WORK/data"
        seq 0 999 | awk '{printf "%d\tval-%d\n", $1, $1}' > "$WORK/data/rows.csv"
    fi
}

ensure_certs() { # MariaDB does not auto-generate TLS certs — bring our own
    [ -f "$WORK/tls/server-key.pem" ] && return
    log "generating MariaDB TLS certs"
    mkdir -p "$WORK/tls"; cd "$WORK/tls"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=lkt-ca' \
        -keyout ca-key.pem -out ca.pem 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj '/CN=lkt-maria' \
        -keyout server-key.pem -out server-req.pem 2>/dev/null
    openssl x509 -req -in server-req.pem -CA ca.pem -CAkey ca-key.pem \
        -CAcreateserial -days 3650 -out server-cert.pem 2>/dev/null
    chmod 644 ca.pem server-cert.pem; chmod 600 server-key.pem
    sudo chown 999 server-key.pem   # mysql uid inside the mariadb image
    cd - >/dev/null
}

SEED_SQL='CREATE TABLE IF NOT EXISTS t (id INT PRIMARY KEY, s VARCHAR(64));
INSERT IGNORE INTO t VALUES (1,"one"),(2,"two"),(3,"three"),(4,"four"),(5,"five");
CREATE TABLE IF NOT EXISTS t_load (a INT, b VARCHAR(64));
CREATE TABLE IF NOT EXISTS big (id INT NOT NULL, payload VARCHAR(100));'
# 2 seed rows + 15 doublings = 65536 rows, ~4.5 MB on the wire as text rows.
seed_big() {
    echo 'INSERT INTO big VALUES (1, REPEAT("x",60)),(2,REPEAT("y",60));'
    for i in 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768; do
        echo "INSERT INTO big SELECT id+$i, payload FROM big;"
    done
}

ensure_server() { # ensure_server NAME IMAGE [docker opts…] -- [server args…]
    local name=$1 image=$2; shift 2
    local dockeropts=() srvargs=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do dockeropts+=("$1"); shift; done
    [ $# -gt 0 ] && shift
    srvargs=("$@")
    if ! docker inspect "lkt-$name" >/dev/null 2>&1; then
        log "starting lkt-$name ($image)"
        docker run -d --name "lkt-$name" \
            -e MYSQL_ROOT_PASSWORD=secret -e MYSQL_DATABASE=test \
            -e MARIADB_ROOT_PASSWORD=secret -e MARIADB_DATABASE=test \
            "${dockeropts[@]}" "$image" --local-infile=ON "${srvargs[@]}" >/dev/null
    fi
    local cli; cli=$(server_cli "$name")
    for _ in $(seq 60); do
        docker exec "lkt-$name" $cli -uroot -psecret -e 'SELECT 1' >/dev/null 2>&1 && break
        sleep 1
    done
    # seed over the unix socket — invisible to the port-3306 capture
    echo "$SEED_SQL" | docker exec -i "lkt-$name" $cli -uroot -psecret test 2>/dev/null
    if [ "$(docker exec "lkt-$name" $cli -uroot -psecret -N -e \
            'SELECT COUNT(*) FROM test.big' 2>/dev/null)" != "65536" ]; then
        docker exec "lkt-$name" $cli -uroot -psecret test \
            -e 'DELETE FROM big' 2>/dev/null
        seed_big | docker exec -i "lkt-$name" $cli -uroot -psecret test 2>/dev/null
    fi
}

server_image() { case $1 in my84) echo mysql:8.4;; my57) echo mysql:5.7;; maria1011) echo mariadb:10.11;; esac; }
server_cli()   { case $1 in maria1011) echo mariadb;; *) echo mysql;; esac; }
server_tlscomm() { case $1 in maria1011) echo mariadbd;; *) echo mysqld;; esac; }
server_ip()    { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "lkt-$1"; }
# plaintext CLI flags: 8.x CLIs default to TLS (the servers auto-generate
# certs) and caching_sha2 over plaintext needs the server RSA key
cli_plain() { case $1 in
    my84)      echo "--ssl-mode=DISABLED --get-server-public-key";;
    my57)      echo "--ssl-mode=DISABLED";;
    maria1011) echo "--skip-ssl";; esac; }
cli_tls()   { case $1 in maria1011) echo "--ssl"; ;; *) echo "--ssl-mode=REQUIRED";; esac; }
cli_compress() { case $1 in my84) echo "--compression-algorithms=zlib";; *) echo "--compress";; esac; }

# --- recording --------------------------------------------------------------

# record SERVER TRACE AGENT_EXTRA_FLAGS -- client command...
record() {
    local srv=$1 name=$2 extra=$3; shift 3; shift # swallow "--"
    local out=$PWD/$srv/$name.lkt alog=$WORK/agent-$srv-$name.log
    mkdir -p "$srv"
    sudo "$LATKIT" --port 3306 --record "$out" --prom-listen none $extra \
        >"$alog" 2>&1 &
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
    if [ "$rc" -ne 0 ] && [ "$name" != "cli-error" ]; then
        note "skip $srv/$name: client failed rc=$rc (see $WORK/client-$srv-$name.log)"
        rm -f "$out"; skipped=$((skipped+1)); return 1
    fi
    note "ok   $srv/$name ($(stat -c %s "$out") bytes)"
    recorded=$((recorded+1))
}

# CLI clients run from the matching server image (libmysqlclient / libmariadb)
cli() { # $1 server, rest: CLI args
    local srv=$1; shift
    docker run --rm -v "$WORK/data:/data:ro" "$(server_image "$srv")" \
        "$(server_cli "$srv")" -h"$(server_ip "$srv")" -uroot -psecret "$@"
}
py()   { "$WORK/venv/bin/python" clients/scenarios.py "$@"; }
jdbc() { java -cp "$WORK/mysql-connector-j.jar:$WORK/jclasses" Scenarios "$@"; }

# Agent flags for the decrypted-channel (uprobe) TLS trace. Trap found while
# recording М0: the pre-М5 agent adopted the TLS comm as the *global* BPF comm
# filter — harmless for postgres, but MySQL 8.x names its per-session OS
# threads `connection`, so filtering on `mysqld` silently dropped every socket
# AND uprobe event (comm is per-thread). For 8.x we therefore skipped the
# comm-based /proc scan (--libssl straight at the container's file) and set
# --tls-comm to the *thread* name. 5.7 and MariaDB do not rename threads.
# Fixed in М5 (РМ10: scan by process comm, kernel filter widened by
# `connection`) — a plain `--tls auto` works on any current agent; the explicit
# flags stay so the corpus can be re-recorded with pre-М5 binaries too.
tls_agent_flags() {
    local srv=$1 pid libssl
    case $srv in
    my84)
        pid=$(docker inspect -f '{{.State.Pid}}' "lkt-$srv")
        libssl=$(sudo sh -c "ls /proc/$pid/root/usr/lib64/libssl.so.3* 2>/dev/null" | head -1)
        [ -n "$libssl" ] && echo "--libssl $libssl --tls-comm connection";;
    *)  echo "--tls auto --tls-comm $(server_tlscomm "$srv")";;
    esac
}

record_server() {
    local srv=$1 ip plain tls
    ip=$(server_ip "$srv"); plain=$(cli_plain "$srv"); tls=$(cli_tls "$srv")
    log "recording $srv ($ip)"

    record "$srv" cli-simple "" -- \
        cli "$srv" $plain test -e 'SELECT * FROM t'
    record "$srv" cli-prepared-text "" -- \
        cli "$srv" $plain test -e \
        "PREPARE s FROM 'SELECT * FROM t WHERE id = ?'; SET @a = 3; EXECUTE s USING @a; DEALLOCATE PREPARE s"
    record "$srv" cli-load-data "" -- \
        cli "$srv" $plain --local-infile=1 test -e \
        "LOAD DATA LOCAL INFILE '/data/rows.csv' INTO TABLE t_load FIELDS TERMINATED BY '\t'; SELECT COUNT(*) FROM t_load; DELETE FROM t_load"
    record "$srv" cli-error "" -- \
        cli "$srv" $plain test -e 'SELECT * FROM no_such_table'
    record "$srv" cli-transaction "" -- \
        cli "$srv" $plain test -e \
        "BEGIN; INSERT INTO t VALUES (500,'cli-txn'); UPDATE t SET s='upd' WHERE id=500; ROLLBACK; SELECT COUNT(*) FROM t"
    record "$srv" cli-big-resultset "" -- \
        cli "$srv" $plain test -e 'SELECT * FROM big'
    # socket-layer-only TLS trace: plaintext greeting + short CLIENT_SSL
    # HandshakeResponse + ciphertext — the М2 framer's TLS-transition fixture
    record "$srv" cli-tls "" -- \
        cli "$srv" $tls test -e "SELECT * FROM t; SHOW STATUS LIKE 'Ssl_cipher'"
    # same load with the SSL_read/SSL_write uprobe channel (LK_F_DECRYPTED)
    record "$srv" cli-tls-decrypted "$(tls_agent_flags "$srv")" -- \
        cli "$srv" $tls test -e "SELECT * FROM t; SHOW STATUS LIKE 'Ssl_cipher'"
    record "$srv" cli-compress "" -- \
        cli "$srv" $plain $(cli_compress "$srv") test \
        -e 'SELECT * FROM t; SELECT COUNT(*) FROM big'
    if [ "$srv" = my84 ]; then
        record "$srv" cli-compress-zstd "" -- \
            cli "$srv" $plain --compression-algorithms=zstd test \
            -e 'SELECT * FROM t; SELECT COUNT(*) FROM big'
    fi

    for sc in simple prepared error transaction multi; do
        record "$srv" "py-$sc" "" -- py "$ip" "$sc"
    done
    record "$srv" py-load-data "" -- py "$ip" load-data "$WORK/data/rows.csv"

    for sc in simple prepared multi cursor-fetch transaction; do
        record "$srv" "jdbc-$sc" "" -- jdbc "$ip" "$sc"
    done

    if [ "$srv" = my84 ]; then # second/third TLS client shape, one server is enough
        record "$srv" py-tls "" -- py "$ip" tls
        record "$srv" jdbc-tls "" -- jdbc "$ip" tls
    fi
}

# --- main ---------------------------------------------------------------------

[ -x "$LATKIT" ] || { echo "agent binary not found: $LATKIT (build it or set LATKIT=)"; exit 1; }
ensure_clients
ensure_certs
ensure_server my84 mysql:8.4
ensure_server my57 mysql:5.7
ensure_server maria1011 mariadb:10.11 \
    -v "$WORK/tls:/etc/mysql/tls:ro" -- \
    --ssl-cert=/etc/mysql/tls/server-cert.pem \
    --ssl-key=/etc/mysql/tls/server-key.pem \
    --ssl-ca=/etc/mysql/tls/ca.pem

for srv in my84 my57 maria1011; do
    [ -n "$ONLY" ] && [ "$ONLY" != "$srv" ] && continue
    record_server "$srv"
done

if [ "${KEEP:-0}" != "1" ]; then
    log "stopping containers (KEEP=1 to keep)"
    docker rm -f lkt-my84 lkt-my57 lkt-maria1011 >/dev/null 2>&1
fi

log "done: $recorded recorded, $skipped skipped, $fails failed"
[ "$fails" -eq 0 ]
