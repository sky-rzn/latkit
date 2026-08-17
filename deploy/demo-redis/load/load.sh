#!/usr/bin/env bash
#
# Load generator for the latkit Redis demo (PLAN-REDIS.md МR9). Runs in the
# stock `redis:7.4` image (bash + redis-cli, nothing else needed), talks to the
# server by service name over the compose network, and repeats forever.
#
# `redis-cli` rather than a client library, for one reason and against another:
# it can put an exact number of commands into one write (feed it a file) and it
# can send an inline command, neither of which a library will do on request —
# and what it cannot do is negotiate RESP3, so one pass uses `-3` to make the
# server answer in the protocol two of the five ходовых client libraries use by
# default (МR0 recon item 2).
#
# The mix is designed so that every panel of dashboards/latkit-redis.json has
# data and so that the *interesting* claims of the track are visible rather than
# asserted:
#
#   - **every key is unique per pass and none of them is ever a label.** The
#     keys carry a counter and a `:`-separated prefix — `lk:user:42:session` —
#     which is what a real Redis keyspace looks like and exactly what must not
#     reach a series. If keys leaked into labels, `latkit_metric_series` would
#     climb without bound; it is flat on the Agent health dashboard, and that is
#     the demo's own honesty check (РR4);
#   - **two databases and two ACL users**, so the two dimension slots (РR5/РR6)
#     have more than one value each and the "top" panels mean something. The
#     `SELECT 42` and the wrong password are there to show that a label moves
#     only when the *server* accepts the command;
#   - **one command family per row of the dashboard**: strings, hashes, sorted
#     sets, lists, streams, a container command (`CONFIG|GET`, whose subcommand
#     is part of the identity), scripting, and `SCAN`;
#   - **a pipeline of 30 in one write**, which is what makes
#     `latkit_redis_pipeline_depth` say something an operator can act on: `le=1`
#     is a client that waits for every reply, and everything above it is a
#     client that does not;
#   - **a transaction**: `MULTI` … `EXEC`, whose members are answered `+QUEUED`
#     in microseconds. They are counted as commands and reach no duration
#     histogram at all; the interval that means something goes to
#     `latkit_txn_duration_seconds`, the same family PostgreSQL feeds (РR9);
#   - **a blocking pop**: `BLPOP` waiting for a push that arrives ~1 s later.
#     Its duration is the client's own choice, so it lands in
#     `latkit_redis_blocking_seconds` and **not** in the general histogram —
#     without that split one `BLPOP key 30` decides the p99 of the instance
#     (РR10);
#   - **a subscription and publishes into it**: the values that answer nobody
#     (`latkit_redis_push_total`), and the one thing on this protocol that is
#     not a request/response at all (РR8);
#   - **a 64 KiB value**, for the size histogram — whose grid starts at 8 bytes,
#     because half of a real Redis's values are smaller than the HTTP grid's
#     first bucket (РR11). 64 KiB and not a megabyte on purpose: a reply large
#     enough to fill the socket's send buffer is written by the server in
#     several `tcp_sendmsg` calls, the first of which is *counted at the length
#     it asked for* rather than the length the kernel took — a capture-layer
#     limitation of the SEND fentry, documented in docs/notes-iov.md and visible
#     on this protocol as one `parse_errors` and one resync per such reply. The
#     demo shows the arithmetic bulk skip working, not that known hole; the
#     README says where to read about it;
#   - **a slow command** — `KEYS *` over ~20k keys — because Redis is
#     single-threaded and that is the shape that stalls everybody else. It is
#     what makes the difference between `INFO commandstats` and a wire
#     measurement visible on a dashboard rather than in an argument;
#   - **three deliberate failures that are three different symbols**:
#     `WRONGTYPE` (a list operation on a string), `NOAUTH` (a client that never
#     authenticated) and `WRONGPASS` (one that got it wrong). At the transport
#     level all three are "an error reply"; the symbol is the whole point of
#     РR7.
#
# What is deliberately NOT here: a command the table does not know. `cmd="other"`
# on the health panel should sit at zero on this stack — it is a *freshness*
# signal about the command table, not a cardinality guard, and a demo that
# lights it up would teach the wrong reflex. Send a `JSON.SET` if you want to
# see it move.
set -u

HOST=${REDIS_HOST:-redis}
PORT=${REDIS_PORT:-6379}
PASS=${REDIS_PASS:-lkrootpass}
APP_USER=${APP_USER:-demoapp}
APP_PASS=${APP_PASS:-demoapppass}
TLS=${REDIS_TLS:-0}

TLS_ARGS=()
[ "$TLS" = 1 ] && TLS_ARGS=(--tls --cacert /certs/ca.crt)

# The default user, authenticated by password only: `AUTH <pass>` names nobody,
# so this connection stays `user="default"` — which is a real answer and not an
# absence (РR6).
r() { redis-cli "${TLS_ARGS[@]}" -h "$HOST" -p "$PORT" -a "$PASS" --no-auth-warning "$@"; }
# ... and the ACL user, whose name the agent reads out of `AUTH <user> <pass>`.
# The password is a separate element of the same array and is never read.
app() { redis-cli "${TLS_ARGS[@]}" -h "$HOST" -p "$PORT" \
            --user "$APP_USER" --pass "$APP_PASS" --no-auth-warning "$@"; }

echo "demo load: driving $HOST:$PORT (tls=$TLS)"
until r ping 2>/dev/null | grep -q PONG; do
    echo "waiting for $HOST:$PORT ..."
    sleep 1
done

# --- setup: a keyspace worth scanning, and the one big value ----------------
# ~20k keys, so `KEYS *` and `SCAN` have something to do and the slow-command
# panel is not a flat line. DEBUG POPULATE is one command and populates faster
# than any loop could.
r debug populate 20000 lkpop: >/dev/null 2>&1 || {
    # A build with DEBUG disabled: fall back to a pipeline of SETs.
    for i in $(seq 1 2000); do echo "SET lkpop:$i v$i"; done | r >/dev/null 2>&1
}
head -c 65536 /dev/urandom | base64 | head -c 65536 > /tmp/big.txt
r -x set lk:blob:1 < /tmp/big.txt >/dev/null 2>&1

pass=0
while :; do
    pass=$((pass + 1))
    k="lk:user:$pass:session"

    # --- the ordinary application mix, one command per round trip ----------
    # A pool that does not pipeline: this is what most of a real Redis's
    # traffic looks like, and it is the `le="1"` bucket of the depth histogram.
    r set "$k" "token-$pass" ex 300                >/dev/null 2>&1
    r get "$k"                                     >/dev/null 2>&1
    r mget "$k" "lk:user:$((pass - 1)):session" lk:missing >/dev/null 2>&1
    r incr lk:counter:hits                         >/dev/null 2>&1
    r expire "$k" 600                              >/dev/null 2>&1
    r hset "lk:cart:$pass" item sku-1 qty 2        >/dev/null 2>&1
    r hgetall "lk:cart:$pass"                      >/dev/null 2>&1
    r zadd lk:leaderboard "$pass" "player:$pass"   >/dev/null 2>&1
    r zrevrange lk:leaderboard 0 9 withscores      >/dev/null 2>&1
    r zscore lk:leaderboard "player:$pass"         >/dev/null 2>&1
    r lpush lk:queue:jobs "job-$pass"              >/dev/null 2>&1
    r ltrim lk:queue:jobs 0 99                     >/dev/null 2>&1
    r xadd lk:events '*' kind click user "$pass"   >/dev/null 2>&1
    r xlen lk:events                               >/dev/null 2>&1
    r sadd lk:online "user:$pass"                  >/dev/null 2>&1
    r scard lk:online                              >/dev/null 2>&1
    r exists "$k"                                  >/dev/null 2>&1
    r ttl "$k"                                     >/dev/null 2>&1
    # A container command: `CONFIG GET` is one identity, `CONFIG|GET`, because
    # for the fifteen container commands the second element is a subcommand and
    # not a key (РR4).
    r config get maxmemory                         >/dev/null 2>&1
    r client setname demo-pool                     >/dev/null 2>&1
    # Scripting, which is one identity per verb and not per script (v1).
    r eval "return redis.call('GET', KEYS[1])" 1 "$k" >/dev/null 2>&1

    # --- the ACL user, and a database that is not 0 ------------------------
    app get "$k"                                   >/dev/null 2>&1
    app -n 9 set "lk:tenant:$pass" v               >/dev/null 2>&1
    app -n 9 get "lk:tenant:$pass"                 >/dev/null 2>&1
    # A database this deployment does not have: the server refuses, and the
    # connection stays where it was — the label moves on the *reply* (РR5).
    r -n 42 get "$k"                               >/dev/null 2>&1

    # --- a pipeline of 30 commands in one write ----------------------------
    {
        for i in $(seq 1 15); do
            echo "SET lk:batch:$pass:$i v$i"
            echo "GET lk:batch:$pass:$i"
        done
    } | r >/dev/null 2>&1

    # --- a transaction: the members are +QUEUED, the work is the EXEC ------
    {
        echo "MULTI"
        echo "INCR lk:counter:orders"
        echo "HSET lk:order:$pass total 42"
        echo "LPUSH lk:queue:orders order-$pass"
        echo "EXEC"
    } | r >/dev/null 2>&1
    # ... and one that is thrown away, so the txn family has both endings.
    { echo "MULTI"; echo "SET lk:tmp v"; echo "DISCARD"; } | r >/dev/null 2>&1

    # --- a blocking pop, woken by a push about a second later --------------
    ( sleep 1; r rpush lk:queue:block "item-$pass" >/dev/null 2>&1 ) &
    r blpop lk:queue:block 5                       >/dev/null 2>&1
    wait

    # --- pub/sub: a subscriber for a few seconds, and traffic into it ------
    ( timeout 3 redis-cli "${TLS_ARGS[@]}" -h "$HOST" -p "$PORT" -a "$PASS" \
        --no-auth-warning subscribe lk:events:cart >/dev/null 2>&1 ) &
    sub=$!
    sleep 0.2
    for i in 1 2 3 4 5; do
        r publish lk:events:cart "cart-$pass-$i"   >/dev/null 2>&1
    done
    wait "$sub" 2>/dev/null

    # --- the big value, and the commands that make the server work ---------
    r get lk:blob:1                                >/dev/null 2>&1
    r scan 0 count 100                             >/dev/null 2>&1
    # Every fourth pass: the command that stalls a single-threaded server, and
    # the reason the difference between `INFO commandstats` and a wire
    # measurement is visible rather than argued about.
    [ $((pass % 4)) -eq 0 ] && r keys 'lkpop:*'    >/dev/null 2>&1

    # --- three failures, three symbols -------------------------------------
    r set lk:notalist "a string"                   >/dev/null 2>&1
    r lpush lk:notalist x                          >/dev/null 2>&1   # WRONGTYPE
    redis-cli "${TLS_ARGS[@]}" -h "$HOST" -p "$PORT" \
        get "$k"                                   >/dev/null 2>&1   # NOAUTH
    redis-cli "${TLS_ARGS[@]}" -h "$HOST" -p "$PORT" \
        --user "$APP_USER" --pass wrongpass --no-auth-warning \
        get "$k"                                   >/dev/null 2>&1   # WRONGPASS

    # Housekeeping, so the keyspace does not grow without bound over a long
    # demo: `UNLINK` is a command of its own on the dashboard.
    [ $((pass % 20)) -eq 0 ] && \
        r unlink "lk:cart:$((pass - 19))" "lk:order:$((pass - 19))" >/dev/null 2>&1

    sleep 0.3
done
