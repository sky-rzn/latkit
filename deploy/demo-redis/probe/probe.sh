#!/usr/bin/env bash
#
# The traffic a client library does not generate (latkit Redis demo, МR9).
# Two shapes, and both of them are things an operator meets in production and a
# test suite usually does not:
#
#   1. **an inline command.** `PING\r\n` written straight onto the socket by a
#      load balancer's TCP probe, a healthcheck script or somebody's telnet. It
#      is not RESP at all — no `*1`, no `$4`, just a line — and it is still a
#      command, classified like one and timed like one (РR15). In a typical
#      deployment these are a large share of everything the port carries;
#   2. **a keyspace-notification listener.** A `CONFIG SET notify-keyspace-events`
#      plus a `PSUBSCRIBE` on `__keyevent@0__:*`: from the agent's side this is
#      a connection that receives values nobody asked for, at the rate the
#      *other* clients write — the second source of pushes beside the demo
#      load's own pub/sub, and the one that is easy to forget exists (риск 4 of
#      the plan).
#
# bash's /dev/tcp does the first one with no extra image; the second is plain
# redis-cli. Both talk to Redis by service name over the compose network.
set -u

HOST=${REDIS_HOST:-redis}
PORT=${REDIS_PORT:-6379}
PASS=${REDIS_PASS:-lkrootpass}

r() { redis-cli -h "$HOST" -p "$PORT" -a "$PASS" --no-auth-warning "$@"; }

echo "demo probe: driving $HOST:$PORT"
until r ping 2>/dev/null | grep -q PONG; do sleep 1; done

# Keyspace notifications for the listener below: `KEA` is every event class.
r config set notify-keyspace-events KEA >/dev/null 2>&1

# The listener, restarted every 30 s so its `PSUBSCRIBE` — the command whose
# confirmation is the one reply a subscribed connection gets — is observed and
# not only inferred.
(
    while :; do
        timeout 30 redis-cli -h "$HOST" -p "$PORT" -a "$PASS" --no-auth-warning \
            psubscribe '__keyevent@0__:*' >/dev/null 2>&1
        sleep 1
    done
) &

# The healthcheck probe: an inline PING every two seconds on a fresh connection,
# which is exactly what a TCP health check does — connect, one line, read one
# line, hang up.
while :; do
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 0
        printf 'AUTH %s\r\nPING\r\n' "$PASS" >&3
        head -n 2 <&3 >/dev/null
    ) 2>/dev/null || true
    sleep 2
done
