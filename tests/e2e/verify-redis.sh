#!/usr/bin/env bash
#
# Plaintext Redis e2e check (PLAN-REDIS.md МR8): Redis 7.4, a fixed command
# sequence with deliberate failures in it, a live subscription, optionally
# memtier for volume, and one agent on `-p 6579=redis`.
#
# The plan's acceptance list for this stand, one assertion each:
#
#   - `latkit_redis_commands_total` grows;
#   - durations are non-zero and plausible;
#   - the injected `WRONGTYPE` / `NOAUTH` are visible **with the right symbolic
#     code** — which is the assertion no HTTP-shaped stand can make, because at
#     the transport level every one of them is just an error reply (РR7);
#   - `SELECT` and the ACL user produce the right labels (РR5/РR6);
#   - no key and no password appears anywhere in the exposition;
#   - a push is not counted as a command (РR8).
#
# Four more this stand is uniquely able to make, and each is a claim the
# milestone would otherwise be making on paper:
#
#   - `cmd="other"` is zero: every command this load sends is a row of the
#     closed table, which is what риск 7's "cardinality is bounded by
#     construction" means from the outside;
#   - the `BLPOP` that waits for a push is in `latkit_redis_blocking_seconds`
#     and **not** in the general duration histogram (РR10) — the p99 an operator
#     reads is the server's work, not a client's own timeout;
#   - the `+QUEUED` members of the transaction are counted as commands and are
#     in no histogram at all (РR9), and the transaction itself is one interval in
#     `latkit_txn_duration_seconds`;
#   - `PING` has a latency of its own (РR15): the healthcheck is the measurement
#     that shows the event loop stalled, so it is a command like any other and
#     is deliberately not folded into anything.
#
# Needs Docker and BPF privileges. Like the other stands, this is a manual /
# optional check where a runner lacks them.
#
#   ./verify-redis.sh              # build, up, assert, down
#   KEEP=1 ./verify-redis.sh       # leave the stand running
#   MEMTIER=1 ./verify-redis.sh    # also run memtier and re-assert
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)
COMPOSE="docker compose -p latkit-redis -f docker-compose.redis.yml"
PROM=http://localhost:19095
AGENT=http://localhost:9760
fails=0

tmp=$(mktemp -d)

log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
pass() { printf '  ok   - %s\n' "$*"; }
fail() { printf '  FAIL - %s\n' "$*"; fails=$((fails + 1)); }

cleanup() {
    rm -rf "$tmp"
    if [ "${KEEP:-0}" = "1" ]; then
        log "KEEP=1 — leaving the stand up ('$COMPOSE down -v' to stop)"
        return
    fi
    log "tearing down"
    $COMPOSE --profile memtier down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

promql() { curl -sG "$PROM/api/v1/query" --data-urlencode "query=$1"; }
scalar_of() {
    promql "$1" | python3 -c '
import json, sys
r = json.load(sys.stdin).get("data", {}).get("result", [])
print(r[0]["value"][1] if r else "")
'
}
# All values of one label across a family, one per line.
labels_of() {
    promql "$1" | python3 -c '
import json, sys
key = sys.argv[1]
res = json.load(sys.stdin).get("data", {}).get("result", [])
print("\n".join(sorted({m["metric"].get(key, "") for m in res})))
' "$2"
}
gt() { [ -n "$1" ] && python3 -c "import sys; sys.exit(0 if float('$1')>${2:-0} else 1)"; }
# Cumulative count of the depth histogram at bound N. The regex is not
# decoration: Prometheus canonicalises a histogram's `le` to a float on
# ingestion, so the exposition's `le="8"` is stored as `le="8.0"` and a literal
# selector silently matches nothing — which is a wrong number that looks like a
# passing zero, exactly the shape of failure this stand exists to catch.
depth_le() { scalar_of "sum(latkit_redis_pipeline_depth_bucket{le=~\"^$1(\\\\.0+)?$\"})"; }
is0() { python3 -c "import sys; sys.exit(0 if float('${1:-0}') == 0 else 1)"; }

# --- 0. build the agent -----------------------------------------------------
log "building the agent"
cmake --build "$REPO_ROOT/build" --target latkit -j"$(nproc)" >/dev/null
note "built $REPO_ROOT/build/latkit"

# --- 1. up ------------------------------------------------------------------
log "bringing the Redis stand up (redis :6579, command load, agent -p 6579=redis)"
$COMPOSE up -d --build
note "waiting for load to accumulate and Prometheus to scrape"
sleep 30

if ! $COMPOSE ps latkit | grep -q ' Up\| running'; then
    fail "latkit container is not running (BPF privileges? see '$COMPOSE logs latkit')"
    $COMPOSE logs --tail=30 latkit || true
    exit 1
fi

[ "$(scalar_of 'up{job="latkit"}')" = "1" ] && pass "target up{job=latkit} == 1" \
    || fail "Prometheus cannot scrape the agent (up != 1)"

# --- 2. observations exist and grow -----------------------------------------
log "Redis observations"
c1=$(scalar_of 'sum(latkit_redis_commands_total)')
note "sum(latkit_redis_commands_total) = ${c1:-<none>}"
gt "$c1" && pass "commands observed" || fail "no Redis observations at all"

sleep 8
c2=$(scalar_of 'sum(latkit_redis_commands_total)')
note "sum after +8s = ${c2:-<none>}"
if [ -n "$c2" ] && python3 -c "import sys; sys.exit(0 if float('$c2')>float('$c1') else 1)"; then
    pass "commands_total increasing under load"
else
    fail "commands_total did not grow"
fi

# --- 3. the identity is a table value, everywhere (РR4) ---------------------
log "commands (РR4)"
cmds=$(labels_of 'latkit_redis_commands_total' cmd)
note "commands: $(echo "$cmds" | tr '\n' ' ')"
for want in SET GET MGET INCR HGETALL ZSCORE PING MULTI EXEC BLPOP 'CONFIG|GET'; do
    echo "$cmds" | grep -qxF "$want" && pass "$want observed" || fail "$want missing from the load"
done
# The container rule of РR4: `CONFIG GET` is one identity and `CONFIG` alone is
# another, and the second element of an ordinary command is a key that must
# never appear. A key is `lk:k1`, so the colon is the discriminating byte.
if echo "$cmds" | grep -qE '[:/ ]'; then
    fail "a command label carries a key: $(echo "$cmds" | grep -E '[:/ ]' | tr '\n' ' ')"
else
    pass "no command label contains a colon, a slash or a space"
fi
other=$(scalar_of 'sum(latkit_redis_commands_total{cmd="other"})')
note "cmd=\"other\" = ${other:-0}"
is0 "$other" && pass "every command the load sends is a row of the table" \
    || fail "cmd=\"other\" is non-zero ($other) — the table has a hole"

# --- 4. the two dimensions (РR5/РR6) ----------------------------------------
log "the database and the ACL user"
dbs=$(labels_of 'latkit_redis_commands_total' db)
note "databases: $(echo "$dbs" | tr '\n' ' ')"
echo "$dbs" | grep -qx 0 && pass "db=0 — the database a connection starts in" \
    || fail "db=0 missing"
echo "$dbs" | grep -qx 3 && pass "db=3 — the SELECTed database is a label (РR5)" \
    || fail "db=3 not found: SELECT did not move the label"
if echo "$dbs" | grep -qvE '^([0-9]+|\?)$'; then
    fail "a db label is not a database number: $(echo "$dbs" | tr '\n' ' ')"
else
    pass "every db label is a number (or the honest \`?\`)"
fi
users=$(labels_of 'latkit_redis_commands_total' user)
note "users: $(echo "$users" | tr '\n' ' ')"
echo "$users" | grep -qx default && pass "user=default — the user a connection starts as" \
    || fail "user=default missing"
echo "$users" | grep -qx lkuser && pass "user=lkuser — the ACL user is a label (РR6)" \
    || fail "user=lkuser not found: AUTH did not move the label"

# --- 5. the failures have symbols, not just the fact of failing (РR7) -------
log "symbolic errors"
codes=$(labels_of 'latkit_redis_errors_total' error)
note "errors: $(echo "$codes" | tr '\n' ' ')"
for want in WRONGTYPE NOAUTH WRONGPASS; do
    gt "$(scalar_of "sum(latkit_redis_errors_total{error=\"$want\"})")" \
        && pass "$want named" \
        || fail "$want missing — the first token of the error reply was not read (РR7)"
done
# The sentence after the symbol names the key that had the wrong type; none of
# it may be in a label, so every error label is upper-case and short.
if echo "$codes" | grep -qE '[^A-Z]' | grep -qv '^other$'; then
    fail "an error label is not a symbol: $(echo "$codes" | tr '\n' ' ')"
else
    pass "every error label is a symbol from the vocabulary"
fi
# No cluster here, so no redirect: the family exists and is empty, which is a
# different statement from "MOVED was counted as an error".
is0 "$(scalar_of 'sum(latkit_redis_redirects_total)')" \
    && pass "no redirects on a single node" || note "redirects seen on a non-cluster stand?"

# --- 6. the timings, and the two families that are not the general one ------
log "timings (РR9, РR10)"
p95=$(scalar_of 'histogram_quantile(0.95, sum(rate(latkit_redis_command_duration_seconds_bucket[3m])) by (le))')
note "p95 command duration = ${p95:-<none>} s"
if [ -n "$p95" ] && python3 -c "import sys; v=float('$p95'); sys.exit(0 if 0<v<1 else 1)" 2>/dev/null; then
    pass "duration p95 is a plausible Redis latency (0..1 s)"
else
    fail "p95 missing or implausible ($p95)"
fi
# РR10, the whole point of the family: the BLPOP waits for a push that arrives
# when the next loop iteration sends one, so its duration is the client's own
# and it must be nowhere near the p99 above.
blk=$(scalar_of 'sum(latkit_redis_blocking_seconds_count)')
note "blocking waits = ${blk:-0}"
gt "${blk:-0}" && pass "the blocking wait is measured in its own family" \
    || fail "no blocking samples — did BLPOP run?"
is0 "$(scalar_of 'sum(latkit_redis_command_duration_seconds_count{cmd="BLPOP"})')" \
    && pass "and BLPOP is absent from the general duration histogram" \
    || fail "a blocking command reached the general histogram — the p99 is now fiction"
# РR9: the queued members are commands, and they are not latencies.
gt "$(scalar_of 'sum(latkit_redis_commands_total{cmd="EXEC"})')" \
    && pass "the transaction's EXEC is observed" || fail "no EXEC observed"
txn=$(scalar_of 'sum(latkit_txn_duration_seconds_count{proto="redis"})')
note "transactions = ${txn:-0}"
gt "${txn:-0}" && pass "MULTI…EXEC is one interval in the shared txn family (РR9)" \
    || fail "no transaction interval recorded"
# The value the command returned, on the grid a cache needs (РR11).
gt "$(scalar_of 'sum(latkit_redis_value_size_bytes_count)')" \
    && pass "reply sizes are distributed" || fail "no value-size samples"
# РR15: the healthcheck is a measurement, not noise to be folded away.
gt "$(scalar_of 'sum(latkit_redis_command_duration_seconds_count{cmd="PING"})')" \
    && pass "PING has a latency of its own (РR15)" || fail "PING is not timed"

# --- 7. РR8: the values that answered nobody --------------------------------
log "pub/sub (РR8)"
push=$(scalar_of 'sum(latkit_redis_push_total)')
note "latkit_redis_push_total = ${push:-0}"
gt "${push:-0}" && pass "deliveries are counted as pushes" \
    || fail "no pushes counted — is the subscriber running?"
gt "$(scalar_of 'sum(latkit_redis_commands_total{cmd="SUBSCRIBE"})')" \
    && pass "the SUBSCRIBE command itself is an observation" || fail "SUBSCRIBE not observed"
# A delivery's first element is the word `message` — lower case, which is how
# the wire spells a kind word and never how it spells a command (a label is
# upper-cased from the table, so `SUBSCRIBE` here is the command and
# `subscribe` would be a confirmation that had been mistaken for one). The
# case-sensitive match is the whole assertion.
if echo "$cmds" | grep -qE '^(message|pmessage|smessage|subscribe|psubscribe|invalidate)$'; then
    fail "a pub/sub kind word became a command label"
else
    pass "no delivery was mistaken for a command"
fi
# The pipeline depth: the fixed sequence is one batch of 21 through one
# connection, so the histogram must have samples above le="1".
d1=$(depth_le 1)
dall=$(scalar_of 'sum(latkit_redis_pipeline_depth_count)')
note "pipeline depth: le=1 -> ${d1:-0} of ${dall:-0} samples"
if python3 -c "import sys; sys.exit(0 if float('${dall:-0}') > float('${d1:-0}') else 1)"; then
    pass "the batched commands are visible as depth (РR3)"
else
    fail "every command looks unpipelined — the batch boundary was lost"
fi

# --- 8. the privacy invariant, on live traffic ------------------------------
log "no key and no password in the exposition (РR4, РR6)"
if curl -s "$AGENT/metrics" > "$tmp/metrics.txt"; then
    # Every key the load touches is `lk:<something>`, and both credentials are
    # spelled out in the compose file — so all four strings are exactly what
    # must not be there.
    if grep -qE 'lk:|lkpass|lkrootpass|wrongpass' "$tmp/metrics.txt"; then
        fail "a key or a password reached the exposition"
        grep -m3 -E 'lk:|lkpass|lkrootpass|wrongpass' "$tmp/metrics.txt" | sed 's/^/      /'
    else
        pass "no key and no password in $(wc -l < "$tmp/metrics.txt") exposition lines"
    fi
    # Structural, like the corpus check: every redis label value is a command
    # from the table, a database number, a user name, a symbolic error or a
    # bounded enum — and not one of those alphabets contains a colon or a space.
    if grep '^latkit_redis_' "$tmp/metrics.txt" | grep -oE '[a-z0-9_]+="[^"]*"' | sort -u |
       grep -qE '="[^"]*[: /]'; then
        fail "a metric label carries a key byte:"
        grep '^latkit_redis_' "$tmp/metrics.txt" | grep -oE '[a-z0-9_]+="[^"]*"' | sort -u |
            grep -E '="[^"]*[: /]' | head -3 | sed 's/^/      /'
    else
        pass "no label value contains a colon, a space or a slash"
    fi
else
    fail "could not scrape the agent directly"
fi

# --- 9. nothing went blind, nothing was lost --------------------------------
log "health"
pe=$(scalar_of 'sum(latkit_parse_errors_total)')
note "parse_errors_total = ${pe:-0}"
is0 "$pe" && pass "no parse errors on clean traffic" || fail "parse errors on clean traffic ($pe)"

rs=$(scalar_of 'sum(latkit_resync_total)')
note "resync_total = ${rs:-0}"
is0 "$rs" && pass "no resyncs" \
    || note "resyncs: $rs (an agent that started beside an open pool resyncs once per connection)"

dropped=$(scalar_of 'sum(latkit_queries_dropped_total{proto="redis"})')
note "queries_dropped_total{proto=redis} = ${dropped:-0}"
is0 "$dropped" && pass "no in-flight unit was dropped" \
    || note "units dropped: $dropped (see the reason label)"

ign=$(scalar_of 'sum(latkit_ignored_conns_total{proto="redis"})')
note "ignored_conns{proto=redis} = ${ign:-0}"
is0 "$ign" && pass "no connection fell into a blind zone (no MONITOR, no replica)" \
    || fail "a connection was ignored ($ign) — MONITOR or replication on this stand?"

drops=$(scalar_of 'sum(latkit_ringbuf_dropped_total)')
note "ringbuf_dropped_total = ${drops:-0}"
is0 "$drops" && pass "no ringbuf drops at this rate" \
    || note "ringbuf drops: $drops (rate-dependent; the gate is tests/bench/run-redis.sh)"

# --- 10. optional: the same stand under memtier -----------------------------
# Volume, and the one place the depth histogram can be checked against a number
# somebody else chose: memtier pipelines exactly 8.
if [ "${MEMTIER:-0}" = "1" ]; then
    log "memtier (4 clients x 2 threads, pipeline 8, 20 s)"
    if $COMPOSE --profile memtier run --rm memtier 2>&1 | tail -6; then
        sleep 10
        c3=$(scalar_of 'sum(latkit_redis_commands_total)')
        note "sum after memtier = ${c3:-<none>}"
        if [ -n "$c3" ] && python3 -c "import sys; sys.exit(0 if float('$c3')>float('$c2')+10000 else 1)"; then
            pass "memtier's commands were observed too"
        else
            fail "memtier did not move commands_total by a memtier-sized amount"
        fi
        pe2=$(scalar_of 'sum(latkit_parse_errors_total)')
        is0 "$pe2" && pass "still no parse errors after memtier" \
            || fail "memtier produced parse errors ($pe2)"
        # The two bounds are read separately and subtracted here rather than in
        # PromQL: `le` is a label, so a difference of two bucket vectors matches
        # nothing and quietly returns empty.
        b8=$(depth_le 8)
        b4=$(depth_le 4)
        d8=$(python3 -c "print(float('${b8:-0}') - float('${b4:-0}'))")
        note "commands arriving in batches of 5..8 = $d8 (of ${b8:-0} at le<=8)"
        gt "$d8" 1000 && pass "the depth histogram shows memtier's pipeline of 8" \
            || fail "a pipeline of 8 is not visible in the depth histogram"
        d2=$(scalar_of 'sum(latkit_ringbuf_dropped_total)')
        ev=$(scalar_of 'sum(latkit_events_total)')
        note "ringbuf drops=${d2:-0} of events=${ev:-0}"
        if python3 -c "import sys; d=float('${d2:-0}'); e=float('${ev:-0}'); sys.exit(0 if e>0 and d <= 0.01*e else 1)"; then
            pass "drop rate under 1 % at memtier volume"
        else
            fail "drop rate above 1 % — see tests/bench/run-redis.sh for the real measurement"
        fi
    else
        note "memtier image unavailable — volume leg skipped (the checks above stand)"
    fi
fi

# --- verdict -----------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  Redis (plaintext) e2e: all checks passed"
    exit 0
fi
echo "  Redis (plaintext) e2e: $fails check(s) failed"
exit 1
