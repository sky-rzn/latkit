#!/bin/sh
# МR3 acceptance (PLAN-REDIS.md): the --queries view over the МR0 corpus must
# yield the expected observations per scenario — the identity (РR4), the
# database (РR5) and the ACL user (РR6) — with parse_errors == 0 on every clean
# trace.
#
#   redis_queries_traces.sh <lkt_queries> <tests/traces/redis dir> [test_redis_cmd]
#
# The same shape as s3_queries_traces.sh and for the same reason: the traces are
# real recorded sessions against Redis 7.4 and Valkey 8, so their timings, ports
# and connection ids differ per capture and only what an observation is
# *supposed to report* can be pinned.
#
# Three of the checks are corpus-wide rather than per scenario, because they are
# the claims the whole milestone rests on:
#
#   1. **every `cmd` is a table value.** With the third argument the check is
#      exact — the set of labels 93 traces produce is compared against the
#      compiled table itself (test_redis_cmd --dump). Without it, the shape rule
#      below still refuses anything that could be a key.
#   2. **no key is ever a label.** The corpus is full of `lk:*` keys, channel
#      names and stream ids; not one of them may appear in any label of any
#      observation. This is the same invariant test_redis_cmd.c states over
#      random input, checked here against traffic a real server answered.
#   3. **no password is anywhere in the view.** `lkpass`, `lkrootpass` and
#      `wrongpass` are planted in the corpus on purpose (clients/raw.py); the
#      whole surface is greppable and none of them may be in it. The other
#      surfaces are tests/replay/redis_privacy.sh.
set -u

LKT="$1"
DIR="$2"
TABLE="${3:-}"
fails=0
seen_cmds=$(mktemp)
trap 'rm -f "$seen_cmds"' EXIT

# The planted credentials (tests/traces/redis/clients/raw.py).
SECRETS='lkpass|lkrootpass|wrongpass'

fail() {
    echo "FAIL $trace: $1" >&2
    fails=$((fails + 1))
}

has() {
    printf '%s\n' "$out" | grep -Eq "$1" || fail "expected /$1/"
}

lacks() {
    printf '%s\n' "$out" | grep -Eq "$1" && fail "unexpected /$1/"
}

# nobs <n> — exactly n observation lines
nobs() {
    got=$(printf '%s\n' "$out" | grep -c '^redis ')
    [ "$got" = "$1" ] || fail "expected $1 observations, got $got"
}

# ncmd <cmd> <n> — the identity appears n times
ncmd() {
    got=$(printf '%s\n' "$out" | grep -c " cmd=$1 ")
    [ "$got" = "$2" ] || fail "expected $2 × $1, got $got"
}

for trace in "$DIR"/*/*.lkt; do
    base=$(basename "$trace" .lkt)
    stand=$(basename "$(dirname "$trace")")
    out=$("$LKT" --proto redis "$trace" 2>&1)
    [ $? -eq 0 ] || fail "lkt_queries exited nonzero"

    lacks "REPLAY FAILED"
    lacks " unknown=[1-9]"

    # --- РR4, corpus-wide: the identity is a name, never an argument ------
    # A command name is upper-case with `_`, `-` and `.`; a container identity
    # is two of them joined by `|`. A Redis key looks like `lk:k1` or
    # `user:42:session`, a channel like `lk:chan`, and none of them can pass
    # this — which is what "the cardinality of `cmd` is bounded by construction"
    # looks like from the outside.
    bad=$(printf '%s\n' "$out" | sed -n 's/^redis .* cmd=\([^ ]*\) .*/\1/p' |
        grep -Ev '^([A-Z][A-Z0-9_.-]*(\|([A-Z][A-Z0-9_.-]*|other))?|other)$' | head -1)
    [ -n "$bad" ] && fail "cmd is not a table value: '$bad'"
    printf '%s\n' "$out" | sed -n 's/^redis .* cmd=\([^ ]*\) .*/\1/p' >> "$seen_cmds"

    # --- РR5/РR6, corpus-wide: the labels are a number and a name ---------
    bad=$(printf '%s\n' "$out" | sed -n 's/^redis .* db=\([^ ]*\) .*/\1/p' |
        grep -Ev '^([0-9]+|\?|-)$' | head -1)
    [ -n "$bad" ] && fail "db label is not a database number: '$bad'"
    bad=$(printf '%s\n' "$out" | sed -n 's/^redis .* user=\([^ ]*\) .*/\1/p' |
        grep -Ev '^([A-Za-z0-9._-]+|\?)$' | head -1)
    [ -n "$bad" ] && fail "user label is not a user name: '$bad'"

    # --- privacy: not a key, not a password, anywhere in the view ---------
    hit=$(printf '%s\n' "$out" | grep -Eo 'cmd=[^ ]*(lk:|:)[^ ]*' | head -1)
    [ -n "$hit" ] && fail "a key reached a label: '$hit'"
    hit=$(printf '%s\n' "$out" | grep -Eo "$SECRETS" | head -1)
    [ -n "$hit" ] && fail "a password appears in the --queries view: '$hit'"

    case "$stand/$base" in
    # The two traces the server itself answers with a protocol error, and the
    # only two where a parse error is the correct reading of the input.
    redis/garbage | redis/torn-bulk) has " parse_errors=[1-9]" ;;
    *) has " parse_errors=0 " ;;
    esac

    case "$stand/$base" in
    # --- РR4: the identity, from the twenty commands an application runs --
    redis/basic | valkey/basic)
        nobs 20
        has '^redis .* cmd=SET .* db=0 user=default '
        has '^redis .* cmd=HGETALL '
        has '^redis .* cmd=ZSCORE '
        has '^redis .* cmd=PING '
        # The key of every one of them is on the wire and in no label.
        lacks 'cmd=lk'
        ;;
    # --- РR4: the container rule, the only place argv[1] is read ----------
    redis/containers | valkey/containers)
        nobs 34
        has '^redis .* cmd=CONFIG\|GET '
        has '^redis .* cmd=CLIENT\|NO-EVICT '
        has '^redis .* cmd=XINFO\|STREAM '
        has '^redis .* cmd=COMMAND\|DOCS '
        # A container called bare is an arity error on the server and a real
        # observation here; an unknown subcommand is `CONFIG|other` and not a
        # new series (notes-redisproto.md §"The table").
        has '^redis .* cmd=CONFIG '
        has '^redis .* cmd=CONFIG\|other '
        # `DEBUG` declares no subcommands, so `DEBUG JMAP` is one identity.
        ncmd DEBUG 1
        ;;
    # --- РR5: the database is connection state ----------------------------
    redis/select-db | valkey/select-db)
        nobs 14
        # `SELECT 3` is itself observed in the database it was issued *from*,
        # and the command after it in the new one.
        has '^redis .* cmd=SELECT .* db=0 '
        has '^redis .* cmd=SET .* db=3 '
        has '^redis .* cmd=DBSIZE .* db=15 '
        # `SELECT 16` and `SELECT abc` are errors: the connection stays in 15,
        # and the two commands after them say so.
        has '^redis .* cmd=SWAPDB .* db=15 '
        # `RESET` goes back to 0, and `MOVE`/`COPY … DB n` name another database
        # in an argument without moving the connection.
        has '^redis .* cmd=MOVE .* db=0 '
        has '^redis .* cmd=COPY .* db=0 '
        ;;
    # --- РR6: every form a user name arrives in ---------------------------
    redis/auth-forms | valkey/auth-forms)
        nobs 11
        # `AUTH lkuser lkpass` → the next command is lkuser's.
        has '^redis .* cmd=ACL\|WHOAMI .* user=lkuser '
        # `RESET` → back to `default`.
        has '^redis .* cmd=ACL\|WHOAMI .* user=default '
        # `HELLO 3 AUTH lkuser lkpass SETNAME lkapp` names the same user.
        has '^redis .* cmd=CLIENT\|GETNAME .* user=lkuser '
        # ... and `-WRONGPASS` moves nothing: four observations under lkuser and
        # no more, because the trace's last two
        # connections authenticate badly (`-WRONGPASS`, once through `AUTH` and
        # once through `HELLO … AUTH`) and stay `default` throughout.
        [ "$(printf '%s\n' "$out" | grep -c 'user=lkuser')" = 4 ] ||
            fail "a refused AUTH moved the user label"
        ;;
    redis/acl-errors)
        # The same rule under an ACL user who is allowed almost nothing: the
        # `-NOPERM` answers do not change who is asking, and neither does the
        # `-NOAUTH` on the second connection.
        has '^redis .* cmd=GET .* user=lkreader '
        has '^redis .* cmd=ACL\|WHOAMI .* user=lkreader '
        ;;
    libs/py-auth)
        # What a real client does: redis-py authenticates, sets its name, and
        # `SELECT`s — so the label moves twice on one connection, once per rule.
        has '^redis .* cmd=CLIENT\|SETINFO .* db=0 user=lkuser '
        has '^redis .* cmd=SET .* db=3 user=lkuser '
        ;;
    # --- РR5/РR6: a connection whose beginning we did not see -------------
    redis/midstream)
        # `db="0"` here would be indistinguishable from a connection that really
        # is in database 0. The client `SELECT`ed 7 and authenticated before the
        # agent attached, and the only honest answer is that we do not know.
        nobs 2
        has '^redis .* db=\? user=\? '
        lacks 'db=[0-9]'
        ;;
    # --- РR4: what the table does not know, and what it must not invent ---
    redis/errors | valkey/errors)
        nobs 17
        # One deliberate unknown command in the trace, and exactly one `other`.
        ncmd other 1
        has '^redis .* cmd=EVALSHA '
        has '^redis .* cmd=XGROUP\|CREATE '
        ;;
    # --- an inline command is a command, and is classified like one -------
    redis/inline-cmds | valkey/inline-cmds)
        nobs 8
        ncmd PING 4
        has '^redis .* cmd=ECHO '
        has '^redis .* cmd=INFO '
        ;;
    # --- pub/sub: the confirmations and the deliveries are not commands ---
    redis/pubsub)
        nobs 12
        ncmd SUBSCRIBE 2
        ncmd UNSUBSCRIBE 1
        ncmd SSUBSCRIBE 1
        has ' push=5 ' # five deliveries, and not one of them an observation
        ;;
    redis/pubsub3)
        # RESP3: the confirmations arrive as pushes and ordinary commands keep
        # working while subscribed, so the queue and the push stream interleave.
        has '^redis .* cmd=SUBSCRIBE '
        has '^redis .* cmd=GET '
        ;;
    # --- the cluster: MOVED and ASK are answers to real commands ----------
    cluster/moved)
        nobs 9
        has '^redis .* cmd=CLUSTER\|SHARDS '
        has '^redis .* cmd=MGET '
        ;;
    # --- the shapes that are not a request/response stream (РR14) ---------
    redis/monitor | server/monitor)
        # The `MONITOR` connection is ignored from its command on; the other
        # connections in the trace are observed normally.
        has ' monitor=1$'
        ;;
    redis/replica | server/replication)
        has ' repl=[1-9] '
        ;;
    # --- pipelining does not change an identity ---------------------------
    redis/pipeline100)
        nobs 200
        ncmd SET 100
        ncmd GET 100
        ;;
    esac
done

# --- the closed set, over the whole corpus ---------------------------------
# The strongest form of the claim, and the only one that does not restate the
# regex above: every label 93 traces produced is an entry of the compiled table.
if [ -n "$TABLE" ]; then
    trace="corpus"
    "$TABLE" --dump | cut -d' ' -f1 | LC_ALL=C sort -u > "$seen_cmds.table"
    LC_ALL=C sort -u "$seen_cmds" > "$seen_cmds.seen"
    bad=$(LC_ALL=C comm -23 "$seen_cmds.seen" "$seen_cmds.table" | head -3 | tr '\n' ' ')
    rm -f "$seen_cmds.table" "$seen_cmds.seen"
    [ -z "$bad" ] || fail "labels outside the table: $bad"
    n=$(sort -u "$seen_cmds" | wc -l)
    [ "$n" -gt 60 ] || fail "only $n distinct commands in the corpus — did the view break?"
fi

# --- РR6: the switch that turns the dimension off --------------------------
trace="auth-forms(--redis-user off)"
out=$("$LKT" --proto redis --redis-user off "$DIR/redis/auth-forms.lkt" 2>&1)
lacks 'user=lkuser'
has 'user=-'
has 'cmd=ACL\|WHOAMI'

if [ "$fails" -eq 0 ]; then
    echo "ok   - redis --queries expectations over the МR0 corpus"
    exit 0
fi
echo "FAIL - $fails expectation(s) unmet" >&2
exit 1
