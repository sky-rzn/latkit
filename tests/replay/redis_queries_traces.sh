#!/bin/sh
# МR3, МR4 and МR5 acceptance (PLAN-REDIS.md): the --queries view over the МR0
# corpus must yield the expected observations per scenario — the identity (РR4),
# the database (РR5) and the ACL user (РR6), and then what the *outcome* of each
# one was: the symbolic error and the redirect that is not one (РR7), the
# transaction interval (РR9), the blocking family (РR10) — with parse_errors == 0
# on every clean trace. The last section (`--metrics`) runs the real aggregator
# over the same traces and checks the `latkit_redis_*` families of РR11: which
# family each of those facts ends up in, and which it does not.
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

# nmatch <n> <regex> — the view holds exactly n lines matching
nmatch() {
    got=$(printf '%s\n' "$out" | grep -Ec "$2")
    [ "$got" = "$1" ] || fail "expected $1 × /$2/, got $got"
}

# The two flags МR4 sets, spelled out once: an observation's flags word is
# printed in hex, so a bit is checked with the arithmetic and not with a regex
# over 0x1004 and its neighbours.
#
#   0x0001 LK_QO_ERROR      the server refused, and it was its own failure
#   0x0100 LK_QO_CLIENT_ERR ... or a cluster redirect, which is not one (РR7)
#   0x1000 LK_QO_QUEUED     `+QUEUED`: no duration (РR9)
#   0x2000 LK_QO_BLOCKING   the client chose the wait (РR10)
#
# nflag <bit> <n> [cmd] — exactly n observations (of `cmd`, if given) carry it
nflag() {
    got=0
    for f in $(printf '%s\n' "$out" | grep -E "^redis ${3:+.* cmd=$3 }" |
        sed -n 's/.* flags=0x\([0-9a-f]*\)$/\1/p'); do
        [ $((0x$f & $1)) -ne 0 ] && got=$((got + 1))
    done
    [ "$got" = "$2" ] || fail "expected $2 observations with flag $1${3:+ on $3}, got $got"
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
        # ... and the two symbols an ACL produces (РR7). The `-NOPERM` sentence
        # quotes the command and the rule that refused it; neither is here.
        has '^redis .* err=NOPERM '
        has '^redis .* err=NOAUTH '
        has ' redirects=0$'
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
    # --- РR7: ... and the symbolic name of every way it went wrong --------
    redis/errors | valkey/errors)
        nobs 17
        # One deliberate unknown command in the trace, and exactly one `other`.
        ncmd other 1
        has '^redis .* cmd=EVALSHA '
        has '^redis .* cmd=XGROUP\|CREATE '
        # The failure is named by its symbol, not by the sentence after it:
        # `WRONGTYPE`, not "Operation against a key holding…" with a key in it.
        has '^redis .* cmd=LPUSH .* err=WRONGTYPE '
        has '^redis .* cmd=EVALSHA .* err=NOSCRIPT '
        has '^redis .* cmd=AUTH .* err=WRONGPASS '
        has '^redis .* cmd=EXEC .* err=ERR '        # `EXEC without MULTI`
        has '^redis .* cmd=HELLO .* err=NOPROTO '   # `HELLO 4`
        has '^redis .* cmd=SELECT .* err=ERR '      # `DB index is out of range`
        # 16 of the 17 commands in the trace fail, and every one of them is an
        # error of the server's own making — no redirects here.
        nflag 0x1 16
        nflag 0x100 0
        has ' errors_sql=16 '
        has ' redirects=0$'
        # Not one byte of a message reached the view: a `-WRONGTYPE` sentence
        # names the key, a `-NOPERM` names the command and the user's rule.
        lacks 'err=[^ ]*[a-z]'
        ;;
    # --- РR7: a script's own error symbol is not the server's -------------
    redis/eval-scripts)
        # `redis.error_reply('CUSTOMERR …')` is a symbol a client invented, and
        # a client may not name a series: it folds to `other` like an unknown
        # command does, and the fold is what bounds the label.
        has '^redis .* err=other '
        lacks 'err=CUSTOMERR'
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
    # --- РR7: ... and a redirect is not a failure -------------------------
    cluster/moved)
        nobs 9
        has '^redis .* cmd=CLUSTER\|SHARDS '
        has '^redis .* cmd=MGET '
        # The МR4 acceptance, in three lines: `MOVED` is in the redirects and in
        # no error counter, and the one real failure on the trace — a
        # `CROSSSLOT` `MGET`, which is the client's mistake and the server's
        # refusal both — is in the errors and not in the redirects.
        has '^redis .* err=MOVED '
        has '^redis .* err=CROSSSLOT '
        has ' redirects=3$'
        has ' errors_sql=1 '
        nflag 0x100 3 # every redirect carries the client-error flag ...
        nflag 0x1 1   # ... and not one of them the error one
        ;;
    cluster/ask)
        # `-ASK` needs a slot in flight and the corpus makes one: the owner
        # answers `-ASK` for a key missing from a migrating slot, the target
        # answers `-MOVED` until an `ASKING` precedes the command, and `-MOVED`
        # again for the very next one. Five redirects of two kinds, no errors.
        has '^redis .* err=ASK '
        has '^redis .* err=MOVED '
        has ' redirects=5$'
        has ' errors_sql=0 '
        # `ASKING` itself is an ordinary command with an ordinary `+OK`.
        has '^redis .* cmd=ASKING .* err=- '
        ;;
    # --- the shapes that are not a request/response stream (РR14) ---------
    redis/monitor | server/monitor)
        # The `MONITOR` connection is ignored from its command on; the other
        # connections in the trace are observed normally.
        has ' monitor=1 '
        ;;
    redis/replica | server/replication)
        has ' repl=[1-9] '
        ;;
    # --- РR9: the transaction, in all its endings -------------------------
    redis/multi | valkey/multi)
        # The МR4 acceptance. Seven transactions are opened on the trace and the
        # last is abandoned by the closing connection, so six intervals are
        # reported. A transaction whose `MULTI` we saw and whose end we never did
        # is not reported at all — Р19, and the reason the abandoned one is
        # missing rather than truncated at the close.
        nmatch 6 '^txn '
        # `+QUEUED` is not a latency: every command between a `MULTI` and its
        # ending carries the flag — nine of them, the abandoned transaction's
        # one included — and the commands that bracket them do not.
        nflag 0x1000 9
        nflag 0x1000 0 MULTI
        nflag 0x1000 0 EXEC
        nflag 0x1000 0 DISCARD
        # The queue-time error is answered *instead* of `+QUEUED` and stays an
        # ordinary error with an ordinary duration; the `EXEC` after it is
        # `-EXECABORT`.
        has '^redis .* cmd=EXEC .* err=EXECABORT '
        # A nested `MULTI` is refused, and what happens next is where the two
        # servers differ (measured): Redis 7.4 keeps the first transaction and
        # answers the following `EXEC` with `*0`, Valkey 8 treats the refusal as
        # a queue-time error and answers `-EXECABORT`. Both are read correctly
        # because the verdict comes from the reply and not from a model of what
        # the server ought to have done — committed for one, aborted for the
        # other (notes-redisproto.md §"Transactions").
        has '^redis .* cmd=MULTI .* err=ERR '
        case "$stand" in
        redis) nmatch 4 '^txn .* final=I$'; nmatch 2 '^txn .* final=E$' ;;
        *) nmatch 3 '^txn .* final=I$'; nmatch 3 '^txn .* final=E$' ;;
        esac
        ;;
    redis/watch-abort)
        # A broken `WATCH` answers `*-1` — a **null, not an error** — and the
        # transaction is aborted all the same. Reading only the error bit here
        # would report a rolled-back transaction as a committed one.
        nmatch 1 '^txn .* final=E$'
        nflag 0x1 0
        ;;
    libs/py-multi | libs/go-multi | libs/node-multi | libs/java-multi | libs/php-multi)
        # What the client libraries actually send — every one of them pipelines
        # the whole transaction, so the `+QUEUED` replies arrive in a batch and
        # the interval spans it.
        has '^txn '
        ;;
    # --- РR10: the wait the client chose ----------------------------------
    redis/blocking | valkey/blocking)
        nobs 8
        # `BLPOP` twice (a timeout and a wake-up), `XREAD BLOCK`, `BLMPOP`,
        # `WAIT`: five observations whose duration is not the server's, and
        # three ordinary ones beside them on the same trace.
        nflag 0x2000 5
        # The refinement of РR10, and the whole reason an argument is read at
        # all: the *same* command is blocking or not depending on a keyword.
        # `XREAD COUNT 10 STREAMS s 0` returns at once; `XREAD BLOCK 300` does
        # not, and the server's own flag cannot tell them apart.
        nmatch 2 '^redis .* cmd=XREAD '
        nflag 0x2000 1 XREAD
        # `RPUSH`, `XADD` and the immediate `XREAD` are ordinary commands.
        nflag 0x2000 0 RPUSH
        nflag 0x2000 0 XADD
        ;;
    libs/py-block | libs/go-block)
        # Two `BLPOP`s per client scenario, one timing out and one woken by a
        # push from another connection: both are the client's own wait.
        nflag 0x2000 2 BLPOP
        ;;
    libs/java-block)
        # Lettuce's scenario is one `BLPOP` behind its `HELLO`/`CLIENT SETINFO`
        # handshake, and the flag belongs to it and to nothing else on the
        # connection.
        nflag 0x2000 1 BLPOP
        nflag 0x2000 1
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

# --- МR5 (РR11): and what all of it does to the families -------------------
# The other half of the acceptance, one level down: an identity, a label and a
# flag are only worth deriving if something downstream reports them, so these
# checks run the real aggregator over the same traces and read the real
# Prometheus exposition. Everything above is about what an observation *says*;
# this is about which family says it, and every assertion below is a number that
# would be plausible in the wrong place.
#
# hist_count <metric> — the observations that reached a histogram
hist_count() {
    printf '%s\n' "$out" | awk -v m="$1" '
        index($1, m "_count{") == 1 { n += $2 } END { print n + 0 }'
}

# ctotal <metric> — the sum of a counter family's series
ctotal() {
    printf '%s\n' "$out" | awk -v m="$1" '
        index($1, m "{") == 1 { n += $2 } END { print n + 0 }'
}

trace="multi(--metrics)"
out=$("$LKT" --proto redis --quiet --metrics "$DIR/redis/multi.lkt" 2>&1)
# 26 commands, all counted — including the nine answered `+QUEUED`, which are
# commands that happened and would be missing from anything compared against the
# server's own `INFO commandstats`.
[ "$(ctotal latkit_redis_commands_total)" = 26 ] ||
    fail "expected 26 in latkit_redis_commands_total, got $(ctotal latkit_redis_commands_total)"
# ... and 17 timed: a transaction's commands are written down in microseconds,
# and in the same histogram as real work they drag every percentile down (РR9).
[ "$(hist_count latkit_redis_command_duration_seconds)" = 17 ] ||
    fail 'a +QUEUED unit reached the duration histogram'
# A `+QUEUED` is not a value, either: those nine bytes are a receipt, and the
# value the command returns arrives inside the array the `EXEC` is answered with.
[ "$(hist_count latkit_redis_value_size_bytes)" = 17 ] ||
    fail 'a +QUEUED reply was counted as a value size'
# The interval that *does* mean something is the transaction's, and it lands in
# the family every database protocol here already feeds — six of them, one per
# transaction that ended (РR9). One family, one HELP block, keyed by proto: a
# second name for the same measurement would have been the worse answer.
[ "$(hist_count latkit_txn_duration_seconds)" = 6 ] ||
    fail "expected 6 transactions in latkit_txn_duration_seconds"
nmatch 1 '^# TYPE latkit_txn_duration_seconds histogram$'
has 'latkit_txn_duration_seconds_count\{db="0",user="default",proto="redis",status="aborted"\} 2'
# The database families are not borrowed for any of it (РR11): a command has no
# rows, no SQLSTATE and no statement text, so no latkit_query_* series is
# printed and no redis observation appears on the `kind` axis. (The two
# label-free `latkit_queries_*_total` counters are in every exposition and
# always have been — РH15 is about families *appearing*, not about those.)
lacks '^latkit_query_'
lacks 'proto="redis",kind='
lacks '^latkit_redis_(rows|ttfb|first_row|upload)'
# ... and no family a cache has no use for was invented for it either.
lacks 'latkit_redis_[a-z_]*\{[^}]*(host|bucket|route|method|status)='

trace="blocking(--metrics)"
out=$("$LKT" --proto redis --quiet --metrics "$DIR/redis/blocking.lkt" 2>&1)
# The general histogram does not shift: of eight commands, the five that waited
# on an event the client named are counted, timed in a family of their own, and
# absent from this one. One 30-second `BLPOP` in the same series as `GET` decides
# the p99 of the whole server (РR10).
[ "$(ctotal latkit_redis_commands_total)" = 8 ] ||
    fail "expected 8 in latkit_redis_commands_total"
[ "$(hist_count latkit_redis_command_duration_seconds)" = 3 ] ||
    fail "a blocking command reached the general duration histogram"
[ "$(hist_count latkit_redis_blocking_seconds)" = 5 ] ||
    fail "expected 5 waits in latkit_redis_blocking_seconds"
# `XREAD` is the one command that is both, and the bit follows the arguments
# rather than the name (РR10): with `BLOCK` it waits, without it does not.
has 'latkit_redis_blocking_seconds_count\{cmd="XREAD",[^}]*\} 1'
has 'latkit_redis_command_duration_seconds_count\{cmd="XREAD",[^}]*\} 1'

trace="moved(--metrics)"
out=$("$LKT" --proto redis --quiet --metrics "$DIR/cluster/moved.lkt" 2>&1)
# The redirect has a counter and is in no error family; the one real cluster
# error is the other way round (РR7). A resharding cluster answers `-MOVED`
# continuously, and in errors_total it would be permanently red.
has 'latkit_redis_redirects_total\{kind="moved",proto="redis"\} 3'
[ "$(ctotal latkit_redis_errors_total)" = 1 ] ||
    fail "a redirect was counted as an error"
has 'latkit_redis_errors_total\{error="CROSSSLOT",'

trace="pipeline-depths(--metrics)"
out=$("$LKT" --proto redis --quiet --metrics "$DIR/redis/pipeline-depths.lkt" 2>&1)
# Batches of 1, 2, 3, 10 and 50 commands, sampled per command: 66 samples, and
# the cumulative octaves are the batch sizes back again (РR3). `le="1"` — the
# one bucket an operator reads first — holds exactly the command that travelled
# alone.
[ "$(hist_count latkit_redis_pipeline_depth)" = 66 ] ||
    fail "expected 66 pipeline-depth samples"
has 'latkit_redis_pipeline_depth_bucket\{proto="redis",le="1"\} 1'
has 'latkit_redis_pipeline_depth_bucket\{proto="redis",le="4"\} 6'
has 'latkit_redis_pipeline_depth_bucket\{proto="redis",le="16"\} 16'
has 'latkit_redis_pipeline_depth_bucket\{proto="redis",le="64"\} 66'

trace="bigvalue(--metrics)"
out=$("$LKT" --proto redis --quiet --metrics "$DIR/redis/bigvalue.lkt" 2>&1)
# The value grid is the redis one, 8 B … 8 MiB (hist.h): a 1 MB reply is in a
# cell of its own, where on the HTTP grid's 64 B floor half of a real Redis's
# values would share bucket zero.
has 'latkit_redis_value_size_bytes_bucket\{cmd="GET",[^}]*le="8"\}'
has 'latkit_redis_value_size_bytes_bucket\{cmd="GET",[^}]*le="8388608"\}'
lacks 'latkit_redis_value_size_bytes_bucket\{[^}]*le="1073741824"\}'

trace="select-db(--metrics)"
out=$("$LKT" --proto redis --quiet --metrics "$DIR/redis/select-db.lkt" 2>&1)
# The two dimension slots hold what РR5/РR6 put in them, in the families and not
# only in the view: a database number and an ACL user, and `?` where the
# connection was joined mid-stream rather than a `0` that would be a guess.
has 'latkit_redis_commands_total\{cmd="SELECT",db="[0-9]+",user="default",proto="redis",code="ok"\}'
has 'latkit_redis_commands_total\{[^}]*db="3",'

# --- corpus-wide, over the families this time ------------------------------
# Every label the aggregator prints for a redis port is one of the four keys of
# the profile plus the outcome — nothing that could be a key, a value or an
# argument. The privacy invariant of МR3, restated where it ends up in
# Prometheus (the same check s3_queries_traces.sh runs over its own nouns).
trace="corpus(--metrics)"
out=$("$LKT" --proto redis --quiet --metrics "$DIR"/*/*.lkt 2>&1)
bad=$(printf '%s\n' "$out" | sed -n 's/^latkit_redis_[a-z_]*[{]\([^}]*\)[}].*/\1/p' |
    tr ',' '\n' | sed -n 's/^\([a-z_0-9]*\)=.*/\1/p' | sort -u |
    grep -Ev '^(cmd|db|user|proto|code|error|kind|direction|le)$' | head -3 | tr '\n' ' ')
[ -z "$bad" ] || fail "unexpected label keys in the redis families: $bad"
bad=$(printf '%s\n' "$out" | grep -E "^latkit_redis" | grep -E "$SECRETS" | head -1)
[ -z "$bad" ] || fail "a planted password reached a metric label: $bad"
bad=$(printf '%s\n' "$out" | sed -n 's/^latkit_redis_[a-z_]*[{]cmd="\([^"]*\)".*/\1/p' |
    grep -Ev '^([A-Z][A-Z0-9_.-]*(\|([A-Z][A-Z0-9_.-]*|other))?|other)$' | head -1)
[ -z "$bad" ] || fail "cmd label is not a table value: '$bad'"
# No series printed twice: a duplicate label set is a rejected scrape, not a
# cosmetic defect, and it is exactly what dropping a key from a family's
# identity would produce.
dup=$(printf '%s\n' "$out" | grep -E '^latkit_' | sed 's/ [^ ]*$//' | sort | uniq -d | head -1)
[ -z "$dup" ] || fail "series printed twice: $dup"

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
