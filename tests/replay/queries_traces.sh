#!/bin/sh
# М3 acceptance (MYSQL.md): the --queries view over the М0 trace corpus must
# yield the expected observations per scenario, with parse_errors == 0 and no
# unknown messages on every clean trace. This is the plan's "expectation
# table in a test": one row of checks per scenario family, applied to every
# server directory (my84 / my57 / maria1011) that recorded it.
#
#   queries_traces.sh <lkt_queries binary> <tests/traces/mysql dir>
#
# The checks are deliberately structural (kinds, flags, row counts, SQLSTATE,
# session labels), not byte-exact dumps: the traces are real recorded
# sessions and their timings/ids differ per capture.
set -u

LKT="$1"
DIR="$2"
fails=0

fail() {
    echo "FAIL $trace: $1" >&2
    fails=$((fails + 1))
}

# has <pattern> — the trace output contains a line matching the ERE
has() {
    printf '%s\n' "$out" | grep -Eq "$1" || fail "expected /$1/"
}

# lacks <pattern>
lacks() {
    printf '%s\n' "$out" | grep -Eq "$1" && fail "unexpected /$1/"
}

for trace in "$DIR"/*/*.lkt; do
    out=$("$LKT" --proto mysql "$trace" 2>&1) || fail "lkt_queries exited nonzero"
    base=$(basename "$trace" .lkt)

    lacks "REPLAY FAILED"
    # Clean-corpus invariants: nothing unparseable, nothing unrecognised.
    has ' parse_errors=0 unknown=0 '

    case "$base" in
    *-tls)
        # Socket layer only: greeting + short SSLRequest, then ciphertext —
        # no session, no queries (the decrypted twin carries the content).
        has ' sessions=0 queries=0 '
        continue
        ;;
    esac

    # Every plaintext/decrypted trace is one full session with known labels.
    has ' sessions=1 '
    has '^session .* user=root db=test'

    case "$base" in
    cli-*) has '^session .* app=mysql ' ;;
    py-*) has 'app=mysql-connector-python' ;;
    jdbc-*) has 'app=MySQL Connector/J' ;;
    esac

    case "$trace" in
    */my84/*) has 'ver=8\.4\.' ;;
    */my57/*) has 'ver=5\.7\.' ;;
    */maria1011/*) has 'ver=10\.11\.' ;; # the 5.5.5- prefix must be stripped
    esac

    case "$base" in
    *simple*)
        # README: table t has 5 rows.
        has 'kind=simple .*rows=5 .*text=SELECT \* FROM t'
        ;;
    *error*)
        # README: the error scenario targets a missing table (1146 / 42S02).
        has 'kind=simple .*sqlstate=42S02'
        ;;
    *transaction*)
        # BEGIN/COMMIT/ROLLBACK: units observed inside the transaction and at
        # least one IN_TRANS -> idle edge.
        has 'txn=T'
        has '^txn .*final=T'
        ;;
    *load-data*)
        # 1000 tab-separated rows streamed: a COPY_IN unit, rows from the
        # final OK's affected_rows, bytes from the client data packets.
        has 'kind=copy_in .*rows=1000 bytes=[1-9][0-9]*'
        ;;
    py-prepared | jdbc-prepared)
        # Real binary prepare: EXTENDED units resolve their text through the
        # stmt_id cache — placeholders intact.
        has 'kind=extended .*text=.*\?'
        ;;
    cli-prepared-text)
        # The CLI's PREPARE .. FROM is textual SQL over COM_QUERY.
        has 'kind=simple .*text=.*PREPARE'
        ;;
    py-multi)
        # The connector closes without draining the last resultset of the
        # multi-statement (SERVER_MORE_RESULTS_EXISTS still set on the final
        # EOF): the unit is honestly dropped at close, never emitted (Р19).
        has ' dropped=0/1/0 '
        ;;
    jdbc-multi)
        # One MULTI_STMT unit for the whole "a; b; c", row counts summed.
        has 'kind=simple .*flags=0x[0-9a-f]*8 .*text=SELECT 1; SELECT'
        ;;
    *cursor-fetch*)
        # CURSOR_TYPE_READ_ONLY execute + FETCH batches: every batch but the
        # last carries LK_QO_SUSPENDED (0x20), the PortalSuspended analogue.
        has 'kind=extended .*flags=0x20'
        has 'kind=extended .*flags=0x0 '
        ;;
    *compress*)
        # РМ7 blind zone: the handshake is parsed (labels above), the
        # compressed command phase is not observed.
        has ' queries=0 '
        ;;
    *big-resultset*)
        # РМ4's accepted cost: capture holes over the 9 MB row stream may
        # drop the unit; the invariant is clean parsing (checked above), not
        # a query count.
        ;;
    *tls-decrypted*)
        # The uprobe channel: the full handshake repeats inside TLS and the
        # queries parse from plaintext.
        has 'kind=simple .*text=SELECT'
        ;;
    esac
done

[ "$fails" -eq 0 ] && echo "ok: mysql М0 corpus expectations hold" || echo "$fails check(s) failed" >&2
exit "$([ "$fails" -eq 0 ] && echo 0 || echo 1)"
