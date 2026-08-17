#!/bin/sh
# РR4/РR6/РR7 acceptance (PLAN-REDIS.md МR3, МR4) — the redis half of the
# privacy check РH12 established for HTTP (http_privacy.sh), against a corpus
# that plants what it is looking for.
#
#   redis_privacy.sh <lkt_queries> <lkt_messages> <tests/traces/redis dir>
#
# The stand is the МR0 corpus. `redis/auth-forms.lkt` and `redis/acl-errors.lkt`
# carry real passwords (`lkpass`, `lkrootpass`, `wrongpass`) in every form a
# Redis client can send one — `AUTH <pass>`, `AUTH <user> <pass>`, `HELLO …
# AUTH`, and a wrong one — and `redis/basic.lkt` carries twenty commands' worth
# of keys. Both are exactly what РR4 says must never become a label.
#
# Two claims are checked, and they are deliberately different claims, because a
# key and a password are different things:
#
#   a **password** must not appear on *any* surface, the raw `--messages
#   --hexdump` view included. It is a credential, the `mask_body` hook of РR6
#   exists for it, and Redis itself sets the precedent by redacting `AUTH` in
#   its own `MONITOR` feed.
#
#   a **key** must not appear in any *exported or aggregated* surface — no
#   label, no metric, no span, and none of the `--messages` header lines. The
#   raw hexdump is a different kind of output: it is the bytes that were on the
#   wire, it is off by default (`--hexdump`), it goes to a terminal and never to
#   a metrics backend, and blanking payloads there would leave a wire view that
#   cannot be used to debug the wire. What the track promises about keys is that
#   nothing *derives* from them and nothing *keeps* them — which is what the
#   surfaces below check.
#
# Each surface is also asserted to have produced output at all: a check that
# greps an empty string passes for the wrong reason, which is how a privacy test
# quietly stops testing anything.
set -u

Q="$1"
M="$2"
DIR="$3"
fails=0

PASSWORDS='lkpass|lkrootpass|wrongpass'
# The keys, channels and stream names raw.py plants (`lk:` prefixed, one and
# all) plus the client name of the `HELLO … SETNAME` form.
KEYS='lk:[a-z0-9:._-]*'

fail() {
    echo "FAIL $1" >&2
    fails=$((fails + 1))
}

# no_hit <label> <pattern> <output>
no_hit() {
    [ -n "$3" ] || { fail "$1 produced no output at all"; return; }
    hit=$(printf '%s\n' "$3" | grep -Eo "$2" | sort -u | head -3 | tr '\n' ' ')
    [ -z "$hit" ] || fail "$1 leaked: $hit"
}

# The ASCII column of the --hexdump view, rejoined across its 16-byte lines: a
# password split over two lines would otherwise slip through a plain grep.
dump_text() {
    "$M" --proto redis --hexdump "$1" 2>&1 | sed -n 's/^  [0-9a-f]*: //p' | cut -c42- | tr -d '\n'
}

# `redis/errors.lkt` and `cluster/moved.lkt` are here for МR4's surface (РR7):
# an error *message* is a sentence written for a human and it quotes the input —
# `-ERR unknown command 'X', with args beginning with: 'lk:…'` names a key, and
# `-MOVED 12182 127.0.0.1:6392` names a node. Only the first token of it ever
# becomes a label, and this is where that is checked against traffic rather than
# against the code.
for trace in "$DIR"/redis/auth-forms.lkt "$DIR"/redis/acl-errors.lkt \
    "$DIR"/valkey/auth-forms.lkt "$DIR"/libs/py-auth.lkt "$DIR"/redis/basic.lkt \
    "$DIR"/redis/errors.lkt "$DIR"/cluster/moved.lkt "$DIR"/redis/monitor.lkt; do
    [ -f "$trace" ] || continue
    name=$(basename "$trace" .lkt)

    # --- the observation view, the exposition, the spans ------------------
    for surface in queries metrics spans; do
        case "$surface" in
        queries) out=$("$Q" --proto redis "$trace" 2>&1) ;;
        metrics) out=$("$Q" --proto redis --quiet --metrics "$trace" 2>&1) ;;
        spans)
            out=$("$Q" --proto redis --quiet --spans 1 "$trace" 2>&1)
            # Every trace here has commands on it, so every one must produce
            # spans: since МR6 a span carries a `db.query.text` of its own
            # making, and a surface that emitted none would pass the greps
            # below for the wrong reason (the stats line alone is not empty).
            printf '%s\n' "$out" | grep -q '^span ' || fail "$name --spans produced no span"
            ;;
        esac
        no_hit "$name --$surface (password)" "$PASSWORDS" "$out"
        no_hit "$name --$surface (key)" "$KEYS" "$out"
    done

    # --- the message view: header lines only, which is what it prints -----
    out=$("$M" --proto redis "$trace" 2>&1)
    no_hit "$name --messages (password)" "$PASSWORDS" "$out"
    no_hit "$name --messages (key)" "$KEYS" "$out"

    # --- the raw hexdump: the password is masked even here ----------------
    out=$(dump_text "$trace")
    no_hit "$name --messages --hexdump (password)" "$PASSWORDS" "$out"
done

# The masking is not an accident of the dump's line breaks: on the trace built
# for it, the `AUTH` commands are still there, still framed, and still readable
# as `AUTH` — with `*` where the credential was.
trace="$DIR/redis/auth-forms.lkt"
out=$(dump_text "$trace")
printf '%s\n' "$out" | grep -q 'AUTH' || fail "the AUTH commands vanished from the dump"
printf '%s\n' "$out" | grep -q '\*\*\*\*\*\*' || fail "nothing was masked in the dump"
# ... and the user name of `HELLO … AUTH <user> <pass>` survives, because it is a
# label and not a secret: hiding it would make the dump useless for the one
# question it answers about a handshake.
printf '%s\n' "$out" | grep -q 'lkuser' || fail "the HELLO user name was masked too"

# Redis redacts `AUTH` in its own MONITOR feed, so the feed carries
# `"AUTH" "(redacted)"` and no password — worth asserting, because that trace is
# the one place a *third party's* credential could reach us (notes-redisproto.md
# §"What is on the port but is not RESP").
trace="$DIR/redis/monitor.lkt"
out=$(dump_text "$trace")
no_hit "monitor feed (password)" "$PASSWORDS" "$out"

if [ "$fails" -eq 0 ]; then
    echo "ok   - no password on any surface, no key on any exported one"
    exit 0
fi
echo "FAIL - $fails privacy check(s) failed" >&2
exit 1
