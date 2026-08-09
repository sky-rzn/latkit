#!/bin/sh
# М3/М4/М5 acceptance (PLAN-HTTP.md): the --queries view over the М0 trace corpus
# must yield the expected observations per scenario — method, status, sizes, the
# four timings and, since М4, the templated route (РH7) — with parse_errors == 0
# on every clean trace. This is the plan's
# "expectation table in a test": one row of checks per scenario family, applied
# to every server directory (nginx / go / node / gunicorn) that recorded it.
#
#   http_queries_traces.sh <lkt_queries binary> <tests/traces/http dir>
#
# The checks are structural, not byte-exact dumps: the traces are real recorded
# sessions and their timings, ports and connection ids differ per capture. What
# *is* pinned is everything an observation is supposed to report — and the
# scenarios where it must deliberately report nothing.
#
# Where the four servers genuinely disagree, the table says so rather than
# testing the intersection: gunicorn's sync worker answers exactly one request
# per connection however many arrive, and only Go delivers a 1 MB body without
# the capture's last call being cut short. Those are findings of М0, and a test
# that hid them would be testing less than the corpus knows.
set -u

LKT="$1"
DIR="$2"
fails=0

fail() {
    echo "FAIL $trace: $1" >&2
    fails=$((fails + 1))
}

# has <ERE> — the trace output contains a line matching it
has() {
    printf '%s\n' "$out" | grep -Eq "$1" || fail "expected /$1/"
}

lacks() {
    printf '%s\n' "$out" | grep -Eq "$1" && fail "unexpected /$1/"
}

# nobs <n> — exactly n observation lines
nobs() {
    got=$(printf '%s\n' "$out" | grep -c '^http ')
    [ "$got" = "$1" ] || fail "expected $1 observations, got $got"
}

# A field of the single observation on this trace, e.g. `field status`.
field() {
    printf '%s\n' "$out" | sed -n "s/^http .*[ ]$1=\([^ ]*\).*/\1/p" | head -1
}

# gt <field> <n> — the field of the first observation is greater than n
gt() {
    v=$(field "$1" | tr -d 'ns')
    [ -n "$v" ] && [ "$v" -gt "$2" ] || fail "expected $1 > $2, got '${v:-none}'"
}

for trace in "$DIR"/*/*.lkt; do
    out=$("$LKT" --proto http "$trace" 2>&1) || fail "lkt_queries exited nonzero"
    base=$(basename "$trace" .lkt)
    srv=$(basename "$(dirname "$trace")")

    lacks "REPLAY FAILED"
    lacks " unknown=[1-9]"

    # --- М4 (РH7): the route label, asserted on every trace ---------------
    # Two ways this label turns into unbounded cardinality, and both are
    # checked here rather than in one scenario: a raw numeric segment that the
    # classifier failed to collapse, and any byte of the query string (dropped
    # whole unless --http-query-keys asks otherwise).
    bad=$(printf '%s\n' "$out" | sed -n 's/^http .* route=\([^ ]*\) .*/\1/p' |
          grep -E '\?|/[0-9]+(/|$)' | head -1)
    [ -n "$bad" ] && fail "route carries an id or a query string: '$bad'"
    # An observation always reports one, except where there is no target at all
    # (an authority-form CONNECT), where it must report none rather than "/".
    nroute=$(printf '%s\n' "$out" | grep -c '^http .* route=[^- ]')
    nhttp=$(printf '%s\n' "$out" | grep -c '^http ')
    case "$srv/$base" in
    go/connect) [ "$nroute" = 0 ] || fail "CONNECT reported a route" ;;
    *) [ "$nroute" = "$nhttp" ] || fail "$((nhttp - nroute)) observation(s) without a route" ;;
    esac

    case "$srv/$base" in
    # The scenarios built to be rejected, and the two TLS traces where
    # ciphertext is framed as plaintext until М7 — the exact set М2 documented
    # in notes-httpproto.md. Everything else must be clean.
    */bad-request | */cl-te | go/huge-head | gunicorn/huge-head | nginx/tls-decrypted*)
        has " parse_errors=[1-9]" ;;
    *)
        has " parse_errors=0 " ;;
    esac

    case "$srv/$base" in
    # --- the base case ---------------------------------------------------
    */get)
        nobs 1
        has '^http .* method=GET status=200 .* route=/hello target=/hello$'
        # A GET has nothing to upload, so the three duration models coincide —
        # РH5's own statement of when the extra timestamp is invisible.
        has '^http .* upload=0ns '
        gt dur 0
        ;;
    # --- РH5: the upload interval is the client's ------------------------
    */post)
        nobs 1
        has '^http .* method=POST status=200 '
        has '^http .* in=65536 '
        gt upload 0 # 64 KB does not arrive instantly, whatever the server
        ;;
    */continue)
        # The client waits ~50 ms for the interim 100 before uploading, so the
        # upload interval dwarfs the server's duration. The interim itself must
        # not be reported as the answer: the status is the final one.
        nobs 1
        has '^http .* method=POST status=200 '
        has '^http .* in=4096 '
        gt upload 10000000
        ;;
    # --- statuses (РH10: 4xx and 5xx are different things) ---------------
    */statuses)
        nobs 3
        has '^http .* status=404 .* flags=0x100 route=/nope target=/nope$'   # client error
        has '^http .* status=500 .* flags=0x1 route=/boom target=/boom$'     # server error
        has '^http .* status=302 .* flags=0x0 route=/redirect target=/redirect$' # neither
        ;;
    # --- the request decides how to read the response --------------------
    */head)
        # A Content-Length describing a body that never arrives: out must be 0,
        # and the connection must still be framed after it.
        nobs 1
        has '^http .* method=HEAD status=200 .* out=0 '
        ;;
    */options)
        # nginx answers 405 for OPTIONS on a static file, the app servers 200.
        # The method is what this row is about, and it is the same everywhere.
        nobs 1
        has '^http .* method=OPTIONS status=[24]'
        ;;
    */absolute-form)
        # The authority in the target overrides Host (РH10).
        nobs 1
        has '^http .* method=GET status=200 '
        ;;
    # --- bodies ----------------------------------------------------------
    */chunked-resp)
        # Chunked reports *decoded* bytes, so the same content is the same
        # number whichever framing carried it — 65 bytes on all four servers.
        nobs 1
        has '^http .* status=200 .* out=65 '
        gt dur 1000000 # five chunks, ~5 ms apart
        ;;
    */chunked-req)
        nobs 1
        has '^http .* method=POST status=200 '
        gt in 1000
        ;;
    go/get-large)
        # Only Go delivers the whole megabyte through the socket within the
        # capture; on the others the connection's last call is cut short and the
        # observation says so (checked below).
        nobs 1
        has '^http .* status=200 .* out=1048576 '
        lacks 'flags=0x200'
        ;;
    */get-large)
        nobs 1
        has '^http .* status=200 '
        gt out 8000
        ;;
    nginx/sendfile-static)
        # РH4's headline measurement: since ~6.5 the kernel routes sendfile
        # through sendmsg, so an 8 MB body that never touches a socket write is
        # nonetheless accounted to the byte.
        nobs 1
        has '^http .* status=200 .* out=8388608 '
        ;;
    nginx/nosendfile-static)
        # The control, written through the socket in ~750 calls — and the one
        # where the capture's last call is cut short, so the count is a lower
        # bound and the observation is flagged for it rather than quietly short.
        nobs 1
        has '^http .* status=200 '
        gt out 8000000
        has '^http .* flags=0x200 '
        ;;
    */slow-response)
        # 250 ms before the first response byte: TTFB and duration are both
        # large and TTFB is essentially all of it — the shape РH5 exists for.
        nobs 1
        gt ttfb 200000000
        ;;
    # --- keep-alive and pipelining (РH6) ---------------------------------
    gunicorn/keepalive-50 | gunicorn/pipelined)
        # gunicorn's sync worker answers one request per connection whatever
        # arrives; the rest are dropped and counted, never mis-paired.
        nobs 1
        has ' dropped=0/[0-9]*/[0-9]* '
        ;;
    */keepalive-50)
        nobs 50
        lacks 'flags=0x80' # sequential requests are not pipelining
        ;;
    */pipelined)
        nobs 4
        # Every unit of the batch is marked: none of them is comparable with a
        # standalone request.
        [ "$(printf '%s\n' "$out" | grep -c '^http .* flags=0x[0-9a-f]*8[0-9a-f] ')" = 4 ] ||
            fail "expected 4 pipelined-flagged observations"
        ;;
    # --- degraded and truncated ------------------------------------------
    */torn-body | */truncated-resp | */abort-midbody)
        # A transfer cut off mid-body: whatever was seen is reported with a
        # status, or dropped and counted — never silently completed.
        has ' parse_errors=0 '
        ;;
    */lf-only)
        # Bare LF: nginx and Go answer 200, node 400, gunicorn nothing at all
        # (М0, the corpus README). Whatever the server did, the observer must
        # not turn it into a parse error.
        has ' parse_errors=0 '
        ;;
    # --- blind zones (РH4) ------------------------------------------------
    */h2-preface | nginx/h2c-prior)
        # Recognised, counted, and no observation invented from HPACK bytes.
        nobs 0
        has ' blind=1 '
        ;;
    nginx/websocket | go/websocket)
        # The handshake unit itself *is* observed — it is an ordinary
        # request/response exchange — and only what follows the 101 is blind.
        nobs 1
        has '^http .* status=101 '
        has ' blind=1 '
        ;;
    */websocket)
        # node and gunicorn have no /ws route: a plain 404, and nothing blind.
        nobs 1
        has '^http .* status=404 '
        has ' blind=0 '
        ;;
    go/connect)
        nobs 1
        has '^http .* method=CONNECT status=200 '
        has ' blind=1 '
        ;;
    */h2c-upgrade)
        # Measured in М0: none of the four servers accepts the upgrade, so this
        # is an ordinary 200 and must *not* be a blind zone.
        nobs 1
        has ' blind=0 '
        ;;
    # --- trace context and the credential header --------------------------
    gunicorn/traceparent)
        # gunicorn does not pipeline: the second request lands on a connection
        # it never answers, so it is dropped and counted rather than observed.
        nobs 1
        has '^http .* target=/json/[^ ]*token=s3cr3t'
        has '^http .* route=/json/\{id\} '
        ;;
    */traceparent)
        nobs 2
        # The raw target reaches the sink unredacted — the span redactor is
        # М6's job — while the *route* beside it is the template, with the id
        # collapsed and the query gone: the two identities of РH7, side by side
        # on one line.
        has '^http .* target=/json/[^ ]*token=s3cr3t'
        has '^http .* route=/json/\{id\} '
        # Without --http-user the credential header is not read at all.
        has '^http .* user=- '
        with_user=$("$LKT" --proto http --http-user basic "$trace" 2>&1)
        printf '%s\n' "$with_user" | grep -Eq '^http .* user=admin ' ||
            fail "--http-user basic did not yield the Basic name half"
        # ... and never the password half, whatever the flag says (РH12).
        printf '%s\n' "$with_user" | grep -Eq 'hunter2|s3cr3tpass' &&
            fail "a password reached the output"
        ;;
    esac
done

# --- М5 (РH9/РH10): the exposition the corpus produces ---------------------
# The same replay, teed into the real aggregator, dumped once over every trace.
# What is asserted here is what a metric consumer sees and the per-observation
# view above cannot check: that the http families exist and are keyed by the
# templated route, that the exposition is *valid* (no series printed twice — the
# failure mode of a label set missing a key), and that none of this leaks into
# the database families.
trace="metrics"
out=$("$LKT" --proto http --quiet --metrics "$DIR"/*/*.lkt 2>&1)

for fam in requests_total request_duration_seconds_count ttfb_seconds_count \
           request_upload_seconds_count errors_total bytes_total \
           response_size_bytes_count; do
    has "^latkit_http_$fam\{"
done

# The route label is the template, in the metric as on the observation line.
bad=$(printf '%s\n' "$out" | grep -oE 'route="[^"]*"' | sort -u |
      grep -E '\?|/[0-9]+(/|")' | head -1)
[ -n "$bad" ] && fail "a metric label carries an id or a query string: '$bad'"

# The method is part of the route identity (РH7): /hello is one path and two
# routes, and their latencies must not be summed into one series.
for m in GET HEAD; do
    has "^latkit_http_requests_total\{route=\"/hello\",method=\"$m\""
done

# 5xx is the server failing and 4xx is not (РH10): both counted, one an error.
has '^latkit_http_requests_total\{route="/boom".*status="5xx"'
has '^latkit_http_request_duration_seconds_count\{route="/boom".*code="error"'
has '^latkit_http_errors_total\{code="500"'

# Nothing HTTP reaches the database families, and the PG-shaped counters stay at
# zero — the profile split of РH10, seen from the outside.
lacks '^latkit_quer(y|ies)_.*proto="http"'
has '^latkit_queries_other_total 0$'
has '^latkit_queries_truncated_total 0$'

# A valid exposition prints every series exactly once. This is the check that
# would catch an http family whose label set dropped a key that is part of its
# identity — Prometheus rejects the whole scrape when that happens.
dup=$(printf '%s\n' "$out" | grep -v '^#' | grep '^latkit_' |
      sed 's/ [^ ]*$//' | sort | uniq -d | head -1)
[ -n "$dup" ] && fail "duplicate series in the exposition: '$dup'"

echo "---"
if [ "$fails" -eq 0 ]; then
    echo "http М3/М4/М5: trace expectations met"
    exit 0
fi
echo "$fails check(s) failed"
exit 1
