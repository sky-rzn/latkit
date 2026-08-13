#!/bin/sh
#
# Load generator for the latkit HTTP demo (PLAN-HTTP.md М9). Runs in a stock
# curl image (busybox sh — POSIX only, no bashisms), talks to nginx by service
# name over the compose network, and repeats forever.
#
# The mix is designed so that every panel of dashboards/latkit-http.json has
# data and so that the *interesting* claims of the track are visible rather
# than asserted:
#
#   - each request carries a freshly random identifier of a different shape
#     (number, UUID, ULID, sha1-ish hex, date). Every pass therefore invents a
#     dozen URLs never seen before, and the route labels must stay put. If the
#     templater were off, `latkit_metric_series` would climb without bound and
#     the "route=other share" panel would go to 1 — that is the demo's own
#     honesty check, visible on the dashboard;
#   - the query string is junk on purpose (?q=<random>&token=<secret>): it must
#     not reach a label at all, and its `token=` value must not survive even in
#     a span (РH12, --http-redact);
#   - two Host headers, so `host` has more than one value;
#   - a slow trickled upload and a one-shot upload, which report their upload
#     interval differently (РH5, and docs/accuracy.md §HTTP explains why);
#   - a keep-alive burst, a sendfile-served 8 MB file and the same file written
#     through the socket, a chunked response, and a spread of failures.
#
# Every request also carries a W3C traceparent with a fresh trace id (РH11).
# Without an OTLP endpoint configured the agent simply ignores it; with one
# (see the README's trace profile) the observation joins that trace.
set -u

FRONT=${FRONT:-http://nginx:8080}
# Extra curl flags, unquoted on purpose so the tls profile can pass
# `-k --http1.1` (self-signed certificate; h2 kept off — it is a declared blind
# zone, and negotiating it would demonstrate the blind-zone counter instead of
# the TLS channel).
CURL_EXTRA=${CURL_EXTRA:-}
HOSTS="shop.demo api.demo"

hex() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }
num() { od -An -tu4 -N4 /dev/urandom | tr -d ' \n'; }

uuid() {
    u=$(hex 16)
    printf '%s-%s-%s-%s-%s' \
        "$(printf %s "$u" | cut -c1-8)"   "$(printf %s "$u" | cut -c9-12)" \
        "$(printf %s "$u" | cut -c13-16)" "$(printf %s "$u" | cut -c17-20)" \
        "$(printf %s "$u" | cut -c21-32)"
}

# Crockford base32 (no I, L, O, U) — what the ULID classifier of РH7 accepts,
# and it accepts exactly 26 characters. 1 KiB of entropy yields ~128 usable
# ones, so the `head -c 26` is never short; with 256 bytes it occasionally was,
# and a 24-character id is a *word* to the classifier — which is the right
# answer to the wrong input.
ulid() { head -c 1024 /dev/urandom | tr -dc '0123456789ABCDEFGHJKMNPQRSTVWXYZ' | head -c 26; }

date_key() { printf '2026-%02d-%02d' "$(( $(num) % 12 + 1 ))" "$(( $(num) % 28 + 1 ))"; }

traceparent() { printf '00-%s-%s-01' "$(hex 16)" "$(hex 8)"; }

# One curl invocation with the demo's standard headers. $1 is the path, the
# rest is passed through.
get() {
    p=$1
    shift
    # shellcheck disable=SC2086  # CURL_EXTRA is a flag list, splitting is wanted
    curl -s -o /dev/null --max-time 10 $CURL_EXTRA \
        -H "Host: $VHOST" -H "traceparent: $(traceparent)" \
        -H 'User-Agent: latkit-demo/1.0' \
        "$@" "$FRONT$p"
}

echo "demo load: driving $FRONT"
pass=0
while :; do
    # Alternate the virtual host between passes.
    for VHOST in $HOSTS; do
        n=$(num)
        # --- the id zoo: five shapes, one route label each ------------------
        get "/api/users/$(( n % 9000 + 1 ))"
        get "/api/users/$(( n % 9000 + 1 ))/orders"
        get "/api/orders/$(uuid)"
        get "/api/sessions/$(ulid)"
        get "/api/blobs/$(hex 20)"
        get "/api/reports/$(date_key)"
        get "/api/orders/$(uuid)" -X DELETE

        # --- query strings: unbounded input, one route ----------------------
        # `token` is here to be redacted: it must not appear in any output of
        # the agent, span text included (РH12).
        get "/api/search?q=$(hex 6)&token=$(hex 16)&page=$(( n % 20 ))"

        # --- shapes of response ---------------------------------------------
        get /api/events                     # chunked (no Content-Length)
        get /api/slow                       # TTFB and duration disagree
        get /api/flaky                      # 200 / 429 / 500 / 503
        get /api/boom                       # always 500
        get /api/legacy -L -o /dev/null     # 302, then the redirect target
        get "/api/nope/$(hex 4)"            # 404 — counted, not an error
        get /hello                          # answered by nginx itself

        # --- uploads: the two upload-interval cases of РH5 -------------------
        # A slow client trickling its body over ~0.5 s: the interval between
        # the first request byte and the last is real and belongs to the
        # client. `Expect:` empty suppresses the 100-continue curl would
        # otherwise send, which РH5 excludes from the family on purpose.
        (i=0; while [ $i -lt 10 ]; do head -c 512 /dev/zero; sleep 0.05; i=$((i+1)); done) |
            curl -s -o /dev/null $CURL_EXTRA -H "Host: $VHOST" -H 'Expect:' \
                 -H 'Content-Type: application/octet-stream' \
                 -T - "$FRONT/api/uploads/$(uuid)"
        # A client that hands the kernel head and body in one call: there is no
        # interval to measure, and the family skips the unit rather than
        # reporting a zero.
        head -c 65536 /dev/zero | curl -s -o /dev/null $CURL_EXTRA -H "Host: $VHOST" \
            -H 'Content-Type: application/octet-stream' \
            --data-binary @- "$FRONT/api/orders"

        # --- static: the sendfile path and the same bytes through write() ---
        # The 8 MB pair runs once every fifth pass, not every pass: it is worth
        # ~40 Mbit/s on its own, and a demo should not be the heaviest thing on
        # the machine. Once a pass is plenty for the size histogram and the
        # throughput panel.
        get /static/small.txt
        pass=$(( pass + 1 ))
        if [ $(( pass % 5 )) -eq 0 ]; then
            get /static/big.bin
            get /nosendfile/big.bin
        fi

        # --- keep-alive: five exchanges on one connection --------------------
        curl -s -o /dev/null $CURL_EXTRA -H "Host: $VHOST" "$FRONT/hello" \
            --next -s -o /dev/null $CURL_EXTRA -H "Host: $VHOST" "$FRONT/api/users/$(( n % 9000 + 1 ))" \
            --next -s -o /dev/null $CURL_EXTRA -H "Host: $VHOST" "$FRONT/api/flaky" \
            --next -s -o /dev/null $CURL_EXTRA -H "Host: $VHOST" "$FRONT/api/search?q=keepalive" \
            --next -s -o /dev/null $CURL_EXTRA -H "Host: $VHOST" "$FRONT/hello"
    done
    sleep 0.2
done
