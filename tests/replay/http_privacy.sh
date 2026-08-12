#!/bin/sh
# РH12 acceptance (PLAN-HTTP.md М6): "a stand driven with deliberately secret
# URLs and headers, then grep across the whole output — no secret is found".
#
#   http_privacy.sh <lkt_queries> <lkt_messages> <tests/traces/http dir>
#
# The stand is the М0 corpus: `<server>/traceparent.lkt` is a real recorded
# session carrying, on purpose, every shape the plan worries about — a
# credential in the query string (`?token=s3cr3t`), one in a header
# (`Authorization: Basic YWRtaW46aHVudGVyMg==` — "admin:hunter2"), and a session
# cookie (`session=deadbeefcafe`). Four servers recorded it, so the check runs
# four times over genuinely different framings of the same request.
#
# Every surface the agent has is checked, because the invariant is worth exactly
# as much as its weakest one:
#
#   --queries   the observation view (raw SQL's counterpart; the target)
#   --metrics   the Prometheus exposition — labels are the permanent surface
#   --spans     what the OTLP exporter would put in a trace backend
#   --messages  the wire view with --hexdump, the rawest output there is
#
# Two properties are asserted per surface and both matter: that no secret is
# present, and that the surface produced *something* — a check that greps an
# empty string passes for the wrong reason, which is how a privacy test quietly
# stops testing anything.
set -u

Q="$1"
M="$2"
DIR="$3"
fails=0

# The literals planted in the corpus (tests/traces/http/clients/raw.py).
SECRETS='s3cr3t|YWRtaW46aHVudGVyMg|hunter2|deadbeefcafe'

fail() {
    echo "FAIL $trace: $1" >&2
    fails=$((fails + 1))
}

# no_secret <label> <output> — the invariant, plus proof the output is real.
no_secret() {
    label="$1"
    out="$2"

    [ -n "$out" ] || { fail "$label produced no output at all"; return; }
    hit=$(printf '%s\n' "$out" | grep -Eo "$SECRETS" | sort -u | head -3 | tr '\n' ' ')
    [ -z "$hit" ] || fail "$label leaked: $hit"
}

# The ASCII column of the --hexdump view, rejoined across its 16-byte lines: a
# secret split over two lines would otherwise slip through a plain grep.
dump_text() {
    "$M" --proto http --hexdump "$1" 2>&1 | sed -n 's/^  [0-9a-f]*: //p' | cut -c42- | tr -d '\n'
}

for trace in "$DIR"/*/traceparent.lkt; do
    [ -f "$trace" ] || continue

    no_secret "--queries" "$("$Q" --proto http "$trace" 2>&1)"
    no_secret "--queries --http-user basic" "$("$Q" --proto http --http-user basic "$trace" 2>&1)"
    no_secret "--metrics" "$("$Q" --proto http --quiet --metrics "$trace" 2>&1)"
    no_secret "--spans" "$("$Q" --proto http --quiet --spans 1.0 "$trace" 2>&1)"
    no_secret "--messages --hexdump" "$(dump_text "$trace")"

    # The positive half: each surface still says what it is supposed to say, so
    # "no secret" cannot be achieved by reporting nothing.
    out=$("$Q" --proto http --quiet --spans 1.0 "$trace" 2>&1)
    printf '%s\n' "$out" | grep -Eq '^span .* route=/json/\{id\} ' ||
        fail "the span lost its route while redacting"
    printf '%s\n' "$out" | grep -Eq 'path=/json/[^ ]*token=\*\*\*' ||
        fail "url.path is not the redacted target"

    # `--http-user basic` is the one flag that lifts an identity off the wire
    # (РH10). It yields the *name* half and never the password, whatever the
    # base64 contained — the decoder stops at the colon.
    out=$("$Q" --proto http --http-user basic "$trace" 2>&1)
    printf '%s\n' "$out" | grep -Eq '^http .* user=admin ' ||
        fail "--http-user basic did not report the name half"

    # The wire view masks the credential headers rather than dropping the
    # message (РH3): the framing stays readable, the value does not.
    text=$(dump_text "$trace")
    printf '%s\n' "$text" | grep -q 'Authorization: \*\*\*' ||
        fail "the Authorization value is not masked in --hexdump"
    printf '%s\n' "$text" | grep -q 'Cookie: \*\*\*' ||
        fail "the Cookie value is not masked in --hexdump"
    printf '%s\n' "$text" | grep -q 'traceparent: 00-4bf92f' ||
        fail "masking ate a header it had no business touching"
done

# `--http-redact off` is the documented escape hatch, and the only way any of
# this reaches an output. Asserted so that "nothing leaks" stays a statement
# about the default rather than about the plumbing being broken.
trace="redact-off"
out=$("$Q" --proto http --http-redact off "$DIR"/nginx/traceparent.lkt 2>&1)
printf '%s\n' "$out" | grep -q 's3cr3t' ||
    fail "--http-redact off did not restore the raw target"

echo "---"
if [ "$fails" -gt 0 ]; then
    echo "$fails privacy check(s) failed" >&2
    exit 1
fi
echo "http М6 (РH12): no secret reached any surface"
exit 0
