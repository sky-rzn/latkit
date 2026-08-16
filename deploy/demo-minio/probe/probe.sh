#!/bin/sh
#
# The callers an SDK cannot produce (PLAN-MINIO.md МS5), driven with busybox
# `wget` against the demo's MinIO. Three of the four ways a request can name —
# or fail to name — who is making it (РS4):
#
#   1. **anonymous, allowed** — no credential carrier at all. `user="-"`, which
#      is a different fact from a key latkit failed to read, and the request
#      succeeds because the `public` bucket has a download policy;
#   2. **anonymous, refused** — the same non-caller against a private bucket:
#      `user="-"`, `403`, S3 code `AccessDenied`;
#   3. **presigned** — the access key travels in the `X-Amz-Credential` query
#      parameter instead of an `Authorization` header, and latkit reads it from
#      there. The URL is minted by the mc container (that is where the secret
#      is) and handed over through the shared volume;
#   4. **a signature from an access key that does not exist** — the shape of
#      "who is hammering us with bad credentials". The label comes off the
#      request, not off the outcome, so the caller is named even though the
#      server rejects it.
#
# `mc` cannot drive any of these: it refuses to configure an alias whose
# credentials the server rejects, and it has no anonymous mode worth the name.
set -u

ENDPOINT=${S3_ENDPOINT:-http://minio:9000}
SHARE=${SHARE:-/share/presigned.json}

# A well-formed SigV4 header whose access key was never created. The signature
# is nonsense on purpose: latkit never reads it (only the key half of the
# credential), and MinIO rejects the request before it would matter. The dates
# are stamped per request — a fixed one would drift out of MinIO's 15-minute
# window and turn every one of these into RequestTimeTooSkewed, which is a
# different (and less interesting) story than "this key does not exist".
SIG=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
bad_auth() {
    printf 'AWS4-HMAC-SHA256 Credential=ghostkey/%s/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-date,Signature=%s' \
        "$(date -u +%Y%m%d)" "$SIG"
}

get() { wget -q -O /dev/null --timeout=10 "$@" >/dev/null 2>&1 || true; }

# The presigned URL appears once the load container has finished its setup.
url=""
while [ -z "$url" ]; do
    if [ -s "$SHARE" ]; then
        # No jq in a busybox image, and none needed: the URL is the only thing
        # in that JSON that starts with a scheme.
        url=$(tr '{},' '\n' < "$SHARE" | grep -o 'https\?://[^"]*' | head -n 1)
    fi
    [ -z "$url" ] && sleep 2
done
echo "demo probe: presigned URL acquired, driving $ENDPOINT"

while :; do
    get "$ENDPOINT/public/hello.txt"                     # anonymous, allowed
    get "$ENDPOINT/photos/small-1.bin"                   # anonymous, refused
    get "$url"                                           # presigned
    get --header="Authorization: $(bad_auth)" \
        --header="X-Amz-Date: $(date -u +%Y%m%dT%H%M%SZ)" \
        "$ENDPOINT/photos/small-1.bin"                   # a caller that is not one
    sleep 2
done
