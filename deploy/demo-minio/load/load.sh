#!/bin/sh
#
# Load generator for the latkit S3 demo (PLAN-MINIO.md МS5). Runs in the stock
# `minio/mc` image (POSIX sh; that image has no grep, sed, awk, curl or wget —
# hence the shapes below), talks to MinIO by service name over the compose
# network, and repeats forever.
#
# `mc` is MinIO's own client, so what goes on the wire is the real S3 framing
# rather than a curl approximation of it: uploads are `aws-chunked`
# (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, which is what makes the object's
# logical size a different number from the bytes on the wire — РS6), listings
# are gzipped, and a stream of unknown length becomes a real multipart upload.
#
# The mix is designed so that every panel of dashboards/latkit-s3.json has data
# and so that the *interesting* claims of the track are visible rather than
# asserted:
#
#   - **every object key is unique and none of them is ever a label.** Each pass
#     writes keys carrying a counter, a slash-separated prefix and a `%`-escape;
#     the `op` label stays a value from the taxonomy table (РS2). If keys leaked
#     into labels, `latkit_metric_series` would climb without bound — that is
#     the demo's own honesty check, visible on the Agent health dashboard;
#   - **three buckets and two access keys**, so the two S3-specific label slots
#     (РS3, РS4) have more than one value each and the "top" panels mean
#     something;
#   - **one operation family per row of the taxonomy**: single PUT, copy, HEAD,
#     GET, listing, delete, multi-delete, and the three-call multipart sequence;
#   - **three object-size decades** (1 KiB / 256 KiB / 5 MiB) for the size
#     histogram, which is fed by the *logical* size, not the wire size;
#   - **a slow upload** — a client trickling a body over ~1 s — which lands in
#     `latkit_s3_request_upload_seconds` and NOT in the duration histogram
#     (РH5: latkit starts the server's clock at the end of the request);
#   - **two deliberate failures that are one HTTP status and two S3 codes**:
#     a missing object and a missing bucket are both `404`, and `NoSuchKey` and
#     `NoSuchBucket` are not the same page at 3 a.m. (РS5).
#
# The presigned URL for the probe container is produced here (this is where the
# credentials are) and handed over through the shared volume; probe/probe.sh
# parses it, because busybox has the tools for that and this image does not.
set -u

ENDPOINT=${S3_ENDPOINT:-http://minio:9000}
MC_EXTRA=${MC_EXTRA:-}          # `--insecure` on the tls leg (self-signed cert)
PRESIGN=${PRESIGN:-1}           # produce /share/presigned.json for the probe
ROOT_KEY=${ROOT_KEY:-lkroot}
ROOT_SECRET=${ROOT_SECRET:-lkrootpass123}
APP_KEY=${APP_KEY:-demoapp}
APP_SECRET=${APP_SECRET:-demoapppass123}

# shellcheck disable=SC2086  # MC_EXTRA is a flag list, splitting is wanted
mc() { /usr/bin/mc --quiet --no-color $MC_EXTRA "$@"; }

echo "demo load: driving $ENDPOINT"

# --- setup: buckets, a second access key, a public prefix -------------------
until mc alias set lk "$ENDPOINT" "$ROOT_KEY" "$ROOT_SECRET" >/dev/null 2>&1; do
    echo "waiting for $ENDPOINT ..."
    sleep 1
done

mc mb --ignore-existing lk/photos lk/backups lk/public >/dev/null 2>&1 || true

# A second caller, so `user` is a real dimension rather than one root key. Its
# access key is the public half of the pair — the only half latkit ever reads
# (the signature, the chunk signatures and X-Amz-Security-Token are not touched).
mc admin user add lk "$APP_KEY" "$APP_SECRET" >/dev/null 2>&1 || true
mc admin policy attach lk readwrite --user "$APP_KEY" >/dev/null 2>&1 || true
mc alias set app "$ENDPOINT" "$APP_KEY" "$APP_SECRET" >/dev/null 2>&1 || true

# Anonymous downloads from one bucket: the probe's `user="-"` requests need
# something that succeeds, next to something that does not.
mc anonymous set download lk/public >/dev/null 2>&1 || true

printf 'hello from the latkit S3 demo\n' > /tmp/hello.txt
mc cp /tmp/hello.txt lk/public/hello.txt >/dev/null 2>&1 || true

# Three payload sizes, made once. /dev/urandom rather than /dev/zero: a
# compressible body would let a proxy or the client shorten it, and the size
# histogram is about what the object really is.
head -c 1024    /dev/urandom > /tmp/small.bin
head -c 262144  /dev/urandom > /tmp/mid.bin
head -c 5242880 /dev/urandom > /tmp/big.bin

# The presigned URL: generated here, consumed by the probe container. `--json`
# so that a parser can find the URL without knowing mc's prose; 12 h of validity
# is longer than any demo, and it is refreshed below anyway.
presign() {
    [ "$PRESIGN" = "1" ] || return 0
    mc share download --expire 12h --json lk/public/hello.txt > /tmp/presigned.json 2>/dev/null \
        && mv /tmp/presigned.json /share/presigned.json
}
presign

i=0
while :; do
    i=$((i + 1))

    # --- single PUT: two sizes, and a key with structure in it --------------
    # The nested key is the point: a slash-separated prefix and a `%`-escape are
    # exactly what an object key looks like in the wild, and neither reaches a
    # label. `mc` signs these as aws-chunked uploads, so the wire carries the
    # chunk framing and `x-amz-decoded-content-length` carries the object.
    mc cp /tmp/small.bin lk/photos/small-$i.bin                   >/dev/null 2>&1
    mc cp /tmp/mid.bin   lk/photos/2026/08/mid%20$i.bin           >/dev/null 2>&1

    # --- multipart: a stream of unknown length --------------------------
    # `mc pipe` cannot know the size in advance, so minio-go has to take the
    # multipart path: CreateMultipartUpload, UploadPart(s), CompleteMultipart-
    # Upload — three different rows of the taxonomy for one logical upload.
    mc pipe lk/backups/stream-$i.bin < /tmp/big.bin               >/dev/null 2>&1

    # --- server-side copy, HEAD, GET, listings -----------------------------
    mc cp   lk/photos/small-$i.bin lk/backups/copy-$i.bin         >/dev/null 2>&1
    mc stat lk/photos/small-$i.bin                                >/dev/null 2>&1
    mc cat  lk/photos/small-$i.bin                                >/dev/null 2>&1
    mc cat  lk/photos/2026/08/mid%20$i.bin                        >/dev/null 2>&1
    mc ls   lk/photos                                             >/dev/null 2>&1
    mc ls   lk                                                    >/dev/null 2>&1

    # --- the second caller --------------------------------------------------
    mc cp   /tmp/small.bin app/public/app-$i.bin                  >/dev/null 2>&1
    mc cat  app/public/app-$i.bin                                 >/dev/null 2>&1
    mc rm   app/public/app-$i.bin                                 >/dev/null 2>&1

    # --- two failures, one status, two codes (РS5) --------------------------
    mc cat lk/photos/no-such-object-$i                            >/dev/null 2>&1
    mc ls  lk/no-such-bucket-demo                                 >/dev/null 2>&1

    # --- deletes: one object, and a bulk sweep every fifth pass -------------
    mc rm lk/photos/small-$i.bin                                  >/dev/null 2>&1
    if [ $((i % 5)) -eq 0 ]; then
        # Recursive removal is a DeleteObjects (POST ?delete) — one request that
        # deletes many keys, and a different row from DeleteObject.
        mc rm --recursive --force lk/photos/2026                  >/dev/null 2>&1
        mc rm --recursive --force lk/backups                      >/dev/null 2>&1
    fi

    # --- a slow client: ~1 s of trickled body (РH5) -------------------------
    # 12 × 128 KiB with a pause between them. The interval belongs to the client
    # and is reported as its own family; the duration histogram must not see it.
    if [ $((i % 3)) -eq 0 ]; then
        (n=0; while [ $n -lt 12 ]; do head -c 131072 /tmp/mid.bin; sleep 0.08; n=$((n + 1)); done) \
            | mc pipe lk/backups/slow-$i.bin                      >/dev/null 2>&1
    fi

    # Refresh the presigned URL well before it expires.
    [ $((i % 500)) -eq 0 ] && presign

    sleep 0.3
done
