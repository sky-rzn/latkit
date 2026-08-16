#!/bin/sh
# МS1 + МS2 acceptance (PLAN-MINIO.md): the --queries view over the МS0 corpus
# must yield the expected observations per scenario — the operation (РS2), the
# bucket (РS3), the access key (РS4), the status and the S3 error code (РS5) and
# both byte counts (РS6) — with parse_errors == 0 on every clean trace; and the
# same replay through the metrics aggregator must produce the `latkit_s3_*`
# families of РS7 (the section at the bottom).
#
#   s3_queries_traces.sh <lkt_queries binary> <tests/traces/s3 dir>
#
# The same shape as http_queries_traces.sh and for the same reason: the traces
# are real recorded sessions against MinIO, so their timings, ports and
# connection ids differ per capture and only what an observation is *supposed to
# report* can be pinned. What is different here is that two of the checks are
# corpus-wide rather than per scenario, because they are the claims the whole
# dialect rests on:
#
#   1. **every `op` is a table value.** Not one observation over 51 traces may
#      carry a route with a slash, a query or a percent-escape in it — that is
#      what "the cardinality of `op` is bounded by construction" (РS2) looks
#      like from the outside, and it is checked on real traffic rather than only
#      on the generated paths of test_s3_op.c.
#   2. **no object key is ever a label.** The corpus deliberately contains keys
#      with spaces, UTF-8, `+=&?#`, twelve segments and a 200-byte segment
#      (`encoded-keys.lkt`); none of them may appear in a bucket or user label.
set -u

LKT="$1"
DIR="$2"
fails=0

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
    got=$(printf '%s\n' "$out" | grep -c '^http ')
    [ "$got" = "$1" ] || fail "expected $1 observations, got $got"
}

# nroute <op> <n> — the operation appears n times
nroute() {
    got=$(printf '%s\n' "$out" | grep -c " route=$1 ")
    [ "$got" = "$2" ] || fail "expected $2 × $1, got $got"
}

for trace in "$DIR"/*/*.lkt; do
    base=$(basename "$trace" .lkt)
    stand=$(basename "$(dirname "$trace")")
    # `vhost` was recorded against a stand with MINIO_DOMAIN=localhost, so it is
    # the one trace that needs the flag — exactly as a real deployment does
    # (РS3: the server's configuration decides, so ours has to as well).
    case "$base" in
    vhost) out=$("$LKT" --proto s3 --s3-domain localhost "$trace" 2>&1) ;;
    *) out=$("$LKT" --proto s3 "$trace" 2>&1) ;;
    esac
    [ $? -eq 0 ] || fail "lkt_queries exited nonzero"

    lacks "REPLAY FAILED"
    lacks " unknown=[1-9]"

    # --- РS2, corpus-wide: the operation is a name, never a path ----------
    bad=$(printf '%s\n' "$out" | sed -n 's/^http .* route=\([^ ]*\) .*/\1/p' |
          grep -Ev '^[A-Za-z0-9]+$' | head -1)
    [ -n "$bad" ] && fail "route is not a table value: '$bad'"

    # --- РS3/РS4/privacy, corpus-wide: neither label is ever a key --------
    # A bucket name cannot contain `/`, `%`, `?` or an upper-case letter by the
    # S3 rules, and an access key cannot contain them either; a label that does
    # is a piece of a path that got in.
    bad=$(printf '%s\n' "$out" | sed -n 's/^http .* host=\([^ ]*\) .*/\1/p' |
          grep -Ev '^(-|other|[a-z0-9][a-z0-9.-]*)$' | head -1)
    [ -n "$bad" ] && fail "bucket label is not a bucket name: '$bad'"
    bad=$(printf '%s\n' "$out" | sed -n 's/^http .* user=\([^ ]*\) .*/\1/p' |
          grep -E '[/%?]' | head -1)
    [ -n "$bad" ] && fail "user label carries path bytes: '$bad'"

    case "$stand/$base" in
    # The one trace built to be rejected: a `PROPFIND`, a traversal, and TLS
    # bytes on a plaintext port. Everything else must be clean — the four-node
    # pool and the decrypted TLS traces included.
    minio/garbage) has " parse_errors=[1-9]" ;;
    *) has " parse_errors=0 " ;;
    esac

    case "$stand/$base" in
    # --- the base case: РS2 + РS3 + РS4 in one line ----------------------
    minio/get)
        nobs 1
        has '^http .* method=GET status=200 .* route=GetObject target=/lkbucket/small.bin$'
        has '^http .* out=1024 obj=1024 host=lkbucket user=lkroot '
        # Every S3 response carries the id `mc admin trace` reports, which is
        # what makes the МS4 accuracy bench a per-request comparison.
        has '^http .* reqid=[0-9A-F]{16} '
        ;;
    minio/put)
        nobs 1
        has '^http .* method=PUT status=200 .* route=PutObject '
        has '^http .* in=8192 out=0 obj=8192 '
        ;;
    # --- РS6: two counts for one upload ----------------------------------
    minio/chunked-put)
        # The measurement §"Two sizes" of the notes rests on: 1050102 bytes of
        # signed chunk stream carrying 1048576 bytes of object. A size histogram
        # built on the first number would move with the client's chunk size.
        nobs 1
        has '^http .* route=PutObject .*'
        has '^http .* in=1050102 out=0 obj=1048576 '
        ;;
    minio/mc-basic)
        # minio-go sends `aws-chunked` for *every* upload and never sends
        # `Content-Encoding: aws-chunked` with it — 1198 on the wire for a
        # 1024-byte object. Keying the detection on the header the notes warn
        # about would make this line read `obj=1198`.
        has '^http .* in=1198 out=0 obj=1024 .* route=PutObject '
        nroute GetBucketLocation 5
        nroute DeleteObjects 1
        ;;
    minio/awscli-basic | minio/boto3-basic)
        # The other main path: a precomputed checksum, an ordinary body and
        # `Expect: 100-continue`, so the two counts agree by arithmetic.
        has '^http .* route=PutObject '
        bad=$(printf '%s\n' "$out" | grep ' route=PutObject ' |
              sed -n 's/^http .* in=\([0-9]*\) out=[0-9]* obj=\([0-9]*\) .*/\1 \2/p' |
              awk '$1 != $2' | head -1)
        [ -n "$bad" ] && fail "an unchunked upload reported two sizes: '$bad'"
        ;;
    minio/copy)
        # Server-side copy: the bytes never cross the wire, the operation and
        # the status still do (a documented blind spot for `bytes_*` only).
        nobs 1
        has '^http .* method=PUT status=200 .* route=CopyObject '
        has '^http .* in=0 '
        ;;
    # --- РS4: who made the request ---------------------------------------
    minio/presigned)
        # No `Authorization` at all — the credential is in the query, percent-
        # encoded, and the label is the same one a header would have given.
        nobs 1
        has '^http .* user=lkroot .* route=GetObject '
        ;;
    minio/presigned-expired)
        # An expired presigned URL is still a named caller: the extractor runs
        # on the request, not on the outcome.
        nobs 1
        has '^http .* status=403 .* user=lkroot .* err=AccessDenied '
        ;;
    minio/badsig)
        # And so is a wrong signature — "who is hammering us with bad
        # credentials" is the question this answers.
        nobs 1
        has '^http .* status=403 .* user=lkroot .* err=SignatureDoesNotMatch '
        ;;
    minio/anon)
        # No credential carrier at all: `-`, and not an invented identity.
        has '^http .* status=403 .* user=- .* err=AccessDenied '
        # The signature is never a label whatever happens.
        lacks 'user=[0-9a-f]{64}'
        ;;
    # --- РS3: the two addressing forms -----------------------------------
    minio/vhost)
        # Virtual-host style: the bucket is in the Host and the whole path is
        # the key, so this is a GetObject of `lkbucket/small.bin` and not a
        # listing of a bucket called `small.bin`.
        nobs 1
        has '^http .* host=lkbucket .* route=GetObject target=/small.bin$'
        ;;
    minio/bucket-names)
        # The strongest statement РS3 can make, and it is the server's: every
        # name MinIO answered `400 InvalidBucketName` is a name our validator
        # refused too, and every name it routed became a label. The two never
        # disagree about what a bucket is.
        nobs 14
        [ "$(printf '%s\n' "$out" | grep -c 'host=other .* err=InvalidBucketName')" = 11 ] ||
            fail "the validator and the server disagree about a bucket name"
        has '^http .* host=abc '
        has '^http .* host=a-b.c '
        lacks 'host=(AB|a_b_c|192.168.1.1|-bucket|bucket\.|\.bucket)'
        ;;
    # --- РS5: the code the status cannot express -------------------------
    minio/errors)
        nobs 4
        # Two 404s that are not the same failure — the whole reason a body byte
        # is looked at.
        has '^http .* status=404 .* err=NoSuchKey .* route=GetObject '
        has '^http .* status=404 .* err=NoSuchBucket '
        # A HEAD error has no body; MinIO's own header fills the gap.
        has '^http .* method=HEAD status=404 .* out=0 obj=0 .* err=NoSuchKey '
        has '^http .* status=403 .* err=SignatureDoesNotMatch '
        ;;
    minio/boto3-errors)
        nobs 4
        has '^http .* method=HEAD status=404 .* err=NoSuchKey '
        has '^http .* err=NoSuchBucket .* route=ListObjectsV2 '
        ;;
    minio/subresources)
        # MinIO's "not configured" family, each with its own code behind one
        # status: this is what a `404` panel looks like without the body.
        has '^http .* err=NoSuchTagSet '
        has '^http .* err=ServerSideEncryptionConfigurationNotFoundError '
        has '^http .* err=ReplicationConfigurationNotFoundError '
        ;;
    # --- РS2: the whole taxonomy on a live server ------------------------
    minio/ops)
        # `clients/ops.py` fires one request per row of the table. Not one of
        # them may land in `other`, and the four `/minio/…` probes around them
        # must land in `internal` — which is the МS1 acceptance criterion in
        # two lines.
        lacks ' route=other '
        nroute internal 4
        [ "$(printf '%s\n' "$out" | grep -oE ' route=[A-Za-z0-9]+ ' | sort -u | wc -l)" -ge 45 ] ||
            fail "fewer than 45 distinct operations on the taxonomy trace"
        ;;
    minio/list)
        nroute ListObjectsV2 2
        nroute ListObjects 1
        nroute ListObjectVersions 1
        ;;
    minio/multipart)
        # The four operations that share `?uploadId` and are told apart by the
        # method alone.
        nroute CreateMultipartUpload 1
        nroute UploadPart 3
        nroute ListParts 1
        nroute CompleteMultipartUpload 1
        ;;
    minio/multipart-abort)
        nroute AbortMultipartUpload 1
        nroute ListMultipartUploads 1
        ;;
    minio/delete-objects)
        # One operation, not N deletions: the keys are in a request body we do
        # not read (§1 of the plan).
        nroute DeleteObjects 1
        ;;
    minio/select)
        # An event-stream response is counted as bytes and closed at end of
        # body; the events inside are not parsed.
        nroute SelectObjectContent 1
        ;;
    # --- MinIO's own surface (РS2) ---------------------------------------
    minio/internal | minio/health)
        # Everything under `/minio/` is the server's own API: one operation, no
        # bucket, and never a name that suggests otherwise. On a single node
        # `/minio/storage/…` answers `404 NoSuchBucket` for a bucket called
        # `minio`, which is exactly the misreading the prefix check prevents.
        lacks ' route=(GetObject|ListObjects|ListBuckets) '
        lacks ' host=minio '
        has ' route=internal '
        ;;
    # --- privacy: the keys the corpus was built to carry ------------------
    minio/encoded-keys)
        # Spaces, UTF-8, `+=&?#`, twelve segments, a 200-byte segment and a
        # double-encoded slash — 21 observations, three operations, one bucket.
        nobs 21
        nroute PutObject 7
        nroute GetObject 7
        nroute HeadObject 7
        lacks '(host|user|route)=[^ ]*(%|/|encoded|leaf)'
        ;;
    # --- degradations, unchanged from the HTTP track ----------------------
    minio/garbage)
        # A traversal is a key and only a key; an unknown method is `other`;
        # neither invents an operation.
        has '^http .* route=other '
        has '^http .* route=GetObject target=/lkbucket/\.\./\.\./etc/passwd$'
        ;;
    minio/torn-body | minio/abort-midbody)
        has ' parse_errors=0 '
        ;;
    minio/warp-mixed)
        # Recorded under `--capture-limit 256`, which is *below* the 405..583
        # bytes an S3 head measures: every head is cut short, every direction
        # resyncs, and no observation is invented from half a head. The РH14
        # default of 2048 is what this trace argues for, and leaving it here
        # keeps the argument checkable.
        nobs 0
        has ' resyncs=[1-9]'
        has ' parse_errors=0 '
        ;;
    minio/keepalive)
        nobs 50
        lacks 'flags=0x80' # sequential requests are not pipelining
        ;;
    minio/pipelined)
        nobs 4
        ;;
    minio/huge-head-cap2048 | minio/get-cap2048)
        # The РH14 budget against the heads MinIO actually sends: 2048 covers
        # every one of them, so these read exactly like their uncapped twins.
        nobs 1
        has ' parse_errors=0 '
        lacks ' route=other '
        ;;
    minio/continue)
        # `Expect: 100-continue`: the interim does not close the unit, and the
        # upload interval contains a server round trip, so it is flagged out of
        # the upload family (РH5).
        nobs 1
        has '^http .* status=200 .* flags=0x[0-9a-f]*4[0-9a-f]{2} '
        ;;
    # --- the cluster's own traffic (§1 "не входит") -----------------------
    dist/grid-idle)
        # Twelve connections of pure inter-node websocket: `101` then binary
        # msgp, so nothing is framed and nothing is invented.
        nobs 0
        ;;
    dist/s3-and-grid | dist/put-and-grid | dist/keepalive-and-grid)
        # A client's operations are observed; the fan-out they cause is not an
        # S3 API and produces none.
        has ' parse_errors=0 '
        lacks ' route=other '
        ;;
    # --- TLS (РS8, the gate МS0 opened) -----------------------------------
    tls/ciphertext)
        # A handshake record where a request line belongs: recognised, and not
        # one observation invented out of encrypted bytes.
        nobs 0
        has ' parse_errors=0 '
        ;;
    tls/decrypted | tls/decrypted-get)
        # The same load through the Go uprobe channel on MinIO's *stripped*
        # binary: ordinary observations, operations, buckets, access keys and
        # error codes, exactly as the plaintext traces give.
        has '^http .* host=lkbucket user=lkroot .* route=GetObject '
        has '^http .* err=(NoSuchBucket|SignatureDoesNotMatch) '
        ;;
    esac
done

# --- МS2 (РS7): the exposition the corpus produces -------------------------
# The same replay, teed into the real aggregator and dumped once over every
# trace. This is what a metric consumer sees, and it can only be checked here:
# the per-observation view above says nothing about which *family* a number
# landed in, under which label keys, or whether the result is a valid scrape.
trace="metrics"
out=$("$LKT" --proto s3 --quiet --metrics "$DIR"/*/*.lkt 2>&1)

for fam in requests_total request_duration_seconds_count ttfb_seconds_count \
           request_upload_seconds_count errors_total bytes_total \
           object_size_bytes_count; do
    has "^latkit_s3_$fam\{"
done
has '^latkit_s3_internal_requests_total [1-9]'

# The S3 nouns, on the families РS7 names them for.
has '^latkit_s3_requests_total\{op="GetObject",method="GET",bucket="lkbucket",user="lkroot",proto="s3",status="2xx"\}'
has '^latkit_s3_request_duration_seconds_count\{op="PutObject",method="PUT",bucket="lkbucket",'

# `op` is a table value everywhere it is printed — the closed-set property of
# РS2, restated where it actually protects cardinality. No slash, no query, no
# percent-escape, and above all no object key.
bad=$(printf '%s\n' "$out" | grep -oE 'op="[^"]*"' | sort -u | grep -E '/|\?|%' | head -1)
[ -n "$bad" ] && fail "an S3 metric label carries a path: '$bad'"

# The failure has a name, not a status (РS5): both 404s of the corpus are in
# the error counter under the code that tells them apart.
has '^latkit_s3_errors_total\{s3code="NoSuchKey",'
has '^latkit_s3_errors_total\{s3code="NoSuchBucket",'
has '^latkit_s3_errors_total\{s3code="SignatureDoesNotMatch",'
lacks '^latkit_s3_errors_total\{s3code="404"'

# The object size is the object's, not the signed stream's (РS6): chunked-put
# carries 1050102 bytes on the wire and 1048576 of object, and the corpus has
# exactly one such upload — so the distribution's sum must not contain the
# framing overhead.
has '^latkit_s3_object_size_bytes_bucket\{op="PutObject".*le="1048576"\} [1-9]'
bad=$(printf '%s\n' "$out" | grep -E '^latkit_s3_object_size_bytes_bucket\{op="(ListObjectsV2|ListObjects|DeleteObjects|CompleteMultipartUpload|HeadObject|CopyObject)"' | head -1)
[ -n "$bad" ] && fail "a non-object payload reached the object-size histogram: '$bad'"

# The object grid, not the response-size one (hist.h): 1 KiB … 1 TiB.
has '^latkit_s3_object_size_bytes_bucket\{.*le="1099511627776"\}'
lacks '^latkit_s3_object_size_bytes_bucket\{.*le="64"\}'

# MinIO's own surface is counted and appears in nothing else (РS2) — the corpus
# has 169 such requests across the health, internal and distributed traces.
lacks 'op="internal"'

# Nothing S3 reaches the database or http families, and the PG-shaped counters
# stay at zero — the profile split of РH10 with a third profile in it.
lacks '^latkit_http_'
lacks '^latkit_quer(y|ies)_.*proto="s3"'
has '^latkit_queries_other_total 0$'

# A valid exposition prints every series exactly once: the check that catches a
# family whose label set dropped a key that is part of its identity.
dup=$(printf '%s\n' "$out" | grep -v '^#' | grep '^latkit_' |
      sed 's/ [^ ]*$//' | sort | uniq -d | head -1)
[ -n "$dup" ] && fail "duplicate series in the exposition: '$dup'"

# And no object key, anywhere in the dump — the corpus-wide privacy invariant of
# МS1, restated over the metric labels the МS2 families introduce. Structural
# rather than by name, because a bucket may legitimately be called `small.bin`
# (a path-style `GET /small.bin` is a listing of a bucket by that name, РS3):
# every label value here is an operation from the table, a method, a validated
# bucket name, an access key or a bounded enum, and not one of those alphabets
# contains a slash, a percent, a space or a traversal. The corpus deliberately
# contains keys that contain all four.
bad=$(printf '%s\n' "$out" | grep '^latkit_s3_' | grep -oE '[a-z0-9_]+="[^"]*"' |
      sort -u | grep -E '="[^"]*([/% ]|\.\.)' | head -1)
[ -n "$bad" ] && fail "an object key reached a metric label: '$bad'"

echo "---"
if [ "$fails" -eq 0 ]; then
    echo "s3 МS1/МS2: trace expectations met"
    exit 0
fi
echo "$fails check(s) failed"
exit 1
