# notes-s3proto: S3 on the wire — operations, buckets, credentials, errors, MinIO

Design notes backing the MinIO track ([PLAN-MINIO.md](../PLAN-MINIO.md),
Russian, decisions РS1–РS8). Same genre as [notes-pgproto](notes-pgproto.md),
[notes-myproto](notes-myproto.md) and [notes-httpproto](notes-httpproto.md),
and like the last two written *before* the code.

**This is a delta.** S3 is HTTP/1.1 with a particular reading of the path, the
query and a handful of headers; framing, the unit lifecycle, the four timings,
the body-length decision list, resync and the blind zones are
[notes-httpproto](notes-httpproto.md) and are not repeated here. What follows is
only what the `s3` dialect (РS1, `struct lk_http_dialect`) has to know that the
base dialect does not: how a request becomes an **operation** instead of a
templated route, where the **bucket** and the **access key** live, how an
**S3 error code** is read out of a response body, and why an upload has two
sizes.

Primary sources: the Amazon S3 API reference (operation set and error codes),
AWS Signature Version 4 (the two credential carriers and the `aws-chunked`
framing), RFC 9110/9112 for everything underneath. Every claim that matters is
cross-checked against `tests/traces/s3/` — the МS0 corpus, recorded from MinIO
`RELEASE.2025-09-07T16-13-09Z` (go1.24.6) driven by six clients — and the file
says which trace proves what.

Scope guard: **the S3 HTTP API, server side**, plaintext or through the
existing TLS channel. Everything the HTTP track excludes is excluded here for
the same reasons; what S3 adds to that list is in §"Blind spots".

## An exchange, annotated

```
 PUT /photos/2026/cat.jpg HTTP/1.1                     <- bucket "photos", key "2026/cat.jpg"
 Host: minio.internal:9000                             <- path-style: bucket is in the path
 Content-Length: 1050102                               <- bytes on the wire
 X-Amz-Content-Sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD   <- body is aws-chunked
 X-Amz-Decoded-Content-Length: 1048576                 <- bytes of object
 X-Amz-Date: 20260815T124726Z
 Authorization: AWS4-HMAC-SHA256 Credential=AKIA…/20260815/us-east-1/s3/aws4_request,
                SignedHeaders=host;…, Signature=74b6a953…      <- access key, and only it

 400;chunk-signature=a82416cb…\r\n <1024 bytes> \r\n   <- signed chunk framing
 0;chunk-signature=ae640020…\r\n\r\n                   <- terminator

 HTTP/1.1 200 OK
 Content-Length: 0
 ETag: "8adca938e4324fcc79dc2279eb53f597"
 X-Amz-Request-Id: 18CBFB5B237EC7FE                    <- the join key for the accuracy bench
 Server: MinIO
```

The whole of the S3 dialect is in the annotations: `op=PutObject`,
`bucket=photos`, `user=AKIA…`, `bytes_in` counted twice (1050102 on the wire,
1048576 of object), and a key that appears in three places on the wire and in
none of the labels.

Verbatim in `tests/traces/s3/minio/chunked-put.lkt` and, from a real client, in
`mc-basic.lkt`.

## Addressing: two forms, one bucket (РS3)

```
 path-style          GET /photos/2026/cat.jpg     Host: minio.internal:9000
 virtual-host-style  GET /2026/cat.jpg            Host: photos.minio.internal:9000
```

The decision is made on the **Host**, not the path:

1. Strip the port from `Host` (or from the absolute-form authority, which wins
   over `Host` exactly as in the base dialect).
2. If the host has a label prefix in front of a configured domain suffix
   (`bucket.s3.example.com`), the first label is the bucket and the whole path
   is the key.
3. Otherwise the first path segment is the bucket and the rest is the key.

There is no way to tell the two apart from the request alone — `GET /x` against
`Host: photos.minio.internal` is `photos/x` if the server was told its domain
and bucket `x` (a `ListObjects`!) if it was not. **The server's configuration
decides, so ours has to as well**: the dialect takes an optional domain-suffix
list (`--s3-domain`, repeatable, empty by default), and with no suffix
configured every request is read path-style. That is the safe default: MinIO
itself only enables virtual-host-style when `MINIO_DOMAIN` is set, and refuses
the form otherwise (`vhost.lkt` was recorded against a stand with
`MINIO_DOMAIN=localhost`; without it the same request answers `404
NoSuchBucket`).

**A bucket name goes into a label only after validation.** It arrives from the
wire, so it is checked against the S3 naming rules before it can become a
series:

| Rule | |
|---|---|
| length | 3–63 bytes |
| alphabet | `a-z`, `0-9`, `-`, `.` |
| ends | first and last byte alphanumeric |
| not | four dot-separated numbers (an IPv4 address) |

Anything else → `bucket="other"`. This is not paranoia about MinIO: it is what
keeps a hostile or broken client from writing arbitrary bytes into a Prometheus
label. MinIO enforces the same rules and answers `400 InvalidBucketName`:
`AB`, `a`, `ab`, `a_b_c`, `192.168.1.1`, a 64-byte name, `bucket.`, `.bucket`,
`bucket..name`, `-bucket` and `buck$et` are all refused, while `abc`, `a-b.c`
and a 63-byte name are routed (`bucket-names.lkt`). So a name that passes our
validator is a name the server would have accepted too, and the two never
disagree about what a bucket is.

## The operation table (РS2)

A URL has no bounded identity, which is why the base dialect needs the
templating heuristic of РH7 and the top-K registry behind it. S3 does have one:
the API is a closed set of operations, and *which* operation a request is can be
read off `(method, path shape, query keys)` alone. So for this dialect the
heuristic is **off**, and `op` is a value from the table below plus `internal`
and `other`. Cardinality is bounded by construction, and the object key — the
most sensitive part of an S3 request — is never even a candidate for a label.

Three path shapes, after the bucket has been located (§"Addressing"):

```
 /                    service level
 /{bucket}            bucket level          (a trailing slash is not a key)
 /{bucket}/{key}      object level          (key = everything after the first /)
```

Selection, in order:

1. Path begins with `/minio/` → `op="internal"`, counted and never observed
   (§"MinIO's own surface").
2. **The first recognised sub-resource query key** picks the operation, together
   with the method: `?acl`, `?tagging`, `?policy`, `?versioning`, `?lifecycle`,
   `?location`, `?notification`, `?encryption`, `?replication`, `?object-lock`,
   `?cors`, `?policyStatus`, `?accelerate`, `?logging`, `?requestPayment`,
   `?website`, `?publicAccessBlock`, `?attributes`, `?retention`,
   `?legal-hold`, `?restore`, `?select`, `?delete`, `?uploads`, `?uploadId`,
   `?versions`, `?list-type`. Keys are compared case-sensitively and only their
   *presence* matters — never their value, with the single exception of
   `list-type=2` (V2 vs V1 listing), which is a documented enum and not user
   input.
3. Otherwise the method and the shape decide: `GET /{bucket}` is a V1
   `ListObjects`, `PUT /{bucket}/{key}` is a `PutObject` — unless it carries
   `x-amz-copy-source`, which makes it a `CopyObject`.
4. Nothing matched → `op="other"`.

Two headers, and only two, participate: `x-amz-copy-source` (Put→Copy,
UploadPart→UploadPartCopy) and, for the record, `x-amz-object-attributes`,
which `GetObjectAttributes` requires but does not need to be *identified* by.

### The table

Rows that share a selector are folded together by method.
`tests/traces/s3/clients/ops.py` fires 53 of them at a live MinIO and the whole
run is recorded in `minio/ops.lkt`; the status column is what MinIO answered on
the МS0 stand, and it is here because "S3 has this operation" and "MinIO routes
it" are different claims. The one row `ops.py` does not fire is `PostObject`,
which needs a signed browser policy document — a bare `curl -F` form upload
answers `400`, which is enough to confirm the route exists.

| Operation | Method | Shape | Selector | MinIO answered |
|---|---|---|---|---|
| ListBuckets | GET | `/` | — | 200 |
| CreateBucket | PUT | `/{bucket}` | — | 200 / 409 `BucketAlreadyOwnedByYou` |
| DeleteBucket | DELETE | `/{bucket}` | — | 204 / 409 `BucketNotEmpty` |
| HeadBucket | HEAD | `/{bucket}` | — | 200 |
| ListObjects | GET | `/{bucket}` | — | 200 |
| ListObjectsV2 | GET | `/{bucket}` | `?list-type=2` | 200 |
| ListObjectVersions | GET | `/{bucket}` | `?versions` | 200 |
| ListMultipartUploads | GET | `/{bucket}` | `?uploads` | 200 |
| DeleteObjects | POST | `/{bucket}` | `?delete` | 200 |
| PostObject | POST | `/{bucket}` | — (form upload) | 400 without a policy |
| GetBucketLocation | GET | `/{bucket}` | `?location` | 200 |
| GetBucketAcl / PutBucketAcl | GET/PUT | `/{bucket}` | `?acl` | 200 |
| GetBucketPolicy / Put / Delete | GET/PUT/DELETE | `/{bucket}` | `?policy` | 404 `NoSuchBucketPolicy` |
| GetBucketPolicyStatus | GET | `/{bucket}` | `?policyStatus` | 200 |
| GetBucketVersioning / Put | GET/PUT | `/{bucket}` | `?versioning` | 200 |
| GetBucketTagging / Put / Delete | GET/PUT/DELETE | `/{bucket}` | `?tagging` | 404 `NoSuchTagSet` / 200 / 204 |
| GetBucketLifecycleConfiguration / Put / Delete | GET/PUT/DELETE | `/{bucket}` | `?lifecycle` | 404 `NoSuchLifecycleConfiguration` |
| GetBucketNotificationConfiguration / Put | GET/PUT | `/{bucket}` | `?notification` | 200 |
| GetBucketEncryption / Put / Delete | GET/PUT/DELETE | `/{bucket}` | `?encryption` | 404 `ServerSideEncryptionConfigurationNotFoundError` |
| GetBucketReplication / Put / Delete | GET/PUT/DELETE | `/{bucket}` | `?replication` | 404 `ReplicationConfigurationNotFoundError` |
| GetObjectLockConfiguration / Put | GET/PUT | `/{bucket}` | `?object-lock` | 404 `ObjectLockConfigurationNotFoundError` |
| GetBucketCors / Put / Delete | GET/PUT/DELETE | `/{bucket}` | `?cors` | 404 `NoSuchCORSConfiguration` |
| GetBucketRequestPayment | GET | `/{bucket}` | `?requestPayment` | 200 |
| GetBucketLogging | GET | `/{bucket}` | `?logging` | 200 |
| GetBucketWebsite / Put / Delete | GET/PUT/DELETE | `/{bucket}` | `?website` | 404 `NoSuchWebsiteConfiguration` |
| GetBucketAccelerateConfiguration | GET | `/{bucket}` | `?accelerate` | 200 |
| GetPublicAccessBlock | GET | `/{bucket}` | `?publicAccessBlock` | **501 NotImplemented** |
| GetObject | GET | `/{bucket}/{key}` | — | 200 / 206 with `Range` |
| HeadObject | HEAD | `/{bucket}/{key}` | — | 200 |
| PutObject | PUT | `/{bucket}/{key}` | — | 200 |
| CopyObject | PUT | `/{bucket}/{key}` | `x-amz-copy-source:` | 200 |
| DeleteObject | DELETE | `/{bucket}/{key}` | — | 204 |
| GetObjectAcl / Put | GET/PUT | `/{bucket}/{key}` | `?acl` | 200 |
| GetObjectTagging / Put / Delete | GET/PUT/DELETE | `/{bucket}/{key}` | `?tagging` | 200 / 200 / 204 |
| GetObjectRetention / Put | GET/PUT | `/{bucket}/{key}` | `?retention` | 400 `InvalidRequest` (lock off) |
| GetObjectLegalHold / Put | GET/PUT | `/{bucket}/{key}` | `?legal-hold` | 400 `InvalidRequest` (lock off) |
| GetObjectAttributes | GET | `/{bucket}/{key}` | `?attributes` | 200 |
| RestoreObject | POST | `/{bucket}/{key}` | `?restore` | 403 `InvalidObjectState` |
| SelectObjectContent | POST | `/{bucket}/{key}` | `?select&select-type=2` | 200, event stream |
| CreateMultipartUpload | POST | `/{bucket}/{key}` | `?uploads` | 200 |
| UploadPart | PUT | `/{bucket}/{key}` | `?partNumber&uploadId` | 200 |
| UploadPartCopy | PUT | `/{bucket}/{key}` | `?partNumber&uploadId` + `x-amz-copy-source:` | 200 |
| ListParts | GET | `/{bucket}/{key}` | `?uploadId` | 200 |
| CompleteMultipartUpload | POST | `/{bucket}/{key}` | `?uploadId` | 200 |
| AbortMultipartUpload | DELETE | `/{bucket}/{key}` | `?uploadId` | 204 |

Counting the method variants that share a selector, that is ~70 names for 28
selectors; the plan's "~45" was the right order of magnitude. What matters for
cardinality is that the set is closed and the classifier is a lookup, not a
guess.

Notes the table cannot hold:

- **`?uploadId` alone is ambiguous by method and only by method.** GET is
  `ListParts`, POST is `CompleteMultipartUpload`, DELETE is
  `AbortMultipartUpload`, PUT (with `?partNumber`) is `UploadPart`. Four
  operations, one query key: the method is not decoration here.
- **A trailing slash on a bucket is still bucket level.** `mc` sends
  `GET /lkbucket/?location=`, aws-cli sends `GET /lkbucket?location=`; both are
  `GetBucketLocation` (`mc-basic.lkt`).
- **`?delete` is a POST with the keys in the body.** We never read them (§1 of
  the plan): `DeleteObjects` reports one operation, not N deletions, and the
  count of objects deleted is not observable without parsing a request body.
- **`?select` responses are an event stream** — chunked, `application/octet-stream`,
  a sequence of framed messages. The unit closes at end of body like any other;
  the body is never parsed (`select.lkt`).
- Query keys we do not recognise are ignored, not fatal: an unknown key on a
  known shape still classifies (a future `?newthing` on `/{bucket}/{key}` is a
  `GetObject` until the table learns better). The *reverse* — an unknown shape —
  is `other`, and the share of `other` is the dashboard's signal that the table
  has aged (risk 5).

### MinIO's own surface, which is never an S3 operation

Everything under `/minio/` is the server's own API and is counted (`op="internal"`)
without becoming an observation:

| Path | What it is | On the МS0 stand |
|---|---|---|
| `/minio/health/live`, `/health/ready`, `/health/cluster` | unauthenticated probes; every deployment runs them | 200, `internal.lkt`, `health.lkt` |
| `/minio/admin/v3/*` | the admin API (info, trace, heal, …) | 200; `?trace` is an endless `text/event-stream` |
| `/minio/storage/…`, `/minio/lock/…`, `/minio/peer/…` | inter-node RPC of a distributed pool | on a single node these fall through to the S3 router and answer `404 NoSuchBucket` for a bucket named `minio` — which is exactly why the `/minio/` prefix is checked *before* the shape rules |
| `/minio/grid/…` | the websocket multiplexer between nodes | `101` then binary msgp: the connection becomes a blind zone by the base dialect's Upgrade rule (РH4) |

On a four-node pool this is not a rounding error: under a warp run **79 % of the
data events and 90 % of the connections on the S3 port were the cluster talking
to itself** (recon item 6). They cost ringbuf budget and CPU, and they must not
appear in any metric that says "requests".

## Credentials (РS4)

Three shapes, and a request is exactly one of them.

**Header auth**, the normal case:

```
 Authorization: AWS4-HMAC-SHA256 Credential=<AK>/<yyyymmdd>/<region>/s3/aws4_request,
                SignedHeaders=<h;h;h>, Signature=<64 hex>
```

The parser has to survive two spellings seen in the corpus: aws-cli and boto3
write `, ` between the three components, minio-go (`mc`, `warp`, the Go SDK)
writes a bare `,` with no space. Take `Credential=` up to the first `/`; that is
the access key ID — the public half of the pair, the thing an audit log records.
Everything else on that line (`Signature`, `SignedHeaders`) is read past and
never retained.

**Presigned**, where the credential is in the query string:

```
 GET /photos/cat.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256
     &X-Amz-Credential=<AK>%2F20260815%2Fus-east-1%2Fs3%2Faws4_request
     &X-Amz-Date=…&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=…
```

`X-Amz-Credential` is percent-encoded (`%2F` for the separators) and has to be
decoded far enough to cut at the first separator. No `Authorization` header at
all (`presigned.lkt`, `presigned-expired.lkt`).

**Anonymous**: neither carrier → `user="-"`. A public bucket, a health probe, a
misconfigured client (`anon.lkt`).

Three details that only a live server teaches:

- **A refused request still identifies its caller.** `403 SignatureDoesNotMatch`
  carries a complete `Credential=`; so does an expired presigned URL. The label
  extractor runs on the request, not on the outcome, which is what makes "who is
  hammering us with bad credentials" answerable (`badsig.lkt`).
- **STS credentials look identical.** A temporary access key is the same field
  with a different value, plus `X-Amz-Security-Token`. It is never emitted, and
  the ephemerality is a cardinality problem, not a parsing one: the existing
  `max_session_dims` spill to `user="other"` is what bounds it, and `--s3-user
  off` turns the dimension off entirely.
- **SigV2 exists and MinIO refuses it.** `Authorization: AWS <AK>:<sig>` gets
  `403 AccessDenied`. The dialect recognises the prefix well enough to take the
  access key out of it (it is the same public half), because a deployment
  migrating off SigV2 is exactly when you want the label.

What never leaves the agent, in any mode: `Signature`, the chunk signatures,
`X-Amz-Security-Token`, the secret (which is never on the wire at all), and the
object key.

## Errors (РS5)

An S3 error is an HTTP status *and* a code in an XML body:

```
 HTTP/1.1 403 Forbidden
 Content-Type: application/xml
 Content-Length: 433

 <?xml version="1.0" encoding="UTF-8"?>
 <Error><Code>SignatureDoesNotMatch</Code><Message>The request signature we
 calculated does not match…</Message><Key>small.bin</Key><BucketName>lkbucket
 </BucketName><Resource>/lkbucket/small.bin</Resource><RequestId>…</RequestId>
 <HostId>…</HostId></Error>
```

The status alone is not enough: `404` is `NoSuchKey`, `NoSuchBucket`,
`NoSuchTagSet`, `NoSuchLifecycleConfiguration` or six others; `400` is
`MalformedXML`, `InvalidRequest`, `InvalidBucketName`, `MetadataTooLarge`… and
they mean completely different things to whoever is on call. So for a response
with status ≥ 400 the framer hands the handler a **bounded prefix of the
response body** — the one case where any body byte is looked at — and the
handler reads `<Code>…</Code>` out of it.

Properties that make this affordable and safe:

- `<Code>` is the **first** child of `<Error>` in every response the corpus
  contains, so a prefix of a few hundred bytes always suffices; MinIO's error
  bodies are 300–450 bytes whole.
- The extracted code is matched against a dictionary of known S3 codes and
  anything else becomes `s3code="other"` — the same bounded-label discipline as
  everywhere else. The corpus alone yields about two dozen distinct codes; the
  AWS list is about a hundred.
- **The prefix contains the object key** (`<Key>`, `<Resource>`). It is read,
  matched, and dropped: it is never stored on the observation, never exported,
  never logged. This is the sharpest edge in the whole dialect and the reason
  the prefix is bounded and its lifetime is one function call.
- **A HEAD error has no body at all** — `404` with `Content-Length: 0`. There is
  nothing to read; it is a property of S3, not a gap in ours, and boto3 has the
  same problem (it reports the code for a failed `head_object` as the literal
  string `404`). **MinIO fills the gap with a header**: when it answers an error
  with no body it adds `X-Minio-Error-Code: NoSuchKey` and
  `X-Minio-Error-Desc`. Measured: present on `HEAD` errors, absent whenever
  there is an XML body to carry the code. So the dialect reads the header when
  it is there — free, since the head is parsed anyway — and falls back to the
  status when it is not, which is what a non-MinIO S3 server will give it
  (`errors.lkt`, `boto3-errors.lkt`, `s3fs.lkt`).
- A non-XML or truncated body (capture hole, budget) yields no code, same
  fallback. Never a parse error, never a dirty direction.

## Two sizes for one upload (РS6)

A `PutObject` or `UploadPart` body comes in one of three framings, and the
identifying header is `x-amz-content-sha256`:

| `x-amz-content-sha256` | Framing | Wire length | Object length |
|---|---|---|---|
| 64 hex digits, or `UNSIGNED-PAYLOAD` | plain body | `Content-Length` | the same |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` | `aws-chunked`, signed chunks | `Content-Length` | `x-amz-decoded-content-length` |
| `STREAMING-UNSIGNED-PAYLOAD-TRAILER` | `aws-chunked` + trailing checksum | `Content-Length` | `x-amz-decoded-content-length` |

`aws-chunked` is *not* `Transfer-Encoding: chunked` — it is a body format inside
a normal `Content-Length` body, and the HTTP framer must not try to interpret
it:

```
 400;chunk-signature=<64 hex>\r\n <0x400 bytes> \r\n
 400;chunk-signature=<64 hex>\r\n <0x400 bytes> \r\n
 0;chunk-signature=<64 hex>\r\n\r\n
```

The framer skips `Content-Length` bytes arithmetically as always, and the
dialect reports two numbers: bytes on the wire, and the logical object size. The
size histogram is built on the second one, because the first one depends on a
client's chunk size: the framing costs ~87 bytes per chunk, which is 0.13 % at
64 KB chunks and 17 % at 1 KB — `mc` putting a 1024-byte object sends
`Content-Length: 1198` (`mc-basic.lkt`). A size distribution that moves with the
client's buffer size is worthless.

Detection detail worth writing down because it costs an hour to rediscover:
**minio-go does not send `Content-Encoding: aws-chunked`.** It sends only the
`STREAMING-…` sha256 marker and `X-Amz-Decoded-Content-Length` (`mc-basic.lkt`,
`chunked-put.lkt`). Keying the detection on `Content-Encoding` would miss every
MinIO-client upload — which, on the МS0 stand, is *all* of them.

Who uses what, measured (recon item 4, and the client traces):

- **minio-go — `mc`, `warp`, MinIO's own SDK — streams `aws-chunked` for every
  upload**: 100 % of the PUTs in a warp run (1435 of 1435), 16 % of all
  requests.
- **aws-cli v2 and boto3 do not**: they precompute a CRC checksum
  (`x-amz-checksum-crc64nvme` / `-crc32`) and send an ordinary `Content-Length`
  body with `Expect: 100-continue` (`awscli-basic.lkt`, `boto3-basic.lkt`).
- So both paths are main paths, and which one you meet depends on the SDK, not
  on the object.

### The response side

MinIO answers with `Content-Length` for **every** object body — 8116 of 9006
responses under warp, with the remaining 890 being `204 No Content` deletes, and
**zero chunked responses in the whole run**. A response is chunked in exactly
three situations, none of which is object I/O:

1. **A gzipped XML listing.** MinIO compresses `application/xml` when the client
   offers `Accept-Encoding: gzip` (minio-go always does; aws-cli sends
   `identity`), and a compressed body has no known length, so Go frames it
   chunked — but only once it outgrows Go's 2 KB response buffer. Measured A/B
   on one 87 KB listing: `identity` → `Content-Length: 87059`, `gzip` →
   `Content-Encoding: gzip` + `Transfer-Encoding: chunked` (`gzip-listing.lkt`).
2. **`SelectObjectContent`** — `application/octet-stream`, an event stream.
3. **`/minio/admin/v3/trace`** — `text/event-stream`, endless.

Object bodies are never compressed (`Accept-Encoding: gzip` on an 8 MB object
still yields `Content-Length: 8388608`), so on the byte-heavy path the length is
always known in advance and the arithmetic body skip always applies.

## Timings, on an object store

The four timings of РH5 carry over unchanged, but their *meaning* separates in a
way it does not for a web API, which is the substance of §2 of the plan:

- `upload` (first request byte → last request byte) is the client pushing an
  object. On a 5 MB `UploadPart` it is most of the exchange.
- `ttfb` (last request byte → first response byte) is the server: erasure
  coding, disks, the peer fan-out on a distributed pool.
- `duration` (first request byte → last response byte) on a `GetObject` is
  dominated by how fast the *client* drains the body.

Putting all three in one histogram is how a slow disk and a slow client end up
indistinguishable, which is why РS7 keeps `duration`, `ttfb` and
`request_upload` as three families.

## MinIO specifics

- **`Expect: 100-continue` on uploads is common but not universal**: aws-cli
  and boto3 send it on every PUT and MinIO answers `100 Continue` before the
  final response; s3fs sends none. An interim response does not close a unit
  (base dialect, `continue.lkt`, `awscli-basic.lkt`, `s3fs.lkt`).
- **Request heads are ~400–600 bytes and capped at ~8 KB.** Measured over 9006
  requests of a warp run: min 405, p50 476, p99 579, max 583; responses 436–581.
  MinIO refuses a head larger than about 8 KB with `400 MetadataTooLarge` (the
  boundary is between 7000 and 7200 bytes of padding on top of a signed GET),
  which means S3 heads are *structurally* bounded, unlike browser HTTP. A 2048-byte
  per-call capture budget (РH14) covers every head the corpus contains with
  room to spare.
- **Some clients put file metadata in the head.** s3fs signs and sends
  `x-amz-meta-mtime`, `-uid`, `-gid`, `-mode`, `-atime`, `-ctime` on every
  upload (`s3fs.lkt`). They are user metadata, they count against MinIO's ~8 KB
  head limit, and — like every header that is not one of the six the dialect
  reads — they are never looked at.
- **Every response carries `X-Amz-Request-Id`** (and `X-Amz-Id-2`). This is the
  join key for the accuracy bench of МS4 (`mc admin trace` reports the same id)
  and the natural span attribute.
- **An anonymous refusal closes the connection** — without a `Connection: close`
  header. The unit is closed by `CONN_CLOSE`, and a second request on that
  connection gets an EOF, not an answer.
- **Rate-limit headers** (`X-Ratelimit-Limit`, `-Remaining`) are on every
  response and are not interesting to us; they are listed here only so nobody
  mistakes them for a throttling signal we should be reading.
- **The console is a different port** (`--console-address`, 9001 by convention)
  and is out of scope; capturing it would put a web UI's browser traffic into
  `latkit_s3_*`.
- **MinIO does not use `sendfile`/`splice`.** Twenty 8 MB `GetObject`s produced
  1585 `write(2)` calls and zero `sendfile`, `splice` or `copy_file_range`
  (recon item 3). The РH4 `BODY_UNSEEN` degradation, which nginx makes real,
  simply does not arise here: byte accounting on MinIO is exact.
- **All MinIO threads are called `minio`** (29 of 29 on the stand), and the
  executable is `/usr/bin/minio`. A single `--comm minio` covers the server, and
  the same name is what the Go TLS module scans for.

## Blind spots

Inherited from the HTTP track and unchanged: HTTP/2, websockets, `CONNECT`,
request and response bodies (except the error prefix of РS5), anything after a
capture hole until resync.

Specific to this dialect:

- **The grid.** `/minio/grid/…` upgrades to a websocket carrying binary msgp
  between cluster nodes. Blind by the Upgrade rule, and deliberately so: it is
  not an S3 API and has no operation.
- **Batch semantics.** `DeleteObjects` deletes N keys in one request; we report
  one operation. Same for the object list inside a `CompleteMultipartUpload`.
- **Server-side copy volume.** `CopyObject` and `UploadPartCopy` move data that
  never crosses the wire, so `bytes_*` under-report exactly the copy traffic.
  The operation, the status and the timings stay right.
- **Event-stream bodies** (`SelectObjectContent`, admin trace) are counted as
  bytes and closed at end of body; the events inside are not parsed. An admin
  trace stream never ends, so it is one unit for as long as it runs — another
  reason `/minio/` is `internal` and not an observation.
- **TLS depends entirely on the Go module** (РS8): MinIO is statically linked
  and maps no libssl, so `--tls auto` has nothing to attach to. See §"What the
  corpus proves" for the resolution.

## What the corpus proves

`tests/traces/s3/` (51 traces, three stands, 9.8 MB), and what each claim rests
on:

| Claim | Trace |
|---|---|
| both addressing forms reach the same object | `minio/get.lkt`, `minio/vhost.lkt` |
| the bucket-name rules are the server's, not ours | `minio/bucket-names.lkt` |
| the whole operation table routes on a real server | `minio/ops.lkt` (53 requests) |
| `aws-chunked` has two lengths, and minio-go omits `Content-Encoding` | `minio/chunked-put.lkt`, `minio/mc-basic.lkt` |
| SDK uploads are `Content-Length` + `100-continue` | `minio/awscli-basic.lkt`, `minio/boto3-basic.lkt` |
| a 403 still carries the access key | `minio/badsig.lkt` |
| presigned credentials live in the query | `minio/presigned.lkt`, `minio/presigned-expired.lkt` |
| anonymous requests exist and end the connection | `minio/anon.lkt` |
| `<Code>` is readable from a bounded prefix; HEAD has none | `minio/errors.lkt`, `minio/boto3-errors.lkt` |
| a listing is chunked only when gzipped | `minio/gzip-listing.lkt` |
| Select is an event stream | `minio/select.lkt` |
| `/minio/*` is a whole traffic class of its own | `minio/internal.lkt`, `minio/health.lkt`, `dist/grid-idle.lkt` |
| a cluster's own traffic dominates its S3 port | `dist/keepalive-and-grid.lkt`, recon item 6 |
| keys carry spaces, UTF-8, `+=&?#`, 200-byte segments | `minio/encoded-keys.lkt` |
| MinIO's TLS is decryptable through the Go uprobes | `tls/ciphertext.lkt` vs `tls/decrypted.lkt` |

The last one is the finding that unblocks МS3, and it was not a given: the
official MinIO image ships a **stripped** binary with no ELF symbol table at
all. `src/agent/go_pclntab.c` (М7 of the HTTP track) resolves
`crypto/tls.(*Conn).Write` and `.Read` in it anyway — 8 and 7 return sites — and
the decrypted traces carry plaintext records where the ciphertext trace carries
none. РS8 stands; the gate in МS3 is open.
