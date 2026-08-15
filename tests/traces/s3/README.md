# tests/traces/s3 — МS0 reference trace corpus (S3 / MinIO)

Raw `--record` (LKT1) traces of real S3 sessions against MinIO, captured with
the stock agent **before any S3 code exists** — the capture layer is
protocol-independent (`--port 9900`, whatever framer the default happens to be
runs and finds nothing), so `--record` writes the raw ringbuf records and
nothing interprets them. This corpus is the raw material for the МS1 unit tests
and МS4 replay fixtures, the seed corpus for the fuzzer, and the ground truth
[notes-s3proto](../../../docs/notes-s3proto.md) was cross-checked against
(PLAN-MINIO.md, этап МS0).

Each trace is one client session: `CONN_OPEN` + data events (both directions,
capture budget 8192 bytes per syscall unless the name or the table says
otherwise) + `CONN_CLOSE`. Little-endian, x86-64, kernel 7.0.0-27-generic,
MinIO `RELEASE.2025-09-07T16-13-09Z` (go1.24.6).

## Layout

```
minio/   single node, plaintext, :9900     — the operation matrix (44 traces)
dist/    four-node pool, plaintext, :9910  — the cluster's own traffic (4)
tls/     single node, TLS, :9902           — ciphertext, and the same load
                                             decrypted through the Go uprobes (3)
```

51 traces, 9.8 MB.

Ports: PLAN-MINIO.md writes `--port 9000=s3` and 9000 is what a MinIO
deployment uses; the corpus was recorded on 9900/9902/9910 only because the
recording host already had something on 9000. A port is the capture filter, not
part of what a trace means.

The single node runs with `MINIO_DOMAIN=localhost` — without it MinIO does not
accept virtual-host-style addressing at all and the `vhost` trace would be a
404. The distributed pool runs on a user-defined bridge network rather than the
host network, because MinIO refuses to form a cluster out of `127.0.0.1`
endpoints inside a container; nothing is published, so no docker-proxy sits in
the middle, and the kprobes see the containers' sockets regardless of netns.

## Scenarios

### `minio/` — the operation matrix

Driven by `clients/raw.py` (our own SigV4 signer over raw sockets) unless the
name says otherwise.

| Trace | What it exercises |
|---|---|
| `get` | the base case: `GET /bucket/key`, `Content-Length` both ways |
| `get-large` | 8 MB object — 129 send events, arithmetic body skip |
| `put` | 64 KB `PutObject` with `Content-Length` |
| `chunked-put` | 1 MB `aws-chunked` upload built by hand: wire 1050102, object 1048576 (РS6) |
| `continue` | `Expect: 100-continue` → `100` → the final response |
| `keepalive` | 50 `GetObject`s on one connection |
| `pipelined` | four requests in one write: in-flight depth > 1 |
| `vhost` | virtual-host-style: bucket in `Host`, key is the whole path (РS3) |
| `anon` | no credentials → `403 AccessDenied`, and MinIO closes the connection |
| `badsig` | valid `Credential=`, wrong signature → `403 SignatureDoesNotMatch` |
| `presigned` / `presigned-expired` | credentials in the query string → 200 / `403 AccessDenied` |
| `errors` | `NoSuchKey`, `NoSuchBucket`, a HEAD 404 with no body, a 403 |
| `multipart` | create → 3 × 5 MB parts → ListParts → complete |
| `multipart-abort` | create → one part → ListMultipartUploads → abort |
| `delete-objects` | `POST ?delete` with the keys in the request body (+ `Content-Md5`) |
| `copy` | `PUT` with `x-amz-copy-source`: no bytes on the wire |
| `list` | V2, V2 with prefix/delimiter/max-keys, V1, `?versions`, ListBuckets |
| `subresources` | 23 `?acl`/`?tagging`/`?policy`/… operations, bucket and object level |
| `internal` | `/minio/health/*`, `/minio/admin/v3/info`, `/minio/peer/…`, `/minio/storage/…` |
| `health` | five liveness probes — what a k8s deployment does all day |
| `ops` | **the whole taxonomy**: 53 requests, one per row of `clients/ops.py` |
| `encoded-keys` | keys with spaces, UTF-8, `+=&?#`, 12 segments, a 200-byte segment, `%2F` |
| `bucket-names` | 14 bucket names, valid and not, against the server that enforces the rules |
| `range` | two `Range` GETs → `206` |
| `garbage` | unknown query, `PROPFIND`, `..` traversal, TLS bytes on a plaintext port |
| `abort-midbody` | client RSTs in the middle of an 8 MB `GetObject` |
| `torn-body` | `PUT` promises 65536 body bytes, sends 100, hangs up |
| `slow-client` | the request head one byte at a time (390 recv events for one head) |
| `select` | `SelectObjectContent`: a chunked event-stream response body |
| `gzip-listing` | the same listing with `Accept-Encoding: gzip` (chunked) and `identity` (length) |
| `huge-head` | a 7 KB request head — just under MinIO's own ~8 KB limit |
| `huge-head-cap2048` | the same head under `--capture-limit 2048` (the РH14 budget) |
| `get-cap2048`, `multipart-cap2048` | the ordinary shapes under that budget |
| `awscli-basic` | aws-cli v2: put/get/head/list/delete + a 404 |
| `awscli-multipart` | aws-cli `s3 cp` of 15 MB — its own multipart chunking |
| `boto3-basic`, `boto3-multipart`, `boto3-errors` | botocore: precomputed CRC, `100-continue`, `ClientError` codes |
| `mc-basic` | MinIO's own client: bucket probes, `aws-chunked` PUT, gzip listing |
| `mc-pipe` | `mc pipe` of 5 MB from stdin: multipart with unknown length |
| `warp-mixed` | 1 s of GET/PUT/STAT/DELETE at concurrency 2 under `--capture-limit 256` (5143 records) |
| `s3fs` | a FUSE mount: 20 connections, `x-amz-meta-*` metadata headers, no `Expect` |

### `dist/` — the four-node pool

| Trace | What it exercises |
|---|---|
| `grid-idle` | eight seconds of an idle cluster: 12 connections opened, none closed, zero client traffic |
| `s3-and-grid` | one client listing, and the internal fan-out it causes |
| `put-and-grid` | a 4 MB `PutObject` across the erasure set |
| `keepalive-and-grid` | 50 client operations on one connection while the cluster does its own work |

### `tls/` — MinIO with certificates

| Trace | What it exercises |
|---|---|
| `ciphertext` | TLS on the socket: handshake records, nothing readable |
| `decrypted` | the same load with `--tls-go` on the container's stripped binary: 8 decrypted records |
| `decrypted-get` | one `GetObject`, decrypted |

## Recording and validating

```
./record.sh              # brings up the three stands, records everything
./record.sh minio        # one stand (minio | dist | tls); KEEP=1 keeps them up
```

Requirements: docker, passwordless sudo (BPF), python3 + boto3, aws-cli, curl,
openssl; the agent binary from `build-rel` (or `LATKIT=path`). Images:
`minio/minio`, `minio/mc`, `minio/warp`, `efrecon/s3fs`.

Validate (replays every record through `lk_replay_file` + `lk_ev_decode`, fails
on any malformed record):

```
cmake --build build --target lkt_info
build/tests/replay/lkt_info tests/traces/s3/*/*.lkt
```

## The clients

```
clients/sigv4.py      SigV4 header auth, presigning and the aws-chunked signature chain
clients/raw.py        the scenarios above, over raw sockets
clients/ops.py        the operation taxonomy as a table; `--table` prints it
clients/scenarios.py  boto3 scenarios
clients/tap.py        a logging HTTP tap: reads heads and body prefixes off a live exchange
clients/framing.py    tallies a tap log: framing, head sizes, methods, statuses
```

`tap.py` frames HTTP/1.1 properly (length, chunked, HEAD/204/1xx, and a method
queue so the response side knows what it is answering). The naive
split-on-CRLFCRLF version of it reports 1 MB "heads" wherever an object body
happens to contain a blank line, which is how the first draft of the head-size
table in `notes-s3proto.md` came out wrong.

## Reconnaissance (МS0), with the evidence

`./recon.sh` re-runs all six items and leaves the raw output in `.work/recon/`.
The findings below are from the run of 2026-08-15 on kernel 7.0.0-27-generic.

### 1. h2 — MinIO offers it, and no real client gets it

`.work/recon/01-h2.txt`. Go's TLS server picks the first entry of *its own*
`NextProtos` that the client also offered, so the question is not whether MinIO
supports h2 but what it chooses:

| Client ALPN offer | Selected |
|---|---|
| `h2,http/1.1` (curl, browsers, Go's default transport) | **http/1.1** |
| `http/1.1,h2` | http/1.1 |
| `http/1.1` | http/1.1 |
| `h2` alone — a client that refuses HTTP/1.1 | h2 |

And end to end: curl default → HTTP/1.1, curl `--http2` → HTTP/1.1, Go
`net/http` with `ForceAttemptHTTP2` → HTTP/1.1, python urllib (the boto3 stack)
→ HTTP/1.1. Cleartext prior-knowledge h2 on the plaintext port is refused
outright.

**Consequence:** the h2 blind zone of PLAN-HTTP.md §8 is empty on MinIO. No
switch has to be documented and no traffic has to be written off — MinIO
prefers HTTP/1.1 and every S3 SDK in the corpus is happy with it. Risk 1 of
PLAN-MINIO.md is closed, and МS3 is worth doing.

### 2. Go symbols — the official binary is stripped, and it does not matter

`.work/recon/02-go-symbols.txt`:

```
# image binary: ELF 64-bit LSB executable, x86-64, statically linked, stripped
# go version:   go1.24.6
# nm symtab:    nm: minio: no symbols
# tls syms by nm: 0
# .gopclntab:   1
# name string in file: 1
```

`nm` finds nothing. The decisive test is the agent itself, attached to the
binary the container is actually running:

```
latkit: Go TLS uprobes on /proc/2604842/root/usr/bin/minio
        crypto/tls.(*Conn).Write (entry + 8 return site(s))
latkit: Go TLS uprobes on /proc/2604842/root/usr/bin/minio
        crypto/tls.(*Conn).Read (entry + 7 return site(s))
```

`src/agent/go_pclntab.c` (М7 of the HTTP track) reads the function table and
resolves both. The `tls/decrypted*.lkt` traces carry decrypted records where
`tls/ciphertext.lkt` carries none.

**Consequence for РS8:** the module works on the official image as shipped. The
diagnostic still has to be understandable for a build with neither symtab nor a
recoverable pclntab, but that is no longer the expected case.

### 3. `sendfile` — MinIO does not use it

`.work/recon/03-sendfile.txt`. Twenty 8 MB `GetObject`s, syscall census of the
MinIO process:

```
% time     seconds  usecs/call     calls    errors syscall
100.00    0.053875          33      1585           write
```

Zero `sendfile`, `splice` or `copy_file_range`; object bodies go out through
ordinary `write(2)` in ~64 KB pieces. The agent's own view of one such
response:

```
latkit: stats events=132 drops=0 bytes=528812/8389612 captured/total
        iter_unsupported=0 recv_miss=0
```

**Consequence:** the РH4 `BODY_UNSEEN` degradation — the thing that makes nginx
byte accounting a lower bound — does not arise on MinIO at all. `bytes_out` is
exact, and risk 3 of PLAN-MINIO.md is closed. (What `sendfile` costs elsewhere
is still measured, in `tests/traces/http`.)

### 4. Framing — chunked responses are rare, `aws-chunked` requests are not

`.work/recon/04-framing.txt`, 9006 exchanges of a warp mixed run (4 concurrent,
1 MiB objects, 15 s) through the tap:

| Direction | Framing | Share |
|---|---|---|
| response | `Content-Length` | 8116 (90.1 %) |
| response | no length header (`204 No Content`) | 890 (9.9 %) |
| response | **chunked** | **0** |
| request | `aws-chunked` (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) | 1435 (15.9 %) — i.e. every PUT |
| request | no body | 7571 |

So on the byte-heavy path a response length is always known in advance. MinIO
chunks a response in exactly three situations, and the A/B pins the first one
down:

```
listing, Accept-Encoding: identity     Content-Length: 87059
listing, Accept-Encoding: gzip         Content-Encoding: gzip  Transfer-Encoding: chunked
listing, Accept-Encoding: zstd,gzip    Content-Encoding: gzip  Transfer-Encoding: chunked
object body, Accept-Encoding: gzip     Content-Length: 8388608
```

— a **gzipped XML listing** (minio-go always offers gzip, aws-cli sends
`identity`; and only once the compressed body outgrows Go's 2 KB write buffer),
`SelectObjectContent`, and `/minio/admin/v3/trace` (`text/event-stream`). Object
bodies are never compressed.

**Consequences:** the chunked *response* path is not on the hot path here, but
it is reachable from any client that offers gzip, so it stays correct rather
than becoming a degradation. `aws-chunked` on the *request* side is a main path
— 100 % of minio-go uploads — which is what makes РS6's two byte counters
mandatory rather than a nicety.

The same run also settles the capture budget question:

```
C->S n=9006 min=405 p50=476 p90=576 p99=579 max=583   0 % over 2048
S->C n=9006 min=436 p50=581 p90=581 p99=581 max=581   0 % over 2048
```

S3 heads are 400–600 bytes and MinIO refuses anything past ~8 KB with `400
MetadataTooLarge` (measured: 7000 bytes of padding pass, 7200 do not). A
2048-byte per-call budget is comfortable.

### 5. Threads — one name, `minio`

`.work/recon/05-comm.txt`: 29 of 29 threads on the single node, 27 of 27 on a
TLS node and on a cluster node, are called `minio`; the executable is
`/usr/bin/minio`.

**Consequence:** unlike MySQL 8.x — which names its session threads
`connection` and cost the MySQL track an afternoon — MinIO needs no special
case. `minio` goes into the default comm set for both the kernel filter and the
Go TLS scan (МS3).

### 6. A cluster mostly talks to itself (not in the plan; the stands insisted)

`.work/recon/06-internal-share.txt`. Four-node pool, one warp run, connections
classified by whether the peer is inside the pool:

```
connections : internal=18 client=2  (90% internal)
data events : internal=212581 client=57796  (79% internal)
```

**Consequences.** Two, both real:

- **РS2's `op="internal"` is not a tidiness rule.** Four fifths of what arrives
  on a distributed cluster's S3 port is the cluster itself, and if any of it
  reached `latkit_s3_requests_total` the number would be wrong by a factor of
  five.
- **Risk 2 (ringbuf pressure) is five times worse than the client load
  suggests.** The per-port capture budget of РH14 is what keeps this affordable,
  and the МS4 perf bench has to be run against a *distributed* stand, not a
  single node, or it will measure the easy case.

## Findings recorded while capturing (feed into МS1)

- **`aws-chunked` is identified by `x-amz-content-sha256`, not by
  `Content-Encoding`.** minio-go sends `X-Amz-Content-Sha256:
  STREAMING-AWS4-HMAC-SHA256-PAYLOAD` and `X-Amz-Decoded-Content-Length` and no
  `Content-Encoding` header at all. Keying detection on `Content-Encoding:
  aws-chunked` would miss every MinIO-client upload.
- **The `Authorization` header has two spellings.** aws-cli/boto3/s3fs write
  `…aws4_request, SignedHeaders=…`; minio-go writes `…aws4_request,SignedHeaders=…`
  with no space. Both are valid and both are in the corpus.
- **MinIO reports the S3 error code in a header when there is no body**:
  `X-Minio-Error-Code: NoSuchKey` on a `HEAD` 404. Present only when the body is
  empty — which is exactly the case where РS5's body prefix has nothing to read.
- **MinIO enforces the S3 bucket-name rules exactly** (`bucket-names.lkt`), so
  the РS3 validator has a reference implementation to agree with:

  | Name | MinIO |
  |---|---|
  | `abc`, `a-b.c`, 63 × `a` | routed (`404 NoSuchBucket` — the name is fine, the bucket is not there) |
  | `AB`, `a`, `ab`, `a_b_c`, `192.168.1.1`, 64 × `a` | `400 InvalidBucketName` |
  | `bucket.`, `.bucket`, `bucket..name`, `-bucket`, `buck$et` | `400 InvalidBucketName` |

- **An error body carries the object key** (`<Key>`, `<Resource>`) right after
  `<Code>`. The РS5 prefix must be read, matched and dropped, never stored.
- **A single node routes `/minio/storage/…` and `/minio/peer/…` into the S3
  router** and answers `404 NoSuchBucket` for a bucket named `minio`: the
  `/minio/` prefix has to be checked before the bucket rules, not after.
- **`?uploadId` alone selects four different operations**, by method
  (GET ListParts, POST Complete, DELETE Abort, PUT+`?partNumber` UploadPart).
- **A ringbuf record reserves a whole 4096-byte payload slot** unless the
  capture fits `LK_CHUNK_SMALL` (256). One second of warp at the default budget
  is 25 MB of trace and under two at 256 bytes — which is why `warp-mixed` is
  the one scenario recorded with a truncating budget.
- **MinIO closes the connection after an anonymous refusal without sending
  `Connection: close`.** The unit ends with `CONN_CLOSE`, and a second request
  on that connection gets an EOF.
