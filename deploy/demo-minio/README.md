# latkit S3 / MinIO demo stack

The object-storage twin of [`../demo`](../demo) (PostgreSQL),
[`../demo-mysql`](../demo-mysql) and [`../demo-http`](../demo-http): MinIO, a
load generator that exercises every operation family the taxonomy has a row
for, the agent, Prometheus and Grafana with the bundled dashboards — one
`docker compose up` away from a live **latkit — S3 / MinIO** dashboard of an
object store that was neither instrumented nor reconfigured, whose admin
credentials nobody handed over, and which does not know the agent is there.

The point of the stack in one line: the agent is told `9000=s3`, so the same
HTTP/1.1 framer that serves the HTTP dashboard reads this exchange under the
object store's nouns — **operation** instead of route, **bucket** instead of
Host, the **access key** out of the signature as `user`, and the **symbolic S3
error code** out of the XML body, because `NoSuchKey` and `NoSuchBucket` are
both `404` and are not the same page at 3 a.m.

## Requirements

- **Linux host** with kernel **≥ 5.15** and BTF at `/sys/kernel/btf/vmlinux`
  (any mainstream distro of the last few years qualifies; the agent checks on
  startup and says exactly what is missing). Docker Desktop on macOS/Windows
  runs a VM kernel — not tested, not promised.
- Docker with the compose plugin. The `latkit` container runs `privileged`
  with `pid: host` (demo simplicity; the minimal capability set is a comment
  in the compose file and a table in [docs/deploy.md](../../docs/deploy.md)).

## Run

```sh
git clone --recurse-submodules https://github.com/sky-rzn/latkit.git
cd latkit/deploy/demo-minio
docker compose up --build -d
```

First run builds the agent image (~1–2 min) and pulls
minio/mc/alpine/prometheus/grafana. With the images already present, **12–29 s**
from `up` to data on every panel of the S3 dashboard on this host (the spread is
how much Docker had to re-check); from `git clone` on a cold machine, about 3–4
minutes, and image pulls on a slow network are the one thing that can stretch
it.

Then open:

| what | where |
|---|---|
| **Grafana** — anonymous, the bundled dashboards in the *latkit* folder | <http://localhost:3000/dashboards> |
| Prometheus | <http://localhost:19090> |
| raw agent metrics | `curl http://localhost:9752/metrics` |

Give it ~1 minute after `up`: Prometheus scrapes every 5 s and the load runs a
pass of ~20 operations in a loop. Start at **latkit — S3 / MinIO**; the
database and HTTP dashboards stay empty here.

Tear down (containers, volumes and network — nothing survives):

```sh
docker compose --profile tls down -v
```

(The profile flag makes `down` cover the optional TLS services too; it is
harmless otherwise.)

## What to look at, and why it is there

The load ([`load/load.sh`](load/load.sh)) drives MinIO's own `mc` client, so
what reaches the wire is real S3 framing rather than a curl approximation of
it — uploads are `aws-chunked`, listings are gzipped, a stream of unknown length
becomes a genuine multipart upload. Every pass writes **fresh object keys**
carrying a counter, a slash-separated prefix and a `%`-escape.

- **Top operations** is a short, stable list, and every entry is a row of the
  taxonomy in [docs/notes-s3proto.md](../../docs/notes-s3proto.md). Measured on
  this stack: 16 of them —

  ```
  CompleteMultipartUpload CopyObject CreateBucket CreateMultipartUpload
  DeleteObjects GetBucketLocation GetBucketPolicy GetObject
  GetObjectLockConfiguration HeadBucket HeadObject ListBuckets ListObjectsV2
  PutBucketPolicy PutObject UploadPart
  ```

  (`CreateBucket` and `PutBucketPolicy` happen once, during setup; the other
  fourteen repeat every pass.)

  Note the ones the load never asked for: `GetBucketLocation`,
  `GetObjectLockConfiguration` and `HeadBucket` are `mc`'s own bookkeeping
  before each transfer. A client asks more questions than its user does, and on
  the wire is the only place that shows;
- **`op="other"` share** is the honesty panel, and it is the S3 counterpart of
  the HTTP dashboard's `route="other"`. It should sit at **zero** here. It is
  not a cardinality guard — the operation label is bounded by a table, not by a
  heuristic — it is a *freshness* signal: a rising `other` share means the S3
  API has grown a call the table does not know yet;
- **`latkit_metric_series`** (Agent health) stays flat while every pass invents
  new object keys. That is the privacy invariant from the other end: **the
  object key is never a label**, and the key is the most sensitive part of an S3
  request (file names, e-mail addresses, customer identifiers all live there);
- **Top buckets** has `photos`, `backups`, `public` — and two values worth
  reading twice: `bucket="-"` is a `ListBuckets`, a request that names no
  bucket, which is a different fact from a name the agent refused; and a
  one-off `probe-bsign-<random>` is minio-go probing which signature version
  the server wants. Neither is an object key;
- **Top access keys** has four values: `lkroot` and `demoapp` (two real
  callers), `-` (anonymous — no credential carrier at all) and `ghostkey` (a
  signature from an access key that was never created). The label comes off the
  *request*, not off the outcome, which is what makes "who is hammering us with
  bad credentials" an answerable question. Only the public half of the pair is
  ever read: the signature, the chunk signatures and `X-Amz-Security-Token` are
  not touched;
- **Errors by S3 code** — measured here: `NoSuchKey`, `NoSuchBucket`,
  `AccessDenied`, `InvalidAccessKeyId`, `NoSuchBucketPolicy`,
  `ObjectLockConfigurationNotFoundError`. The status panel beside it shows the
  same events as two numbers, `4xx` and `2xx`, which is exactly how much a
  status code tells you here. The overall error share on this stack sits around
  a fifth of all requests, and most of it is `mc` asking every bucket about an
  object-lock configuration that does not exist — an object store's error rate
  is largely its clients' own probing, and that is visible only per code;
- **Duration vs TTFB vs upload time.** Three panels because they are three
  different stories (РH5). The 1.5 MiB body the load trickles over ~1 s appears
  in **Request upload time**, not in duration: latkit starts the server's clock
  at the *end* of the request, so a slow client is never reported as a slow
  server. On a `GetObject` of a 5 MiB object the gap between TTFB and duration
  is the streaming of the body;
- **Object size** is fed by the *logical* size — `x-amz-decoded-content-length`
  when the upload is `aws-chunked`, `Content-Length` otherwise (РS6). On the
  demo's 1 KiB uploads the chunk framing is worth several per cent of the
  object — a wire-fed histogram would report that as part of your data, and the
  smaller your objects the worse it reads;
- **Not an S3 API** is the last honesty panel: `latkit_s3_internal_requests_total`
  counts MinIO's own `/minio/…` surface — here the container's health probe,
  on a distributed pool the majority of the port — and those requests appear in
  **no** family that says "requests". Beside it, the blind-zone counters, which
  should be all zeros: this stack is HTTP/1.1 throughout.

### The claims, by hand

```sh
# 1. Operations, and nothing but operations from the table:
curl -s http://localhost:9752/metrics | grep '^latkit_s3_requests_total' \
  | sed 's/.*op="\([^"]*\)".*/\1/' | sort -u

# 2. No object key, anywhere in the exposition (the load names keys after a
#    counter and a date prefix precisely so this is checkable):
curl -s http://localhost:9752/metrics | grep -ciE 'small-|stream-|copy-|\.bin|%20'   # 0

# 3. The two numbers of РS6 — bytes on the wire vs the objects themselves — on
#    the 1 KiB uploads of the second access key. object_size_sum is an exact
#    multiple of 1024; bytes_total{direction="in"} is several per cent above it,
#    and the difference is the aws-chunked framing:
curl -s http://localhost:9752/metrics | grep 'bucket="public",user="demoapp"' \
  | grep -E '^latkit_s3_(bytes_total.*PutObject.*direction="in"|object_size_bytes_sum.*PutObject)'

# 4. The internal surface, counted and set apart:
curl -s http://localhost:9752/metrics | grep '^latkit_s3_internal_requests_total'
```

One honest caveat about the third one: on **large** bodies the wire counter can
come out *below* the logical size instead of above it. A 256 KiB upload leaves
the client in one write, of which the port's 2048-byte budget captures the head
and reports the rest as a hole — and the tail of a body's last call is never
credited, so `bytes_total` is a declared lower bound there (the same effect
`docs/accuracy.md` §S3 measures on the response side, bounded by one call and
never above the truth). It is one more reason the size histogram is fed by the
header's logical size rather than by counted bytes.

## TLS profile

```sh
docker compose --profile tls up --build -d
```

adds a **second** MinIO serving HTTPS on 9443 with a self-signed certificate,
and an `mc` client that only talks to it, next to the plaintext pair. The socket
bytes of those sessions are ciphertext; the plaintext on the dashboards comes
from uprobes on `crypto/tls` **inside the MinIO binary itself** (РS8) — and the
observations are not distinguishable from the plaintext leg's, which is the
claim. Proof it is really the TLS path:

```sh
curl -s http://localhost:9752/metrics | grep -E '^latkit_tls_(attached|connections|decrypted|correlation)'
# want: tls_attached{state="go"} 1, connections and decrypted_bytes growing,
#       correlation_misses_total 0
```

Measured here on the official image (stripped, resolved through Go's own
function table): 597 decrypted connections and 31 MB of plaintext in the first
two minutes, **0** correlation misses, and 0 parse errors on either leg.

**MinIO has exactly one TLS channel, and it is this one.** MinIO maps no
`libssl`, so `--tls auto` on its own would find nothing at all; the Go channel
is named explicitly (`LATKIT_TLS_GO`). `auto` is still set in the compose file
for the other half of it — with an `s3` port configured, the derived `/proc`
scan set is `{minio}`, and that set is what gates the uprobe channel kernel-side.

One deployment detail this stack demonstrates on purpose: a uprobe is registered
against an **inode**, not a path. The `bin-init` service stages one copy of the
MinIO binary in a volume; both MinIO containers execute it and the agent hooks
it, so "the binary latkit hooked" and "the binary MinIO runs" are provably the
same file. On a host install that is simply `--tls-go /usr/bin/minio`; for a
containerised MinIO seen from a host agent it is
`--tls-go /proc/<pid>/root/usr/bin/minio` ([docs/notes-tls.md](../../docs/notes-tls.md) §4b).

The HTTPS leg is HTTP/1.1: MinIO offers `http/1.1` to every real client's ALPN
list, so — unlike a browser-facing web server — an `s3` port does not quietly
fall into the h2 blind zone. If you put a proxy in front that does negotiate h2,
`latkit_ignored_conns_total{reason="h2"}` is where the traffic goes.

## Spans

There is no trace profile here, and that is a decision rather than an omission.
Spans are off until you pass an endpoint — the compose file forwards
`LATKIT_OTLP_ENDPOINT` and `LATKIT_OTLP_SPANS` from your environment if you have
a Collector to point at:

```sh
LATKIT_OTLP_ENDPOINT=http://your-collector:4318 LATKIT_OTLP_SPANS=1 \
  docker compose up --build -d
```

A sampled S3 observation becomes a `SPAN_KIND_SERVER` span with the HTTP
semantic conventions plus `aws.s3.bucket` and `url.template` (the operation).
That span carries the raw `url.path` — **the object key included** — which is
the one path by which a key leaves the host, and `--http-redact` applies to its
query string. That is why this stack ships no Jaeger to make it one click:
turning spans on for an object store is a deliberate act. The HTTP demo has the
wired-up example ([`../demo-http`](../demo-http/README.md), `trace` profile).

## How it is wired

- **minio** (`minio/minio:latest`, single node, single drive) publishes **no**
  port: the load reaches it by service name over the compose network. A
  published `localhost` port would route through docker-proxy, which `splice()`s
  the payload past the socket layer and defeats the capture (README "Known
  limitations"). No Console either — the WebUI is a separate port and
  deliberately out of scope.
- **load** — [`load/load.sh`](load/load.sh) in the stock `minio/mc` image: the
  three buckets, the second access key, the operation mix, three object-size
  decades and the deliberate failures.
- **probe** — [`probe/probe.sh`](probe/probe.sh) in a busybox image: the
  requests no SDK will make — anonymous (allowed and refused), presigned, and a
  signature from an access key that does not exist. `mc` cannot produce these:
  it refuses to configure an alias whose credentials the server rejects.
- **latkit** — the release scratch image built from
  [`deploy/docker/Dockerfile`](../docker/Dockerfile) (musl static), configured
  only through `LATKIT_*` env: `LATKIT_PORT=9000=s3,9443=s3`, `/metrics` on
  `0.0.0.0:9752`, `LATKIT_TLS=auto` + `LATKIT_TLS_GO=/binsrc/minio`.
- **prometheus** (2.x) — scrapes `latkit:9752` every 5 s, 2 h retention.
- **grafana** (pinned 11.x) — anonymous Viewer; the datasource and the
  dashboards are provisioned from the postgres demo's
  [`../demo/grafana/provisioning`](../demo/grafana/provisioning) (same
  `prometheus` service name) plus [`../../dashboards`](../../dashboards),
  mounted read-only — the repo directory is the single source, no copies.

## Troubleshooting

- `latkit` exits immediately → `docker compose logs latkit`. The usual causes
  are missing BTF (`/sys/kernel/btf/vmlinux`), an old kernel, or — specific to
  this stack — a `--tls-go` binary the agent cannot hook, which is fatal by
  design and prints the reason and a way forward rather than going quietly
  blind.
- Panels show "No data" → wait for the first scrapes (~30 s after `up`), then
  check `docker compose logs load` and the Prometheus target page at
  <http://localhost:19090/targets>.
- Ports 3000/9752/19090 taken → edit the `ports:` mappings in
  `docker-compose.yml`; nothing inside the stack depends on the host port
  numbers.
- **You already run something else on port 9000.** The port filter is
  kernel-wide, so a second MinIO on the host would land in the same metrics.
  Either stop it, or move this stack (`--address :9010` in the compose file and
  `LATKIT_PORT=9010=s3`) — the labels are the only thing that would tell the two
  apart, and they are not meant to.
- `latkit_tls_attached{state="go"}` is 0 with the tls profile up → the binary in
  the `miniobin` volume and the one MinIO runs have drifted apart. `docker
  compose --profile tls down -v` and up again restages it.
