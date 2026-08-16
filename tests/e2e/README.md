# e2e stand (milestone M3)

A `docker compose` stack that exercises both stage-5 export paths end to end:
**postgres + pgbench + latkit + prometheus + otel-collector**. It backs the M3
exit criteria (STAGE5.md task 5.4): the stage-4 metric nomenclature is reachable
from outside the agent by *both* Prometheus scrape and OTLP push, and the agent
stays honest under export failure.

```
pgbench ──sql──▶ postgres          (compose bridge; NO localhost/docker-proxy)
                    ▲
   latkit ─────────┘  (BPF capture, kernel-wide)
     ├── /metrics  ◀── prometheus            (pull)
     └── OTLP/HTTP ──▶ otel-collector ──▶ prometheus (push, re-exported :8889)
```

## Run

```sh
./verify.sh          # build the agent, bring the stand up, assert M3, tear down
KEEP=1 ./verify.sh   # same, but leave the stand running to poke at it

./verify-tls.sh        # TLS variant: ssl=on + sslmode=require + --tls auto (stage 6)
./verify-mysql-tls.sh  # MySQL TLS stand: mysqld require_secure_transport=ON,
                       #   -p 3306=mysql --tls auto (MYSQL.md этап М5)

./verify-http.sh         # plaintext HTTP: nginx + a Go backend, both legs (М8)
./verify-http-tls.sh     # HTTPS via nginx + libssl uprobes (PLAN-HTTP.md М7)
./verify-http-go-tls.sh  # HTTPS via a Go net/http server + --tls-go (М7, РH13.3)

./verify-s3.sh           # plaintext S3: MinIO, mc + busybox wget, one agent
                         #   on -p 9402=s3 (PLAN-MINIO.md МS4)
WARP=1 ./verify-s3.sh    # + the warp profile: MinIO's own benchmark for volume
./verify-s3-tls.sh       # S3 over TLS: two MinIOs (one with certificates, one
                         #   without), mc against both, one agent each, and the
                         #   two legs compared (PLAN-MINIO.md МS3, РS8)
SOAK_SEC=86400 ./verify-s3-tls.sh   # + the МS3 soak: a 24 h warp run under the
                                    #   uprobes, MinIO has to come through it
```

The two HTTPS stands are self-contained (their own compose file, their own
Prometheus, no postgres): each brings up a TLS server, a curl load loop and the
agent, and asserts that an encrypted run produces the *ordinary* HTTP
observations — templated routes, the 4xx/5xx split, plausible timings — plus the
proof that the TLS path is the source. The Go one additionally asserts that the
three routes it drives arrive in comparable numbers: a correlation that only
caught the later requests of a connection would light every counter and still be
wrong. `STRIP=1 ./verify-http-go-tls.sh` rebuilds the server with
`-ldflags "-s -w"` — the shape every Go server in the wild is actually shipped
in — and runs the same assertions against the agent's other resolution path,
Go's own function table. It builds `tests/e2e/gotls` on the host (a Go toolchain
is required) and bind-mounts the binary into both the server and the agent, so
the uprobe and the running process provably share an inode.

`verify-s3-tls.sh` is the same idea applied to a real Go server rather than a
purpose-built one, and it is built as a **comparison** because that is what its
milestone claims (МS3: "a TLS run gives the same observations a plaintext run of
the same load gives"). It extracts `minio` from the official image to
`build/minio`, bind-mounts that one host file into two MinIO containers — one
with certificates on :9444, one without on :9401 — and into the encrypted leg's
agent, so the hooked inode and the running binary are provably the same file. A
single `mc` client drives an identical sequence against both endpoints; the
script then takes a snapshot of both legs' `latkit_s3_*` families, lets the load
run, stops it, snapshots again, and compares the *window* operation by
operation. Comparing windows rather than totals is deliberate: the two agents
attach at slightly different instants, so the client's one-time bucket bootstrap
lands on whichever leg was already listening and says nothing about either
channel.

Besides the comparison it asserts the things that make the comparison mean
something: the Go channel is the source (`state="go"`, uprobe events, TLS
connections at the socket, correlation misses ≈ 0), the МS3 comm derivation
(`--tls auto` on an `s3` port scans for `minio` and nothing else), no object key
in either exposition, and — the failure path — that a binary latkit cannot hook
refuses at startup with a cause and a way forward. Ports are 9401/9444 rather
than 9000 on purpose: the agent's port filter is kernel-wide, and a stand on
9000 would capture any other MinIO on the host.

`verify-s3.sh` is the plaintext S3 stand, and what it asserts is the list МS4
names: the `latkit_s3_*` families exist and grow, every operation is a value
from the closed table with `op="other"` at zero, the bucket and the access key
are labels, the injected 404s arrive **with their S3 codes** (`NoSuchKey` and
`NoSuchBucket` are the same status and not the same page), no failure falls back
to a bare numeric status, the timings are three separate numbers, and the blind
zones, parse errors and drops are zero on an HTTP/1.1 run.

Two of its checks exist only here. The first is РS6 as a ratio: `mc` uploads
through `aws-chunked`, so the *object* bytes must be strictly fewer than the
*wire* bytes and by the framing's own margin — measured 0.16 %, where a
histogram fed from the wire count would read exactly 1.0. The second is that
MinIO's own surface is counted and nothing more: the container's health probes
land in `latkit_s3_internal_requests_total` and in no family that says
"requests", and no `/minio/...` path is read as a bucket called `minio`.

It needs two clients, and the reason is worth knowing: `mc` refuses to configure
an alias whose credentials the server rejects, so the refused-caller cases of
РS4 — an anonymous request, and a signature from an access key that does not
exist — are driven by busybox `wget` with a hand-written `Authorization` header.
That is also the honest shape of the thing being tested, since no SDK would ever
generate it. Port 9402, for the same reason 9401/9444 are used above.

`verify.sh` builds `build/latkit` on the host first (the image just wraps that
binary — the BPF skeleton toolchain is not reproduced in a container), brings the
stand up, and asserts:

- **pull**: Prometheus scrapes the agent with no failed scrape, sees
  `latkit_queries_total` growing under load, and a plausible p95 from
  `histogram_quantile` over the duration histogram;
- **push**: the collector receives the same metrics over OTLP (re-exported on
  `:8889`, so a series under `job="otel-collector"` proves the protobuf was
  accepted — a malformed one 400s and never appears), logs an
  `ExponentialHistogram`, and receives the sampled spans (`db.query.text`);
- **cross-check**: the pull and push query counts agree within an export
  interval.

By hand, once up: <http://localhost:19090> (Prometheus — 19090 to avoid a host
Prometheus on 9090), <http://localhost:9752/metrics> (the agent),
`docker compose logs -f otel-collector` (the debug dump of every metric/span).
The S3 stands publish their own: <http://localhost:19094> and
<http://localhost:9757/metrics> for `verify-s3.sh`, <http://localhost:19093>
and 9755/9756 for the two legs of `verify-s3-tls.sh`. Every stand has a distinct
set, because they can be up at the same time and the agent's port filter is
kernel-wide.

## Requirements & caveats

- **Docker + BPF privileges on the host.** The agent container is `privileged`
  to load/attach BPF; where the runner has no BPF access this stand is a manual
  check (CI marks e2e optional). Everything else (parser, metrics, HTTP, OTLP
  encoder) is covered by the unprivileged unit tests.
- **Capture goes over the compose bridge, not localhost.** pgbench connects to
  `postgres:5432` by service name — a direct container-to-container hop the
  agent captures cleanly. A `localhost:<published>` hop would traverse
  docker-proxy, which `splice()`s the payload and defeats socket capture (see
  the top-level README "Known limitations"). So postgres does **not** publish
  5432.
- **Span volume.** `--otlp-spans 0.1` in the compose keeps the collector's debug
  log and CPU sane under pgbench; raise it to `1.0` for a "every query" demo.
- The p95 can read high (tens of seconds) in the first couple of minutes: the
  `pgbench -i` `VACUUM ANALYZE` runs multi-second queries that land in the top
  buckets, and the cumulative histogram carries them until they age out of the
  `rate()` window under steady load. That is real captured latency, not a
  histogram error.

## The plaintext HTTP stand (М8)

`docker-compose.http.yml` + `verify-http.sh`: nginx in front of a Go `net/http`
backend, **both legs observed** (`-p 8080=http -p 8081=http`), a curl load loop
shaped to hit the cases РH4 and РH5 are about, and — behind `--profile burst`,
so a runner that cannot pull the image still runs every correctness check — a
`wrk` burst. It asserts the М8 list in one run:

- `latkit_http_requests_total` exists and grows;
- every route label is templated — no raw id, no query string, bounded
  cardinality (РH7);
- the injected 500 and 404 are both visible and told apart: both counted, only
  one an error (РH10);
- the durations are plausible, and `/slow`'s deliberate 50 ms shows up in
  **TTFB** rather than only in the duration — the two are measured, not copied
  from each other (РH5);
- the upload family holds the trickling client's transfer and skips the units
  that have no interval to report;
- the front and upstream legs keep distinct label sets — a proxy's two legs are
  two latencies;
- an 8 MB `sendfile` body is accounted to the byte on this kernel (РH4);
- and nothing went blind, nothing was dropped, no parse error on clean traffic.

It needs a Go toolchain: the backend is built on the host and bind-mounted, the
same recipe the Go-TLS stand uses.

The М6 claim about spans in somebody else's trace stays verified **offline**,
and deliberately so — the corpus carries real recorded `traceparent` traffic
that no synthetic stand can improve on:

- `tests/replay/http_queries_traces.sh` replays the recorded `*/traceparent.lkt`
  corpus traces (four servers, a real W3C context on the wire) through the
  production handler and the real span collector, and asserts that the resulting
  span carries the caller's `trace_id`, the caller's span id as its parent, kind
  `server`, and the caller's `tracestate` — and that the second request on the
  same connection, whose `traceparent` says `sampled=0`, produces no span at all;
- `tests/unit/test_otlp_enc.c` asserts the same span on the wire, decoding the
  encoder's protobuf: `SPAN_KIND_SERVER`, `parent_span_id`, `trace_state`, and
  the HTTP semconv attributes with no `db.*` among them.

## Files

| File | Role |
|---|---|
| `docker-compose.yml` | the five services + wiring |
| `Dockerfile.latkit` | minimal runtime image wrapping the host-built `build/latkit` |
| `prometheus.yml` | scrape config (agent + collector re-export) |
| `otel-collector-config.yaml` | OTLP receiver → debug + prometheus exporters |
| `verify.sh` | build + up + assert + down |
| `docker-compose.tls.yml` | TLS overlay for the base stand (postgres ssl=on, stage 6) |
| `verify-tls.sh` | the TLS assert set: same series + `latkit_tls_*` provenance |
| `docker-compose.mysql-tls.yml` | standalone MySQL TLS stand (MYSQL.md этап М5) |
| `verify-mysql-tls.sh` | MySQL twin of `verify-tls.sh` |
| `docker-compose.http.yml` | plaintext HTTP stand: nginx + Go backend, both legs (М8) |
| `nginx-http.conf` | its nginx: static with `sendfile on`, a reverse-proxy leg |
| `httpbackend/` | the Go application server the stand proxies to (built on the host) |
| `verify-http.sh` | the М8 assert set: routes, statuses, the four timings, blind zones |
