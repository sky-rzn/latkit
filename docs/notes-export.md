# notes — exporters (stage 5)

Design notes for `src/export/`. Task 5.1 covers the Prometheus pull path (the
HTTP server, `/metrics`, `/healthz`), task 5.2 the OTLP/HTTP push path (protobuf
writer, exponential-histogram mapping, async client, timebase), task 5.3 the
sampled spans, and task 5.4 the config/env layer, the security posture, and the
v1 limitations — all below.

## HTTP server (Р29, task 5.1)

A own minimal server rather than a dependency (libmicrohttpd, civetweb): the
format we need is trivial and the server lives inside the existing single-thread
epoll loop (`src/agent/loop.c`), so it adds no thread and no lock.

**Protocol subset.** `GET` and `HEAD` only. The server reads the request line
plus headers up to the blank line (`\r\n\r\n`) and ignores header *contents*
except `Accept` (plumbed through to the route for the OpenMetrics negotiation of
task 5.3; unused in 5.1). Every response carries `Content-Length` and
`Connection: close` — the connection closes after one response. No keep-alive:
Prometheus reopens per scrape without complaint, and keep-alive would double the
connection state machine for nothing. Routes are exact-match: `/metrics`,
`/healthz`, everything else `404`; a non-GET/HEAD method is `405` with `Allow:
GET, HEAD`; a malformed request line or one that overflows the size ceiling is
`400`. `HEAD` sends the headers (including the real `Content-Length`) with no
body.

**Untrusted input (Р18).** The agent faces the network, so the server is
hardened from the first commit: at most 8 concurrent connections (excess
accepts are dropped), a 2 KiB ceiling on the request (a request with no blank
line by then is rejected `400` and closed), and a 5 s per-connection deadline
swept once a second. A client that opens a socket, sends half a request line and
sleeps is reaped by the sweep without touching concurrent scrapes or the capture
pipeline (`tests/unit/test_http.c::slow_client_timeout`).

**Loop integration.** The listen fd and each accepted fd register through
`lk_loop_add_fd`; a connection flips its epoll interest `EPOLLIN`→`EPOLLOUT`
with `lk_loop_mod_fd` when it moves from reading the request to writing the
response, and drops itself with `lk_loop_del_fd` on completion or timeout. The
loop tolerates a handler deregistering its own fd mid-batch (a generation guard
keeps a stale event from being mistaken for a reused slot).

**Response construction (contract Р26).** `/metrics` is `open_memstream` +
`lk_metrics_dump`: the registry serialises between ringbuf events in the single
thread, so there is no lock and no snapshot — the HTTP layer wraps the stage-4
dump and recomputes nothing. The buffer is then drained to the socket by
`EPOLLOUT` readiness, as much as the socket buffer takes each time (covered by
`test_http.c::partial_write` with a shrunk `SO_RCVBUF`).

**Bind default.** `127.0.0.1:9752` (`--prom-listen ADDR:PORT|none`). Loopback by
default: scraping from another host or a container is an explicit choice
(`--prom-listen 0.0.0.0:9752`), a conservative default with a security note in
the README. TLS/auth on the endpoint is out of scope for v1 (front with a
reverse proxy); a bind failure is fatal at startup — no silent fallback.

**`/healthz`.** `200` with a short text body (`uptime_seconds`, `events_total`,
`ringbuf_dropped_total`). "Alive" means the loop turns and answers; capture
degradation (drops, resyncs) is a metric, not a health signal — the endpoint
never returns 503, so partial capture degradation does not pull the agent out of
a load balancer.

**Export self-metrics.** Counted by prom.c and poured into the very dump they
describe via a facade provider (Р27):

- `latkit_http_requests_total{path,code}` — responses by matched route
  (`/metrics`, `/healthz`, or `other`) and status code;
- `latkit_scrape_duration_seconds` — gauge, duration of the last `/metrics`
  serialisation.

## Scrape cost (task 5.1 measurement)

The whole registry serialises in one pass while the pipeline waits, so the dump
duration is a pipeline pause. Measured on a registry filled to its ceiling —
K=500 fingerprints across 16 `(db,user)` dims with the duration/rows/first-row
histograms populated (`first_row_hist` on, the worst case), **516 series →
~2.75 MB → ~6.3 ms** per dump (best of 20, release build, this host).

That pause is far below the ringbuf drain budget: the default ringbuf is 8 MiB
(`LK_RINGBUF_SZ`), holding thousands of in-flight events, so a ~6 ms stall even
at tens of thousands of events/s buffers a few hundred events — well within
headroom, and the top-K ceiling (Р23) bounds the series count regardless of
workload. If this ever bites (a much larger K, or a tighter ringbuf under a
burst), the seam for an incremental chunked dump is `lk_metrics_iter` (stage 8);
the number above is the baseline to watch.

## OTLP/HTTP push (Р31, Р33, task 5.2)

The push path mirrors the pull path over the same registry — `lk_metrics_iter`
walks the exact rows `lk_metrics_dump` prints (contract Р26/Р31), recomputing
nothing — and serialises them straight to OTLP protobuf by hand (`pbuf.c` +
`otlp.c`), no `opentelemetry-cpp`, no `protobuf-c`.

**Wire format.** `pbuf.c` is an append-only proto3 writer: varints, tags, and
length-delimited submessages written body-first (the length varint is inserted
before the body with a `memmove` once the body is complete, so submessages close
in LIFO order). Golden-byte tests (`test_pbuf`) pin the primitives; the encoder
tests (`test_otlp_enc`) decode the output and assert the OTLP shape; the live
Collector is the strict schema authority (it rejects malformed protobuf 400).

**Mapping.** counters → `Sum{is_monotonic, cumulative}`, gauges → `Gauge`,
histograms → `ExponentialHistogram{scale=2}`. The Р24 grid goes out **as-is**:
`positive.offset = -53` (= `LK_HIST_MIN_INDEX`), `bucket_counts` is the flat
77-cell array; the underflow cell becomes `zero_count` with
`zero_threshold = 2^(-53/4)` = `lk_hist_bound(MIN)`; the overflow cell is folded
into the **top** bucket. That last fold distorts only values ≥ `2^6` s (64 s) —
acceptable, since the histogram's declared range tops out at 60 s. Grid index
`k` maps to OTLP index `k` directly; the two conventions differ only at exact
power boundaries (OTLP buckets are `(base^i, base^(i+1)]`, ours are lower-
inclusive), which is noise next to the ~9% bucketing error the grid already
carries.

**Temporality — cumulative.** `time_unix_nano` is the export instant;
`start_time_unix_nano` is the series' `created_ns` (added to the registry row in
this task). A fingerprint evicted from the top-K (Р23) and later re-admitted gets
a **new** series with a fresh `created_ns`, i.e. a new stream with a new start —
a legal cumulative reset per the OTLP spec, never a shrinking counter. The fixed
families (`queries_total`, `errors_total`, txn) and the flat scalars carry their
own creation stamps too; all are captured at startup, consistent with
`process_start_time_seconds` to within construction jitter.

**Time (Р33).** Every pipeline stamp is `CLOCK_MONOTONIC` (Р13). `timebase.c`
samples `offset = REALTIME − MONOTONIC` on **every** export tick (an NTP step
moves REALTIME, and the offset must follow) and `lk_wall_ns(mono)` converts. A
step between two ticks shifts absolute timestamps by ≤ the step within one
interval; durations, being monotonic differences, are unaffected. The Prometheus
text format carries no timestamps and must not.

**Delivery.** POST `<endpoint>/v1/metrics`, `application/x-protobuf`, every
`--otlp-interval` seconds (default 15). **No queue, no retries**: a batch that
does not land (timeout, non-2xx, connect refused) is dropped and
`latkit_otlp_exports_total{result="error"}` bumps — cumulative temporality makes
the loss harmless, the next push carries full state. `429`/`503` with a
`Retry-After` (seconds form) are honoured by pausing ticks until then. The client
is a non-blocking state machine (connect → write → read status) in the shared
loop with **one export in flight** — a tick arriving mid-export is skipped
(`latkit_otlp_export_ticks_skipped_total`). `getaddrinfo` is blocking, so the
endpoint is resolved once and cached; a connection/timeout failure marks it for
re-resolve on the next attempt (a Collector that moves), while an HTTP error
keeps the cache. `http://` only in v1 (a sidecar Collector is the standard OTel
topology); `https://` is rejected with a message.

**Wire-type footguns (validated by the live Collector).** proto3 numeric fields
are not all varints. In `(Exponential)HistogramDataPoint` the `count` (field 4)
and `zero_count` (field 7) are `fixed64`, not varint; `start`/`time` are
`fixed64`; `scale` is `sint32` (zigzag). Encoding `count` as a varint round-trips
through our own decoder but the Collector rejects the whole batch with `proto:
wrong wireType = 0 for field Count` (HTTP 400) — which is exactly why the e2e
stand (task 5.4) keeps a live Collector in the loop as the strict schema
authority: `protoc` is unavailable offline, so the golden `pbuf` tests pin the
primitives and the Collector pins the OTLP schema. `bucket_counts` inside
`Buckets` stays a packed `uint64` (varint) — that one *is* a varint.

**Config (Р34).** Enabled by an endpoint (`--otlp-endpoint` or
`OTEL_EXPORTER_OTLP_ENDPOINT`). See the "Configuration & environment" section
below for the priority rules; resource defaults are `service.name=latkit`,
`service.version`, `host.name`.

## Spans (Р32, task 5.3)

Spans carry what metrics structurally cannot: the timings of one concrete
execution and the **raw** SQL text (the registry only ever holds the normalised,
literal-free form, Р28).

**Collector as a sink.** The span collector is another `lk_query_sink`
implementation, so it slots into the tee `proto_pg → (metrics | spans |
--queries)` without the parser or aggregator knowing it exists (the stage-4 tee
generalised to a list of sinks in `events.c`).

**Sampling.** Decided in `on_query` by two independent predicates: `--otlp-spans
RATIO` (a probabilistic "representative slice", via a splitmix64 hash of
ts+cookie+seed — deterministic under a seed, no `rand(3)`) and/or
`--otlp-spans-slow-ms N` (a duration floor, "every slow query"). A query is
sampled if either fires. Off by default.

**Ring + text.** A sampled query is copied into a fixed FIFO ring (`LK_SPAN_BUF =
2048`); the raw SQL is copied (it only lives for the callback, Р16) capped at
`--otlp-span-text-max` (default 4 KiB). A full ring drops the new span and bumps
`latkit_spans_dropped_total`. Delivery is a POST to `/v1/traces` on the same
client (Р31), alongside a metrics tick or when the ring hits 3/4.

**Ids & timings.** `trace_id` (16 B) and `span_id` (8 B) come from a
`getrandom(2)` seed; the trace is standalone (no parent — the client's context is
invisible; parsing a `traceparent` from a sqlcommenter SQL comment is a v1.1
candidate). `start = ts_start_ns`, `end = ts_complete_ns` (the precise
per-request model — spans need no averaging compromise, cf. Р25), converted to
wall clock by `timebase.c` (Р33).

**Attributes** (OTel semconv for databases): `db.system.name="postgresql"`,
`db.query.text` (raw SQL; omitted under `NO_TEXT`), `db.namespace` (database),
`db.user`, `db.response.returned_rows`; the span name is the normalised text
truncated to 64 chars (the normaliser Р22 runs only for sampled queries — a
negligible cost). An error sets `otel.status = ERROR` and
`db.response.status_code = SQLSTATE`.

**Exemplars** (optional tail of 5.3, **deferred** — not an M3 criterion): the
last sampled `{trace_id, span_id, value}` per histogram row, emitted in the
OTLP histogram `exemplars` and in an OpenMetrics `/metrics` variant negotiated by
`Accept`. The seam exists (`lk_span` already carries the ids); it bolts on
without reworking anything.

## Configuration & environment (Р34, task 5.4)

Every agent flag has a `LATKIT_<UPPER_SNAKE>` environment equivalent. The
resolution order is **flag > `LATKIT_*` env > (`OTEL_*` env for the five OTel
vars) > default**. Mechanically: `main.c` records which options getopt saw, then
`apply_env_defaults` fills only the *unseen* ones from `env_opts[]` — so a flag
always wins, and a repeatable flag given on the CLI *replaces* (does not merge
with) its env list. Booleans read a truthy word (`1`/`true`/`yes`/`on`);
`0`/`false`/`no`/`off` leave the default. `--print-config` resolves everything
and prints it (before any BPF work) — the no-privilege way to see what the agent
will actually use, and the basis of `tests/unit/config_priority.sh`.

Standard OpenTelemetry variables are honoured as the default for their flag, so
an agent deployed beside other OTel tooling inherits the ambient config:

| Flag | `LATKIT_*` | Standard OTel var |
|---|---|---|
| `--otlp-endpoint` | `LATKIT_OTLP_ENDPOINT` | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| `--otlp-interval` | `LATKIT_OTLP_INTERVAL` | — |
| `--otlp-header` (list) | `LATKIT_OTLP_HEADERS` | `OTEL_EXPORTER_OTLP_HEADERS` |
| `--otlp-resource` (list) | `LATKIT_OTLP_RESOURCE` | `OTEL_RESOURCE_ATTRIBUTES` |
| (`service.name`) | `LATKIT_OTLP_SERVICE_NAME` | `OTEL_SERVICE_NAME` |

For a list-valued env var (`LATKIT_OTLP_HEADERS`, `LATKIT_OTLP_RESOURCE`,
`LATKIT_PORT`) the whole comma-separated list lives in the single variable
(`LATKIT_OTLP_HEADERS="k1=v1,k2=v2"`), matching the OTel spelling. **No YAML in
v1**: a YAML parser is a dependency or a chore, and a systemd unit / DaemonSet
lives comfortably on flags + env; revisit on real demand.

## Security posture (PLAN.md §7)

- **Bind loopback by default.** `--prom-listen` defaults to `127.0.0.1:9752`;
  scraping from another host or a container is an explicit `0.0.0.0` choice. No
  TLS/auth on the agent's own endpoints in v1 (front with a reverse proxy) — a
  documented limitation; a bind failure is fatal at startup, never a silent
  fallback.
- **Raw SQL leaves the agent only through spans.** Metrics are masked by
  construction (normalisation turns literals into `?` before anything reaches a
  label). Spans are the one place the raw SQL — literals and all — leaves the
  process, so they are **off by default**. `--otlp-span-masked` sends the
  normalised (literal-free) text as `db.query.text` for environments that need
  spans without leaking literals; `--otlp-span-text-max` caps the text.
  Exemplars carry only ids, never text.
- **Untrusted network input.** The HTTP server is a microscopic GET-only subset
  with per-connection size/time limits (Р29); the protobuf path is write-only.

## v1 limitations (with the native-histogram recipe)

- **No HTTPS on the OTLP endpoint** — `http://` only. A sidecar Collector is the
  standard OTel topology; front a remote Collector with TLS termination if
  needed.
- **No OTLP/gRPC** — OTLP/HTTP only. The Collector accepts both; gRPC would add a
  dependency for nothing.
- **No Prometheus protobuf exposition / native histograms on `/metrics`.** The
  text format carries classic `le` buckets (Р30). Native histograms need the
  protobuf exposition format — a second serialiser for data the same Prometheus
  already accepts over OTLP. **Recipe:** point latkit's OTLP exporter at
  Prometheus directly (its `otlp-write-receiver`) or at a Collector in front of
  it — our OTLP path already emits a lossless `ExponentialHistogram`, which
  Prometheus stores as a native histogram. Revisit a protobuf exposition only if
  real demand appears (stage 8+).
- **No `traceparent` from SQL comments** (sqlcommenter) — spans are standalone;
  correlating with an upstream trace is a v1.1 candidate.
