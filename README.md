# latkit

An eBPF agent (C + libbpf, CO-RE) for PostgreSQL observability: it captures
PostgreSQL wire traffic at the TCP-socket level, and will parse the v3
protocol into per-query latency metrics exported to Prometheus and
OpenTelemetry. No backend of its own — Grafana reads the data from
Prometheus / an OTel-compatible store.

**Status: capture, framing, parser, metrics, and exporters done (milestones M1 + M2 + M3).**
The agent attaches to a live kernel, captures both directions of traffic on
configured server ports as a stream of connection-scoped events, accounts for
every lost event, and survives overload without touching the database. On top of
that it runs the stage-2 userspace pipeline (an epoll event loop, a connection
table, and a streaming framer that reassembles the event stream into whole
PostgreSQL v3 messages) and the stage-3 protocol handler, which turns those
messages into protocol-independent **query observations** — timings, the
SQL-text prefix, row counts, SQLSTATE, and session labels — for simple, extended
(prepared / pipelined) and COPY traffic, honestly dropping anything that spans a
loss. Stage 4 aggregates those observations into a bounded set of Prometheus
series: it normalises the SQL to a fingerprint (literals → `?`, à la
`pg_stat_statements` but lexer-only), keeps latency histograms under a top-K
cardinality cap, and exposes them plus agent self-metrics as a valid Prometheus
text exposition. Stage 5 serves that exposition over HTTP `/metrics`
(`--prom-listen`) and pushes the same registry to an OTel Collector as OTLP/HTTP
protobuf (`--otlp-endpoint`) — `Sum`s, `Gauge`s, and `ExponentialHistogram`s —
plus optional sampled **spans** carrying the exact per-query timings and full
SQL. See [PLAN.md](PLAN.md) (Russian) for the roadmap,
[STAGE1.md](STAGE1.md) for the capture-layer decisions, [STAGE2.md](STAGE2.md) /
[docs/notes-reassembly.md](docs/notes-reassembly.md) for the framing model,
[STAGE3.md](STAGE3.md) / [docs/notes-pgproto.md](docs/notes-pgproto.md) for the
parser, [STAGE4.md](STAGE4.md) / [docs/notes-metrics.md](docs/notes-metrics.md)
for normalisation, the metric nomenclature, the duration model, and cardinality
control, and [STAGE5.md](STAGE5.md) / [docs/notes-export.md](docs/notes-export.md)
for the exporters, the OTLP mapping, spans, and the config/env layer.

## How it works

Kernel side (`src/bpf/latkit.bpf.c`):

- `fentry/tcp_sendmsg` + `fentry/fexit tcp_recvmsg` read payload bytes
  straight out of the userspace `iov_iter` (see
  [docs/notes-iov.md](docs/notes-iov.md)) and emit chunked data events into a
  ringbuf;
- `tp_btf/inet_sock_set_state` tracks connection lifecycle: `CONN_OPEN` on
  ESTABLISHED, `CONN_CLOSE` on CLOSE;
- connections are keyed by the socket cookie; only sockets whose **local**
  port is in the filter map are captured (the server side), so loopback
  traffic is seen exactly once and directions are fixed: `RECV` =
  frontend→backend, `SEND` = backend→frontend;
- losses are double-accounted: global per-CPU counters plus a per-connection
  `seq`/`LK_F_GAP` scheme, so userspace can tell exactly which connection
  lost how many events;
- capture is budgeted (`--capture-limit`, per-connection HEADERS mode), but
  `total_len` always reports the real call size — budgets only cut
  `cap_len`, so the future reassembler knows the exact size of every hole.

Userspace (`src/agent/`) loads the skeleton, fills the filter maps and runs an
epoll loop over the ringbuf, a timerfd (10 s stats, 60 s connection sweep) and
a signalfd for clean shutdown. Decoded records feed a connection table (seq-gap
detection, LRU ceiling, idle sweep) and a streaming framer that emits whole
protocol messages. Output is opt-in: `--events` prints one line per raw event,
`--messages` one line per reassembled message (`--hexdump` adds the body
prefix); a stats line goes to stderr every 10 s. `--record` dumps the raw
event stream to a file that replays offline through the same pipeline (used by
the test fixtures — see `tests/replay`).

## Requirements

- **Linux kernel 5.15+** with BTF (`/sys/kernel/btf/vmlinux`). The hard
  floors underneath that claim: BPF ringbuf (5.8), `bpf_get_socket_cookie`
  in tracing programs and BPF atomics (5.12), plus fentry/`tp_btf`
  trampolines. Developed and verified on 6.x; pre-6.x validation is a
  stage-8 task (the CO-RE branches for older `iov_iter` layouts are framed
  but untested).
- clang (BPF target), CMake ≥ 3.16, `bpftool`, `libelf`, `zlib`.
- Root (or `CAP_BPF` + `CAP_PERFMON`) to run.

## Build

```sh
git submodule update --init            # bundled libbpf
cmake -B build
cmake --build build -j"$(nproc)"
ctest --test-dir build                 # unit tests, no root needed
```

Use `-DLATKIT_SYSTEM_LIBBPF=ON` to link against a system libbpf ≥ 1.0
instead of the submodule, and `-DLATKIT_VMLINUX_H=` to build on a host
without BTF.

## Run

```sh
sudo ./build/latkit                    # captures local port 5432
```

| Flag | Default | Meaning |
|---|---|---|
| `-p, --port PORT` | 5432 | local (server) port to capture; repeatable, up to 16 |
| `--ringbuf-bytes N` | 8 MiB | ringbuf size, power of two |
| `--capture-limit N` | 8192 | capture budget in bytes per send/recv call; `total_len` stays honest |
| `--comm NAME` | off | only capture send/recv from processes with this exact comm |
| `--cap-headers` | off | test hook: switch every connection to HEADERS mode (64 B/call) at OPEN |
| `--max-conns N` | 65536 | userspace connection table ceiling; the least recently active entry is evicted past it |
| `--conn-idle-timeout SEC` | 600 | evict connections with no events for this long (leak insurance for lost CLOSEs) |
| `--record FILE` | off | append every raw ringbuf record to FILE for offline replay (LKT1 trace) |
| `--events` | off | print one line per raw ringbuf event (the stage-1 output) |
| `--messages` | off | print one line per reassembled protocol message |
| `--queries` | off | print one line per session and per parsed query observation (debug tee before the aggregator) |
| `--top-queries N` | 500 | distinct normalised queries tracked before the rest fold into `query="other"` |
| `--query-label-len N` | 256 | max chars of the normalised text kept as the `query` label |
| `--first-row-hist` | off | also record `latkit_query_first_row_seconds` (doubles the query-labelled series) |
| `--dump-metrics[=FILE]` | off | write the Prometheus exposition on `SIGUSR1` and at exit, to FILE (default: stderr) |
| `-x, --hexdump` | off | dump event payload (`--events`) and the captured message body prefix (`--messages`) |

Dev environment (PostgreSQL 16 in docker + pgbench load):

```sh
docker compose -f deploy/dev/docker-compose.yml up -d
sudo ./build/latkit &
./deploy/dev/bench.sh -c 8 -T 15
```

### Reading `--queries`

`--queries` prints the stage-3 parser output: one line when a session
authenticates and one per query observation. It is the debug view of what stage
4 will aggregate into metrics — the parser does no normalisation, so the text is
the raw captured SQL prefix.

```
<ts> session conn=<cookie> user=<u> db=<d> app=<a> ver=<v>[ (incomplete)]
<ts> query conn=<cookie> dur=<n>ns kind=<k> db=<d> user=<u> rows=<n> \
     sqlstate=<s> txn=<c> flags=0x<f> text=<sql>
```

- `kind` — `simple` / `extended` / `function` / `copy_in` / `copy_out` /
  `cancel`.
- `dur` — the honest per-query span `ts_complete − ts_start` (see the timing
  model below). `rows` comes from the `CommandComplete` tag; `sqlstate` is `-`
  unless the query failed; `txn` is the `I`/`T`/`E` status from the closing
  `ReadyForQuery`.
- `flags` — the `LK_QO_*` bitset: `ERROR`, `TEXT_TRUNC` (text is a
  budget-truncated prefix), `NO_TEXT` (prepared statement not in cache, or a
  function call), `MULTI_STMT`, `EMPTY`, `SUSPENDED`, `ABORTED` (killed by an
  earlier error in a pipelined batch), `PIPELINED`.
- `text` is truncated to 120 chars **in the output only** — the observation
  carries the full captured prefix.

**Timing model.** All timestamps are `bpf_ktime_get_ns` at *syscall* granularity
(the framer's limit — messages packed into one `send`/`recv` share a timestamp,
[docs/notes-reassembly.md](docs/notes-reassembly.md)). Each observation carries
four: `ts_start` (query arrives), `ts_first_row`, `ts_complete` (reply done),
`ts_ready` (following `ReadyForQuery`). `--queries` reports `ts_complete −
ts_start`; a pipelined batch shares one `ReadyForQuery`, so this per-unit span is
more honest than `ts_ready − ts_start`. The full rationale and the parser's blind
spots (query cut off by a disconnect, `NO_TEXT`, TLS) are in
[docs/notes-pgproto.md](docs/notes-pgproto.md).

### Metrics (`--dump-metrics`)

`--dump-metrics[=FILE]` writes a Prometheus text exposition on `SIGUSR1` and at
exit — the aggregated form of the query observations, and the seam stage 5 wraps
in HTTP `/metrics` unchanged. Each observation is normalised to a fingerprint,
histogrammed by latency, and bounded by a top-K cardinality cap; agent
self-metrics (ringbuf drops, resyncs, parser errors, CPU/RSS) come through the
same dump. Send `kill -USR1 $(pidof latkit)` to sample it live.

```
# HELP latkit_query_duration_seconds Server-side query latency in seconds.
# TYPE latkit_query_duration_seconds histogram
latkit_query_duration_seconds_bucket{query="select ?",db="latkit",user="latkit",code="ok",le="0.0001220703125"} 165292
...
latkit_query_duration_seconds_bucket{query="select ?",db="latkit",user="latkit",code="ok",le="+Inf"} 165343
latkit_query_duration_seconds_sum{query="select ?",db="latkit",user="latkit",code="ok"} 23.71
latkit_query_duration_seconds_count{query="select ?",db="latkit",user="latkit",code="ok"} 165343
latkit_queries_total{db="latkit",user="latkit",kind="extended",code="ok"} 596799
latkit_query_errors_total{sqlstate="22012",db="latkit",user="latkit"} 3
latkit_metric_series 7
```

The `le` boundaries are exact powers of two, so they read as "un-round" decimals
(`0.0001220703125` = 2⁻¹³) — this is deliberate; see
[docs/notes-metrics.md](docs/notes-metrics.md) for the grid, the full series
nomenclature, the duration model, and the top-K / `other` behaviour.

**Security.** The agent sees SQL text, but literal masking is on by default and
by construction: normalisation turns every string and numeric literal into `?`
before it can reach a metric label, and raw SQL never enters the registry — only
the normalised, masked prefix does. Full SQL is available only to OTel spans,
opt-in (see below).

## Exporters (Prometheus + OpenTelemetry)

Two independent paths expose the registry above. The Prometheus **pull** server
is on by default; the OTLP **push** exporter turns on when an endpoint is set.

```sh
# Prometheus scrape target on :9752 (the default), OTLP push to a Collector,
# and 5 % of queries sampled as spans:
sudo ./build/latkit \
  --prom-listen 0.0.0.0:9752 \
  --otlp-endpoint http://localhost:4318 \
  --otlp-spans 0.05
curl -s localhost:9752/metrics | promtool check metrics   # valid exposition
curl -s localhost:9752/healthz                             # uptime/events/drops
```

| Flag | Default | Meaning |
|---|---|---|
| `--prom-listen ADDR:PORT\|none` | `127.0.0.1:9752` | serve `/metrics` + `/healthz`; `none` disables. Loopback by default — bind `0.0.0.0` to scrape from another host/container |
| `--otlp-endpoint URL` | off | push OTLP/HTTP metrics to this Collector base URL (`http://` only); **enables** the OTLP exporter |
| `--otlp-interval SEC` | 15 | OTLP export period |
| `--otlp-header K=V` | — | repeatable OTLP request header (auth for managed backends) |
| `--otlp-resource K=V` | — | repeatable OTLP resource attribute |
| `--otlp-spans RATIO` | off | sample this fraction `[0,1]` of queries as spans (**raw SQL!**); needs `--otlp-endpoint` |
| `--otlp-spans-slow-ms N` | off | also sample every query at least N ms long |
| `--otlp-span-text-max N` | 4096 | cap `db.query.text` at N bytes |
| `--otlp-span-masked` | off | send the normalised (literal-free) SQL as `db.query.text` instead of the raw text |
| `--print-config` | — | resolve config (flag > env > default) to stdout and exit; no BPF |

A quick end-to-end stack (postgres + pgbench + latkit + Prometheus + Collector)
lives in [tests/e2e/](tests/e2e) — `./tests/e2e/verify.sh` builds the agent,
brings it up, and asserts both paths (milestone M3).

### Configuration & environment

Every flag has a `LATKIT_<UPPER_SNAKE>` environment equivalent; the priority is
**flag > `LATKIT_*` env > (`OTEL_*` env, below) > default**. Booleans take a
truthy word (`1`/`true`/`yes`/`on`); repeatable/list vars hold a comma-separated
list in the one variable (`LATKIT_PORT=5432,5433`,
`LATKIT_OTLP_HEADERS="k1=v1,k2=v2"`). `latkit --print-config` prints the resolved
result. Standard OpenTelemetry variables are honoured as the default for their
flag, so an agent deployed beside other OTel tooling inherits the ambient config:

| Flag | `LATKIT_*` | Standard OTel var |
|---|---|---|
| `--otlp-endpoint` | `LATKIT_OTLP_ENDPOINT` | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| `--otlp-interval` | `LATKIT_OTLP_INTERVAL` | — |
| `--otlp-header` | `LATKIT_OTLP_HEADERS` | `OTEL_EXPORTER_OTLP_HEADERS` |
| `--otlp-resource` | `LATKIT_OTLP_RESOURCE` | `OTEL_RESOURCE_ATTRIBUTES` |
| (`service.name`) | `LATKIT_OTLP_SERVICE_NAME` | `OTEL_SERVICE_NAME` |

No YAML config in v1 — flags + env only (see [docs/notes-export.md](docs/notes-export.md)).

### Export security

- **Loopback by default.** `--prom-listen` binds `127.0.0.1`; exposing the
  endpoint (`0.0.0.0`) is an explicit choice. No TLS/auth on the agent's own
  endpoints in v1 — front with a reverse proxy; a bind failure is fatal.
- **Spans are the only path for raw SQL.** Metrics are masked by construction;
  spans carry the literal SQL and are **off by default**. Turn them on
  deliberately, and use `--otlp-span-masked` where literals must not leave the
  host (it substitutes the normalised text). `--otlp-endpoint` is `http://` only;
  a remote Collector should be fronted with TLS.
- **Native histograms in Prometheus?** Don't scrape for them — point the OTLP
  exporter at Prometheus's `otlp-write-receiver` (or a Collector in front of it);
  our OTLP `ExponentialHistogram` lands as a native histogram losslessly.

## Known limitations (v1 scope)

- TLS traffic is opaque at the socket level — the uprobe channel on
  `SSL_read`/`SSL_write` is stage 6.
- Unix-domain sockets are invisible (`tcp_*` is not on that path) — v1.1.
- `splice()`-relayed traffic (e.g. docker-proxy) arrives with kernel-page
  iterators: sends degrade to honest `cap_len=0` events, receives bypass
  `tcp_recvmsg` entirely. Irrelevant for the intended agent-on-the-DB-host
  deployment; details in [docs/notes-iov.md](docs/notes-iov.md).
