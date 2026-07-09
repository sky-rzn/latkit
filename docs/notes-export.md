# notes — exporters (stage 5)

Design notes for `src/export/`. This file grows over stage 5; task 5.1 covers
the Prometheus pull path (the HTTP server, `/metrics`, `/healthz`). The OTLP
push path, spans and the full config/env table land with tasks 5.2–5.4.

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
