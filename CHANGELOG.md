# Changelog

All notable changes to latkit are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the metric
nomenclature is treated as a public API, so any change to a metric name or its
label set is called out explicitly.

## [Unreleased]

### Added

- **MySQL / MariaDB support (classic protocol).** latkit now observes MySQL 5.7
  / 8.x and MariaDB 10.6+ to the same depth as PostgreSQL: simple and prepared
  statements, sessions, multi-statements and multi-resultsets, `LOAD DATA LOCAL
  INFILE`, transactions, and errors (errno + SQLSTATE), plaintext and over TLS
  via the same libssl uprobe channel. Select a port's wire protocol with
  `--port 3306=mysql` (a bare port number still defaults to `pg`); one agent can
  watch a 5432 and a 3306 at once. See
  [docs/notes-myproto.md](docs/notes-myproto.md) and the design plan in
  `MYSQL.md`.
- MySQL deploy stacks: [`deploy/demo-mysql`](deploy/demo-mysql) (the two-minute
  demo, plaintext + TLS profiles) and
  [`deploy/existing-mysql`](deploy/existing-mysql) (monitoring-only, for a
  MySQL/MariaDB you already run).
- Dashboards gained a **`proto`** template variable; all four work under
  `proto="pg"` and `proto="mysql"`.
- Accuracy validation extended with a MySQL track against
  `performance_schema.events_statements_summary_by_digest`
  ([docs/accuracy.md](docs/accuracy.md)).

- **HTTP/1.x support.** latkit now observes an HTTP server the way it observes a
  database: `--port 8080=http` (a bare port number still means `pg`) and every
  request-response on that port becomes an observation — method, **templated
  route**, Host, status, body sizes and four separate timings — from a server
  with no access log, no status module and no instrumentation. Keep-alive,
  pipelining, `Transfer-Encoding: chunked`, `Expect: 100-continue`, 1xx,
  absolute-form targets and all methods are parsed; HTTP/2 (hence gRPC),
  WebSocket/`Upgrade`, `CONNECT` tunnels and `sendfile` bodies are recognised
  and counted as blind rather than guessed at. Plaintext and TLS, OpenSSL and Go
  servers alike. See [docs/notes-httpproto.md](docs/notes-httpproto.md) and the
  design plan in `PLAN-HTTP.md`.
- **Route templating** (`route` label): a URL is unbounded by construction, so
  the label is a template built in three layers — an explicit map
  (`--http-routes FILE`), a segment classifier (numbers, UUIDs, ULIDs, hex
  digests, dates, digit-dense and over-long segments become `{id}`; the query
  string is dropped unless named in `--http-query-keys`), and the same top-K
  dictionary that bounds the `query` label. The heuristic decides *which*
  routes you get, never *how many*: the overflow is `route="other"` and its
  share is a panel. Knobs: `--http-routes`, `--http-route-depth`,
  `--http-query-keys`, `--http-route-header`, `--http-user`, `--http-redact`,
  each with a `LATKIT_HTTP_*` environment equivalent.
- HTTP deploy stacks: [`deploy/demo-http`](deploy/demo-http) (the two-minute
  demo — nginx + a Go backend + load, with `tls` and `trace` profiles) and
  [`deploy/existing-http`](deploy/existing-http) (monitoring-only, for a web
  server you already run).
- **HTTP metric families and the `latkit-http` dashboard** (PLAN-HTTP.md М5).
  Observations from an `--port 8080=http` port are reported under their own
  family set rather than borrowed database ones:
  `latkit_http_requests_total{route,method,host,user,proto,status}`,
  `latkit_http_request_duration_seconds{…,code}`, `latkit_http_ttfb_seconds`,
  `latkit_http_request_upload_seconds`,
  `latkit_http_errors_total{code,host,user,proto}`,
  `latkit_http_bytes_total{…,direction}` and
  `latkit_http_response_size_bytes` (an octave grid, 64 B … 1 GiB, separate from
  the latency one). `route` is the *template*, bounded by the same top-K
  dictionary the `query` label uses; the share of `route="other"` is on the
  dashboard as the honesty signal for how well the templater is doing.
  The four timings of РH5 are visible here: duration and TTFB both start at the
  *end of the request*, so a slow upload is not reported as a slow server, and
  the upload interval is its own family.
- `latkit_ignored_conns_total{reason}` gained `h2`, `upgrade` and `connect` —
  the HTTP blind zones, split by what the connection switched to (they replace
  the single `blind` reason introduced during the HTTP track's development).

- **HTTP spans that join the caller's trace** (PLAN-HTTP.md М6, РH11). A sampled
  observation from an HTTP port is exported as an OTel `SPAN_KIND_SERVER` span
  with the current HTTP semantic conventions (`http.request.method`,
  `http.route`, `http.response.status_code`, `server.address`, `url.scheme`,
  `url.path`, `network.protocol.version`, `user_agent.original`,
  `client.address`, request/response body sizes). If the request carries a W3C
  `traceparent`, the span takes **that** trace id and the caller's span id as its
  parent, and passes `tracestate` through — so the agent's view of a request
  appears inside an existing distributed trace with no instrumentation in the
  application. Sampling becomes parent-based for such requests: a sampled trace
  is always exported, an unsampled one is skipped by the ratio predicate but can
  still be picked up by `--otlp-spans-slow-ms` (the asymmetry is deliberate and
  documented). Database spans are unchanged, `SPAN_KIND_CLIENT` and `db.*` as
  before.
- **`--http-redact` (default on)** — query-string values whose key names a
  credential (`token`, `sig`, `password`, `secret`, `key`, `code`, `auth`,
  matched as case-insensitive substrings) are replaced by `***` where the request
  target leaves the handler, so every output path — spans, `--queries`, anything
  later — carries the redacted form. Credential headers (`Authorization`,
  `Proxy-Authorization`, `Cookie`, `Set-Cookie`) are additionally blanked in the
  `--messages --hexdump` view. `--http-redact off` restores the raw target.

- **HTTPS: TLS capture for HTTP servers, OpenSSL and Go** (PLAN-HTTP.md М7,
  РH13). An HTTPS port is observed exactly like a cleartext one — same routes,
  statuses and timings — from two plaintext sources:
  - **OpenSSL servers** (nginx, Apache, HAProxy) need no new machinery: with
    `--tls auto` the `/proc` scan set is now derived from the protocols on
    `--port`, so an HTTP port scans for `nginx`, `httpd`, `apache2`, `haproxy`
    while a database port keeps scanning for `postgres`, `mysqld`, `mariadbd`.
    `--libssl` also accepts a *server binary* with a statically linked OpenSSL.
  - **Go servers** (Caddy, Traefik, any `net/http`) get a channel of their own:
    `--tls-go PATH` probes `crypto/tls.(*Conn).Read/Write` inside the named
    binary. Since a uretprobe cannot survive Go's goroutine-stack copying, the
    agent decodes the function bodies and probes their `ret` instructions
    instead; a body that does not decode cleanly is left unhooked and reported,
    never probed at a guessed offset. Stripped binaries — which is how Caddy,
    Traefik and MinIO are all shipped — are resolved through Go's own function
    table (`.gopclntab`) when the ELF symbol table is gone.
    `latkit_tls_attached{state}` gained the value **`go`**. x86-64; see
    [docs/notes-tls.md](docs/notes-tls.md) §4b.

  An HTTP connection that starts with a TLS handshake is now recognised as such
  by the framer (HTTP, unlike PG/MySQL, negotiates nothing in band), so an
  HTTPS port with no uprobes attached reads as "TLS, unread" instead of
  producing parse errors from ciphertext.
- **`latkit_udp_bytes_total{port,dir}` and `latkit_udp_packets_total{port,dir}`**
  (РH16) — datagram volume on the captured ports, counted and never parsed. This
  exists for one failure mode: HTTP/3 is QUIC over UDP and never passes the TCP
  capture point, so an h3 server is indistinguishable from a broken agent. Now it
  is not: the counters are non-zero and the agent says so once per port in its
  log. The series appear only for ports that actually see datagrams.
- **Per-port capture budget** (РH14): `--port 8080=http:4096` sets how many bytes
  of each send/recv call are copied for that port. HTTP ports default to 2048 (a
  head is all the framer reads, and a gigabyte of response body copied into the
  ringbuf buys nothing), database ports keep the 8192 of `--capture-limit`; a
  global `--capture-limit` still caps the protocol default, while an explicit
  per-port value wins outright. `latkit --print-config` prints the resolved
  budget per port as `port_cap=PORT:BYTES`.

- **S3 / MinIO support** (`--port 9000=s3`). latkit now observes an
  S3-compatible object store — MinIO first, and anything else on the same wire
  (Ceph RGW, SeaweedFS, Garage) — with no admin credentials, no bucket-metrics
  level to raise and no restart. S3 is implemented as a **dialect of the HTTP
  track**, not as a second protocol: the same framer, the same four timings, the
  same TLS channels and the same per-port budget, with the object store's nouns
  on top (PLAN-MINIO.md, [docs/notes-s3proto.md](docs/notes-s3proto.md)):
  - **the operation replaces the route.** `(method, path shape, query keys)` map
    through a table of ~45 values — `GetObject`, `PutObject`, `UploadPart`,
    `CompleteMultipartUpload`, `ListObjectsV2`, `DeleteObjects`, `CopyObject`,
    the sub-resource calls — so cardinality is bounded by the table rather than
    by a heuristic, and the route templater is off for this dialect. An unknown
    call is `op="other"`, whose share is a **freshness** signal about the table
    rather than a cardinality guard. **The object key is never a label**;
  - **`bucket`** takes the `host` slot, path-style or from the Host with
    `--s3-domain`, and only after passing S3's naming rules (`bucket="other"` if
    it does not; `bucket="-"` when the request names none, e.g. `ListBuckets`);
  - **`user`** is the access key out of the SigV4 `Credential=` or a presigned
    `X-Amz-Credential` — the public half of the pair. The signature, the
    per-chunk signatures and `X-Amz-Security-Token` are never read; an anonymous
    request is `user="-"`; `--s3-user off` drops the label. Because STS
    credentials are ephemeral, the (bucket,user) dimension ceiling is raised to
    128 for an `s3` port (32 elsewhere) and spills to `user="other"`;
  - **the S3 error code** is read from the `<Code>` element at the start of an
    error response body — the only case in which any response-body byte is
    parsed — so `NoSuchKey`, `NoSuchBucket` and `AccessDenied` are three
    different failures instead of two status numbers;
  - **two byte counts**: the wire's `Content-Length` and the object's logical
    size from `x-amz-decoded-content-length` when the upload is `aws-chunked`.
    The size histogram is fed by the logical one, so chunk framing is not
    reported as part of your objects.
- **S3 metric families and the `latkit-s3` dashboard** (PLAN-MINIO.md МS2). An
  `s3` port reports through its own family set:
  `latkit_s3_requests_total{op,method,bucket,user,proto,status}`,
  `latkit_s3_request_duration_seconds{…,code}`, `latkit_s3_ttfb_seconds`,
  `latkit_s3_request_upload_seconds`,
  `latkit_s3_errors_total{s3code,bucket,user,proto}`,
  `latkit_s3_bytes_total{…,direction}`, `latkit_s3_object_size_bytes` (an octave
  grid over the logical size) and `latkit_s3_internal_requests_total` — MinIO's
  own `/minio/…` surface, counted and present in nothing that says "requests".
  The `rows`/`txn` families are off in this profile: an object store has no rows
  and no transactions. `dashboards/latkit-s3.json` is the sixth bundled
  dashboard.
- **`proto="s3"`** is a new value of the existing `proto` label, and the
  dashboards' `$proto` variable selects it.
- **S3 spans**: a sampled S3 observation is exported with the HTTP semantic
  conventions plus `aws.s3.bucket` and `url.template` (the operation). A span is
  the only path by which a `url.path` — object key included — leaves the host,
  and spans stay off until an OTLP endpoint is configured.
- **TLS for MinIO** (PLAN-MINIO.md МS3, РS8): MinIO terminates TLS in Go's
  `crypto/tls` and maps no `libssl`, so of the three mechanics the HTTP track
  built exactly one applies — `--tls-go /usr/bin/minio`, stripped official image
  included. `minio` joined the comm set derived from an `s3` port (it gates the
  uprobe channel), a configuration that cannot work (`--tls auto` with no
  `--tls-go` on an s3-only agent) now warns at startup instead of reporting a
  flat dashboard, and a binary that cannot be hooked explains which of five
  causes it hit. Verified as a comparison: a TLS run and a plaintext run of the
  same load produce the same observations operation for operation.
- S3 deploy stacks: [`deploy/demo-minio`](deploy/demo-minio) (the two-minute
  demo — MinIO driven by `mc` through every operation family, plus a `tls`
  profile) and [`deploy/existing-minio`](deploy/existing-minio)
  (monitoring-only, for a MinIO you already run).
- Accuracy validation extended with an S3 track against `mc admin trace`, joined
  per request by `x-amz-request-id` ([docs/accuracy.md](docs/accuracy.md) §S3):
  duration p50 0.17 ms / p90 0.29 ms against MinIO's own `callStats`, status and
  response bytes exact, and 100 % of operations agreeing with the name MinIO
  gives the call.

- **Redis support (RESP2/RESP3)** (`--port 6379=redis`). latkit now observes a
  cache the way it observes a database — Redis first, and everything on the same
  wire (Valkey, KeyDB, Dragonfly, Sentinel) — with no password, no `CONFIG SET`,
  no lowered `slowlog-log-slower-than` and no restart. Unlike S3 this is a
  **fourth framer** rather than a dialect: RESP has no heads, no statuses and no
  routes, so it brings its own value machine, its own unit queue and its own
  profile (PLAN-REDIS.md, [docs/notes-redisproto.md](docs/notes-redisproto.md)):
  - **the identity is a command from a closed table** — `GET`, `XADD`, and for
    the fifteen *container* commands the subcommand too (`CONFIG|GET`,
    `XINFO|STREAM`): ~250 values, so cardinality is a compile-time constant and
    the top-K dictionary has nothing to bound. An unknown verb (a module
    command, a fork's own) is `cmd="other"`, whose share is a **freshness**
    signal about the table. **Keys, values and arguments never become labels**,
    at any setting: the second element of a non-container command is a key, and
    it is not read;
  - **the two dimensions are connection state.** `db` is the `SELECT`ed database
    number and `user` the ACL user of `AUTH <user> <pass>` / `HELLO … AUTH`,
    both tracked per connection and both moved **only when the server accepts
    the command** — a refused `SELECT` or a `-WRONGPASS` changes nothing. A
    connection joined mid-stream reports `db="?"` rather than a `0` it would be
    guessing. The password is a separate array element: never read, and blanked
    in the `--messages --hexdump` view by the protocol's `mask_body` hook;
  - **the failure is a symbol**, the first token of the error reply
    (`WRONGTYPE`, `NOSCRIPT`, `NOAUTH`, `NOPERM`, `OOM`, `LOADING`, …), folded
    to a closed vocabulary. The sentence after it — which names the key that had
    the wrong type, the slot, the node — reaches nothing. **`-MOVED`/`-ASK` are
    counted as redirects and not as errors**, or a resharding cluster would read
    as a permanent outage;
  - **three kinds of duration, three families.** A command answered `+QUEUED`
    inside a `MULTI` has no latency worth reporting (it is counted and reaches
    no histogram); a blocking command's duration is the *client's* own timeout
    (`BLPOP key 30`) and has a family of its own; the general histogram is left
    with the server's actual work. The `MULTI`…`EXEC` interval goes to
    `latkit_txn_duration_seconds`, the same family PostgreSQL and MySQL feed;
  - **pub/sub and RESP3 pushes close no unit.** Order is the only correspondence
    RESP offers, so a delivery mistaken for a reply would shift every later
    latency on that connection plausibly and for ever; they are recognised and
    counted in `latkit_redis_push_total` instead.
- **Redis metric families and the `latkit-redis` dashboard** (PLAN-REDIS.md
  МR5). A `redis` port reports through its own family set:
  `latkit_redis_commands_total{cmd,db,user,proto,code}`,
  `latkit_redis_command_duration_seconds{…,code}`,
  `latkit_redis_blocking_seconds{cmd,db,user,proto}`,
  `latkit_redis_errors_total{error,db,user,proto}`,
  `latkit_redis_redirects_total{kind,proto}`,
  `latkit_redis_bytes_total{…,direction}`, `latkit_redis_value_size_bytes` (an
  octave grid from 8 B, because half of what a cache holds is smaller than the
  HTTP grid's first bucket), `latkit_redis_pipeline_depth{proto}` and
  `latkit_redis_push_total{proto}` — plus `latkit_txn_duration_seconds`
  unchanged. The `rows`, `ttfb` and `upload` families are off in this profile: a
  reply is one value, so there is no first row and no separate upload to report.
  `dashboards/latkit-redis.json` is the seventh bundled dashboard.
- **`proto="redis"`** is a new value of the existing `proto` label, and the
  dashboards' `$proto` variable selects it.
- **Redis spans**: a sampled command is exported with the DB semantic
  conventions (`db.system.name=redis`, `db.operation.name`, `db.namespace`,
  `error.type`) plus `redis.pipeline.depth` and, on an `EXEC`,
  `db.operation.batch.size`. `db.query.text` is **built** from the identity —
  `GET ?`, one `?` per argument — and never copied from the wire: on a
  PostgreSQL port a span carries raw SQL, here there is nothing raw to carry.
- **TLS for Redis** (PLAN-REDIS.md МR7, РR12): a `tls-port` is TLS from the
  client's first byte, and every Redis, Valkey and KeyDB build measured (Alpine
  images included) links OpenSSL dynamically — so `--tls auto` is the whole
  configuration and the existing libssl channel carries it. Two things follow
  from Redis' own thread model and are handled without configuration: the
  kernel-side uprobe gate admits the server's io threads by prefix (`io_thd_*`,
  since `io-threads N` moves the `SSL_read`/`SSL_write` calls there — an
  operator's own `--comm redis-server` was measured seeing 24 % of the traffic),
  and a connection that was already open when the agent attached is adopted on
  its first decrypted byte rather than read as ciphertext for the life of the
  pool. Verified as a comparison: an encrypted run and a plaintext run of the
  same load produce the same observations command for command.
- **A comm filter entry may end in `*`** and match a prefix (`--comm
  'io_thd_*'`, `LATKIT_COMM`, `--tls-comm`); the wildcard is accepted in the
  last position only and a filter that puts it elsewhere is refused at startup
  rather than installed to match nothing. `--print-config` prints the derived
  uprobe gate as `tls_gate_comm` beside `tls_scan_comm`.
- **Per-port capture budget of a `redis` port defaults to 512 bytes** (a command
  is a verb and a key; a value is never read). A *bulk* reply of any size is
  unaffected — it announces its length and the payload is skipped arithmetically
  — but an **array** reply longer than the budget cannot be skipped, and that
  command is not observed at all (its unit is counted in
  `latkit_queries_dropped_total`). `--port 6379=redis:4096` buys it back for a
  keyspace-scanning workload; both sides are measured in
  [docs/perf.md](docs/perf.md) §Redis.
- Redis deploy stacks: [`deploy/demo-redis`](deploy/demo-redis) (the two-minute
  demo — every command family, a pipeline, a transaction, a blocking pop, a
  subscription and three failures that are three different symbols, plus a `tls`
  profile) and [`deploy/existing-redis`](deploy/existing-redis)
  (monitoring-only, for a Redis you already run).
- Accuracy validation extended with a Redis track against three references at
  once ([docs/accuracy.md](docs/accuracy.md) §Redis): counts exact against
  `INFO commandstats` (1 621 commands, 0 mismatched), **0 of 1 621** durations
  below the server's own per-command execution time from `SLOWLOG GET`, and our
  p50 of 6 µs under `memtier_benchmark`'s 39 µs — the inequality
  `SLOWLOG ≤ latkit ≤ client`, which is what "measured on the wire rather than
  inside the server" means as a number.

### Changed

- **Renamed self-metric: `latkit_http_requests_total` →
  `latkit_exporter_requests_total`** (labels `{path,code}` unchanged). The old
  name described the agent's *own* `/metrics` server; with HTTP observation it
  would have collided with the traffic being observed. This is the one breaking
  change of the HTTP track: alerts or dashboards referring to the agent's
  exporter request count must be updated. The bundled dashboards already are.
- **Metric label set: every query-family series now carries a
  `proto="pg"|"mysql"` label** (`latkit_query_duration_seconds`,
  `latkit_queries_total`, `latkit_query_errors_total`, `latkit_query_rows_total`
  and the transaction/first-row series). This is the only visible change for
  existing PostgreSQL users — the label is *added*, no metric is renamed or
  removed, and existing PromQL keeps working (an un-grouped query now simply
  spans both protocols). Grouping or joining by the full label set should add
  `proto`. Bundled dashboards and alerts are updated; a minor version, no major
  bump.
- `--tls auto` default `/proc` scan set is now `{postgres, mysqld, mariadbd}`
  (was `postgres`), widened by `{nginx, httpd, apache2, haproxy}` when an HTTP
  port is configured (М7) and by `{minio}` when an `s3` one is (МS3).
  `--tls-comm` still narrows it to a single comm. A deployment with only
  database ports scans exactly what it scanned before.
- Internal, no visible effect: the kernel-side `ports` map value grew from a
  flag to a small struct (the per-port budget above), and the comm-filter
  capacity from 4 to 12 entries (a host running all three protocols with TLS
  needed nine slots).

### Fixed

- **`--tls auto` no longer narrows plaintext capture.** The comm set latkit
  derives for TLS (the libssl scan set, `--tls-comm`, the basenames of
  `--tls-go` binaries, `connection`) was installed as *the* kernel capture
  filter, gating the socket path as well as the uprobes. On a database host that
  was invisible — the captured process is the scanned one — but on any host
  where it is not, capture went silently missing: with TLS on, a plaintext
  `--port 8081=http` served by a Go, Node or Python application produced **no
  observations at all**, while the nginx port beside it looked healthy. The
  symptom was a port with connections and zero queries.
  The derived set now gates only the uprobe channels, which is what it was for
  (a shared-`libssl` uprobe attaches at pid=-1 and fires for every process
  mapping the file). `--comm` is unchanged: an explicit filter still applies to
  every path. Nothing changes for a database-only deployment. Regression: the
  `comm-filter scope` phase of `tests/kernel/smoke.sh`, on the whole kernel
  matrix.

### Notes

- **HTTP blind zones** (recognised and counted, never guessed at):
  **HTTP/2 — and therefore gRPC** (`latkit_ignored_conns_total{reason="h2"}`;
  a TLS port facing browsers negotiates h2 through ALPN almost always, so
  capture the origin leg behind the terminator, which is HTTP/1.1 by default),
  WebSocket and any `Upgrade` (`reason="upgrade"`), `CONNECT` tunnels
  (`reason="connect"`), **HTTP/3** (QUIC over UDP never reaches the TCP capture
  point — hence the UDP counters above), and `sendfile` response bodies on
  kernels that do not route them through `sendmsg` (`bytes_out` becomes a
  declared lower bound). Request bodies and headers beyond a small list of
  interest are never parsed. Outgoing (client-side) requests are out of scope in
  v1. Reasoning: README "Known limitations", PLAN-HTTP.md §8.
- **HTTPS: one parse error per ~70 client connections** (newly documented, see
  [docs/notes-tls.md](docs/notes-tls.md) §6). An HTTPS connection is recognised
  as TLS from the first event of a direction; nginx's OpenSSL reads the client's
  record header in two pieces, so the client side is recognised late — from the
  server's ServerHello — and the ciphertext framed in between is counted as one
  parse error. The observations (route, status, timings) are unaffected: they
  come from the uprobe channel. Measured at 1.4 % of connections on a stand that
  opens one connection per request; a keep-alive client sees it far less often.
- **A `tcp_sendmsg` the kernel refuses is still counted** (capture layer, all
  protocols, newly documented — see
  [docs/notes-iov.md](docs/notes-iov.md) "Known limitations"). SEND is hooked on
  entry, before a return value exists, so a call rejected with `-EAGAIN` on a
  full socket buffer is counted at its requested length and the application's
  re-send is counted again. It takes a large response and a saturated socket:
  measured at ~0.07 % of observations on the HTTP demo's 8 MB routes, where it
  inflates `bytes_out` and produces one `parse_errors` + a resync per
  occurrence. Loud, not silent — but not fixed in this release: the correction
  is a capture-layer redesign (SEND moving to the `fexit` shape RECV already
  uses).
- **MySQL blind zones** (recognised and honestly counted, not parsed): the X
  Protocol (port 33060), the compressed protocol (`CLIENT_COMPRESS`), and
  replication streams (`COM_BINLOG_DUMP`). MariaDB builds linking bundled
  wolfSSL/GnuTLS instead of OpenSSL cannot have their TLS decrypted (detected
  and dropped-and-counted). See [README](README.md) "Known limitations".
- **S3 blind zones and non-goals**, all of them counted rather than guessed at:
  MinIO's inter-node **grid** (binary msgp inside a websocket — it leaves
  through `latkit_ignored_conns_total{reason="upgrade"}`), the rest of the
  `/minio/…` surface on the client port including health probes and the **admin
  API** (`latkit_s3_internal_requests_total`, which on a distributed pool is
  most of the port's traffic), the **Console/WebUI** (a separate port, not
  captured unless named), **S3 Select** and other event-framed responses (the
  body is not parsed; timings and status stay right), and request bodies (XML
  policies, the key list of a `DeleteObjects`). MinIO offers `http/1.1` to every
  real client's ALPN list, so an `s3` port does not fall into the h2 blind zone
  the way a browser-facing web server does — a proxy in front of it can.
- **S3: the tail of a large response body can be under-counted** (measured, see
  [docs/accuracy.md](docs/accuracy.md) §S3). A 1 MiB object leaves in 128 KiB
  writes, each captured at the port's 2048-byte budget with the remainder
  reported as a hole — and a hole is detected when the *next* call starts, which
  for a body's last call never comes. 25 of 880 requests on the accuracy stand
  therefore reported `bytes_out` short by one call's worth, flagged
  `LK_QO_BODY_UNSEEN` and left out of the size histogram: a declared lower
  bound, never above the truth, and bounded by one call regardless of object
  size.
