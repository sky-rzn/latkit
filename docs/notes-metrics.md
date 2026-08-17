# Normalisation and metrics (stage 4)

Companion to [STAGE4.md](../STAGE4.md) (the design decisions Р22–Р28) and
[PLAN.md](../PLAN.md) §4. This is the reference for what latkit measures and how
it keeps the metric cardinality bounded — the material a dashboard author or an
operator reading `/metrics` needs, without re-deriving it from the source.

The stage turns the parser's stream of **query observations** (`lk_query_obs`,
[docs/notes-pgproto.md](notes-pgproto.md)) into a bounded set of Prometheus
series held in memory: latency histograms, row/error/connection counters, and
agent self-metrics. Stage 5 serialises the same in-memory registry to the HTTP
`/metrics` endpoint and to OTLP without recomputing anything — the dump this
stage produces (`--dump-metrics`) is already a valid Prometheus text exposition.

The code lives in two pure modules (no libbpf, no I/O beyond a caller `FILE*`):
`src/norm/` (the SQL normaliser + fingerprint) and `src/metrics/` (the
histogram, the registry, the facade, the self-stat providers).

## Metric nomenclature

Names are frozen at milestone M2 and treated as a public API from here on
(the stage-7 dashboards depend on them). Units are seconds and bytes; counters
carry the `_total` suffix, per Prometheus convention.

### Query and transaction metrics

| Series | Type | Labels |
|---|---|---|
| `latkit_queries_total` | counter | `db, user, proto, kind, code` — `kind`=`simple\|extended\|function\|copy_in\|copy_out\|cancel`; `code`=`ok\|error\|aborted\|canceled` |
| `latkit_query_duration_seconds` | histogram | `query, db, user, proto, code` — `code`=`ok\|error` (Р23/Р25) |
| `latkit_query_first_row_seconds` | histogram | `query, db, user, proto` — opt-in, `--first-row-hist` (Р24) |
| `latkit_query_rows_total` | counter | `query, db, user, proto` — rows from `CommandComplete` |
| `latkit_query_errors_total` | counter | `sqlstate, db, user, proto` — **no** `query` label (Р23) |
| `latkit_queries_truncated_total` | counter | — observations whose SQL was a budget-truncated prefix |
| `latkit_queries_other_total` | counter | — observations folded into `query="other"` (top-K honesty) |
| `latkit_txn_duration_seconds` | histogram | `db, user, proto, status` — `status`=`ok\|aborted` (PG: `T→I` vs `E→I` at `ReadyForQuery`; MySQL: the `SERVER_STATUS_IN_TRANS` edge; Redis: `MULTI` … the reply to `EXEC`, РR9) |

`code="error"` in the duration histogram is deliberately just `ok|error`, not
the raw SQLSTATE: a SQLSTATE label in the `query × db × user` product would
explode the series count. Per-SQLSTATE detail lives, query-free, in
`latkit_query_errors_total`.

The `proto` label (`pg`\|`mysql`, РМ6) is present on every query family
**always**, not only when both protocols run: it is the wire protocol of the
connection (from `lk_conn.ops`), so a single-DBMS deployment simply pins it to
one value while a mixed one never blurs the two `(db,user,query)` spaces. It is
an orthogonal axis to the `(db,user)` cardinality limit — the per-`(db,user)`
`other` spill stays split per protocol.

### HTTP metrics (РH9/РH10)

An HTTP port (`--port 8080=http`) reports through its own **profile**: the same
registry, the same top-K dictionary and the same `other` fold, printed under
different family names and different label keys. Reusing `latkit_query_*` with
`proto="http"` would have been quicker and would have meant an HTTP request
carrying `rows`, `sqlstate` and a transaction histogram that mean nothing, in
the middle of the database dashboards.

| Series | Type | Labels |
|---|---|---|
| `latkit_http_requests_total` | counter | `route, method, host, user, proto, status` — `status` is the **class** (`1xx…5xx`) |
| `latkit_http_request_duration_seconds` | histogram | `route, method, host, user, proto, code` — `code`=`ok\|error` (error = 5xx) |
| `latkit_http_ttfb_seconds` | histogram | `route, method, host, user, proto` |
| `latkit_http_request_upload_seconds` | histogram | `route, method, host, user, proto` |
| `latkit_http_errors_total` | counter | `code, host, user, proto` — the **exact** status ≥ 400, **no** `route` |
| `latkit_http_bytes_total` | counter | `route, method, host, user, proto, direction` — `direction`=`in\|out` |
| `latkit_http_response_size_bytes` | histogram | `route, method, host, user, proto` — the octave grid below |

The label slots map onto the same interned dimensions the database profile uses:
`route` takes the query slot, `host` the `db` slot, `user` the `user` slot. Two
consequences worth knowing:

- **`method` is part of the route's identity**, not a decoration: the
  fingerprint is `XXH3(method NUL template)`, so `GET /orders/{id}` and
  `DELETE /orders/{id}` hold two dictionary slots and never share a histogram.
- **`user` is `-` unless `--http-user basic`.** HTTP usually has no user, but
  the label is always printed: it is part of the series identity, and a family
  that dropped it would emit two identical label sets the moment two users
  shared a route — which is a scrape error, not a cosmetic one.

`host` is the Host of *that request*, not of the connection: one keep-alive
socket can serve several virtual hosts.

**A 4xx is not an error.** `code="error"` on the duration histogram means 5xx —
the server failing. A 404 is the server correctly saying no, and folding it in
would make every 404-heavy service look broken. Both land in
`latkit_http_errors_total`, which carries the exact code (a set bounded by HTTP
itself, ~60 values) and no `route`, exactly as the SQLSTATE counter carries no
`query`.

**The four timings (РH5).** For a `GET` every latency model agrees and none of
this matters. For an upload they do not, so the interval is split:

```
ts_start ──request head+body──▶ ts_req_done ──server──▶ ts_first_row ──▶ ts_complete
```

- `latkit_http_request_duration_seconds` = `ts_complete − ts_req_done` — the
  server's time. A 1 GB POST over a slow link is not a slow server, and this is
  the number that says so;
- `latkit_http_ttfb_seconds` = `ts_first_row − ts_req_done`;
- `latkit_http_request_upload_seconds` = `ts_req_done − ts_start`, recorded only
  where it is the client's time alone: a request carrying `Expect:
  100-continue` contains a server round trip and is excluded, and a body that
  arrived in the same capture event as its head has no interval to report.

Note this differs from nginx's `$request_time`, which covers the whole
`ts_start … ts_complete` span. The two are reconciled — with numbers — in
[docs/accuracy.md](accuracy.md).

**Sizes** go into their own grid: one bucket per power of two, `le` = 64 B …
1 GiB (25 buckets). The latency grid's ±9% resolution is pointless for body
sizes and its range is wrong by twenty orders of magnitude; nobody reads a size
distribution to better than an octave. A response whose body never reached the
socket (`sendfile`, РH4 — `bytes_out` is then a lower bound) is left out of the
histogram but still counted in `latkit_http_bytes_total`: an undercounted total
is honest, an undercounted *distribution* is misleading.

**Route cardinality is bounded by construction**, not by the templater being
right. `route` goes through the same top-K dictionary as `query` (РH7 layer 3),
so a heuristic that fails on some API costs accuracy, never series count: the
overflow is reported as `route="other"`, and its share is a headline panel on
the HTTP dashboard. A large or growing share is the signal to raise
`--top-queries` or to pin the routes with `--http-routes`.

### S3 metrics (РS7, PLAN-MINIO.md МS2)

An S3 port (`--port 9000=s3`) is the same HTTP exchange (РS1) reported under a
third profile. Nothing in the engine differs — the dictionary, the doorkeeper,
the dimension limit and the `other` fold are shared — and everything in the
*nouns* does, because "which route, which host" and "which operation, which
bucket" are not the same question.

| Series | Type | Labels |
|---|---|---|
| `latkit_s3_requests_total` | counter | `op, method, bucket, user, proto, status` — `status` is the **class** |
| `latkit_s3_request_duration_seconds` | histogram | `op, method, bucket, user, proto, code` — `code`=`ok\|error` (error = 5xx) |
| `latkit_s3_ttfb_seconds` | histogram | `op, method, bucket, user, proto` |
| `latkit_s3_request_upload_seconds` | histogram | `op, method, bucket, user, proto` |
| `latkit_s3_errors_total` | counter | `s3code, bucket, user, proto` — the symbolic code, **no** `op` |
| `latkit_s3_bytes_total` | counter | `op, method, bucket, user, proto, direction` |
| `latkit_s3_object_size_bytes` | histogram | `op, method, bucket, user, proto` — the object grid below |
| `latkit_s3_internal_requests_total` | counter | none |

Four things are worth knowing, and each is a decision rather than a convention:

- **`op` is a lookup, not a heuristic** (РS2). It comes from the closed table of
  [notes-s3proto.md](notes-s3proto.md), so its cardinality is a compile-time
  constant (~45 values plus `other`) and the object key — the most sensitive
  part of an S3 request — is never a candidate for a label. The top-K
  dictionary is still underneath it, and still cannot be filled by hostile
  input. Consequently `op="other"` means something different from
  `route="other"`: not "the templater lost" but "the table has aged" (risk 5),
  which is why it has its own dashboard panel.
- **`bucket` and `user` take the two dimension slots** the query profile uses
  for `db` and `user` (РS3/РS4): the bucket after it passes the S3 naming rules
  (a name that fails them becomes `bucket="other"` rather than travelling into a
  label), the access key ID out of the request's own signature or presigned
  query. The signature, the chunk signatures and `X-Amz-Security-Token` are
  never copied. Because the dimension is (bucket × tenant) rather than (schema ×
  role), an agent watching an S3 port raises `max_session_dims` from 32 to
  **128**.
- **The failure has a name.** `s3code` is the `<Code>` of the error body (РS5),
  matched against the known S3 vocabulary and folded to `other` outside it;
  `NoSuchKey` and `NoSuchBucket` are both `404` and are different problems. A
  failing response that carried no code — a bodiless `HEAD` error from a server
  that sends no `x-minio-error-code` — is counted under its numeric status
  instead, so the label space is "S3 codes ∪ HTTP statuses".
- **`/minio/…` is counted and nothing more.** MinIO's own surface — health
  probes, the admin API, inter-node RPC — is not an S3 API, and on a
  distributed pool it is *most* of the traffic on the port (79 % of the data
  events in the МS0 measurement). It lands in
  `latkit_s3_internal_requests_total` and in no family that says "requests",
  which is the whole point of counting it separately.

**Object sizes get a second octave grid**: `le` = 1 KiB … 1 TiB (31 buckets),
against the HTTP response grid's 64 B … 1 GiB. The extent is a property of what
is being measured — an object store's distribution lives where a web server's
overflow cell is, and a 64 B first bucket would spend seven cells on sizes S3
never sees. The sample is the **logical** size (РS6): with `aws-chunked` that is
`x-amz-decoded-content-length` rather than the wire count, because the signed
chunk framing costs ~87 bytes per chunk (17 % at 1 KB chunks) and a distribution
built on the wire count would follow the client's buffer size instead of the
objects. Only the four operations that actually move object bytes feed it —
`GetObject`, `PutObject`, `UploadPart`, `PostObject` — and only when the server
accepted the request: a listing's XML, a multipart manifest and an error
document are payload too, and none of them is an object. `CopyObject` and
`UploadPartCopy` move objects entirely inside the server and are missing from
both this histogram and `latkit_s3_bytes_total`, which is the same documented
blind spot.

### Redis metrics (РR11, PLAN-REDIS.md МR5)

A Redis port (`--port 6379=redis`) reports under a fourth profile. The engine is
the same one again — one dictionary, one doorkeeper, one dimension limit — but
this profile is not the http shape under other nouns: RESP has no statuses, no
rows and no request body, and a command's *duration* means three different
things depending on how the server answered it.

| Series | Type | Labels |
|---|---|---|
| `latkit_redis_commands_total` | counter | `cmd, db, user, proto, code` — `code`=`ok\|error\|aborted\|canceled` |
| `latkit_redis_command_duration_seconds` | histogram | `cmd, db, user, proto, code` — `code`=`ok\|error` |
| `latkit_redis_blocking_seconds` | histogram | `cmd, db, user, proto` |
| `latkit_redis_errors_total` | counter | `error, db, user, proto` — the symbolic token, **no** `cmd` |
| `latkit_redis_redirects_total` | counter | `kind, proto` — `kind`=`moved\|ask` |
| `latkit_redis_bytes_total` | counter | `cmd, db, user, proto, direction` |
| `latkit_redis_value_size_bytes` | histogram | `cmd, db, user, proto` — the value grid below |
| `latkit_redis_pipeline_depth` | histogram | `proto` |
| `latkit_redis_push_total` | counter | `proto` — a parser counter (see below) |
| `latkit_txn_duration_seconds` | histogram | `db, user, proto, status` — **the existing family**, unchanged |

Six things are worth knowing, and each is a decision rather than a convention:

- **`cmd` is a table lookup, and the identity includes the subcommand** (РR4).
  `CONFIG|GET`, `XINFO|STREAM`, `CLIENT|LIST` are single labels; for every other
  command the second array element is a *key* and never reaches a label at any
  setting. Cardinality is a compile-time constant (~250 values plus `other`), so
  unlike `route` this label needs no top-K reasoning to stay bounded — the
  dictionary is underneath it and simply never fills. `cmd="other"` therefore
  reads like `op="other"` on S3: not "the classifier lost" but "the table has
  aged" — a module command, a fork's own admin verb, or a new Redis release.
- **`db` and `user` are connection state, not a startup packet** (РR5/РR6).
  Both take the dimension slots PG fills from its startup message, and both are
  filled here by a state machine that moves a label only when the *server*
  accepts the command: `SELECT 16` is an error and changes nothing,
  `AUTH u wrongpass` is `-WRONGPASS` and changes nothing. A connection joined
  mid-stream carries `db="?"` until a `SELECT` says otherwise — `"0"` would be a
  guess, and the whole family would be quietly wrong on a synthetic connection.
  The password half of `AUTH` is never read, and `--redis-user off` makes `user`
  the constant `-`. `max_session_dims` stays at its default 32: databases are
  ≤ 16 and ACL users are a handful (risk 7 of the plan).
- **Three durations, three homes.** `latkit_redis_command_duration_seconds` is
  work the server did. `latkit_redis_blocking_seconds` is the timeout the
  *client* chose — `BLPOP key 30` is a thirty-second observation about somebody
  else's traffic (РR10) — and one of those in the general histogram decides the
  p99 of the instance. A command answered `+QUEUED` inside a `MULTI` has no
  duration at all (РR9): it is counted in `commands_total` and appears in no
  histogram, because what it measures is how fast the server can write a command
  down. The interval that *does* mean something there is `MULTI` … the reply to
  `EXEC`, and it goes to `latkit_txn_duration_seconds` — the one family two
  profiles feed, printed once, keyed by `proto`, because a Redis transaction is a
  transaction in exactly the sense PG's is.
- **The failure has a symbol and the redirect is not one** (РR7). `error` is the
  first token of the reply (`WRONGTYPE`, `NOSCRIPT`, `NOAUTH`, `OOM`, `LOADING`,
  …) folded to a closed vocabulary; the sentence after it holds the key that had
  the wrong type and the node a `MOVED` points at, and it reaches no output.
  `-MOVED` and `-ASK` are error replies on the wire and ordinary cluster
  operation in fact, so they carry `LK_QO_CLIENT_ERR` (the flag a 4xx carries in
  HTTP), land in `latkit_redis_redirects_total{kind}` and appear in no error
  family — in one, a resharding cluster would be permanently red. `-MISCONF` and
  `-LOADING` are the opposite case and stay errors: that is a server refusing to
  work.
- **Values get a third octave grid**: `le` = 8 B … 8 MiB (21 buckets), against
  the HTTP grid's 64 B … 1 GiB and the object grid's 1 KiB … 1 TiB. Half of what
  a Redis holds is smaller than the HTTP grid's *first* bucket — a counter, a
  flag, a session id — so on that grid the median of every real workload is
  cell 0 and the distribution says nothing. The sample is the reply's size on the
  wire, minus the `+QUEUED` receipts, which are not values.
  `latkit_redis_pipeline_depth` reuses the same machine for something that is not
  a size at all: octaves 1 … 256 commands per syscall, sampled **per command**,
  so `le="1"` is "this command travelled alone" and the p50 answers "did the
  median command wait behind its own batch" (РR3).
- **`latkit_redis_push_total` is a parser counter, not a profile family.** A
  pub/sub delivery, a RESP3 push and a client-side-caching invalidation answer no
  command (РR8), so there is no observation to hang them on; they are published
  by the same provider as `latkit_parse_errors_total` and the rest of the
  per-protocol parser counters. Nothing was lost when one is counted — the
  opposite: a queue that let a push close a unit would mis-time every later
  command on that connection.

Deliberately absent, and each absence is a family that would have been noise:
no `rows` (a reply is one value), no TTFB (a reply has no first row to arrive
early — the family would always equal the duration), no upload interval (there
is no request body separate from the command), no `status` class, and no
`method` beside `cmd`.

### Connection and self metrics (Р27)

| Series | Type | Source |
|---|---|---|
| `latkit_connections_active` | gauge | conn table |
| `latkit_connections_opened_total` | counter | conn table |
| `latkit_conns_evicted_total{reason}` | counter | conn table (LRU / idle) |
| `latkit_ringbuf_dropped_total` | counter | kernel per-CPU `stats` (summed) |
| `latkit_events_total{dir}` | counter | kernel per-CPU `stats` |
| `latkit_resync_total` | counter | framer `lk_reasm_stats.resyncs` |
| `latkit_parse_errors_total{proto}` | counter | protocol parser, split by `proto`=`pg\|mysql` (РМ6) |
| `latkit_unknown_msgs_total{proto}` | counter | protocol parser, per `proto` |
| `latkit_queries_dropped_total{reason, proto}` | counter | parser `units_dropped_*` — `reason`=`resync\|disconnect\|overflow` (Р19), per `proto` |
| `latkit_ignored_conns_total{reason, proto}` | counter | deliberate blind zones — `reason`=`replication\|compressed` (РМ7/РМ8) or, on HTTP, `h2\|upgrade\|connect` (РH4), per `proto` |
| `latkit_exporter_requests_total{path,code}` | counter | the agent's **own** `/metrics` server (renamed from `latkit_http_requests_total` in the HTTP track, РH9) |
| `latkit_udp_bytes_total{port,dir}` | counter | kernel `udp_stats` map — datagram volume on a captured port, **counted and never parsed** (РH16, М7). Present only once a port sees UDP. Its reason for existing: HTTP/3 is QUIC over UDP and never reaches the TCP capture point, so without these an h3 server is indistinguishable from a broken agent |
| `latkit_udp_packets_total{port,dir}` | counter | the same map, packet count |
| `latkit_metric_series` | gauge | the registry itself — live count of cardinality-controlled series |
| `process_cpu_seconds_total` | counter | `getrusage(2)` |
| `process_resident_memory_bytes` | gauge | `/proc/self/statm` |
| `process_start_time_seconds` | gauge | recorded at startup |

Self-metrics are pulled through **providers** (`lk_metrics_add_provider`): a
callback per subsystem, run at the top of every dump, that pours its live
counters into flat named series. The aggregator never learns about libbpf or
procfs; the kernel never learns about metrics. The 10-second stderr stats line
prints from the same providers — one set of numbers in the log and in
`/metrics`.

## Duration model (Р25 + Р13)

Each observation carries four timestamps: `ts_start` (query arrives),
`ts_first_row`, `ts_complete` (reply done), `ts_ready` (following
`ReadyForQuery`). The histogrammed duration is:

- **standalone unit** (`LK_QO_PIPELINED` clear): `ts_ready − ts_start` — from
  the `Query`/`Bind` to the `ReadyForQuery` after `Sync`; the server is done
  **and** ready for the next request (PLAN.md §1);
- **pipelined unit** (`LK_QO_PIPELINED` set): `ts_complete − ts_start`. A
  pipelined batch shares one `ReadyForQuery`, so binding `ts_ready` to every
  unit would charge the tail of the batch the whole batch's wait. The honest
  per-unit span is `ts_complete`. The systematic offset between the two models
  (`ts_ready` also includes sending `Z`) is far below one bucket width (±9%),
  but it exists.
- `ts_ready == 0` (ABORTED / CANCEL — no `Z` seen) → **not** histogrammed; the
  observation is counted only, in `latkit_queries_total`.
- `latkit_query_first_row_seconds` = `ts_first_row − ts_start`, only when
  `ts_first_row != 0`.

**What this is not.** Timestamps are `bpf_ktime_get_ns` at syscall granularity
(Р13): messages packed into one `send`/`recv` share a stamp. This is
"network-to-network" server time — the time from the request landing in the
kernel to the reply leaving it — not `EXPLAIN ANALYZE` execute time. It includes
kernel/socket queueing ahead of the backend. A formal comparison against
`pg_stat_statements.mean_exec_time` is a stage-8 task; here we only sanity-check
that the histogram mass lands where pgbench's own latency report says it should.

## Normalisation and deviations from pg_stat_statements (Р22)

The normaliser is a single-pass lexer (a state machine over bytes), not a PG
parser — the same spirit as `pg_stat_statements`, zero allocations, output into
the caller's buffer. Rules, in priority order:

- comments (`-- …` and nested `/* … */`, which PG does nest) are dropped;
- string literals (`'…'` with `''` escape, `E'…'` with `\`, `B'…'`, `X'…'`,
  dollar-quoting `$tag$…$tag$`) → `?`;
- numbers (integer, decimal, exponent, `0x`/`0o`/`0b`, `1_000` digit
  separators) → `?`. A sign is an operator, not part of the literal: `-1` →
  `- ?`, so `a-1` and `a - 1` normalise alike;
- bind parameters `$1, $2, …` → `?`;
- keywords and unquoted identifiers → lower-case (PG folds unquoted identifiers
  to lower anyway); quoted identifiers `"…"` (with `""` escape) are kept
  verbatim, case-significant;
- runs of whitespace collapse to a single separator; a trailing `;` is dropped;
- list collapsing: `( ? , ? , … )` → `( ? )` (covers `IN (1,2,3)`), then runs
  of groups `( ? ) , ( ? ) , …` → `( ? )` (covers multi-row `VALUES`).

The canonical text is the tokens joined by single spaces. The **fingerprint** is
XXH3-64 over the token stream (NUL-separated), computed streaming and
independently of the text buffer: if the normalised text overflows
`LK_NORM_TEXT_MAX` (1 KiB) the label is truncated but the hash keeps consuming
tokens to the end, so a truncated label never changes a query's identity.

Deliberate deviations from `pg_stat_statements`, all so that the same logical
query lands in **one** series:

- **`$N` is replaced, not preserved.** pg_stat_statements keeps `$1`; latkit
  folds it to `?`. So `where id = 42` (simple), `where id = $1` (prepared) and
  `where id = ?` (a JDBC-style client) merge into one fingerprint — the desired
  behaviour for a top-K latency view.
- **`null` / `true` / `false` are left as-is**, not turned into `?`. A pure
  lexer cannot tell `is null` (a predicate) from a boolean literal, so it does
  not try.
- **Truncated input merges by prefix.** Input past the capture budget (8 KiB) is
  a truncated prefix; the lexer finishes cleanly and fingerprints the prefix,
  setting the `trunc` flag (counted in `latkit_queries_truncated_total`). Two
  distinct queries sharing a prefix longer than the budget collapse — an
  accepted cost, tunable by raising the capture budget, not by code.

**Security.** Literal masking promised in the README (PLAN.md §7) is a
by-product of normalisation, not a separate pass: every string and numeric
literal becomes `?` before it can reach a label, so the stored `query` label
never carries user data. Raw SQL never enters the registry at all — the full
text is available only to stage-5 OTel spans/exemplars, which read it from the
live `lk_query_obs` during the `on_query` callback (it dangles afterwards).

## Observation profiles (РH10)

One registry, four vocabularies. The cardinality machinery — the top-K
dictionary, the doorkeeper, the `(db,user)` limit, the fold into `other`, the
OTLP iterator — is written once and is protocol-blind; what a profile supplies
is a family-name set, a label-key set and a mask of which families an
observation touches (`src/metrics/registry.c`, `struct reg_profile`). `pg` and
`mysql` use the `query` profile, `http` the `http` one, `s3` the third
(РS7) — which was added by adding a table row, one grid constant and a counter,
and touched no part of the engine at all — and `redis` the fourth (РR11).

The redis row is the one that made the engine grow, and it is worth naming what
by: **an observation that is counted and deliberately not timed.** Until it,
every profile's total counter was reached only through the duration path, so
"how many" and "how long" were the same walk. A `+QUEUED` command and a `BLPOP`
are neither aborted nor canceled — they happened, they have bytes and an outcome
— and their duration is not the server's (РR9/РR10). So the slot-keyed counter
now resolves its dictionary slot before the duration branch, and the duration
histogram skips a series that never recorded one, which no other profile can
produce. Two families are keyed by the protocol alone for the first time as
well (`_redirects_total`, `_pipeline_depth`): what they measure is a fact about
the cluster and about a syscall, not about any one command's series.

Two properties fall out of that and are worth stating, because both are tested:

- **a profile prints nothing until it has seen an observation.** A PostgreSQL-
  only agent's exposition is byte-for-byte what it was before HTTP existed
  (РH15) — no empty `latkit_http_*` blocks appear;
- **the dictionary is shared, the label spaces are not.** An HTTP route, an S3
  operation and a SQL statement compete for the same `K` slots (one knob, one
  memory bound), but a route never lands in a `query` label and each profile's
  `other` counter is its own.

The **dimension** table is shared too, and that is why one knob moves when an S3
port is configured: `max_session_dims` defaults to 32 for a database agent and
to 128 when any watched port speaks `s3` (РS4), because the dimension there is
(bucket × access key) and a deployment has thousands of buckets where a database
has a handful of schemas. An agent watching both gets the larger of the two,
which costs kilobytes.

## Cardinality control: top-K, doorkeeper, `other` (Р23)

Three defences keep the `query × db × user × code` product bounded for
Prometheus:

1. **Top-K query dictionary.** A `fingerprint → {label, series}` map of capacity
   `K` (`--top-queries`, default 500). Eviction is LRU; an evicted slot's
   histograms and counters are **merged into `query="other"`**, so global sums
   stay monotonic and the `other` row never shrinks. A fingerprint that returns
   after eviction starts from zero — an ordinary Prometheus counter reset, which
   `rate()`/`increase()` survive by design.
2. **Doorkeeper against churn.** A flood of one-shot ad-hoc queries (migrations,
   human psql sessions) must not wash out the working top-K. When the dictionary
   is full a brand-new fingerprint goes to `other` and is recorded in a
   direct-mapped candidate cache; it is admitted only on its **second**
   appearance. One hash probe, and it removes the dominant churn pattern.
3. **Secondary-dimension limits.** `(db, user)` pairs are capped at
   `--max-session-dims` (default 32); pairs beyond the limit collapse to
   `db="other", user="other"`. SQLSTATEs in `latkit_query_errors_total` are
   capped at 64 distinct codes, the rest folding into `sqlstate="other"`.

`latkit_queries_other_total` exposes how much traffic is landing in `other` — the
honesty gauge for whether `K` is set high enough — and `latkit_metric_series`
exposes the live series count. The unit test `test_cardinality_ceiling` drives
100k unique fingerprints through a `K=64` registry and asserts the admitted
count stays at `K`, the series count at `K+1` (the `other` row), and that the
summed histogram counts equal the observation count — no observation is ever
lost to eviction, and memory does not grow.

Note that random **literals** are already merged by normalisation, so a
cardinality stress test must vary **identifiers** (table/column names) to
generate genuinely distinct fingerprints.

## Memory ceiling (Р23)

The worst case is explicit: `K` queries × `max_session_dims` pairs × 2 codes ×
(one histogram of ~80 × u64 ≈ 650 B + a ≤ 1 KiB dictionary label). At the
defaults (K=500, dims=32) a fully-populated Cartesian product is on the order of
tens of MiB — but real traffic is sparse across the pairs, not a Cartesian
product, so actual residency is far lower. `latkit_metric_series` and
`process_resident_memory_bytes` let an operator watch the real figure; `K` and
`max_session_dims` bound the ceiling.

## The histogram grid and "un-round" `le` values (Р24)

One internal representation, two exports. The grid is `2^(k/4)` seconds —
schema=2 in Prometheus native-histogram / OTLP exponential-histogram terms,
factor ≈1.189, bucketing error ≤ ±9%. The range 0.1 ms … 60 s is grid indices
`k ∈ [−53, 24)` — 77 buckets, plus an underflow cell, an overflow cell, a
floating-point `sum`, and a `count`; ~80 × u64 ≈ 650 B per series. The bucket
index is computed from the IEEE-754 exponent with bit operations — no `log()` on
the hot path. Non-positive or NaN durations are clamped into underflow (and a
`nonpos` guard counter) rather than corrupting the grid — insurance against a
bad timestamp.

The **classic text-format** export (this stage's dump, and stage 5's `/metrics`)
emits every 4th grid boundary — `le = 2^j` seconds for integer `j`, a factor-2
log scale, ~20 `le` values. These come out as "un-round" decimals:

```
le="0.0001220703125"   (2^-13)   le="0.001953125"   (2^-9)
le="0.0009765625"      (2^-10)   le="1"             (2^0)
…                                le="32"            (2^5)   le="+Inf"
```

They look odd but are exact powers of two, so the classic buckets are a strict
sub-sampling of the native grid — no rebucketing, no second histogram to keep in
sync, and native/exponential export (stage 5) takes the same grid as-is. Grafana
renders them without complaint. If the un-round values are ever unacceptable,
the substitution table lives in one place (`hist.h`).

## Aggregation is in the event thread, lock-free (Р26)

`on_query` runs synchronously from `ring_buffer__poll`, on the single pipeline
thread — normalisation plus increment is microseconds per query, low single
digits of a core at the 50k-qps target. The metrics reader (stage 5's HTTP
handler) lives in the **same** epoll loop, so the registry needs neither locks
nor snapshots: serialisation is just a table walk between ringbuf events. That is
why `lk_metrics_dump` already writes a valid exposition — stage 5 wraps it in
HTTP and recomputes nothing.

**Measured cost (stage 4.5).** A `perf` profile of the agent under select-only
pgbench (`-M simple -S -c 8`, ~87k qps sustained on loopback with **zero** dropped
events — above the 50k-qps target) attributes the on-CPU time roughly as:
`mx_on_query` (the whole aggregator) ≈ 43%, of which `lk_norm_sql` (normalisation
+ XXH3 fingerprint + token output) ≈ 36% and the registry increment
(`lk_reg_observe` + `lk_hist_observe`) ≈ 3%; the remainder is framing /
reassembly. The agent spent ~0.6 of a core (`process_cpu_seconds_total`) at 87k
qps, RSS ~20 MiB. So the O(1) histogram increment is negligible, as designed
(Р24), and **normalisation dominates** the aggregator — precisely the hot path
the stage-8 optimisation targets (a fingerprint cache keyed by the raw-text
pointer/length, Р22/Р26). This is a single-statement microbenchmark that
maximises the fixed per-query normalisation cost; real mixed workloads with
larger statements dilute the share.

## Validation (M2)

The exit criterion (PLAN.md §6) is: pgbench/psql load → correct latency
histograms over normalised queries, plaintext.

- **Replay assertions.** `tests/replay/test_replay.c` drives every stage-3
  fixture through the real aggregator and pins the resulting series: the
  duration histogram `_count`/`_sum`, `rows_total`, `metric_series`,
  `queries_other_total`, and the SQLSTATE counter. The loss fixtures
  (`session_gap`, `synthetic_midsession`, `ssl_tls`) assert **zero** query
  series — the Р19 invariant "no observation survives a gap" is now visible in
  the metrics, not just the parser. The dump is also asserted byte-for-byte
  deterministic across two calls (stable line order, no address/iteration-order
  leakage).
- **Same query, three protocols.** `select 1` sent as a simple query, under
  `-M extended`, and under `-M prepared` (`$1`) all normalise to `select ?` and
  land in one row — checked by the `simple_query`, `extended` and `prepared`
  fixtures sharing the `query="select ?"` label.
- **Live pgbench.** On the test stand (`pgbench -c 8 -T 60`, simple / extended /
  prepared, capturing on the container IP — not localhost, or docker-proxy
  splices past the hooks), the dump shows exactly the handful of normalised
  pgbench statements, the histogram `count` tracks transactions × statements,
  and p50/p95 read off the buckets track pgbench's own latency report. This is a
  sanity check, not the formal `pg_stat_statements` cross-check (stage 8).
