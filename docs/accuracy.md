# Accuracy validation — agent vs PostgreSQL (stage 8.2, Р50)

**Verdict: the acceptance holds.** On a lossless run the agent's `count`
matches the PostgreSQL log **exactly** (34 804 statements, both protocols,
zero ringbuf drops / resyncs), per-SQLSTATE error counts and `rows_total`
match the injected ground truth exactly, and the offset-adjusted p50/p95
agree **to the last digit of the bucket arithmetic** (≤ 0.01% where ≥ 5%
was allowed) for queries ≥ 1 ms. The measured systematic offset — the
agent's network-to-network span minus PostgreSQL's own statement duration —
is **+6…+10 µs (simple protocol) / +13…+25 µs (extended)** per query on
loopback, growing to +30…+70 µs on multi-ms statements; the agent is never
below the log, exactly as the measurement model predicts.

Everything below is produced by `tests/bench/accuracy/run.sh`; rerun it to
reproduce one-to-one (verdicts are asserted, the script exits non-zero on
any regression).

## Method

Three views of one controlled workload:

1. **the agent** — `--dump-metrics` exposition written at exit;
2. **csvlog** with `log_min_duration_statement=0` — a `duration:` line per
   completed statement (the honest raw percentiles come from here), an
   `ERROR` line per failed one;
3. **`pg_stat_statements`** — `calls`/`mean_exec_time` as a sanity bound
   only. Its `queryid` never enters the join: pgss normalises on the parse
   tree, the agent on a lexer, and the differences would read as false
   mismatches.

**The join** (`tests/bench/accuracy/logjoin.c`): every statement text from
the csvlog runs through the **same `lk_norm_sql` the agent links** — same
fingerprint, same canonical text, same label clipping — so a log line lands
on exactly the agent series that counted it. Unix-socket sessions
(`[local]`, the stand's control plane) are excluded: they never cross the
capture point, keeping both views of the workload identical. Both
directions are asserted: no log-only and no agent-only series.

**Workload** (exact counts via `pgbench -t`, never `-T`): select-only
`-c 8 -t 2500`, tpcb-like `-c 4 -t 500`, `pg_sleep` 2 ms ×300 and
50 ms ×200 (deliberately one fingerprint — a bimodal distribution that
straddles export buckets), a 100-row `generate_series` ×200 (known
`rows_total`), a ~25 ms 1M-row aggregate ×100, plus injected errors via
psql: `SELECT 1/0` ×200 (SQLSTATE 22012) and a unique violation ×200
(23505), in autocommit so no aborted-transaction statements blur the error
accounting.

**Validity**: a run counts only if the dump shows zero
`latkit_ringbuf_dropped_total` and zero `latkit_resync_total` — `count
matches exactly` is meaningless under loss (Р49/Р50).

### Separating discretisation from measurement

The agent's percentiles come out of the Р24 histogram, so they carry the
grid's error on top of any measurement offset. To keep the two apart,
logjoin computes every log-side percentile three ways — raw from the
samples, through the fine Р24 grid (factor 2^(1/4), error ≤ ~9%), and
through the classic export boundaries (factor 2 — what `--dump-metrics`
exposes) — and computes the agent percentile from those same classic
boundaries with the same estimator. A measured p95 of the sleep tail:

| view | p50 | p95 |
|---|---|---|
| csvlog raw | 2.123 ms | 50.380 ms |
| csvlog through the Р24 grid | 2.263 ms | 51.511 ms |
| csvlog through the export boundaries | 3.581 ms | 58.594 ms |
| **agent** (export boundaries) | **3.581 ms** | **58.594 ms** |

Identically discretised values agree to the digit: the whole distance from
"raw" is the price of the factor-2 export grid, none of it is the capture.
(Dashboards using the OTLP exponential-histogram export sit on the fine
grid, i.e. the ≤ 9% row.)

One trap: identical discretisation does **not** cancel when the offset
moves samples across a bucket boundary — interpolation amplifies a
5%-of-value offset into a double-digit percentile delta while the
distributions agree perfectly (observed on sub-ms tpcb rows: raw delta
+66% at p95 over a 20 µs offset). The percentile **gate** is therefore
offset-adjusted: log samples shifted by the measured per-query mean offset,
then discretised — testing shape agreement under `agent = log + const`,
which is the measurement model itself. The unadjusted delta stays in the
report as the "what a dashboard would show" number.

## Results

Campaign of 2026-07-12, commit `56d3d89`+8.2, kernel 7.0, postgres:16,
loopback (container IP), `fsync=off`. Both protocol runs **PASS** every
assertion: exact counts (22 000 / 2 000×5 / 500 / 200 / 100 per fp), rows
(20 000 and 100 vs ground truth), errors (200+200 by SQLSTATE, both
sides), zero drops/resyncs.

### The measured offset (agent − csvlog, mean per query)

| query (canonical) | mean, log | simple | extended |
|---|---|---|---|
| tpcb `BEGIN` / `END` | 4–15 µs | +6.2…+6.8 µs | +12.6…+13.2 µs |
| select-only point SELECT | ~45 µs | **+9.1 µs** | +24.6 µs |
| tpcb UPDATEs / INSERT | 25–70 µs | +7.9…+9.6 µs | +18.7…+19.5 µs |
| `pg_sleep` (2/50 ms) | 21.35 ms | +30.1 µs | +50.3 µs |
| 1M-row aggregate | ~25 ms | +32.0 µs | +69.6 µs |
| **weighted, all 34 804 samples** | | **+9.0 µs** | **+22.5 µs** |

Reading it back through the measurement model (README "What the numbers
mean"):

- **the agent is never below the log** — its span additionally contains
  the server-side kernel socket path, protocol handling outside the
  executor timer, and the result write-out;
- **sub-ms queries**: the offset (+6…+10 µs simple) is 15–25% of a 40 µs
  statement. That is a *characteristic*, not an error — at these
  durations the two tools measure genuinely different spans. It is also
  why the p50/p95 gate applies at ≥ 1 ms: below the first export boundary
  (122 µs) an exposition percentile is pure first-bucket interpolation.
- **extended protocol runs carry a bigger constant**: PostgreSQL logs
  parse/bind/execute as three phases and logjoin compares against their
  *sum*, while the agent times first-frontend-message → ReadyForQuery —
  the inter-message gaps land in the agent's span only. Same caveat
  applies to reading agent numbers next to PG's log for extended-protocol
  clients in production.

### p50/p95 gate (queries ≥ 1 ms, ≥ 50 samples)

| query | protocol | Δp50 adj | Δp95 adj | gate |
|---|---|---|---|---|
| `select pg_sleep ( ? )` (bimodal 2/50 ms) | simple | +0.00% | +0.00% | ≤ 5% ✓ |
| `select sum ( abalance ) …` | simple | +0.00% | +0.00% | ≤ 5% ✓ |
| both | extended | +0.00% | +0.00% | ≤ 5% ✓ |

### pg_stat_statements sanity

`calls` matches exactly (22 000 on the top query). The means line up as the
three nested spans they are — executor only ⊂ whole statement ⊂
network-to-network:

| query | pgss `mean_exec_time` | csvlog mean | agent mean |
|---|---|---|---|
| point SELECT (simple) | 0.013 ms | 0.042 ms | 0.051 ms |
| `pg_sleep` | 21.298 ms | 21.355 ms | 21.385 ms |

## Normaliser notes surfaced by the join

- `pg_sleep(0.002)` and `pg_sleep(0.05)` share one fingerprint — literals
  collapse; by design, and handy here (a controlled bimodal series).
- Simple-protocol tpcb splits each ±delta statement into **two**
  fingerprints: `abalance + 3455` lexes to `+ ?` but `abalance + -3455`
  to `+ - ?` (the lexer sees an operator where pgss's parse tree sees one
  negative constant). Counts still reconcile exactly per fp; a documented
  lexer-vs-parse-tree difference, not a capture error. Extended protocol
  binds parameters, so the split does not occur there.

## Reproduction

```sh
cmake -B build-rel -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-rel --target latkit -j
tests/bench/accuracy/run.sh            # ~2 min; exits non-zero on failure
```

Knobs: `PROTOCOLS="simple extended"`, `TXNS`, `ERR_N`, `TOL` (percent),
`MIN_MS`, … — see the script header. Artifacts per run: `report.txt`
(asserted verdicts), `<proto>/join.tsv` (the full per-query table incl.
raw/fine/grid percentile ladders), `<proto>/pgss.txt`, the agent dump and
the csvlog.

---

# Accuracy validation — agent vs MySQL (MYSQL.md М7, РМ5)

**Verdict: the acceptance holds.** On a lossless run (zero ringbuf drops, zero
resyncs) the agent's `count` matches `performance_schema`'s per-digest
`COUNT_STAR` **exactly** for every workload family — point SELECT, aggregate,
UPDATE, `BEGIN`/`COMMIT`, `SELECT … FOR UPDATE`, `SELECT SLEEP(…)`, the
known-row SELECT, and the injected missing-table error all reconcile at
±0.0%. The only digests that do not enter the comparison are the mysql CLI's
own per-connection control-plane probes (`SELECT @@version_comment`, session
setup), filtered by shape on both sides — the classic-protocol analogue of
the PG stand's `[local]` exclusion, except MySQL issues them over TCP so they
cross the capture and must be filtered rather than skipped by transport.

Everything below is produced by `tests/bench/accuracy/run-mysql.sh`; the
verdict is asserted and the script exits non-zero on any regression.

The MySQL track validates the same properties on a different ground truth.
MySQL has no per-statement text log with durations that is as convenient as
PostgreSQL's csvlog, so the reference here is
**`performance_schema.events_statements_summary_by_digest`**: per-digest
`COUNT_STAR` and the latency sums/percentiles the server itself measured.
The comparison is produced by `tests/bench/accuracy/run-mysql.sh`.

## Method

Two views of one controlled workload against a fresh `mysql:8.4` (plaintext,
`performance_schema` on, the digest table `TRUNCATE`d at the start of the
measured phase):

1. **the agent** — `--dump-metrics` at exit, the `proto="mysql"` series;
2. **`events_statements_summary_by_digest`** — `DIGEST_TEXT`, `COUNT_STAR`,
   `SUM_TIMER_WAIT`, the latency percentiles.

**The join** maps each server digest onto the agent series that counted the
same statements. The two normalisers are **not** the same — the server
digests on its own parser, the agent on the РМ9 lexer — so, exactly as
`pg_stat_statements` is kept out of the PG join, the digest text is
re-normalised through the agent's `lk_norm_sql` (MySQL dialect) before the
match. One MySQL-specific step: the digest text backtick-quotes every
identifier (`` `abalance` ``) even though the client's raw statement did not,
so the backticks are stripped before re-normalising, recovering the
bare-identifier form the agent parsed off the wire (values are already `?`
in the digest, so no backtick can hide inside a literal). The handful of
digests that still straddle a lexer-vs-parser boundary are reconciled by
grouping (documented per run in `join.tsv`); control-plane digests the
agent never captured (`SET`, `SHOW`, the seeding CTE) appear one-sided and
are skipped.
Control-plane statements the load harness runs over the local socket never
cross the capture point and are excluded from both views.

**Workload** (exact repetition counts): a point `SELECT … WHERE id = ?`
mix, an aggregate, a DML `UPDATE`, a `BEGIN…COMMIT` transaction, a
`SELECT SLEEP(…)` bimodal tail (2 ms / 50 ms — one digest, straddling
export buckets), a known-row-count `SELECT` over a seeded table, and an
injected `SELECT … FROM <missing>` (errno 1146 / SQLSTATE 42S02) plus a
duplicate-key `INSERT` (1062 / 23000).

**Validity**: as on PG, a run counts only if the agent dump shows zero
`latkit_ringbuf_dropped_total` and zero `latkit_resync_total` — the count
equality is meaningless under loss (Р49/Р50).

## Systematic differences (documented, not defects)

- **Rows are a lower bound under capture holes (РМ5).** For a `SELECT` the
  agent counts **row packets seen by the framer**; a capture hole over the
  row stream drops the packets it swallowed, so `latkit_query_rows_total`
  is a *lower* bound, never an over-count. On a lossless run (the only kind
  the validity gate admits) it matches the server's `Rows_sent` exactly; the
  bound only bites on a degraded capture, and the metrics that flag one
  (`resync`, `ringbuf_dropped`) are dashboarded. DML rows come from the OK
  packet's `affected_rows` and are exact regardless. This is the MySQL
  analogue of the PG `PortalSuspended` caveat: latency is always honest,
  the row *count* carries a capture-quality asterisk.

- **One done-point, not two.** MySQL has no separate `ReadyForQuery`, so
  `ts_ready == ts_complete`: the agent's span is command-packet →
  terminator (OK/ERR/final EOF), i.e. network-to-network. Against the
  server's own `TIMER_WAIT` (execution inside the server) the agent span is
  strictly wider by the network round trip and the terminator-read latency —
  the same nested-span relationship as PG (server exec ⊂ agent
  network-to-network), never below the server's measurement.

- **Multi-statement and stored-procedure resultsets** fold into one unit
  (`LK_QO_MULTI_STMT`), so a `a; b; c` batch is one agent observation whose
  rows are the sum, while the server records three digests. The join sums
  the member digests before comparing; documented per run.

- **Prepared statements**: the agent keys text off the `stmt_id` cache, so a
  binary `COM_STMT_EXECUTE` carries the prepared text with `?` placeholders
  intact — the same fingerprint the digest table shows, so these reconcile
  directly.

## Reproduction

```sh
cmake -B build-rel -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-rel --target latkit -j
tests/bench/accuracy/run-mysql.sh      # ~2 min; exits non-zero on failure
```

Knobs (env): `SELECT_N`, `SLEEP2_N`, `SLEEP50_N`, `ROWS_N`, `ERR_N`,
`TOL` (percent), `MIN_MS`, … — see the script header. Artifacts per run:
`report.txt` (asserted verdicts), `join.tsv` (per-digest table: server
count/latency vs agent), the digest dump and the agent dump.

---

# Accuracy validation — agent vs nginx (PLAN-HTTP.md М8)

**Verdict: the acceptance holds.** On a lossless run the agent's per-request
duration agrees with nginx's `$request_time` to **0.33 ms at p50 and 0.71 ms
at p90** on the front leg, and with `$upstream_response_time` to 0.13 / 0.90 ms
on the upstream leg — 0.21 % / 1.3 % relative on the requests slow enough for a
relative number to mean anything (≥ 50 ms). Response-body bytes match
**exactly** on every Content-Length response; the two families where they do
not are both definitional and both listed below. **100 %** of the joinable
requests were observed — the only log lines without a match are nginx's own
readiness probes, which carry no request id and ran before the agent
attached.

Unlike the database stands, this comparison is **per request, not per
statement family**: every request carries its own `X-Request-Id`, the agent
reports it (`lkt_queries --proto http`, `reqid=`), nginx logs it, and the join
is on that id. An aggregate comparison of two percentile curves can hide a
systematic per-request error as long as it cancels out; this one cannot.

Everything below is produced by `tests/bench/accuracy/run-http.sh`; the gates
are asserted and the script exits non-zero on any regression.

## Method

Two views of one controlled workload against nginx 1.27 (`sendfile on`) in
front of a Go `net/http` backend:

1. **the agent** — `--record` over both legs (`-p 8080=http -p 8081=http`),
   replayed offline through the real handler (`lkt_queries --proto http`), so
   the artefact that produced the numbers is kept and re-runnable;
2. **nginx's access log** — `$request_time`, `$upstream_response_time`,
   `$body_bytes_sent`, `$status`, keyed by `$http_x_request_id`.

**The two legs are different questions.** The front leg (client → nginx) is
what `$request_time` measures; the upstream leg (nginx → application) is what
`$upstream_response_time` measures. The bench's nginx config sets
`Host: upstream-app` on the upstream side so the agent's own `host` label tells
them apart — the same request id appears on both, and merging them would
compare a proxy's inbound latency with its outbound one.

**What is compared per request:** `request_time` against the agent's
`upload + duration` (РH5 splits the interval that nginx reports as one number),
`upstream_response_time` against the upstream leg's, and `body_bytes_sent`
against the agent's `out`.

**Workload:** N passes of {`/hello`, `/json/{id}`, a chunked response, a 50 ms
route, a 404, a 500, a 1 MB static file through `sendfile`, a trickled upload,
a single-call upload} — chosen to hit the shapes РH4 and РH5 are about rather
than to produce a uniform flood.

**Validity:** as on PG and MySQL, a run counts only if the agent dump shows
zero `latkit_ringbuf_dropped_total` and zero `latkit_resync_total`.

## Systematic differences (documented, not defects)

- **The agent measures at the socket, nginx inside itself.** The residual
  sub-millisecond gap above is that difference and nothing else: the agent's
  interval starts at the first captured byte of the request and ends at the
  last byte written to the socket, while `$request_time` starts when nginx has
  read the first bytes into a worker. The agent's interval is the wider one,
  which is the point of a network-to-network measurement — it contains the
  time the server does not see.

- **Chunked responses: decoded bytes vs wire bytes.** The agent counts
  **decoded** body bytes, so a chunked body and a Content-Length body of the
  same content report the same number (РH4); nginx counts what it wrote to the
  socket, chunk framing included. The gap *is* the framing — 11 B at p50,
  16 B at p90 on the bench's four-chunk response — and the joiner checks that
  the agent is lower by a plausible overhead rather than requiring equality.

- **A body that bypassed the socket is a declared lower bound.** A response
  flagged `LK_QO_BODY_UNSEEN` (РH4: promised by Content-Length, not seen on the
  socket — an old-kernel `sendfile`, or a transfer the capture lost the tail
  of) reports fewer bytes than nginx sent. The assertion that means something
  is that it is **never above** the truth, and that is what the bench gates; on
  the reference run 4 of 270 requests were in this state, all of them the 1 MB
  static file, short by ≤ 30 KB.

- **A request body whose last call is cut by the capture budget loses its
  upload interval.** An under-captured call's uncaptured tail is a hole of
  known size, but it is detected lazily — when the *next* call on that
  direction starts (Р9). For a request body that is the last thing the client
  writes, that next call comes after the server has already answered, so the
  body never reaches its Content-Length, the framer never publishes its end,
  and the observation carries no `ts_req_done`: its `duration` then holds the
  client's upload time and `bytes_in` is short by up to one budget. With the
  default per-port budget of 2048 B (РH14) this is every upload whose final
  write is larger than that. Consequences and the workaround:
  - `latkit_http_request_upload_seconds` skips such units — the family is not
    wrong, it is empty for them;
  - `latkit_http_request_duration_seconds` includes the client's transfer, so
    a slow uploader looks like a slow server;
  - raising the port's budget (`--port 8080=http:32768`) restores the split for
    bodies whose calls fit under it — measured: with 32 KB writes and a 32 KB
    budget the same upload reports `upload=1.0 s, duration=176 µs`, against
    `upload=0, duration=1.0 s` at the default.

  The bench reports the count of affected requests on every run (`# NOTE:`),
  and the e2e stand drives both shapes deliberately.

- **A large response can be over-counted, and then mis-framed, when the
  server's socket fills.** This one is not an HTTP property but a capture-layer
  one, surfaced by HTTP because HTTP is the first protocol here to write
  megabytes into one connection: SEND is hooked on `fentry`, so a
  `tcp_sendmsg` the kernel refuses outright (`-EAGAIN`, full send buffer,
  non-blocking socket) is counted at its *requested* length, and the
  application then re-sends the same bytes in another call. `bytes_out` is
  high by that call, the arithmetic body skip finishes early, and the leftover
  body bytes are rejected as a start line — one `parse_errors` and a resync,
  loudly rather than silently. Measured on the demo stand (8 MB responses,
  load generator and agent on one host): 11 in 15 548 observations, ~0.07 %,
  all on the big-file routes. The accuracy bench does not reproduce it (1 MB
  responses, one request at a time), which is itself informative about when it
  happens. Full signature and the fix it would take:
  [notes-iov.md](notes-iov.md) "Known limitations".

## Reproduction

```sh
cmake -B build-rel -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-rel --target latkit -j
tests/bench/accuracy/run-http.sh       # ~2 min; exits non-zero on failure
```

Knobs (env): `PASSES`, `TOL_MS`, `MIN_SAMPLES`, `AGENT_BIN`, `OUT` — see the
script header. Artifacts per run: `report.txt` (the gates and the verdict),
`join.tsv` (one row per request: both views side by side, plus the observation
flags that explain a difference), `queries.txt` (the replayed observations),
`run.lkt` (the recording itself — every number above is reproducible from it
without the stand) and the agent's exit dump.

---

# Accuracy validation — agent vs MinIO (PLAN-MINIO.md МS4)

**Verdict: the acceptance holds.** On a lossless run the agent's per-request
duration agrees with MinIO's own `callStats.duration` to **0.17 ms at p50 and
0.29 ms at p90**, and the split of РH5 reassembles into MinIO's single
`timeToFirstByte` to **0.19 / 0.30 ms**. Response-body bytes match **exactly**
on every request that was not a declared lower bound (855/855), every status
matches, **100 %** of the 880 requests MinIO traced were observed, and — the
assertion no other stand here can make — **100 % of the operations agree with
the name MinIO itself gives them**.

That last one is why an S3 accuracy bench is worth more than an HTTP one. The
reference is not a log line about latency: it is the server naming the request.
`op` is the label the whole S3 profile is keyed by (РS2), and this is the one
place it can be checked against the authority on what an S3 operation is,
rather than against our own table.

Everything below is produced by `tests/bench/accuracy/run-s3.sh`; the gates are
asserted and the script exits non-zero on any regression.

## Method

Two views of one controlled workload against `minio/minio:latest` on a compose
bridge:

1. **the agent** — `--record` on `-p 9403=s3`, replayed offline through the
   real handler (`lkt_queries --proto s3`), so the artefact that produced the
   numbers is kept and re-runnable;
2. **MinIO** — `mc admin trace -v --json --call s3`, one object per S3 request
   carrying `callStats.duration`, `.timeToFirstByte`, `.rx`, `.tx`, the status
   and the `api` name, joined on the `X-Amz-Request-Id` the server answered
   with. МS1 reads that header off the response head for exactly this purpose.

**What is compared per request** (`tests/bench/accuracy/s3_join.py`):

| MinIO | agent | gate |
|---|---|---|
| `callStats.duration` | `upload + dur` | p90 gap ≤ 5 ms |
| `callStats.timeToFirstByte` | `upload + ttfb` | p90 gap ≤ 5 ms |
| `callStats.tx` | `out` | exact |
| `statusCode` | `status` | exact |
| `api` (`s3.GetObject`) | `route` | ≥ 99 % agree |

**Why `upload` is added back on the left-hand rows.** MinIO measures both of its
numbers from one origin — the moment the request arrived — so its
`timeToFirstByte` includes the time it spent reading the request body. РH5
splits that interval deliberately (`upload` is the client's, `dur`/`ttfb` are
the server's) because on an object store a slow uploader and a slow server are
different incidents. Adding `upload` back is therefore not a fudge to make two
numbers agree: it is the statement that **the split is exact**, and it is
checked as such. A bench that compared `ttfb` against `timeToFirstByte`
directly would be asserting that MinIO makes the same distinction, which it
does not.

**Workload:** N passes of {`PutObject` small, `PutObject` 1 MiB (both
`aws-chunked`, since `mc` is minio-go), `GetObject` of each, `HeadObject`, a V2
listing, a 404 `NoSuchKey`, a 404 `NoSuchBucket`, a batched delete} plus one
multipart upload — the shapes РS5 and РS6 are about, not a uniform flood. On
the reference run that is 880 requests across nine operations.

**Validity:** as on the three stands before it, a run counts only if the agent
dump shows zero `latkit_ringbuf_dropped_total` and zero `latkit_resync_total`.

**A second, aggregate opinion:** MinIO's own Prometheus endpoint. Printed, not
gated — the two count over slightly different windows, since the agent attaches
after the server starts — but a factor-of-two difference there would mean
something is counted twice or not at all. Measured: `minio_s3_requests_total`
882 against `latkit_s3_requests_total` 880, a ratio of 0.998, the two missing
requests being the ones the server answered before the probes were attached.

## Systematic differences (documented, not defects)

- **`callStats.rx` is not the request's wire bytes and is not compared.** MinIO
  charges a fixed ~93-byte estimate for the head and counts the `aws-chunked`
  stream as it decodes it, so its `rx` is neither our `bytes_in` (the wire) nor
  our `obj_bytes` (the object). The РS6 claim is checked where it can be
  checked — in the e2e stand's exposition, where the object bytes are compared
  against the wire counter over the same requests, and come out 0.16 % lower,
  which is the signed-chunk framing to within a rounding of the notes'
  measurement.

- **The last write of a large response is missing from `bytes_out`, by exactly
  one call's uncaptured tail.** This is the Р9 lazy-hole rule that §HTTP
  documents for *request* bodies, arriving on the response side because an
  object store is the first thing here that writes megabytes back: MinIO sends
  a 1 MiB object in 128 KiB `write(2)` calls, each captured at the port's
  2048-byte budget (РH14) with the remaining 129024 bytes reported as a hole —
  but a hole is only detected when the *next* call on that direction starts, and
  the body's last call has no next call. So the unit is closed by the following
  request head with `LK_QO_BODY_UNSEEN` and `out = 919552` of 1048576, short by
  exactly 129024 = 131072 − 2048.

  Measured: 25 of 880 requests, all of them the 1 MiB `GetObject`, every one
  short by exactly that amount. The observation **declares** itself a lower
  bound, and what the bench gates is that it is never *above* the truth. The
  shortfall is bounded by one call: `max(0, write size − capture budget)`,
  independent of the object's size. Raising the port's budget shrinks it
  (`--port 9000=s3:32768` → 98304); closing it properly would mean crediting a
  Content-Length body's outstanding tail when the unit is retired, which is a
  change to the HTTP framer's hole accounting and belongs to that track, not to
  this milestone.

  Operationally: `latkit_s3_bytes_total{direction="out"}` under-reports
  large-object reads by ~12 % at the default budget, `latkit_s3_object_size_bytes`
  is unaffected on uploads (it reads a header, not the body) and equally short
  on downloads, and the timings — which is what the profile is for — are
  unaffected entirely.

- **MinIO's name for an operation is not always the S3 API's name.** The server
  calls the handler `s3.GetBucketObjectLockConfig` where the API calls the
  request `GetObjectLockConfiguration`, and `s3.DeleteMultipleObjects` where the
  API says `DeleteObjects`. The classifier produces the **API's** names — those
  are what an operator reads in AWS documentation and writes in an IAM policy —
  so the join carries a small alias table (`MINIO_API_ALIASES` in
  `s3_join.py`). A pair that is neither equal nor aliased is printed as a
  disagreement, which is the "the S3 API grew and the table did not" signal of
  risk 5 arriving from the server rather than from a rising `op="other"` share.
  On the reference run: none.

- **`sendfile` does not arise.** МS0 recon item 3 measured zero
  `sendfile`/`splice`/`copy_file_range` in MinIO under load — object bodies go
  out through ordinary `write(2)` — so the РH4 degradation that makes nginx byte
  accounting a lower bound has no MinIO equivalent. What is left is the
  budget-tail above, which is a different mechanism with a different (and
  bounded) size.

## Reproduction

```sh
cmake -B build-rel -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-rel --target latkit -j
tests/bench/accuracy/run-s3.sh        # ~2 min; exits non-zero on failure
```

Knobs (env): `PASSES`, `TOL_MS`, `MIN_SAMPLES`, `PORT`, `AGENT_BIN`, `OUT` —
see the script header. Artifacts per run: `report.txt` (the gates and the
verdict), `join.tsv` (one row per request, both views side by side plus the
observation flags that explain a difference), `trace.json` (MinIO's own view),
`queries.txt` (the replayed observations), `run.lkt` (the recording — every
number above is reproducible from it without the stand), `minio.prom` and the
agent's exit dump.

The trace is read for five fields and nothing else: `-v` mode includes response
**bodies**, and an S3 error body carries the object key (РS5), which has no
business in a bench artefact.
