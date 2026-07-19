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
| `latkit_txn_duration_seconds` | histogram | `db, user, proto, status` — `status`=`ok\|aborted` (PG: `T→I` vs `E→I` at `ReadyForQuery`; MySQL: the `SERVER_STATUS_IN_TRANS` edge) |

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
| `latkit_ignored_conns_total{reason, proto}` | counter | deliberate blind zones — `reason`=`replication\|compressed` (РМ7/РМ8), per `proto` |
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
