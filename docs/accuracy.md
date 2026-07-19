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
