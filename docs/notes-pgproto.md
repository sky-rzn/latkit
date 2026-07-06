# notes-pgproto: the PostgreSQL v3 parser — phases, message table, blind spots

Design notes backing the stage-3 protocol handler (`src/proto/pg/`). Full
rationale is in [STAGE3.md](../STAGE3.md) (Russian, decisions Р15–Р21); this is
the English summary of what the parser turns wire messages into, the state it
keeps per connection, and the cases where it deliberately emits nothing.

The handler sits **above** the framer: the framer ([notes-reassembly](notes-reassembly.md))
turns the event stream into whole messages (`lk_msg`), the handler turns those
into protocol-independent **observations** (`lk_query_obs`) — timings, SQL-text
prefix, row count, SQLSTATE, session labels. Metrics (stage 4) aggregate the
observations; the parser itself keeps no histograms and does no normalisation.

The boundary is two contracts in `src/proto/proto.h`: **down**, the handler is
an `lk_msg_sink` (the framer does not know who listens); **up**, it drives an
`lk_query_sink` (`on_query` / `on_session` / `on_txn`). Everything under
`src/proto/` is pure — no I/O, no libbpf — so unit tests feed synthetic `lk_msg`
and replay tests feed `.lkt` fixtures through the same code the live agent runs.

## The unit of accounting: a query unit and the in-flight ring (Р16)

A **query unit** is one request and its reply. Per connection the parser keeps a
FIFO ring of up to `LK_PG_MAX_INFLIGHT` (64) units: a frontend message opens a
unit, backend replies close units in order, and a batch is emitted together at
its `ReadyForQuery`. The ring exists because the extended protocol pipelines —
libpq and drivers really do put dozens of `Bind`/`Execute` on the wire before
reading a single reply, and the parser must match each reply to the right
request. Simple queries never pipeline (the client blocks on `ReadyForQuery`),
so they are the degenerate one-unit case.

Every observation carries **four** timestamps, all at syscall granularity (the
framer's limit, see notes-reassembly): `ts_start` (first frontend message of the
unit), `ts_first_row` (first `DataRow`), `ts_complete` (the backend message that
closed the unit), `ts_ready` (the following `Z`). The parser does **not** pick a
latency definition — it hands all four up and lets stage 4 decide. This matters
because of pipelining: a whole batch shares one `Z`, so `ts_ready − ts_start`
over-counts for every unit but the last, while `ts_complete − ts_start` is the
honest per-unit span. The `--queries` logger prints the latter; the trade-off is
recorded here so it does not become a surprise when it becomes a metric.

### Phase machine

```
                 StartupMessage            AuthenticationOk (R,0)
   STARTUP  ───────────────────────▶  AUTH  ───────────────────────▶  READY
      │  CancelRequest                                                 │  ▲
      └───────────────────────────────────────────────▶ IGNORE        │  │ Z
                                        CopyBothResponse ▲             │  │
                                                         │             ▼  │
                        CopyInResponse / CopyOutResponse │   COPY_IN / COPY_OUT
                                                         │             │
   READY ────────────────────────────────────────────────────────────┘
      │  ErrorResponse in an extended batch
      └──────────────────────────────▶  SKIP_TO_SYNC  ──── Z ───▶ READY
```

- **STARTUP → AUTH → READY** is the normal handshake. A synthetic or resynced
  connection skips it and starts in **READY-degraded**: startup was never seen,
  so it waits for the first clean `Z` before opening any unit (Р19).
- **COPY_IN / COPY_OUT** (Р20) are entered by `CopyInResponse` / `CopyOutResponse`
  and left by the `Z` after the closing `CommandComplete`.
- **SKIP_TO_SYNC** is extended-protocol error recovery: after an `ErrorResponse`
  the backend ignores everything until `Sync`, so the parser marks the rest of
  the batch `ABORTED` and skips to that batch's `Z`.
- **IGNORE** is terminal for this connection: replication (`CopyBothResponse`)
  and cancellation. No further observations, only counters.

## Message table (type → action)

Direction disambiguates the shared letters (frontend `E` is Execute, backend `E`
is ErrorResponse). "tally only" means the type is counted in `by_type[]` and
otherwise skipped — it carries no latency signal (Р18).

### Frontend (client → server, `RECV`)

| Type | Message | Action |
|---|---|---|
| *(startup)* | StartupMessage | parse `user`/`database`/`application_name` → session; → AUTH |
| *(startup)* | CancelRequest | emit a CANCEL observation, no timings; → IGNORE |
| *(startup)* | SSL/GSSENCRequest | framer owns the one-byte reply; stay in STARTUP |
| `Q` | Query (simple) | open a SIMPLE unit, copy the SQL text |
| `P` | Parse | cache `{name → SQL prefix}` (Р17); opens **no** unit |
| `B` | Bind | open an EXTENDED unit; text from the cache, or `NO_TEXT` |
| `E` | Execute | tally only (start time is already the Bind time) |
| `F` | FunctionCall | open a FUNCTION unit, `NO_TEXT` (body not parsed) |
| `C` | Close | kind `S`: drop a prepared statement from the cache |
| `S` | Sync | batch boundary; the following `Z` does the closing |
| `D` | Describe | tally only |
| `H` | Flush | tally only |
| `d` | CopyData (COPY IN) | add `len` to the unit's byte counter; body ignored |
| `c` / `f` | CopyDone / CopyFail | tally only (the following `C` / `E` closes the unit) |
| `p` | PasswordMessage / SASL | **never read** — the body is the password (Р16) |
| `X` | Terminate | tally only (teardown is the close hook's job) |
| *other* | unknown | `unknown_msgs++`, skipped by `len` |

### Backend (server → client, `SEND`)

| Type | Message | Action |
|---|---|---|
| `R` | Authentication | code 0 (Ok) → READY + `on_session`; other codes: wait |
| `S` | ParameterStatus | take `server_version` into the session; else skip |
| `D` | DataRow | stamp `ts_first_row` on the unit's first row; body ignored |
| `C` | CommandComplete | row count from the tag; `>1` per unit → MULTI_STMT |
| `I` | EmptyQueryResponse | close the unit with `EMPTY` |
| `s` | PortalSuspended | close the unit with `SUSPENDED` (Execute hit a row limit) |
| `E` | ErrorResponse | attach SQLSTATE (`C` field) + `ERROR`; abort an extended batch |
| `V` | FunctionCallResponse | close a FUNCTION unit at the next `Z` |
| `Z` | ReadyForQuery | emit the batch; end degraded/skip/COPY; track the transaction |
| `G` / `H` | CopyIn/OutResponse | the open unit becomes a COPY unit; → COPY_IN/OUT |
| `d` | CopyData (COPY OUT) | add `len` to the unit's byte counter; body ignored |
| `W` | CopyBothResponse | walsender/replication → IGNORE + HEADERS capture (Р20/Р21) |
| `T t n 1 2 3 N A K` | RowDescription, … | tally only |
| *other* | unknown | `unknown_msgs++`, skipped by `len` |

### CommandComplete row counts

Row count = the tag's last space-separated token, but only for a whitelist of
verbs (`SELECT INSERT UPDATE DELETE MERGE FETCH MOVE COPY`) — so `INSERT 0 5` →
5, `SELECT 42` → 42, while `BEGIN` / `SET` / `CREATE TABLE` → 0. An unrecognised
tag is 0 + a counter, never a parse error: the tag table is data, and PostgreSQL
adds tags across versions.

## Untrusted input: "truncated" ≠ "corrupt" (Р18)

Every field read goes through the bounded cursor `pg_wire` (`pg_wire.h`): each
`get_u8` / `get_u32` / `cstring` checks the end pointer, so a read past the
captured body is impossible by construction. Two different outcomes when a read
comes up short:

- the cursor hit the **capture budget** (`LK_MSG_BODY_TRUNC` set) — this is
  truncation, **not** an error: salvage the prefix, flag the text `TEXT_TRUNC`,
  leave missing fields unknown, carry on;
- the cursor hit the end of a **full** body (a field contradicts `len`) — this
  is corruption: `parse_errors++`, drop the current unit, and reset semantics to
  the next `Z`. Framing is **not** touched — the message frames were valid, only
  the content was bad.

An unknown message *type* is likewise not an error (`unknown_msgs++`, skip by
`len`): a future PostgreSQL type must not desynchronise the parser.

The fuzz harness (`tests/fuzz/pg_fuzz.c`, built with `-DLATKIT_FUZZ=ON`) drives
this whole path — `bytes → framer → lk_msg → parser` — from a single
`lk_pg_fuzz_one(data, n)`, run over the fixture corpus under ASAN/UBSAN in CI and
as a libFuzzer target (`-DLATKIT_FUZZER=ON`) for stage 8.

## Losses and honesty (Р19): an observation never spans a gap

On `on_resync`, on the first message flagged `LK_MSG_AFTER_RESYNC`, or on a
`CONN_CLOSE` with a non-empty queue, the whole in-flight ring is **dropped**
(counted in `units_dropped_{resync,close}`) and the connection goes
READY-degraded until the next clean `Z`. A latency that straddles a lost stretch
would be a lie, so the parser refuses to emit it. Session labels survive a resync
(startup cannot be re-read); a synthetic connection has no labels at all.

## Blind spots (known, by design)

- **Query cut off by a disconnect.** A unit still open at `CONN_CLOSE` is dropped,
  never emitted — an aborted-mid-flight request is not an observation. This
  under-counts genuinely slow queries that the client killed; a dedicated
  counter is a stage-4 candidate.
- **`NO_TEXT`.** A `Bind` on a statement name the parser never saw `Parse` for
  (agent started after the `Parse`, cache eviction, synthetic connection) yields
  an honest latency with no text. So does `FunctionCall`. Stage 4 buckets these
  by statement name or `other` rather than dropping them.
- **PortalSuspended re-execution.** An `Execute` with a row limit closes the unit
  `SUSPENDED`; a following `Execute` of the same portal is observed as a *fresh*
  unit (the parser does not track portal→text bindings), which gets `NO_TEXT`
  unless re-`Bind`. A documented simplification, not a bug.
- **Extended `ts_ready` vs `ts_complete`.** See the timing discussion above — a
  pipelined batch shares one `Z`, so the two timings diverge; both are emitted,
  the choice is stage 4's.
- **TLS.** An `SSLRequest` answered `S` makes the connection opaque at the socket
  layer: zero observations, zero sessions. The plaintext source is the stage-6
  `SSL_read`/`SSL_write` uprobe channel.
