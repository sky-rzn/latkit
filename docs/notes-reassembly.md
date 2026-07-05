# notes-reassembly: the stream-with-holes model and timestamp precision

Design notes backing the stage-2 streaming framer (`src/agent/reassembly.c`,
connection table `conn_table.c`, chunk layer in `lk_reasm_data`). Full rationale
is in [STAGE2.md](../STAGE2.md) (Russian, decisions Р9–Р13); this is the
English summary of the two ideas most likely to surprise a reader of the code
or the metrics: how the reassembler avoids buffering the stream, and why
message timestamps are only as precise as syscall boundaries.

## A direction is a stream of two primitives (Р9)

The reassembler does **not** keep a per-direction byte buffer and does not
"glue fragments" in the classic TCP-reassembly sense. Each direction of a
connection is a stream built from exactly two primitives, which the stage-1
events produce deterministically:

- `bytes(p, n)` — captured payload: `payload[0..cap_len)` of a chunk;
- `hole(n)` — a gap of **known size**: the uncaptured tail of a send/recv call
  (`total_len − Σ cap_len`) and any missing `off` interval between chunks of
  one call.

This works only because of the stage-1 invariant that `total_len` is always
honest — capture budgets (`--capture-limit`, HEADERS mode, the chunk-slot
bound) cut `cap_len`, never `total_len`. So the size of every truncation hole
is exact arithmetic, and the per-direction stream is self-describing: ordering
within a direction is guaranteed (the socket lock serialises
`tcp_sendmsg`/`tcp_recvmsg`, chunks of one call submit in order, the ringbuf
preserves submission order). The only thing that ever needs buffering is an
**unfinished message**, and only its header (≤ 5 bytes normal, ≤ 8 startup)
plus a body prefix up to `LK_MSG_BODY_MAX` (16 KiB); the body tail beyond the
prefix is skipped by `len` (state `SKIP`). Steady-state memory per direction is
therefore ~0 — a partial message lives only from one chunk to the next.

Holes come in two kinds, and they matter differently to framing:

1. **Known holes** (budget truncation): the stream position stays exact. If a
   message header was captured, a body of any size is skipped arithmetically by
   `len` — truncation does **not** desynchronise framing. A hole that lands on
   a header is the exception: the position of the next message inside the hole
   is unknowable, so the direction goes dirty.
2. **Unknown holes** (lost ringbuf events): a gap in the per-connection `seq`.
   How many stream bytes vanished is unknowable in principle (a whole call may
   be gone), so the direction goes dirty and must resynchronise. A `seq` gap is
   per-connection, so it conservatively dirties **both** directions.

Recovery from a dirty direction is anchor-based (Р10): the backend scans for
the `ReadyForQuery` byte pattern `'Z' 00 00 00 05 [I|T|E]` and resumes at the
next byte; the frontend re-enters at a send/recv call boundary whose first byte
is a plausible message type. The scan runs **only** while dirty, so a matching
byte pattern inside a clean message body costs nothing. The first message after
recovery carries `LK_MSG_AFTER_RESYNC` so the consumer knows prior context is
lost. Synthetic connections (the agent attached mid-session) start dirty and
join through the exact same mechanism.

## Timestamp precision = syscall boundaries (Р13)

A reassembled message is stamped with `ts_ns` of the event (chunk) that carried
the **first byte of its header**. The clock is `bpf_ktime_get_ns`
(CLOCK_MONOTONIC); wall-clock conversion happens later, at export.

The consequence to be honest about: several protocol messages emitted by one
`send`/`recv` call share a single timestamp — the call's. The backend
frequently packs `RowDescription` + `DataRow`… + `CommandComplete` +
`ReadyForQuery` into one write, and all of them get that write's `ts_ns`. So
**latency resolution is bounded by syscall granularity, not per-message.** This
is not a bug to fix later; it is a structural property of measuring at the
socket layer. It is sufficient for the PLAN.md latency model, which measures
from the `recv` call carrying a query (`Q`) to the `send` call carrying its
`ReadyForQuery` (`Z`) — both are call-level events, so call-level timestamps
lose nothing for that model. Sub-call attribution would require a different
vantage point (e.g. userspace probes) and is out of scope.

## Replaying the model offline

Because the framer is a pure function of the event stream, the whole pipeline
(decode → connection table → framer) runs identically over live ringbuf
records and over a recorded trace. `--record FILE` dumps the raw records (the
`LKT1` format in `src/agent/record.h`); the replay harness in `tests/replay`
feeds a trace back through the same `lk_pipeline` the agent uses, which is how
the committed `tests/fixtures/*.lkt` are both produced and checked in CI
without BPF or privileges.
