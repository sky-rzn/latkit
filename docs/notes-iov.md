# notes-iov: reading socket payload out of `iov_iter` (task 0.3)

Research notes backing the payload-capture code in `src/bpf/latkit.bpf.c`
(stage 0: `iter_first_seg`, `capture_payload`; renamed/generalized in stage
1.4 to `iter_snapshot`, `emit_data_chunks`, `emit_chunk`). These are the
inputs to stage 1 (per-connection capture, larger chunks) and to the stage 8
kernel matrix.

Validated on **6.17.0-35-generic, x86_64** (2026-07-02) against `postgres:16`
in docker, psql over loopback inside the container netns. Both directions read
correctly; the limitations below are known and bounded, not surprises waiting
to happen.

## The two paths

SEND (`fentry/tcp_sendmsg`) and RECV (`fentry`+`fexit/tcp_recvmsg`) both funnel
through `iter_snapshot(msg, &segs)` (stage 0: `iter_first_seg`), which resolves
the userspace `{base, len}` pairs of up to `LK_MAX_SEGS` iterator segments. The
data lives in userspace in both cases, so the copy is always
`bpf_probe_read_user`.

- **SEND** — on entry to `tcp_sendmsg` the data has not been copied into the
  kernel yet; `msg->msg_iter` still points at the caller's buffer, `iov_offset`
  is 0 and `count == size`. Read straight through.
- **RECV** — on entry the destination buffer is empty. By the time `tcp_recvmsg`
  returns, `iov_iter` has been advanced past the copied bytes
  (`iov_iter_advance` during `copy_to_user`), so the base pointers no longer
  point at the start of the data. We therefore snapshot the segment list on
  `fentry` (hash map keyed by `pid_tgid` — the syscall does not switch task
  between entry and exit) and read the first `ret` bytes out of it on `fexit`.
  The map entry is deleted on **every** `fexit`, including the `ret <= 0` path,
  or it leaks (verified empty after a 46k-transaction pgbench run — see below).

## iter_type observed

Enum `iter_type` (from vmlinux BTF): `ITER_UBUF=0, ITER_IOVEC=1, ITER_BVEC=2,
ITER_KVEC=3, ITER_FOLIOQ=4, ITER_XARRAY=5, ITER_DISCARD=6`.

For psql/libpq TCP traffic on 6.17 **every** send and recv used `ITER_UBUF` —
the single-userspace-buffer iterator (kernel ~6.0+). `ITER_IOVEC` was not
exercised by psql at all. The code still handles `ITER_IOVEC` (reads
`__iov[0]`), but that branch is currently unexercised on this kernel. KVEC /
BVEC / FOLIOQ / XARRAY reference kernel-internal memory rather than the
application buffer and are rejected (`iter_first_seg` returns -1 → `cap_len=0`).

## Fields read (all via CO-RE / `BPF_CORE_READ`)

`struct iov_iter` on 6.17:

```
u8      iter_type;
size_t  iov_offset;
union { struct iovec __ubuf_iovec;
        struct { union { const struct iovec *__iov; ... void *ubuf; }; size_t count; }; };
union { unsigned long nr_segs; ... };
```

- `ITER_UBUF`: `base = ubuf + iov_offset`, `len = count` (count is the bytes
  still to transfer from the current position).
- `ITER_IOVEC`: `iov = __iov` (first segment); `base = iov->iov_base +
  iov_offset`, `len = iov->iov_len - iov_offset`.

### Field-rename framework for older kernels (stage 8)

The reads are wired for CO-RE so the object relocates, but the *spellings* below
only exist in newer trees; filling in the old-kernel branches and testing on
5.15 is deferred to stage 8:

- `ubuf` appeared ~6.0. Guarded here with
  `bpf_core_field_exists(msg->msg_iter.ubuf)`; pre-6.0 kernels have no UBUF path
  and everything arrives as `ITER_IOVEC`.
- `__iov` was named `iov` before ~6.4. We reference `__iov` (present in the
  build vmlinux.h). A kernel whose BTF only has `iov` needs the alternate
  spelling — not compiled in today.
- `count` sat directly in `iov_iter` on older kernels rather than inside the
  anonymous struct; the `BPF_CORE_READ(msg, msg_iter.count)` access relocates
  across that move.

## Length clipping and the verifier

`capture_payload` clamps to `POC_CHUNK` (256) with an explicit
`if (cap > POC_CHUNK) cap = POC_CHUNK;` plus a `cap == 0`/`base == 0` guard
before `bpf_probe_read_user(ev->payload, cap, base)`. The verifier accepted this
directly on 6.17 — no masking trick needed, no complaints about the variable
size against the 256-byte `payload[]` in the ringbuf record. All three programs
(`lk_tcp_sendmsg`, `lk_tcp_recvmsg_entry`, `lk_tcp_recvmsg_exit`) load and
verify clean; `dmesg` showed no verifier output during load or under load.

### Stage 1.4: the chunk loop vs the verifier (6.17)

The multi-chunk loop (up to `LK_MAX_CHUNKS` reserve/submit per call, cursor
walking up to `LK_MAX_SEGS` segments) needed three tricks to verify; all are
commented in the code, recorded here with symptoms so they aren't undone:

- **Loop-carried state must round-trip through a map.** With the cursor
  (`si`/`soff`/`pos`/`budget`) on the stack, every branch outcome leaves the
  verifier with different *precise* scalar values, iteration states never
  merge, and verification dies at `-E2BIG` (1M insns processed, the log shows
  narrowing ranges like `off ∈ [517, 5883]` deep in the loop). Reloading the
  cursor from a per-CPU map each iteration turns the values into
  bounds-checked unknowns, states converge and prune. Plain map accesses are
  NOT enough — clang forwards the stored values and elides the loads — hence
  the `ONCE()` volatile wrapper.
- **Segment indexing needs `idx = si & (LK_MAX_SEGS - 1)` plus
  `barrier_var(idx)`.** Without the barrier clang strength-reduces the
  indexing into a walking pointer (`p += 4` per iteration) whose accumulated
  var_off the verifier can't tie back to the `si < LK_MAX_SEGS` loop bound —
  rejected with `invalid access to map value, off=104` (i.e. one element past
  the 104-byte `lk_segs`).
- **The two size classes verify as separate `bpf_ringbuf_reserve` call
  sites.** `emit_chunk` is `__always_inline` and takes the class as a
  parameter; each call site passes a literal (`LK_CHUNK_SMALL`/`LK_CHUNK_FULL`),
  so each inlined copy reserves a constant size, which is what the helper
  demands. The stage-0 tricks (64-bit `cap`, `barrier_var(cap)` before
  `bpf_probe_read_user`) carry over unchanged.

With all three in place the programs verify in well under the insn budget and
`dmesg` stays clean under pgbench load.

## Experiments run

- **Marker query** `select 'latkit_poc_marker', 42`: frontend `Q` query and
  backend `T`/`D`/`C`/`Z` messages all readable in the ASCII column, directions
  correct, `total_len` matching wire sizes.
- **Large response** `select repeat('x',100000)`: server emitted a stream of
  8192-byte `tcp_sendmsg` calls; client `tcp_recvmsg` returned in chunks
  (8192 + 57344 + 32768 + 1759 ≈ 100063 bytes = 100000 payload + framing).
  `total_len` reflects real per-call sizes; `cap_len` clips to 256 as designed
  (`total=8192 captured=256`, `total=440 captured=256`).
- **pgbench** `-c 8 -T 15`: 46049 transactions, 0 failed, ~3073 tps. Agent did
  not crash, no verifier errors in dmesg, and the `recv_state` hash map dumped
  **empty** afterward — no fentry→fexit leak.
- **Clean detach**: on SIGINT the 3 tracing links and 3 programs disappear from
  `bpftool link/prog show`.

### Stage 1.7 (M1) verification, 2026-07-03, 6.17.0-35-generic

Full checklist run against the dev stack (`deploy/dev`), agent at defaults
unless noted; `dmesg` stayed empty across all loads.

- **pgbench v4 + v6** (`-c 8 -T 15` tpcb, `-c 4 -T 10` over `::1`): every
  connection got exactly one OPEN and one CLOSE (18/18 v4 incl. the
  docker-proxy legs, 6/6 v6), tuples correct for both families, 0 drops,
  0 seq holes over ~1.3M events.
- **Payload seen exactly once**: a marker query on the server-side
  connection shows one RECV (`Q`) and one SEND (`T/D/C/Z`) — the loopback
  SEND+RECV duplication of stage 0 is gone (local-port predicate, Р7).
- **Synthetic OPEN**: a psql session opened before the agent started got
  `OPEN ... synthetic` (with a real pid, data path) on its first query, in
  both the host and container netns.
- **Overload** (`--ringbuf-bytes 65536`, select-only `-c 20`, ~47k tps):
  877 reserve failures counted in `stats`, 360 seq-gap events flagged
  `LK_F_GAP` and detected by the agent's tracker, per-connection totals in
  CLOSE (`dropped=31` etc.); agent and DB unaffected (0 failed txns).
- **Churn long-run** (`pgbench -c 20 -T 600 -C`, one reconnect per txn):
  144076 OPEN = 144076 CLOSE, 0 drops and 0 holes over 2.74M events; agent
  RSS constant at 19.5 MiB for the whole 11 min; `conns` oscillated 31–42
  during the run and drained to **0** after the clients left, `recv_state`
  stayed empty throughout.
- **Overhead, by eye** (formal budget is stage 8): tpcb `-c 8` ≈ 3200 tps
  with the agent vs ≈ 3440 without on this host; stage 0 measured ≈ 3070
  with the agent on the same benchmark.

## Known limitations (carried forward, not deferred discoveries)

- **Multi-segment iterators**: *resolved in stage 1.4* — `iter_snapshot`
  captures up to `LK_MAX_SEGS` (8) `{base, len}` pairs and the chunk loop
  walks them; segments beyond the 8th are not captured (`LK_F_TRUNC`).
  Chunks are sliced at segment boundaries, so every
  `bpf_probe_read_user` still writes to the start of its own record's
  `payload[]` — the variable-offset destination write that scared the PoC
  never materializes. Verified byte-exact against a 3-segment `writev` and a
  3-buffer `readv` on a captured port.
- **256-byte cap** (`POC_CHUNK`): *resolved in stage 1.4* — two record size
  classes (`LK_CHUNK_SMALL` 256 / `LK_CHUNK_FULL` 4096) picked per chunk
  before reserve, and one send/recv call emits up to `LK_MAX_CHUNKS` (8)
  chunked events with shared `total_len`, increasing `off` and consecutive
  `seq`, up to `--capture-limit` bytes (default 8192). A fragmented iovec
  (many sub-4KiB segments) spends one chunk slot per segment and can exhaust
  the slots before the byte budget; such calls under-capture without
  `LK_F_TRUNC`, which stage 2 still detects from `off`/`cap_len` vs
  `total_len`.
- **splice() traffic is invisible or empty** (observed via docker-proxy,
  which relays with splice): the send side arrives at `tcp_sendmsg` with an
  `ITER_BVEC` iterator (kernel pages, not the application buffer) and
  degrades to honest `cap_len=0` + `LK_F_TRUNC` events; the receive side goes
  through `tcp_splice_read`, never enters `tcp_recvmsg`, and produces no
  events at all. Same class of gap as unix sockets (PLAN.md §5); irrelevant
  for the direct agent-on-PG-host deployment.
- **Old kernels**: UBUF/`__iov`/`iov` rename branches are framed but only the
  6.x spellings are compiled and tested; 5.15 validation is stage 8.
- **Unix sockets invisible**: psql over the local socket (no `-h`) produced zero
  events — `tcp_sendmsg`/`tcp_recvmsg` are not on that path. Confirmed by
  probing with a marker; this is the known PLAN.md §5 gap.
- **Loopback double-count**: for a loopback connection both the sender's
  `tcp_sendmsg` and the receiver's `tcp_recvmsg` fire on the same host, so each
  payload appears twice (one SEND, one RECV, tuple swapped). *Resolved in stage
  1.3*: the capture predicate matches the local port only (STAGE1.md, Р7), so
  only the server-side socket is captured and each payload is seen once, with
  fixed direction semantics (RECV = frontend→backend, SEND = backend→frontend).
