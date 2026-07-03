# notes-iov: reading socket payload out of `iov_iter` (task 0.3)

Research notes backing the payload-capture code in `src/bpf/latkit.bpf.c`
(`iter_first_seg`, `capture_payload`). These are the inputs to stage 1
(per-connection capture, larger chunks) and to the stage 8 kernel matrix.

Validated on **6.17.0-35-generic, x86_64** (2026-07-02) against `postgres:16`
in docker, psql over loopback inside the container netns. Both directions read
correctly; the limitations below are known and bounded, not surprises waiting
to happen.

## The two paths

SEND (`fentry/tcp_sendmsg`) and RECV (`fentry`+`fexit/tcp_recvmsg`) both funnel
through `iter_first_seg(msg, &base, &len)`, which resolves the userspace base
pointer and remaining length of the **first** iterator segment. The data lives
in userspace in both cases, so the copy is always `bpf_probe_read_user`.

- **SEND** — on entry to `tcp_sendmsg` the data has not been copied into the
  kernel yet; `msg->msg_iter` still points at the caller's buffer, `iov_offset`
  is 0 and `count == size`. Read straight through.
- **RECV** — on entry the destination buffer is empty. By the time `tcp_recvmsg`
  returns, `iov_iter` has been advanced past the copied bytes
  (`iov_iter_advance` during `copy_to_user`), so the base pointer is no longer
  at the start of the data. We therefore stash the base pointer on `fentry`
  (hash map keyed by `pid_tgid` — the syscall does not switch task between entry
  and exit) and read `min(ret, POC_CHUNK)` bytes from it on `fexit`. The map
  entry is deleted on **every** `fexit`, including the `ret <= 0` path, or it
  leaks (verified empty after a 46k-transaction pgbench run — see below).

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

## Known limitations (carried forward, not deferred discoveries)

- **Multi-segment iterators**: only the first segment is captured, for both
  directions. psql/libpq is single-segment `ITER_UBUF`, so this was never hit,
  but a multi-`iovec` send or a recv scattered across segments would capture
  only its first segment. Stage 1 TODO: iterate/concatenate up to N segments
  (the verifier cost of a variable-offset destination write is why it is not
  done in the PoC).
- **256-byte cap** (`POC_CHUNK`): payloads are truncated to 256 bytes;
  `total_len` still reports the true size. 4 KiB chunks and length-based slicing
  are stage 1.
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
