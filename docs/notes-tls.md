# TLS capture notes (stage 6)

How latkit observes **TLS-encrypted** PostgreSQL and MySQL/MariaDB sessions. At
the socket level the bytes are ciphertext — useless to the parser — so the
plaintext is read one layer up, at the `libssl` API boundary, via uprobes. The
design decisions are Р35–Р41 in [STAGE6.md](../STAGE6.md) plus РМ10 in
[MYSQL.md](../MYSQL.md) (этап М5); this note is the operator- and reader-facing
summary of the mechanism and its limits. The prose below narrates the postgres
process-per-connection model; §4a is the delta for the thread-per-connection
MySQL/MariaDB servers.

The guiding constraint: a TLS session must yield the **same** query
observations, metrics and spans as its plaintext twin, with **no change** to
`src/proto/`, `src/norm/`, `src/metrics/` or `src/export/`. Everything below is
confined to the BPF program (`src/bpf/latkit.bpf.c`), the uprobe attach manager
(`src/agent/tls_attach.c`) and the routing in `events.c` / `conn_table.c` /
`pipeline.c`.

## 1. Where the plaintext is read (Р35)

PostgreSQL's TLS backend calls into OpenSSL with application data that is (or is
about to be) plaintext. latkit attaches an **entry** uprobe and a **return**
uretprobe to each transfer function:

| Function | Plaintext valid at | Length known at | Direction |
|---|---|---|---|
| `SSL_write(ssl, buf, num)` | entry (app hands plaintext down) | return (`ret` = bytes written) | `SEND` — backend→client |
| `SSL_read(ssl, buf, num)` | **return** (OpenSSL fills `buf`) | return (`ret` = bytes read) | `RECV` — client→backend |
| `SSL_write_ex` / `SSL_read_ex` | as above | return `*written` when `ret == 1` | as above |

- The entry probe saves `{ssl, buf, written_ptr}` in a per-thread map
  (`active_ssl_wr` / `active_ssl_rd`, keyed by `pid_tgid`). A postgres backend
  is a single-threaded process-per-connection, and `SSL_read`/`SSL_write` never
  nest, so `pid_tgid` is a correct entry→return key.
- The return probe copies `min(ret, budget)` bytes with a direct
  `bpf_probe_read_user` (the SSL buffer is one contiguous user pointer — no
  `iov_iter` walk, so chunking is simpler than the socket path) into an
  `LK_EV_DATA` event with the new `LK_F_DECRYPTED` flag. `total_len = ret` stays
  honest; the `--capture-limit` budget only trims `cap_len`, and `LK_F_TRUNC` is
  set when `cap_len < total_len` — so the reassembler still knows the exact size
  of every hole.
- `ret <= 0` (`WANT_READ`/`WANT_WRITE`, error, EOF) emits **nothing**: there is
  no plaintext to copy, and a half-finished non-blocking read must not derail
  the stream.

**Direction.** On the DB host, inside the backend, `SSL_read` = data arriving
from the client = **frontend** messages (`Q`, `P`, `B`, …) → `LK_DIR_RECV`;
`SSL_write` = the reply = **backend** messages (`Z`, `C`, `D`, …) →
`LK_DIR_SEND`. This is exactly the socket path's convention (`tcp_recvmsg` =
recv = frontend), so the stage-3 parser cannot tell the two channels apart.

A comm filter inside the uprobe (default: the DB-server set, §4a) drops traps
from unrelated processes that happen to map the same `libssl` — see §4.

## 2. Bridging `SSL*` to a connection (Р36, Р37)

The decrypted event must land in the **same** `conn_table` entry the socket path
opened on `CONN_OPEN` — that entry holds the tuple (→ address labels) and has
already seen `SSLRequest`/`'S'`. So each decrypted event must carry the socket
**cookie** as its `conn_id`. But a uprobe sees `SSL*` and userspace registers,
not a `struct sock`. Two independent bridges fill a map `ssl_to_conn`
(`SSL*` → `{cookie, tuple}`), read in the uretprobe:

1. **Primary — `SSL_set_fd` walk.** The backend calls
   `SSL_set_fd(port->ssl, port->sock)` in `be_tls_open_server`, before the
   handshake and any data. The uprobe has `fd` and `current`, and does a
   CO-RE walk `task->files->fdt->fd[fd]->private_data` → `struct socket` → `sk`
   → `bpf_get_socket_cookie(sk)`, capturing the tuple from `sk` at the same
   time. This resolves the cookie **deterministically and early**, so the first
   `SSL_read` already has its link. Each dereference is guarded by
   `bpf_core_field_exists`; a miss falls silently through to the fallback.
   `SSL_set_rfd`/`SSL_set_wfd` are attached too.
2. **Fallback — nested-syscall correlation.** Between a `SSL_read`/`SSL_write`
   entry and its return, the same thread synchronously calls
   `tcp_recvmsg`/`tcp_sendmsg` on the real socket (postgres backends use
   blocking sockets / synchronous I/O). The entry probe sets
   `active_ssl[pid_tgid] = ssl`; our existing `tcp_*` fentry, seeing an active
   `SSL*`, writes `ssl_to_conn[ssl] = {cookie, tuple}` from `sk`. This needs no
   OpenSSL struct knowledge — it works for BoringSSL and for `SSL_set_bio`
   setups too. Its one gap (a read served from OpenSSL's internal buffer with no
   fresh `tcp_recvmsg`) does not matter: the link is **persistent** in
   `ssl_to_conn`, so a single correlating call ever is enough, and the primary
   bridge already covers the first read.

If the uretprobe finds `ssl_to_conn[ssl]` still empty, the event is **dropped**
and counted (`LK_ST_TLS_CORR_MISS` → `latkit_tls_correlation_misses_total`):
plaintext without an address is useless, and it is more honest to lose it and
count it than to emit an unattributed observation. On a clean psql/pgbench
session the miss count is **zero** (verified by `tests/e2e/verify-tls.sh`).

`ssl_to_conn` and `active_ssl` are `LRU_HASH` maps with a ceiling, so a missed
`SSL_free` leaks at most until eviction; the primary cleanup is a `SSL_free`
uprobe that removes the entry.

**Assumption (documented).** The fallback relies on postgres backends doing
synchronous, blocking socket I/O — true for the standard build. The primary
bridge does **not** depend on it. A build that violates the assumption still
works through `SSL_set_fd`.

### Startup re-frames inside TLS (Р36)

The real `StartupMessage` (with `user`/`database`) travels **inside** TLS: the
plaintext socket path only ever saw `SSLRequest → 'S'`, then ciphertext. So when
a connection flips to `LK_CONN_TLS`, the framer for both directions is **reset
to the fresh startup state** (`lk_conn_tls_reset_framing`), so the first
decrypted `SSL_read` is parsed as a `StartupMessage` exactly like a brand-new
plaintext connection. This is the only state edit — `reassembly.c` itself is
untouched. Without it the `db`/`user` labels would be unavailable on TLS
sessions (they had no plaintext source before stage 6).

## 3. Merging the two channels (Р38)

A TLS connection has two physical event sources under one cookie: ciphertext
(socket, `tcp_*`) and plaintext (uprobe). The rules:

- **Only decrypted is data.** Raw socket events (no `LK_F_DECRYPTED`) on a
  `LK_CONN_TLS` connection are dropped **before** the seq detector, in
  `pipeline.c`, and counted as `latkit_tls_socket_events_dropped_total`. The
  uprobe channel is the sole data source once the connection is TLS.
- **Separate seq spaces.** The kernel bumps `hdr.seq` per submitted event in the
  `conns` map. If ciphertext and plaintext shared that counter and userspace
  threw the ciphertext half away, the seq detector would see phantom holes. So
  decrypted events are numbered from an independent per-conn counter (`tls_seq`,
  keyed by cookie); userspace runs the decrypted stream's hole detector against
  its own `tls_last_seq` space and ignores the raw seq for that connection. A
  ciphertext gap (irrelevant) never dirties the plaintext, and vice versa.
- **Ordering.** The ringbuf order is global and `'S'` happens-before any
  decrypted byte (the handshake precedes application data), so there is no race
  at the flip. A decrypted event arriving on a still-plaintext connection would
  mean the assumption broke — it is logged (`decrypted_early`) and framed
  best-effort.

## 4. Autodetect and lifecycle (Р39)

`tls_attach.c` owns all the process/path handling, outside the BPF logic:

- **Scan.** For each `/proc/<pid>` whose `comm` matches the scan set (default
  `{postgres, mysqld, mariadbd}` — РМ10; `--tls-comm` narrows it to one name),
  parse `/proc/<pid>/maps` for `…/libssl.so[.N]` lines; deduplicate by
  device+inode (many backends → one `libssl`). This is the **process** comm
  (the top-level `/proc/<pid>` entries), distinct from the per-thread comm the
  BPF filter matches — see §4a.
- **Containers.** The path in `maps` is in the target's mount namespace; latkit
  opens it as `/proc/<pid>/root/<path>` so libbpf's uprobe attach can resolve
  the symbol offset from that ELF on the host.
- **Attach.** One uprobe+uretprobe per function per **unique** libssl path, with
  `pid = -1` (all processes mapping that file, including future forked
  backends), gated by the in-program comm filter. Symbols:
  `SSL_read`, `SSL_write`, `SSL_read_ex`, `SSL_write_ex`, `SSL_set_fd`,
  `SSL_set_rfd`, `SSL_set_wfd`, `SSL_free`. Missing symbols (old OpenSSL without
  `_ex`) are skipped without error, which is what `state=partial` reports.
- **Rescan.** A periodic rescan (`--tls auto`, ~30 s) discovers new libssl
  **paths** (a restarted or upgraded cluster, a second install) and attaches
  them; already-bound paths are skipped. Forked backends need no rescan —
  `pid=-1` already covers them.
- **Flags.** `--tls auto|off` (default `off`; `auto` scans and attaches),
  `--libssl PATH` (explicit target, skips the scan — for a container copy or a
  non-standard build), `--tls-comm NAME` (narrow the scan set to one comm).
  Every flag has a `LATKIT_*` env equivalent.
- **Degradation.** Under `--tls auto`, no libssl found is **not** an error: it
  logs and reports `latkit_tls_attached{state="none"}`, and the agent keeps
  working on plaintext. An explicit `--libssl` pointing at a missing file is
  fatal at startup (like a failed port bind).

### Privileges

uprobes need `CAP_BPF` + `CAP_PERFMON` (as fentry does) **plus** read access to
the targets' `/proc/<pid>/maps` and `/proc/<pid>/root`. In a container that
means **`hostPID: true`** and a readable `/proc` (see the deploy notes, stage
7). Without host PID visibility the scan finds no DB server process and TLS
degrades to `state=none`.

## 4a. MySQL/MariaDB delta (РМ10, MYSQL.md этап М5)

The mechanism above transfers to mysqld/mariadbd unchanged — the differences
are in the process model and in naming, not in the probes:

- **Thread-per-connection is already covered.** postgres forks a process per
  connection; mysqld runs one process with a thread per session. Every per-call
  key in the BPF program is per-*thread* (`pid_tgid` for the in-flight
  SSL_read/SSL_write, `{SSL*, tgid}` for the SSL*→cookie bridge), so both
  models key correctly; for a single-process server the `tgid` in the bridge
  key is merely redundant. Neither server nests SSL_read/SSL_write on one
  thread.
- **Process comm ≠ thread comm.** MySQL 8.x names its session OS threads
  `connection` while the process stays `mysqld` (5.7 and MariaDB do not rename
  threads). The /proc **scan** matches the process comm; the kernel comm filter
  matches the **thread** comm (`bpf_get_current_comm`). A single shared name —
  the pre-М5 behaviour of adopting `--tls-comm` as the kernel filter — silently
  dropped *every* socket and uprobe event of an 8.x server (находка М0). Since
  М5 the two diverge: with `--tls` and no explicit `--comm`, the kernel filter
  is the scan set widened by `connection`; an explicit `--comm` still overrides
  the kernel filter exactly.
- **MariaDB bundled TLS is a blind spot.** MariaDB builds linked against
  bundled wolfSSL (the upstream default in some packagings) or GnuTLS map no
  `libssl.so`, so there is nothing to hook: the scan finds the process but no
  target, TLS sessions stay ciphertext and are dropped-and-counted.
  `latkit_tls_attached{state="none"}` (with mariadbd running and `--tls auto`)
  is the diagnostic; the fix is a server build linked against OpenSSL — the
  official MariaDB docker images and most distro packages qualify.
- **e2e.** `tests/e2e/verify-mysql-tls.sh` is the MySQL twin of
  `verify-tls.sh`: mysqld with `require_secure_transport=ON`, a CLI load loop
  on `--ssl-mode=REQUIRED`, latkit with `-p 3306=mysql --tls auto` and **no**
  `--tls-comm` — proving the default scan set and the widened kernel filter on
  a live 8.x server.

## 5. Self-metrics (Р41)

Exposed by both exporters, poured by the `events.c` provider from three sources
— the kernel per-CPU counters, the conn table, and the attach manager:

```
latkit_tls_attached{state}                gauge     state=ok|partial|none (1 on the live one)
latkit_tls_connections                    gauge     TLS connections currently tracked
latkit_tls_connections_total              counter   TLS connections since start
latkit_tls_uprobe_events_total            counter   decrypted events submitted
latkit_tls_decrypted_bytes_total          counter   decrypted plaintext captured (cap_len)
latkit_tls_correlation_misses_total       counter   uretprobe with no known cookie (Р37)
latkit_tls_socket_events_dropped_total    counter   ciphertext socket events dropped (Р38)
```

`uprobe_events` and `decrypted_bytes` carry no `{fn}`/`{dir}` split: the kernel
counts them without that dimension (the same documented deviation as
`latkit_events_total`), so the label the design table sketches would always be a
single value.

## 6. Limits (v1 scope)

latkit v1 covers **dynamically linked OpenSSL** only. Everything else is a
documented gap with **explicit, non-silent behaviour** — a TLS connection is
still detected (the `'S'`/`'G'` reply sets `LK_CONN_TLS`) and its ciphertext is
dropped and counted, so data is never silently corrupted, only absent:

- **GnuTLS / NSS** (non-OpenSSL TLS libraries) — out of scope; no uprobe channel.
- **Statically linked OpenSSL** inside the postgres binary — out of scope
  (detecting the symbol in the binary itself is possible but deferred). Use
  `--libssl` only for a *dynamic* library file.
- **BoringSSL** — the offset-independent nested-syscall bridge (Р37) should
  work, but it is not tested in v1: "may work, not guaranteed."
- **GSSENC** (a `'G'` reply to `GSSENCRequest`, Kerberos encryption via
  libgssapi) — a different API, rare. v1 detects it (the TLS flag is set on `'G'`
  too) and **drops** its data as a known gap; libgssapi uprobes are v1.1.
- **SSLKEYLOGFILE / TLS-record decryption** — not needed and not done: the
  uprobe already hands back decrypted application-layer buffers.

## 7. Security

The agent sees SQL over TLS exactly as it does over plaintext. The same defaults
apply: **literal masking is on by construction** — normalisation turns every
literal into `?` before it can reach a metric label, and raw SQL never enters the
registry. Full SQL is available only to sampled OTel spans, off by default, and
`--otlp-span-masked` substitutes the normalised text where literals must not
leave the host. TLS does not widen this surface; it only means the masking now
also applies to formerly opaque encrypted sessions.

## 8. Testing

- **Unit** (`tests/unit/test_tls_route.c`, no BPF): synthetic events prove
  ciphertext is dropped on a TLS conn, decrypted events reach the framer, the
  startup re-frame parses a `StartupMessage` from the first decrypted event, and
  a decrypted-space hole dirties only the plaintext.
- **Replay** (`tests/replay`, no BPF): `ssl_tls.lkt` yields a full session
  (user/database, a query, latencies) — the same observation as its plaintext
  twin `ssl_plain.lkt`.
- **e2e** (`tests/e2e/verify-tls.sh`, Docker + BPF): postgres `ssl=on`, pgbench
  `sslmode=require`, `latkit --tls auto`. Asserts the same query series as the
  plaintext stand plus `latkit_tls_connections > 0`,
  `latkit_tls_attached{state="ok"} == 1`, uprobe events flowing, and ~zero
  correlation misses.
</content>
</invoke>
