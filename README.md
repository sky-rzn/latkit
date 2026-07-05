# latkit

An eBPF agent (C + libbpf, CO-RE) for PostgreSQL observability: it captures
PostgreSQL wire traffic at the TCP-socket level, and will parse the v3
protocol into per-query latency metrics exported to Prometheus and
OpenTelemetry. No backend of its own — Grafana reads the data from
Prometheus / an OTel-compatible store.

**Status: capture layer done (milestone M1); userspace framing in place.**
The agent attaches to a live kernel, captures both directions of traffic on
configured server ports as a stream of connection-scoped events, accounts for
every lost event, and survives overload without touching the database. On top
of that it now runs the stage-2 userspace pipeline: an epoll event loop, a
connection table, and a streaming framer that reassembles the event stream
into whole PostgreSQL v3 protocol messages (type + length + body), honestly
flagging the stretches made dirty by loss. Message *semantics* (query/response
matching, latency), metrics and exporters are the next stages — see
[PLAN.md](PLAN.md) (Russian) for the roadmap, [STAGE1.md](STAGE1.md) for the
capture-layer design decisions and [STAGE2.md](STAGE2.md) for the framing
model (a per-direction stream of bytes and known-size holes,
[docs/notes-reassembly.md](docs/notes-reassembly.md)).

## How it works

Kernel side (`src/bpf/latkit.bpf.c`):

- `fentry/tcp_sendmsg` + `fentry/fexit tcp_recvmsg` read payload bytes
  straight out of the userspace `iov_iter` (see
  [docs/notes-iov.md](docs/notes-iov.md)) and emit chunked data events into a
  ringbuf;
- `tp_btf/inet_sock_set_state` tracks connection lifecycle: `CONN_OPEN` on
  ESTABLISHED, `CONN_CLOSE` on CLOSE;
- connections are keyed by the socket cookie; only sockets whose **local**
  port is in the filter map are captured (the server side), so loopback
  traffic is seen exactly once and directions are fixed: `RECV` =
  frontend→backend, `SEND` = backend→frontend;
- losses are double-accounted: global per-CPU counters plus a per-connection
  `seq`/`LK_F_GAP` scheme, so userspace can tell exactly which connection
  lost how many events;
- capture is budgeted (`--capture-limit`, per-connection HEADERS mode), but
  `total_len` always reports the real call size — budgets only cut
  `cap_len`, so the future reassembler knows the exact size of every hole.

Userspace (`src/agent/`) loads the skeleton, fills the filter maps and runs an
epoll loop over the ringbuf, a timerfd (10 s stats, 60 s connection sweep) and
a signalfd for clean shutdown. Decoded records feed a connection table (seq-gap
detection, LRU ceiling, idle sweep) and a streaming framer that emits whole
protocol messages. Output is opt-in: `--events` prints one line per raw event,
`--messages` one line per reassembled message (`--hexdump` adds the body
prefix); a stats line goes to stderr every 10 s. `--record` dumps the raw
event stream to a file that replays offline through the same pipeline (used by
the test fixtures — see `tests/replay`).

## Requirements

- **Linux kernel 5.15+** with BTF (`/sys/kernel/btf/vmlinux`). The hard
  floors underneath that claim: BPF ringbuf (5.8), `bpf_get_socket_cookie`
  in tracing programs and BPF atomics (5.12), plus fentry/`tp_btf`
  trampolines. Developed and verified on 6.x; pre-6.x validation is a
  stage-8 task (the CO-RE branches for older `iov_iter` layouts are framed
  but untested).
- clang (BPF target), CMake ≥ 3.16, `bpftool`, `libelf`, `zlib`.
- Root (or `CAP_BPF` + `CAP_PERFMON`) to run.

## Build

```sh
git submodule update --init            # bundled libbpf
cmake -B build
cmake --build build -j"$(nproc)"
ctest --test-dir build                 # unit tests, no root needed
```

Use `-DLATKIT_SYSTEM_LIBBPF=ON` to link against a system libbpf ≥ 1.0
instead of the submodule, and `-DLATKIT_VMLINUX_H=` to build on a host
without BTF.

## Run

```sh
sudo ./build/latkit                    # captures local port 5432
```

| Flag | Default | Meaning |
|---|---|---|
| `-p, --port PORT` | 5432 | local (server) port to capture; repeatable, up to 16 |
| `--ringbuf-bytes N` | 8 MiB | ringbuf size, power of two |
| `--capture-limit N` | 8192 | capture budget in bytes per send/recv call; `total_len` stays honest |
| `--comm NAME` | off | only capture send/recv from processes with this exact comm |
| `--cap-headers` | off | test hook: switch every connection to HEADERS mode (64 B/call) at OPEN |
| `--max-conns N` | 65536 | userspace connection table ceiling; the least recently active entry is evicted past it |
| `--conn-idle-timeout SEC` | 600 | evict connections with no events for this long (leak insurance for lost CLOSEs) |
| `--record FILE` | off | append every raw ringbuf record to FILE for offline replay (LKT1 trace) |
| `--events` | off | print one line per raw ringbuf event (the stage-1 output) |
| `--messages` | off | print one line per reassembled protocol message |
| `-x, --hexdump` | off | dump event payload (`--events`) and the captured message body prefix (`--messages`) |

Dev environment (PostgreSQL 16 in docker + pgbench load):

```sh
docker compose -f deploy/dev/docker-compose.yml up -d
sudo ./build/latkit &
./deploy/dev/bench.sh -c 8 -T 15
```

## Known limitations (v1 scope)

- TLS traffic is opaque at the socket level — the uprobe channel on
  `SSL_read`/`SSL_write` is stage 6.
- Unix-domain sockets are invisible (`tcp_*` is not on that path) — v1.1.
- `splice()`-relayed traffic (e.g. docker-proxy) arrives with kernel-page
  iterators: sends degrade to honest `cap_len=0` events, receives bypass
  `tcp_recvmsg` entirely. Irrelevant for the intended agent-on-the-DB-host
  deployment; details in [docs/notes-iov.md](docs/notes-iov.md).
