# tests/traces/redis — МR0 reference trace corpus (Redis / RESP)

Raw `--record` (LKT1) traces of real Redis sessions, captured with the stock
agent **before any Redis code exists** — the capture layer is
protocol-independent (`--port 6399`, whatever framer the default happens to be
runs and finds nothing), so `--record` writes the raw ringbuf records and
nothing interprets them. This corpus is the raw material for the МR1/МR2 unit
tests and the МR8 replay fixtures, the seed corpus for the fuzzer, and the
ground truth [notes-redisproto](../../../docs/notes-redisproto.md) was
cross-checked against (PLAN-REDIS.md, этап МR0).

Each trace is one scenario: `CONN_OPEN` + data events (both directions, capture
budget 8192 bytes per syscall unless the name or the table says otherwise) +
`CONN_CLOSE`. Little-endian, x86-64, kernel 7.0.0-27-generic, Redis 7.4.10
(`redis:7.4`) and Valkey 8.1.9 (`valkey/valkey:8`).

## Layout

```
redis/    single node, plaintext, :6399   — the protocol matrix (clients/raw.py)
libs/     the same node                   — five client libraries, redis-cli, memtier
valkey/   Valkey 8, :6398                 — the fork, on the same scenarios
cluster/  three nodes, :6390–6392         — MOVED, ASK, CROSSSLOT, and the bus
server/   :6399 and :6396                 — replication, MONITOR, io-threads 4
```

93 traces, 9.5 MB, 24 409 records.

Ports: PLAN-REDIS.md writes `--port 6379=redis` and 6379 is what a Redis
deployment uses; the corpus was recorded on 639x only because the recording host
already had a Redis on 6379/6380. A port is the capture filter, not part of what
a trace means.

The matrix node runs with `--enable-debug-command yes` (so `DEBUG PROTOCOL` can
produce every RESP3 type on demand and `DEBUG SLEEP` can occupy the event loop
on purpose) and with a unix socket, so the blind zone of §1 can be demonstrated
rather than asserted. Neither setting changes the wire format of anything else.

## Scenarios

### `redis/` — the protocol matrix

Driven by `clients/raw.py`, which sends bytes rather than using a client
library: a library will not send an inline command, a torn bulk, a pipeline of
exactly three, or a `HELLO 4`.

| Trace | What it exercises |
|---|---|
| `basic` | the twenty commands an application actually runs |
| `types` | every RESP2 reply type, from `DEBUG PROTOCOL` and from real commands |
| `types3` | the seven types RESP3 adds, plus an attribute prefix and a push |
| `bigvalue` | 1 MB through a bulk, both directions — the arithmetic body skip |
| `mget100` | 100 keys in one command, 100 bulks in one reply |
| `pipeline100` | 100 commands in one `write(2)`, twice |
| `pipeline-depths` | batches of 1, 2, 3, 10, 50 — the whole depth histogram |
| `multi` | MULTI/EXEC: commit, DISCARD, EXECABORT, a runtime error inside EXEC, a nested MULTI, an abandoned transaction |
| `watch-abort` | a watched key moves → `EXEC` answers null, and that is not an error |
| `eval-scripts` | EVAL, SCRIPT LOAD, an EVALSHA that hits, one that does not (`NOSCRIPT`), a script's own error |
| `pubsub` | RESP2 subscription: confirmations, messages, `PING` → `*2 ["pong",""]`, the "not allowed in this context" error, shard channels, `RESET` |
| `pubsub3` | RESP3: confirmations arrive as pushes, and ordinary commands keep working while subscribed |
| `tracking` | `CLIENT TRACKING ON` → an `invalidate` push nobody asked for |
| `blocking` | BLPOP by timeout and by event, XREAD with and without BLOCK, BLMPOP, WAIT |
| `scan` | a 16-call SCAN loop and an HSCAN |
| `errors` | the error dictionary: WRONGTYPE, NOSCRIPT, NOPROTO, WRONGPASS, EXECABORT, arity, range |
| `acl-errors` | NOPERM by command and by key, NOAUTH, and both `AUTH` forms against `requirepass` |
| `auth-forms` | `AUTH user pass`, `HELLO 3 AUTH … SETNAME`, `-WRONGPASS` leaving the user alone, `RESET` |
| `select-db` | SELECT 3/15/16/`abc`, SWAPDB, RESET, MOVE, COPY … DB |
| `inline-cmds` | inline PING/ECHO/quoted SET, empty lines, a bare LF, inline and RESP in one write |
| `containers` | 34 container-command calls (`CONFIG\|GET`, `CLIENT\|INFO`, `XINFO\|STREAM`, …), an unknown subcommand, a bare container |
| `nested` | aggregates inside aggregates: XRANGE, XINFO STREAM FULL, GEOPOS, COMMAND INFO |
| `torn-bulk` | a client that promises 1 MB, sends 100 bytes and hangs up; and the same on a reply |

`torn-bulk`'s **first** connection turns out to record something else, and МR1
found it by framing it: the scenario declares `$8` for the seven-byte key
`lk:torn`, so the server reads the CRLF as payload, answers `-ERR Protocol
error: expected '$', got '1'` and closes before the torn bulk is ever reached.
That makes it a length-mismatch trace rather than a truncation one — a useful
case either way (the framer's `BULK_EOL` note fires at the same byte the server
complains about), and the second connection does record the intended shape. Left
as recorded: a trace is what the wire did, and re-recording it would lose the
agreement between our verdict and the server's.
| `slow-client` | one byte per syscall, for a whole command |
| `garbage` | eleven ways to not speak RESP, and what the server does about each |
| `monitor` | MONITOR + traffic from another connection (with Redis redacting `AUTH` itself) |
| `replica` | the replication handshake by hand: `\n` keepalives, `+FULLRESYNC`, `$EOF:` and the RDB |
| `head-of-line` | `DEBUG SLEEP 0.2` on one connection, four `GET`s on four others |
| `hello-probe` | HELLO with no argument, 3, 2, 4 (`NOPROTO`) and `abc` |
| `keepalive1000` | 2000 round trips on one socket (`--capture-limit 512`) |
| `keys-1m` | `DEBUG POPULATE 1000000` + `KEYS *`: one command, a **16.9 MB reply in 212 writes**, 207 of them truncated by the 512-byte budget |
| `basic-cap512`, `bigvalue-cap512`, `pipeline100-cap512` | the ordinary shapes at the budget РR13 proposes |
| `midstream` | the client starts **before** the agent: its `SELECT 7` and `AUTH` are never seen (РR5, `db="?"`) |

### `libs/` — what a client library puts on the wire

Defaults everywhere: the question is what a library does when nobody configures
it. Scenario sources are `clients/{py,go,node,java,php}/`.

| Trace | Client |
|---|---|
| `py-basic`, `py-pipeline`, `py-multi`, `py-err`, `py-resp3`, `py-pool`, `py-pubsub`, `py-block`, `py-auth` | redis-py 5.2.1 (RESP2 by default) |
| `go-basic`, `go-pipeline`, `go-multi`, `go-err`, `go-pool`, `go-pubsub`, `go-block`, `go-resp2` | go-redis v9.7 (**RESP3 by default**, lower-case command names) |
| `node-basic`, `node-pipeline`, `node-multi`, `node-err`, `node-resp3` | node-redis 4.7 (RESP2 by default) |
| `java-basic`, `java-pipeline`, `java-multi`, `java-block`, `java-err`, `java-resp2` | Lettuce 6.5 (**RESP3 by default**) |
| `php-basic`, `php-pipeline`, `php-multi` | phpredis 6.x (RESP2, and no `HELLO` at all) |
| `cli-resp2`, `cli-resp3`, `cli-inline` | `redis-cli`, and a bare `nc` speaking inline commands |
| `memtier-nopipe`, `memtier-pipe100` | memtier 2000 requests × 2 connections, at `--capture-limit 256` |

### `valkey/` — the fork

The same `raw.py` scenarios (`basic`, `types`, `types3`, `multi`, `errors`,
`auth-forms`, `select-db`, `containers`, `pubsub`, `blocking`, `inline-cmds`)
plus `cli`, against Valkey 8.1.9. They exist to be diffed against `redis/`: the
claim "the forks are the same protocol" is only worth something if somebody
checked.

### `cluster/` — three nodes

| Trace | What it exercises |
|---|---|
| `moved` | `-MOVED` on a key that lives elsewhere, `-CROSSSLOT` on a multi-key command, `CLUSTER SHARDS` |
| `ask` | a slot in flight: `-ASK` from the owner, `-MOVED` from the target, `ASKING` + the command, and `-MOVED` again for the next one |
| `bus` | three seconds of port 16390 — binary gossip, so that the README can point at what is *not* RESP |
| `cli-c` | `redis-cli -c` following a redirect |

### `server/` — traffic the server makes

| Trace | What it exercises |
|---|---|
| `replication` | a replica restarting: `REPLCONF`, `PSYNC`, the RDB transfer, then the write-propagation stream |
| `monitor` | the MONITOR feed under load |
| `io-basic`, `io-pipeline100`, `io-bigvalue` | the same shapes against a server with `--io-threads 4 --io-threads-do-reads yes` |
| `io-memtier` | twenty connections against it, which is what it takes to make Redis actually engage its io threads |

## Recording and validating

```
./record.sh              # brings up the five stands, records everything
./record.sh redis        # one stand (redis | libs | valkey | cluster | server)
KEEP=1 ./record.sh       # leave the stands running afterwards
```

Requirements: docker, passwordless sudo (BPF), python3, `script(1)` for the
interactive-`redis-cli` recon item; the agent binary from `build-rel` (or
`LATKIT=path`). Images: `redis:7.4`, `valkey/valkey:8`,
`redislabs/memtier_benchmark`, plus the five client images the script builds
from `clients/*/Dockerfile`.

Validate (replays every record through `lk_replay_file` + `lk_ev_decode`, fails
on any malformed record):

```
cmake --build build --target lkt_info
build/tests/replay/lkt_info tests/traces/redis/*/*.lkt
```

Frame them (МR1 acceptance — one line per top-level RESP value, plus a per-file
framer summary; `--hexdump` adds the published body prefix):

```
cmake --build build --target lkt_messages
build/tests/replay/lkt_messages --proto redis tests/traces/redis/redis/basic.lkt
build/tests/replay/lkt_messages --quiet --proto redis tests/traces/redis/*/*.lkt
```

On the clean traces every counter in the summary is zero. The ones that are not
are the ones recorded to be: `garbage` has three corrupt lengths, `replica` and
`server/replication` a `$EOF:` bulk that is not a value (they go
`LK_CONN_IGNORE` in МR2), `keys-1m` and `memtier-pipe100` resync where a capture
hole fell inside an aggregate, and `midstream`, `cluster/bus` and the `libs/`
traces start on a connection nobody saw open.

## The clients

```
clients/resp.py       RESP2/RESP3 encoder, incremental decoder, raw connection
clients/raw.py        the scenarios above, over raw sockets; --list to see them
clients/tap.py        a logging RESP proxy: which protocol a client negotiates,
                      and how many commands it puts in one write
clients/cmdtable.py   the command table straight out of `COMMAND` (РR4)
clients/depth.py      how deep a reply can nest (РR2)
clients/wirestats.py  command and reply sizes (РR13)
clients/commandstats.py  `INFO commandstats` against the wire (§2 of the plan)
clients/{py,go,node,java,php}/  one image per real client library
```

`resp.py`'s decoder returns `(type_byte, value)` rather than a plain Python
object, because the distinctions the wire makes — `+OK` versus `$2\r\nOK`, a
null bulk versus an empty one, a push versus an array — are exactly the ones a
client library throws away and the framer has to keep.

## Reconnaissance (МR0), with the evidence

`./recon.sh` re-runs all six items and leaves the raw output in `.work/recon/`.
The findings below are from the run of 2026-08-16 on kernel 7.0.0-27-generic.

### 1. The unix socket — a real blind zone, and a narrow one where we run

`.work/recon/01-unixsocket.txt`. Three commands sent over `AF_UNIX` while the
agent captured the TCP port produced a **4-byte trace** — the LKT1 file header
and nothing else. The blind zone is exactly as total as the plan says.

How much traffic it swallows depends on whether the server listens on a socket
at all, and the packaged configurations disagree:

| Deployment | `unixsocket` by default |
|---|---|
| official `redis:*` image (and every compose file that uses it) | **no** — the image ships no `redis.conf` at all, only flags |
| Debian 12 / Ubuntu 24.04 `redis-server` package (7.0.15) | **no** — `# unixsocket /run/redis/redis-server.sock` is commented out |
| **Alpine `redis` package (7.2.9)** | **yes** — `unixsocket /run/redis/redis.sock`, `unixsocketperm 770` |
| `bitnami/redis` image | no — commented out in its packaged `redis.conf` |
| bitnami Redis helm chart (2347 lines of `values.yaml`) | no — the chart has no unix-socket setting at all |

**Consequence:** in containers and Kubernetes — where latkit runs — the socket
is off unless somebody turned it on, and a client cannot use what the server
does not offer. On a hand-built Alpine host it is on by default and an
application colocated with Redis may well be using it. That asymmetry is the
README paragraph the plan asks for, and it bounds the blind zone from above
without pretending it is empty.

### 2. `HELLO 3` — two of five clients, so RESP3 is a main path

`.work/recon/02-hello3.txt`, measured through `clients/tap.py`.

| Client | First bytes on a fresh connection | Protocol |
|---|---|---|
| go-redis v9.7 | `hello 3`, `client setinfo LIB-NAME`, `client setinfo LIB-VER` | **RESP3** |
| Lettuce 6.5 | `HELLO 3`, `CLIENT SETINFO` ×2 | **RESP3** |
| redis-py 5.2.1 | `CLIENT SETINFO` ×2 (no HELLO) | RESP2 |
| node-redis 4.7 | `CLIENT SETINFO` ×2 (no HELLO) | RESP2 |
| phpredis 6.x | nothing — straight to the first command | RESP2 |
| `redis-cli` | the command itself; `-3` switches | RESP2 |
| `redis-cli` **interactive** | `COMMAND DOCS` — a 213 KB, 13-deep reply, before the prompt | RESP2 |

**Consequence for risk 5 of the plan:** neither branch is the exotic one. The
RESP3 push path is what a Go or Spring service produces out of the box, and the
RESP2 path is what Python and PHP produce; the tests for the two weigh the same,
and МR2 has no reason to order its work by "which is the main mode".

Two details that fell out and are worth keeping: go-redis sends **lower-case**
command names, and four of the five libraries announce themselves with `CLIENT
SETINFO` — a container command in the first three round trips of every
connection, i.e. `CLIENT|SETINFO` will be one of the busiest identities in any
deployment.

### 3. Pipeline depth — 1 or exactly what was asked for

`.work/recon/03-pipeline.txt`, commands per client `write(2)`.

| Load | Depth histogram |
|---|---|
| any library, ordinary calls | `1` |
| redis-py / node-redis / Lettuce / phpredis pipeline of 100 | `100 ×1` |
| go-redis pipeline of 100 | `18 ×1`, `82 ×1` — its write buffer splits the batch |
| redis-py pool, 4 threads × 50 commands | `1 ×208` |
| go-redis pool, 4 goroutines × 50 commands | `1 ×204`, `2 ×4` |
| memtier `--pipeline 1` | `1 ×15542` |
| memtier `--pipeline 8` | `8 ×10911` (87 288 commands) |
| memtier `--pipeline 100` | `100 ×3606` (360 600 commands in 3 606 writes) |

**Consequence:** `LK_REDIS_MAX_INFLIGHT = 256` covers everything measured with
room to spare, and the `pipeline_depth` grid needs to separate 1 from 2–8 from
the explicit batch sizes — a log-ish grid, not a linear one. go-redis's split
also shows why the queue cannot be a "one batch, one reply set" shortcut: a
batch arrives in as many syscalls as its buffer decides.

### 4. io-threads — the comm filter would drop three quarters of the traffic

`.work/recon/04-iothreads.txt`. A server started with `--io-threads 4
--io-threads-do-reads yes` has these threads:

```
  redis-server   io_thd_1   io_thd_2   io_thd_3   bio_close_file  bio_aof
  bio_lazy_free  jemalloc_bg_thd ×2
```

Underscores, not the `io-thd-*` the plan guessed. And the io threads are only
*engaged* when there are more clients than `io-threads × 2`: at 4 connections
all the I/O stayed on `redis-server`, at 100 connections it spread out. Same
load (memtier, 4 threads × 25 connections × 1000 requests), three filters:

| Agent flags | Records captured |
|---|---|
| `--port 6396` | 200 200 |
| `--port 6396 --comm redis-server` | 56 375 (**28 %**) |
| `--port 6396 --comm io_thd_1` | 49 307 (25 %) |

**Consequence for РR12 and the МR7 gate:** both directions appear under every
thread name, so reads and writes of one connection genuinely change hands, and
a comm filter naming only `redis-server` loses 72 % of the traffic. The thread
filter must accept `redis-server`, `valkey-server` **and** `io_thd_*`. The
`{ssl, tgid}` bridge is keyed on the process rather than the thread, so it is
unaffected — but that is now a claim the МR7 stand has to confirm with TLS on,
not an inference from thread names.

### 5. libssl — dynamically linked everywhere, including Alpine

`.work/recon/05-libssl.txt`. The plan expected the Alpine image to be the
exception. It is not:

| Image / package | `libssl` | TLS compiled in |
|---|---|---|
| `redis:7.4` (Debian) | `libssl.so.3`, `libcrypto.so.3` | yes |
| `redis:7.4-alpine`, `redis:6.2-alpine` | `libssl.so.3` (musl) | yes |
| `valkey/valkey:8` | `libssl.so.3` | yes |
| `bitnami/redis:latest` (8.10.0) | `libssl.so.3` | yes |
| Debian 12 / Ubuntu 24.04 packages | `libssl.so.3` | yes |

**Consequence:** the existing libssl uprobe channel (РH13.1) applies to Redis
without a line of new BPF, the Go channel is not needed at all, and the МR7
gate ("if the recon shows static builds, shrink the milestone") is open rather
than triggered.

### 6. The wire, measured — sizes, depth, and what `commandstats` cannot see

`.work/recon/06-wire.txt`.

**Sizes** (`clients/wirestats.py`, over a load shaped like an application):

```
  command bytes: min 14   median 36   max 65 574
  reply bytes:   min  3   median 23   max 65 546
  under a 512-byte budget: 31/32 commands fit whole, 28/32 replies do
```

which is the argument for РR13: a Redis exchange is tiny except when it carries
a value, and the value is never read.

**Depth** (`clients/depth.py`) contradicts the plan's assumption that replies
never nest deeper than 4:

```
  13  COMMAND DOCS      (213 589 B — the first command an interactive redis-cli sends)
   9  COMMAND, COMMAND INFO
   8  XINFO STREAM … FULL
   7  COMMAND INFO GET
   4  XRANGE, XPENDING, SLOWLOG GET, FUNCTION STATS
```

and a Lua script can return an arbitrarily nested table. **`LK_REDIS_MAX_DEPTH`
must be 32, not 8, and an overflow has to degrade rather than declare
corruption** — otherwise a human opening `redis-cli` looks like a corrupt
stream.

**The command table** (`clients/cmdtable.py --stats`), which is what РR4's
closed set actually contains:

```
  Redis 7.4.10:  250 commands, 15 containers, 129 subcommands -> 379 identities
                 12 blocking, 104 writing
  Valkey 8.1.9:  242 commands, 16 containers, 137 subcommands -> 379 identities
                 (241 command names in common; Redis has the HEXPIRE family,
                  Valkey has COMMANDLOG, and each is `other` on the other)
```

**`INFO commandstats` against the wire** (`clients/commandstats.py`), which is
§2 of the plan reduced to two numbers. 2000 `GET`s on an idle server:

```
  wire:    20.68 us/call       server: usec_per_call=0.22
```

and 50 `GET`s while one `DEBUG SLEEP 0.2` occupies the event loop on another
connection:

```
  wire:  4038.69 us/call       server: usec_per_call=0.30
```

The server is not wrong — the `GET` really did execute in under a microsecond.
It is simply not the number anybody is paged about, and no configuration of
`commandstats`, `SLOWLOG` (which never fires here: execution time was
microseconds) or `LATENCY HISTORY` will produce it.

## What МR2 found in the corpus

**39 of the 93 traces carry a replication link they were not recorded for.** The
recording host had a replica attached to the matrix node, so most sessions were
captured beside a second connection on which the master propagates its writes:
RESP arrays *from the server*, answering nothing, with a `REPLCONF ACK <offset>`
back from the replica every second or so. `libs/java-pipeline.lkt` is the
clearest — a hundred propagated `SET java:p:N` on one connection while Lettuce
pipelines its hundred commands on another.

Left as recorded, and useful exactly as it is: the link was established long
before the agent attached, so its `PSYNC` is not on the tape and it is the real
shape of the problem РR14 has to solve mid-stream. It is what made МR2 widen the
rule from `REPLCONF listening-port` to any `REPLCONF` — only a replica sends the
command, and without the broader rule those hundred propagated writes read as a
hundred unanswerable replies. Every affected trace now reports `repl=1` and no
orphans.

The one place this shows up as arithmetic: `lkt_messages` counts the frontend
values of *every* connection, while `lkt_queries` produces no observation for an
ignored one, so on those traces the two differ by the number of `REPLCONF ACK`s.

## What is deliberately not here

- **Unix-socket traffic** — it cannot be captured at all (item 1); the empty
  capture lives in `.work/recon/`, not in the corpus, because a 4-byte file is
  evidence and not a trace.
- **TLS traces** — the libssl channel already exists and belongs to МR7; item 5
  is what says it will work.
- **A million-operation benchmark** — one second of memtier at full rate is
  56 MB of trace even at a 256-byte budget. The corpus keeps the *shape*
  (2000 requests) and leaves the volume to the perf bench of МR8.
