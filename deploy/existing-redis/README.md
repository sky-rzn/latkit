# latkit with an existing Redis

Monitoring-only stack — **latkit + Prometheus + Grafana**, pointed at a Redis
(or Valkey, KeyDB, Dragonfly, Sentinel — anything speaking RESP over TCP) you
already run on the host. Unlike [`../demo-redis`](../demo-redis) it brings **no**
server and **no** load generator: the agent captures the real traffic. Grafana
and Prometheus reuse the postgres demo's provisioning and the bundled dashboards
from [`../../dashboards`](../../dashboards) — open **latkit — Redis**.

Nothing is asked of the server: no password, no `CONFIG SET`, no lowered
`slowlog-log-slower-than`, no `latency-monitor-threshold`, no exporter beside
it, no restart.

## Read this first: the unix socket

**Capture is on `tcp_sendmsg` / `tcp_recvmsg`. A client connected over a unix
socket is invisible — completely, not partially.** Redis is the one server in
this repository where that is a live question rather than a footnote, because
an application and its cache are often on the same host. Check what your server
offers:

```sh
redis-cli config get unixsocket        # empty => TCP only, you are fine
```

and, if it is not empty, what your clients actually use:

```sh
ss -x -p | grep -i redis               # unix-socket connections, with the peer
ss -tnp  | grep -i ':6379'             # TCP connections
```

What the packaged configurations do, measured:

| Deployment | `unixsocket` by default |
|---|---|
| official `redis:*` image, and every compose file that uses it | **no** — the image ships no `redis.conf`, only flags |
| Debian 12 / Ubuntu 24.04 `redis-server` package | **no** — the line is commented out |
| **Alpine `redis` package** | **yes** — `/run/redis/redis.sock` |
| `bitnami/redis` image, bitnami Helm chart | no |

So in containers and Kubernetes — where this agent usually runs — the socket is
off unless somebody turned it on, and a client cannot use what the server does
not offer. On a hand-built Alpine host it is on by default. If that is your
deployment, this agent is not the tool for it: point the application at TCP
(`127.0.0.1:6379` still goes through `tcp_*`) or accept the gap.

## Requirements

- Linux kernel **≥ 5.15 with BTF** (`/sys/kernel/btf/vmlinux`). The agent checks
  at startup and says exactly what is missing.
- Docker + compose plugin.
- The traffic must be **RESP2 or RESP3 over TCP** — that is every client library
  in ordinary use, including the two that negotiate RESP3 by default (go-redis,
  Lettuce).

## Run

```sh
cd deploy/existing-redis
GF_ADMIN_PASSWORD='choose-one' docker compose up --build -d
```

Edit `LATKIT_PORT` in `docker-compose.yml` first — the default is `6379=redis`.
First build of the agent image is ~2 min. Grafana and Prometheus bind to
**127.0.0.1 only** — `/metrics` and this Grafana have no auth; reach them over
an SSH tunnel, never publish them:

```sh
ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 your-node
```

Then Grafana at <http://localhost:3000> (`admin` / your `GF_ADMIN_PASSWORD`) →
left nav **Dashboards** (click the word, not the arrow) → folder **latkit** →
**latkit — Redis**.

## Redis already has `INFO commandstats`. Why this?

An honest answer, because `commandstats` is good and it is free:

- **`commandstats` gives you a mean and nothing about the tail.**
  `usec_per_call` is a running average since the last `CONFIG RESETSTAT`; a p99
  cannot be recovered from it, and `LATENCY HISTORY` is a list of events past a
  threshold, not a distribution. latkit gives the histogram;
- **it measures execution inside the server; latkit measures network to
  network** on the server's host. The difference is reading the command off the
  socket, writing the reply, and — the part that matters on a single-threaded
  server — the time this command spent waiting behind somebody else's. One
  `KEYS *` delays everyone, and `commandstats` will still report `GET` as fast.
  Measured against `SLOWLOG` at threshold 0 on 1 621 commands, the gap is 8–14 µs
  per command on an idle server, and `PING` — whose server-side service time is
  *zero* — took 13 µs of it ([docs/accuracy.md](../../docs/accuracy.md) §Redis);
- **per database and per ACL user at once.** `INFO` is global for the instance;
  "which tenant is driving the p99 on database 3" is not a question it can be
  asked;
- **zero touch**: no password, no `CONFIG SET`, no `SLOWLOG` threshold to lower
  on a production server (it is a per-command cost and a ring buffer somebody
  has to read), no exporter to deploy, no restart;
- **the individual slow command as a span**, joined to the rest of your traces;
- **one agent per host** for the databases, the web servers, the object store
  and the cache — one deployment, one nomenclature, one set of dashboards.

What it is *not*: a replacement for `INFO` (memory, evictions, replication lag,
keyspace hits/misses, RDB/AOF state, `INFO commandstats`' exact call counts).
Run both — and if you already run `redis_exporter`, keep it: it answers "how is
the server", latkit answers "what did the clients experience".

## Which port to capture

The filter is on the **local (server) port** — the port Redis accepts client
connections on:

```yaml
LATKIT_PORT: "6379=redis"
```

- **Sentinel** speaks the same protocol on 26379 and needs no extra code:
  `LATKIT_PORT: "6379=redis,26379=redis"`;
- a **`tls-port`** is a second entry (`6379=redis,6380=redis`) plus
  `LATKIT_TLS: auto` — see below;
- **Cluster**: capture the client port on every node, one agent per node. The
  **cluster bus** (client port + 10000) is a binary gossip protocol, not RESP,
  and must not be in `LATKIT_PORT`. `-MOVED` and `-ASK` replies on the client
  port are counted as *redirects* and not as errors, so a resharding cluster
  does not read as an outage;
- **outgoing** connections — your application's calls to somebody else's Redis —
  are **not** captured: the filter is on the local port, and a client socket's
  local port is ephemeral. This is a server-side observer;
- the per-port **capture budget** is 512 bytes per call by default, and
  `6379=redis:4096` raises it. Read "What is not captured" below before deciding
  you do not need it.

## What is not captured — read this before troubleshooting

Each of these is *counted*, so the dashboard tells you which one you are in
rather than leaving you with an empty panel:

| What | Why | What you see |
|---|---|---|
| **Unix-socket clients** | `tcp_*` hooks are not on that path | nothing at all — see the top of this file |
| **The cluster bus** (port + 10000) | binary gossip, not RESP | nothing — it is not in `LATKIT_PORT`, and it must not be |
| **Replication links** (`PSYNC`/`SYNC`/`REPLCONF`) | after the handshake the connection is an RDB stream and a write feed, not a request/response | `latkit_ignored_conns_total{reason="replication"}` |
| **`MONITOR` connections** | the connection turns into a feed of *other* clients' commands; parsing it as replies would corrupt the pairing | `latkit_ignored_conns_total{reason="monitor"}`. Worth an alert of its own: somebody left a debugging tool attached to a single-threaded server |
| **The contents of values** | never parsed, at any setting — only lengths | the size histogram, and nothing else |
| **Module commands** (`JSON.SET`, `FT.SEARCH`, a fork's own admin verbs) | not in the command table | `cmd="other"`, whose share is a freshness signal |
| **A reply that is a long array bigger than the capture budget** | an array announces a count, not a size, so a hole inside it cannot be skipped arithmetically the way a bulk's payload can | the command is not observed at all; its unit lands in `latkit_queries_dropped_total`. Raise the budget (`6379=redis:4096`) if your workload does this — see below |
| **A reply large enough to fill the socket's send buffer** | the SEND hook counts the call at the length it asked for, and the server re-sends the remainder | one `latkit_parse_errors_total` and one resync for that reply ([docs/notes-iov.md](../../docs/notes-iov.md)) |
| **RESP3 client-side caching `invalidate` pushes** | recognised as pushes, never interpreted | `latkit_redis_push_total` |
| **`splice()`-relayed traffic** | e.g. docker-proxy on a published port, for connections originating on the same host | sends degrade to zero-payload events, receives are missed |

### The capture budget, and when to raise it

The default is **512 bytes per call**, and it is chosen for what a command
looks like: a verb and a key. A *bulk* reply of any size is fine at that budget
— a bulk announces its length, and the framer skips the payload arithmetically,
so a 1 MB value costs one 512-byte record and still reports its true size. An
**array** is the exception, and the difference is worth understanding once:

```
6379=redis          SCAN 0 COUNT 100  ->  observed: none of 5,  dropped: 5
6379=redis:4096     SCAN 0 COUNT 100  ->  observed: 6 of 6,     dropped: 1
```

If your application scans keyspaces (`SCAN` with a large `COUNT`, `KEYS`,
`LRANGE 0 -1` over long lists, `HGETALL` over big hashes, `XRANGE` over wide
ranges) and you want those commands on the dashboard, raise the budget for the
port. The cost is bytes per ringbuf record: measured, the default sustains
147 k commands/s with zero drops on an unpipelined load, and a wider budget
lowers that ceiling ([docs/perf.md](../../docs/perf.md) §Redis).

## TLS: `auto`, and nothing else

A `tls-port` Redis is TLS from the client's first byte — there is no in-band
negotiation to watch for, unlike PostgreSQL and MySQL. Every Redis, Valkey and
KeyDB build measured (the Alpine images included) links `libssl` dynamically, so
the existing uprobe channel carries it:

```yaml
LATKIT_PORT: "6379=redis,6380=redis"
LATKIT_TLS: auto
```

- the derived `/proc` scan set for a redis port is
  `{redis-server, valkey-server, keydb-server}` (`latkit --print-config` prints
  it as `tls_scan_comm`), and the kernel-side uprobe gate is that set **plus
  `io_thd_*`** — with `io-threads N` the server makes its `SSL_read`/`SSL_write`
  calls from threads with those names, and a gate without them would drop most
  of the traffic. `--print-config` prints the gate as `tls_gate_comm`;
- **do not narrow it with `LATKIT_COMM`** unless you include the wildcard: an
  operator's `--comm redis-server` was measured seeing 24 % of the commands on a
  100-connection load;
- a connection that was already open when the agent started is adopted on its
  first decrypted byte. Client pools live for days, so on this protocol "the
  agent started after the connection did" is what *every* restart looks like;
- verify:

```sh
docker compose exec prometheus wget -qO- http://latkit:9752/metrics \
  | grep -E '^latkit_tls_(attached|connections|correlation_misses_total)'
# want: tls_attached{state="ok"} 1, connections growing, misses 0
```

> **For a production install, prefer running the agent on the host as a systemd
> unit** ([`../systemd/latkit.service`](../systemd/latkit.service)): `/proc` is
> native and privileges are bounded by `CapabilityBoundingSet`. Set
> `LATKIT_PORT=6379=redis` in `/etc/latkit/latkit.env`.

## Labels: what is bounded, and by what

| Label | Source | Bound |
|---|---|---|
| `cmd` | the first array element, plus the second for the fifteen container commands (`CONFIG\|GET`) | the command table itself, ~250 values; anything else is `cmd="other"` |
| `db` | the `SELECT`ed database, per connection | a number, 0…1024; `?` on a connection joined mid-stream, which is honest rather than a guessed `0` |
| `user` | the ACL user of `AUTH <user> <pass>` / `HELLO … AUTH` | the (db,user) dimension limit, then `user="other"`; `LATKIT_REDIS_USER=off` drops it |
| `error` | the first token of an error reply | the dictionary of known symbols, then `other` |

This is the first protocol in this repository whose cardinality is bounded by a
**table** rather than by a dictionary of observed values: commands are ~250,
databases are 16, ACL users are a handful. Measured over a soak with 32 ACL
users rotating through, the series count plateaued at **59** against a default
ceiling of 2 000 — so `--max-session-dims` and `--top-queries` are knobs you can
leave alone here.

## Privacy

A Redis key is `user:42:session` — an identifier, and often a map of your users.
The rules are structural rather than a promise:

- **no key, value or argument is ever a label**, at any setting. The identity is
  an *index into a table*, not a string from the wire, so there is nothing to
  leak;
- **the password of an `AUTH` is never read**, and never displayed: the
  `--messages --hexdump` view blanks it before printing;
- **the error *symbol* is a label, the sentence after it is not.** `-WRONGTYPE
  Operation against a key holding the wrong kind of value` contributes
  `WRONGTYPE`; a `-MOVED 12539 10.0.0.3:6379` contributes `moved` to a redirect
  counter and no node address anywhere;
- **a span carries no argument either.** `db.query.text` is *built* from the
  identity — `GET ?`, one `?` per argument — rather than copied. On a PostgreSQL
  port a span carries raw SQL; here there is nothing raw to carry.

## Troubleshooting

- **Dashboards empty** → is the traffic on the unix socket? (top of this file).
  Then check `latkit_events_total` — zero means nothing reached the capture at
  all (wrong port, or a `splice()`d hop), non-zero with no commands means the
  port is being read as another protocol (`LATKIT_PORT` without `=redis`).
- **`cmd="other"` climbing** → module commands or a fork's own verbs. Worth an
  issue against [docs/notes-redisproto.md](../../docs/notes-redisproto.md).
- **A command you know your application runs is missing** → its reply is
  probably a long array; see the capture budget above.
- **`latkit_ignored_conns_total{reason="monitor"}` non-zero** → somebody left a
  `MONITOR` attached. That is a performance problem on a single-threaded server
  as well as a blind spot.
- **Latency looks higher than `INFO commandstats`** → it should. That is the
  point; see the section above, and `docs/accuracy.md` §Redis for the size of
  the difference and what it is made of.
