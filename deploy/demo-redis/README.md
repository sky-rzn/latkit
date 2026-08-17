# latkit Redis demo stack

The cache twin of [`../demo`](../demo) (PostgreSQL), [`../demo-mysql`](../demo-mysql),
[`../demo-http`](../demo-http) and [`../demo-minio`](../demo-minio): Redis, a
load generator that exercises every command family the dashboard has a row for,
the agent, Prometheus and Grafana with the bundled dashboards — one
`docker compose up` away from a live **latkit — Redis** dashboard of a cache
that was neither instrumented nor reconfigured, whose password nobody handed
over, and which does not know the agent is there.

The point of the stack in one line: the agent is told `6379=redis`, so a fourth
framer reads RESP2/RESP3 under the cache's own nouns — a **command** from a
closed table instead of normalised SQL, the **`SELECT`ed database** and the
**ACL user** as the two dimensions, a **symbolic error** instead of a SQLSTATE,
and three separate duration families, because a `GET`, a `BLPOP` and a command
answered `+QUEUED` inside a transaction are not the same kind of number.

Works the same against Valkey, KeyDB, Dragonfly and Sentinel: on the wire they
are RESP.

## Requirements

- **Linux host** with kernel **≥ 5.15** and BTF at `/sys/kernel/btf/vmlinux`
  (any mainstream distro of the last few years qualifies; the agent checks on
  startup and says exactly what is missing). Docker Desktop on macOS/Windows
  runs a VM kernel — not tested, not promised.
- Docker with the compose plugin. The `latkit` container runs `privileged`
  with `pid: host` (demo simplicity; the minimal capability set is a comment
  in the compose file and a table in [docs/deploy.md](../../docs/deploy.md)).

## Run

```sh
git clone --recurse-submodules https://github.com/sky-rzn/latkit.git
cd latkit/deploy/demo-redis
docker compose up --build -d
```

First run builds the agent image (~1–2 min) and pulls redis/prometheus/grafana.
With the images already present, measured on this host: `up` returns in **4 s**,
the first `latkit_redis_*` samples are in Prometheus **14 s** after the command,
and the dashboard's top-commands panel is complete within the minute. From
`git clone` on a cold machine it is about 3–4 minutes, and image pulls on a slow
network are the one thing that can stretch it.

Then open:

| what | where |
|---|---|
| **Grafana** — anonymous, the bundled dashboards in the *latkit* folder | <http://localhost:3000/dashboards> |
| Prometheus | <http://localhost:19090> |
| raw agent metrics | `curl http://localhost:9752/metrics` |

Give it ~1 minute after `up`: Prometheus scrapes every 5 s and the load runs a
pass of ~60 commands in a loop. Start at **latkit — Redis**; the database, HTTP
and S3 dashboards stay empty here.

Tear down (containers, volumes and network — nothing survives):

```sh
docker compose --profile tls down -v
```

(The profile flag makes `down` cover the optional TLS services too; it is
harmless otherwise.)

**If this host already runs a Redis on 6379** — an application's cache, another
compose stack — its traffic lands in these metrics too: the port filter is
kernel-wide and the labels are not meant to tell two servers apart. Move the
stack instead of stopping yours:

```sh
REDIS_PORT=6399 docker compose up --build -d
```

`GRAFANA_PORT`, `PROM_PORT` and `METRICS_PORT` work the same way if 3000, 19090
or 9752 are taken on your machine.

## What to look at, and why it is there

The load ([`load/load.sh`](load/load.sh)) drives `redis-cli` rather than a
client library, for one reason and against another: it can put an exact number
of commands into a single write (feed it a file) and it can speak an inline
command, neither of which a library will do on request. Every pass writes
**fresh keys** — `lk:user:<n>:session`, `lk:cart:<n>` — which is what a real
keyspace looks like and exactly what must not reach a label.

Measured on this stack after a couple of minutes (3 095 commands):

- **Top commands** is a short, stable list of **35 identities**, and every one
  of them is a row of the table in
  [docs/notes-redisproto.md](../../docs/notes-redisproto.md):

  ```
  AUTH BLPOP CLIENT|SETNAME CONFIG|GET DISCARD EVAL EXEC EXISTS EXPIRE GET
  HGETALL HSET INCR KEYS LPUSH LTRIM MGET MULTI PING PSUBSCRIBE PUBLISH RPUSH
  SADD SCAN SCARD SELECT SET SUBSCRIBE TTL UNLINK XADD XLEN ZADD ZREVRANGE
  ZSCORE
  ```

  Note `CONFIG|GET` and `CLIENT|SETNAME`: for the fifteen *container* commands
  the second element is a subcommand and part of the identity, and for every
  other command the second element is a **key** and is not read at all;
- **`cmd="other"` share** is the honesty panel. It sits at **zero** here, and it
  is not a cardinality guard — the command label is bounded by a table of ~250
  values, not by a heuristic — it is a *freshness* signal: a module command
  (`JSON.SET`, `FT.SEARCH`) or a fork's own extension lands there, and a rising
  share means the table has fallen behind what your deployment actually runs;
- **`latkit_metric_series`** (Agent health) stays flat at **42** while every
  pass invents new keys. That is the privacy invariant from the other end: **a
  key is never a label**, and a Redis key is the most sensitive string in the
  request — `lk:user:42:session` is an identifier, and a cache's keyspace is
  usually a map of your users;
- **Top databases** has `0` and `9`: `db` is the `SELECT`ed database, tracked
  per connection. The load also issues `SELECT 42` on a server with 16
  databases — the server refuses, the connection stays where it was, and the
  label does not move, because it moves on the *reply* and not on the command;
- **Top users** has `default` and `demoapp`. The name comes out of
  `AUTH <user> <pass>`; the password is a separate element of the same array and
  is never read — nor shown: `--messages --hexdump` blanks it. A connection that
  authenticates with a password only (`AUTH <pass>`) is `default`, which is a
  real answer rather than an absence;
- **Errors by symbol** — measured here: `WRONGTYPE` (a list operation on a
  string), `NOAUTH` (a client that never authenticated), `WRONGPASS` (one that
  got the password wrong) and `ERR` (the refused `SELECT 42`). At the transport
  level all four are "an error reply"; the symbol is what makes them four
  different pages at 3 a.m. The sentence after the symbol — which names the key
  that had the wrong type — reaches nothing;
- **Blocking waits** is a family of its own: the load's `BLPOP` waits about a
  second for a push that another process sends. That duration is the *client's*
  own choice, and in the general histogram one `BLPOP key 30` would decide the
  p99 of the whole instance. 23 of them here, and the duration histogram beside
  it does not contain a single one;
- **Transactions** — 24 committed and 24 aborted, in
  `latkit_txn_duration_seconds`, the same family PostgreSQL and MySQL feed. The
  commands *inside* a `MULTI` are answered `+QUEUED` in microseconds: they are
  counted as commands and reach no duration histogram at all, because their
  latency describes nothing;
- **Pushes** — 834 of them: pub/sub deliveries and keyspace notifications, the
  values that answer nobody. A queue that let one of those close a unit would
  shift every latency on that connection *plausibly*, which is why this counter
  exists rather than an assertion in a comment;
- **`PING`** has a panel of its own (and 42 of them came from the probe
  container's inline healthcheck — a bare `PING\r\n` on a fresh connection,
  which is not RESP at all and is still a command). `PING` does no work, so its
  latency *is* the event loop's queueing delay: it is the one command whose p99
  answers "is the server stalled", and `INFO commandstats` reports its mean
  service time as a flat zero for ever;
- **Value sizes** — the grid starts at 8 bytes, because half of what a real
  Redis holds is smaller than the first bucket of the HTTP grid. The load's
  64 KiB blob sits at the top of it.

### The claims, by hand

```sh
# 1. Commands, and nothing but commands from the table:
curl -s http://localhost:9752/metrics | grep '^latkit_redis_commands_total' \
  | sed 's/.*cmd="\([^"]*\)".*/\1/' | sort -u

# 2. No key, anywhere in the exposition (the load names keys after a counter
#    with a `:`-separated prefix precisely so this is checkable):
curl -s http://localhost:9752/metrics | grep -c 'lk:'            # 0

# 3. ... and no password either, though two of them cross the wire every pass:
curl -s http://localhost:9752/metrics | grep -cE 'lkrootpass|demoapppass'   # 0

# 4. The three duration families, and what is in each:
curl -s http://localhost:9752/metrics \
  | grep -E '^latkit_(redis_command_duration_seconds_count|redis_blocking_seconds_count|txn_duration_seconds_count)'
```

## What you will not see, and why

Two things this stack is deliberately explicit about, because both are
properties of the design rather than bugs, and an operator meets them:

**1. A reply that is a long array needs a bigger capture budget.** The per-port
budget defaults to **512 bytes** on a redis port (a command is a verb and a key,
and a value is never read) — and a *bulk* reply of any size is fine at that
budget, because a bulk announces its length and the framer skips the payload
arithmetically. An **array** announces a count and not a size, so a hole inside
one cannot be skipped: the reply is unframeable and its command is not observed
at all. Measured on this stack with `SCAN 0 COUNT 100`, whose reply is ~2 KB of
array:

| budget | `SCAN` observed | dropped units |
|---|---|---|
| `6379=redis` (default 512) | **none of 5** | 5 |
| `6379=redis:4096` | **6 of 6** | 1 |

So this demo sets `LATKIT_PORT=…=redis:4096`, and says so in the compose file.
The default is right for the deployments the track is aimed at — `GET`, `SET`,
`HGETALL`, `MGET` of a handful of keys — and a keyspace-scanning workload
(`SCAN` with a large `COUNT`, `KEYS *`, `LRANGE 0 -1` over a long list) wants
the budget raised for exactly those commands. The cost is documented and
measured in [docs/perf.md](../../docs/perf.md) §Redis: more bytes per ringbuf
record, which matters at a few hundred thousand commands a second and not at a
few thousand.

**2. `latkit_queries_dropped_total{reason="disconnect"}` is not zero here, and
that is a fact about clients.** About one per pass: the load kills a subscriber
with `timeout` every pass, and `redis-cli` exits the moment its `SELECT 42` is
refused. A client that goes away with a command outstanding leaves a unit that
will never be answered, and it is dropped and counted rather than guessed at.
`parse_errors`, `resync` and `ringbuf_dropped` are all **zero** on this stack —
those three are facts about the agent.

One more, out of the demo's reach but worth knowing: a reply large enough to
fill the server's socket buffer is written in several `tcp_sendmsg` calls, of
which the first is counted at the length it *asked for* rather than the length
the kernel took. That is a capture-layer limitation of the SEND hook
([docs/notes-iov.md](../../docs/notes-iov.md) "Known limitations"), it shows up
on RESP as one `parse_errors` and one resync for that reply, and it is why the
demo's blob is 64 KiB rather than a megabyte.

## TLS profile

```sh
docker compose --profile tls up --build -d
```

adds a **TLS-only** Redis on 6380 (`--port 0`, so there is no plaintext
fallback to observe by accident) with `io-threads 4`, and a client that only
talks to it, next to the plaintext pair. The socket bytes of those sessions are
ciphertext; the plaintext on the dashboards comes from uprobes on `libssl`
inside the Redis process, and the observations are not distinguishable from the
plaintext leg's — which is the claim, measured command for command by
[`tests/e2e/verify-redis-tls.sh`](../../tests/e2e/verify-redis-tls.sh). Proof it
is really the TLS path:

```sh
curl -s http://localhost:9752/metrics | grep -E '^latkit_tls_(attached|connections|decrypted|correlation)'
# want: tls_attached{state="ok"} 1, connections and decrypted_bytes growing,
#       correlation_misses_total 0
```

`--tls auto` is the whole configuration: every Redis, Valkey and KeyDB build
measured — the Alpine images included — links OpenSSL dynamically, so unlike
MinIO there is no second mechanism to name. Two things follow from Redis' own
thread model and are handled for you: with `io-threads N` the server does its
`SSL_read`/`SSL_write` from threads called `io_thd_1…N`, which the derived
uprobe gate admits by prefix (an operator's own `--comm redis-server` would not,
and that is measured — 24 % of the commands), and a connection that was already
open when the agent started is adopted on its first decrypted byte rather than
read as ciphertext for the life of the pool. Client pools live for days, so on
this protocol "the agent started after the connection did" is what every restart
looks like.

## Spans

There is no trace profile here, and unlike the S3 demo that is not because a
span would carry something sensitive — on Redis it structurally cannot. A
sampled command becomes a `SPAN_KIND_CLIENT` span with the DB semantic
conventions (`db.system.name=redis`, `db.operation.name`, `db.namespace`) and a
`db.query.text` that is **built** from the identity: `GET ?`, one `?` per
argument, never a byte of the wire. Spans stay off until you pass an endpoint:

```sh
LATKIT_OTLP_ENDPOINT=http://your-collector:4318 LATKIT_OTLP_SPANS=1 \
  docker compose up --build -d
```

## How it is wired

- **redis** (`redis:7.4`, no persistence — an RDB fork or an AOF rewrite would
  show up in these latencies as the agent's fault) publishes **no** port: the
  clients reach it by service name over the compose network. A published
  `localhost` port would route through docker-proxy, which `splice()`s the
  payload past the socket layer and defeats the capture (README "Known
  limitations"). `requirepass` plus one ACL user, so the `user` label has more
  than one value and the two authentication failures are two different symbols.
- **load** — [`load/load.sh`](load/load.sh): the command mix, two databases, two
  users, a pipeline of 30 in one write, a transaction, a blocking pop, a
  subscription, a 64 KiB value, a `KEYS *` over 20k keys every fourth pass, and
  the deliberate failures.
- **probe** — [`probe/probe.sh`](probe/probe.sh): the traffic a client library
  does not generate — an **inline** `PING` from a load balancer's TCP probe, and
  a keyspace-notification listener, which is the second source of pushes and the
  one that is easy to forget exists.
- **latkit** — the release scratch image built from
  [`deploy/docker/Dockerfile`](../docker/Dockerfile) (musl static), configured
  only through `LATKIT_*` env: `LATKIT_PORT=6379=redis:4096,6380=redis:4096`,
  `/metrics` on `0.0.0.0:9752`, `LATKIT_TLS=auto`.
- **prometheus** (2.x) — scrapes `latkit:9752` every 5 s, 2 h retention.
- **grafana** (pinned 11.x) — anonymous Viewer; the datasource and the
  dashboards are provisioned from the postgres demo's
  [`../demo/grafana/provisioning`](../demo/grafana/provisioning) (same
  `prometheus` service name) plus [`../../dashboards`](../../dashboards),
  mounted read-only — the repo directory is the single source, no copies.

## Troubleshooting

- `latkit` exits immediately → `docker compose logs latkit`. The usual causes
  are missing BTF (`/sys/kernel/btf/vmlinux`) or an old kernel.
- Panels show "No data" → wait for the first scrapes (~30 s after `up`), then
  check `docker compose logs load` and the Prometheus target page at
  <http://localhost:19090/targets>.
- Ports 3000/9752/19090 taken → `GRAFANA_PORT=3010 PROM_PORT=19091
  METRICS_PORT=9753 docker compose up -d`; nothing inside the stack depends on
  the host port numbers.
- **The numbers look too big, or there are commands the load does not send** →
  something else on this host is speaking Redis on the same port. See the
  `REDIS_PORT` note above.
- **Your application connects over a unix socket** → then this agent sees
  nothing at all, and that is the track's declared blind zone. Check with
  `redis-cli config get unixsocket`; capture is on `tcp_sendmsg`/`tcp_recvmsg`,
  and `AF_UNIX` never goes through them.
