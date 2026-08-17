# notes-redisproto: RESP2/RESP3 — values on the wire, commands, sessions, pushes

Design notes backing the Redis track ([PLAN-REDIS.md](../PLAN-REDIS.md),
Russian, decisions РR1–РR15). Same genre as [notes-pgproto](notes-pgproto.md),
[notes-myproto](notes-myproto.md) and [notes-httpproto](notes-httpproto.md),
and like the last three written *before* the code: it fixes what we believe the
protocol does, which fields become labels, and where we stay blind on purpose.

**This is a new protocol, not a dialect.** RESP has no headers, no statuses and
no routes, so the `struct lk_http_dialect` seam (РH8) does not apply here and is
not reused. What is reused is everything else: the stream mode of the protocol
vtable (РH1), the in-flight unit queue, the metric-profile machinery (РH10), the
closed identity table instead of a heuristic (РS2), the symbolic `err_name`
field (РS5), the `mask_body` hook (РH3/РH12), the TLS comm sets (РH13.1/РМ10)
and the per-port capture budget (РH14).

Primary sources: the RESP2 and RESP3 specifications, the Redis command
reference, and `redis/src/networking.c` for the parser's own limits. Every claim
that matters is cross-checked against `tests/traces/redis/` — the МR0 corpus,
recorded from Redis 7.4.10 and Valkey 8 driven by six client libraries — and
this file says which trace proves what. Numbers quoted as "measured" come from
`tests/traces/redis/recon.sh`, whose output is kept in `.work/recon/`.

Scope guard: **RESP over TCP, server side**, plaintext or through the existing
libssl channel. The unix socket, the cluster bus, the replication stream and the
`MONITOR` feed are out of scope by construction — see §"Blind spots", where each
is named rather than implied.

## What МR0 changed in the plan

Six assumptions of PLAN-REDIS.md did not survive contact with a live server.
They are argued where they belong, and collected here so that МR1–МR7 do not
have to rediscover them:

| Plan | Measured |
|---|---|
| РR2: `LK_REDIS_MAX_DEPTH = 8`, "real replies never nest deeper than 4" | `COMMAND DOCS` nests **13** deep and is the first thing an interactive `redis-cli` sends; `COMMAND` nests 9, `XINFO STREAM FULL` 8. The stack is **32**, and overflow degrades instead of declaring corruption (§"Depth") |
| РR8: "a push never closes a unit", plus a counting rule for RESP2 | In RESP3 the **subscribe confirmation is itself a push**, so that rule would leave every `SUBSCRIBE` unit open. One rule serves both versions: read the kind word in the first element (§"Subscriptions") |
| РR3: the attribute is only listed among the types | An attribute is a **prefix** to the next value and must not close a unit (§"The attribute is a prefix") |
| РR4: "~250 identities, table closed" | 250 commands **+ 129 subcommands = 379** identities; the container list is 15 and includes `MODULE`, while `DEBUG` has no declared subcommands at all (§"The table") |
| РR12: the thread filter must pass `io-thd-*`; Alpine may be statically linked | The threads are `io_thd_N`; a filter naming only `redis-server` drops **72 %** of the traffic; every image measured, Alpine included, links `libssl` dynamically with TLS compiled in (§"TLS and io-threads") |
| Risk 5: "if RESP3 turns out to be the main mode, reorder МR2" | Two of five client libraries (go-redis, Lettuce) speak RESP3 out of the box and three speak RESP2. Neither branch is the exotic one; no reordering (§"`HELLO` and the protocol version") |
| РR6: `mask_body` covers `AUTH` and `HELLO` | Three more commands put a password on the wire, and two of them are in the corpus: `ACL SETUSER u on >pass`, `CONFIG SET requirepass <pass>` and `MIGRATE … AUTH <pass>`. The mask covers all five (§"The user is the first argument") |

## An exchange, annotated

```
 *3\r\n$3\r\nSET\r\n$4\r\nlk:k\r\n$5\r\nhello\r\n   <- one command: an array of bulks
 +OK\r\n                                           <- one reply: a simple string

 *2\r\n$3\r\nGET\r\n$4\r\nlk:k\r\n                 <- cmd="GET"; the key is never a label
 $5\r\nhello\r\n                                   <- a bulk: 5 bytes follow, then CRLF

 *1\r\n$4\r\nEXEC\r\n
 *3\r\n+OK\r\n:1\r\n$1\r\n1\r\n                    <- an array of three replies, one unit
```

The whole of the framer is in those three exchanges: a value starts with a type
byte, a bulk carries its length in bytes, an aggregate carries its length **in
elements**, and a unit is one command and the one top-level value that answers
it. Everything difficult in this track follows from the third of those.

Verbatim in `redis/basic.lkt` and `redis/multi.lkt`.

## Framing: values, not packets

### The type bytes

| Byte | Type | RESP2 | RESP3 | On the wire |
|---|---|---|---|---|
| `+` | simple string | ✓ | ✓ | `+OK\r\n` |
| `-` | error | ✓ | ✓ | `-WRONGTYPE Operation against…\r\n` |
| `:` | integer | ✓ | ✓ | `:12345\r\n` |
| `$` | bulk string | ✓ | ✓ | `$5\r\nhello\r\n`, null is `$-1\r\n` |
| `*` | array | ✓ | ✓ | `*3\r\n…`, null is `*-1\r\n` |
| `_` | null | — | ✓ | `_\r\n` |
| `#` | boolean | — | ✓ | `#t\r\n` / `#f\r\n` |
| `,` | double | — | ✓ | `,3.141\r\n`, also `,inf`, `,-inf`, `,nan` |
| `(` | big number | — | ✓ | `(1234567999999999999999999999999999999\r\n` |
| `!` | blob error | — | ✓ | `!21\r\nSYNTAX invalid syntax\r\n` — **never seen**: Redis 7.4 answers `-` even in RESP3 |
| `=` | verbatim string | — | ✓ | `=22\r\ntxt:Redis ver. 7.4.10\n\r\n` (`LOLWUT`) |
| `%` | map | — | ✓ | `%1\r\n$3\r\nkey\r\n$3\r\nval\r\n` — the count is **pairs** |
| `~` | set | — | ✓ | `~3\r\n…` |
| `>` | push | — | ✓ | `>3\r\n$7\r\nmessage\r\n…` |
| `\|` | attribute | — | ✓ | `\|1\r\n…` — a **prefix**, see below |

Measured, one command per type: `DEBUG PROTOCOL <type>` (`redis/types.lkt`,
`redis/types3.lkt`). The same command against the same server in the two
versions is the cleanest statement of what RESP3 changed:

| `DEBUG PROTOCOL` | RESP2 answer | RESP3 answer |
|---|---|---|
| `double` | `$5\r\n3.141` | `,3.141` |
| `bignum` | `$37\r\n1234567…` | `(1234567…` |
| `null` | `$-1` | `_` |
| `set` | `*3` | `~3` |
| `map` | `*6` (flattened) | `%3` (pairs) |
| `true` / `false` | `:1` / `:0` | `#t` / `#f` |
| `verbatim` | `$25\r\nThis is a verbatim\nstring` | `=29\r\ntxt:This is a verbatim\nstring` |
| `attrib` | (nothing — the reply alone) | `\|1\r\n…` then the reply |

Consequences for the framer (РR2):

- **The type byte is the whole classification.** Unlike MySQL, no phase context
  is needed to read a value; unlike PG, there is no fixed header. A framer that
  knows the fourteen bytes above knows every value both versions can produce.
- **A bulk has a byte length, an aggregate has an element count.** `$1048576`
  can be skipped arithmetically through a capture hole, exactly like a PG body;
  `*3` cannot be skipped at all — the only way past an array is through its
  elements. This asymmetry is the substance of risk 1 of the plan.
- **A map's count is pairs, an attribute's count is pairs**, and both then hold
  `2 × n` values. Off-by-two here silently eats the next reply.
- **Verbatim carries a three-byte format and a colon inside the payload**
  (`txt:`, `mkd:`) that are part of the bytes counted by the length; nothing has
  to be done about it, and nothing may be assumed about it either.

### The attribute is a prefix, not a reply

```
 |1\r\n$14\r\nkey-popularity\r\n*2\r\n$7\r\nkey:123\r\n:90\r\n
 $39\r\nSome real reply following the attribute\r\n
```

Two top-level values arrive; only the second answers the command
(`redis/types3.lkt`). **An attribute must not close a unit** — if it does, every
subsequent reply on that connection answers the previous command, and the
latencies stay plausible while being wrong. Attributes exist only in RESP3; in
RESP2 the same server sends the reply alone.

Nothing in a stock Redis 7.4 emits an attribute outside `DEBUG PROTOCOL`, which
is precisely why it will not be noticed until a module or a future version emits
one.

### Inline commands

A line that does not begin with a type byte is an inline command — what
`telnet`, a healthcheck script and a load balancer's TCP probe send:

```
 PING\r\n                      -> +PONG
 ECHO hello\r\n                -> $5\r\nhello
 SET  "a b"  "c d"\r\n         -> +OK      (quotes, and repeated spaces, are handled)
 \r\n                          -> (nothing at all: an empty line is not a command)
 PING\n                        -> +PONG    (a bare LF terminates an inline line)
```

Measured in `redis/inline-cmds.lkt`, including an inline `INFO server` and a
RESP `PING` in the same write. Three properties matter to us:

- an **empty line produces no reply**, so it must not open a unit;
- the parser splits on `\n` and strips a trailing `\r`, so `\n`-only clients
  work — while a *multibulk* command with `\n`-only terminators does **not**
  parse and simply stalls (measured);
- an inline line longer than 64 KB is `-ERR Protocol error: too big inline
  request` and the connection is closed.

### What the server refuses, and what it does next

| Input | Answer | Connection |
|---|---|---|
| `*0\r\n`, `*-1\r\n`, `*-5\r\n` | none | stays open |
| `*1\r\n+PING\r\n` (element not a bulk) | `-ERR Protocol error: expected '$', got '+'` | **closed** |
| `$536870913` (over `proto-max-bulk-len`) | `-ERR Protocol error: invalid bulk length` | **closed** |
| `$abc` | `-ERR Protocol error: invalid bulk length` | **closed** |
| `*2147483648` (over `INT_MAX`) | `-ERR Protocol error: invalid multibulk length` | **closed** |
| `SET "x\r\n` | `-ERR Protocol error: unbalanced quotes in request` | **closed** |
| `GET / HTTP/1.1` + `Host: …` | none | **closed** (Redis's own "security attack" check on `Host:`/`POST`) |
| 256 bytes of binary junk | none | stays open (it is an unterminated inline line) |
| a TLS ClientHello on the plaintext port | none | stays open, for the same reason |

Measured in `redis/garbage.lkt`. **A protocol error is terminal**: the server
answers once and hangs up, so a framer that sees `-ERR Protocol error:` knows
the connection is over and its in-flight units are lost — a cheap, reliable
signal PG and MySQL do not offer.

`proto-max-bulk-len` is 512 MB by default and is a *configured* bound, so it is
read from the wire's perspective as a validation rule, not a constant: a bulk
length beyond it is corruption (`bad_len`, dirty direction), a bulk length under
it is honoured even when it is enormous.

### Depth: the plan said 4, the server says 13

`LK_REDIS_MAX_DEPTH` was proposed as 8 on the reasoning that real replies never
nest deeper than 4. Measured against a stock 7.4 (`clients/depth.py`, recon item
6):

| Depth | Reply | Size |
|---|---|---|
| **13** | `COMMAND DOCS` | 213 589 B |
| 9 | `COMMAND`, `COMMAND INFO` | 93 936 B |
| 8 | `XINFO STREAM … FULL` (with a group, a consumer and a PEL) | |
| 7 | `COMMAND INFO GET` | |
| 5 | `COMMAND DOCS GET` | |
| 4 | `XRANGE`, `XPENDING`, `SLOWLOG GET`, `FUNCTION STATS` | |
| ≤ 3 | everything an application actually runs | |

And `COMMAND DOCS` is not exotic: **it is the first command an interactive
`redis-cli` sends**, before the prompt appears (measured, recon item 2). A Lua
script can return an arbitrarily nested table, so no bound is universal:
`EVAL "return {1,{2,{3,{4,{5,{6,{7,{8,{9,10}}}}}}}}}"` measures 10.

Therefore: **the stack is 32 entries, and an overflow is a degradation, not a
verdict.** A stack entry is one counter, so 32 costs 128 bytes per direction;
treating depth as evidence of corruption would declare a human opening
`redis-cli` to be a corrupt stream. Past the bound the framer stops descending
and resynchronises on the next syscall boundary, counting it — the same honesty
as a capture hole, and visible on the dashboard rather than silent.

### Resync anchors

After a capture hole the framer re-enters on:

- **Frontend (strong):** a syscall boundary + `*` + a plausible element count
  (1…1024) + `$` as the first element's type + a plausible bulk length. Clients
  start a batch on a write boundary, so this is the direct analogue of the PG
  frontend anchor and it is what `redis/pipeline-depths.lkt` exercises.
- **Backend (weak):** a syscall boundary + a valid type byte. A bulk's *payload*
  can look like anything, including a perfectly formed reply, so the backend
  anchor cannot be strong; the discipline comes from the frontend side.
- **A hole inside an aggregate is not recoverable** — there is no length to skip
  by. The direction is dirtied and the queued units are dropped into the
  existing `units_dropped_resync`. The mitigation is the budget: at 512 bytes
  per call (РR13) the holes fall in bulk *payloads*, which are skipped
  arithmetically, and not in the headers.

### What is on the port but is not RESP

Three streams share the port with ordinary traffic and none of them is a
sequence of replies:

- **The replication handshake and the RDB transfer.** Measured
  (`redis/replica.lkt`, `server/replication.lkt`): the master answers `PING` and
  the `REPLCONF`s normally, then sends **bare `\n` bytes as keepalives** while
  it forks, then `+FULLRESYNC <replid> <offset>`, then — with the default
  `repl-diskless-sync yes` — `$EOF:<40 hex>\r\n<RDB><40 hex>`, a bulk with a
  delimiter instead of a length. Turn diskless off and it is `$<len>\r\n<RDB>`
  **with no trailing CRLF**: a bulk that is not a value. After that the
  connection carries the write-propagation stream: RESP arrays, but *from the
  server*, none of which answers anything. `PSYNC`/`SYNC` → `LK_CONN_IGNORE` (РR14) is not an
  optimisation, it is the only correct reading.

  **Any `REPLCONF` is the marker, not just `listening-port`** — a correction МR2
  made to РR14, and the corpus is the reason. A replication link is usually
  joined *mid-stream*: it was established long before the agent attached, so its
  handshake is not on the tape and the only mark left is the replica's periodic
  `REPLCONF ACK <offset>`. **39** of the МR0 traces carry such a link beside
  the traffic they were recorded for (the recording host had a replica attached
  — `libs/java-pipeline.lkt` is the clearest: a hundred propagated `SET`s from
  the server on one connection while Lettuce pipelines a hundred commands on
  another). Only a replica sends `REPLCONF` at all, so the broader rule costs
  nothing and is the one that catches them.
- **The `MONITOR` feed.** `+OK` and then an unbounded stream of simple strings,
  one per command executed by *other* clients:
  `+1786889998.990261 [0 127.0.0.1:47914] "SET" "lk:mon" "v"`. Redis redacts
  `AUTH` arguments in this feed itself — a useful precedent for what РR6 asks of
  us (`redis/monitor.lkt`).
- **The cluster bus** on port +10000: binary gossip, not RESP, and out of scope
  by port (`cluster/bus.lkt` records three seconds of it so the README can point
  at what it is not).

## The unit: one command, one top-level value (РR3)

A unit opens at the first byte of a command and closes at the last byte of the
**oldest unanswered** top-level value from the server. There is no request id
and no sequence number: order is the only correspondence the protocol offers,
which is why the in-flight queue is mandatory from the first day and why
anything unsolicited on the wire has to be recognised as such.

### Pipelining is the normal mode, and it is measured

Commands per client `write(2)`, measured through `clients/tap.py` (recon item 3;
the tap counts on the same boundary the kprobes see):

| Client | Ordinary work | Its own pipeline API | Pool of 4 under threads |
|---|---|---|---|
| redis-py 5.2.1 | 1 | 100 in one write | 1 (208 writes, 208 commands) |
| go-redis v9.7 | 1 | 100, split 18 + 82 by its buffer | 1 |
| node-redis 4.7 | 1 | 100 in one write | — |
| Lettuce 6.5 | 1 | 100 in one write | — |
| phpredis 6.x | 1 | 100 in one write | — |
| memtier `--pipeline 1` | 1 (15 542 writes, 15 542 commands) | — | — |
| memtier `--pipeline 100` | **100** (3 606 writes, 360 600 commands) | — | — |

So: a pooled application pipelines at depth 1 and a batching one at exactly the
depth it asked for. `LK_REDIS_MAX_INFLIGHT = 256` covers every measured case
with room; go-redis's split shows the other reason the queue exists — a batch
can arrive in more than one syscall, and a syscall can hold part of a command.

### What closes a unit, and what must not

| Arrives from the server | Closes the oldest unit? | Why |
|---|---|---|
| any ordinary value | **yes** | the reply |
| `+QUEUED` | yes, as a queued unit (`LK_QO_QUEUED`) | it is a real reply, but not a measurement |
| an error, including `-MOVED`/`-ASK` | yes | still the reply to that command |
| `\|` attribute (RESP3) | **no** | a prefix to the value that follows |
| `>` push carrying `message`/`pmessage`/`smessage` | **no** | somebody else's publication |
| `>` push carrying `invalidate` | **no** | client-side-caching notification |
| `>` push carrying `subscribe`/`unsubscribe`/… | **yes** | it *is* the reply to `SUBSCRIBE` — see below |
| the `MONITOR` feed, the RDB stream | n/a | the connection is `LK_CONN_IGNORE` |

### Subscriptions: the correction to РR8

РR8 says pushes never close units and that RESP2 needs a counting rule. Measured
(`redis/pubsub.lkt`, `redis/pubsub3.lkt`), the truth is one rule for both
versions and it is not counting:

```
 RESP2  SUBSCRIBE chan  ->  *3 [ "subscribe", "chan", 1 ]      (an ordinary array)
        publication     ->  *3 [ "message",   "chan", "…"  ]   (an ordinary array)
 RESP3  SUBSCRIBE chan  ->  >3 [ "subscribe", "chan", 1 ]      (a push!)
        publication     ->  >3 [ "message",   "chan", "…"  ]   (a push)
```

The **first element carries the kind** in both versions, and the two sets do not
overlap: `subscribe`, `unsubscribe`, `psubscribe`, `punsubscribe`, `ssubscribe`,
`sunsubscribe` are confirmations; `message`, `pmessage`, `smessage`,
`invalidate` are deliveries and close nothing. Reading the first element is
cheaper and steadier than counting channels across a resync — and in RESP3 the
naive rule "a push never closes a unit" would leave every `SUBSCRIBE` unit open
for ever.

**A confirmation closes a unit only when the unit it would close is itself a
subscribe-family command** — the refinement МR2 had to make to the sentence
above, because one command is not always one confirmation. `SUBSCRIBE c1 c2` is
one command and **two** confirmations, one per channel (measured,
`redis/pubsub.lkt`), and a bare `UNSUBSCRIBE` produces one per channel the
connection happened to hold, a number no observer can know. So the first
confirmation answers the unit and the rest answer nothing that is still queued.
Letting them close the units behind it would credit the next command with a
latency it never had; calling them orphans would report a loss where nothing was
lost. They are counted with the pushes, which is what they are to the queue: a
server value that closes nothing.

Three more facts a subscribe-mode connection needs:

- **RESP2 restricts the connection**: only `(P|S)SUBSCRIBE`, `(P|S)UNSUBSCRIBE`,
  `PING`, `QUIT` and `RESET` are allowed, and anything else is
  `-ERR Can't execute 'get': only (P|S)SUBSCRIBE / … are allowed in this
  context`. **`PING` answers `*2 ["pong", ""]` there** — an array, not `+PONG`.
- **RESP3 does not restrict anything**: `GET` while subscribed works normally
  and answers with an ordinary value (measured). This is why the RESP3 branch is
  not exotic — it is the branch where a connection is a subscriber *and* a
  client at the same time, and where the in-flight queue and the push stream
  genuinely interleave.
- `RESET` leaves subscribe mode (and the transaction, and the ACL user, and the
  database, and RESP3 — everything) and answers `+RESET`.

### A reply can arrive before its own command

Not on the wire — in the *message stream*, and the difference matters because
the queue is built on the second. A command larger than the per-call capture
budget (РR13 makes that 512 bytes, so a `SET` of a one-kilobyte value qualifies)
has an uncaptured tail, and the chunk layer only learns that tail existed when
the **next call on that direction** starts (Р9's lazy tail: `total_len` is
honest, so the remainder is a hole of known size, but nothing reveals it until
the following `off == 0`). The value is therefore published late — after the
reply to it has already gone by.

Measured on `redis/bigvalue.lkt`: four commands, and framing them naively yields
three observations, one orphan, and a pairing that stays one behind for the rest
of the connection — three plausible durations belonging to the wrong commands,
which is exactly the failure the in-flight queue exists to prevent. So a reply
that finds an empty queue *while a value is still being assembled on the
frontend* is held rather than orphaned, and the command claims it when it
arrives. Only the last value of a call can be left open, so one held reply is
the realistic depth.

### Timeouts

`LK_REDIS_UNIT_TIMEOUT` (30 s) is the second line of defence of risk 4: a queue
that has been non-empty longer than any sane `BLPOP` is flushed into
`units_dropped_close` instead of mis-attributing latency for ever. `BLPOP key 0`
blocks indefinitely and is legal, so the timeout drops units rather than closing
the connection.

## Identity: the command table (РR4)

`COMMAND` on a live server is the table's source of truth — it enumerates every
command, every container's subcommands, and the flags that decide the bits we
need (`clients/cmdtable.py`, recon item 6):

```
 Redis 7.4.10   250 commands, 15 containers, 129 subcommands -> 379 identities
                12 blocking, 104 writing
```

That is more identities than the plan's "~250 with subcommands", and it is still
a closed set: a lookup, never a heuristic, and bounded by construction.

The fifteen container commands, whose *second* word is part of the identity and
whose second word is therefore never a key: `ACL`, `CLIENT`, `CLUSTER`,
`COMMAND`, `CONFIG`, `FUNCTION`, `LATENCY`, `MEMORY`, `MODULE`, `OBJECT`,
`PUBSUB`, `SCRIPT`, `SLOWLOG`, `XGROUP`, `XINFO`. For every other command the
second word is user data — a key, a field, a value — and must never reach a
label. Redis itself uses our notation: a permission error names the identity as
`'acl|whoami'` (`redis/acl-errors.lkt`).

`DEBUG` is the exception the table does not describe: the server declares no
subcommands for it, and `DEBUG SLEEP`, `DEBUG PROTOCOL`, `DEBUG OBJECT`,
`DEBUG JMAP` are one command with a free-form first argument. It is disabled in
any real deployment (`enable-debug-command` defaults to off), so it is `DEBUG`
and nothing more. `SENTINEL` is a container too, but only on a server running
in sentinel mode, where it is the whole API.

### The table

<!-- generated by tests/traces/redis/clients/cmdtable.py; regenerate it, do not
     edit it by hand — src/norm/norm_redis_table.h is generated *from this
     section* (tests/unit/redis_table.sh --emit) and the ctest `redis_table`
     fails if the compiled table and this one ever disagree, so the source of
     truth is the server and the chain from it is two mechanical steps -->

250 commands, 15 of them containers holding 129 subcommands: 379 identities in
all. `*` marks the write bit; the blocking bit is listed under the table.

```
  APPEND*               ASKING                AUTH                  BGREWRITEAOF
  BGSAVE                BITCOUNT              BITFIELD*             BITFIELD_RO
  BITOP*                BITPOS                BLMOVE*               BLMPOP*
  BLPOP*                BRPOP*                BRPOPLPUSH*           BZMPOP*
  BZPOPMAX*             BZPOPMIN*             COPY*                 DBSIZE
  DEBUG                 DECR*                 DECRBY*               DEL*
  DISCARD               DUMP                  ECHO                  EVAL
  EVALSHA               EVALSHA_RO            EVAL_RO               EXEC
  EXISTS                EXPIRE*               EXPIREAT*             EXPIRETIME
  FAILOVER              FCALL                 FCALL_RO              FLUSHALL*
  FLUSHDB*              GEOADD*               GEODIST               GEOHASH
  GEOPOS                GEORADIUS*            GEORADIUSBYMEMBER*    GEORADIUSBYMEMBER_RO
  GEORADIUS_RO          GEOSEARCH             GEOSEARCHSTORE*       GET
  GETBIT                GETDEL*               GETEX*                GETRANGE
  GETSET*               HDEL*                 HELLO                 HEXISTS
  HEXPIRE*              HEXPIREAT*            HEXPIRETIME           HGET
  HGETALL               HINCRBY*              HINCRBYFLOAT*         HKEYS
  HLEN                  HMGET                 HMSET*                HPERSIST*
  HPEXPIRE*             HPEXPIREAT*           HPEXPIRETIME          HPTTL
  HRANDFIELD            HSCAN                 HSET*                 HSETNX*
  HSTRLEN               HTTL                  HVALS                 INCR*
  INCRBY*               INCRBYFLOAT*          INFO                  KEYS
  LASTSAVE              LCS                   LINDEX                LINSERT*
  LLEN                  LMOVE*                LMPOP*                LOLWUT
  LPOP*                 LPOS                  LPUSH*                LPUSHX*
  LRANGE                LREM*                 LSET*                 LTRIM*
  MGET                  MIGRATE*              MONITOR               MOVE*
  MSET*                 MSETNX*               MULTI                 PERSIST*
  PEXPIRE*              PEXPIREAT*            PEXPIRETIME           PFADD*
  PFCOUNT               PFDEBUG*              PFMERGE*              PFSELFTEST
  PING                  PSETEX*               PSUBSCRIBE            PSYNC
  PTTL                  PUBLISH               PUNSUBSCRIBE          QUIT
  RANDOMKEY             READONLY              READWRITE             RENAME*
  RENAMENX*             REPLCONF              REPLICAOF             RESET
  RESTORE*              RESTORE-ASKING*       ROLE                  RPOP*
  RPOPLPUSH*            RPUSH*                RPUSHX*               SADD*
  SAVE                  SCAN                  SCARD                 SDIFF
  SDIFFSTORE*           SELECT                SET*                  SETBIT*
  SETEX*                SETNX*                SETRANGE*             SHUTDOWN
  SINTER                SINTERCARD            SINTERSTORE*          SISMEMBER
  SLAVEOF               SMEMBERS              SMISMEMBER            SMOVE*
  SORT*                 SORT_RO               SPOP*                 SPUBLISH
  SRANDMEMBER           SREM*                 SSCAN                 SSUBSCRIBE
  STRLEN                SUBSCRIBE             SUBSTR                SUNION
  SUNIONSTORE*          SUNSUBSCRIBE          SWAPDB*               SYNC
  TIME                  TOUCH                 TTL                   TYPE
  UNLINK*               UNSUBSCRIBE           UNWATCH               WAIT
  WAITAOF               WATCH                 XACK*                 XADD*
  XAUTOCLAIM*           XCLAIM*               XDEL*                 XLEN
  XPENDING              XRANGE                XREAD                 XREADGROUP*
  XREVRANGE             XSETID*               XTRIM*                ZADD*
  ZCARD                 ZCOUNT                ZDIFF                 ZDIFFSTORE*
  ZINCRBY*              ZINTER                ZINTERCARD            ZINTERSTORE*
  ZLEXCOUNT             ZMPOP*                ZMSCORE               ZPOPMAX*
  ZPOPMIN*              ZRANDMEMBER           ZRANGE                ZRANGEBYLEX
  ZRANGEBYSCORE         ZRANGESTORE*          ZRANK                 ZREM*
  ZREMRANGEBYLEX*       ZREMRANGEBYRANK*      ZREMRANGEBYSCORE*     ZREVRANGE
  ZREVRANGEBYLEX        ZREVRANGEBYSCORE      ZREVRANK              ZSCAN
  ZSCORE                ZUNION                ZUNIONSTORE*
```

| Container | Subcommands |
|---|---|
| `ACL` | `CAT`, `DELUSER`, `DRYRUN`, `GENPASS`, `GETUSER`, `HELP`, `LIST`, `LOAD`, `LOG`, `SAVE`, `SETUSER`, `USERS`, `WHOAMI` |
| `CLIENT` | `CACHING`, `GETNAME`, `GETREDIR`, `HELP`, `ID`, `INFO`, `KILL`, `LIST`, `NO-EVICT`, `NO-TOUCH`, `PAUSE`, `REPLY`, `SETINFO`, `SETNAME`, `TRACKING`, `TRACKINGINFO`, `UNBLOCK`, `UNPAUSE` |
| `CLUSTER` | `ADDSLOTS`, `ADDSLOTSRANGE`, `BUMPEPOCH`, `COUNT-FAILURE-REPORTS`, `COUNTKEYSINSLOT`, `DELSLOTS`, `DELSLOTSRANGE`, `FAILOVER`, `FLUSHSLOTS`, `FORGET`, `GETKEYSINSLOT`, `HELP`, `INFO`, `KEYSLOT`, `LINKS`, `MEET`, `MYID`, `MYSHARDID`, `NODES`, `REPLICAS`, `REPLICATE`, `RESET`, `SAVECONFIG`, `SET-CONFIG-EPOCH`, `SETSLOT`, `SHARDS`, `SLAVES`, `SLOTS` |
| `COMMAND` | `COUNT`, `DOCS`, `GETKEYS`, `GETKEYSANDFLAGS`, `HELP`, `INFO`, `LIST` |
| `CONFIG` | `GET`, `HELP`, `RESETSTAT`, `REWRITE`, `SET` |
| `FUNCTION` | `DELETE`, `DUMP`, `FLUSH`, `HELP`, `KILL`, `LIST`, `LOAD`, `RESTORE`, `STATS` |
| `LATENCY` | `DOCTOR`, `GRAPH`, `HELP`, `HISTOGRAM`, `HISTORY`, `LATEST`, `RESET` |
| `MEMORY` | `DOCTOR`, `HELP`, `MALLOC-STATS`, `PURGE`, `STATS`, `USAGE` |
| `MODULE` | `HELP`, `LIST`, `LOAD`, `LOADEX`, `UNLOAD` |
| `OBJECT` | `ENCODING`, `FREQ`, `HELP`, `IDLETIME`, `REFCOUNT` |
| `PUBSUB` | `CHANNELS`, `HELP`, `NUMPAT`, `NUMSUB`, `SHARDCHANNELS`, `SHARDNUMSUB` |
| `SCRIPT` | `DEBUG`, `EXISTS`, `FLUSH`, `HELP`, `KILL`, `LOAD` |
| `SLOWLOG` | `GET`, `HELP`, `LEN`, `RESET` |
| `XGROUP` | `CREATE`, `CREATECONSUMER`, `DELCONSUMER`, `DESTROY`, `HELP`, `SETID` |
| `XINFO` | `CONSUMERS`, `GROUPS`, `HELP`, `STREAM` |

Blocking: `BLMOVE`, `BLMPOP`, `BLPOP`, `BRPOP`, `BRPOPLPUSH`, `BZMPOP`,
`BZPOPMAX`, `BZPOPMIN`, `WAIT`, `WAITAOF`, `XREAD`, `XREADGROUP` — twelve, of
which the last two block only with a `BLOCK` argument (see below).

`PSYNC`, `SYNC`, `REPLCONF` and `MONITOR` are in the table as commands and are
the four that take a connection out of observation entirely (РR14).

Details the table does not hold:

- **Case is free.** go-redis sends `set`/`get`/`hello` in lower case, every
  other client in the corpus sends upper case, and the server accepts both
  (`libs/go-basic.lkt`). Normalise to upper case before the lookup.
- **A container called bare** (`CONFIG` alone) is an arity error, and an unknown
  subcommand (`CONFIG NOSUCHSUB`) is `-ERR unknown subcommand`. Both are real
  commands with real replies; identity is `CONFIG|other` and `CONFIG`.
- **Module commands** (`JSON.SET`, `FT.SEARCH`, `TS.ADD`) are not in the table
  and become `cmd="other"`, as are the admin extensions of the forks.
- **The blocking bit is on the command, not on the arguments**: the server flags
  `XREAD` and `XREADGROUP` blocking unconditionally, but `XREAD COUNT 10
  STREAMS s 0` returns immediately and `XREAD BLOCK 300 STREAMS s $` does not
  (`redis/blocking.lkt`). The bit therefore has to be refined by looking for the
  `BLOCK` keyword — the single place where an argument is inspected, and only
  for its presence as a keyword, never for its value.
- The twelve commands the server itself flags blocking: `BLMOVE`, `BLMPOP`,
  `BLPOP`, `BRPOP`, `BRPOPLPUSH`, `BZMPOP`, `BZPOPMAX`, `BZPOPMIN`, `WAIT`,
  `WAITAOF`, `XREAD`, `XREADGROUP`.

### What never becomes a label, at any setting

Keys, fields, members, values, scores, script bodies, script SHAs, channel
names, passwords, and the arguments of any command. A Redis key *is* an
identifier (`user:42:session`), and it belongs where an S3 object key belongs:
nowhere. The privacy test of РH12 gets Redis cases for exactly this
(`redis/basic.lkt` has keys, `redis/auth-forms.lkt` has passwords, and neither
may appear in any label, span attribute or `--messages` line).

## The session: database and user (РR5, РR6)

**Both labels move on the reply, never on the command** — the rule the whole
section rests on, and the reason the handler parks a *candidate* on the
in-flight unit instead of applying it where it reads it. `SELECT 16` is an error
and the connection stays where it was; `AUTH lkuser wrongpass` is `-WRONGPASS`
and the user does not change. A state machine that moved on the request would be
wrong about every command after it, for as long as the connection lived, and
every one of those observations would look perfectly plausible.

Three consequences of that rule are worth stating, because none of them is
obvious from the wire:

- **the `SELECT` itself is observed in the database it was issued from.** At the
  moment the command went out, the connection was still in the old one.
- **a `SELECT` whose reply was lost takes the label with it** (`db="?"`): we know
  the connection moved and cannot say where, and keeping the old number would be
  a plausible lie for the rest of the connection. Same for a lost `AUTH`.
- **a user name that is not label-shaped folds to `user="other"`.** An ACL name
  is an operator's word and always passes (printable ASCII, no space, no quote);
  what does not is a client writing arbitrary bytes where a series name goes —
  the rule S3 applies to bucket names (РS3), for the same reason.

### `SELECT` is connection state

```
 SELECT 3      -> +OK          the connection is now in database 3
 SELECT 16     -> -ERR DB index is out of range     (the default is 16 databases)
 SELECT abc    -> -ERR value is not an integer or out of range
 RESET         -> +RESET       back to database 0, user default, RESP2, no MULTI
 SWAPDB 3 15   -> +OK          the *contents* move; the connection does not
```

Measured in `redis/select-db.lkt`. Consequences: the label follows a per-
connection state machine, only a **successful** `SELECT` moves it, and a
connection the agent did not see open cannot know it — hence `db="?"` and not
`db="0"` for `LK_CONN_SYNTHETIC` (`redis/midstream.lkt` is recorded by starting
the client before the agent, so the `SELECT 7` and the `AUTH` really are
invisible). `MOVE`/`COPY … DB n` name another database in an argument without
changing the connection's own — they are ordinary commands.

### The user is the first argument of `AUTH`, and the password is never read

```
 AUTH <password>                       one argument: the default user, nothing to read
 AUTH <user> <password>                two: the *first* is the user
 HELLO 3 AUTH <user> <password> SETNAME <name>
 HELLO 2 AUTH <user> <wrongpass>   -> -WRONGPASS … and the user does not change
```

Measured in `redis/auth-forms.lkt`, confirmed by `ACL WHOAMI` after each form.
The name sits in its own array element, so unlike HTTP Basic (РH12) nothing has
to be decoded to find it and the dimension can default to `on`.

`mask_body` must cover `AUTH` and `HELLO`: in `--messages --hexdump` and in
`lkt_messages` the password element is replaced, not shown. Redis sets the
precedent itself — its own `MONITOR` feed prints `"AUTH" "(redacted)"
"(redacted)"`.

**And three more commands, which МR3 found in the corpus rather than in the
plan.** A password reaches the wire without an `AUTH` in sight:

```
 ACL SETUSER lkreader on >lkpass ~lk:* +get     the rules starting with > < # !
 CONFIG SET requirepass lkrootpass              the value of a credential parameter
 MIGRATE host port key db timeout AUTH <pass>   another server's credential
```

The first two are in `redis/acl-errors.lkt` — the trace creates its ACL user and
turns `requirepass` on and off around the `-NOAUTH` scenario — so a mask that
covered only `AUTH` would have left two real passwords in a `--hexdump` view.
Each has its own shape (a rule prefix, a parameter name, a keyword), which is
why each is a separate bit of the table rather than one "there is a secret in
here" flag: a viewer has to know *which* element to blank.

What is **not** masked is as deliberate: the ACL user name, the permission rules,
the `HELLO` version and its `SETNAME`, and every key. The first four are what a
dump of a handshake is read for, and a key is not a credential — what the track
promises about keys is that nothing derives from them and nothing keeps them,
which is a claim about labels, metrics and spans (`tests/replay/redis_privacy.sh`
checks both halves, and states the distinction).

`--redis-user off` turns the dimension off entirely: the name is then not read at
all, and `user=""` reaches the registry as `user="-"`. On by default, unlike
`--http-user` — the name is its own array element, so reading it decodes nothing
and touches no password (РH12 vs РR6).

Failure modes worth having tests for: `-NOAUTH Authentication required.` before
any successful `AUTH` on a password-protected server, `-WRONGPASS` for a bad
pair, `-NOPERM User lkreader has no permissions to run the 'set' command` and
`-NOPERM No permissions to access a key` for an ACL user who is allowed less
than it asked (`redis/acl-errors.lkt`).

### `HELLO` and the protocol version

`HELLO` with no argument reports the current version and does not change it;
`HELLO 3` switches the connection to RESP3 **and the reply itself is RESP3**
(a map); `HELLO 2` switches back and answers with a RESP2 array; `HELLO 4` is
`-NOPROTO unsupported protocol version`; `HELLO abc` is an ordinary argument
error (`redis/hello-probe.lkt`). The version is per connection, it can change
mid-stream, and a connection picked up mid-stream has to be discovered from what
it sends — a `%`, `~`, `,`, `#`, `_`, `=`, `(` or `>` on the wire proves RESP3.

Which clients switch, measured (recon item 2 — this is risk 5 of the plan,
answered):

| Client | Version | What it sends first |
|---|---|---|
| go-redis v9.7 | **RESP3** | `hello 3`, then `client setinfo` ×2 |
| Lettuce 6.5 | **RESP3** | `HELLO 3`, then `CLIENT SETINFO` ×2 |
| redis-py 5.2.1 | RESP2 | `CLIENT SETINFO` ×2 (`protocol=3` is opt-in) |
| node-redis 4.7 | RESP2 | `CLIENT SETINFO` ×2 (`RESP: 3` is opt-in) |
| phpredis 6.x | RESP2 | nothing — straight to the first command |
| `redis-cli` | RESP2 | the command (`-3` switches; interactive sends `COMMAND DOCS`) |

**Both branches are main paths.** Two of the five libraries negotiate RESP3 out
of the box, so the push branch is not a curiosity, and the RESP2 branch is not
legacy: the tests for both weigh the same.

## Errors: symbolic, and not all of them are failures (РR7)

An error is `-` followed by a first token that is the symbol. Measured
dictionary from the corpus (`redis/errors.lkt`, `redis/acl-errors.lkt`,
`cluster/moved.lkt`, `cluster/ask.lkt`):

| Symbol | Where it came from |
|---|---|
| `ERR` | unknown command, wrong arity, `DB index is out of range`, `EXEC without MULTI`, `MULTI calls can not be nested`, `value is not an integer`, protocol errors |
| `WRONGTYPE` | `LPUSH` on a string, `XADD` on a string |
| `NOSCRIPT` | `EVALSHA` of a sha the server does not have |
| `NOAUTH` | any command before `AUTH` on a protected server |
| `WRONGPASS` | `AUTH` with a bad pair, `HELLO … AUTH` with a bad pair |
| `NOPERM` | an ACL user without the command, or without the key |
| `EXECABORT` | `EXEC` after a queue-time error |
| `NOPROTO` | `HELLO 4` |
| `MOVED` / `ASK` | a cluster key that lives elsewhere / is in flight |
| `CROSSSLOT` | `MGET foo bar` on a cluster |
| `LOADING`, `MISCONF`, `BUSY`, `BUSYGROUP`, `READONLY`, `MASTERDOWN`, `CLUSTERDOWN`, `TRYAGAIN`, `UNBLOCKED`, `NOTBUSY`, `OOM`, `NOREPLICAS` | states of a server under load, replication or eviction — in the dictionary, not in the corpus |
| anything else | `error="other"` — including a script's own `redis.error_reply('CUSTOMERR …')`, which is measured |

Two properties decide how they are counted:

- **`MOVED` and `ASK` are normal cluster operation.** Measured
  (`cluster/moved.lkt`): a client that guesses wrong gets `-MOVED 12182
  127.0.0.1:6392` and retries; a healthy resharding cluster produces them
  continuously. In `errors_total` they would paint a healthy cluster red for
  ever, so they get their own counter and `LK_QO_CLIENT_ERR` — the same flag 4xx
  carries in HTTP.
- **`ASK` needs a slot in flight**, and the corpus produces one on purpose
  (`cluster/ask.lkt`): with the slot `MIGRATING` on the owner and `IMPORTING` on
  the target, a *missing* key in that slot answers `-ASK 14758 127.0.0.1:6390`,
  the target answers `-MOVED` for the same key without `ASKING`, serves it after
  `ASKING`, and goes back to `-MOVED` for the very next command. One `ASKING`,
  one command.
- **`MISCONF` and `LOADING` stay errors**: they are the server refusing to work.

Two rules the МR4 implementation adds, both about what may become a label:

- **the symbol is folded to the table, and the answer is a pointer into it.**
  Not "the token, if we recognise it": an unfolded token is a series name chosen
  by whoever is talking to the server, and a script really does invent them
  (`redis.error_reply('CUSTOMERR …')`, measured in `redis/eval-scripts.lkt`).
  Case is not folded either — an error symbol is upper-case by convention, and a
  lower-case one is somebody's invention.
- **the sentence after the symbol reaches nothing.** It is written for a human
  and it names the key that had the wrong type, the slot and node a `MOVED`
  points at, the command an ACL refused. `MOVED 12182 127.0.0.1:6392` as a label
  would be one series per slot per node.

A symbol the capture budget cut in half is not a symbol: the reader takes a token
only when something ended it inside the published prefix, so a `-NOPERM …` cut at
its fourth byte yields nothing rather than `NOPE` — which would fold to `other`
anyway, by luck rather than by rule. A capture *hole* inside an error line is a
different thing again: a line has no length to step over, the direction resyncs
and the in-flight units are dropped (risk 1).

## Transactions (РR9)

```
 MULTI              -> +OK
 SET a 1            -> +QUEUED          microseconds; not a latency
 INCR n             -> +QUEUED
 EXEC               -> *2 [ +OK, :1 ]   the only reply that took any work
```

Measured, with all five endings (`redis/multi.lkt`, `redis/watch-abort.lkt`):

| Ending | Wire |
|---|---|
| commit | `EXEC` → an array of the queued replies |
| discard | `DISCARD` → `+OK`, nothing runs |
| queue-time error | the offending command errors *at queue time*, `EXEC` → `-EXECABORT Transaction discarded because of previous errors.` |
| run-time error | the command queues fine and the error is an element inside `EXEC`'s array — the transaction still commits |
| `WATCH` broken | `EXEC` → `*-1` (RESP2) / `_` (RESP3): a **null, not an error** |
| abandoned | the connection closes with the transaction open; nothing runs |

A nested `MULTI` is `-ERR MULTI calls can not be nested` and the first
transaction survives unharmed. So: `+QUEUED` units carry `LK_QO_QUEUED` and no
duration; the transaction's interval is `MULTI` → the reply to `EXEC` and goes
to `lk_reg_observe_txn`; `DISCARD`, `-EXECABORT` and a null `EXEC` are all
`aborted`.

Three details МR4 had to settle, none of which is visible from the table above:

- **`*0` and `*-1` are one byte apart and opposite.** An `EXEC` that ran no
  commands answers `*0` and committed; one a broken `WATCH` refused answers
  `*-1` and did not. To the framer both are "an aggregate of no elements" —
  rightly, since both are complete where they stand — so the handler reads the
  sign out of the published prefix rather than the element count.
- **Valkey 8 ends a nested `MULTI` differently from Redis 7.4** (measured,
  `redis/multi.lkt` against `valkey/multi.lkt`): Redis keeps the transaction and
  answers the following `EXEC` with `*0`, Valkey treats the refusal as a
  queue-time error and answers `-EXECABORT`. Both are read correctly because the
  verdict comes from the reply and not from a model of what a server ought to
  do — the same reason the session labels of РR5/РR6 move on the reply.
- **`+QUEUED` is recognised from the reply, not from a `MULTI` we saw.** It costs
  nothing (no command outside a transaction is answered with that word) and it is
  what makes a connection joined mid-stream right: the transaction started before
  we were watching, and its commands are still not latencies. It also keeps a
  queue-time error honest — the offending command is answered *instead* of
  `+QUEUED`, so it keeps its duration and its symbol.

## Blocking commands (РR10)

```
 BLPOP lk:bl 1   -> *-1 after 1.08 s     the client chose the wait
 BLPOP lk:bl 5   -> *2 [...] after 0.50 s   the event chose it
```

Measured in `redis/blocking.lkt`. Neither number says anything about the server,
which is why they belong in their own histogram: with a 30-second `BLPOP` in the
same series as `GET`, the p99 of a Redis is whatever its longest poll is. `WAIT`
and `WAITAOF` block on replication rather than on a key and belong there too.

The `BLOCK` keyword of `XREAD`/`XREADGROUP` is **the only argument anything in
this tree reads past the identity**, so it is worth stating exactly how far the
read goes:

- only for those two commands, which carry their own table bit
  (`LK_REDIS_C_ARGBLOCK`) precisely so that every other command pays nothing;
- for its *presence*, never its value — how many milliseconds the client was
  willing to wait is its own business;
- and only **before `STREAMS`**, after which every element is a key or an id. A
  stream named `BLOCK` is a legal key (`XREAD COUNT 2 STREAMS BLOCK 0`), and a
  key that decided the family would be the same mistake as a key that decided a
  label.

The read is LK_REDIS_ARGV_MAX elements deep for those two commands and
LK_REDIS_ARGV_LABELS for the rest: `XREADGROUP GROUP g c COUNT 10 BLOCK 0` puts
the keyword at element 6, which the label-depth read would not reach. A keyword
past even that bound — or cut off by the capture budget — reads as an ordinary
command, which is the same honest failure a command whose verb was cut off
already has.

## Sizes, and why the budget is 512 bytes (РR13)

Measured over a load shaped like an application (`clients/wirestats.py`):

```
 command bytes: min 14   median 36   max 65 574 (a 64 KB SET)
 reply bytes:   min  3   median 19   max 65 546 (the GET of it)
 under a 512-byte budget: 31/32 commands fit whole, 29/32 replies do
```

The outliers are the point. A command is a verb, a key and sometimes a value;
the value can be megabytes and is never read. A reply is a few bytes, except
when it is an entire object, a `KEYS *` over a million keys (`redis/keys-1m.lkt`)
or `COMMAND DOCS` (213 KB). Everything the agent needs — the type byte, the
error symbol, the declared length, the command and its subcommand — lives in the
first few dozen bytes of each. 512 bytes is chosen so that holes land in bulk
payloads, which are skipped arithmetically, and not in headers, which cannot be.

## What Redis already reports, and what it cannot (§2 of the plan)

Measured (`clients/commandstats.py`, recon item 6), 2000 `GET`s on one
connection against an idle server:

```
 wire (first byte out -> last byte in):     20.68 us/call
 server (INFO commandstats):    usec_per_call=0.22
```

…and the same 50 `GET`s while a single `DEBUG SLEEP 0.2` occupies the event loop
on **another** connection:

```
 wire:                                    4038.69 us/call
 server (INFO commandstats):    usec_per_call=0.30
```

The server is not lying: the `GET` really did execute in under a microsecond.
But Redis is single-threaded, the sleeping neighbour held the loop, and the
application waited four milliseconds for a cache hit. `commandstats` cannot see
that gap by construction, `SLOWLOG` only sees execution time (so it never fires
here), and `LATENCY HISTORY` reports events, not distributions. The gap *is* the
product. `redis/head-of-line.lkt` records it: four `GET`s on four connections,
all answered 0.201 s after a `DEBUG SLEEP 0.2` started elsewhere.

## Servers and forks

- **Valkey 8.1.9** is RESP-identical on everything the corpus exercises
  (`valkey/*.lkt` runs the same scenarios). Measured with the same
  `COMMAND`-derived table: 242 commands against Redis 7.4's 250, 241 of them
  shared; Redis has the hash-field-TTL family Valkey has not yet taken
  (`HEXPIRE`, `HPEXPIRE`, `HTTL`, `HPERSIST` and five relatives), Valkey has
  `COMMANDLOG`. Both land in `cmd="other"` on the other server, which is the
  designed behaviour. Its binary is `valkey-server` and it ships `redis-server`
  as a symlink to it, which matters for the comm set; it also reports
  `redis_version:7.2.4` in `INFO` for compatibility, so a version label read
  from `INFO` would name the wrong product — one more reason we read none.
- **KeyDB** is wire-compatible and multi-threaded; not in CI.
- **Dragonfly** claims compatibility and diverges in `INFO` and in its own admin
  commands — those land in `cmd="other"`, which is the designed behaviour.
- **Sentinel** (26379) speaks RESP with its own command set (`SENTINEL …` is a
  container command); it needs no code at all.

## TLS and io-threads (РR12)

**Every image measured links libssl dynamically and has TLS compiled in** —
including the Alpine ones, which the plan expected to be the exception (recon
item 5): `redis:7.4` (Debian), `redis:7.4-alpine`, `redis:6.2-alpine`,
`valkey/valkey:8`, `bitnami/redis`, and the Debian/Ubuntu/Alpine packages. So
the existing libssl uprobe channel applies without a line of new BPF, and the
Go channel is not needed at all.

**io-threads change who makes the syscalls.** A server started with
`--io-threads 4 --io-threads-do-reads yes` has threads named `redis-server` (the
main one), `io_thd_1`, `io_thd_2`, `io_thd_3` — underscores, not the `io-thd-*`
the plan guessed — plus `bio_*` and `jemalloc_bg_thd`, which never touch
sockets. Two measurements decide МR7:

- Redis only *engages* its io threads when there are more clients than
  `io-threads × 2`; at 4 connections all the I/O stayed on the main thread, and
  at 100 connections it spread out.
- Under 100 connections, `--comm redis-server` captured **56 375 records where
  no filter captured 200 200** — a comm filter naming only the main thread
  drops **72 %** of the traffic, and `--comm io_thd_1` alone captures 49 307,
  another quarter. Both directions appear under every thread, so read and write of one
  connection genuinely change hands. The `{ssl, tgid}` bridge is keyed on the
  process, so it survives; the comm filter is what must name all four.

**What МR7 then built and measured** (details in
[notes-tls.md](notes-tls.md) §4c):

- the AUTO scan set for a redis port is `{redis-server, valkey-server,
  keydb-server}`, and the uprobe gate is that set plus **`io_thd_*`** — a comm
  filter entry may now end in `*` and match a prefix, because how many io
  threads exist is the server's own `io-threads` setting and no list of literals
  can be written in advance;
- the recon number reproduced under TLS on `verify-redis-tls.sh`: of memtier's
  100 000 commands over 100 connections, the derived gate observed 100 005 (the
  five extra are the stand's own traffic) and a second agent on the same port
  with `--comm redis-server` observed 24 147 — 24 %, against the 28 % measured
  in plaintext;
- the `{ssl, tgid}` bridge did survive: **0 correlation misses**, and the
  encrypted leg matched the plaintext leg command for command;
- one thing the recon did not predict: RESP has no in-band TLS negotiation, so
  the framer needed the HTTPS treatment — recognise the handshake record where a
  command belongs (`LK_REDIS_NOTE_TLS`) — and a connection already open when the
  agent attaches is adopted on its first decrypted byte. The second matters more
  for Redis than for anything before it: clients hold pools and subscriptions
  open for days, so every agent restart lands mid-session.

## Blind spots

- **The unix socket.** `tcp_sendmsg`/`tcp_recvmsg` are not on that path, so a
  client on `/run/redis/redis.sock` is invisible — measured, not assumed: three
  commands over AF_UNIX under a live capture produce a 4-byte trace, which is
  the file header and nothing else (recon item 1). How much that costs depends
  on the deployment, and the packaged configurations disagree:

  | Deployment | Listens on a unix socket by default? |
  |---|---|
  | official `redis:*` image (and every compose file using it) | no — the image ships no config file at all |
  | Debian 12 / Ubuntu 24.04 `redis-server` package | no — `# unixsocket …` is commented out |
  | **Alpine `redis` package** | **yes** — `unixsocket /run/redis/redis.sock`, perm 770 |
  | bitnami image / bitnami helm chart | no — commented out, and the chart has no setting for it |

  So in containers and Kubernetes — where latkit runs — the socket is off unless
  somebody turned it on, and on an Alpine host it is on unless somebody turned
  it off. This belongs in the README as the first line, and it is the entry
  point to a possible separate track (`unix_stream_sendmsg`).
- **The cluster bus** (port +10000): binary gossip, not RESP.
- **Replication**: `PSYNC`/`SYNC`/`REPLCONF` → `LK_CONN_IGNORE`; the RDB stream
  and the propagation stream are not commands.
- **`MONITOR`**: `LK_CONN_IGNORE` with its own reason — the connection becomes a
  feed of other clients' commands, and parsing it as replies is guaranteed
  corruption.
- **Values.** Bulk payloads are skipped, never parsed; the only bytes ever read
  out of a reply body are the error symbol and the kind word of a push.
- **Module commands** — `cmd="other"` (RedisJSON, RediSearch, TimeSeries).
- **Keyspace notifications** are ordinary pub/sub messages and are covered by
  the push rule; they are named here because they arrive without anybody
  subscribing to a channel by name (`__keyevent@0__:set`).
- **Anything after a capture hole inside an aggregate**, until resync.

## What the corpus proves

`tests/traces/redis/` (МR0, recorded against Redis 7.4.10 and Valkey 8), and
what each claim in this file rests on:

| Claim | Trace |
|---|---|
| every RESP2 and RESP3 type, from one command | `redis/types.lkt`, `redis/types3.lkt` |
| an attribute precedes the reply and a push can follow it | `redis/types3.lkt` |
| inline commands, empty lines, bare LF, quotes | `redis/inline-cmds.lkt` |
| a protocol error is answered once and the socket closes | `redis/garbage.lkt` |
| a bulk of 1 MB is skipped arithmetically in both directions | `redis/bigvalue.lkt`, `redis/bigvalue-cap512.lkt` |
| a torn bulk and a torn reply | `redis/torn-bulk.lkt` |
| one byte per syscall still parses | `redis/slow-client.lkt` |
| batches of 1, 2, 3, 10, 50 and 100 | `redis/pipeline-depths.lkt`, `redis/pipeline100.lkt` |
| the RESP2 subscribe protocol, `PING` included | `redis/pubsub.lkt` |
| the RESP3 push protocol, and commands while subscribed | `redis/pubsub3.lkt` |
| an `invalidate` push nobody asked for | `redis/tracking.lkt` |
| the five endings of a transaction | `redis/multi.lkt`, `redis/watch-abort.lkt` |
| blocking latency is the client's, not the server's | `redis/blocking.lkt` |
| the error dictionary | `redis/errors.lkt`, `redis/acl-errors.lkt` |
| `MOVED`, `CROSSSLOT`, and a real `ASK` | `cluster/moved.lkt`, `cluster/ask.lkt` |
| both `AUTH` forms, `HELLO … AUTH`, and `-WRONGPASS` leaving the user alone | `redis/auth-forms.lkt` |
| the database is connection state, and out-of-range is an error | `redis/select-db.lkt` |
| a connection whose `SELECT` and `AUTH` happened before the agent attached | `redis/midstream.lkt` |
| container commands and their subcommands | `redis/containers.lkt` |
| replies nest to 5 in ordinary use and to 13 in `COMMAND DOCS` | `redis/nested.lkt`, recon item 6 |
| the replication handshake, the RDB transfer, the propagation stream | `redis/replica.lkt`, `server/replication.lkt` |
| the `MONITOR` feed, with Redis redacting `AUTH` itself | `redis/monitor.lkt` |
| one slow command delays everybody, and `commandstats` does not show it | `redis/head-of-line.lkt`, recon item 6 |
| what five client libraries put on the wire when nobody configures them | `libs/*.lkt` |
| 150k operations per second under memtier, and the same pipelined | `libs/memtier-nopipe.lkt`, `libs/memtier-pipe100.lkt` |
| io-threads spread the syscalls over four thread names | `server/io-*.lkt`, recon item 4 |
| Valkey answers the same bytes | `valkey/*.lkt` |
| the unix socket produces nothing at all | recon item 1 (`.work/recon/05-unixsocket.lkt`) |
