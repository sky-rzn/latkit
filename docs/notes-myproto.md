# notes-myproto: the MySQL classic protocol — framing, phases, packets, blind spots

Design notes backing the MySQL track ([MYSQL.md](../MYSQL.md), Russian, decisions
РМ1–РМ10). This is the wire-level conspectus the М2 framer and М3 handler will
be written against — the same genre as [notes-pgproto](notes-pgproto.md), but
written *before* the code: it fixes what we believe the protocol does, which
capability flags we read, and where we deliberately stay blind. Primary sources
are the MySQL source dox ("MySQL Client/Server Protocol") and the MariaDB KB
protocol pages; every claim that matters is cross-checked against the recorded
traces in `tests/traces/mysql/` (М0 corpus — real servers × real clients).

Scope guard: **classic protocol only** (port 3306). The X Protocol (33060,
protobuf) is a different protocol, not a superset — out of scope. The compressed
protocol and replication streams are recognised and treated as blind zones
(РМ7, below).

## Framing: 4-byte header, no type, 16 MB continuations

```
  +--------+--------+--------+--------+----------------------+
  | payload length (u24, LE) |  seq   |  payload (len bytes) |
  +--------+--------+--------+--------+----------------------+
```

- **No type byte in the header.** The first payload byte identifies a client
  command; a server packet has *no* self-describing type at all — OK/ERR/EOF/
  row/column-definition are distinguished by the first payload byte **plus the
  phase** (see "Response classification"). This is the single biggest contrast
  with PG v3 and drives РМ3: the framer hands the handler a whole logical
  packet with `lk_msg.type` = first payload byte for the frontend, `type = 0`
  for the backend.
- **Length is 3 bytes, little-endian**, max `0xFFFFFF` (16 MB − 1). A payload
  of ≥ 16 MB − 1 bytes is split: the sender emits packets of exactly `0xFFFFFF`
  until one with `len < 0xFFFFFF` terminates the sequence (an exact multiple is
  terminated by an *empty* packet). The framer glues continuations into one
  logical `lk_msg` (body prefix still capped at `LK_MSG_BODY_MAX`, the rest is
  an arithmetic skip, as in PG).
- **Sequence id** (`seq`) is per-physical-packet, mod 256. It resets to 0 at
  the start of every command the client sends; each subsequent packet of the
  exchange — server responses, continuation fragments, LOAD DATA chunks, auth
  round-trips — increments it. During the connection phase the server greeting
  is seq 0 and the client's HandshakeResponse is seq 1. The framer swallows seq
  (handlers never see it) but uses it for resync anchoring (РМ4).
- **Who speaks first: the server.** The initial handshake packet arrives before
  the client says anything — the framer's initial states are the mirror image
  of PG's (backend starts in "expect greeting", frontend in "expect handshake
  response").

### Resync anchors (РМ4) — no 'Z'-like pattern exists

There is no byte pattern comparable to PG's `Z 00 00 00 05 [ITE]`. After a
capture gap the framer re-enters on:

- **Frontend (primary):** a syscall boundary (`off == 0`) + `seq == 0` + a
  known command byte + a plausible `len` for that command. Commands start their
  own syscall in every real client, so this is a direct analogue of the PG
  frontend anchor.
- **Backend (weak):** syscall boundary + `seq` consistent with expectation +
  `len < 0xFFFFFF`. Weak on purpose — a row packet body can look like anything.
- Because the protocol is strictly request→response, a clean frontend anchor
  also disciplines the backend direction: a client command while a reply is
  still open closes/drops the open unit (`units_dropped_resync`).

Accepted cost (documented, measured on the accuracy bench): on very large
resultsets with the default capture budget, the tail of the reply falls into a
hole and the unit is lost — the same class of loss as PG losing a
`CommandComplete` in a dirty stretch.

## Connection phase

```
 server                                  client
 ──────────────────────────────────────────────────────────────
 Initial Handshake (seq 0)  ──▶
                            ◀──  SSLRequest (short, CLIENT_SSL set)   } only
                            ═══  TLS handshake, rest inside TLS       } with TLS
                            ◀──  HandshakeResponse41 (user, db, attrs)
 AuthSwitchRequest (0xFE) / AuthMoreData (0x01) ──▶◀── raw auth payloads …
 OK (0x00) ──▶   → command phase          ERR (0xFF) ──▶  → server closes
```

### Initial Handshake (protocol version 10)

What we read, in wire order: `protocol_version u8` (= 10; anything else →
parse error), `server_version` NUL-string (→ session label; **MariaDB prefixes
`5.5.5-`** for replication-compat — strip it: `5.5.5-10.11.6-MariaDB` →
`10.11.6-MariaDB`), `thread_id u32`, 8 bytes auth-plugin-data + filler,
`capability_flags` lower u16, charset u8, `status_flags u16`,
`capability_flags` upper u16, auth-data length u8, 10 reserved bytes (**MariaDB:
the last 4 carry `MARIADB_CLIENT_*` extended capabilities** when the server
does not set the `CLIENT_MYSQL` bit), up to 13 more auth bytes, auth plugin
name NUL-string.

The *server's* capabilities are an offer; what governs the connection is the
**intersection** with the flags the client sends back. The handler keeps the
client's flags as the connection's truth.

### HandshakeResponse41 (and the short SSLRequest)

`client_flags u32`, `max_packet_size u32`, `charset u8`, 23 bytes filler
(MariaDB clients put extended caps in the last 4), then:

- **If `CLIENT_SSL` is set the packet ends right there** (32 bytes of payload)
  and the next bytes on the socket are a TLS ClientHello. The framer flips the
  connection to `LK_CONN_TLS`; the full HandshakeResponse41 repeats *inside*
  TLS and is parsed from the decrypted uprobe channel (М5).
- Otherwise: `username` NUL, auth response (lenenc-prefixed with
  `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA`, else u8-length-prefixed), `database`
  NUL if `CLIENT_CONNECT_WITH_DB`, auth plugin name NUL if `CLIENT_PLUGIN_AUTH`,
  and connection attributes if `CLIENT_CONNECT_ATTRS` — lenenc total length,
  then lenenc key/value pairs. We read `user`, `database`, and from the attrs
  `program_name` (falling back to `_client_name`) → the session's `app` label.

### Authentication round-trips: never read the bodies

Between the HandshakeResponse and the final OK the server may send
`AuthSwitchRequest` (first byte `0xFE` + plugin name NUL + plugin data) or
`AuthMoreData` (first byte `0x01`); the client answers with **raw packets — no
command byte**. The handler counts these and tracks the phase but does not
parse the payloads: they carry password scrambles, and with the
`mysql_clear_password` or TLS paths, actual passwords (the Р16 rule from PG
applies verbatim). `caching_sha2_password` specifics worth knowing for the
test stands: `AuthMoreData 0x03` = fast-path success (OK follows),
`0x04` = full auth — over TLS the client sends the cleartext password, over
plaintext it requests the server's RSA key (`0x02`) and sends it encrypted.
Session labels are safe either way: user/db/attrs sit in the
HandshakeResponse, not in the auth exchange.

Note `0xFE` reuse: in the connection phase `0xFE` is AuthSwitchRequest, in the
command phase it is EOF / terminating-OK. Phase context, not the byte,
disambiguates — a recurring theme of this protocol.

### Capability flags we read (РМ-referenced)

| Flag | Bit | Why latkit cares |
|---|---|---|
| `CLIENT_PROTOCOL_41` | `0x00000200` | assumed on (every supported server/client); ERR carries SQLSTATE only with it |
| `CLIENT_CONNECT_WITH_DB` | `0x00000008` | `database` field present in HandshakeResponse |
| `CLIENT_COMPRESS` | `0x00000020` | compressed protocol → blind zone, IGNORE + HEADERS (РМ7) |
| `CLIENT_ZSTD_COMPRESSION_ALGORITHM` | `0x04000000` | same as above, zstd flavour |
| `CLIENT_SSL` | `0x00000800` | short HandshakeResponse, TLS transition in the framer |
| `CLIENT_TRANSACTIONS` | `0x00002000` | status flags in OK/EOF are meaningful → txn tracking |
| `CLIENT_MULTI_STATEMENTS` | `0x00010000` | `COM_QUERY` may carry `a; b; c` → MULTI_STMT units |
| `CLIENT_MULTI_RESULTS` / `CLIENT_PS_MULTI_RESULTS` | `0x00020000` / `0x00040000` | `SERVER_MORE_RESULTS_EXISTS` chains resultsets in one unit |
| `CLIENT_PLUGIN_AUTH` | `0x00080000` | plugin name field present; auth cycle shape |
| `CLIENT_CONNECT_ATTRS` | `0x00100000` | `program_name` → session `app` label |
| `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA` | `0x00200000` | auth-response length encoding in HandshakeResponse |
| `CLIENT_SESSION_TRACK` | `0x00800000` | OK may carry session-state info (schema change → live `db` label) |
| `CLIENT_DEPRECATE_EOF` | `0x01000000` | resultset terminator is OK-with-0xFE-header instead of EOF |
| `CLIENT_OPTIONAL_RESULTSET_METADATA` | `0x02000000` | metadata-follows byte before column count |
| `CLIENT_QUERY_ATTRIBUTES` | `0x08000000` | **shifts the COM_QUERY layout** — see below |

MariaDB extended flags (the u32 in the greeting filler / response filler):
`MARIADB_CLIENT_PROGRESS` (progress ERR packets, error code `0xFFFF` — not an
error!), `MARIADB_CLIENT_CACHE_METADATA` (resultset may *omit* column
definitions — a metadata-follows byte says which), `MARIADB_CLIENT_STMT_BULK_OPERATIONS`
(COM_STMT_BULK_EXECUTE `0xFA`). Each is covered by an М0 trace or an explicit
unit case rather than assumed compatible (risk 3 of the plan).

## Command phase

The client opens every exchange with a packet at `seq 0` whose first payload
byte is the command. Everything until the reply's terminator belongs to one
**query unit** (the PG unit model carries over; the in-flight ring degenerates
to depth 1 because the classic protocol does not pipeline — see "no response"
exceptions below).

### Command table (byte → action, РМ8)

| Byte | Command | Action |
|---|---|---|
| `0x03` | COM_QUERY | open a SIMPLE unit; SQL text = rest of packet — **but with `CLIENT_QUERY_ATTRIBUTES` two lenenc ints (param count, set count) and, if params > 0, a null-bitmap + types + values precede the text**. Reading the text at a fixed offset is the classic corruption bug (plan risk 4); the offset is computed from the negotiated caps |
| `0x16` | COM_STMT_PREPARE | cache candidate: remember the SQL text, wait for PREPARE-OK to learn the `stmt_id`; opens no unit |
| `0x17` | COM_STMT_EXECUTE | open an EXTENDED unit; text from the `stmt_id → SQL` cache, else `NO_TEXT` |
| `0x1c` | COM_STMT_FETCH | continue/reopen the cursor unit → `SUSPENDED` semantics (PortalSuspended analogue) |
| `0x19` | COM_STMT_CLOSE | drop `stmt_id` from the cache; **no server response** |
| `0x18` | COM_STMT_SEND_LONG_DATA | tally only; **no server response** |
| `0x1a` | COM_STMT_RESET | tally only (OK/ERR reply) |
| `0x02` | COM_INIT_DB | update the session `db` label on OK |
| `0x11` | COM_CHANGE_USER | re-enters an auth cycle; update `user`/`db` on the final OK |
| `0x01` | COM_QUIT | tally only; **no response**, socket closes |
| `0x0e` | COM_PING | tally only |
| `0x09`/`0x0a`/`0x0d` | COM_STATISTICS / PROCESS_INFO / DEBUG | tally only (STATISTICS replies with a bare string packet — not OK/ERR!) |
| `0x1f` | COM_RESET_CONNECTION | tally only; clears server-side session state (prepared statements survive? no — drop the whole prep cache) |
| `0x1b` | COM_SET_OPTION | tally only (toggles MULTI_STATEMENTS live — update the conn's flags) |
| `0x12`/`0x1e` | COM_BINLOG_DUMP / _GTID | replication → IGNORE + `replication_conns` + HEADERS capture |
| `0x15` | COM_REGISTER_SLAVE | tally only (binlog dump follows) |
| `0x04` | COM_FIELD_LIST | tally only (deprecated; replies col defs + EOF) |
| *other* | unknown | `unknown_msgs++`, skip the packet — a future command must not desync the handler |

Service commands never become observations — only `by_type[]` counters (Р18
analogue). `KILL QUERY <id>` is an ordinary COM_QUERY on *another* connection:
indistinguishable and not worth distinguishing — the CANCEL kind stays unused
(unlike PG's CancelRequest).

There is no `SELECT … INTO OUTFILE` marker on the wire — it looks exactly like
a SELECT with zero row packets. Fine; not our problem.

### Response classification (first byte + phase — never the byte alone)

| First byte | When | Meaning |
|---|---|---|
| `0x00` | reply head, or after all rows with DEPRECATE_EOF off | **OK**: lenenc `affected_rows`, lenenc `last_insert_id`, `status u16`, `warnings u16`[, session-track info] |
| `0x00` | expected *binary* row (COM_STMT_EXECUTE resultset) | row header — **not** an OK. Phase decides |
| `0xFF` | anywhere in a reply | **ERR**: `errno u16` (LE), `'#'`, 5-byte SQLSTATE, message. MariaDB progress packets are ERR with errno `0xFFFF` — swallow, not an error |
| `0xFE`, payload < 9 bytes | DEPRECATE_EOF off | **EOF**: `warnings u16`, `status u16` |
| `0xFE`, payload ≥ 7 bytes | DEPRECATE_EOF on, end of rows | **terminating OK** (same layout as OK after the header byte) |
| `0xFB` | reply head to COM_QUERY | **LOCAL INFILE request**: rest = filename → COPY_IN phase |
| `0x01`–`0xFA` (lenenc) | reply head | **resultset**: column count follows |
| anything | row phase | a row packet: text rows are lenenc-string columns (`0xFB` = NULL), binary rows are `0x00` + NULL-bitmap + values |

The `0xFE` length rules are not folklore, they are the protocol's own
disambiguation: a text row whose first column is a huge string starts with the
lenenc prefix `0xFE`, but that implies ≥ 9 bytes of payload — hence "EOF iff
`0xFE` and shorter than 9". The М2 framer/handler asserts these bounds through
`my_wire.h` cursors exactly like `pg_wire` does (fuzz invariants included).

### Resultset state machine (one COM_QUERY / COM_STMT_EXECUTE unit)

```
 command ──▶ [column count] ──▶ col defs × n ──▶ (EOF)* ──▶ rows … ──▶ terminator
     │              │ 0xFB                                              │
     │              └─▶ LOCAL INFILE: client data packets …, empty ──▶ OK/ERR
     │ 0x00/0xFF                                                        │
     └─▶ OK (DML: rows = affected_rows) / ERR                           │
                                                                        ▼
                             SERVER_MORE_RESULTS_EXISTS set? ──▶ next resultset,
                                                        same unit (MULTI_STMT)
```

(*) the EOF after column definitions exists only with `CLIENT_DEPRECATE_EOF`
off — i.e. always on MariaDB, never on modern MySQL clients.

- **Rows (РМ5):** for SELECT the row count is the number of row packets the
  framer actually saw — under capture holes this is a *lower bound*, stated in
  docs/accuracy.md and checked against `performance_schema` on the accuracy
  bench. For DML the count is `affected_rows` from OK — exact, but beware
  `CLIENT_FOUND_ROWS` changes UPDATE semantics from "changed" to "matched"
  (we report what the server reports, per-connection).
- **Timings:** `ts_start` = the command packet, `ts_first_row` = first row
  packet, `ts_complete` = the terminator (OK/ERR/final EOF),
  `ts_ready ≡ ts_complete` — MySQL has no separate `ReadyForQuery`; the
  done-point is single, and the PG field pair is kept equal rather than
  special-cased.
- **Transactions:** `SERVER_STATUS_IN_TRANS` (`0x0001`) edges in OK/EOF status
  flags map onto the existing `on_txn` tracking. `SERVER_STATUS_CURSOR_EXISTS`
  (`0x0040`) / `SERVER_STATUS_LAST_ROW_SENT` (`0x0080`) drive the cursor-fetch
  path below.
- **Multi-statement / multi-resultset:** each terminator with
  `SERVER_MORE_RESULTS_EXISTS` (`0x0008`) keeps the unit open; the unit closes
  on the last terminator and is flagged `LK_QO_MULTI_STMT`. Stored procedures
  with result sets produce the same shape (an extra trailing OK) — same code
  path, no special case.
- **Session tracking:** with `CLIENT_SESSION_TRACK`, an OK after `USE db` (a
  plain COM_QUERY!) carries a `SESSION_TRACK_SCHEMA` blob — parse it to keep
  the `db` label honest; COM_INIT_DB alone does not cover ORMs that issue `USE`.

## Prepared statements (РМ8, cache = pg_prep with a u32 key)

- **COM_STMT_PREPARE → COM_STMT_PREPARE_OK**: `0x00`, `stmt_id u32`,
  `num_columns u16`, `num_params u16`, filler, `warning_count u16`. Then
  `num_params` parameter definitions (+ EOF without DEPRECATE_EOF) and
  `num_columns` column definitions (+ EOF) — the handler needs both counts
  precisely to know how many metadata packets to skip. The cache maps
  `stmt_id → SQL prefix` with the PG rescue/generation machinery intact
  (prep_idx/gen, eviction rescue).
- **COM_STMT_EXECUTE**: `stmt_id u32`, `flags u8`, `iteration_count u32`, then
  parameter values (null-bitmap + new-params-bound flag + types + values; with
  `CLIENT_QUERY_ATTRIBUTES` a lenenc param count comes first). We read only
  `stmt_id` and `flags`. Binary resultset follows — rows start `0x00`.
- **Cursors**: `flags & CURSOR_TYPE_READ_ONLY` makes the server reply with
  metadata + OK (`SERVER_STATUS_CURSOR_EXISTS`) and *no rows*; rows arrive via
  **COM_STMT_FETCH** (`stmt_id u32`, `num_rows u32`), each fetch closed by an
  EOF/OK carrying `CURSOR_EXISTS`, the last one `LAST_ROW_SENT`. Fetch maps to
  the PG `SUSPENDED` outcome — same honesty caveat as PortalSuspended (rows
  counted only from packets seen, dashboard hint text updated in М6).
- **COM_STMT_CLOSE / COM_STMT_SEND_LONG_DATA have no reply.** The unit model
  must not wait for one (they are cache/tally actions, not units), or every
  subsequent latency would be shifted by one exchange.
- JDBC (`useServerPrepStmts=true`) and connector/python (`prepared=True`) are
  the real COM_STMT_* sources in the trace corpus; the mysql CLI's `PREPARE
  s FROM …` is *textual* SQL over COM_QUERY (server-side prepare) — both
  shapes are in the М0 traces and both must parse.

## LOAD DATA LOCAL INFILE (→ LK_Q_COPY_IN)

`COM_QUERY "LOAD DATA LOCAL INFILE 'f' …"` → server replies `0xFB` + filename
→ the client streams the file as raw packets (seq continuing, bodies are data
— never parsed, only `bytes` accumulated) → an **empty packet** marks EOF →
server sends the final OK (`affected_rows` = rows loaded) or ERR. Maps onto
the PG COPY_IN unit shape one-to-one, including the byte counter.

## TLS

The transition is client-initiated via the short HandshakeResponse
(`CLIENT_SSL`), *after* the plaintext greeting — so unlike PG there is always
a parseable server greeting even on TLS connections (server version is never
blind). Past the flip the socket layer is opaque; plaintext re-enters through
the `SSL_read`/`SSL_write` uprobe channel (М5, РМ10) where the full
HandshakeResponse — with user/db/attrs — repeats as the first decrypted bytes.
mysqld is one process with a thread per connection; the existing pid_tgid and
`{ssl, tgid}` keying already assumes nothing about process-per-connection
(the PG comments claiming otherwise get revised in М5). MariaDB builds linked
against bundled wolfSSL/GnuTLS are not uprobe-able — detected by
`latkit_tls_attached`, documented as a support caveat.

## Compression (РМ7 — recognised, not parsed)

`CLIENT_COMPRESS` (zlib) or `CLIENT_ZSTD_COMPRESSION_ALGORITHM` in the
HandshakeResponse switches the stream — *after the auth exchange completes* —
to a compressed framing (7-byte header: compressed len u24, seq u8,
uncompressed len u24). First version: the connection flips to IGNORE +
HEADERS capture with a `reason`-coded counter, exactly like PG replication.
The session labels *are* still read (the handshake happens before compression
kicks in) — a compressed connection is a named blind spot, not an anonymous
one. Decompression in the agent is a possible later extension; note that
compression and TLS stack (compressed frames inside TLS), so the uprobe
channel alone does not lift this blindness.

## MariaDB differences (checklist, each backed by a trace or unit case)

- `server_version` prefixed `5.5.5-` — strip for the session label.
- **No `CLIENT_DEPRECATE_EOF`, ever**: resultsets always carry the
  post-metadata EOF and the EOF terminator. The two resultset shapes are both
  first-class, selected per-connection by the negotiated caps, not by "server
  is MariaDB".
- Extended capabilities live in the greeting's reserved bytes / response
  filler (`MARIADB_CLIENT_*`), governed by the `CLIENT_MYSQL` bit (0x1): a
  MariaDB server talking to a MariaDB client drops `CLIENT_MYSQL` and the
  extra u32 becomes meaningful.
- Progress reporting: ERR packets with `errno == 0xFFFF` are progress events,
  not errors — must not close the unit or count as an error.
- `MARIADB_CLIENT_CACHE_METADATA` (10.6+): a `metadata_follows` byte lets the
  server *skip* column definitions in resultsets — changes the packet count
  between column-count and rows; explicit unit case, present in the trace
  corpus via mariadb clients that enable it.
- Default auth is `mysql_native_password`; `ed25519` and PAM appear in the
  wild — all irrelevant to labels (auth bodies unread), relevant only to the
  round-trip count before OK.

## Blind spots (known, by design)

- **Compressed connections** — labels yes, queries no (РМ7, above).
- **Replication** (`COM_BINLOG_DUMP*`) — IGNORE + HEADERS, `replication_conns`.
- **Row counts under capture holes** — lower bound for SELECT (РМ5); exact for
  DML via `affected_rows`.
- **Huge resultset tails** — a hole eating the terminator drops the unit
  (resync honesty, РМ4); the accuracy bench quantifies the loss rate vs
  `performance_schema`.
- **`KILL QUERY`** — indistinguishable from an ordinary query by design; the
  CANCEL observation kind is not used for MySQL.
- **X Protocol / port 33060** — out of scope, stated in the README.
- **Auth bodies** — never read (passwords); auth timing is not measured, the
  session starts at the final OK (`on_session`).
