# tests/traces/mysql — М0 reference trace corpus (MySQL/MariaDB classic protocol)

Raw `--record` (LKT1) traces of real MySQL/MariaDB sessions, captured with the
stock agent **before any MySQL protocol code exists** — the capture layer is
protocol-independent (`--port 3306`). This corpus is the raw material for the
М2/М3 replay fixtures and the fuzzer seed corpus, and the ground truth
[notes-myproto](../../../docs/notes-myproto.md) was cross-checked against
(MYSQL.md, этап М0).

Each trace is **one client session**: `CONN_OPEN` + data events (both
directions, capture budget 8192 bytes per syscall) + `CONN_CLOSE`. Traces are
little-endian, recorded on x86-64, kernel 7.0.

## Layout

```
my84/       MySQL 8.4.10   (caching_sha2_password, CLIENT_DEPRECATE_EOF on)
my57/       MySQL 5.7.44   (mysql_native_password, pre-DEPRECATE_EOF clients ok)
maria1011/  MariaDB 10.11.18 (5.5.5- version prefix, no DEPRECATE_EOF at all)
```

File name = `<client>-<scenario>.lkt`:

| Client prefix | Implementation | Notes |
|---|---|---|
| `cli-` | `mysql`/`mariadb` CLI from the matching server image (libmysqlclient / libmariadb) | `PREPARE … FROM` is **textual** server-side prepare over COM_QUERY |
| `py-` | mysql-connector-python 9.7, `use_pure=True` | `prepared` = real binary COM_STMT_PREPARE/EXECUTE |
| `jdbc-` | Connector/J 9.3 | `prepared` = `useServerPrepStmts`; `cursor-fetch` = `useCursorFetch` → COM_STMT_FETCH round-trips |

## Scenarios

| Scenario | What it exercises |
|---|---|
| `simple` | COM_QUERY + text resultset (query-attributes header on 8.4 CLI) |
| `prepared` (`-text` for cli) | COM_STMT_PREPARE/EXECUTE/CLOSE, binary rows; CLI variant = textual PREPARE/EXECUTE/DEALLOCATE |
| `multi` | several statements in one COM_QUERY, chained resultsets (`SERVER_MORE_RESULTS_EXISTS`) |
| `load-data` | LOAD DATA LOCAL INFILE: 0xFB request, client data stream, empty-packet EOF |
| `error` | ERR packet (errno 1146, SQLSTATE 42S02) |
| `transaction` | BEGIN/ROLLBACK/COMMIT, `SERVER_STATUS_IN_TRANS` edges |
| `big-resultset` | 65536 rows (~9 MB wire): capture-budget holes over row packets — the РМ4/РМ5 resync material (`trunc` on most row events, tails cut) |
| `tls` | socket layer only: plaintext greeting → short CLIENT_SSL HandshakeResponse → TLS ciphertext (М2 transition fixture) |
| `tls-decrypted` | same load with SSL_read/SSL_write uprobes: ciphertext socket events **plus** `LK_F_DECRYPTED` plaintext events |
| `cursor-fetch` | CURSOR_TYPE_READ_ONLY execute + COM_STMT_FETCH batches (jdbc only) |
| `compress` (`-zstd` on my84) | CLIENT_COMPRESS(_ZSTD): plaintext handshake, then compressed framing — the РМ7 blind zone |

Not every cell of the server×client×scenario cube is recorded — each protocol
dimension is covered by at least one client per server (63 traces total).

## Recording and validating

```
./record.sh              # brings up the servers (docker), records everything
./record.sh my84         # one server; KEEP=1 leaves containers running
```

Requirements: docker, passwordless sudo (BPF), python3, java 17+, curl,
openssl; the agent binary from `build-rel` (or `LATKIT=path`). Clients connect
to the **container IP** — docker-proxy on localhost would double every
connection (see the test-stand notes).

Validate / summarise (replays every record through `lk_replay_file` +
`lk_ev_decode`, fails on any malformed record):

```
cmake --build build --target lkt_info
build/tests/replay/lkt_info tests/traces/mysql/*/*.lkt
```

## Findings recorded while capturing (feed into М2/М5)

- **MySQL 8.x names session OS threads `connection`** (5.7 and MariaDB keep
  `mysqld`/`mariadbd`). With `--tls`, the agent adopts the TLS comm as the
  global kernel comm filter, so `--tls-comm mysqld` silently drops *all* 8.x
  events — socket and uprobe alike (per-thread comm). The `tls-decrypted`
  traces for 8.4 were recorded with `--libssl <container path> --tls-comm
  connection`; the М5 default-scan design must handle process-comm ≠
  thread-comm.
- mysql:8.4 / mysql:5.7 containers link OpenSSL (`libssl.so.3` / `1.0.2k` —
  the latter attaches partial, no `_ex` symbols); mariadb:10.11 (Ubuntu) links
  `libssl.so.3`. All three decrypt fine via uprobes.
- 8.4 CLI over plaintext needs `--get-server-public-key` (caching_sha2 RSA
  exchange — visible in the traces); connector/python and Connector/J do the
  equivalent automatically.
- The MariaDB greeting really does say `5.5.5-10.11.18-MariaDB` — the version
  label must strip the prefix (notes-myproto).
- `t` has 5 rows, `big` 65536 (`REPEAT`-padded ~68-byte rows), LOAD DATA feeds
  1000 tab-separated rows; error scenario targets a missing table.
