# latkit with an existing MySQL / MariaDB

Monitoring-only stack — **latkit + Prometheus + Grafana**, pointed at a
MySQL or MariaDB you already run on the host. Unlike
[`../demo-mysql`](../demo-mysql), it brings **no** server and **no** load
generator: the agent captures the real database. Grafana and Prometheus reuse
the postgres demo's provisioning and the four dashboards from
[`../../dashboards`](../../dashboards); the `$proto` variable selects `mysql`.

## Requirements

- Linux kernel **≥ 5.15 with BTF** (`/sys/kernel/btf/vmlinux`). The agent checks
  at startup and says exactly what is missing.
- Docker + compose plugin.
- The app must reach mysql over **TCP**. latkit captures `tcp_sendmsg`/
  `tcp_recvmsg` (kernel-wide) — **unix-socket** connections
  (`/var/run/mysqld/mysqld.sock`) are invisible. Loopback TCP, IPv4 or IPv6
  (`127.0.0.1` / `[::1]`), is fine. Quick check:

  ```sh
  sudo ss -tnp 'sport = :3306 or dport = :3306'   # TCP sessions to the DB?
  sudo ss -xp | grep -i mysqld                     # ...or a unix socket?
  ```

  The `mysql` CLI defaults to the unix socket for `-h localhost`; use
  `-h 127.0.0.1` (or `--protocol=TCP`) to force TCP.

## Run

```sh
cd deploy/existing-mysql
GF_ADMIN_PASSWORD='choose-one' docker compose up --build -d
```

First build of the agent image is ~2 min. Grafana and Prometheus bind to
**127.0.0.1 only** — `/metrics` and this Grafana have no auth; reach them via an
SSH tunnel, never publish them:

```sh
ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 your-vps
```

Then Grafana at <http://localhost:3000> (`admin` / your `GF_ADMIN_PASSWORD`) →
left nav **Dashboards** (click the word, not the arrow) → folder **latkit**;
set the `proto` variable to `mysql`.

## Plaintext vs TLS — the one decision that matters

latkit parses the MySQL wire protocol off the socket. If the DB connection is
**TLS**, the socket bytes are ciphertext and latkit needs to read the plaintext
from libssl via uprobes instead. Two traps live here:

- **MySQL 8.x always offers TLS and clients prefer it.** The 8.x/8.4 CLI and
  most connectors negotiate TLS whenever the server supports it (which it does
  by default, with an auto-generated cert). So a connection you *think* is
  plaintext often is not. Confirm plaintext by forcing it off:

  ```sh
  # queries_total appears immediately when the connection is plaintext
  mysql --ssl-mode=DISABLED --get-server-public-key -h 127.0.0.1 -u<user> -p <db> -e 'SELECT 1'
  ```

- **A TLS connection with no working uprobe is dropped silently** — you see
  `latkit_events_total` climbing but `latkit_queries_total` never created, and
  `parse_errors`/`unknown_msgs`/`resync` all flat (it is a "TLS, drop", not a
  parse error). The agent log says `conn=… TLS detected, switching to decrypted
  channel` and `TLS uprobes: no libssl found …`.

### Option A — plaintext (simplest for a same-host DB)

TLS on a loopback connection buys nothing (traffic never leaves the host). Set
`--ssl-mode=DISABLED` (libmysqlclient) / `sslmode=disable` (Go, JDBC's
`useSSL=false`) on the app's connection and **restart the app** so its pool
reconnects unencrypted. Then drop the TLS bits from `docker-compose.yml`:
`LATKIT_TLS: "off"`, `cap_add: [BPF, PERFMON]`, remove the `security_opt` block.

### Option B — capture TLS (keep encryption)

`LATKIT_TLS: auto` (the default here) scans `/proc` for the DB server's libssl
and attaches `SSL_read`/`SSL_write` uprobes. The default scan set is
`{postgres, mysqld, mariadbd}`, so mysqld is found with no extra config
(MYSQL.md М5 / РМ10). In a container this needs:

- `pid: host` (scan host `/proc`);
- `cap_add: [BPF, PERFMON, SYS_PTRACE, SYS_ADMIN]` (`SYS_PTRACE` for the
  `/proc/<pid>/root` reads, `SYS_ADMIN` because the kernel demands full
  `CAP_SYS_ADMIN` for uprobes);
- **`security_opt: [apparmor=unconfined]`** — the `docker-default` AppArmor
  profile mediates the cross-process `/proc/<pid>/root` read and makes the scan
  come back empty **even with `CAP_SYS_PTRACE`** (seccomp stays on). See
  [docs/deploy.md](../../docs/deploy.md) "Minimal capabilities".

`mysqld` must link libssl **dynamically** (the official Debian/Oracle packages
and the `mysql:8.4` image do — `libssl.so.3` shows in `/proc/<pid>/maps`).

> **MariaDB caveat.** MariaDB builds that link a bundled **wolfSSL** or
> **GnuTLS** instead of OpenSSL have no `libssl.so` for the uprobe to attach to,
> and TLS sessions are then *detected and dropped-and-counted*, not decrypted
> (`latkit_tls_attached` stays at 0 / `state!="ok"`). For those, terminate TLS
> in front of MariaDB, or capture plaintext on a loopback hop. Distro MariaDB
> that dynamically links system OpenSSL works like MySQL.

Verify TLS capture is live:

```sh
LKIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker compose ps -q latkit))
docker compose logs latkit | grep -i 'TLS uprobes'   # "attached on … (12 probes)"
curl -s "http://$LKIP:9752/metrics" | grep -E '^latkit_tls_(attached|correlation_misses_total)'
# want: tls_attached{state="ok"} 1  and correlation_misses_total 0
```

> **For a customer / production TLS install, prefer running the agent on the
> host as a systemd unit** ([`../systemd/latkit.service`](../systemd/latkit.service)):
> `/proc` is native, there is no container mount-namespace or AppArmor barrier,
> the libssl scan just works, and privileges are bounded by
> `CapabilityBoundingSet`. Set `LATKIT_PORT=3306=mysql` and
> `LATKIT_TLS_COMM=mysqld` (or `mariadbd`) in `/etc/latkit/latkit.env`.

## A trap unique to MySQL 8.x: the `connection` thread comm

Do **not** set `LATKIT_COMM=mysqld`. That is the *kernel* capture filter, which
matches on the per-**thread** comm — and MySQL 8.x renames its per-session
threads to `connection`, not `mysqld` (5.7 and MariaDB do not). With
`LATKIT_COMM=mysqld` on an 8.x server every captured event is silently dropped.
The `LATKIT_PORT=3306` filter already scopes the capture to the DB; leave the
comm filter unset. (The TLS `/proc` scan, `LATKIT_TLS_COMM`, is a separate knob
that matches the *process* comm `mysqld` and is fine.)

## Persistent pools attach mid-stream

The agent registers a connection lazily on its first captured send/recv, so a
long-lived pool connection opened **before** the agent (or before a TLS uprobe
attached) is joined mid-conversation: you may see one `resync`, or
`decrypted event before TLS handshake` for that connection, and it stays quiet.
**Restart the app after latkit is up** so the pool reconnects under observation
— every query then parses from a clean baseline.

## Troubleshooting ladder

Isolate top-down; each step says which layer is at fault.

1. **Agent capturing?** Read the agent's own counters (Prometheus already has
   them, avoiding scrape/DNS quirks):

   ```sh
   for q in latkit_connections_active latkit_events_total latkit_queries_total \
            latkit_tls_attached latkit_tls_connections; do
     echo "== $q =="; curl -s "http://localhost:9090/api/v1/query?query=$q" | sed 's/.*"result"://'; echo
   done
   ```

   - `connections_active > 0` comes from the `inet_sock_set_state` tracepoint;
     `events_total`/`queries_total` come from the `tcp_*` data path. Their
     divergence localises the break.
   - `events_total` grows but `queries_total` empty, error counters flat →
     **TLS with no uprobe** (Option B), or the app is on a unix socket.
   - all flat → agent not seeing the port at all (wrong `LATKIT_PORT`, unix
     socket, `LATKIT_COMM=mysqld` on 8.x, or `pid: host` missing).

2. **Prometheus scraping?** `http://localhost:9090/targets` — job `latkit` UP.

3. **Grafana?** Datasource *Test* green; time range **Last 15 minutes**; the
   `proto` variable set to `mysql`; check the host clock (`timedatectl`).

## Ports

Grafana `127.0.0.1:3000`, Prometheus `127.0.0.1:9090`; the agent's `9752` is not
published (Prometheus scrapes it over the compose network). Edit the `ports:`
mappings if any clash.
