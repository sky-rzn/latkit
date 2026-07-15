# latkit with an existing PostgreSQL

Monitoring-only stack — **latkit + Prometheus + Grafana**, pointed at a
PostgreSQL you already run on the host (a website's database, say). Unlike
[`../demo`](../demo), it brings **no** postgres and **no** load generator: the
agent captures the real database. Grafana and Prometheus reuse the demo's
provisioning and the four dashboards from [`../../dashboards`](../../dashboards).

## Requirements

- Linux kernel **≥ 5.15 with BTF** (`/sys/kernel/btf/vmlinux`). The agent checks
  at startup and says exactly what is missing.
- Docker + compose plugin.
- The app must reach postgres over **TCP**. latkit captures `tcp_sendmsg`/
  `tcp_recvmsg` (kernel-wide) — **unix-socket** connections
  (`/var/run/postgresql/.s.PGSQL.5432`) are invisible. Loopback TCP, IPv4 or
  IPv6 (`127.0.0.1` / `[::1]`), is fine. Quick check:

  ```sh
  sudo ss -tnp 'sport = :5432 or dport = :5432'   # TCP sessions to the DB?
  sudo ss -xp | grep -i pgsql                     # ...or a unix socket?
  ```

  If the app is on a unix socket, point it at `host=127.0.0.1` first.

## Run

```sh
cd deploy/existing-postgres
GF_ADMIN_PASSWORD='choose-one' docker compose up --build -d
```

First build of the agent image is ~2 min. Grafana and Prometheus bind to
**127.0.0.1 only** — `/metrics` and this Grafana have no auth; reach them via an
SSH tunnel, never publish them:

```sh
ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 your-vps
```

Then Grafana at <http://localhost:3000> (`admin` / your `GF_ADMIN_PASSWORD`) →
left nav **Dashboards** (click the word, not the arrow) → folder **latkit**.

## Plaintext vs TLS — the one decision that matters

latkit parses the PostgreSQL wire protocol off the socket. If the DB connection
is **TLS**, the socket bytes are ciphertext and latkit needs to read the
plaintext from libssl via uprobes instead. Two non-obvious traps live here:

- **`sslmode=prefer` is the libpq default.** If the server has `ssl=on`, clients
  — including `psql -h ... ` with no flags, and most app pools — silently
  negotiate TLS. So a connection you *think* is plaintext often is not. Confirm:

  ```sh
  # queries_total appears immediately when the connection is plaintext
  PGSSLMODE=disable psql -h 127.0.0.1 -p 5432 -U <user> -d <db> -c 'select 1'
  ```

- **A TLS connection with no working uprobe is dropped silently** — you see
  `latkit_events_total` climbing but `latkit_queries_total` never created, and
  `parse_errors`/`unknown_msgs`/`resync` all flat (it is a "TLS, drop", not a
  parse error). The agent log says `conn=… TLS detected, switching to decrypted
  channel` and `TLS uprobes: no libssl found …`.

### Option A — plaintext (simplest for a same-host DB)

TLS on a loopback connection buys nothing (traffic never leaves the host).
Set `sslmode=disable` on the app's connection (or `PGSSLMODE=disable` in its
environment) and **restart the app** so its pool reconnects unencrypted. Then
drop the TLS bits from `docker-compose.yml`: `LATKIT_TLS: "off"`,
`cap_add: [BPF, PERFMON]`, remove the `security_opt` block.

### Option B — capture TLS (keep encryption)

`LATKIT_TLS: auto` (the default here) scans `/proc` for the postgres backends'
libssl and attaches `SSL_read`/`SSL_write` uprobes. In a container this needs:

- `pid: host` (scan host `/proc`);
- `cap_add: [BPF, PERFMON, SYS_PTRACE, SYS_ADMIN]` (`SYS_PTRACE` for the
  `/proc/<pid>/root` reads, `SYS_ADMIN` because the kernel demands full
  `CAP_SYS_ADMIN` for uprobes);
- **`security_opt: [apparmor=unconfined]`** — the `docker-default` AppArmor
  profile mediates the cross-process `/proc/<pid>/root` read and makes the scan
  come back empty **even with `CAP_SYS_PTRACE`**. This was the subtle one: on a
  test VPS `privileged` worked and the four-cap set did not; the same caps plus
  `apparmor=unconfined` fixed it (seccomp stays on). See
  [docs/deploy.md](../../docs/deploy.md) "Minimal capabilities".

`postgres` must link libssl **dynamically** (Debian/Ubuntu packages do —
`libssl.so.3` shows in `/proc/<pid>/maps`). A statically-linked OpenSSL has no
`libssl.so` mapping and the scan can't find it; point `LATKIT_LIBSSL` at a path
instead.

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
> `CapabilityBoundingSet`. Keep Prometheus + Grafana in this compose and point
> Prometheus at the host agent (`LATKIT_PROM_LISTEN=0.0.0.0:9752`, scrape
> `host-gateway:9752`).

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
     socket, or `pid: host` missing).

2. **Prometheus scraping?** `http://localhost:9090/targets` — job `latkit` UP.
   (busybox `wget` inside the prometheus container can't resolve `latkit:9752`;
   query Prometheus itself or the agent's container IP instead.)

3. **Grafana?** Datasource *Test* green; time range **Last 15 minutes**; check
   the host clock (`timedatectl`). Dashboards live in the **latkit** folder,
   reached by clicking **Dashboards** in the nav (not just expanding it).

## Ports

Grafana `127.0.0.1:3000`, Prometheus `127.0.0.1:9090`; the agent's `9752` is not
published (Prometheus scrapes it over the compose network). Edit the `ports:`
mappings if any clash.
