# latkit MySQL demo stack

The MySQL twin of [`../demo`](../demo): a MySQL server, a load generator, the
agent, Prometheus and Grafana with the four dashboards provisioned — one
`docker compose up` away, showing `proto="mysql"` data on every panel.

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
cd latkit/deploy/demo-mysql
docker compose up --build -d
```

First run builds the release image (~2 min) and pulls mysql/prometheus/
grafana. From `git clone` to live panels is about 3–4 minutes on an average
machine — image pulls on a slow network are the one thing that can stretch it.

Then open:

| what | where |
|---|---|
| **Grafana** — anonymous, four dashboards in the *latkit* folder | <http://localhost:3000/dashboards> |
| Prometheus | <http://localhost:19090> |
| raw agent metrics | `curl http://localhost:9752/metrics` |

Give it ~1 minute after `up`: the load seeds its dataset, warms up, Prometheus
scrapes every 5 s. The dashboards carry a **`proto`** variable (top-left) — it
resolves to `mysql` here. Start at **latkit — Overview** (QPS, latency
quantiles, error rate), click a query on **Top queries** to jump into
**Drilldown**, and check **Agent health** for the agent's own vitals (ringbuf
drops, parse errors, series counts).

The load mix is designed so nothing on the dashboards is dead: persistent
point-read/update sessions for volume, `SELECT SLEEP()` calls for a visible p99
tail, and deliberate failures (a missing table, a duplicate key, a syntax
error) for the error rate and SQLSTATE panels (42S02 / 23000 / 42000).

Tear down (removes containers, volumes and the network — nothing survives):

```sh
docker compose --profile tls down -v
```

(`--profile tls` makes `down` also cover the TLS services if you started them;
it is harmless otherwise.)

## TLS profile

```sh
docker compose --profile tls up --build -d
```

adds a **second** MySQL with `--require_secure_transport=ON` (the entrypoint
auto-generates a self-signed cert pair into the datadir on first init — no cert
sidecar) and a load client connecting with `--ssl-mode=REQUIRED`, next to the
plaintext pair. The socket bytes of those sessions are ciphertext; the agent
decrypts them via libssl uprobes (stage 6) and feeds the same pipeline, so the
dashboards show plaintext and TLS traffic side by side. Proof it is really the
TLS path:

```sh
curl -s http://localhost:9752/metrics | grep -E '^latkit_tls_(connections|attached)'
```

`latkit_tls_connections` grows and `latkit_tls_attached{state="ok"} 1` is the
attach gauge. The default `--tls auto` scan set is
`{postgres, mysqld, mariadbd}`, so it finds the mysqld with no extra config
(MYSQL.md М5 / РМ10).

## How it is wired

- **mysql** (8.4) publishes **no** port on purpose: the load reaches it by
  service name over the compose network. A published `localhost` port would
  route through docker-proxy, which `splice()`s the payload past the socket
  layer and defeats the capture (README "Known limitations"). MySQL 8.4 always
  offers TLS, so the plaintext clients pass `--ssl-mode=DISABLED
  --get-server-public-key` (RSA auth over the plaintext link — plan risk 2).
- **load** — [`load/load.sh`](load/load.sh) in a stock mysql image: seeds a
  10k-row `accounts` table, then runs the mix described above forever.
- **latkit** — the release scratch image built from
  [`deploy/docker/Dockerfile`](../docker/Dockerfile) (musl static), configured
  only through `LATKIT_*` env: capture `LATKIT_PORT=3306=mysql` (the port form
  selects the wire protocol — a bare number would default to `pg`), `/metrics`
  on `0.0.0.0:9752` (the bare-metal default is loopback), `--tls auto`,
  first-row histogram on.
- **prometheus** (2.x) — scrapes `latkit:9752` every 5 s, 2 h retention.
- **grafana** (pinned 11.x) — anonymous Viewer; the datasource and the four
  dashboards are provisioned from the postgres demo's
  [`../demo/grafana/provisioning`](../demo/grafana/provisioning) (same
  `prometheus` service name) plus [`../../dashboards`](../../dashboards),
  mounted read-only — the repo directory is the single source, no copies.

## Troubleshooting

- `latkit` exits immediately → `docker compose logs latkit`. The usual cause
  is missing BTF (`/sys/kernel/btf/vmlinux`) or an old kernel; the error
  message states the requirement.
- Dashboards render but show "No data" → confirm the `proto` variable is
  `mysql`, wait for the first scrapes (~30–60 s after `up`), then check
  `docker compose logs load` and the Prometheus target page at
  <http://localhost:19090/targets>.
- Ports 3000/9752/19090 taken → edit the `ports:` mappings in
  `docker-compose.yml`; nothing inside the stack depends on the host port
  numbers.
