# latkit demo stack

Everything needed to *see* latkit work: a PostgreSQL server, a load generator,
the agent itself, Prometheus and Grafana with the four dashboards provisioned —
one `docker compose up` away.

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
cd latkit/deploy/demo
docker compose up --build -d
```

First run builds the release image (~2 min) and pulls postgres/prometheus/
grafana. From `git clone` to live panels is about 3–4 minutes on an average
machine — image pulls on a slow network are the one thing that can stretch it.

Then open:

| what | where |
|---|---|
| **Grafana** — anonymous, four dashboards in the *latkit* folder | <http://localhost:3000/dashboards> |
| Prometheus | <http://localhost:19090> |
| raw agent metrics | `curl http://localhost:9752/metrics` |

Give it ~1 minute after `up`: pgbench initialises its dataset, the load warms
up, Prometheus scrapes every 5 s. Start at **latkit — Overview** (QPS,
latency quantiles, error rate), click a query on **Top queries** to jump into
**Drilldown**, and check **Agent health** for the agent's own vitals
(ringbuf drops, parse errors, series counts).

The load mix is designed so nothing on the dashboards is dead: pgbench TPC-B +
select-only for volume, `pg_sleep` calls for a visible p99 tail, and deliberate
failures (division by zero, a missing table, a unique violation) for the error
rate and SQLSTATE panels.

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

adds a **second** PostgreSQL with `ssl=on` (self-signed cert generated on
startup) and a load client connecting with `sslmode=require`, next to the
plaintext pair. The socket bytes of those sessions are ciphertext; the agent
decrypts them via libssl uprobes (stage 6) and feeds the same pipeline, so the
dashboards show plaintext and TLS traffic side by side. Proof it is really the
TLS path:

```sh
curl -s http://localhost:9752/metrics | grep -E '^latkit_tls_(connections|attached)'
```

`latkit_tls_connections` grows and `latkit_tls_attached{state="ok"} 1` is the
attach gauge. The `pg_sleep`/error spice queries run against the TLS server
too, so the SQLSTATE panels get contributions from both.

## How it is wired

- **postgres** (17-alpine) publishes **no** port on purpose: the load reaches
  it by service name over the compose network. A published `localhost` port
  would route through docker-proxy, which `splice()`s the payload past the
  socket layer and defeats the capture (README "Known limitations").
- **load** — [`load/load.sh`](load/load.sh) in a stock postgres image:
  initialises pgbench (scale 10), then runs the mix described above forever.
- **latkit** — the release scratch image built from
  [`deploy/docker/Dockerfile`](../docker/Dockerfile) (musl static, Р45/Р46),
  configured only through `LATKIT_*` env: capture port 5432, `/metrics` on
  `0.0.0.0:9752` (the bare-metal default is loopback), `--tls auto`,
  first-row histogram on.
- **prometheus** (2.x) — scrapes `latkit:9752` every 5 s, 2 h retention.
- **grafana** (pinned 11.x) — anonymous Viewer; the datasource and the four
  dashboards are provisioned from [`../../dashboards`](../../dashboards),
  mounted read-only — the repo directory is the single source, no copies.

## Troubleshooting

- `latkit` exits immediately → `docker compose logs latkit`. The usual cause
  is missing BTF (`/sys/kernel/btf/vmlinux`) or an old kernel; the error
  message states the requirement.
- Dashboards render but show "No data" → wait for the first scrapes
  (~30–60 s after `up`), then check `docker compose logs load` (pgbench init
  progress) and the Prometheus target page at
  <http://localhost:19090/targets>.
- Ports 3000/9752/19090 taken → edit the `ports:` mappings in
  `docker-compose.yml`; nothing inside the stack depends on the host port
  numbers.
