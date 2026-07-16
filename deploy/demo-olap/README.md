# latkit demo-olap stack

The same one-command stack as [`../demo`](../demo) — PostgreSQL, a load generator,
the agent, Prometheus and Grafana with the dashboards provisioned — but the load
is a **complex analytical (OLAP) workload** instead of pgbench. It shows what
latkit reports when the traffic is heavy, multi-row and slow rather than lots of
tiny transactions.

The load builds a small e-commerce star schema (categories tree, 50k customers,
5k products, 300k orders, ~900k order lines) and then runs nine genuinely
non-trivial queries in a loop:

| # | shape | features |
|---|---|---|
| Q1 | revenue rolled up to root category, monthly | **recursive CTE** + window running total |
| Q2 | customer spend quintiles | `ntile()` + `percentile_cont()` ordered-set aggregates |
| Q3 | country × segment crosstab with subtotals | **`GROUPING SETS`** + `COUNT(DISTINCT)` |
| Q4 | top-3 products per category | correlated **`LATERAL`** with `ORDER BY`/`LIMIT` |
| Q5 | customers above their country average | window `avg() OVER (PARTITION BY …)` |
| Q6 | category tree with depth & breadcrumb path | **recursive CTE** building a text path |
| Q7 | avg gap between consecutive orders | `lag()` window + `FILTER` aggregate |
| Q8 | orders/revenue by status × segment | **`CUBE`** |
| Q9 | monthly top-10 categories, ranked, with MoM delta | two chained CTEs + `rank()` + `lag()` — the p99 query |

Each query uses `random()` for its runtime cutoffs, so the SQL *text* is identical
on every execution — latkit normalizes it to **one stable row per query** on the
*Top queries* panel while the rows actually scanned vary. A small side loop adds a
`pg_sleep` (guaranteed tail) and three deliberate failures for the error-rate and
SQLSTATE panels (`22012` / `42P01` / `23505`).

## Requirements

Identical to the base demo: a **Linux host**, kernel **≥ 5.15** with BTF at
`/sys/kernel/btf/vmlinux`, and Docker with the compose plugin. See
[`../demo/README.md`](../demo/README.md) for the details and the minimal
capability set.

## Run

```sh
cd latkit/deploy/demo-olap
docker compose up --build -d
```

First run builds the release image (~2 min) and pulls postgres/prometheus/
grafana. Then give it a bit longer than the base demo — the dataset build
(schema.sql) takes a few seconds and the analytical queries are slow by design.

Then open:

| what | where |
|---|---|
| **Grafana** — anonymous, dashboards in the *latkit* folder | <http://localhost:3001/dashboards> |
| Prometheus | <http://localhost:19091> |
| raw agent metrics | `curl http://localhost:9752/metrics` |

> Ports are shifted (Grafana **3001**, Prometheus **19091**) so this stack can run
> side by side with the base demo (3000 / 19090). The agent metrics port is 9752
> in both — run only one stack at a time if you keep the default, or edit the
> `latkit` `ports:` mapping.

Start at **latkit — Overview**, then click Q9 (the heaviest query) on
**Top queries** to jump into **Drilldown** and see its latency distribution and
time-to-first-row. **Agent health** shows the agent's own vitals under the load.

Follow the per-query client-side timings while it runs:

```sh
docker compose logs -f load
```

Tear down (removes containers, the volume and the network):

```sh
docker compose down -v
```

## How it differs from `../demo`

- **load** — [`load/load.sh`](load/load.sh) builds [`load/schema.sql`](load/schema.sql)
  once, then runs [`load/queries.sql`](load/queries.sql) in `WORKERS` (default 3)
  parallel sessions. No pgbench.
- **postgres** — same image, but `shared_buffers=256MB` / `work_mem=64MB` /
  `max_parallel_workers_per_gather=2` so the heavy queries hash and sort in RAM.
- **no TLS profile** — TLS decryption is orthogonal and already covered by the
  base demo's `--profile tls`; this stack stays `ssl=off` to keep the focus on the
  query workload.
- everything else (the agent config, Prometheus, the provisioned dashboards from
  `../../dashboards`) is identical.
