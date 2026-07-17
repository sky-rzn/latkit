# latkit demo-blindspots stack

The same one-command stack as [`../demo`](../demo) — PostgreSQL, a load generator,
the agent, Prometheus and Grafana with the dashboards provisioned — but built to
make one point: **the things the usual in-database tools miss, and latkit doesn't.**

The load drives four *problematic query patterns* against a small multi-tenant
SaaS database. Each is a real production antipattern, and each is a blind spot of
`pg_stat_statements` — the tool you'd normally reach for. This postgres has
`pg_stat_statements` **preloaded**, so you can query it side by side with latkit's
Grafana and see the gap yourself.

Every claim below was checked on `postgres:17-alpine` with the default config this
stack ships.

## The four blind spots

| # | Problem pattern | What `pg_stat_statements` shows | What latkit shows |
|---|---|---|---|
| 1 | **Queries that always fail** — a runaway report killed by `statement_timeout`, a duplicate API key, a query to a table dropped in a migration, unvalidated input, an orphaned write | **Nothing.** A statement that errors or is canceled is never recorded — the calls that hurt most are invisible | Every one, on the **error-rate** and **SQLSTATE** panels: `57014`, `23505`, `42P01`, `22P02`, `23503`, attributed to db/user |
| 2 | **`IN (…)` lists and multi-row `VALUES` of varying length** — the classic ORM / query-builder shape | **One row per length.** `IN ($1,$2)` and `IN ($1,$2,$3)` are different queries; with a bounded table it churns and **evicts real queries** | **One** stable, normalised row: `in ( ? )` and `values ( ? )` — cardinality bounded by construction |
| 3 | **An un-`LIMIT`ed export** returning ~300k rows | `rows` and `mean_exec_time`, *if* you had it installed before the incident | The true **rows/query**, per-query **wire latency**, and **time-to-first-row** — measured on the socket, with nothing running inside postgres |
| 4 | **The tool wasn't there yet** — `pg_stat_statements` needs `shared_preload_libraries` and a **restart**; a `pg_stat_statements_reset()` wipes history | You can't add it to a running database mid-incident, and any reset loses the past | latkit **attached to the already-running server**; history lives in Prometheus, independent of any in-DB reset |

## Requirements

Identical to the base demo: a **Linux host**, kernel **≥ 5.15** with BTF at
`/sys/kernel/btf/vmlinux`, and Docker with the compose plugin. See
[`../demo/README.md`](../demo/README.md) for details and the minimal capability
set.

## Run

```sh
cd latkit/deploy/demo-blindspots
docker compose up --build -d
```

First run builds the release image (~2 min) and pulls postgres/prometheus/
grafana. The dataset build (`schema.sql`, 1.5M events) takes a few seconds.

Then open:

| what | where |
|---|---|
| **Grafana** — anonymous, dashboards in the *latkit* folder | <http://localhost:3002/dashboards> |
| Prometheus | <http://localhost:19092> |
| raw agent metrics | `curl http://localhost:9752/metrics` |

> Ports are shifted (Grafana **3002**, Prometheus **19092**) so this stack can run
> alongside `../demo` (3000 / 19090) and `../demo-olap` (3001 / 19091). The agent
> metrics port is 9752 in all three and latkit's capture filter matches server
> port 5432 **kernel-wide** — so run only **one** of the three stacks at a time,
> or the agents will double-count each other's postgres.

## See the gap yourself

Give it ~1 minute after `up` for the first scrapes. Open **latkit — Overview** and
keep it next to a shell. Each block below is a blind spot from the table.

### 1 · Failed queries — invisible to pg_stat_statements

The error loop fires five always-failing statements. In Grafana they show up
immediately on the **error rate** panel and the **SQLSTATE** breakdown
(`latkit_query_errors_total`). Now ask `pg_stat_statements` for them:

```sh
docker compose exec postgres psql -U latkit -c \
  "select calls, query from pg_stat_statements
   where query ilike '%pg_sleep%' or query ilike '%audit_log%'
      or query ilike '%999999%';"
```

→ **0 rows.** The runaway report, the missing table, the orphaned write — none of
them were ever recorded. latkit, reading the wire, counted every one:

```sh
curl -s http://localhost:9752/metrics | grep '^latkit_query_errors_total'
```

```
latkit_query_errors_total{sqlstate="22P02",db="latkit",user="latkit"} …   invalid input
latkit_query_errors_total{sqlstate="23503",db="latkit",user="latkit"} …   FK violation
latkit_query_errors_total{sqlstate="23505",db="latkit",user="latkit"} …   duplicate key
latkit_query_errors_total{sqlstate="42P01",db="latkit",user="latkit"} …   undefined table
latkit_query_errors_total{sqlstate="57014",db="latkit",user="latkit"} …   statement canceled
```

### 2 · IN-list / VALUES cardinality — one row, not hundreds

The cardinality loop sends `WHERE user_id IN (…)` and `INSERT … VALUES (…)` with a
different number of elements every time. Count how many rows each produced:

```sh
docker compose exec postgres psql -U latkit -c \
  "select count(*) as distinct_entries
   from pg_stat_statements where query like 'select user_id, email from users where user_id in%';"

docker compose exec postgres psql -U latkit -c \
  "select dealloc as evictions_so_far from pg_stat_statements_info;"
```

→ **dozens of distinct entries** for what is logically one query, and a climbing
`dealloc` — `pg_stat_statements` is throwing away *real* queries to make room for
these near-duplicates (that's why `max=100` here — the same thing happens at the
default 5000, just later). On latkit's **Top queries** panel the same traffic is
**one** row each: `select user_id , email from users where user_id in ( ? )` and
`insert into ingest ( a , b ) values ( ? )`. Literals, `IN` lists and multi-row
`VALUES` all collapse to `?` — cardinality is bounded by construction, not by luck.

> PostgreSQL 18 adds an opt-in `query_id_squash_values` for `IN` lists, but it is
> off by default and does not cover multi-row `VALUES` arity or dynamically-built
> SQL. latkit's normalisation covers all of them, on every server version.

### 3 · The big export — rows and time-to-first-row from the wire

The bigresult loop runs an un-`LIMIT`ed join returning ~300k rows. Click that
query on **Top queries** to open **Drilldown**: `latkit_query_rows_total` shows the
real result size and the **time to first row** panel shows how long the client
waited before the first byte of data — the server-side truth of what that export
costs, measured on the socket with nothing installed in postgres.

### 4 · Zero-touch, and history that survives a reset

`pg_stat_statements` only exists here because we set `shared_preload_libraries`
and let postgres start with it — on a database you don't control, mid-incident,
you can't. And a routine `pg_stat_statements_reset()` erases the past:

```sh
docker compose exec postgres psql -U latkit -c "select pg_stat_statements_reset();"
```

latkit never touched postgres, and its Prometheus history is untouched by that
reset — the graphs keep going.

## How it is wired

- **postgres** (17-alpine) publishes **no** port: the load reaches it by service
  name over the compose network, so nothing crosses docker-proxy on localhost
  (which would `splice()` the payload past the socket layer). It runs with
  `pg_stat_statements` preloaded (`track=all`, `max=100`) purely so the contrast
  commands above work — that's the tool latkit is being compared against.
- **load** — [`load/load.sh`](load/load.sh) builds [`load/schema.sql`](load/schema.sql)
  once, then runs the four blind-spot loops (baseline + errors + cardinality +
  bigresult) forever.
- **latkit** — the release scratch image built from
  [`deploy/docker/Dockerfile`](../docker/Dockerfile) (musl static), configured
  only through `LATKIT_*` env: capture port 5432, `/metrics` on `0.0.0.0:9752`,
  `--tls auto`, first-row histogram on.
- **prometheus** (2.x) — scrapes `latkit:9752` every 5 s, 2 h retention.
- **grafana** (pinned 11.x) — anonymous Viewer; the datasource and the four
  dashboards are provisioned from [`../../dashboards`](../../dashboards), mounted
  read-only.

The admin `psql` commands run via `docker compose exec postgres` over the unix
socket; latkit watches **TCP** 5432, so those comparison queries never show up on
its dashboards — what you see there is only the app load.

## Contrast in one shot

```sh
# latkit: every error, by SQLSTATE
curl -s http://localhost:9752/metrics | grep '^latkit_query_errors_total'

# pg_stat_statements: none of those errors, plus cardinality churn
docker compose exec postgres psql -U latkit -c \
  "select (select count(*) from pg_stat_statements)              as live_entries,
          (select dealloc  from pg_stat_statements_info)         as evicted,
          (select count(*) from pg_stat_statements
             where query like '%where user_id in%')              as in_list_dupes;"
```

Tear down (removes containers, the volume and the network):

```sh
docker compose down -v
```

## How it differs from `../demo` and `../demo-olap`

- **`../demo`** — pgbench: shows latkit *working* (QPS, latency, a p99 tail, a few
  errors). The "does it run" demo.
- **`../demo-olap`** — heavy analytics: shows latkit under *complex* multi-row,
  slow queries. The "how does it behave under load" demo.
- **this one** — shows *why* you'd pick latkit over the in-database tools: the
  queries those tools structurally can't report. The "what does it catch that the
  others miss" demo.
