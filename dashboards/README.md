# Grafana dashboards

Seven provisioned dashboards for latkit (Р42, РH9, РS7, РR11). Fixed `uid`s —
cross-links and provisioning depend on them, so don't change them:

| file | uid | what |
|---|---|---|
| `latkit-overview.json` | `latkit-overview` | QPS, p50/p95/p99, error rate, connections, transaction duration, capture honesty |
| `latkit-queries.json` | `latkit-queries` | top-N normalised queries by p99 / total time / frequency / errors (data link → drilldown) |
| `latkit-drilldown.json` | `latkit-drilldown` | one `$db`/`$user`/`$query` selection: latency, first-row, rows, SQLSTATE |
| `latkit-health.json` | `latkit-health` | every agent self-metric: losses, cardinality, OTLP, TLS, cgroup, `process_*`, pipeline overhead |
| `latkit-http.json` | `latkit-http` | HTTP ports (`--port 8080=http`): RPS and duration/TTFB by route, status classes, sizes and throughput, blind zones, `route="other"` share |
| `latkit-s3.json` | `latkit-s3` | S3 ports (`--port 9000=s3`): operations/s and duration/TTFB by operation, top buckets and access keys, errors by S3 code, throughput, object sizes, and the traffic that is not an S3 API |
| `latkit-redis.json` | `latkit-redis` | Redis ports (`--port 6379=redis`): commands/s and duration by command, `PING` on its own, pipeline depth, database and ACL user, symbolic errors, cluster redirects, blocking waits, reply sizes, pushes |

## Design rules (enforced by `lint.sh`)

- **Datasource is a variable.** Every panel/target uses the `$datasource`
  template variable (type `datasource`, filtered to `prometheus`), so the same
  JSON works against Prometheus / Mimir / VictoriaMetrics with no edits. No
  hardcoded datasource `uid`s, no `__inputs`/`__requires` "share export"
  placeholders — these are provisioned **as-is**.
- **Quantiles from classic `le` buckets** with `$__rate_interval`, never a
  literal window:
  `histogram_quantile(0.95, sum by (le) (rate(latkit_query_duration_seconds_bucket[$__rate_interval])))`.
- **Bounded cardinality.** Nothing graphs an unbounded set of `query` — or, on
  the HTTP dashboard, `route`, or on the Redis one, `cmd` — series. Top-N panels
  are instant tables over `topk($topk, ...)`; the only per-`query` timeseries is
  the single selected `$query`. `$topk` is 5/10/20 (default 10). `cmd` is the one
  of the three that is bounded by construction (a closed table, РR4), and it is
  still graphed through `topk`: 250 series is not a cardinality incident, it is
  an unreadable panel.
- **Data honesty on the overview.** A `capture degraded` annotation fires from
  `latkit_ringbuf_dropped_total` / `latkit_resync_total`, and a dedicated panel
  plots them — when capture is lossy, the operator sees it (Р5/Р27).

The HTTP dashboard's headline row carries the two honesty numbers of the track:
the 5xx share, and the share of requests reported as `route="other"` — the
signal for whether route templating (РH7) is working on *your* API. A large or
growing `other` share means the heuristic is losing: raise `--top-queries`, or
name the routes explicitly with `--http-routes`.

The S3 dashboard has the same headline slot and it means something else there.
`op` comes from a closed table (РS2), so its cardinality is bounded whatever the
traffic does and `op="other"` is not a cardinality warning — it is an **ageing**
one: the S3 API grows, and a rising `other` share says the table in
`docs/notes-s3proto.md` has fallen behind the server. Its last panel is the
counterpart honesty number: `latkit_s3_internal_requests_total` (MinIO's own
`/minio/…` surface, counted and in no family that says "requests") beside the
blind connections, because on a distributed pool most of the traffic on port
9000 is the cluster talking to itself and a dashboard that hid that would be
lying about the port.

The Redis dashboard is the one that splits its latency into three panels rather
than one, and that is the whole design: `latkit_redis_command_duration_seconds`
is work, `latkit_redis_blocking_seconds` is the timeout a client chose (РR10),
and a `+QUEUED` inside a `MULTI` has no duration at all (РR9) — one histogram
holding all three would have a p99 of "whatever the longest `BLPOP` was". `PING`
gets a panel to itself for the opposite reason (РR15): it does no work, so on a
single-threaded server its p99 *is* the event loop's queueing delay, and folding
it into the general rate would hide the best signal on the page. The last row
carries the honesty numbers: pushes that closed no unit (РR8), the dropped units
of a capture hole inside an array (risk 1 of the plan), the deliberately ignored
replication and `MONITOR` connections (РR14) — and a reminder in the panel text
that a **unix socket** carries no traffic past this agent at all.

Note: the drilldown's *time to first row* panel needs the agent's
`--first-row-hist` (`LATKIT_FIRST_ROW_HIST=1`); without it that histogram family
is not emitted and the panel reads *No data*. The demo stack enables it.

## Provisioning

Grafana is pointed at this directory read-only with `foldersFromFilesStructure`
(see `deploy/demo/grafana/`). **This directory is the single source** — no
copies. Grafana is pinned to a major version (11.x) in the demo; the JSON
`schemaVersion` is whatever that version's export produces.

## Editing / re-export

Edit in the Grafana UI on the demo stack, then **Export → Save to file** and
overwrite the file here (keep `Export for sharing externally` **off** so no
`__inputs` block is added). Then run the lint before committing:

```sh
./dashboards/lint.sh    # needs jq
```

## `lint.sh`

Runs in CI (job `dashboards-lint`, jq only — no build, no BPF). It checks JSON
validity, that `.uid` matches the filename, the `$datasource`/`$__rate_interval`
rules and the cardinality guard above, and — the anti-rot check — that **every
metric named in any PromQL expression exists in the agent's metric
nomenclature**. That nomenclature is the set of `latkit_*` / `process_*` metric
name string literals in `src/`, so renaming a metric in the code turns this red
until the dashboards are re-exported. Verify it bites:

```sh
sed -i 's/latkit_query_duration_seconds/latkit_query_duration_RENAMED/' src/metrics/registry.c
./dashboards/lint.sh   # -> FAIL: unknown metric ...
git checkout src/metrics/registry.c
```
