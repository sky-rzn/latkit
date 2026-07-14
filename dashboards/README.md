# Grafana dashboards

Four provisioned dashboards for latkit (Р42). Fixed `uid`s — cross-links and
provisioning depend on them, so don't change them:

| file | uid | what |
|---|---|---|
| `latkit-overview.json` | `latkit-overview` | QPS, p50/p95/p99, error rate, connections, transaction duration, capture honesty |
| `latkit-queries.json` | `latkit-queries` | top-N normalised queries by p99 / total time / frequency / errors (data link → drilldown) |
| `latkit-drilldown.json` | `latkit-drilldown` | one `$db`/`$user`/`$query` selection: latency, first-row, rows, SQLSTATE |
| `latkit-health.json` | `latkit-health` | every agent self-metric: losses, cardinality, OTLP, TLS, cgroup, `process_*`, pipeline overhead |

## Design rules (enforced by `lint.sh`)

- **Datasource is a variable.** Every panel/target uses the `$datasource`
  template variable (type `datasource`, filtered to `prometheus`), so the same
  JSON works against Prometheus / Mimir / VictoriaMetrics with no edits. No
  hardcoded datasource `uid`s, no `__inputs`/`__requires` "share export"
  placeholders — these are provisioned **as-is**.
- **Quantiles from classic `le` buckets** with `$__rate_interval`, never a
  literal window:
  `histogram_quantile(0.95, sum by (le) (rate(latkit_query_duration_seconds_bucket[$__rate_interval])))`.
- **Bounded cardinality.** Nothing graphs an unbounded set of `query` series.
  Top-N panels are instant tables over `topk($topk, ...)`; the only per-`query`
  timeseries is the single selected `$query`. `$topk` is 5/10/20 (default 10).
- **Data honesty on the overview.** A `capture degraded` annotation fires from
  `latkit_ringbuf_dropped_total` / `latkit_resync_total`, and a dedicated panel
  plots them — when capture is lossy, the operator sees it (Р5/Р27).

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
