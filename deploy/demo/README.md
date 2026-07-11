# Demo stack (draft)

> **Draft (task 7.3).** This exists to make and review the dashboards under live
> load. Task 7.4 turns it into the polished "value in 5 minutes" stack (real
> scratch image, `tls` profile, timing, full requirements). It already gives you
> live Grafana with the four dashboards.

## Requirements

- **Linux host** (real kernel, not Docker Desktop's VM), kernel ≥ 5.15 with BTF
  at `/sys/kernel/btf/vmlinux`.
- Docker + `docker compose`, run with privileges to load BPF.
- The host-built agent binary: **`build/latkit`** (this draft wraps it instead of
  building the static image — much faster to iterate on dashboards).

## Run

```sh
# from the repo root: build the agent once
cmake --build build            # (configure first if needed: cmake -B build)

cd deploy/demo
docker compose up --build      # Ctrl-C to stop
```

Then open:

| what | url |
|---|---|
| **Grafana** (anonymous, dashboards under the *latkit* folder) | http://localhost:3000 |
| Prometheus | http://localhost:19090 |
| raw agent metrics | `curl http://localhost:9752/metrics` |

Give it ~30–60s after start: postgres initialises the pgbench dataset, the load
loop warms up, Prometheus scrapes every 5s.

Tear down (removes volumes, leaves nothing behind):

```sh
docker compose down -v
```

## What's running

- **postgres** (16) — no published port; the load talks to it over the compose
  network so nothing crosses docker-proxy on localhost (which would defeat the
  socket capture — see README "Known limitations").
- **load** — `pgbench` (TPC-B + select-only) for QPS/latency, plus a loop of
  `pg_sleep` (fills the p99 tail) and deliberate errors (`1/0`, a missing table)
  so the error-rate and SQLSTATE panels are alive.
- **latkit** — `privileged`, `pid: host`, capturing server port 5432, serving
  `/metrics` on `0.0.0.0:9752`, with `--first-row-hist` so the drilldown's
  time-to-first-row panel has data.
- **prometheus** — scrapes `latkit:9752` every 5s.
- **grafana** (pinned 11.x) — anonymous Viewer, datasource + the four dashboards
  provisioned from `../../dashboards` (the repo dir is the single source).

## Notes

- If the `grafana/grafana:11.4.0` tag is unavailable, pin any other `11.x`.
- The four dashboards are the files in `../../dashboards`; edit them there (or in
  the Grafana UI, then export back) and re-run `../../dashboards/lint.sh`.
