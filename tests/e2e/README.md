# e2e stand (milestone M3)

A `docker compose` stack that exercises both stage-5 export paths end to end:
**postgres + pgbench + latkit + prometheus + otel-collector**. It backs the M3
exit criteria (STAGE5.md task 5.4): the stage-4 metric nomenclature is reachable
from outside the agent by *both* Prometheus scrape and OTLP push, and the agent
stays honest under export failure.

```
pgbench ──sql──▶ postgres          (compose bridge; NO localhost/docker-proxy)
                    ▲
   latkit ─────────┘  (BPF capture, kernel-wide)
     ├── /metrics  ◀── prometheus            (pull)
     └── OTLP/HTTP ──▶ otel-collector ──▶ prometheus (push, re-exported :8889)
```

## Run

```sh
./verify.sh          # build the agent, bring the stand up, assert M3, tear down
KEEP=1 ./verify.sh   # same, but leave the stand running to poke at it
```

`verify.sh` builds `build/latkit` on the host first (the image just wraps that
binary — the BPF skeleton toolchain is not reproduced in a container), brings the
stand up, and asserts:

- **pull**: Prometheus scrapes the agent with no failed scrape, sees
  `latkit_queries_total` growing under load, and a plausible p95 from
  `histogram_quantile` over the duration histogram;
- **push**: the collector receives the same metrics over OTLP (re-exported on
  `:8889`, so a series under `job="otel-collector"` proves the protobuf was
  accepted — a malformed one 400s and never appears), logs an
  `ExponentialHistogram`, and receives the sampled spans (`db.query.text`);
- **cross-check**: the pull and push query counts agree within an export
  interval.

By hand, once up: <http://localhost:19090> (Prometheus — 19090 to avoid a host
Prometheus on 9090), <http://localhost:9752/metrics> (the agent),
`docker compose logs -f otel-collector` (the debug dump of every metric/span).

## Requirements & caveats

- **Docker + BPF privileges on the host.** The agent container is `privileged`
  to load/attach BPF; where the runner has no BPF access this stand is a manual
  check (CI marks e2e optional). Everything else (parser, metrics, HTTP, OTLP
  encoder) is covered by the unprivileged unit tests.
- **Capture goes over the compose bridge, not localhost.** pgbench connects to
  `postgres:5432` by service name — a direct container-to-container hop the
  agent captures cleanly. A `localhost:<published>` hop would traverse
  docker-proxy, which `splice()`s the payload and defeats socket capture (see
  the top-level README "Known limitations"). So postgres does **not** publish
  5432.
- **Span volume.** `--otlp-spans 0.1` in the compose keeps the collector's debug
  log and CPU sane under pgbench; raise it to `1.0` for a "every query" demo.
- The p95 can read high (tens of seconds) in the first couple of minutes: the
  `pgbench -i` `VACUUM ANALYZE` runs multi-second queries that land in the top
  buckets, and the cumulative histogram carries them until they age out of the
  `rate()` window under steady load. That is real captured latency, not a
  histogram error.

## Files

| File | Role |
|---|---|
| `docker-compose.yml` | the five services + wiring |
| `Dockerfile.latkit` | minimal runtime image wrapping the host-built `build/latkit` |
| `prometheus.yml` | scrape config (agent + collector re-export) |
| `otel-collector-config.yaml` | OTLP receiver → debug + prometheus exporters |
| `verify.sh` | build + up + assert + down |
