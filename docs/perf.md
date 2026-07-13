# Overhead benchmark — v1.0 budget (stage 8.1, Р49)

**Verdict: the v1.0 gates hold.** At the target ~50k queries/s the agent
costs the observed workload **≤ 0.2% TPS** (noise-level; gate < 3%), and
its own CPU is **0.31 cores plaintext / 0.45 cores TLS per 50k queries/s**
(gate < 1 core). RSS stays ~25 MiB under load. Every quoted run finished
with **zero ringbuf drops and zero resyncs** — numbers taken under a
degraded capture are rejected by construction.

Everything below is produced by `tests/bench/run.sh` (Р49); rerun it to
reproduce the tables one-to-one.

## Method

One load, five environments, so each increment is isolated:

| # | Environment | What it isolates |
|---|---|---|
| A | agent not running | baseline |
| B | agent up, filter miss (`--port 1`) | fentry probes without the pipeline |
| C | agent, plaintext capture | probes + ringbuf + pipeline |
| D | agent, TLS capture (`--tls auto`, `sslmode=require`) | + the libssl uprobe channel (Р40) |
| E | C + OTLP spans 1:100 into a dummy collector | + the export path (Р31/Р32) |

- **ABAB pairing**: each configuration alternates with its own baseline
  (A, X, A, X — 5 pairs of 60 s runs plus a discarded 30 s warmup);
  machine drift lands on both sides and medians are compared. The spread
  ((max−min)/median of tps) is recorded per series; it stayed ≤ 0.5%.
- **Validity**: a run is discarded if `latkit_ringbuf_dropped_total` or
  `latkit_resync_total` grew during it, if the capture saw no queries
  (C/D/E), if the filter leaked (B), or if the TLS uprobes were not
  attached (D). An agent that loses events is "cheaper" than one that
  works, so degraded runs must not enter the medians.
- **Load**: pgbench select-only `-M prepared -c 128` and TPC-B `-c 100`
  (both `-j $(nproc)`), scale 100 (fits shared_buffers), **rate-capped at
  the target**: `-R 50000` for select-only and `-R 7000` tx/s for TPC-B
  (≈ 49k wire queries/s — one TPC-B transaction is ~7 statements). The
  uncapped ceiling of this stand is ~7x the target and saturates the
  agent's pipeline thread outright (see "saturation probe"), which the
  validity rule correctly rejects; the budget is defined at ~50k qps.
- **CPU accounting**: agent = Δ`process_cpu_seconds_total` / wall,
  normalised per 50k queries/s on the agent's own query count; postgres =
  the container's cgroup `cpu.stat` (cross-check that the agent does not
  offload its cost onto the observed process). `perf record -F 499 -g`
  runs on the agent during every C/D run.
- **Stand**: Intel Core Ultra 7 155H (22 hw threads, hybrid), 62 GiB RAM,
  kernel 7.0, postgres:16 in Docker, dataset in `shared_buffers` (2 GB),
  `fsync=off` — CPU-bound on purpose. Load is driven at the **container
  IP** (docker-proxy on a published port would pollute the capture; the
  bench containers publish nothing). pgbench runs on the same host —
  client CPU is deliberately part of the stand's budget. Agent built
  RelWithDebInfo (`-O2 -g -fno-omit-frame-pointer`).

Reproduction:

```sh
cmake -B build-rel -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_FLAGS=-fno-omit-frame-pointer
cmake --build build-rel --target latkit -j
PERF=1 tests/bench/run.sh run          # full campaign, ~1.5 h
tests/bench/run.sh down                # drop the bench containers
```

## Results (2026-07-12, commit of stage 8.1)

Medians over the valid ABAB pairs; latencies in ms; `cores/50k` is the
agent CPU normalised to 50k queries/s.

```
workload cfg runs       tps A      tps X   dTPS%    sprA%    sprX%   p50 A>X   p95 A>X    agent cores/50k  pgSCPU
select   B    5+5       49968      49976  -0.01%     0.1%     0.1% 0.10>0.10 0.18>0.18    0.000     0.000  +0.04
select   C    5+5       49965      49988  -0.05%     0.1%     0.1% 0.10>0.11 0.19>0.16    0.310     0.311  +0.29
select   D    5+4       49993      49971  +0.04%     0.1%     0.1% 0.12>0.15 0.23>0.25    0.447     0.449  +1.19  [1 invalid: resync]
select   E    5+5       49978      49975  +0.01%     0.1%     0.2% 0.10>0.10 0.18>0.16    0.241     0.242  +0.23
tpcb     B    5+5        6995       7008  -0.19%     0.3%     0.3% 0.49>0.49 0.95>1.00    0.000     0.000  +0.01
tpcb     C    5+5        6994       6995  -0.01%     0.5%     0.3% 0.47>0.53 1.07>1.61    0.292     0.299  +0.33
tpcb     D    5+2        7001       6995  +0.08%     0.3%     0.4% 0.61>0.84 0.87>1.22    0.430     0.441  +1.38  [3 invalid: resync]
tpcb     E    5+5        6997       6996  +0.02%     0.3%     0.3% 0.47>0.54 0.75>0.82    0.231     0.237  +0.36

GATE: PASS — dTPS(C), dTPS(D) < 3%; agent < 1 core / 50k qps
```

How to read it:

- **ΔTPS is noise** in every configuration (±0.2% against a 3% gate, with
  series spread of the same order). At the target rate the agent does not
  move throughput.
- **Agent CPU**: 0.31 cores (plaintext), 0.45 (TLS), 0.24–0.30 (with
  OTLP export / TPC-B mix) per 50k queries/s. Gate < 1 core: **passed
  with ~2x margin**. E costing slightly *less* than C is within run-to-run
  variance of the pipeline thread (0.24 vs 0.31), not a real speedup.
- **B is free**: with the port filter missing everything, the fentry
  probes alone are not measurable from the workload side (ΔTPS −0.01%,
  agent CPU 0.000 — the pipeline never wakes).
- **`pgSCPU` — the uprobe channel's real price**: TLS capture costs the
  *observed postgres* +1.19 cores at 50k queries/s (select) / +1.38
  (TPC-B), i.e. **~24–28 µs of postgres CPU per query** for the four
  SSL_* uprobe+uretprobe hits, versus +0.3 for plaintext fentry capture.
  This is the Р40 number the stage-6 debt asked for, and it feeds the
  "SSL_read-only + timing reconstruction" row of the Р54 table (decision
  in task 8.6): the cost lives in the *uprobe mechanism on the postgres
  side*, not in the agent's pipeline, so no agent-side optimisation
  touches it.
- **TPC-B tail**: at a fixed 7k tx/s the plaintext capture adds ~60 µs to
  p50 and ~0.5 ms to p95 of a TPC-B transaction (1.07 → 1.61 ms); TLS adds
  ~0.2–0.4 ms on both. Visible, bounded, and consistent with the per-call
  probe cost multiplied by ~14 send/recv calls per transaction.
- **TLS residual resyncs**: 4 of 22 D-runs were discarded for a handful of
  resyncs (3–8 per run: one-to-two capture holes of tens of bytes in ~10M
  messages, ≤ 1 query observation lost, capture recovers by itself). Root
  cause of the bulk of this class was fixed during 8.1 (see "fixes");
  what remains is rare cursor-pool exhaustion under preemption on a fully
  loaded host. Kept visible on purpose — the validity rule, not manual
  judgement, decides which runs count.

## Saturation probe (uncapped, diagnostic — not a gate number)

Select-only with no rate cap on this stand: **361k qps** (pgbench side).
The agent's pipeline thread pins at ~0.8–1.0 core, keeps up with ~190–220k
events/s, and honestly drops the rest (`latkit_ringbuf_dropped_total` grew
by 15.5M of 32.4M submitted events over 45 s; ~52% of queries still
observed and counted). Loss is *counted, never silent*, which is exactly
the designed behaviour past the budget point. Single-thread ceiling ≈
**150–200k queries/s per core** for this pipeline; the v1 target (50k)
uses under half a core. This is the input for the Р54 "second thread /
lock-free aggregation" row — no go signal at v1 scale.

## Profiles (perf, C/D runs at 50k qps)

Flat on-CPU profile of the agent, top symbols (full reports live next to
each run's `perf.data` under `tests/bench/out/`):

- select C: `lk_frame_bytes` 4.5%, `out_token` 3.7%, `lk_norm_sql` 3.6%,
  `ringbuf_process_ring` 2.8%, `pg_on_msg` 2.0%; the rest is scheduler
  wake/sleep cost of an under-loaded thread.
- select D: same shape (framer 3.6%, norm cluster ~5%, ringbuf 3.7%) —
  the uprobe channel adds kernel-side work in *postgres* context, not
  agent hotspots.
- tpcb C: `lk_norm_sql` 5.2% + `out_token` 3.6% + XXH3 3.1% — the
  normaliser cluster is the largest block on write-heavy SQL.

Conclusions for the Р54 go/no-go (final decisions belong to task 8.6):

- **No single site reaches the ≥10% trigger.** The largest coherent
  cluster is normalisation (`lk_norm_sql` + `out_token` + XXH3):
  ~8% at 50k select, ~12% on TPC-B — borderline; the "fp cache by raw
  text pointer/length" row keeps a *watch* signal, not a go.
- Registry/dump, conn table, exporter are all ≤ 3% — no signal for the
  sharding, incremental-dump or flip rows.
- Uprobe channel: the D−C delta lives in postgres-side uprobe cost (Р40
  row gets a real, quantified trigger: ~25 µs/query).

## Fixes that landed during 8.1

The benchmark's validity rule caught three real capture-quality bugs on
concurrent TLS (all fixed in this stage, verified live at 50k qps with
zero drops/resyncs):

1. **`ssl_to_conn` keyed by bare `SSL*`** glued forked backends whose SSL
   objects landed on the same heap address into one connection (resync
   churn, cross-session attribution). Key is now `{SSL*, tgid}`.
2. **Ciphertext-drop accounting**: dropped ciphertext socket events of a
   TLS connection never advanced the raw seq baseline, so CONN_CLOSE read
   the whole ciphertext stream as "lost". The drop path now moves the
   baseline without counting a gap.
3. **Per-CPU chunk cursor collision**: a BPF chain preempted mid-emit by
   another task's chain on the same CPU degraded the preemptor to a
   `cap_len=0` event — an artificial capture hole and a resync
   (~0.5/s at 50k TLS qps). The single cursor is now a 4-slot pool
   (`cursor_claim()`), and the degrade path is the 5th concurrent chain,
   not the 2nd.

## Stand pitfalls worth knowing (reproduction notes)

- **ACPI `platform_profile` left in `low-power`** (e.g. after a suspend)
  caps package power: ~700 MHz under all-core load at 65 °C, every agent
  run drowns in drops that have nothing to do with the agent. `run.sh`
  refuses to start in that state.
- **TPC-B bloats the dataset** across a campaign (dead tuples → postgres
  CPU per tx creeps up ~50% over an hour); `run.sh` re-inits the dataset
  before every TPC-B series so baselines stay comparable.
- **docker-proxy** must not be in the load path (it splices, and its
  traffic pollutes the capture); the bench publishes no ports and drives
  load at container IPs.
- Turbo stays **on**: on laptop-class CPUs base clocks are a fraction of
  sustained turbo and the stand loses the capacity the target rate needs;
  drift is what the ABAB alternation and the reported spread are for.

## Deployment resources (Р47 hypothesis closed)

Measured at 50k queries/s: ≤ 0.45 cores agent CPU (TLS, worst case),
RSS ~25 MiB steady under load (64k-conn table and top-500 query registry
at defaults). `deploy/k8s/latkit-daemonset.yaml` now requests
`100m/64Mi` and limits `1 CPU/256Mi` — the limit equals the v1.0 CPU
budget at the 50k target; memory headroom covers bigger
`--top-queries`/`--max-conns` settings.

## Long-run soak — leaks and stability (stage 8.5, Р53)

`tests/longrun/run.sh` runs the agent for 24 h under continuous disturbance
and asserts that nothing drifts. The point is not throughput — it is that
the agent that survives a night of churn, induced loss and restarts looks
exactly like the one that started it.

**Load** (all pgbench, each wrapped in a restart-on-exit loop so a postgres
bounce never kills the generator): a persistent-connection baseline
(`-S -M prepared` + TPC-B writes) plus two reconnect-per-transaction
generators (`pgbench -C`) — one plaintext, one `sslmode=require`. The `-C`
generators are the churn: every transaction is a fresh connection (and, for
the TLS one, a fresh SSL handshake on a forked backend), which keeps the
conn-table LRU + idle sweep (Р12) and the libssl uprobe attach/detach + the
fd→sock→cookie bridge (Р37) under constant pressure.

**Disturbances on a schedule:** hourly induced loss — `kill -STOP latkit;
sleep; kill -CONT` — overflows the ringbuf while the agent is frozen, so the
`gap → resync → recovery` path (Р10/Р19) is exercised dozens of times, not
once (real overload can't be provoked deterministically; the bench peak
configs cover that side). And a periodic TLS-postgres restart — synthetic
OPEN, libssl rescan (Р39), cgroup re-resolve (Р48) in one shot.

The agent runs **detached via `setsid`** (reparented to init), not as a
`sudo` child: otherwise `sudo` mirrors the induced `SIGSTOP` onto itself and,
stopped, never reaps the agent — deadlocking shutdown. Under systemd in
production there is no such parent; the harness reproduces that.

**Witness:** every 15 s a row lands in `samples.tsv` — RSS, `metric_series`,
active conns, the process fd count (from `/proc/<pid>/fd`), and the
dropped/resync/TLS counters, each tagged with the phase (`steady` /
`recovery` / `restart`). `bpftool map show` for the agent's maps is captured
before and after; a map that grew or appeared is a leak. `plot.py` renders
the three-panel RSS/fd/series PNG for this doc.

**Acceptance** (checked by the script, `VERDICT: PASS/FAIL`):

- RSS reaches a plateau — 2nd-half spread < 5 % of the median;
- fd count does not grow — 2nd-half max within 20 % of the first sample;
- `latkit_metric_series` stays under the ceiling (top-K is bounded, Р23);
- `dropped`/`resync` grow **only** inside induced/recovery/restart windows —
  zero unexpected loss in any pure-`steady` sample;
- kernel maps identical before/after.

Reproduce (dev stand; needs docker, passwordless sudo, an optimised
`build-rel`):

```
tests/longrun/run.sh up            # start + init the two postgres containers
tests/longrun/run.sh run           # 24 h soak, DURATION_H=24 default
SMOKE=1 tests/longrun/run.sh run   # 5-min harness self-check, same PASS/FAIL
tests/longrun/plot.py tests/longrun/out/<ts>/samples.tsv   # RSS PNG
```

**Results.** The harness is validated end-to-end (the `SMOKE=1` self-check
passes: RSS spread 0.16 %, fds flat, series bounded, zero steady-phase loss,
maps unchanged, and every induced window recovers to zero resync). The full
24 h stand run and its RSS graph land here once complete — this is the one
calendar-bound step of the stage.

## Nightly memory checking (stage 8.5, Р53)

ASAN/UBSAN on the unit + replay suites already run on every PR (stages 2–4).
The nightly `valgrind` CI job adds a second echelon: memcheck on the replay
harness (`tests/replay/test_replay`), which drives the whole libbpf-free
pipeline — decode → conn_table → reassembly → PG parser → norm →
metrics/export — over the committed fixtures. It runs with
`--leak-check=full --track-origins=yes --error-exitcode=1`; a failure is a
release blocker. Suppressions live in `tests/valgrind.supp` with a
justification policy — empty today by design: the harness is memcheck-clean
(0 errors, all heap freed), and a leak there is a leak in code the agent runs
24/7. memcheck is nightly-only (~20–50× slowdown); ASAN stays the fast PR
echelon. Built without sanitizers on purpose — ASAN and valgrind don't mix.
