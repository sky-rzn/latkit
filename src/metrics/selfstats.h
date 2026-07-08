/* SPDX-License-Identifier: GPL-2.0 */
/* Process self-metrics (Р27, STAGE4.md task 4.4): the standard Prometheus
 * process_* collectors — CPU seconds (getrusage), resident memory
 * (/proc/self/statm) and the start time (captured once). Plugs into the metrics
 * facade as an lk_metrics_provider_fn, so the aggregator stays oblivious to the
 * OS. This is the one metrics-side module that does OS I/O (getrusage, procfs) —
 * a documented exception to the pure-facade rule; it still needs no libbpf, so
 * it links into the agent and offline harnesses alike. */
#ifndef LATKIT_METRICS_SELFSTATS_H
#define LATKIT_METRICS_SELFSTATS_H

#include "metrics.h"

struct lk_selfstats;

/* Capture the process start time (Unix epoch) once. NULL on allocation failure;
 * treat as optional — process_* is simply absent then. */
struct lk_selfstats *lk_selfstats_new(void);
void lk_selfstats_free(struct lk_selfstats *ss);

/* lk_metrics_provider_fn (ctx = the lk_selfstats): pour process_cpu_seconds_total,
 * process_resident_memory_bytes and process_start_time_seconds into m. */
void lk_selfstats_provide(void *ctx, struct lk_metrics *m);

#endif /* LATKIT_METRICS_SELFSTATS_H */
