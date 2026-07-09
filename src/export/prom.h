/* SPDX-License-Identifier: GPL-2.0 */
/* Prometheus pull path (Р29/Р30, STAGE5.md task 5.1): binds the generic HTTP
 * server (http.h) to the metrics facade and serves two routes:
 *
 *   /metrics  -- open_memstream + lk_metrics_dump, i.e. the exact stage-4 text
 *                exposition (contract Р26: HTTP wraps the dump, recomputing
 *                nothing). Content-Type is the classic 0.0.4 text format.
 *   /healthz  -- 200 with a short body (uptime and a couple of liveness
 *                counters). "Alive" means the loop turns and answers; capture
 *                degradation (drops, resyncs) is a metric, never a 503 (Р29).
 *
 * It also owns the export self-metrics — http_requests_total{path,code} and
 * scrape_duration_seconds — registered as a facade provider so they ride out in
 * the very dump they describe. */
#ifndef LATKIT_PROM_H
#define LATKIT_PROM_H

#include <stdbool.h>
#include <stdint.h>

struct lk_loop;
struct lk_metrics;
struct lk_prom;

/* Liveness counters for /healthz, filled by an optional caller callback (the
 * kernel counters live behind libbpf in events.c, which prom must not touch). */
struct lk_prom_health {
    uint64_t events_total;
    uint64_t ringbuf_dropped_total;
    bool valid; /* false: source unavailable, omit the counters from the body */
};

struct lk_prom_cfg {
    const char *bind_addr;      /* "ADDR:PORT"; caller handles the "none" opt-out */
    struct lk_metrics *metrics; /* borrowed, must outlive the server */
    unsigned int timeout_sec;   /* HTTP per-connection deadline; 0 = default */
    void (*health_fn)(void *ctx, struct lk_prom_health *out); /* optional */
    void *health_ctx;
};

/* Creates the HTTP server and registers the /metrics + /healthz routes and the
 * export self-metric provider on cfg->metrics. Returns NULL on failure (a bind
 * error is fatal by design — the caller aborts startup). */
struct lk_prom *lk_prom_new(struct lk_loop *loop, const struct lk_prom_cfg *cfg);
void lk_prom_free(struct lk_prom *p);

/* Actually-bound TCP port (host order), for logging. */
int lk_prom_port(const struct lk_prom *p);

#endif /* LATKIT_PROM_H */
