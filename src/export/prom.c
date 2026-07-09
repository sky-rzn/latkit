// SPDX-License-Identifier: GPL-2.0
/* See prom.h. Two route callbacks over the generic HTTP server, plus the export
 * self-metrics. /metrics serialises the registry into an in-memory stream with
 * open_memstream and hands the buffer to the server; /healthz reports liveness.
 * The self-metrics (request counts, last scrape duration) are gathered here and
 * poured into the facade through a provider, so they appear in the same dump. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* open_memstream */
#endif
#include "prom.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "http.h"
#include "metrics.h"

/* Bounded by the fixed route set x the handful of status codes it can return. */
#define LK_PROM_MAX_REQ_SERIES 24

struct req_count {
    char path[16]; /* "/metrics", "/healthz", "other" */
    int code;
    uint64_t n;
};

struct lk_prom {
    struct lk_http *http;
    struct lk_metrics *metrics;
    uint64_t start_ns;
    void (*health_fn)(void *ctx, struct lk_prom_health *out);
    void *health_ctx;
    double last_scrape_seconds;
    struct req_count reqs[LK_PROM_MAX_REQ_SERIES];
    int nreqs;
    struct lk_http_route routes[2];
};

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* --- routes --------------------------------------------------------------- */

static int route_metrics(void *ctx, const char *accept, char **body, size_t *body_len,
                         const char **content_type)
{
    struct lk_prom *p = ctx;
    char *buf = NULL;
    size_t sz = 0;
    FILE *f;
    uint64_t t0;

    (void)accept; /* OpenMetrics negotiation is task 5.3 */
    f = open_memstream(&buf, &sz);
    if (!f)
        return -1;
    t0 = now_ns();
    lk_metrics_dump(p->metrics, f); /* recomputes nothing — contract Р26 */
    fclose(f);                      /* finalises buf/sz */
    p->last_scrape_seconds = (double)(now_ns() - t0) / 1e9;

    *body = buf;
    *body_len = sz;
    *content_type = "text/plain; version=0.0.4; charset=utf-8";
    return 200;
}

static int route_healthz(void *ctx, const char *accept, char **body, size_t *body_len,
                         const char **content_type)
{
    struct lk_prom *p = ctx;
    struct lk_prom_health hs = {0};
    char *buf = NULL;
    size_t sz = 0;
    FILE *f;

    (void)accept;
    if (p->health_fn)
        p->health_fn(p->health_ctx, &hs);
    f = open_memstream(&buf, &sz);
    if (!f)
        return -1;
    fprintf(f, "ok\nuptime_seconds %.3f\n", (double)(now_ns() - p->start_ns) / 1e9);
    if (hs.valid)
        fprintf(f, "events_total %llu\nringbuf_dropped_total %llu\n",
                (unsigned long long)hs.events_total, (unsigned long long)hs.ringbuf_dropped_total);
    fclose(f);

    *body = buf;
    *body_len = sz;
    *content_type = "text/plain; charset=utf-8";
    return 200;
}

/* --- self-metrics --------------------------------------------------------- */

/* http.c calls this once per completed response; tally by (path, code). */
static void prom_on_response(void *ctx, const char *path, int code)
{
    struct lk_prom *p = ctx;

    for (int i = 0; i < p->nreqs; i++)
        if (p->reqs[i].code == code && !strcmp(p->reqs[i].path, path)) {
            p->reqs[i].n++;
            return;
        }
    if (p->nreqs >= LK_PROM_MAX_REQ_SERIES)
        return; /* bounded set; drop the unexpected extra */
    snprintf(p->reqs[p->nreqs].path, sizeof(p->reqs[p->nreqs].path), "%s", path);
    p->reqs[p->nreqs].code = code;
    p->reqs[p->nreqs].n = 1;
    p->nreqs++;
}

/* Facade provider (Р27): runs at the top of every dump, so these ride out in the
 * very exposition they describe. */
static void prom_provide(void *ctx, struct lk_metrics *m)
{
    struct lk_prom *p = ctx;

    lk_metrics_set_gauge(m, "latkit_scrape_duration_seconds",
                         "Duration of the last /metrics serialisation, seconds.",
                         p->last_scrape_seconds);
    for (int i = 0; i < p->nreqs; i++) {
        char code[8];

        snprintf(code, sizeof(code), "%d", p->reqs[i].code);
        lk_metrics_set_counter_l2(m, "latkit_http_requests_total",
                                  "HTTP responses served, by route and status code.", "path",
                                  p->reqs[i].path, "code", code, (double)p->reqs[i].n);
    }
}

/* --- lifecycle ------------------------------------------------------------ */

struct lk_prom *lk_prom_new(struct lk_loop *loop, const struct lk_prom_cfg *cfg)
{
    struct lk_prom *p = calloc(1, sizeof(*p));
    struct lk_http_cfg hc;

    if (!p)
        return NULL;
    p->metrics = cfg->metrics;
    p->health_fn = cfg->health_fn;
    p->health_ctx = cfg->health_ctx;
    p->start_ns = now_ns();
    p->routes[0] = (struct lk_http_route){.path = "/metrics", .handle = route_metrics, .ctx = p};
    p->routes[1] = (struct lk_http_route){.path = "/healthz", .handle = route_healthz, .ctx = p};

    hc = (struct lk_http_cfg){
        .bind_addr = cfg->bind_addr,
        .routes = p->routes,
        .nroutes = 2,
        .timeout_sec = cfg->timeout_sec,
        .on_response = prom_on_response,
        .cb_ctx = p,
    };
    p->http = lk_http_new(loop, &hc);
    if (!p->http) {
        free(p);
        return NULL;
    }
    /* Register the provider only once the server is up: providers cannot be
     * unregistered, so a failed bind must not leave a dangling one behind. */
    lk_metrics_add_provider(cfg->metrics, prom_provide, p);
    return p;
}

void lk_prom_free(struct lk_prom *p)
{
    if (!p)
        return;
    lk_http_free(p->http);
    free(p);
}

int lk_prom_port(const struct lk_prom *p)
{
    return p ? lk_http_port(p->http) : 0;
}
