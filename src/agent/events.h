/* SPDX-License-Identifier: GPL-2.0 */
/* Ringbuf consumer: decode records, feed the connection table (task 2.2 —
 * seq-hole detection, idle sweep, LRU ceiling) and route data events into
 * the streaming framer (task 2.3). Output is opt-in: --events prints the raw
 * per-event lines of stage 1, --messages prints one line per reassembled PG
 * message. Talks to the BPF side through bpf_map handles only, so it does
 * not depend on the skeleton. */
#ifndef LATKIT_EVENTS_H
#define LATKIT_EVENTS_H

#include <linux/types.h>
#include <stdbool.h>

/* Prometheus /metrics listener default (Р29): loopback only, so a scrape from
 * outside the host is an explicit choice (bind 0.0.0.0). "none" disables it. */
#define LK_PROM_LISTEN_DEFAULT "127.0.0.1:9752"

struct bpf_map;
struct lk_loop;
struct lk_tls;
struct lk_cgroup;

struct lk_events_cfg {
    struct bpf_map *ringbuf;     /* `events` map */
    struct bpf_map *stats;       /* `stats` per-CPU counters */
    struct bpf_map *capmode;     /* per-conn capture-budget override (Р21) */
    struct lk_tls *tls;          /* TLS uprobe manager: source of the attach-state
                                    gauge (latkit_tls_attached), NULL when off */
    struct lk_cgroup *cgroup;    /* cgroup filter: source of latkit_cgroup_filter_paths,
                                    NULL / disabled when --cgroup was not given */
    __u32 max_conns;             /* userspace conn table ceiling (LRU past it) */
    __u32 conn_idle_timeout_sec; /* idle sweep threshold */
    const char *record_path;     /* --record: raw trace file, NULL when off (Р14) */
    bool hexdump;                /* dump event payload / message body prefix */
    bool cap_headers;
    bool events;   /* per-event log lines (the stage-1 output) */
    bool messages; /* one line per reassembled protocol message */
    bool queries;  /* tee: one line per session/query observation (stage 3) */

    /* Aggregator (stage 4). The parser's standard consumer is now the metrics
     * aggregator; --queries is a debug tee in front of it. */
    __u32 top_queries;             /* --top-queries (K); 0 = default */
    __u32 query_label_len;         /* --query-label-len; 0 = default */
    bool first_row_hist;           /* --first-row-hist */
    bool dump_metrics;             /* --dump-metrics[=path] given */
    const char *dump_metrics_path; /* target file, NULL = stderr */
    const char *prom_listen;       /* --prom-listen ADDR:PORT, or "none"/NULL to disable */

    /* OTLP/HTTP push exporter (task 5.2, Р31). Enabled by a non-NULL endpoint
     * (flag or OTEL_EXPORTER_OTLP_ENDPOINT). */
    const char *otlp_endpoint;       /* http://host:port[/path]; NULL disables */
    unsigned otlp_interval;          /* --otlp-interval seconds; 0 = default (15) */
    const char *const *otlp_headers; /* --otlp-header / OTEL_EXPORTER_OTLP_HEADERS */
    int otlp_nheaders;
    const char *const *otlp_resource; /* --otlp-resource / OTEL_RESOURCE_ATTRIBUTES */
    int otlp_nresource;
    const char *otlp_service_name; /* OTEL_SERVICE_NAME; NULL = "latkit" */

    /* Spans (task 5.3, Р32). Enabled when a predicate is set AND an OTLP
     * endpoint exists (nowhere to send otherwise). */
    double otlp_span_ratio;      /* --otlp-spans RATIO; (0,1], 0 = off */
    unsigned otlp_span_slow_ms;  /* --otlp-spans-slow-ms; 0 = off */
    unsigned otlp_span_text_max; /* --otlp-span-text-max; 0 = default (4 KiB) */
    bool otlp_span_masked;       /* --otlp-span-masked: strip literals from db.query.text */
};

struct lk_events;

struct lk_events *lk_events_new(const struct lk_events_cfg *cfg);
void lk_events_free(struct lk_events *e);

/* Register the ringbuf fd (consume on readiness) and the 10 s stats task. */
int lk_events_register(struct lk_events *e, struct lk_loop *loop);

/* One stats line to stderr; the loop calls this periodically, main calls it
 * once more for the final totals on shutdown. */
void lk_events_print_stats(struct lk_events *e);

/* Write the metrics registry as Prometheus text exposition to the configured
 * --dump-metrics target (stderr when no path), refreshing the connection gauges
 * from the conn table first. Fired on SIGUSR1 and once by main on shutdown;
 * no-op when --dump-metrics was not given. */
void lk_events_dump_metrics(struct lk_events *e);

#endif /* LATKIT_EVENTS_H */
