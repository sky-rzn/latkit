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

struct bpf_map;
struct lk_loop;

struct lk_events_cfg {
    struct bpf_map *ringbuf;     /* `events` map */
    struct bpf_map *stats;       /* `stats` per-CPU counters */
    struct bpf_map *capmode;     /* per-conn capture-budget override (Р21) */
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
