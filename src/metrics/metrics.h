/* SPDX-License-Identifier: GPL-2.0 */
/* Metrics facade (Р26, STAGE4.md tasks 4.2-4.4). The one header a consumer
 * (events.c live, the replay harness offline) needs to hold a metrics registry
 * and dump it. Stage-4 task split:
 *
 *   - 4.2 (here): configuration, lifecycle, and lk_metrics_dump — a valid
 *     Prometheus text exposition (the cardinality-controlled query-duration
 *     family lives in registry.c). Stage 5 wraps this dump in HTTP unchanged;
 *   - 4.3: the lk_query_sink implementation (on_query/on_session/on_txn) that
 *     turns lk_query_obs into registry observations;
 *   - 4.4: self-metric providers (getrusage, kernel/framer/parser counters).
 *
 * The facade owns a struct lk_registry (registry.h) plus, later, the flat
 * counter/gauge series the providers fill. Pure: no libbpf; I/O only through the
 * caller's FILE. */
#ifndef LATKIT_METRICS_H
#define LATKIT_METRICS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* Config defaults (Р23, Р28). */
#define LK_TOP_QUERIES_DEFAULT      500
#define LK_QUERY_LABEL_LEN_DEFAULT  256
#define LK_MAX_SESSION_DIMS_DEFAULT 32

/* Hard cap on the stored query label (Р28): the buffer size, so
 * query_label_len is clamped to [1, LK_QUERY_LABEL_MAX - 1] characters. */
#define LK_QUERY_LABEL_MAX 256

/* code label of latkit_query_duration_seconds (Р23/Р25): ok|error, NOT the raw
 * SQLSTATE (that would explode query x db x user; it lives label-free in the
 * error counter). */
enum lk_code {
    LK_CODE_OK = 0,
    LK_CODE_ERROR = 1,
    LK_N_CODES = 2,
};

/* code label of latkit_queries_total (Р23): four states — a superset of the
 * duration code, since aborted/canceled observations carry no latency. */
enum lk_qcode {
    LK_QCODE_OK = 0,
    LK_QCODE_ERROR,
    LK_QCODE_ABORTED,
    LK_QCODE_CANCELED,
    LK_N_QCODES,
};

/* kind label of latkit_queries_total. Mirrors enum lk_query_kind (proto.h) by
 * value so the facade can pass lk_query_obs.kind straight through; kept as an
 * independent enum so the pure metrics/registry code needs no protocol header. */
enum lk_qkind {
    LK_QK_SIMPLE = 0,
    LK_QK_EXTENDED,
    LK_QK_FUNCTION,
    LK_QK_COPY_IN,
    LK_QK_COPY_OUT,
    LK_QK_CANCEL,
    LK_N_QKINDS,
};

struct lk_metrics_cfg {
    uint32_t top_queries;      /* K, top-K query dictionary (Р23) */
    uint32_t query_label_len;  /* stored `query` label length (Р28) */
    uint32_t max_session_dims; /* distinct (db,user) pairs before `other` (Р23) */
    bool first_row_hist;       /* emit latkit_query_first_row_seconds (Р24) */
};

/* Fill cfg with the defaults above. */
void lk_metrics_cfg_defaults(struct lk_metrics_cfg *cfg);

struct lk_metrics;
struct lk_query_sink;

/* cfg is copied; NULL means defaults. Returns NULL on allocation failure. */
struct lk_metrics *lk_metrics_new(const struct lk_metrics_cfg *cfg);
void lk_metrics_free(struct lk_metrics *m);

/* The aggregator (Р26, task 4.3): the lk_query_sink turning parser observations
 * (lk_query_obs) into registry series. Install it as lk_proto_pg_new()'s output.
 * Borrowed — valid for the metrics object's lifetime. */
const struct lk_query_sink *lk_metrics_query_sink(struct lk_metrics *m);

/* Flat named scalar series the facade dumps after the registry families (Р27):
 * idempotent absolute writes of a counter/gauge value, keyed by name (no labels
 * in stage 4 — connections and, later, the self-metric providers). `help` is
 * remembered on first sight and may be NULL afterwards. Unknown-name writes
 * register the series; memory is bounded by the fixed metric set. */
void lk_metrics_set_counter(struct lk_metrics *m, const char *name, const char *help, double v);
void lk_metrics_set_gauge(struct lk_metrics *m, const char *name, const char *help, double v);

/* Write the whole registry plus the flat scalars as Prometheus text exposition
 * format (Р26); stable line order for replay diff-asserts. Returns 0. */
int lk_metrics_dump(struct lk_metrics *m, FILE *f);

#endif /* LATKIT_METRICS_H */
