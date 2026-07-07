/* SPDX-License-Identifier: GPL-2.0 */
/* Series registry with cardinality control (Р23, STAGE4.md task 4.2). Internal
 * to the metrics library: the facade (metrics.c) owns one, and the white-box
 * unit test drives it directly. Three defences against a Prometheus cardinality
 * explosion (PLAN.md §5):
 *
 *   - a top-K query dictionary (fp -> label), capacity cfg.top_queries. When it
 *     is full a newly *admitted* fingerprint evicts the LRU entry, and the
 *     evicted entry's series are FOLDED into query="other": global sums stay
 *     monotone and the `other` row never shrinks. A fingerprint that returns
 *     after eviction starts from zero — an ordinary Prometheus counter reset;
 *   - a doorkeeper against churn: while the dictionary is full a brand-new
 *     fingerprint is routed to `other` and remembered; it is admitted only on
 *     its SECOND appearance, so a stream of one-shot ad-hoc queries cannot wash
 *     out the working set (one direct-mapped probe, Р23);
 *   - a (db,user) dimension limit: cfg.max_session_dims distinct pairs, then
 *     db="other",user="other".
 *
 * The family carried here is latkit_query_duration_seconds{query,db,user,code}
 * (the cardinality-critical one); the flat self / connection counters attach at
 * the facade in tasks 4.3-4.4. Pure: no libbpf, I/O only via lk_reg_dump's
 * FILE. */
#ifndef LATKIT_METRICS_REGISTRY_H
#define LATKIT_METRICS_REGISTRY_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "metrics.h"

struct lk_registry;

/* cfg is copied (defaults applied / clamped). NULL on allocation failure. */
struct lk_registry *lk_reg_new(const struct lk_metrics_cfg *cfg);
void lk_reg_free(struct lk_registry *r);

/* One completed query observation, already reduced from lk_query_obs by the
 * facade (metrics.c on_query): text normalised, duration selected (Р25), flags
 * mapped to codes. The registry owns cardinality control (top-K dictionary,
 * doorkeeper, (db,user) and sqlstate limits) and fans this out to every family
 * that a single observation touches, so all of them share one dim interning and
 * one query-slot resolution:
 *
 *   - latkit_queries_total{db,user,kind,code}  (always; code = qcode, 4 values)
 *   - latkit_query_duration_seconds{query,db,user,code}   (if has_duration)
 *   - latkit_query_rows_total{query,db,user}              (if has_duration)
 *   - latkit_query_first_row_seconds{query,db,user}       (if enabled + has_first_row)
 *   - latkit_query_errors_total{sqlstate,db,user}         (if sqlstate != NULL)
 *   - latkit_queries_truncated_total                      (if truncated)
 *
 * `fp`/`label` come from the normaliser; `label` NULL or `force_other` routes
 * the query-keyed families to query="other" without consulting the dictionary
 * (NO_TEXT / CANCEL, Р28). db/user "" = unknown. */
struct lk_reg_obs {
    uint64_t fp;
    const char *label; /* canonical text; NULL -> query="other" */
    const char *db, *user;
    uint8_t kind;             /* enum lk_qkind (== enum lk_query_kind) */
    uint8_t qcode;            /* enum lk_qcode: ok|error|aborted|canceled */
    bool force_other;         /* skip the dictionary, record under query="other" */
    bool has_duration;        /* observe duration + rows (+ first_row); else counter-only */
    enum lk_code dcode;       /* duration series code: ok|error (Р23/Р25) */
    double dur_seconds;       /* server-side latency (Р25) */
    uint64_t rows;            /* from CommandComplete */
    bool has_first_row;       /* ts_first_row was present */
    double first_row_seconds; /* time to first DataRow */
    bool truncated;           /* text was a capture-budget/label prefix */
    const char *sqlstate;     /* non-NULL -> latkit_query_errors_total */
};

/* Fan one observation into all the families above, applying cardinality control. */
void lk_reg_observe(struct lk_registry *r, const struct lk_reg_obs *o);

/* Record one transaction span into latkit_txn_duration_seconds{db,user,status}
 * (status ok = T->I, aborted = E->I, Р16). db/user are the session labels. */
void lk_reg_observe_txn(struct lk_registry *r, const char *db, const char *user, bool aborted,
                        double dur_seconds);

/* Prometheus text exposition of every registry-owned family, each as a
 * HELP/TYPE block followed by its series in a stable (sorted) order — a valid
 * exposition stage 5 serves unchanged and replay diff-asserts against. Returns
 * 0, or -1 on an allocation failure while building the sort scratch. */
int lk_reg_dump(const struct lk_registry *r, FILE *f);

/* --- introspection for the Р23 invariant tests --------------------------- */
uint32_t lk_reg_n_queries(const struct lk_registry *r); /* admitted real fps (excl. other) */
uint32_t lk_reg_n_dims(const struct lk_registry *r);    /* interned (db,user) pairs */
uint32_t lk_reg_n_series(const struct lk_registry *r);
uint64_t lk_reg_total_obs(const struct lk_registry *r); /* observations with a duration */
uint64_t lk_reg_other_obs(const struct lk_registry *r); /* ... routed to query="other" */
bool lk_reg_has_fp(const struct lk_registry *r, uint64_t fp);
/* Histogram count summed over the live series of `fp`'s slot, 0 if not admitted
 * (used to see that a re-admitted fingerprint restarts from zero). */
uint64_t lk_reg_fp_count(const struct lk_registry *r, uint64_t fp);
/* Sum of every series' histogram count; equals total_obs iff nothing was lost
 * across evictions (the monotonicity invariant). */
uint64_t lk_reg_series_count_sum(const struct lk_registry *r);

#endif /* LATKIT_METRICS_REGISTRY_H */
