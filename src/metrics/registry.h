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

/* Record one completed query observation into the duration histogram, applying
 * all three cardinality controls. `fp` and `label` come from the normaliser
 * (norm_sql): `label` is the canonical text, truncated to the label cap on a
 * UTF-8 boundary when the registry first admits `fp`. db/user are the session
 * labels ("" = unknown). dur_seconds is the server-side latency (Р25). */
void lk_reg_observe(struct lk_registry *r, uint64_t fp, const char *label, const char *db,
                    const char *user, enum lk_code code, double dur_seconds);

/* Prometheus text exposition of the query-duration family, HELP/TYPE first,
 * then one series per (query,db,user,code) in a stable order. Returns 0. */
int lk_reg_dump(const struct lk_registry *r, FILE *f);

/* --- introspection for the Р23 invariant tests --------------------------- */
uint32_t lk_reg_n_queries(const struct lk_registry *r); /* admitted real fps (excl. other) */
uint32_t lk_reg_n_dims(const struct lk_registry *r);    /* interned (db,user) pairs */
uint32_t lk_reg_n_series(const struct lk_registry *r);
uint64_t lk_reg_total_obs(const struct lk_registry *r); /* every lk_reg_observe call */
uint64_t lk_reg_other_obs(const struct lk_registry *r); /* ... routed to query="other" */
bool lk_reg_has_fp(const struct lk_registry *r, uint64_t fp);
/* Histogram count summed over the live series of `fp`'s slot, 0 if not admitted
 * (used to see that a re-admitted fingerprint restarts from zero). */
uint64_t lk_reg_fp_count(const struct lk_registry *r, uint64_t fp);
/* Sum of every series' histogram count; equals total_obs iff nothing was lost
 * across evictions (the monotonicity invariant). */
uint64_t lk_reg_series_count_sum(const struct lk_registry *r);

#endif /* LATKIT_METRICS_REGISTRY_H */
