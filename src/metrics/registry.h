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
 * Every dimensioned family additionally carries proto="pg"|"mysql" (РМ6, М6):
 * the protocol is part of the interned dimension tuple, so the (db,user,query)
 * spaces of two DBMSes never merge. proto is bounded by the protocol registry
 * (LK_REG_MAX_PROTOS), not by max_session_dims — the (other,other) spill stays
 * split per protocol for the same reason.
 *
 * The family carried here is latkit_query_duration_seconds{query,db,user,proto,
 * code} (the cardinality-critical one); the flat self / connection counters
 * attach at the facade in tasks 4.3-4.4. Pure: no libbpf, I/O only via
 * lk_reg_dump's FILE.
 *
 * Since PLAN-HTTP.md М5 the same three defences serve a second *profile*
 * (РH10): an HTTP observation keys the dictionary on (method, route) and prints
 * under latkit_http_* with its own label names. The mechanism is untouched by
 * that — one dictionary, one doorkeeper, one dimension limit, shared by both —
 * and so is the PG/MySQL output, byte for byte. See struct lk_reg_obs. */
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

/* One completed observation, already reduced from lk_query_obs by the facade
 * (metrics.c on_query): text normalised, duration selected (Р25/РH5), flags
 * mapped to codes. The registry owns cardinality control (top-K dictionary,
 * doorkeeper, (db,user) and error-code limits) and fans this out to every family
 * that a single observation touches, so all of them share one dim interning and
 * one query-slot resolution.
 *
 * Which families those are is the `profile` (РH10). The engine is the same; the
 * family names and the label keys are not:
 *
 *   LK_PROF_QUERY (pg / mysql)
 *   - latkit_queries_total{db,user,proto,kind,code}  (always; code = qcode)
 *   - latkit_query_duration_seconds{query,db,user,proto,code}  (if has_duration)
 *   - latkit_query_rows_total{query,db,user,proto}             (if has_duration)
 *   - latkit_query_first_row_seconds{query,db,user,proto}      (if enabled + has_first_row)
 *   - latkit_query_errors_total{sqlstate,db,user,proto}        (if err_code != NULL)
 *   - latkit_queries_truncated_total                           (if truncated)
 *   - latkit_queries_other_total, latkit_txn_duration_seconds
 *
 *   LK_PROF_HTTP (http)
 *   - latkit_http_requests_total{route,method,host,user,proto,status}
 *   - latkit_http_request_duration_seconds{route,method,host,user,proto,code}
 *   - latkit_http_ttfb_seconds{route,method,host,user,proto}     (if has_first_row)
 *   - latkit_http_request_upload_seconds{route,method,host,user,proto} (if has_upload)
 *   - latkit_http_errors_total{code,host,user,proto}             (if err_code != NULL)
 *   - latkit_http_bytes_total{route,method,host,user,proto,direction}
 *   - latkit_http_response_size_bytes{route,method,host,user,proto} (if has_size)
 *
 *   LK_PROF_S3 (s3, PLAN-MINIO.md МS2/РS7) — the same shapes under the S3
 *   nouns: the dictionary slot is the operation, the dim slots are the bucket
 *   and the access key, the error label is the symbolic S3 code
 *   - latkit_s3_requests_total{op,method,bucket,user,proto,status}
 *   - latkit_s3_request_duration_seconds{op,method,bucket,user,proto,code}
 *   - latkit_s3_ttfb_seconds{op,method,bucket,user,proto}        (if has_first_row)
 *   - latkit_s3_request_upload_seconds{op,method,bucket,user,proto} (if has_upload)
 *   - latkit_s3_errors_total{s3code,bucket,user,proto}           (if err_code != NULL)
 *   - latkit_s3_bytes_total{op,method,bucket,user,proto,direction}
 *   - latkit_s3_object_size_bytes{op,method,bucket,user,proto}   (if has_size)
 *   - latkit_s3_internal_requests_total                          (if internal)
 *
 *   LK_PROF_REDIS (redis, PLAN-REDIS.md МR5/РR11) — the same engine again under
 *   the cache's nouns: the dictionary slot is the command from a closed table
 *   (РR4), the dim slots the database number and the ACL user (РR5/РR6), the
 *   error label the symbolic error (РR7). Three families exist nowhere else,
 *   and each of them keeps a number out of a place where it would be wrong:
 *   - latkit_redis_commands_total{cmd,db,user,proto,code}        (always)
 *   - latkit_redis_command_duration_seconds{cmd,db,user,proto,code} (if has_duration)
 *   - latkit_redis_blocking_seconds{cmd,db,user,proto}           (if has_block)
 *   - latkit_redis_errors_total{error,db,user,proto}             (if err_code != NULL)
 *   - latkit_redis_redirects_total{kind,proto}                   (if redirect)
 *   - latkit_redis_bytes_total{cmd,db,user,proto,direction}
 *   - latkit_redis_value_size_bytes{cmd,db,user,proto}           (if has_size)
 *   - latkit_redis_pipeline_depth{proto}                         (if has_depth)
 *
 *   `code` on the first two is the *outcome* (ok|error|aborted|canceled) rather
 *   than a status class: RESP has no statuses, and a command that was never
 *   answered is a fact the counter has to be able to state. A profile keyed this
 *   way counts every observation, including the ones with no duration — a
 *   `+QUEUED` inside a `MULTI` and a `BLPOP` that waited for the client's own
 *   thirty seconds are both commands and neither is a latency (РR9/РR10).
 *

 * РH9 lists the http label sets without `user`, and РS7 the s3 ones without
 * `user` and `method`; they are here because the series identity must stay
 * unique whatever `--http-user basic` / `--s3-user off` does — a family printed
 * without a key that is part of its key would emit duplicate label sets the
 * moment two users share a route, and a duplicate series is a scrape error, not
 * a cosmetic issue. Without those flags `user` is the constant "-" and costs
 * nothing; `method` is nearly a function of the operation and costs as little.
 *
 * `fp`/`label` come from the normaliser (norm_sql for the query profile,
 * norm_route for the http one); `label` NULL or `force_other` routes the
 * slot-keyed families to query="other" / route="other" without consulting the
 * dictionary (NO_TEXT / CANCEL, Р28; a request whose target never arrived, РH7).
 * db/user "" = unknown; proto NULL = "pg" (the protocol default, РМ2 — bare
 * unit-test observations stay PG-shaped). */
struct lk_reg_obs {
    uint64_t fp;
    const char *label; /* canonical text; NULL -> query="other" / route="other" */
    const char *op;    /* http: the method, part of the slot's identity (РH7) and
                          printed as its own label; NULL for the query profile */
    const char *db, *user;
    const char *proto;        /* lk_proto_ops.name; NULL -> "pg" (РМ6) */
    uint8_t profile;          /* enum lk_profile (== lk_proto_ops.profile) */
    uint8_t kind;             /* enum lk_qkind (== enum lk_query_kind) */
    uint8_t qcode;            /* enum lk_qcode: ok|error|aborted|canceled */
    uint8_t sclass;           /* enum lk_sclass, http only: the `status` label */
    bool force_other;         /* skip the dictionary, record under `other` */
    bool internal;            /* s3 (РS2): the server's own API, not an S3 operation.
                                 Counted in the profile's internal counter and
                                 reported nowhere else — every other field is ignored */
    bool has_duration;        /* observe duration + rows (+ first_row); else counter-only */
    enum lk_code dcode;       /* duration series code: ok|error (Р23/Р25; http: 5xx) */
    double dur_seconds;       /* server-side latency (Р25 / РH5) */
    uint64_t rows;            /* from CommandComplete */
    bool has_first_row;       /* ts_first_row was present */
    double first_row_seconds; /* time to first DataRow / http TTFB (РH5) */
    bool has_upload;          /* http: the request body took measurable time (РH5) */
    double upload_seconds;    /* ... ts_req_done - ts_start */
    bool has_size;            /* http/s3: the size below is worth histogramming */
    uint64_t size_bytes;      /* the size-histogram sample: the response body for http,
                                 the logical object size for s3 (РS6) — the two
                                 differ, and so do the grids they are recorded on */
    uint64_t bytes_in;        /* http: request body bytes */
    uint64_t bytes_out;       /* http: response body bytes */
    bool truncated;           /* text was a capture-budget/label prefix */
    const char *err_code;     /* SQLSTATE / HTTP status >= 400; non-NULL -> the
                                 profile's error counter */
    /* --- redis (РR7/РR10/РR3, МR5) — three facts no other profile has ------
     * Separate fields rather than reuses, because each of them is precisely a
     * number that must *not* go where the obvious existing field would put it:
     * a redirect is not an error, a blocking wait is not a latency, and a batch
     * depth is not a property of any one command's series. */
    uint8_t redirect;    /* enum lk_redirect; non-zero -> the redirect counter and
                            no entry in the error one */
    bool has_block;      /* the unit's duration is a wait the client asked for */
    double block_seconds;
    bool has_depth;      /* the observation knows its batch depth */
    uint32_t depth;      /* ... commands that arrived in one syscall with it */
};

/* Fan one observation into all the families above, applying cardinality control. */
void lk_reg_observe(struct lk_registry *r, const struct lk_reg_obs *o);

/* Record one transaction span into latkit_txn_duration_seconds{db,user,proto,
 * status} (status ok = T->I, aborted = E->I, Р16). db/user are the session
 * labels; proto as in lk_reg_obs (NULL -> "pg").
 *
 * The family is the one place where two profiles share a name (РR9): a `MULTI`
 * … `EXEC` is a transaction in exactly the sense PG's is, so Redis reports it
 * here unchanged rather than under a fourth name that would mean the same thing.
 * `profile` is therefore taken as well as `proto` — it is what the protocol name
 * is interned *under*, and a connection whose first observation is a transaction
 * would otherwise pin `redis` to the query profile and print its whole block
 * with SQL family names. */
void lk_reg_observe_txn(struct lk_registry *r, const char *db, const char *user, const char *proto,
                        uint8_t profile, bool aborted, double dur_seconds);

/* Prometheus text exposition of every registry-owned family, each as a
 * HELP/TYPE block followed by its series in a stable (sorted) order — a valid
 * exposition stage 5 serves unchanged and replay diff-asserts against. Returns
 * 0, or -1 on an allocation failure while building the sort scratch. */
int lk_reg_dump(const struct lk_registry *r, FILE *f);

/* Structured walk of every registry-owned family, same order as lk_reg_dump,
 * emitting each series as a read-only lk_metric_view (Р31, task 5.2). Counters
 * carry created_ns = the registry's creation time; query-keyed series carry
 * their own, so a fingerprint evicted and re-admitted starts a fresh OTLP stream
 * (a legal cumulative reset). Best-effort: an allocation failure while building
 * the sort scratch skips the query-keyed families rather than aborting. The
 * view's `labels`/`hist` pointers are valid only for the duration of the call. */
void lk_reg_iter(const struct lk_registry *r, lk_metrics_iter_fn fn, void *ctx);

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
