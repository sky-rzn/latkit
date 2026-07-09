/* SPDX-License-Identifier: GPL-2.0 */
/* Span collector (Р32, STAGE5.md task 5.3): a third lk_query_sink alongside the
 * aggregator and the --queries logger. Where metrics keep only the normalised
 * fingerprint (Р28), a span carries what metrics cannot — the exact per-query
 * timings and the *raw* SQL of one sampled execution — so the two link up in
 * Grafana (metrics for the whole, a span for the specimen).
 *
 * Sampling is decided in on_query by two independent predicates (Р32): a
 * probabilistic ratio ("a representative slice") and a duration threshold ("all
 * the slow ones"); a query is sampled if either fires. The ratio draw is a pure
 * hash of (ts, cookie, seed) — no rand(3) on the hot path and deterministic
 * under a fixed seed for tests; the production seed comes from getrandom(2) so a
 * client cannot game which of its queries are sampled. Sampled queries are
 * copied (raw SQL bounded by text_max, since lk_query_obs.text dangles after the
 * callback, Р16) into a bounded FIFO ring; a full ring drops the newest and
 * bumps latkit_spans_dropped_total. The OTLP traces encoder drains the ring
 * (drop-and-count on a failed push — spans, unlike cumulative metrics, are a
 * best-effort signal).
 *
 * Pure like the rest of src/export: no libbpf, no sockets. The only I/O is the
 * one-shot getrandom for the id seed; timings stay CLOCK_MONOTONIC and convert
 * to wall clock at export through the timebase (Р33). */
#ifndef LATKIT_SPANS_H
#define LATKIT_SPANS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct lk_query_sink;

/* Ring depth (Р32) and the default per-span raw-text cap (--otlp-span-text-max). */
#define LK_SPAN_BUF          2048
#define LK_SPAN_TEXT_MAX_DEF 4096
#define LK_SPAN_NAME_MAX     64 /* span name = normalised text, truncated (Р32) */

struct lk_spans_cfg {
    double sample_ratio;             /* (0,1]; <= 0 disables the probabilistic predicate */
    uint64_t slow_ns;                /* > 0: also sample any query with duration >= slow_ns */
    uint32_t text_max;               /* cap on stored db.query.text bytes; 0 -> default */
    bool masked;                     /* store the normalised text as db.query.text (no literals) */
    uint64_t seed;                   /* sampling + id PRNG seed; 0 -> getrandom(2) */
    void (*on_watermark)(void *ctx); /* fired once when the ring crosses 3/4 full */
    void *watermark_ctx;
};

/* One collected span, drained by the OTLP traces encoder. Timings are still
 * CLOCK_MONOTONIC — the encoder converts them to Unix-epoch ns via the timebase
 * at export (Р33). text is a bounded copy of the raw (or, when masked, the
 * normalised) SQL, freed by the drain; NULL on a NO_TEXT observation. */
struct lk_span {
    uint8_t trace_id[16];
    uint8_t span_id[8];
    uint64_t start_ns, end_ns; /* mono (bpf_ktime_get_ns domain) */
    uint64_t rows;
    char name[LK_SPAN_NAME_MAX]; /* normalised text prefix, NUL-terminated */
    char db[64], user[64];       /* db.namespace, db.user */
    char *text;                  /* db.query.text bytes; NULL if none */
    uint32_t text_len;
    char sqlstate[6]; /* on error, C-string */
    uint8_t kind;     /* enum lk_query_kind */
    bool error;
    bool have_rows;
};

/* cfg is copied; NULL is not allowed (the exporter only builds this when spans
 * are enabled). Returns NULL on allocation failure. */
struct lk_spans *lk_spans_new(const struct lk_spans_cfg *cfg);
void lk_spans_free(struct lk_spans *s);

/* The tee sink handed to the parser (only on_query is populated). Borrowed —
 * valid for the collector's lifetime. */
const struct lk_query_sink *lk_spans_sink(struct lk_spans *s);

/* Pop every queued span in FIFO order into emit(), then clear the ring (each
 * span's text is freed after emit returns, so emit must copy what it needs). */
void lk_spans_drain(struct lk_spans *s, void (*emit)(void *ctx, const struct lk_span *sp),
                    void *ctx);

uint64_t lk_spans_sampled_total(const struct lk_spans *s);
uint64_t lk_spans_dropped_total(const struct lk_spans *s);
unsigned lk_spans_queued(const struct lk_spans *s);

#endif /* LATKIT_SPANS_H */
