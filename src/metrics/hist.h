/* SPDX-License-Identifier: GPL-2.0 */
/* Exponential latency histogram (Р24, STAGE4.md task 4.2).
 *
 * One internal representation, two exports (stage 5 adds the second):
 *
 *   - the grid: bucket k covers [2^(k/4), 2^((k+1)/4)) seconds. That is a
 *     base-2 exponential grid with 4 sub-buckets per power of two — schema=2 in
 *     Prometheus native-histogram / OTLP exponential-histogram terms, factor
 *     ~1.189, bucketing error <= +-9%. The range 0.1 ms .. 60 s maps to grid
 *     indices k in [LK_HIST_MIN_INDEX, LK_HIST_MAX_INDEX) — 77 buckets — plus
 *     an underflow and an overflow cell, a floating-point sum and a count. That
 *     is ~80 * u64, and the hot-path increment is O(1): frexp + three mantissa
 *     comparisons, no log() (Р24, Р26);
 *   - classic buckets (the text-format export, task 4.2 dump / stage 5): every
 *     4th grid boundary, i.e. le = 2^j seconds for integer j, factor 2, ~20 le
 *     values. The le values are "un-round" decimals (2^-13 = 0.0001220703125,
 *     ...) but exact, so no rebucketing and no second histogram — see
 *     lk_hist_write and docs/notes-metrics.md.
 *
 * A native/exponential export (stage 5) takes the grid as-is. Pure: math + I/O
 * on the caller's FILE only, no libbpf, no heap. */
#ifndef LATKIT_METRICS_HIST_H
#define LATKIT_METRICS_HIST_H

#include <stdint.h>
#include <stdio.h>

/* Prometheus native-histogram schema: 2^(2^schema) sub-buckets per octave.
 * schema=2 -> 4 sub-buckets, factor 2^(1/4). Baked into the index math below;
 * changing it means rewriting lk_hist_index. */
#define LK_HIST_SCHEMA 2

/* Grid extent. bound(k) = 2^(k/4) s: bound(-53) ~= 0.105 ms, bound(23) ~= 45 s,
 * bound(24) = 64 s. Valid bucket indices are k in [MIN, MAX); everything below
 * is underflow, everything at/above is overflow. 77 buckets. */
#define LK_HIST_MIN_INDEX (-53)
#define LK_HIST_MAX_INDEX (24)
#define LK_HIST_NBUCKETS  (LK_HIST_MAX_INDEX - LK_HIST_MIN_INDEX) /* 77 */

struct lk_hist {
    uint64_t bucket[LK_HIST_NBUCKETS]; /* bucket[i] == grid index (MIN + i) */
    uint64_t underflow;                /* value below bound(MIN) */
    uint64_t overflow;                 /* value >= bound(MAX), or +Inf */
    uint64_t nonpos;                   /* value <= 0 or NaN: clamped to underflow,
                                          counted here too (bit-flipped timestamps) */
    double sum;                        /* sum of the finite positive observations */
    uint64_t count;                    /* every observation; == sum over all cells */
};

/* Record one observation (seconds). Non-finite / non-positive input is clamped
 * defensively rather than corrupting the grid (Р24): v <= 0 or NaN -> underflow
 * (and nonpos), +Inf -> overflow; neither contributes to `sum`. */
void lk_hist_observe(struct lk_hist *h, double seconds);

/* dst += src, cell by cell (the other-fold of an evicted query, Р23). */
void lk_hist_merge(struct lk_hist *dst, const struct lk_hist *src);

/* Grid index floor(4 * log2(v)) for a finite v > 0: the k with
 * bound(k) <= v < bound(k+1). Undefined for v <= 0 / non-finite (callers of the
 * histogram guard those; exposed for tests). */
int lk_hist_index(double v);

/* Lower boundary of grid bucket k, i.e. 2^(k/4) seconds, computed exactly from
 * ldexp and the quarter-power constants (the reference the tests check against
 * and the inverse of lk_hist_index). */
double lk_hist_bound(int k);

/* Emit the classic text-format lines for one series into `f`:
 *
 *     <metric>_bucket{<labelset>,le="..."} <cumulative>   (~20 le, then +Inf)
 *     <metric>_sum{<labelset>} <sum>
 *     <metric>_count{<labelset>} <count>
 *
 * `labelset` is the already-escaped `k="v",...` pairs without braces (may be
 * ""), so the histogram owns the le label but not the series identity. */
void lk_hist_write(const struct lk_hist *h, FILE *f, const char *metric,
                   const char *labelset);

#endif /* LATKIT_METRICS_HIST_H */
