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
void lk_hist_write(const struct lk_hist *h, FILE *f, const char *metric, const char *labelset);

/* --- size histogram (РH9, PLAN-HTTP.md М5) --------------------------------
 * A second, deliberately separate grid for *bytes*. The latency grid above
 * covers 0.1 ms … 60 s, five orders of magnitude around one second; an HTTP
 * response body is anywhere from an empty 204 to a gigabyte of video, nine
 * orders of magnitude in the other direction, so reusing the latency grid would
 * put every real response in the overflow cell. It is also a much coarser
 * question: nobody reads a size distribution to ±9%, they read it to tell a
 * page of JSON from a video file. Hence octaves — one bucket per power of two —
 * which gives `le` values that are already the numbers an operator thinks in.
 *
 * bucket[i] holds the values in (2^(min+i-1), 2^(min+i)], so bucket[0] is
 * "2^min bytes or less" (empty bodies included — a size of zero is a fact about
 * the response, not a bad observation, which is why there is no underflow cell
 * and no nonpos guard here) and `overflow` is everything past the last bound.
 *
 * **Two grids, one representation** (PLAN-MINIO.md МS2). The extent is a
 * property of what is being measured, and an object store measures something
 * else than a web server: HTTP response bodies cluster around a page of JSON,
 * S3 objects around a multipart part of 8–64 MiB and reach a 5 TiB ceiling. A
 * 64 B first bucket wastes seven cells on sizes an object store never sees, and
 * a 1 GiB last one puts every large object in the overflow — where a
 * distribution says nothing at all. So the grid travels *in* the histogram: a
 * zero-initialised one is the default HTTP grid (which is what keeps every
 * pre-МS2 caller and every byte of the http exposition unchanged), and
 * lk_bhist_init asks for the other one. */
#define LK_BHIST_MIN_LOG2 6                                           /* first le = 64 B */
#define LK_BHIST_MAX_LOG2 30                                          /* last le = 1 GiB */
#define LK_BHIST_NBUCKETS (LK_BHIST_MAX_LOG2 - LK_BHIST_MIN_LOG2 + 1) /* 25 */

/* The object grid (РS7): 1 KiB … 1 TiB. The bottom is 1 KiB because an S3
 * object smaller than that is a marker file and its exact size is nobody's
 * question; the top is 1 TiB because that is past MinIO's largest single
 * object and one octave below the S3 limit of 5 TiB, so the overflow cell means
 * "impossibly large" rather than "big". */
#define LK_OHIST_MIN_LOG2 10                                          /* first le = 1 KiB */
#define LK_OHIST_MAX_LOG2 40                                          /* last le = 1 TiB */
#define LK_OHIST_NBUCKETS (LK_OHIST_MAX_LOG2 - LK_OHIST_MIN_LOG2 + 1) /* 31 */

/* The widest grid, i.e. the storage every byte histogram carries. */
#define LK_BHIST_MAX_NBUCKETS LK_OHIST_NBUCKETS

struct lk_bhist {
    uint8_t min_log2; /* le of bucket[i] = 2^(min_log2 + i) */
    uint8_t nbuckets; /* 0 = never initialised: the default grid above */
    uint64_t bucket[LK_BHIST_MAX_NBUCKETS];
    uint64_t overflow; /* value past the last bound */
    double sum;        /* sum of the observed sizes */
    uint64_t count;
};

/* Point a (zeroed) histogram at a grid: bucket[i] covers up to 2^(min_log2+i),
 * nbuckets cells of it. Only the two grids above are used, and only by the
 * registry, which knows a family's grid from its profile. */
void lk_bhist_init(struct lk_bhist *h, unsigned min_log2, unsigned nbuckets);

/* Record one size (bytes). Total order, no clamping needed: the domain is
 * unsigned and every value lands in a cell. */
void lk_bhist_observe(struct lk_bhist *h, uint64_t bytes);

/* dst += src, cell by cell (the other-fold of an evicted route, Р23/РH7). An
 * uninitialised dst adopts src's grid, which is what lets a caller accumulate
 * into a `struct lk_bhist acc = {0}` without knowing which family it is
 * merging. Two different grids never meet: a grid is a property of the family
 * and every merge is within one. */
void lk_bhist_merge(struct lk_bhist *dst, const struct lk_bhist *src);

/* The histogram's cell count and the upper boundary of bucket i, i.e.
 * 2^(min_log2 + i) bytes — exact integers, so the text export prints them
 * without a decimal point and the OTLP export hands the same numbers over as
 * explicit bounds. */
unsigned lk_bhist_nbuckets(const struct lk_bhist *h);
double lk_bhist_bound(const struct lk_bhist *h, int i);

/* Text-format lines for one size series, in the shape lk_hist_write uses. */
void lk_bhist_write(const struct lk_bhist *h, FILE *f, const char *metric, const char *labelset);

#endif /* LATKIT_METRICS_HIST_H */
