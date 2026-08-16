// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the exponential histogram (task 4.2, Р24). Checks:
 *
 *   - the grid index is the exact inverse of the reference boundary (ldexp), so
 *     a value on bound(k) lands in bucket k and bound(k)-eps in bucket k-1;
 *   - observations reach the expected cell; sum accumulates finite positives;
 *   - defensive clamping: 0 / negative / NaN -> underflow (+nonpos), +Inf ->
 *     overflow, below-range -> underflow, above-range -> overflow;
 *   - merge is cell-wise;
 *   - the classic text export: cumulative le buckets, +Inf == count, _sum;
 *   - and the same for the octave *size* grids (РH9, РS7): boundaries, the
 *     empty-body edge, the 1 GiB overflow, merge, integer le values in the
 *     export — and that a histogram carries which of the two grids it is on, so
 *     an object distribution reaching 1 TiB and a response distribution
 *     starting at 64 B live in one dump without either rebucketing the other. */
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "hist.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* index is the inverse of bound across the whole grid, and lower-inclusive. */
static int test_index_inverse(void)
{
    for (int k = LK_HIST_MIN_INDEX; k < LK_HIST_MAX_INDEX; k++) {
        double lo = lk_hist_bound(k);

        CHECK(lk_hist_index(lo) == k);                     /* on the boundary -> k */
        CHECK(lk_hist_index(nextafter(lo, 0.0)) == k - 1); /* just below -> k-1 */
        CHECK(lk_hist_bound(k + 1) > lo);                  /* strictly increasing */
    }
    /* factor between adjacent boundaries is 2^(1/4). */
    CHECK(fabs(lk_hist_bound(4) / lk_hist_bound(0) - 2.0) < 1e-12);
    CHECK(fabs(lk_hist_bound(0) - 1.0) < 1e-15);
    return 0;
}

static int test_observe(void)
{
    struct lk_hist h = {0};
    int k = -10; /* ~0.18 s .. 0.21 s, the pg_sleep(0.2) neighbourhood */
    double mid = (lk_hist_bound(k) + lk_hist_bound(k + 1)) / 2.0;

    lk_hist_observe(&h, mid);
    CHECK(h.count == 1);
    CHECK(h.bucket[k - LK_HIST_MIN_INDEX] == 1);
    CHECK(fabs(h.sum - mid) < 1e-12);

    /* a value exactly on a boundary is counted in the upper bucket */
    lk_hist_observe(&h, lk_hist_bound(k + 1));
    CHECK(h.bucket[k + 1 - LK_HIST_MIN_INDEX] == 1);
    CHECK(h.count == 2);
    return 0;
}

static int test_clamp(void)
{
    struct lk_hist h = {0};

    lk_hist_observe(&h, 0.0);
    lk_hist_observe(&h, -1.5);
    lk_hist_observe(&h, NAN);
    CHECK(h.nonpos == 3);
    CHECK(h.underflow == 3);
    CHECK(h.sum == 0.0); /* none contributed to the sum */

    lk_hist_observe(&h, INFINITY);
    CHECK(h.overflow == 1);

    lk_hist_observe(&h, 1e-9);   /* below 0.1 ms -> underflow */
    lk_hist_observe(&h, 3600.0); /* an hour -> overflow */
    CHECK(h.underflow == 4);
    CHECK(h.overflow == 2);
    CHECK(h.count == 6);
    /* count is conserved across every cell */
    uint64_t cells = h.underflow + h.overflow;
    for (int i = 0; i < LK_HIST_NBUCKETS; i++)
        cells += h.bucket[i];
    CHECK(cells == h.count);
    return 0;
}

static int test_merge(void)
{
    struct lk_hist a = {0}, b = {0};

    lk_hist_observe(&a, 0.05);
    lk_hist_observe(&b, 0.05);
    lk_hist_observe(&b, 100.0);
    lk_hist_merge(&a, &b);
    CHECK(a.count == 3);
    CHECK(a.overflow == 1);
    CHECK(fabs(a.sum - (0.05 + 0.05 + 100.0)) < 1e-9);
    return 0;
}

static int contains(const char *hay, const char *needle)
{
    return strstr(hay, needle) != NULL;
}

static int test_classic_dump(void)
{
    struct lk_hist h = {0};
    char buf[8192];
    FILE *f = tmpfile();
    size_t n;

    CHECK(f != NULL);
    lk_hist_observe(&h, 0.2); /* -> some mid-range bucket */
    lk_hist_observe(&h, 0.2);
    lk_hist_observe(&h, 1e-9); /* underflow: shows up in every le bucket */

    lk_hist_write(&h, f, "latkit_query_duration_seconds", "query=\"q\",code=\"ok\"");
    rewind(f);
    n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    /* le values are the exact un-round decimals (Р24) */
    CHECK(contains(buf, "le=\"0.0001220703125\""));
    CHECK(contains(buf, "le=\"1\""));
    CHECK(contains(buf, "le=\"+Inf\""));
    /* the underflow observation is <= every finite le */
    CHECK(contains(buf, "le=\"0.0001220703125\"} 1\n"));
    /* +Inf and _count carry the full count of 3 */
    CHECK(contains(buf, "le=\"+Inf\"} 3\n"));
    CHECK(contains(buf, "_count{query=\"q\",code=\"ok\"} 3\n"));
    /* 0.2 s sits in [0.177, 0.210): counted from le="0.25" up, not at le="0.125"
     * (there only the 1e-9 underflow shows) */
    CHECK(contains(buf, "le=\"0.125\"} 1\n"));
    CHECK(contains(buf, "le=\"0.25\"} 3\n"));
    CHECK(contains(buf, "le=\"1\"} 3\n"));
    return 0;
}

/* --- the octave size grid (РH9) ------------------------------------------- */

/* Every observation lands in the bucket whose upper bound it is the first to
 * fit under, boundaries included (the grid is upper-inclusive, the opposite of
 * the latency one, because `le` is what Prometheus asks for). */
static int test_bhist_buckets(void)
{
    struct lk_bhist h = {0};

    CHECK(lk_bhist_bound(&h, 0) == 64.0);
    CHECK(lk_bhist_bound(&h, LK_BHIST_NBUCKETS - 1) == 1073741824.0); /* 1 GiB */
    CHECK(lk_bhist_nbuckets(&h) == LK_BHIST_NBUCKETS); /* a zeroed grid is the default one */

    lk_bhist_observe(&h, 0);  /* a 204: no body at all */
    lk_bhist_observe(&h, 64); /* exactly on the first boundary */
    lk_bhist_observe(&h, 65); /* one byte over it */
    lk_bhist_observe(&h, 1500);
    lk_bhist_observe(&h, 2ull << 30); /* 2 GiB: past the top boundary */
    CHECK(h.bucket[0] == 2);          /* 0 and 64 */
    CHECK(h.bucket[1] == 1);          /* 65 -> (64, 128] */
    CHECK(h.bucket[5] == 1);          /* 1500 -> (1024, 2048], le=2048 */
    CHECK(h.overflow == 1);
    CHECK(h.count == 5);
    CHECK(h.sum == 0.0 + 64 + 65 + 1500 + (double)(2ull << 30));

    uint64_t cells = h.overflow;

    for (int i = 0; i < LK_BHIST_NBUCKETS; i++)
        cells += h.bucket[i];
    CHECK(cells == h.count);
    return 0;
}

static int test_bhist_merge(void)
{
    struct lk_bhist a = {0}, b = {0};

    lk_bhist_observe(&a, 100);
    lk_bhist_observe(&b, 100);
    lk_bhist_observe(&b, 1ull << 40);
    lk_bhist_merge(&a, &b);
    CHECK(a.count == 3);
    CHECK(a.bucket[1] == 2);
    CHECK(a.overflow == 1);
    return 0;
}

static int test_bhist_dump(void)
{
    struct lk_bhist h = {0};
    char buf[8192];
    FILE *f = tmpfile();
    size_t n;

    CHECK(f != NULL);
    lk_bhist_observe(&h, 0);
    lk_bhist_observe(&h, 4096);
    lk_bhist_observe(&h, 2ull << 30);

    lk_bhist_write(&h, f, "latkit_http_response_size_bytes", "route=\"/x\"");
    rewind(f);
    n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    /* le values print as plain integers, no exponent, no decimal point */
    CHECK(contains(buf, "le=\"64\"} 1\n"));         /* the empty body */
    CHECK(contains(buf, "le=\"2048\"} 1\n"));       /* 4096 is not in yet */
    CHECK(contains(buf, "le=\"4096\"} 2\n"));       /* ... and is here */
    CHECK(contains(buf, "le=\"1073741824\"} 2\n")); /* the 2 GiB body is not */
    CHECK(contains(buf, "le=\"+Inf\"} 3\n"));
    CHECK(contains(buf, "_count{route=\"/x\"} 3\n"));
    return 0;
}

/* The object grid (РS7, PLAN-MINIO.md МS2): the same machine one grid over, so
 * that "1 KiB … 1 TiB" is a property of the histogram and not of the code that
 * writes it. Its reason for existing is the two boundary cases below — a
 * multipart part of 64 MiB is a *cell* here and the top cell of the default
 * grid, and a 500 GiB object is a cell here and pure overflow there. */
static int test_ohist_grid(void)
{
    struct lk_bhist h = {0}, acc = {0};

    lk_bhist_init(&h, LK_OHIST_MIN_LOG2, LK_OHIST_NBUCKETS);
    CHECK(lk_bhist_nbuckets(&h) == LK_OHIST_NBUCKETS);
    CHECK(lk_bhist_bound(&h, 0) == 1024.0);
    CHECK(lk_bhist_bound(&h, LK_OHIST_NBUCKETS - 1) == 1099511627776.0); /* 1 TiB */

    lk_bhist_observe(&h, 512);                   /* a marker object: the first cell */
    lk_bhist_observe(&h, 64ull << 20);           /* a multipart part */
    lk_bhist_observe(&h, 800ull << 30);          /* most of a terabyte: still a cell */
    lk_bhist_observe(&h, 4ull << 40);            /* past 1 TiB: overflow */
    CHECK(h.bucket[0] == 1);                     /* (0, 1 KiB] */
    CHECK(h.bucket[16] == 1);                    /* le = 2^26 = 64 MiB */
    CHECK(h.bucket[LK_OHIST_NBUCKETS - 1] == 1); /* (512 GiB, 1 TiB] */
    CHECK(h.overflow == 1);
    CHECK(h.count == 4);

    /* A zeroed accumulator takes the grid of what it merges — the property the
     * dump's per-family accumulators rely on. */
    lk_bhist_merge(&acc, &h);
    CHECK(lk_bhist_nbuckets(&acc) == LK_OHIST_NBUCKETS);
    CHECK(lk_bhist_bound(&acc, 0) == 1024.0);
    CHECK(acc.count == 4 && acc.overflow == 1);
    return 0;
}

int main(void)
{
    if (test_index_inverse() || test_observe() || test_clamp() || test_merge() ||
        test_classic_dump() || test_bhist_buckets() || test_bhist_merge() || test_bhist_dump() ||
        test_ohist_grid())
        return 1;
    printf("test_hist: all passed\n");
    return 0;
}
