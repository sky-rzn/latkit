// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the exponential histogram (task 4.2, Р24). Checks:
 *
 *   - the grid index is the exact inverse of the reference boundary (ldexp), so
 *     a value on bound(k) lands in bucket k and bound(k)-eps in bucket k-1;
 *   - observations reach the expected cell; sum accumulates finite positives;
 *   - defensive clamping: 0 / negative / NaN -> underflow (+nonpos), +Inf ->
 *     overflow, below-range -> underflow, above-range -> overflow;
 *   - merge is cell-wise;
 *   - the classic text export: cumulative le buckets, +Inf == count, _sum. */
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

        CHECK(lk_hist_index(lo) == k);                 /* on the boundary -> k */
        CHECK(lk_hist_index(nextafter(lo, 0.0)) == k - 1); /* just below -> k-1 */
        CHECK(lk_hist_bound(k + 1) > lo);              /* strictly increasing */
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
    lk_hist_observe(&h, 0.2);  /* -> some mid-range bucket */
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

int main(void)
{
    if (test_index_inverse() || test_observe() || test_clamp() || test_merge() ||
        test_classic_dump())
        return 1;
    printf("test_hist: all passed\n");
    return 0;
}
