// SPDX-License-Identifier: GPL-2.0
/* Exponential latency histogram (Р24, task 4.2). See hist.h for the grid and
 * the contract; this file is the arithmetic. */
#include "hist.h"

#include <math.h>

/* 2^(r/4) for r in 0..3, exact enough that dividing by two (frexp) reproduces
 * the index thresholds below bit-for-bit. */
static const double quarter_pow[4] = {
    1.0,
    1.189207115002721,  /* 2^(1/4) */
    1.4142135623730951, /* 2^(1/2) */
    1.681792830507429,  /* 2^(3/4) */
};

/* Floor division / non-negative remainder by 4 (C's / and % truncate toward
 * zero, which is wrong for negative k). */
static void divmod4(int k, int *q, int *r)
{
    int qq = k / 4, rr = k % 4;

    if (rr < 0) {
        rr += 4;
        qq -= 1;
    }
    *q = qq;
    *r = rr;
}

double lk_hist_bound(int k)
{
    int q, r;

    divmod4(k, &q, &r);
    return ldexp(quarter_pow[r], q); /* 2^(k/4) = 2^(r/4) * 2^q */
}

int lk_hist_index(double v)
{
    int e;
    /* v = m * 2^e, m in [0.5, 1). Then log2(v) = e + log2(m), and
     * floor(4*log2(v)) = 4*e + floor(4*log2(m)); 4*log2(m) in [-4, 0), so the
     * sub-bucket is one of -4..-1, picked by comparing m to 2^(-j/4). Boundary
     * values (v == bound(k)) give m == 2^(-r/4) exactly and the >= lands them in
     * bucket k — the grid is lower-inclusive. */
    double m = frexp(v, &e);
    int sub;

    if (m >= 0.8408964152537145) /* 2^(-1/4) */
        sub = -1;
    else if (m >= 0.7071067811865476) /* 2^(-1/2) */
        sub = -2;
    else if (m >= 0.5946035575013605) /* 2^(-3/4) */
        sub = -3;
    else
        sub = -4;
    return 4 * e + sub;
}

void lk_hist_observe(struct lk_hist *h, double v)
{
    int idx;

    h->count++;
    if (isnan(v) || v <= 0.0) { /* bit-flipped / missing timestamp */
        h->nonpos++;
        h->underflow++;
        return;
    }
    if (isinf(v)) {
        h->overflow++;
        return;
    }
    h->sum += v;
    idx = lk_hist_index(v);
    if (idx < LK_HIST_MIN_INDEX)
        h->underflow++;
    else if (idx >= LK_HIST_MAX_INDEX)
        h->overflow++;
    else
        h->bucket[idx - LK_HIST_MIN_INDEX]++;
}

void lk_hist_merge(struct lk_hist *dst, const struct lk_hist *src)
{
    for (int i = 0; i < LK_HIST_NBUCKETS; i++)
        dst->bucket[i] += src->bucket[i];
    dst->underflow += src->underflow;
    dst->overflow += src->overflow;
    dst->nonpos += src->nonpos;
    dst->sum += src->sum;
    dst->count += src->count;
}

/* Classic le boundaries: le = 2^j s (every 4th grid boundary -> factor 2). The
 * cumulative count for le=2^j is underflow plus every bucket with grid index
 * < 4j; `lt` is that 4j. Values are exact terminating decimals. */
static const struct {
    int lt; /* cumulate grid buckets with index < lt */
    const char *le;
} classic[] = {
    {-52, "0.0001220703125"},
    {-48, "0.000244140625"},
    {-44, "0.00048828125"},
    {-40, "0.0009765625"},
    {-36, "0.001953125"},
    {-32, "0.00390625"},
    {-28, "0.0078125"},
    {-24, "0.015625"},
    {-20, "0.03125"},
    {-16, "0.0625"},
    {-12, "0.125"},
    {-8, "0.25"},
    {-4, "0.5"},
    {0, "1"},
    {4, "2"},
    {8, "4"},
    {12, "8"},
    {16, "16"},
    {20, "32"},
};

static uint64_t cum_lt(const struct lk_hist *h, int lt)
{
    uint64_t c = h->underflow;
    int hi = lt < LK_HIST_MAX_INDEX ? lt : LK_HIST_MAX_INDEX;

    for (int k = LK_HIST_MIN_INDEX; k < hi; k++)
        c += h->bucket[k - LK_HIST_MIN_INDEX];
    return c;
}

void lk_hist_write(const struct lk_hist *h, FILE *f, const char *metric, const char *labelset)
{
    /* With a labelset the le pair follows a comma; without one it stands alone
     * inside the braces. */
    const char *sep = labelset[0] ? "," : "";
    size_t n = sizeof(classic) / sizeof(classic[0]);

    for (size_t i = 0; i < n; i++)
        fprintf(f, "%s_bucket{%s%sle=\"%s\"} %llu\n", metric, labelset, sep, classic[i].le,
                (unsigned long long)cum_lt(h, classic[i].lt));
    fprintf(f, "%s_bucket{%s%sle=\"+Inf\"} %llu\n", metric, labelset, sep,
            (unsigned long long)h->count);
    /* %.17g round-trips an IEEE-754 double and is deterministic across glibc. */
    fprintf(f, "%s_sum{%s} %.17g\n", metric, labelset, h->sum);
    fprintf(f, "%s_count{%s} %llu\n", metric, labelset, (unsigned long long)h->count);
}
