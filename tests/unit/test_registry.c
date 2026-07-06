// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the series registry (task 4.2, Р23). Drives lk_reg_observe and
 * checks the three cardinality defences and their invariants:
 *
 *   - overflow past K routes a brand-new fingerprint to query="other";
 *   - a fingerprint that returns after eviction restarts its histogram from
 *     zero (an ordinary counter reset), while `other` keeps the old mass;
 *   - the doorkeeper drops one-shot fingerprints: a flood of single-appearance
 *     queries never evicts the working set;
 *   - nothing is ever lost: sum of every series' count == total observations,
 *     across arbitrary eviction (the monotonicity invariant);
 *   - the (db,user) dimension limit spills to (other,other);
 *   - the dump is valid text format with stable, escaped labels. */
#include <stdio.h>
#include <string.h>

#include "registry.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static struct lk_registry *reg(uint32_t k, uint32_t dims)
{
    struct lk_metrics_cfg c;

    lk_metrics_cfg_defaults(&c);
    c.top_queries = k;
    c.max_session_dims = dims;
    return lk_reg_new(&c);
}

static void obs(struct lk_registry *r, uint64_t fp, const char *label, const char *db,
                const char *user, enum lk_code code)
{
    lk_reg_observe(r, fp, label, db, user, code, 0.2);
}

/* Capture a dump into buf; returns bytes read. */
static size_t dump(struct lk_registry *r, char *buf, size_t cap)
{
    FILE *f = tmpfile();
    size_t n;

    if (!f)
        return 0;
    lk_reg_dump(r, f);
    rewind(f);
    n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    return n;
}

static int contains(const char *hay, const char *needle) { return strstr(hay, needle) != NULL; }

/* A new fingerprint at a full dictionary lands in query="other". */
static int test_overflow_to_other(void)
{
    struct lk_registry *r = reg(4, 8);

    CHECK(r);
    for (uint64_t i = 1; i <= 4; i++)
        obs(r, i, "q", "db", "u", LK_CODE_OK);
    CHECK(lk_reg_n_queries(r) == 4);

    obs(r, 5, "q", "db", "u", LK_CODE_OK); /* dict full, first sight -> other */
    CHECK(!lk_reg_has_fp(r, 5));
    CHECK(lk_reg_n_queries(r) == 4);
    CHECK(lk_reg_other_obs(r) == 1);
    CHECK(lk_reg_total_obs(r) == 5);
    CHECK(lk_reg_series_count_sum(r) == 5);
    lk_reg_free(r);
    return 0;
}

/* An evicted fingerprint that comes back restarts from zero; `other` keeps the
 * mass folded out of it. */
static int test_evict_reset(void)
{
    struct lk_registry *r = reg(2, 8);

    CHECK(r);
    obs(r, 10, "A", "db", "u", LK_CODE_OK); /* admit A, count it 3x */
    obs(r, 10, "A", "db", "u", LK_CODE_OK);
    obs(r, 10, "A", "db", "u", LK_CODE_OK);
    obs(r, 20, "B", "db", "u", LK_CODE_OK); /* admit B; dict {A(LRU),B} full */
    CHECK(lk_reg_fp_count(r, 10) == 3);

    obs(r, 30, "C", "db", "u", LK_CODE_OK); /* C first sight -> other + doorkeeper */
    obs(r, 30, "C", "db", "u", LK_CODE_OK); /* C admitted, evicts A (folds 3 to other) */
    CHECK(!lk_reg_has_fp(r, 10));
    CHECK(lk_reg_has_fp(r, 30));

    obs(r, 10, "A", "db", "u", LK_CODE_OK); /* A back: first sight -> other + doorkeeper */
    obs(r, 10, "A", "db", "u", LK_CODE_OK); /* A re-admitted, evicts B */
    CHECK(lk_reg_has_fp(r, 10));
    CHECK(lk_reg_fp_count(r, 10) == 1); /* fresh: only the re-admitting observation */
    CHECK(!lk_reg_has_fp(r, 20));

    /* 8 observations total, none lost across the two evictions */
    CHECK(lk_reg_total_obs(r) == 8);
    CHECK(lk_reg_series_count_sum(r) == 8);
    lk_reg_free(r);
    return 0;
}

/* A flood of one-shot fingerprints cannot wash out the working set. */
static int test_doorkeeper(void)
{
    struct lk_registry *r = reg(2, 8);

    CHECK(r);
    obs(r, 10, "A", "db", "u", LK_CODE_OK);
    obs(r, 20, "B", "db", "u", LK_CODE_OK); /* working set {A,B}, full */

    for (uint64_t i = 0; i < 1000; i++)
        obs(r, 1000 + i, "adhoc", "db", "u", LK_CODE_OK); /* each seen once */

    CHECK(lk_reg_n_queries(r) == 2);
    CHECK(lk_reg_has_fp(r, 10));
    CHECK(lk_reg_has_fp(r, 20));
    CHECK(lk_reg_other_obs(r) == 1000);
    CHECK(lk_reg_total_obs(r) == 1002);
    CHECK(lk_reg_series_count_sum(r) == 1002); /* monotone: nothing dropped */
    lk_reg_free(r);
    return 0;
}

/* Unique fingerprints stress: rows stay bounded by K, memory does not grow. */
static int test_cardinality_ceiling(void)
{
    struct lk_registry *r = reg(64, 8);
    const uint64_t n = 100000;

    CHECK(r);
    for (uint64_t i = 1; i <= n; i++)
        obs(r, i, "q", "db", "u", LK_CODE_OK);

    CHECK(lk_reg_n_queries(r) == 64);      /* first 64 admitted, rest -> other */
    CHECK(lk_reg_n_series(r) == 64 + 1);   /* one series each + the other row */
    CHECK(lk_reg_total_obs(r) == n);
    CHECK(lk_reg_series_count_sum(r) == n);
    lk_reg_free(r);
    return 0;
}

/* The (db,user) product is capped: extra pairs spill to (other,other). */
static int test_dim_limit(void)
{
    struct lk_registry *r = reg(8, 2);
    char buf[16384];

    CHECK(r);
    obs(r, 1, "q", "db1", "u1", LK_CODE_OK);
    obs(r, 1, "q", "db2", "u2", LK_CODE_OK);
    obs(r, 1, "q", "db3", "u3", LK_CODE_OK); /* third pair over the limit */
    CHECK(lk_reg_n_dims(r) == 2);

    dump(r, buf, sizeof(buf));
    CHECK(contains(buf, "db=\"db1\",user=\"u1\""));
    CHECK(contains(buf, "db=\"other\",user=\"other\""));
    CHECK(!contains(buf, "db=\"db3\""));
    lk_reg_free(r);
    return 0;
}

/* Dump shape: HELP/TYPE, per-series bucket/sum/count, escaped labels. */
static int test_dump_format(void)
{
    struct lk_registry *r = reg(8, 8);
    char buf[16384];

    CHECK(r);
    obs(r, 1, "select ?", "app", "alice", LK_CODE_OK);
    obs(r, 1, "select ?", "app", "alice", LK_CODE_OK);
    obs(r, 2, "upd\"ate", "app", "alice", LK_CODE_ERROR); /* label needs escaping */

    dump(r, buf, sizeof(buf));
    CHECK(contains(buf, "# HELP latkit_query_duration_seconds "));
    CHECK(contains(buf, "# TYPE latkit_query_duration_seconds histogram\n"));
    CHECK(contains(buf,
                   "latkit_query_duration_seconds_count{query=\"select ?\",db=\"app\","
                   "user=\"alice\",code=\"ok\"} 2\n"));
    CHECK(contains(buf, "code=\"error\""));
    CHECK(contains(buf, "query=\"upd\\\"ate\"")); /* the " is backslash-escaped */
    CHECK(contains(buf, "le=\"+Inf\""));
    lk_reg_free(r);
    return 0;
}

int main(void)
{
    if (test_overflow_to_other() || test_evict_reset() || test_doorkeeper() ||
        test_cardinality_ceiling() || test_dim_limit() || test_dump_format())
        return 1;
    printf("test_registry: all passed\n");
    return 0;
}
