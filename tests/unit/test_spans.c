// SPDX-License-Identifier: GPL-2.0
/* Span collector tests (task 5.3, Р32): drive the lk_query_sink over synthetic
 * lk_query_obs and assert on the sampling predicates and the ring. Covers:
 *   - a fixed seed makes sampling deterministic (same set twice) and ratio
 *     bounds hold (0 -> none, 1 -> all eligible);
 *   - the slow-ms predicate is independent of the ratio;
 *   - a query with no measurable duration is never sampled;
 *   - the ring drops the newest when full (latkit_spans_dropped_total);
 *   - NO_TEXT observations sample with a NULL text and empty name;
 *   - masked mode stores the normalised (literal-free) text as db.query.text;
 *   - raw mode stores the raw SQL and the normalised name.
 * Pure: links the export lib (spans.c) + the lk_query_obs contract, no BPF. */
#include <stdio.h>
#include <string.h>

#include "proto.h"
#include "spans.h"

static int failures;
#define EXPECT(cond, msg)                                                                          \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);                                   \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

static struct lk_session g_sess;

static void set_session(const char *db, const char *user)
{
    memset(&g_sess, 0, sizeof(g_sess));
    snprintf(g_sess.database, sizeof(g_sess.database), "%s", db);
    snprintf(g_sess.user, sizeof(g_sess.user), "%s", user);
    g_sess.complete = true;
}

/* Feed one observation with the given cookie / timings / text. */
static void feed(struct lk_spans *s, uint64_t cookie, uint64_t start_ns, uint64_t dur_ns,
                 const char *text, uint16_t flags, const char *sqlstate)
{
    const struct lk_query_sink *sink = lk_spans_sink(s);
    struct lk_conn c = {.cookie = cookie};
    struct lk_query_obs o = {
        .ts_start_ns = start_ns,
        .ts_complete_ns = dur_ns ? start_ns + dur_ns : 0,
        .text = text,
        .text_len = text ? (uint32_t)strlen(text) : 0,
        .rows = 2,
        .kind = LK_Q_SIMPLE,
        .flags = flags,
    };

    if (sqlstate)
        snprintf(o.sqlstate, sizeof(o.sqlstate), "%s", sqlstate);
    sink->on_query(sink->ctx, &c, &g_sess, &o);
}

/* Drain-capture: copy the drained spans into a caller array. */
struct capture {
    struct lk_span spans[64];
    char texts[64][256];
    unsigned n;
};

static void cap_emit(void *ctx, const struct lk_span *sp)
{
    struct capture *cap = ctx;

    if (cap->n >= 64)
        return;
    cap->spans[cap->n] = *sp;
    cap->texts[cap->n][0] = '\0';
    if (sp->text && sp->text_len < sizeof(cap->texts[0])) {
        memcpy(cap->texts[cap->n], sp->text, sp->text_len);
        cap->texts[cap->n][sp->text_len] = '\0';
    }
    cap->spans[cap->n].text = cap->texts[cap->n]; /* re-point to our stable copy */
    cap->n++;
}

/* ---- determinism + ratio bounds ------------------------------------------ */

static uint64_t run_ratio(double ratio, uint64_t seed)
{
    struct lk_spans_cfg cfg = {.sample_ratio = ratio, .seed = seed};
    struct lk_spans *s = lk_spans_new(&cfg);
    uint64_t n;

    for (uint64_t i = 0; i < 1000; i++)
        feed(s, 0x1000 + i, 1000 + i * 7, 1000000, "select 1", 0, NULL);
    n = lk_spans_sampled_total(s);
    lk_spans_free(s);
    return n;
}

static int test_ratio(void)
{
    set_session("db", "u");

    /* Same seed + same input -> identical sampled count (deterministic hash). */
    EXPECT(run_ratio(0.5, 42) == run_ratio(0.5, 42), "sampling deterministic under a fixed seed");
    /* A different seed generally shifts which queries are picked. */
    EXPECT(run_ratio(0.5, 42) != run_ratio(0.5, 43) || run_ratio(0.5, 42) != run_ratio(0.5, 99),
           "seed changes the sampled set");
    /* Ratio bounds: 1.0 samples every eligible query, 0.0 samples none. */
    EXPECT(run_ratio(1.0, 7) == 1000, "ratio 1.0 samples all");
    EXPECT(run_ratio(0.0, 7) == 0, "ratio 0.0 samples none");
    /* ~half at 0.5, generous tolerance. */
    {
        uint64_t n = run_ratio(0.5, 7);

        EXPECT(n > 350 && n < 650, "ratio 0.5 is roughly half");
    }
    return 0;
}

/* ---- slow predicate ------------------------------------------------------ */

static int test_slow(void)
{
    struct lk_spans_cfg cfg = {.sample_ratio = 0.0, .slow_ns = 100000000ULL /* 100 ms */};
    struct lk_spans *s = lk_spans_new(&cfg);

    set_session("db", "u");
    feed(s, 1, 1000, 50000000ULL, "select 1", 0, NULL);  /* 50 ms  -> no  */
    feed(s, 2, 2000, 200000000ULL, "select 2", 0, NULL); /* 200 ms -> yes */
    feed(s, 3, 3000, 0, "select 3", 0, NULL);            /* no duration -> no */
    EXPECT(lk_spans_sampled_total(s) == 1, "only the slow query sampled");
    EXPECT(lk_spans_queued(s) == 1, "one span queued");
    lk_spans_free(s);
    return 0;
}

/* ---- ring overflow ------------------------------------------------------- */

static int test_overflow(void)
{
    struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1};
    struct lk_spans *s = lk_spans_new(&cfg);
    const unsigned extra = 10;

    set_session("db", "u");
    for (unsigned i = 0; i < LK_SPAN_BUF + extra; i++)
        feed(s, 0x2000 + i, 1000 + i, 1000000, "select 1", 0, NULL);

    EXPECT(lk_spans_sampled_total(s) == LK_SPAN_BUF + extra, "all sampled counted");
    EXPECT(lk_spans_dropped_total(s) == extra, "overflow dropped the newest");
    EXPECT(lk_spans_queued(s) == LK_SPAN_BUF, "ring full at capacity");
    lk_spans_free(s);
    return 0;
}

/* ---- text handling: raw, masked, NO_TEXT, error -------------------------- */

static int test_text(void)
{
    set_session("appdb", "alice");

    /* Raw mode: db.query.text is the raw SQL; name is normalised. */
    {
        struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1};
        struct lk_spans *s = lk_spans_new(&cfg);
        struct capture cap = {0};

        feed(s, 1, 1000, 5000000, "SELECT 42", 0, NULL);
        lk_spans_drain(s, cap_emit, &cap);
        EXPECT(cap.n == 1, "one span drained");
        EXPECT(cap.n == 1 && !strcmp(cap.texts[0], "SELECT 42"), "raw text preserved");
        EXPECT(cap.n == 1 && !strcmp(cap.spans[0].name, "select ?"), "name normalised");
        EXPECT(cap.n == 1 && !strcmp(cap.spans[0].db, "appdb"), "db.namespace set");
        EXPECT(cap.n == 1 && !strcmp(cap.spans[0].user, "alice"), "db.user set");
        EXPECT(lk_spans_queued(s) == 0, "ring emptied by drain");
        lk_spans_free(s);
    }

    /* Masked mode: db.query.text is the normalised (literal-free) SQL. */
    {
        struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1, .masked = true};
        struct lk_spans *s = lk_spans_new(&cfg);
        struct capture cap = {0};

        feed(s, 1, 1000, 5000000, "SELECT 42", 0, NULL);
        lk_spans_drain(s, cap_emit, &cap);
        EXPECT(cap.n == 1 && !strcmp(cap.texts[0], "select ?"), "masked text has no literal");
        EXPECT(cap.n == 1 && !strstr(cap.texts[0], "42"), "no literal leaked in masked mode");
        lk_spans_free(s);
    }

    /* NO_TEXT: sampled, but no db.query.text and empty name. */
    {
        struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1};
        struct lk_spans *s = lk_spans_new(&cfg);
        struct capture cap = {0};

        feed(s, 1, 1000, 5000000, NULL, LK_QO_NO_TEXT, NULL);
        EXPECT(lk_spans_sampled_total(s) == 1, "NO_TEXT query still sampled");
        lk_spans_drain(s, cap_emit, &cap);
        EXPECT(cap.n == 1 && cap.spans[0].text == cap.texts[0] && cap.texts[0][0] == '\0',
               "NO_TEXT span has no text");
        EXPECT(cap.n == 1 && cap.spans[0].name[0] == '\0', "NO_TEXT span has empty name");
        lk_spans_free(s);
    }

    /* Error: status + sqlstate captured. */
    {
        struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1};
        struct lk_spans *s = lk_spans_new(&cfg);
        struct capture cap = {0};

        feed(s, 1, 1000, 5000000, "select 1/0", LK_QO_ERROR, "22012");
        lk_spans_drain(s, cap_emit, &cap);
        EXPECT(cap.n == 1 && cap.spans[0].error, "error flag set");
        EXPECT(cap.n == 1 && !strcmp(cap.spans[0].sqlstate, "22012"), "sqlstate captured");
        lk_spans_free(s);
    }
    return 0;
}

/* A MySQL connection stamps the span's db_system and, on error, the vendor
 * errno alongside the SQLSTATE (М6). */
static int test_mysql_span(void)
{
    struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1};
    struct lk_spans *s = lk_spans_new(&cfg);
    struct capture cap = {0};
    const struct lk_query_sink *sink = lk_spans_sink(s);
    struct lk_conn c = {.cookie = 7, .ops = &lk_proto_my_ops};
    struct lk_query_obs o = {
        .ts_start_ns = 1000,
        .ts_complete_ns = 1000 + 5000000,
        .text = "select 1/0",
        .text_len = 10,
        .kind = LK_Q_SIMPLE,
        .flags = LK_QO_ERROR,
        .err_code = 1365, /* ER_DIVISION_BY_ZERO */
    };

    set_session("shop", "root");
    snprintf(o.sqlstate, sizeof(o.sqlstate), "%s", "22012");
    sink->on_query(sink->ctx, &c, &g_sess, &o);
    lk_spans_drain(s, cap_emit, &cap);
    EXPECT(cap.n == 1 && cap.spans[0].db_system && !strcmp(cap.spans[0].db_system, "mysql"),
           "span db_system = mysql");
    EXPECT(cap.n == 1 && cap.spans[0].err_code == 1365, "span carries mysql errno");
    EXPECT(cap.n == 1 && !strcmp(cap.spans[0].sqlstate, "22012"), "span keeps sqlstate too");
    lk_spans_free(s);
    return 0;
}

/* ---- text truncation ----------------------------------------------------- */

static int test_text_max(void)
{
    struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1, .text_max = 4};
    struct lk_spans *s = lk_spans_new(&cfg);
    struct capture cap = {0};

    set_session("db", "u");
    feed(s, 1, 1000, 5000000, "select abcdefgh", 0, NULL);
    lk_spans_drain(s, cap_emit, &cap);
    EXPECT(cap.n == 1 && cap.spans[0].text_len == 4, "text capped at text_max");
    lk_spans_free(s);
    return 0;
}

int main(void)
{
    test_ratio();
    test_slow();
    test_overflow();
    test_text();
    test_text_max();
    test_mysql_span();
    printf(failures ? "\n%d FAILURES\n" : "\nall span tests passed\n", failures);
    return failures ? 1 : 0;
}
