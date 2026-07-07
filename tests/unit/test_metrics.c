// SPDX-License-Identifier: GPL-2.0
/* Aggregator tests (task 4.3): drive the lk_query_sink over synthetic
 * lk_query_obs and assert on the resulting Prometheus exposition. Covers the
 * flag -> code/counter mapping (Р23/Р25/Р28), the duration model's pipelined vs
 * standalone selection (Р25), normalisation into query="other", the error /
 * rows / truncated / txn / connection families, and the first-row histogram
 * flag. Durations are exact powers of two in seconds so their `_sum` prints
 * cleanly under %.17g. */
#include <stdio.h>
#include <string.h>

#include "metrics.h"
#include "proto.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* Exact-in-double second durations, in ns. */
#define NS_500MS 500000000ULL
#define NS_250MS 250000000ULL
#define NS_125MS 125000000ULL

static const struct lk_query_sink *g_sink;

static struct lk_conn g_conn = {.cookie = 0xabcd1234};
static struct lk_session g_sess;

static void set_session(const char *db, const char *user)
{
    memset(&g_sess, 0, sizeof(g_sess));
    snprintf(g_sess.database, sizeof(g_sess.database), "%s", db);
    snprintf(g_sess.user, sizeof(g_sess.user), "%s", user);
    g_sess.complete = true;
}

static void feed(struct lk_metrics *m, const struct lk_query_obs *o)
{
    g_sink = lk_metrics_query_sink(m);
    g_sink->on_query(g_sink->ctx, &g_conn, &g_sess, o);
}

static size_t dump(struct lk_metrics *m, char *buf, size_t cap)
{
    FILE *f = tmpfile();
    size_t n;

    if (!f)
        return 0;
    lk_metrics_dump(m, f);
    rewind(f);
    n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    return n;
}

static int has(const char *hay, const char *needle)
{
    return strstr(hay, needle) != NULL;
}

/* A plain successful simple query -> queries_total(ok) + a duration + rows. */
static int test_ok_query(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    char buf[65536];
    struct lk_query_obs o = {
        .ts_start_ns = 0,
        .ts_complete_ns = NS_250MS,
        .ts_ready_ns = NS_500MS, /* standalone -> uses ts_ready = 0.5 s */
        .text = "select 1",
        .text_len = 8,
        .rows = 3,
        .kind = LK_Q_SIMPLE,
    };

    CHECK(m);
    set_session("app", "alice");
    feed(m, &o);
    dump(m, buf, sizeof(buf));

    CHECK(has(buf,
              "latkit_queries_total{db=\"app\",user=\"alice\",kind=\"simple\",code=\"ok\"} 1\n"));
    CHECK(has(buf, "latkit_query_duration_seconds_count{query=\"select ?\",db=\"app\","
                   "user=\"alice\",code=\"ok\"} 1\n"));
    CHECK(has(buf, "latkit_query_duration_seconds_sum{query=\"select ?\",db=\"app\","
                   "user=\"alice\",code=\"ok\"} 0.5\n"));
    CHECK(has(buf, "latkit_query_rows_total{query=\"select ?\",db=\"app\",user=\"alice\"} 3\n"));
    lk_metrics_free(m);
    return 0;
}

/* An ErrorResponse -> code=error on both queries_total and the duration, plus a
 * query-independent SQLSTATE counter. */
static int test_error_query(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    char buf[65536];
    struct lk_query_obs o = {
        .ts_start_ns = 0,
        .ts_complete_ns = NS_250MS,
        .ts_ready_ns = NS_500MS,
        .text = "select 1",
        .text_len = 8,
        .kind = LK_Q_SIMPLE,
        .flags = LK_QO_ERROR,
    };

    CHECK(m);
    set_session("app", "alice");
    memcpy(o.sqlstate, "22012", 6);
    feed(m, &o);
    dump(m, buf, sizeof(buf));

    CHECK(has(
        buf, "latkit_queries_total{db=\"app\",user=\"alice\",kind=\"simple\",code=\"error\"} 1\n"));
    CHECK(has(buf, "code=\"error\"} 1\n")); /* duration series carries code=error */
    CHECK(has(buf, "latkit_query_errors_total{sqlstate=\"22012\",db=\"app\",user=\"alice\"} 1\n"));
    lk_metrics_free(m);
    return 0;
}

/* ABORTED (killed by an earlier batch error) and CANCEL carry no latency: they
 * bump queries_total only, no duration series exists at all. */
static int test_no_duration(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    char buf[65536];
    struct lk_query_obs ab = {
        .text = "select 1", .text_len = 8, .kind = LK_Q_EXTENDED, .flags = LK_QO_ABORTED};
    struct lk_query_obs cancel = {.kind = LK_Q_CANCEL};

    CHECK(m);
    set_session("app", "alice");
    feed(m, &ab);
    feed(m, &cancel);
    dump(m, buf, sizeof(buf));

    CHECK(has(buf, "kind=\"extended\",code=\"aborted\"} 1\n"));
    CHECK(has(buf, "kind=\"cancel\",code=\"canceled\"} 1\n"));
    /* No duration observation was recorded -> no per-series histogram lines. */
    CHECK(!has(buf, "latkit_query_duration_seconds_count{"));
    lk_metrics_free(m);
    return 0;
}

/* NO_TEXT folds the duration into query="other" while still counting the kind
 * (Р28); the honesty counter latkit_queries_other_total reflects it. */
static int test_no_text_other(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    char buf[65536];
    struct lk_query_obs o = {
        .ts_start_ns = 0,
        .ts_complete_ns = NS_250MS,
        .ts_ready_ns = NS_500MS,
        .kind = LK_Q_EXTENDED,
        .flags = LK_QO_NO_TEXT,
    };

    CHECK(m);
    set_session("app", "alice");
    feed(m, &o);
    dump(m, buf, sizeof(buf));

    CHECK(has(buf, "kind=\"extended\",code=\"ok\"} 1\n"));
    CHECK(has(buf, "latkit_query_duration_seconds_count{query=\"other\",db=\"app\","
                   "user=\"alice\",code=\"ok\"} 1\n"));
    CHECK(has(buf, "latkit_queries_other_total 1\n"));
    lk_metrics_free(m);
    return 0;
}

/* A capture-budget prefix (TEXT_TRUNC) increments the truncation counter. */
static int test_truncated(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    char buf[65536];
    struct lk_query_obs o = {
        .ts_start_ns = 0,
        .ts_complete_ns = NS_250MS,
        .ts_ready_ns = NS_500MS,
        .text = "select 1",
        .text_len = 8,
        .kind = LK_Q_SIMPLE,
        .flags = LK_QO_TEXT_TRUNC,
    };

    CHECK(m);
    set_session("app", "alice");
    feed(m, &o);
    dump(m, buf, sizeof(buf));
    CHECK(has(buf, "latkit_queries_truncated_total 1\n"));
    lk_metrics_free(m);
    return 0;
}

/* Duration model (Р25): a standalone unit uses ts_ready, a pipelined unit uses
 * ts_complete. Same timestamps, different flag -> different `_sum`. */
static int test_pipelined_duration(void)
{
    char buf[65536];
    struct lk_query_obs o = {
        .ts_start_ns = 0,
        .ts_complete_ns = NS_250MS, /* 0.25 s */
        .ts_ready_ns = NS_500MS,    /* 0.5 s */
        .text = "select 1",
        .text_len = 8,
        .kind = LK_Q_EXTENDED,
    };
    struct lk_metrics *standalone = lk_metrics_new(NULL);
    struct lk_metrics *pipelined = lk_metrics_new(NULL);

    CHECK(standalone && pipelined);
    set_session("app", "alice");

    feed(standalone, &o); /* not pipelined -> ts_ready = 0.5 */
    dump(standalone, buf, sizeof(buf));
    CHECK(has(buf, "latkit_query_duration_seconds_sum{query=\"select ?\",db=\"app\","
                   "user=\"alice\",code=\"ok\"} 0.5\n"));

    o.flags = LK_QO_PIPELINED; /* pipelined -> ts_complete = 0.25 */
    feed(pipelined, &o);
    dump(pipelined, buf, sizeof(buf));
    CHECK(has(buf, "latkit_query_duration_seconds_sum{query=\"select ?\",db=\"app\","
                   "user=\"alice\",code=\"ok\"} 0.25\n"));

    lk_metrics_free(standalone);
    lk_metrics_free(pipelined);
    return 0;
}

/* on_txn labels the span with the session cached at on_session/on_query time,
 * and maps the closing status T->ok, E->aborted. */
static int test_txn(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    char buf[65536];

    CHECK(m);
    set_session("app", "alice");
    g_sink = lk_metrics_query_sink(m);
    g_sink->on_session(g_sink->ctx, &g_conn, &g_sess);
    g_sink->on_txn(g_sink->ctx, &g_conn, 0, NS_500MS, 'T'); /* committed */
    g_sink->on_txn(g_sink->ctx, &g_conn, 0, NS_250MS, 'E'); /* rolled back */
    dump(m, buf, sizeof(buf));

    CHECK(
        has(buf, "latkit_txn_duration_seconds_count{db=\"app\",user=\"alice\",status=\"ok\"} 1\n"));
    CHECK(
        has(buf, "latkit_txn_duration_seconds_sum{db=\"app\",user=\"alice\",status=\"ok\"} 0.5\n"));
    CHECK(
        has(buf,
            "latkit_txn_duration_seconds_count{db=\"app\",user=\"alice\",status=\"aborted\"} 1\n"));
    lk_metrics_free(m);
    return 0;
}

/* The first-row histogram is opt-in: absent by default, present with the flag. */
static int test_first_row_flag(void)
{
    struct lk_metrics_cfg cfg;
    struct lk_query_obs o = {
        .ts_start_ns = 0,
        .ts_first_row_ns = NS_125MS, /* 0.125 s to first row */
        .ts_complete_ns = NS_250MS,
        .ts_ready_ns = NS_500MS,
        .text = "select 1",
        .text_len = 8,
        .kind = LK_Q_SIMPLE,
    };
    struct lk_metrics *off = lk_metrics_new(NULL);
    struct lk_metrics *on;
    char buf[65536];

    lk_metrics_cfg_defaults(&cfg);
    cfg.first_row_hist = true;
    on = lk_metrics_new(&cfg);
    CHECK(off && on);
    set_session("app", "alice");

    feed(off, &o);
    dump(off, buf, sizeof(buf));
    CHECK(!has(buf, "latkit_query_first_row_seconds"));

    feed(on, &o);
    dump(on, buf, sizeof(buf));
    CHECK(has(buf, "latkit_query_first_row_seconds_count{query=\"select ?\",db=\"app\","
                   "user=\"alice\"} 1\n"));
    CHECK(has(buf, "latkit_query_first_row_seconds_sum{query=\"select ?\",db=\"app\","
                   "user=\"alice\"} 0.125\n"));
    lk_metrics_free(off);
    lk_metrics_free(on);
    return 0;
}

/* Flat scalars (connections now, self-metrics in 4.4): idempotent absolute
 * writes, dumped as valid counter/gauge families. */
static int test_scalars(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    char buf[65536];

    CHECK(m);
    lk_metrics_set_gauge(m, "latkit_connections_active", "Active.", 7);
    lk_metrics_set_counter(m, "latkit_connections_opened_total", "Opened.", 42);
    lk_metrics_set_gauge(m, "latkit_connections_active", "Active.", 5); /* overwrite */
    dump(m, buf, sizeof(buf));

    CHECK(has(buf, "# TYPE latkit_connections_active gauge\n"));
    CHECK(has(buf, "latkit_connections_active 5\n"));
    CHECK(has(buf, "# TYPE latkit_connections_opened_total counter\n"));
    CHECK(has(buf, "latkit_connections_opened_total 42\n"));
    lk_metrics_free(m);
    return 0;
}

int main(void)
{
    if (test_ok_query() || test_error_query() || test_no_duration() || test_no_text_other() ||
        test_truncated() || test_pipelined_duration() || test_txn() || test_first_row_flag() ||
        test_scalars())
        return 1;
    printf("test_metrics: all passed\n");
    return 0;
}
