// SPDX-License-Identifier: GPL-2.0
/* Aggregator tests (task 4.3): drive the lk_query_sink over synthetic
 * lk_query_obs and assert on the resulting Prometheus exposition. Covers the
 * flag -> code/counter mapping (Р23/Р25/Р28), the duration model's pipelined vs
 * standalone selection (Р25), normalisation into query="other", the error /
 * rows / truncated / txn / connection families, and the first-row histogram
 * flag. Durations are exact powers of two in seconds so their `_sum` prints
 * cleanly under %.17g.
 *
 * Since М5 the same harness covers the second observation profile (РH10): an
 * http connection's observations must land in latkit_http_* with the four
 * timings of РH5 split into their three families, and in none of the database
 * ones. */
#include <stdio.h>
#include <string.h>

#include "metrics.h"
#include "proto.h"
#include "selfstats.h"

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

    CHECK(has(buf, "latkit_queries_total{db=\"app\",user=\"alice\",proto=\"pg\",kind=\"simple\","
                   "code=\"ok\"} 1\n"));
    CHECK(has(buf, "latkit_query_duration_seconds_count{query=\"select ?\",db=\"app\","
                   "user=\"alice\",proto=\"pg\",code=\"ok\"} 1\n"));
    CHECK(has(buf, "latkit_query_duration_seconds_sum{query=\"select ?\",db=\"app\","
                   "user=\"alice\",proto=\"pg\",code=\"ok\"} 0.5\n"));
    CHECK(has(buf,
              "latkit_query_rows_total{query=\"select ?\",db=\"app\",user=\"alice\",proto=\"pg\"} "
              "3\n"));
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

    CHECK(has(buf, "latkit_queries_total{db=\"app\",user=\"alice\",proto=\"pg\",kind=\"simple\","
                   "code=\"error\"} 1\n"));
    CHECK(has(buf, "code=\"error\"} 1\n")); /* duration series carries code=error */
    CHECK(has(buf, "latkit_query_errors_total{sqlstate=\"22012\",db=\"app\",user=\"alice\","
                   "proto=\"pg\"} 1\n"));
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
                   "user=\"alice\",proto=\"pg\",code=\"ok\"} 1\n"));
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
                   "user=\"alice\",proto=\"pg\",code=\"ok\"} 0.5\n"));

    o.flags = LK_QO_PIPELINED; /* pipelined -> ts_complete = 0.25 */
    feed(pipelined, &o);
    dump(pipelined, buf, sizeof(buf));
    CHECK(has(buf, "latkit_query_duration_seconds_sum{query=\"select ?\",db=\"app\","
                   "user=\"alice\",proto=\"pg\",code=\"ok\"} 0.25\n"));

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

    CHECK(has(buf, "latkit_txn_duration_seconds_count{db=\"app\",user=\"alice\",proto=\"pg\","
                   "status=\"ok\"} 1\n"));
    CHECK(has(buf, "latkit_txn_duration_seconds_sum{db=\"app\",user=\"alice\",proto=\"pg\","
                   "status=\"ok\"} 0.5\n"));
    CHECK(has(buf, "latkit_txn_duration_seconds_count{db=\"app\",user=\"alice\",proto=\"pg\","
                   "status=\"aborted\"} 1\n"));
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
                   "user=\"alice\",proto=\"pg\"} 1\n"));
    CHECK(has(buf, "latkit_query_first_row_seconds_sum{query=\"select ?\",db=\"app\","
                   "user=\"alice\",proto=\"pg\"} 0.125\n"));
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

/* Labeled scalars (task 4.4, Р27): several label values of one name form a
 * single family — one HELP/TYPE header, one series line per value. */
static int test_labeled_scalars(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    char buf[65536];

    CHECK(m);
    lk_metrics_set_counter_l(m, "latkit_queries_dropped_total", "Dropped units.", "reason",
                             "resync", 3);
    lk_metrics_set_counter_l(m, "latkit_queries_dropped_total", NULL, "reason", "disconnect", 1);
    lk_metrics_set_counter_l(m, "latkit_queries_dropped_total", NULL, "reason", "overflow", 0);
    lk_metrics_set_counter_l(m, "latkit_queries_dropped_total", NULL, "reason", "resync",
                             5); /* overwrite */
    dump(m, buf, sizeof(buf));

    /* Exactly one HELP and one TYPE header for the whole family. */
    CHECK(strstr(buf, "# TYPE latkit_queries_dropped_total counter\n"));
    CHECK(!strstr(strstr(buf, "# TYPE latkit_queries_dropped_total counter\n") + 1,
                  "# TYPE latkit_queries_dropped_total"));
    CHECK(has(buf, "latkit_queries_dropped_total{reason=\"resync\"} 5\n"));
    CHECK(has(buf, "latkit_queries_dropped_total{reason=\"disconnect\"} 1\n"));
    CHECK(has(buf, "latkit_queries_dropped_total{reason=\"overflow\"} 0\n"));
    lk_metrics_free(m);
    return 0;
}

/* Providers (task 4.4): the callback runs at dump time and pours its series in;
 * the registry's own latkit_metric_series honesty gauge appears too. */
static void probe_provider(void *ctx, struct lk_metrics *m)
{
    (*(int *)ctx)++;
    lk_metrics_set_gauge(m, "test_probe", "Set by a provider.", 99);
}

static int test_providers(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    char buf[65536];
    int calls = 0;

    CHECK(m);
    lk_metrics_add_provider(m, probe_provider, &calls);

    dump(m, buf, sizeof(buf));
    CHECK(calls == 1); /* the provider ran exactly once for the dump */
    CHECK(has(buf, "test_probe 99\n"));
    CHECK(has(buf, "# TYPE latkit_metric_series gauge\n"));

    dump(m, buf, sizeof(buf));
    CHECK(calls == 2); /* ... and again on the next dump */
    lk_metrics_free(m);
    return 0;
}

/* A MySQL connection (conn->ops = lk_proto_my_ops) is labelled proto="mysql"
 * (М6): the facade resolves the protocol through the connection, not the port. */
static int test_mysql_proto_label(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    struct lk_conn myconn = {.cookie = 0x5151, .ops = &lk_proto_my_ops};
    char buf[65536];
    struct lk_query_obs o = {
        .ts_start_ns = 0,
        .ts_complete_ns = NS_250MS,
        .ts_ready_ns = NS_500MS,
        .text = "select 1",
        .text_len = 8,
        .rows = 1,
        .kind = LK_Q_SIMPLE,
    };

    CHECK(m);
    set_session("shop", "root");
    g_sink = lk_metrics_query_sink(m);
    g_sink->on_query(g_sink->ctx, &myconn, &g_sess, &o);
    dump(m, buf, sizeof(buf));

    CHECK(has(buf, "latkit_queries_total{db=\"shop\",user=\"root\",proto=\"mysql\",kind=\"simple\","
                   "code=\"ok\"} 1\n"));
    CHECK(has(buf, "latkit_query_duration_seconds_count{query=\"select ?\",db=\"shop\","
                   "user=\"root\",proto=\"mysql\",code=\"ok\"} 1\n"));
    /* on_txn also inherits the connection's protocol via the session cache. */
    g_sink->on_txn(g_sink->ctx, &myconn, 0, NS_500MS, 'T');
    dump(m, buf, sizeof(buf));
    CHECK(has(buf, "latkit_txn_duration_seconds_count{db=\"shop\",user=\"root\",proto=\"mysql\","
                   "status=\"ok\"} 1\n"));
    lk_metrics_free(m);
    return 0;
}

/* An HTTP connection reports through the http profile (РH9/РH10, М5): the four
 * timings become three families, the labels are the http ones, and none of it
 * touches latkit_query_*. The stamps below are the shape a POST produces — the
 * client spent 0.5 s uploading, the server answered 0.25 s after that. */
static int test_http_profile(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    struct lk_conn hconn = {.cookie = 0x8080, .ops = &lk_proto_http_ops};
    char buf[65536];
    struct lk_query_obs o = {
        .ts_start_ns = 0,
        .ts_req_done_ns = NS_500MS,
        .ts_first_row_ns = NS_500MS + NS_125MS,
        .ts_complete_ns = NS_500MS + NS_250MS,
        .ts_ready_ns = NS_500MS + NS_250MS,
        .text = "/orders/8123?token=secret",
        .text_len = 25,
        .bytes_in = 4096,
        .bytes_out = 700,
        .op = "POST",
        .route = "/orders/{id}",
        .route_len = 12,
        .route_fp = 0x1234,
        .err_code = 201,
        .kind = LK_Q_REQUEST,
    };

    CHECK(m);
    set_session("shop.example", ""); /* host -> the db slot; no --http-user */
    g_sink = lk_metrics_query_sink(m);
    g_sink->on_query(g_sink->ctx, &hconn, &g_sess, &o);
    dump(m, buf, sizeof(buf));

#define ID(m)                                                                                      \
    m "route=\"/orders/{id}\",method=\"POST\",host=\"shop.example\",user=\"-\",proto=\"http\""
    CHECK(has(buf, ID("latkit_http_requests_total{") ",status=\"2xx\"} 1\n"));
    /* duration is measured from the *end of the request* (РH5): 0.25 s, not the
     * 0.75 s the client experienced, and the upload is its own 0.5 s family. */
    CHECK(has(buf, ID("latkit_http_request_duration_seconds_sum{") ",code=\"ok\"} 0.25\n"));
    CHECK(has(buf, ID("latkit_http_ttfb_seconds_sum{") "} 0.125\n"));
    CHECK(has(buf, ID("latkit_http_request_upload_seconds_sum{") "} 0.5\n"));
    CHECK(has(buf, ID("latkit_http_bytes_total{") ",direction=\"in\"} 4096\n"));
    CHECK(has(buf, ID("latkit_http_bytes_total{") ",direction=\"out\"} 700\n"));
    CHECK(has(buf, ID("latkit_http_response_size_bytes_bucket{") ",le=\"1024\"} 1\n"));
#undef ID
    /* A 2xx is not an error, and nothing here is a query. */
    CHECK(!has(buf, "latkit_http_errors_total{"));
    CHECK(!has(buf, "proto=\"http\",kind=\"request\""));
    /* The raw target never leaves the observation: only the template is a label
     * (РH7/РH12), and the query string with it. */
    CHECK(!has(buf, "8123"));
    CHECK(!has(buf, "secret"));
    lk_metrics_free(m);
    return 0;
}

/* A 5xx is the server's error and a 4xx is the client's (РH10): both are in the
 * exact-code counter, only the 5xx is code="error". */
static int test_http_status_split(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    struct lk_conn hconn = {.cookie = 0x8081, .ops = &lk_proto_http_ops};
    char buf[65536];
    struct lk_query_obs o = {
        .ts_complete_ns = NS_250MS,
        .ts_ready_ns = NS_250MS,
        .op = "GET",
        .route = "/health",
        .route_len = 7,
        .route_fp = 0x99,
        .err_code = 404,
        .kind = LK_Q_REQUEST,
        .flags = LK_QO_CLIENT_ERR,
    };

    CHECK(m);
    set_session("", ""); /* no Host header: the label is "-", never empty */
    g_sink = lk_metrics_query_sink(m);
    g_sink->on_query(g_sink->ctx, &hconn, &g_sess, &o);
    o.err_code = 503;
    o.flags = LK_QO_ERROR;
    g_sink->on_query(g_sink->ctx, &hconn, &g_sess, &o);
    dump(m, buf, sizeof(buf));

    CHECK(has(buf, "latkit_http_requests_total{route=\"/health\",method=\"GET\",host=\"-\","
                   "user=\"-\",proto=\"http\",status=\"4xx\"} 1\n"));
    CHECK(has(buf, ",status=\"5xx\"} 1\n"));
    CHECK(has(buf, "latkit_http_request_duration_seconds_count{route=\"/health\",method=\"GET\","
                   "host=\"-\",user=\"-\",proto=\"http\",code=\"ok\"} 1\n")); /* the 404 */
    CHECK(has(buf, ",proto=\"http\",code=\"error\"} 1\n"));                   /* the 503 */
    CHECK(has(buf, "latkit_http_errors_total{code=\"404\",host=\"-\",user=\"-\",proto=\"http\"} "
                   "1\n"));
    CHECK(has(buf, "latkit_http_errors_total{code=\"503\","));
    lk_metrics_free(m);
    return 0;
}

/* An S3 connection reports through the s3 profile (РS7, PLAN-MINIO.md МS2).
 * The same observation shape as an HTTP one — it is the same exchange — read
 * under the S3 nouns, plus the three facts only this dialect produces: the
 * symbolic error code, the logical object size, and the request that is the
 * server's own business and is not an operation at all. */
static int test_s3_profile(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    struct lk_conn sconn = {.cookie = 0x9000, .ops = &lk_proto_s3_ops};
    char buf[65536];
    struct lk_query_obs o = {
        .ts_start_ns = 0,
        .ts_req_done_ns = NS_500MS,
        .ts_first_row_ns = NS_500MS + NS_125MS,
        .ts_complete_ns = NS_500MS + NS_250MS,
        .ts_ready_ns = NS_500MS + NS_250MS,
        .text = "/photos/2026/holiday.jpg",
        .text_len = 24,
        /* the aws-chunked case of РS6: 1050102 bytes of signed stream carrying a
         * 1 MiB object, and only one of the two is a size distribution */
        .bytes_in = 1050102,
        .obj_bytes = 1048576,
        .op = "PUT",
        .route = "PutObject",
        .route_len = 9,
        .route_fp = 0x5301,
        .err_code = 200,
        .kind = LK_Q_REQUEST,
    };

    CHECK(m);
    set_session("photos", "AKIALKROOT"); /* bucket -> db slot, access key -> user */
    g_sink = lk_metrics_query_sink(m);
    g_sink->on_query(g_sink->ctx, &sconn, &g_sess, &o);
    dump(m, buf, sizeof(buf));

#define ID(m) m "op=\"PutObject\",method=\"PUT\",bucket=\"photos\",user=\"AKIALKROOT\",proto=\"s3\""
    CHECK(has(buf, ID("latkit_s3_requests_total{") ",status=\"2xx\"} 1\n"));
    CHECK(has(buf, ID("latkit_s3_request_duration_seconds_sum{") ",code=\"ok\"} 0.25\n"));
    CHECK(has(buf, ID("latkit_s3_ttfb_seconds_sum{") "} 0.125\n"));
    CHECK(has(buf, ID("latkit_s3_request_upload_seconds_sum{") "} 0.5\n"));
    CHECK(has(buf, ID("latkit_s3_bytes_total{") ",direction=\"in\"} 1050102\n"));
    /* the object, not the stream that carried it, on the object grid */
    CHECK(has(buf, ID("latkit_s3_object_size_bytes_sum{") "} 1048576\n"));
    CHECK(has(buf, ID("latkit_s3_object_size_bytes_bucket{") ",le=\"1048576\"} 1\n"));
#undef ID
    /* the object key reached no label, exactly as РS2 promises */
    CHECK(!has(buf, "holiday"));
    CHECK(!has(buf, "latkit_http_"));

    /* A 404 with a code: the error counter names the failure, not the status. */
    o.route = "GetObject";
    o.route_len = 9;
    o.route_fp = 0x5302;
    o.op = "GET";
    o.err_code = 404;
    o.err_name = "NoSuchKey";
    o.obj_bytes = 0;
    o.flags = LK_QO_CLIENT_ERR;
    g_sink->on_query(g_sink->ctx, &sconn, &g_sess, &o);
    /* ... and one without: the status is the honest fallback (РS5). */
    o.err_name = NULL;
    o.err_code = 500;
    o.flags = LK_QO_ERROR;
    g_sink->on_query(g_sink->ctx, &sconn, &g_sess, &o);
    dump(m, buf, sizeof(buf));
    CHECK(has(buf, "latkit_s3_errors_total{s3code=\"NoSuchKey\",bucket=\"photos\","
                   "user=\"AKIALKROOT\",proto=\"s3\"} 1\n"));
    CHECK(has(buf, "latkit_s3_errors_total{s3code=\"500\","));
    /* a failing GET recorded no object size — an error document is not an
     * object, and neither is a listing */
    CHECK(!has(buf, "latkit_s3_object_size_bytes_count{op=\"GetObject\""));

    /* `/minio/health/live`: counted, and in nothing that says "requests" (РS2). */
    o.route = "internal";
    o.route_len = 8;
    o.route_fp = 0x5303;
    o.err_code = 200;
    o.err_name = NULL;
    o.flags = LK_QO_INTERNAL;
    g_sink->on_query(g_sink->ctx, &sconn, &g_sess, &o);
    dump(m, buf, sizeof(buf));
    CHECK(has(buf, "latkit_s3_internal_requests_total 1\n"));
    CHECK(!has(buf, "op=\"internal\""));
    lk_metrics_free(m);
    return 0;
}

/* The selfstats provider (task 4.4) emits the standard process_* series. */
static int test_selfstats_provider(void)
{
    struct lk_metrics *m = lk_metrics_new(NULL);
    struct lk_selfstats *ss = lk_selfstats_new();
    char buf[65536];

    CHECK(m && ss);
    lk_metrics_add_provider(m, lk_selfstats_provide, ss);
    dump(m, buf, sizeof(buf));

    CHECK(has(buf, "# TYPE process_cpu_seconds_total counter\n"));
    CHECK(has(buf, "process_cpu_seconds_total "));
    CHECK(has(buf, "# TYPE process_start_time_seconds gauge\n"));
    CHECK(has(buf, "process_resident_memory_bytes "));
    lk_selfstats_free(ss);
    lk_metrics_free(m);
    return 0;
}

int main(void)
{
    if (test_ok_query() || test_error_query() || test_no_duration() || test_no_text_other() ||
        test_truncated() || test_pipelined_duration() || test_txn() || test_first_row_flag() ||
        test_scalars() || test_labeled_scalars() || test_providers() || test_selfstats_provider() ||
        test_mysql_proto_label() || test_http_profile() || test_http_status_split() ||
        test_s3_profile())
        return 1;
    printf("test_metrics: all passed\n");
    return 0;
}
