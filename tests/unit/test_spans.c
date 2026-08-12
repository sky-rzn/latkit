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
 *
 * Since М6 (РH11) the same collector builds a second shape — an HTTP *server*
 * span — and the tests at the bottom cover what is new about it: the semconv
 * attributes, the status rule (a 4xx is not an error), the adoption of an
 * inbound W3C trace context, parent-based sampling with its documented
 * asymmetry, and masked mode meaning "the route and nothing else".
 *
 * Pure: links the export lib (spans.c) + the lk_query_obs contract, no BPF. */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h> /* AF_INET for the connection tuple of an HTTP span */

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

/* ---- the HTTP span shape (РH11, PLAN-HTTP.md М6) -------------------------- */

static const uint8_t tp_trace[16] = {0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
                                     0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36};
static const uint8_t tp_parent[8] = {0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7};

/* One HTTP observation, in the shape http.c emits: a request/response exchange
 * with the four timings of РH5, a templated route beside the (already redacted)
 * target, and optionally the trace context it arrived under. */
static void feed_http(struct lk_spans *s, const struct lk_http_obs *hb, uint64_t start_ns,
                      uint64_t req_done_ns, uint64_t complete_ns, uint16_t status, uint16_t flags)
{
    const struct lk_query_sink *sink = lk_spans_sink(s);
    struct lk_conn c = {.cookie = 0x99, .ops = &lk_proto_http_ops};
    struct lk_query_obs o = {
        .ts_start_ns = start_ns,
        .ts_req_done_ns = req_done_ns,
        .ts_first_row_ns = req_done_ns + 1000,
        .ts_complete_ns = complete_ns,
        .text = "/orders/42?token=***&page=2",
        .text_len = 27,
        .bytes_in = 11,
        .bytes_out = 4096,
        .op = "GET",
        .route = "/orders/{id}",
        .route_len = 12,
        .route_fp = 0xabcdef,
        .http = hb,
        .err_code = status,
        .kind = LK_Q_REQUEST,
        .flags = flags,
    };

    /* A server-side capture: the peer of the connection is the client (РH2). */
    c.tuple.family = AF_INET;
    c.tuple.daddr[0] = 10;
    c.tuple.daddr[3] = 7;
    c.tuple.dport = 51000;
    c.tuple.sport = 8080;
    memset(&g_sess, 0, sizeof(g_sess));
    snprintf(g_sess.database, sizeof(g_sess.database), "%s", "shop.example");
    snprintf(g_sess.app, sizeof(g_sess.app), "%s", "curl/8.5.0");
    sink->on_query(sink->ctx, &c, &g_sess, &o);
}

/* Every attribute РH11 promises, and the two things that must *not* be there:
 * db.* material and an unredacted target. */
static int test_http_attrs(void)
{
    struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1};
    struct lk_spans *s = lk_spans_new(&cfg);
    struct lk_http_obs hb = {
        .req_id = "8f14e45fceea167a",
        .ctype = "application/json",
        .version = 1,
    };
    struct capture cap = {0};

    feed_http(s, &hb, 1000, 2000, 5000000, 200, 0);
    lk_spans_drain(s, cap_emit, &cap);
    EXPECT(cap.n == 1, "one http span drained");
    if (cap.n != 1) {
        lk_spans_free(s);
        return 0;
    }
    EXPECT(cap.spans[0].otel_kind == LK_OTEL_KIND_HTTP, "span speaks HTTP semconv");
    EXPECT(cap.spans[0].http != NULL, "http attributes attached");
    EXPECT(cap.spans[0].db_system == NULL, "no db.system on an HTTP span");
    EXPECT(!strcmp(cap.spans[0].name, "GET /orders/{id}"), "name is `method route`");
    EXPECT(!strcmp(cap.spans[0].http->route, "/orders/{id}"), "http.route is the template");
    EXPECT(!strcmp(cap.spans[0].http->method, "GET"), "http.request.method");
    EXPECT(cap.spans[0].http->status == 200, "http.response.status_code");
    EXPECT(!strcmp(cap.spans[0].http->host, "shop.example"), "server.address from the Host");
    EXPECT(!strcmp(cap.spans[0].http->ua, "curl/8.5.0"), "user_agent.original");
    EXPECT(!strcmp(cap.spans[0].http->client, "10.0.0.7"), "client.address from the tuple");
    EXPECT(cap.spans[0].http->client_port == 51000 && cap.spans[0].http->server_port == 8080,
           "ports from the tuple");
    EXPECT(!strcmp(cap.spans[0].http->req_id, "8f14e45fceea167a"), "the request id is kept");
    EXPECT(!strcmp(cap.spans[0].http->ctype, "application/json"), "the content type is kept");
    EXPECT(cap.spans[0].http->bytes_in == 11 && cap.spans[0].http->bytes_out == 4096,
           "body sizes both ways");
    EXPECT(!cap.spans[0].http->tls, "url.scheme is http on a plaintext connection");
    EXPECT(!cap.spans[0].error, "a 200 is not an error");
    /* url.path: the target as the handler redacted it (РH12) — the span copies,
     * it does not re-read the wire. */
    EXPECT(cap.n == 1 && strstr(cap.texts[0], "token=***"), "url.path carries the redacted query");
    EXPECT(cap.n == 1 && !strstr(cap.texts[0], "s3cr3t"), "no secret in url.path");
    lk_spans_free(s);
    return 0;
}

/* A 5xx is the server failing and sets the span status; a 4xx is the server
 * correctly saying no and does not (РH10). */
static int test_http_status(void)
{
    struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1};
    struct lk_spans *s = lk_spans_new(&cfg);
    struct lk_http_obs hb = {.version = 1};
    struct capture cap = {0};

    feed_http(s, &hb, 1000, 2000, 5000000, 500, LK_QO_ERROR);
    feed_http(s, &hb, 1000, 2000, 5000000, 404, LK_QO_CLIENT_ERR);
    lk_spans_drain(s, cap_emit, &cap);
    EXPECT(cap.n == 2, "two spans");
    EXPECT(cap.n == 2 && cap.spans[0].error && cap.spans[0].http->status == 500, "5xx is an error");
    EXPECT(cap.n == 2 && !cap.spans[1].error && cap.spans[1].http->client_error,
           "4xx is the client's, not the span's");
    lk_spans_free(s);
    return 0;
}

/* The span joins the caller's trace instead of starting one (РH11) — the whole
 * reason М6 exists. */
static int test_http_traceparent(void)
{
    struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1};
    struct lk_spans *s = lk_spans_new(&cfg);
    struct lk_http_obs hb = {
        .trace_id = tp_trace,
        .parent_id = tp_parent,
        .trace_flags = 0x01,
        .tracestate = "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",
        .tracestate_len = 39,
        .version = 1,
    };
    struct capture cap = {0};

    feed_http(s, &hb, 1000, 2000, 5000000, 200, 0);
    lk_spans_drain(s, cap_emit, &cap);
    EXPECT(cap.n == 1, "one span");
    if (cap.n != 1) {
        lk_spans_free(s);
        return 0;
    }
    EXPECT(!memcmp(cap.spans[0].trace_id, tp_trace, 16), "the caller's trace id is adopted");
    EXPECT(cap.spans[0].have_parent, "the span has a parent");
    EXPECT(!memcmp(cap.spans[0].parent_id, tp_parent, 8), "the caller's span is the parent");
    EXPECT(memcmp(cap.spans[0].span_id, tp_parent, 8) != 0, "our span id is our own");
    EXPECT(!strcmp(cap.spans[0].http->tstate, "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE"),
           "tracestate carried verbatim");

    /* No context: a standalone trace, exactly as before М6. */
    {
        struct lk_http_obs bare = {.version = 1};
        struct capture cap2 = {0};

        feed_http(s, &bare, 1000, 2000, 5000000, 200, 0);
        lk_spans_drain(s, cap_emit, &cap2);
        EXPECT(cap2.n == 1 && !cap2.spans[0].have_parent, "no traceparent, no parent");
        EXPECT(cap2.n == 1 && memcmp(cap2.spans[0].trace_id, tp_trace, 16) != 0,
               "and a trace id of our own");
    }
    lk_spans_free(s);
    return 0;
}

/* Parent-based sampling (РH11): the caller's decision wins over the ratio, and
 * the slow predicate still overrides an unsampled trace. */
static int test_http_parent_sampling(void)
{
    struct lk_http_obs on = {.trace_id = tp_trace, .parent_id = tp_parent, .trace_flags = 0x01};
    struct lk_http_obs off = {.trace_id = tp_trace, .parent_id = tp_parent, .trace_flags = 0x00};

    /* Ratio 1.0 would take everything — but an unsampled trace stays out. */
    {
        struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1};
        struct lk_spans *s = lk_spans_new(&cfg);

        feed_http(s, &off, 1000, 2000, 5000000, 200, 0);
        EXPECT(lk_spans_sampled_total(s) == 0, "sampled=0 is respected against ratio 1.0");
        lk_spans_free(s);
    }
    /* Ratio 0 would take nothing — but a sampled trace comes through, because a
     * trace with a hole where the server hop should be is worse than a span. */
    {
        struct lk_spans_cfg cfg = {.sample_ratio = 0.0, .seed = 1};
        struct lk_spans *s = lk_spans_new(&cfg);

        feed_http(s, &on, 1000, 2000, 5000000, 200, 0);
        EXPECT(lk_spans_sampled_total(s) == 1, "sampled=1 is respected against ratio 0");
        lk_spans_free(s);
    }
    /* The documented asymmetry: slow wins even over an unsampled trace. */
    {
        struct lk_spans_cfg cfg = {.sample_ratio = 0.0, .slow_ns = 1000000, .seed = 1};
        struct lk_spans *s = lk_spans_new(&cfg);

        feed_http(s, &off, 1000, 2000, 5000000, 200, 0);
        EXPECT(lk_spans_sampled_total(s) == 1, "a slow request is sampled anyway");
        lk_spans_free(s);
    }
    /* And the РH5 rule inside the predicate: the client's upload is not the
     * server's time, so a long upload with a fast answer is not "slow". */
    {
        struct lk_spans_cfg cfg = {.sample_ratio = 0.0, .slow_ns = 1000000, .seed = 1};
        struct lk_spans *s = lk_spans_new(&cfg);
        struct lk_http_obs bare = {.version = 1};

        feed_http(s, &bare, 1000, 9000000, 9100000, 200, 0);
        EXPECT(lk_spans_sampled_total(s) == 0, "a slow upload is not a slow server");
        lk_spans_free(s);
    }
    return 0;
}

/* --otlp-span-masked on an HTTP span means "the route and nothing else": there
 * are no literals to collapse in a URL, so the only honest masked form is to
 * drop the path (РH12). */
static int test_http_masked(void)
{
    struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1, .masked = true};
    struct lk_spans *s = lk_spans_new(&cfg);
    struct lk_http_obs hb = {.version = 1};
    struct capture cap = {0};

    feed_http(s, &hb, 1000, 2000, 5000000, 200, 0);
    lk_spans_drain(s, cap_emit, &cap);
    EXPECT(cap.n == 1 && cap.texts[0][0] == '\0', "masked mode carries no url.path");
    EXPECT(cap.n == 1 && !strcmp(cap.spans[0].http->route, "/orders/{id}"), "the route stays");
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
    test_http_attrs();
    test_http_status();
    test_http_traceparent();
    test_http_parent_sampling();
    test_http_masked();
    printf(failures ? "\n%d FAILURES\n" : "\nall span tests passed\n", failures);
    return failures ? 1 : 0;
}
