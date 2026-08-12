// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the request head (PLAN-HTTP.md М3, src/proto/http/http_req.c)
 * — what a unit and a session are made of, asserted on the observation that
 * comes out the far end rather than on the parser's internals, because the
 * observation is the contract.
 *
 * The matrix the plan asks for: degraded input, truncated heads, missing
 * headers. The cases beyond it are the ones the М0 corpus proved are real —
 * absolute-form targets, an HTTP/1.0 request with no Host at all, a header
 * block split across capture events, and the two privacy rules (`Authorization`
 * read only when asked for, `Cookie` never).
 *
 * Every test drives the production chain through http_obs.h, so a "field" here
 * means "what a metric or a span would carry", not "what a function returned". */
#include "http_obs.h"

/* A minimal response, so the unit closes and its observation is emitted. */
#define RESP200 "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

static void answer(__u64 ts)
{
    h_call(LK_DIR_SEND, RESP200, ts);
}

/* --- the base case: what an ordinary GET reports -------------------------- */

static int test_basic_fields(void)
{
    h_reset();
    h_call(LK_DIR_RECV,
           "GET /orders/42?x=1 HTTP/1.1\r\n"
           "Host: shop.example\r\n"
           "User-Agent: curl/8.5.0\r\n"
           "Accept: */*\r\n\r\n",
           1000);
    answer(2000);

    CHECK(h_nobs == 1);
    CHECK(!strcmp(h_obs[0].method, "GET"));
    CHECK(h_obs[0].kind == LK_Q_REQUEST);
    CHECK(h_target_is(0, "/orders/42?x=1"));
    CHECK(!strcmp(h_obs[0].host, "shop.example"));
    CHECK(!strcmp(h_obs[0].user, "")); /* no identity on the wire, and none invented */

    /* The session is emitted once, off the first head, and carries the labels
     * the connection opened with. */
    CHECK(h_nsess == 1);
    CHECK(!strcmp(h_sess[0].host, "shop.example"));
    CHECK(!strcmp(h_sess[0].app, "curl/8.5.0"));
    CHECK(!strcmp(h_sess[0].ver, "HTTP/1.1"));
    CHECK(h_sess[0].complete);
    return 0;
}

/* Two requests on one keep-alive connection produce one session, not two. */
static int test_session_once(void)
{
    h_reset();
    h_call(LK_DIR_RECV, "GET /a HTTP/1.1\r\nHost: h1\r\nUser-Agent: ua1\r\n\r\n", 1000);
    answer(2000);
    h_call(LK_DIR_RECV, "GET /b HTTP/1.1\r\nHost: h2\r\nUser-Agent: ua2\r\n\r\n", 3000);
    answer(4000);

    CHECK(h_nsess == 1);
    CHECK(!strcmp(h_sess[0].host, "h1"));
    /* ... but each *observation* reports its own request's host: one socket can
     * serve several name-based virtual hosts, and folding them onto the first
     * one would put the wrong label on real traffic (РH10). */
    CHECK(h_nobs == 2);
    CHECK(!strcmp(h_obs[0].host, "h1") && !strcmp(h_obs[1].host, "h2"));
    return 0;
}

/* --- request-target forms ------------------------------------------------- */

static int test_target_forms(void)
{
    h_reset();
    /* absolute-form: the authority beats Host, which here names a proxy. */
    h_call(LK_DIR_RECV, "GET http://real.example/orders/42 HTTP/1.1\r\nHost: proxy.local\r\n\r\n",
           1000);
    answer(2000);
    CHECK(h_nobs == 1);
    CHECK(h_target_is(0, "/orders/42"));
    CHECK(!strcmp(h_obs[0].host, "real.example"));

    h_reset();
    /* asterisk-form: a target, not an authority, and not a route to template. */
    h_call(LK_DIR_RECV, "OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].method, "OPTIONS"));
    CHECK(h_target_is(0, "*"));

    h_reset();
    /* authority-form (CONNECT): there is no path, so there is no text — an
     * empty route would be a lie, LK_QO_NO_TEXT is the truth. */
    h_call(LK_DIR_RECV, "CONNECT tunnel.example:443 HTTP/1.1\r\nHost: tunnel.example:443\r\n\r\n",
           1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 Connection Established\r\n\r\n", 2000);
    CHECK(h_nobs == 1);
    CHECK(!strcmp(h_obs[0].method, "CONNECT"));
    CHECK(h_obs[0].flags & LK_QO_NO_TEXT);
    CHECK(!strcmp(h_obs[0].host, "tunnel.example:443"));
    return 0;
}

/* --- missing and degraded headers ----------------------------------------- */

static int test_missing_headers(void)
{
    h_reset();
    /* HTTP/1.0 with no Host at all — legal, and the shape nginx uses towards an
     * upstream by default. The host label is empty, not invented. */
    h_call(LK_DIR_RECV, "GET /a HTTP/1.0\r\n\r\n", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", 2000);
    CHECK(h_nobs == 1);
    CHECK(!strcmp(h_obs[0].host, ""));
    CHECK(!strcmp(h_obs[0].app, "")); /* no User-Agent either */
    CHECK(!strcmp(h_sess[0].ver, "HTTP/1.0"));
    CHECK(h_target_is(0, "/a"));

    h_reset();
    /* An unknown method parses and is reported by its own bytes — never mapped
     * onto a method it merely resembles, and never allowed to cost the framing. */
    h_call(LK_DIR_RECV, "PROPFIND /dav/x HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].method, "PROPFIND"));
    CHECK(h_stats()->by_type[LK_DIR_RECV][(__u8)'?'] == 1);
    return 0;
}

/* A header block split across two capture events must parse identically to one
 * that arrived whole: the framer reassembles it into its slab, and the handler
 * must not care which buffer it is reading. */
static int test_torn_head(void)
{
    const char *a = "GET /split?q=1 HTTP/1.1\r\nHost: shop.exa";
    const char *b = "mple\r\nUser-Agent: ua\r\n\r\n";
    __u32 n = (__u32)(strlen(a) + strlen(b));

    h_reset();
    h_feed(LK_DIR_RECV, n, 0, a, (__u32)strlen(a), 1000);
    h_feed(LK_DIR_RECV, n, (__u32)strlen(a), b, (__u32)strlen(b), 1100);
    answer(2000);

    CHECK(h_nobs == 1);
    CHECK(h_target_is(0, "/split?q=1"));
    CHECK(!strcmp(h_obs[0].host, "shop.example"));
    /* ts_start is the event of the head's *first* byte (Р13), not of the one
     * that completed it — otherwise a slow client would shorten its own
     * latency. */
    CHECK(h_obs[0].ts_start == 1000);
    return 0;
}

/* A head cut short by a capture hole: the start line and the first fields are
 * what always arrive (РH14), so the framer publishes the prefix flagged
 * BODY_TRUNC and the handler keeps what it can read, marked TEXT_TRUNC. */
static int test_truncated_head(void)
{
    const char *head = "GET /kept HTTP/1.1\r\nHost: shop.example\r\nCookie: a=";

    h_reset();
    h_feed(LK_DIR_RECV, 4096, 0, head, (__u32)strlen(head), 1000);
    h_hole(LK_DIR_RECV, 4096 - strlen(head));
    /* The direction resyncs; the next request is framed from its start line. */
    h_call(LK_DIR_RECV, "GET /next HTTP/1.1\r\nHost: shop.example\r\n\r\n", 2000);
    answer(3000);

    /* The truncated head opened no unit — without a terminated block there is
     * no body length, so no boundary anyone could stand behind. What it did do
     * is not become a parse error: the input was fine, the capture was not. */
    CHECK(h_nobs == 1);
    CHECK(h_target_is(0, "/next"));
    CHECK(h_stats()->parse_errors == 0);
    return 0;
}

/* The head arrives whole but the target is longer than a label may be: kept up
 * to the ceiling and flagged, rather than dropped. */
static int test_long_target(void)
{
    static char req[LK_HTTP_TARGET_MAX + 256];
    int n = snprintf(req, sizeof(req), "GET /");

    memset(req + n, 'a', LK_HTTP_TARGET_MAX + 32);
    n += LK_HTTP_TARGET_MAX + 32;
    snprintf(req + n, sizeof(req) - n, " HTTP/1.1\r\nHost: h\r\n\r\n");

    h_reset();
    h_call(LK_DIR_RECV, req, 1000);
    answer(2000);
    CHECK(h_nobs == 1);
    CHECK(h_obs[0].target_len == LK_HTTP_TARGET_MAX);
    CHECK(h_obs[0].flags & LK_QO_TEXT_TRUNC);
    return 0;
}

/* --- trace context and the request id (РH11, М6) --------------------------- */

static int test_trace_headers(void)
{
    static const __u8 want_trace[16] = {0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6,
                                        0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36};
    static const __u8 want_parent[8] = {0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7};

    h_reset();
    h_call(LK_DIR_RECV,
           "GET /a HTTP/1.1\r\n"
           "Host: h\r\n"
           "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n"
           "tracestate: rojo=00f067aa0ba902b7\r\n"
           "X-Request-Id: 7f3a2b1c-0000-4000-8000-000000000001\r\n\r\n",
           1000);
    answer(2000);
    CHECK(h_nobs == 1);
    /* Since М6 the context reaches the observation, which is what lets a span
     * join the caller's trace instead of starting its own. */
    CHECK(h_obs[0].have_http && h_obs[0].have_trace);
    CHECK(!memcmp(h_obs[0].trace_id, want_trace, sizeof(want_trace)));
    CHECK(!memcmp(h_obs[0].parent_id, want_parent, sizeof(want_parent)));
    CHECK(h_obs[0].trace_flags & 0x01); /* the caller is sampling this trace */
    CHECK(!strcmp(h_obs[0].tracestate, "rojo=00f067aa0ba902b7"));
    CHECK(!strcmp(h_obs[0].req_id, "7f3a2b1c-0000-4000-8000-000000000001"));
    CHECK(h_obs[0].version == 1); /* the response's HTTP/1.1 */

    /* A malformed header produces *no* context rather than a patched-up one: a
     * span hung off a made-up trace id is worse than a standalone span, because
     * it silently corrupts somebody else's trace. The shapes themselves are
     * covered exhaustively in test_http_wire.c. */
    h_reset();
    h_call(
        LK_DIR_RECV,
        "GET /a HTTP/1.1\r\nHost: h\r\ntraceparent: garbage\r\nX-Amzn-Trace-Id: Root=1-x\r\n\r\n",
        1000);
    answer(2000);
    CHECK(h_nobs == 1 && h_stats()->parse_errors == 0);
    CHECK(h_obs[0].have_http && !h_obs[0].have_trace);
    /* X-Amzn-Trace-Id fills the same slot as X-Request-Id: whichever arrives. */
    CHECK(!strcmp(h_obs[0].req_id, "Root=1-x"));

    /* An oversized tracestate is dropped, not clipped (РH11): half a
     * comma-separated list is not a shorter list, it is a malformed one, and
     * passing it on would corrupt the trace for whoever does parse it. */
    {
        char big[64 + LK_HTTP_TSTATE_MAX + 32];
        int off = snprintf(big, sizeof(big), "GET /a HTTP/1.1\r\nHost: h\r\ntracestate: ");

        for (int i = 0; i < LK_HTTP_TSTATE_MAX + 8; i++)
            big[off++] = 'x';
        snprintf(big + off, sizeof(big) - (size_t)off, "\r\n\r\n");
        h_reset();
        h_call(LK_DIR_RECV, big, 1000);
        answer(2000);
        CHECK(h_nobs == 1 && h_obs[0].tracestate[0] == '\0');
    }
    return 0;
}

/* --- РH12: the query-string redactor -------------------------------------- */

/* The rules of the redactor live in test_norm_redact.c; what is asserted here
 * is that the *handler* applies them — once, at the one point where a target
 * leaves it — and that the route beside it is unaffected, because the templater
 * still classifies the bytes that arrived. */
static int test_redaction(void)
{
    struct lk_http_cfg cfg = {0};

    lk_proto_http_configure(NULL); /* the default is on (РH12) */
    h_reset();
    h_call(LK_DIR_RECV, "GET /orders/42?token=s3cr3t&page=2 HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1);
    CHECK(h_target_is(0, "/orders/42?token=***&page=2"));
    CHECK(!strcmp(h_obs[0].route, "/orders/{id}"));

    /* Nothing to redact: the observation points straight at the unit's own copy,
     * no scratch buffer and no rewrite. Asserted through the output, which is
     * all a test can see — and all that matters. */
    h_reset();
    h_call(LK_DIR_RECV, "GET /orders/42?page=2 HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_target_is(0, "/orders/42?page=2"));

    /* A key promoted into the route by --http-query-keys is the operator saying
     * "this value is a route": the templater keeps it, and the redactor — which
     * runs on the target, not on the template — leaves the template alone. */
    cfg.route.query_keys[0] = "action";
    cfg.route.nquery_keys = 1;
    lk_proto_http_configure(&cfg);
    h_reset();
    h_call(LK_DIR_RECV, "GET /api?action=List&sig=abcdef HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].route, "/api?action=List"));
    CHECK(h_target_is(0, "/api?action=List&sig=***"));

    /* --http-redact off is the escape hatch, and the only way to see the raw
     * bytes anywhere in the agent. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.no_redact = true;
    lk_proto_http_configure(&cfg);
    h_reset();
    h_call(LK_DIR_RECV, "GET /orders/42?token=s3cr3t HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_target_is(0, "/orders/42?token=s3cr3t"));
    lk_proto_http_configure(NULL);
    return 0;
}

/* --- РH10 / РH12: the credential header ----------------------------------- */

static int test_authorization(void)
{
    /* "admin:hunter2" */
    const char *req = "GET /a HTTP/1.1\r\n"
                      "Host: h\r\n"
                      "Authorization: Basic YWRtaW46aHVudGVyMg==\r\n"
                      "Cookie: session=deadbeef\r\n\r\n";

    /* Default: the header is not read, so there is no user and nothing to leak.
     * This is the case that must hold without anyone configuring anything. */
    lk_proto_http_configure(NULL);
    h_reset();
    h_call(LK_DIR_RECV, req, 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].user, ""));

    /* --http-user basic: the name half becomes the user label, and only it. */
    lk_proto_http_configure(&(struct lk_http_cfg){.user_basic = true});
    h_reset();
    h_call(LK_DIR_RECV, req, 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].user, "admin"));

    /* A Bearer token is never touched even with the flag on. */
    h_reset();
    h_call(LK_DIR_RECV,
           "GET /a HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9\r\n\r\n",
           1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].user, ""));

    /* The user is per request, not sticky: an unauthenticated request on the
     * same connection must not inherit the previous one's identity. */
    h_reset();
    h_call(LK_DIR_RECV, req, 1000);
    answer(2000);
    h_call(LK_DIR_RECV, "GET /b HTTP/1.1\r\nHost: h\r\n\r\n", 3000);
    answer(4000);
    CHECK(h_nobs == 2);
    CHECK(!strcmp(h_obs[0].user, "admin") && !strcmp(h_obs[1].user, ""));
    lk_proto_http_configure(NULL);
    return 0;
}

/* --- the route reaches the observation (М4, РH7/РH8) ---------------------- */

/* The templating rules themselves live in test_norm_route.c; what is asserted
 * here is the wiring: the dialect runs once per observation, the raw target
 * survives beside the template, and a unit with no target reports no route
 * rather than a plausible-looking one. */
static int test_route(void)
{
    struct lk_http_cfg cfg = {0};

    lk_proto_http_configure(NULL);
    h_reset();
    h_call(LK_DIR_RECV, "GET /orders/42?token=secret HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1);
    CHECK(!strcmp(h_obs[0].route, "/orders/{id}"));
    /* The target travels beside the template, uncollapsed — the two identities
     * of РH7 — with only РH12's redaction applied to it (test_redaction). */
    CHECK(h_target_is(0, "/orders/42?token=***"));
    CHECK(h_obs[0].route_fp != 0);

    /* Two ids, one route: the whole point of the label. And two methods on one
     * path are two routes (РH7), which the fingerprint has to carry. */
    h_reset();
    h_call(LK_DIR_RECV, "GET /orders/1 HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    h_call(LK_DIR_RECV, "GET /orders/999 HTTP/1.1\r\nHost: h\r\n\r\n", 3000);
    answer(4000);
    h_call(LK_DIR_RECV, "DELETE /orders/1 HTTP/1.1\r\nHost: h\r\n\r\n", 5000);
    answer(6000);
    CHECK(h_nobs == 3);
    CHECK(h_obs[0].route_fp == h_obs[1].route_fp);
    CHECK(h_obs[0].route_fp != h_obs[2].route_fp);

    /* The knobs travel through the same config the CLI fills. */
    cfg.route.depth = 2;
    cfg.route.query_keys[0] = "action";
    cfg.route.nquery_keys = 1;
    lk_proto_http_configure(&cfg);
    h_reset();
    h_call(LK_DIR_RECV, "GET /a/b/c/d?action=List&x=9 HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].route, "/a/b/...?action=List"));

    /* --http-route-header: the app's own name wins over the classifier, and is
     * read only because a header was named. */
    memset(&cfg, 0, sizeof(cfg));
    h_reset();
    h_call(LK_DIR_RECV,
           "GET /posts/why-we-left HTTP/1.1\r\nHost: h\r\nX-Route: /posts/{slug}\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].route, "/posts/why-we-left"));

    snprintf(cfg.route_header, sizeof(cfg.route_header), "x-route");
    lk_proto_http_configure(&cfg);
    h_reset();
    h_call(LK_DIR_RECV,
           "GET /posts/why-we-left HTTP/1.1\r\nHost: h\r\nX-Route: /posts/{slug}\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].route, "/posts/{slug}"));
    /* ... and a request without the header still gets classified */
    h_call(LK_DIR_RECV, "GET /posts/17 HTTP/1.1\r\nHost: h\r\n\r\n", 3000);
    answer(4000);
    CHECK(h_nobs == 2 && !strcmp(h_obs[1].route, "/posts/{id}"));
    lk_proto_http_configure(NULL);

    /* No target, no route: an authority-form CONNECT reports neither a path nor
     * an invented "/" (the blind-zone note is test_http_frame.c's business). */
    h_reset();
    h_call(LK_DIR_RECV, "CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n", 2000);
    CHECK(h_nobs == 1);
    CHECK(h_obs[0].route[0] == '\0' && h_obs[0].route_fp == 0);
    return 0;
}

int main(void)
{
    int rc = test_basic_fields() || test_session_once() || test_target_forms() ||
             test_missing_headers() || test_torn_head() || test_truncated_head() ||
             test_long_target() || test_trace_headers() || test_redaction() ||
             test_authorization() || test_route();

    h_free();
    if (rc)
        return 1;
    printf("ok\n");
    return 0;
}
