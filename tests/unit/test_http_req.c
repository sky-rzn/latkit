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

/* --- trace context and the request id ------------------------------------- */

static int test_trace_headers(void)
{
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

    /* The parsed context lives on the unit until М6 threads it into a span; the
     * unit is gone by now, so what this test can assert is that a well-formed
     * header costs nothing and a malformed one is refused. Both are checked
     * exhaustively in test_http_wire.c; here the point is that the handler runs
     * them at all and survives the shapes. */
    h_reset();
    h_call(
        LK_DIR_RECV,
        "GET /a HTTP/1.1\r\nHost: h\r\ntraceparent: garbage\r\nX-Amzn-Trace-Id: Root=1-x\r\n\r\n",
        1000);
    answer(2000);
    CHECK(h_nobs == 1 && h_stats()->parse_errors == 0);
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

int main(void)
{
    int rc = test_basic_fields() || test_session_once() || test_target_forms() ||
             test_missing_headers() || test_torn_head() || test_truncated_head() ||
             test_long_target() || test_trace_headers() || test_authorization();

    h_free();
    if (rc)
        return 1;
    printf("ok\n");
    return 0;
}
