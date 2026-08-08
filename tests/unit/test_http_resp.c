// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the response head (PLAN-HTTP.md М3, src/proto/http/http_resp.c).
 *
 * Three properties are what this file is really about, and each of them is a
 * decision that cannot be revisited once the metric is aggregated:
 *
 *   - **the status splits three ways.** 5xx is the server's failure
 *     (LK_QO_ERROR), 4xx is the client's (LK_QO_CLIENT_ERR), and everything
 *     else is neither. Fold the two together and a 404-heavy service reads as
 *     broken (РH10).
 *   - **a 1xx closes nothing.** An interim response is head-only and leaves the
 *     unit in flight; treating it as the answer would report a `100 Continue`
 *     as the outcome of every upload (РH6).
 *   - **the status is on every observation, not only the failing ones.** It is
 *     the response's identity, not its error code, so err_code carries it
 *     always — which is why a 200 must show up here too.
 *
 * Plus the shapes where the *request* decides how to read the response: a HEAD
 * answer, and the rule-6 body that only the connection's end terminates. */
#include "http_obs.h"

/* Ask a question so a response has a unit to land on. */
static void ask(const char *target, __u64 ts)
{
    char req[256];

    snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: h\r\n\r\n", target);
    h_call(LK_DIR_RECV, req, ts);
}

/* --- status classes ------------------------------------------------------- */

static int test_status_classes(void)
{
    struct {
        const char *head;
        __u16 code;
        __u16 want;
    } cases[] = {
        {"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 200, 0},
        {"HTTP/1.1 204 No Content\r\n\r\n", 204, 0},
        {"HTTP/1.1 301 Moved\r\nContent-Length: 0\r\n\r\n", 301, 0},
        {"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 404, LK_QO_CLIENT_ERR},
        {"HTTP/1.1 429 Too Many\r\nContent-Length: 0\r\n\r\n", 429, LK_QO_CLIENT_ERR},
        {"HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n", 500, LK_QO_ERROR},
        {"HTTP/1.1 503 Down\r\nContent-Length: 0\r\n\r\n", 503, LK_QO_ERROR},
    };
    __u64 errors = 0;

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        h_reset();
        ask("/a", 1000);
        h_call(LK_DIR_SEND, cases[i].head, 2000);
        CHECK(h_nobs == 1);
        CHECK(h_obs[0].status == cases[i].code); /* set whatever the outcome */
        CHECK((h_obs[0].flags & (LK_QO_ERROR | LK_QO_CLIENT_ERR)) == cases[i].want);
        /* The status class is the per-direction tally the stats line prints. */
        CHECK(h_stats()->by_type[LK_DIR_SEND][(__u8)('0' + cases[i].code / 100)] == 1);
        if (cases[i].want == LK_QO_ERROR)
            errors++;
        CHECK(h_stats()->errors_sql == (cases[i].want == LK_QO_ERROR ? 1u : 0u));
    }
    CHECK(errors == 2);
    return 0;
}

/* A bare status line with no reason phrase parses like a full one — RFC 9112
 * §4 makes the phrase optional and real servers omit it. */
static int test_no_reason_phrase(void)
{
    h_reset();
    ask("/a", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 204\r\n\r\n", 2000);
    CHECK(h_nobs == 1 && h_obs[0].status == 204);
    return 0;
}

/* --- 1xx: an answer that is not the answer -------------------------------- */

static int test_interim(void)
{
    h_reset();
    h_call(LK_DIR_RECV,
           "POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n",
           1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 100 Continue\r\n\r\n", 2000);
    CHECK(h_nobs == 0); /* still in flight: a 1xx closes nothing */
    h_call(LK_DIR_RECV, "data", 3000);
    h_call(LK_DIR_SEND, "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n", 4000);

    CHECK(h_nobs == 1);
    CHECK(h_obs[0].status == 201); /* the final status, not the interim one */
    /* TTFB is the *final* head: the 100 is a handshake, not the answer, and
     * counting it would report every 100-continue upload as instant. */
    CHECK(h_obs[0].ts_first_row == 4000);
    CHECK(h_obs[0].ts_req_done == 3000);
    CHECK(h_obs[0].bytes_in == 4);

    /* 103 Early Hints is the same machinery in front of a 200, and several may
     * arrive; none of them closes the unit either. */
    h_reset();
    ask("/a", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n", 2000);
    h_call(LK_DIR_SEND, "HTTP/1.1 103 Early Hints\r\nLink: </t.css>\r\n\r\n", 2500);
    CHECK(h_nobs == 0);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 3000);
    CHECK(h_nobs == 1 && h_obs[0].status == 200 && h_obs[0].ts_first_row == 3000);
    return 0;
}

/* --- when the request decides how to read the response -------------------- */

static int test_head_and_bodyless(void)
{
    h_reset();
    /* A HEAD response carries a Content-Length describing a body that will
     * never arrive. Reading it as a body length desynchronises everything that
     * follows, so the second request here is the real assertion. */
    h_call(LK_DIR_RECV, "HEAD /big HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n", 2000);
    CHECK(h_nobs == 1);
    CHECK(!strcmp(h_obs[0].method, "HEAD"));
    CHECK(h_obs[0].bytes_out == 0); /* the declared length is not bytes we saw */

    h_call(LK_DIR_RECV, "GET /after HTTP/1.1\r\nHost: h\r\n\r\n", 3000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", 4000);
    CHECK(h_nobs == 2);
    CHECK(h_target_is(1, "/after") && h_obs[1].bytes_out == 2);

    /* 304 is the same shape: a validator response may declare a length and
     * never send one. */
    h_reset();
    ask("/cached", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n", 2000);
    h_call(LK_DIR_RECV, "GET /after HTTP/1.1\r\nHost: h\r\n\r\n", 3000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 4000);
    CHECK(h_nobs == 2 && h_obs[0].status == 304 && h_obs[0].bytes_out == 0);
    return 0;
}

/* Rule 6: no length, no chunking, so the body ends when the socket does. The
 * close *completes* the unit rather than truncating it — which is the only
 * reason a plain HTTP/1.0 exchange produces an observation at all. */
static int test_body_until_close(void)
{
    h_reset();
    ask("/stream", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", 2000);
    h_call(LK_DIR_SEND, "hello world", 2500);
    CHECK(h_nobs == 0); /* the body is still running */
    h_close(3000);

    CHECK(h_nobs == 1);
    CHECK(h_obs[0].status == 200);
    CHECK(h_obs[0].bytes_out == 11);
    CHECK(h_obs[0].ts_complete == 3000); /* the close is the last byte */
    /* Nothing was lost, so nothing is flagged: this is a complete observation,
     * not a degraded one. */
    CHECK(!(h_obs[0].flags & LK_QO_BODY_UNSEEN));
    CHECK(h_stats()->units_dropped_close == 0);
    return 0;
}

/* The mirror case: a declared length that never finished. The status, the route
 * and the head timings are honest and worth reporting; only the byte count is
 * short, so the unit is emitted flagged rather than thrown away (РH4). */
static int test_declared_length_cut_short(void)
{
    h_reset();
    ask("/big", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n", 2000);
    h_call(LK_DIR_SEND, "partial", 2500);
    h_close(3000);

    CHECK(h_nobs == 1);
    CHECK(h_obs[0].status == 200);
    CHECK(h_obs[0].bytes_out == 7); /* a lower bound, and it says so */
    CHECK(h_obs[0].flags & LK_QO_BODY_UNSEEN);
    return 0;
}

/* --- the response nobody asked for ---------------------------------------- */

static int test_response_without_request(void)
{
    h_reset();
    /* A connection joined mid-stream: the response is framed fine and there is
     * simply no unit to attach it to. Not a parse error — the bytes were
     * correct, we never saw the request — and not counted as an anomaly either,
     * because we already know we joined late. */
    h_reset_flags(LK_CONN_SYNTHETIC);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", 1000);
    CHECK(h_nobs == 0);
    CHECK(h_stats()->parse_errors == 0);
    CHECK(h_stats()->orphan_msgs == 0);

    /* On a connection we *were* watching from the start, the same shape is a
     * real anomaly and is counted. */
    h_reset();
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", 1000);
    CHECK(h_nobs == 0);
    CHECK(h_stats()->orphan_msgs > 0);
    return 0;
}

int main(void)
{
    int rc = test_status_classes() || test_no_reason_phrase() || test_interim() ||
             test_head_and_bodyless() || test_body_until_close() ||
             test_declared_length_cut_short() || test_response_without_request();

    h_free();
    if (rc)
        return 1;
    printf("ok\n");
    return 0;
}
