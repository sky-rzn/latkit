// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the exchange lifecycle (PLAN-HTTP.md М3, РH5/РH6) — the part
 * of the handler that owns *time* and *order* rather than fields.
 *
 * Two things are being asserted throughout:
 *
 *   - **the four timings mean what РH5 says they mean.** ts_start is the first
 *     byte of the request head, ts_req_done the last byte of its body,
 *     ts_first_row the first byte of the response head, ts_complete its last
 *     body byte. For a GET they collapse to the familiar two; for an upload
 *     they must not, because the difference is the client's time and reporting
 *     it as the server's is the single most misleading thing this handler could
 *     do.
 *   - **a unit is emitted exactly once, or dropped and counted.** Every path
 *     out of the ring — a resync, a disconnect, pipelining past the ring, a
 *     response for a request we never saw — has to land in exactly one of those
 *     two buckets, and the tests check the counters, not just the output.
 *
 * The plan's matrix for this file: pipelining with an error in the middle, the
 * LOSSY (ring-overflow) mode, and degraded input. */
#include "http_obs.h"

#define OK200 "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

static void get(const char *target, __u64 ts)
{
    char req[256];

    snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: h\r\n\r\n", target);
    h_call(LK_DIR_RECV, req, ts);
}

/* --- the four timings ----------------------------------------------------- */

/* A GET: the request head and its (absent) body arrive in one event, so all
 * three duration models agree. This is why the extra stamp is invisible until
 * it matters — and why the test says so explicitly. */
static int test_timings_get(void)
{
    h_reset();
    get("/hello", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", 5000);
    h_call(LK_DIR_SEND, "world", 6000);

    CHECK(h_nobs == 1);
    CHECK(h_obs[0].ts_start == 1000);
    CHECK(h_obs[0].ts_req_done == 1000); /* nothing to upload */
    CHECK(h_obs[0].ts_first_row == 5000);
    CHECK(h_obs[0].ts_complete == 6000);
    CHECK(h_obs[0].ts_ready == h_obs[0].ts_complete); /* no separate ready point */
    CHECK(h_obs[0].bytes_in == 0 && h_obs[0].bytes_out == 5);
    return 0;
}

/* A POST whose body takes a while to arrive: the upload interval is the
 * client's and must not be inside the server's duration. */
static int test_timings_upload(void)
{
    h_reset();
    h_call(LK_DIR_RECV, "POST /echo HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\n", 1000);
    h_call(LK_DIR_RECV, "12345", 4000);
    h_call(LK_DIR_RECV, "67890", 9000); /* upload finishes here */
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n", 11000);
    h_call(LK_DIR_SEND, "abc", 12000);

    CHECK(h_nobs == 1);
    CHECK(h_obs[0].ts_start == 1000);
    CHECK(h_obs[0].ts_req_done == 9000);
    CHECK(h_obs[0].ts_first_row == 11000);
    CHECK(h_obs[0].ts_complete == 12000);
    CHECK(h_obs[0].bytes_in == 10 && h_obs[0].bytes_out == 3);

    /* The three intervals РH5 defines, spelled out so the arithmetic is pinned
     * by the test and not only by the comment in proto.h. */
    CHECK(h_obs[0].ts_complete - h_obs[0].ts_req_done == 3000);  /* duration */
    CHECK(h_obs[0].ts_first_row - h_obs[0].ts_req_done == 2000); /* ttfb */
    CHECK(h_obs[0].ts_req_done - h_obs[0].ts_start == 8000);     /* upload */
    CHECK(h_obs[0].ts_complete - h_obs[0].ts_start == 11000);    /* nginx $request_time */
    return 0;
}

/* A server that answers before the upload finishes (a 413 mid-POST) leaves no
 * request-body end. ts_req_done falls back to ts_start rather than staying
 * zero: the upload family loses that unit, the duration and TTFB stay right. */
static int test_early_response(void)
{
    h_reset();
    h_call(LK_DIR_RECV, "POST /big HTTP/1.1\r\nHost: h\r\nContent-Length: 1000\r\n\r\n", 1000);
    h_call(LK_DIR_RECV, "some bytes", 2000);
    h_call(LK_DIR_SEND, "HTTP/1.1 413 Too Large\r\nContent-Length: 0\r\n\r\n", 3000);

    CHECK(h_nobs == 1);
    CHECK(h_obs[0].status == 413 && (h_obs[0].flags & LK_QO_CLIENT_ERR));
    CHECK(h_obs[0].ts_req_done == h_obs[0].ts_start);
    CHECK(h_obs[0].ts_complete - h_obs[0].ts_req_done == 2000);
    CHECK(h_obs[0].bytes_in == 10); /* what did arrive is still counted */
    return 0;
}

/* --- bytes: counted, never read ------------------------------------------- */

/* A hole inside a Content-Length body is skipped arithmetically, and the bytes
 * it swallowed are still reported: total_len is honest, so byte accounting is
 * exact under any capture budget rather than "exact when nothing was lost". */
static int test_bytes_under_a_hole(void)
{
    h_reset();
    get("/big", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n", 2000);
    h_feed(LK_DIR_SEND, 5000, 0, "0123456789", 10, 3000); /* 10 of 5000 captured */
    h_hole(LK_DIR_SEND, 4990);

    CHECK(h_nobs == 1);
    CHECK(h_obs[0].bytes_out == 5000);
    CHECK(!(h_obs[0].flags & LK_QO_BODY_UNSEEN)); /* the body was accounted in full */
    return 0;
}

/* A chunked body reports *decoded* bytes, so a chunked response and a
 * Content-Length one of the same size report the same number. */
static int test_bytes_chunked(void)
{
    h_reset();
    get("/chunked", 1000);
    h_call(LK_DIR_SEND,
           "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
           2000);
    CHECK(h_nobs == 1);
    CHECK(h_obs[0].bytes_out == 11); /* "hello world", not the framing around it */
    return 0;
}

/* --- keep-alive and pipelining -------------------------------------------- */

static int test_keepalive(void)
{
    h_reset();
    for (int i = 0; i < 5; i++) {
        char t[32];

        snprintf(t, sizeof(t), "/r%d", i);
        get(t, 1000 + (__u64)i * 100);
        h_call(LK_DIR_SEND, OK200, 1050 + (__u64)i * 100);
    }
    CHECK(h_nobs == 5);
    /* Sequential requests are not pipelining: the ring never holds more than
     * one, so nothing carries the flag. */
    for (int i = 0; i < 5; i++)
        CHECK(!(h_obs[i].flags & LK_QO_PIPELINED));
    CHECK(h_target_is(4, "/r4"));
    CHECK(h_stats()->queries == 5);
    return 0;
}

/* Four requests written before the first answer: the responses come back in
 * request order, so the FIFO pairs them, and every unit in the batch is marked
 * — the first one's duration is honest but the rest started while the client
 * was not waiting, so none of them compares with a standalone unit. */
static int test_pipelined(void)
{
    h_reset();
    get("/a", 1000);
    get("/b", 1000);
    get("/c", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA", 2000);
    h_call(LK_DIR_SEND, "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nBB", 3000);
    h_call(LK_DIR_SEND, "HTTP/1.1 500 Oops\r\nContent-Length: 3\r\n\r\nCCC", 4000);

    CHECK(h_nobs == 3);
    CHECK(h_target_is(0, "/a") && h_target_is(1, "/b") && h_target_is(2, "/c"));
    CHECK(h_obs[0].status == 200 && h_obs[1].status == 404 && h_obs[2].status == 500);
    CHECK(h_obs[0].bytes_out == 1 && h_obs[1].bytes_out == 2 && h_obs[2].bytes_out == 3);
    for (int i = 0; i < 3; i++)
        CHECK(h_obs[i].flags & LK_QO_PIPELINED);
    /* An error in the middle of a batch does not disturb the pairing: the two
     * flags land on the units that earned them and nowhere else. */
    CHECK(!(h_obs[0].flags & (LK_QO_ERROR | LK_QO_CLIENT_ERR)));
    CHECK(h_obs[1].flags & LK_QO_CLIENT_ERR);
    CHECK(h_obs[2].flags & LK_QO_ERROR);
    CHECK(h_stats()->errors_sql == 1);
    return 0;
}

/* Pipelining deeper than the ring holds: the newest requests are dropped and
 * counted, the ones already in the ring still pair correctly, and the responses
 * to the dropped ones are recognised and skipped rather than mis-attributed —
 * which is the failure that would matter, because it would put one request's
 * route on another's latency. */
static int test_ring_overflow(void)
{
    const int n = LK_HTTP_MAX_INFLIGHT + 4;

    h_reset();
    for (int i = 0; i < n; i++) {
        char t[32];

        snprintf(t, sizeof(t), "/r%d", i);
        get(t, 1000);
    }
    CHECK(h_stats()->units_dropped_overflow == 4);
    for (int i = 0; i < n; i++) {
        char body[64];

        snprintf(body, sizeof(body), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n%02d", i % 100);
        h_call(LK_DIR_SEND, body, 2000 + (__u64)i);
    }
    /* Exactly the ring's worth of observations, in request order, and no
     * observation for the four we could not track. */
    CHECK(h_nobs == LK_HTTP_MAX_INFLIGHT);
    CHECK(h_target_is(0, "/r0"));
    CHECK(h_target_is(LK_HTTP_MAX_INFLIGHT - 1, "/r15"));
    for (int i = 0; i < LK_HTTP_MAX_INFLIGHT; i++)
        CHECK(h_obs[i].bytes_out == 2);
    return 0;
}

/* The sharp edge of the same mechanism: while an untracked response's body is
 * still arriving, a *new* request opens a unit. Those bytes belong to nobody,
 * and charging them to the new unit would produce an observation that looks
 * entirely plausible — right route, right status, wrong size. */
static int test_owed_body_not_misattributed(void)
{
    const int n = LK_HTTP_MAX_INFLIGHT + 1;

    h_reset();
    for (int i = 0; i < n; i++)
        get("/pipelined", 1000);
    CHECK(h_stats()->units_dropped_overflow == 1);

    /* Answer the whole ring, so the next response is the untracked one. */
    for (int i = 0; i < LK_HTTP_MAX_INFLIGHT; i++)
        h_call(LK_DIR_SEND, OK200, 2000);
    CHECK(h_nobs == LK_HTTP_MAX_INFLIGHT);

    /* The untracked response's head, then its body in two events — with a fresh
     * request opening a unit in between. */
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", 3000);
    h_feed(LK_DIR_SEND, 100, 0, "0123456789", 10, 3100);
    get("/fresh", 3200);
    h_feed(LK_DIR_SEND, 100, 10, "0123456789", 10, 3300);
    h_hole(LK_DIR_SEND, 80);

    /* Now the fresh unit's own response. */
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxyz", 4000);
    CHECK(h_nobs == LK_HTTP_MAX_INFLIGHT + 1);
    CHECK(h_target_is(LK_HTTP_MAX_INFLIGHT, "/fresh"));
    CHECK(h_obs[LK_HTTP_MAX_INFLIGHT].bytes_out == 3); /* 3, not 103 */
    return 0;
}

/* --- losing the thread ---------------------------------------------------- */

/* A capture hole inside a chunked body cannot be skipped — the sizes live in
 * the byte stream — so the direction resyncs and the unit is dropped rather
 * than reported with a byte count nobody can stand behind. */
static int test_resync_drops_units(void)
{
    h_reset();
    get("/chunked", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", 2000);
    h_hole(LK_DIR_SEND, 4096);

    /* The scan comes back at the next status line — but which request that
     * response answers is exactly what the loss destroyed, so everything in
     * flight is dropped rather than paired by guesswork. That is the same rule
     * PG applies at a resync (Р19), and the reason it matters more here is that
     * mis-pairing would put one request's route on another's latency. */
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 3000);
    CHECK(h_stats()->resyncs >= 1);
    CHECK(h_stats()->units_dropped_resync == 1);
    CHECK(h_nobs == 0);

    /* The connection is usable again: the next exchange is observed normally. */
    get("/after", 4000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 5000);
    CHECK(h_nobs == 1);
    CHECK(h_target_is(0, "/after"));
    CHECK(h_stats()->parse_errors == 0); /* a hole is not a parse error */
    return 0;
}

/* A request cut off by a disconnect is not an observation (Р19): no response
 * head ever arrived, so there is nothing to report but the drop. */
static int test_close_drops_unanswered(void)
{
    h_reset();
    get("/never-answered", 1000);
    h_close(2000);

    CHECK(h_nobs == 0);
    CHECK(h_stats()->units_dropped_close == 1);
    return 0;
}

/* The РH4 sendfile shape, as it looks on an old kernel: the head promised a
 * body, not one byte of it came through the socket, and the next response head
 * is what closes the unit. The timings are honest, bytes_out is a lower bound,
 * and the observation says so. */
static int test_body_unseen(void)
{
    h_reset();
    get("/static", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 8388608\r\n\r\n", 2000);
    get("/next", 3000);
    /* The next response head arrives on a direction still owing a body: the
     * framer notes it and closes the first unit here. */
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 4000);

    CHECK(h_nobs >= 1);
    CHECK(h_target_is(0, "/static"));
    CHECK(h_obs[0].flags & LK_QO_BODY_UNSEEN);
    CHECK(h_obs[0].bytes_out == 0);
    CHECK(h_obs[0].ts_first_row == 2000); /* the head's timing is untouched */
    return 0;
}

/* A connection we joined mid-stream: nothing before the next request head is a
 * boundary we can vouch for, so the leftovers of the exchange in progress are
 * ignored and the first complete exchange after them is reported. */
static int test_degraded_entry(void)
{
    h_reset_flags(LK_CONN_SYNTHETIC);
    /* The tail of somebody else's response, mid-body. */
    h_call(LK_DIR_SEND, "...tail of a body nobody framed...", 1000);
    get("/first-clean", 2000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 3000);

    CHECK(h_nobs == 1);
    CHECK(h_target_is(0, "/first-clean"));
    return 0;
}

/* Everything the handler allocates is released on the close hook, on every
 * removal path — the property ASAN checks for real, asserted here so the test
 * exercises a connection that owns both of its per-unit buffers. */
static int test_state_released(void)
{
    h_reset();
    h_call(LK_DIR_RECV,
           "GET /a HTTP/1.1\r\nHost: h\r\n"
           "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n"
           "tracestate: rojo=00f067aa0ba902b7,congo=t61rcWkgMzE\r\n\r\n",
           1000);
    h_call(LK_DIR_SEND, OK200, 2000);
    CHECK(h_nobs == 1);
    h_close(3000);
    CHECK(h_conn.proto_state == NULL);
    return 0;
}

int main(void)
{
    int rc = test_timings_get() || test_timings_upload() || test_early_response() ||
             test_bytes_under_a_hole() || test_bytes_chunked() || test_keepalive() ||
             test_pipelined() || test_ring_overflow() || test_owed_body_not_misattributed() ||
             test_resync_drops_units() || test_close_drops_unanswered() || test_body_unseen() ||
             test_degraded_entry() || test_state_released();

    h_free();
    if (rc)
        return 1;
    printf("ok\n");
    return 0;
}
