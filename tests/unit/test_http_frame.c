// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the HTTP/1.x framer (PLAN-HTTP.md М2, src/proto/http/) — the
 * test_reassembly.c / test_my_frame.c matrix rerun over lk_proto_http_ops in
 * stream mode, plus the cases only a text protocol has.
 *
 * The matrix, in the order the plan lists it: torn heads, a hole on a head and
 * a hole on a body, a head over the ceiling, chunked with a hole,
 * 100-continue, a HEAD response carrying a Content-Length for a body that
 * never comes, 204/304, keep-alive, pipelining, the three blind zones
 * (upgrade, h2 preface, CONNECT), torn resync anchors, `Content-Length`
 * together with `Transfer-Encoding` (the desynchronisation attack — rejected
 * explicitly), and bare LF.
 *
 * Two properties are asserted throughout rather than in one test, because they
 * are what the framer exists to guarantee:
 *
 *   - every byte of a body is reported exactly once, captured or holed, so the
 *     'E' total always equals the sum of the 'D's and both equal the length the
 *     head promised;
 *   - a degradation never silently mis-frames: it emits its '!' note and drops
 *     the direction into the anchor scan, and the scan comes back at the next
 *     start line.
 *
 * The wire helpers (http_wire.h) get their own section at the end — bounds and
 * shape rules that the framer relies on and the М3 handler will too. */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"
#include "reassembly.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* --- captured sink output ------------------------------------------------- */

#define MAXREC 128

struct rec {
    __u64 ts;
    __u8 dir;
    char type;
    __u16 flags;
    __u32 len, cap;
    char body[96]; /* prefix copy: lk_msg.body is valid only in the callback */
};

static struct rec recs[MAXREC];
static int nrecs, nresyncs;

static void on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct rec *r = &recs[nrecs % MAXREC];
    __u32 nbody = m->body_cap < sizeof(r->body) - 1 ? m->body_cap : (__u32)sizeof(r->body) - 1;

    (void)ctx;
    (void)c;
    nrecs++;
    memset(r, 0, sizeof(*r));
    r->ts = m->ts_ns;
    r->dir = dir;
    r->type = m->type;
    r->flags = m->flags;
    r->len = m->len;
    r->cap = m->body_cap;
    if (nbody)
        memcpy(r->body, m->body, nbody);
}

static void on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    (void)ctx;
    (void)c;
    (void)dir;
    nresyncs++;
}

static struct lk_reasm reasm;
static struct lk_conn conn;

static void reset(void)
{
    static const struct lk_msg_sink sink = {.on_msg = on_msg, .on_resync = on_resync};

    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    free(conn.frame_state); /* the conn table does this in the live path */
    lk_reasm_free(&reasm);  /* drain the recycled slab pool before re-init */
    memset(&conn, 0, sizeof(conn));
    conn.ops = &lk_proto_http_ops;
    lk_reasm_init(&reasm, &sink);
    nrecs = 0;
    nresyncs = 0;
}

/* One data event: a chunk of a call, modelled by off/total like the agent's. */
static void feed(enum lk_dir dir, __u32 total, __u32 off, const void *p, __u32 cap, __u64 ts)
{
    static union {
        struct lk_ev_data d;
        __u8 raw[sizeof(struct lk_ev_data) + 65536];
    } u;

    memset(&u.d, 0, sizeof(u.d));
    u.d.hdr.ts_ns = ts;
    u.d.hdr.dir = dir;
    u.d.total_len = total;
    u.d.off = off;
    u.d.cap_len = cap;
    if (cap)
        memcpy(u.d.payload, p, cap);
    lk_reasm_data(&reasm, &conn, dir, &u.d, cap);
}

/* A whole syscall's worth of bytes, fully captured — the common shape. */
static void call(enum lk_dir dir, const char *s, __u64 ts)
{
    feed(dir, (__u32)strlen(s), 0, s, (__u32)strlen(s), ts);
}

static void nbytes(enum lk_dir dir, const void *p, __u32 n, __u64 ts)
{
    feed(dir, n, 0, p, n, ts);
}

/* Bytes we will never see: the primitive the framer's four degradations are
 * judged on (РH4). */
static void hole(enum lk_dir dir, __u64 n)
{
    lk_frame_hole(&reasm, &conn, dir, n);
}

/* --- assertions ----------------------------------------------------------- */

static int is(int i, enum lk_dir dir, char type, __u32 len)
{
    if (i >= nrecs || i >= MAXREC) {
        fprintf(stderr, "FAIL: no message #%d (have %d)\n", i, nrecs);
        return 0;
    }
    if (recs[i].dir != dir || recs[i].type != type || recs[i].len != len) {
        fprintf(stderr, "FAIL: msg #%d is %s '%c' len=%u, want %s '%c' len=%u\n", i,
                recs[i].dir == LK_DIR_RECV ? "fe" : "be", recs[i].type ? recs[i].type : '?',
                recs[i].len, dir == LK_DIR_RECV ? "fe" : "be", type, len);
        return 0;
    }
    return 1;
}

static int note_is(int i, enum lk_dir dir, enum lk_http_note n)
{
    return is(i, dir, LK_HTTP_MSG_NOTE, (__u32)n);
}

/* Length of the header block at the head of a literal, terminator included —
 * so the expected head length is derived from the same bytes the test feeds in
 * rather than counted by hand. */
static __u32 hl(const char *s)
{
    const char *e = strstr(s, "\r\n\r\n");

    if (e)
        return (__u32)(e - s) + 4;
    e = strstr(s, "\n\n");
    return e ? (__u32)(e - s) + 2 : (__u32)strlen(s);
}

/* --- the base case -------------------------------------------------------- */

static const char GET[] = "GET /hello HTTP/1.1\r\nHost: h\r\n\r\n";
static const char OK2[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
static const char EMPTY200[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
static const char ERR500[] = "HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n";

/* A request with no body and a response with a length: head, empty body end,
 * head, one data chunk, body end. The head message carries the whole header
 * block — that is what М3 parses and М4 templates the route out of. */
static int test_get(void)
{
    reset();
    call(LK_DIR_RECV, GET, 100);
    call(LK_DIR_SEND, OK2, 200);

    CHECK(nrecs == 5);
    CHECK(is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(GET) - 1));
    CHECK(recs[0].ts == 100 && recs[0].cap == sizeof(GET) - 1);
    CHECK(!memcmp(recs[0].body, "GET /hello HTTP/1.1", 19));
    CHECK(is(1, LK_DIR_RECV, LK_HTTP_MSG_END, 0));
    CHECK(is(2, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(OK2)));
    CHECK(recs[2].ts == 200);
    CHECK(is(3, LK_DIR_SEND, LK_HTTP_MSG_DATA, 2));
    CHECK(is(4, LK_DIR_SEND, LK_HTTP_MSG_END, 2));
    CHECK(reasm.st.resyncs == 0 && nresyncs == 0);
    /* The message machine of the other mode never ran. */
    CHECK(conn.frame[LK_DIR_RECV].hdr_len == 0);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_HEADER);
    return 0;
}

/* A head torn across events — the `slow-client` shape, one byte per event in
 * the extreme. The head is published once, whole, timestamped at its *first*
 * byte (Р13): the request started when its first byte arrived, not when the
 * client finally finished typing. */
static int test_head_torn(void)
{
    __u32 n = (__u32)strlen(GET);

    reset();
    for (__u32 i = 0; i < n; i++)
        feed(LK_DIR_RECV, 1, 0, GET + i, 1, 100 + i);

    CHECK(nrecs == 2);
    CHECK(is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, n));
    CHECK(recs[0].ts == 100);
    CHECK(!memcmp(recs[0].body, GET, n));
    CHECK(is(1, LK_DIR_RECV, LK_HTTP_MSG_END, 0));
    /* The slab went back to the pool at the message boundary. */
    CHECK(conn.frame[LK_DIR_RECV].buf == NULL);
    return 0;
}

/* Keep-alive and pipelining: four requests in one write, four responses. The
 * FIFO of in-flight requests is what makes the third response (to a HEAD) come
 * out right, which is the point of keeping it at all. */
static int test_keepalive_pipelined(void)
{
    static const char A[] = "GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
    static const char B[] = "GET /b HTTP/1.1\r\nHost: h\r\n\r\n";
    static const char C[] = "HEAD /c HTTP/1.1\r\nHost: h\r\n\r\n";
    static const char R1[] = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx";
    static const char R2[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nnop";
    static const char R3[] = "HTTP/1.1 200 OK\r\nContent-Length: 9999\r\n\r\n";
    char all[128];

    reset();
    snprintf(all, sizeof(all), "%s%s%s", A, B, C);
    call(LK_DIR_RECV, all, 10);
    CHECK(nrecs == 6);
    CHECK(is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, hl(A)) && is(1, LK_DIR_RECV, LK_HTTP_MSG_END, 0));
    CHECK(is(2, LK_DIR_RECV, LK_HTTP_MSG_REQ, hl(B)) && is(3, LK_DIR_RECV, LK_HTTP_MSG_END, 0));
    CHECK(is(4, LK_DIR_RECV, LK_HTTP_MSG_REQ, hl(C)) && is(5, LK_DIR_RECV, LK_HTTP_MSG_END, 0));

    call(LK_DIR_SEND, R1, 20);
    call(LK_DIR_SEND, R2, 21);
    /* Rule 1: the answer to a HEAD carries a Content-Length describing a body
     * that never arrives. Reading it as a body length would desynchronise the
     * connection for every request that follows. */
    call(LK_DIR_SEND, R3, 22);
    CHECK(nrecs == 6 + 8);
    CHECK(is(6, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(R1)) && is(8, LK_DIR_SEND, LK_HTTP_MSG_END, 1));
    CHECK(is(9, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(R2)) && is(11, LK_DIR_SEND, LK_HTTP_MSG_END, 3));
    CHECK(is(12, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(R3)));
    CHECK(is(13, LK_DIR_SEND, LK_HTTP_MSG_END, 0)); /* no body, whatever it says */
    CHECK(conn.frame[LK_DIR_SEND].st != LK_FR_DIRTY);
    return 0;
}

/* Statuses that cannot carry a body however they are framed. */
static int test_no_body_statuses(void)
{
    reset();
    call(LK_DIR_RECV, GET, 10);
    call(LK_DIR_SEND, "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", 20);
    CHECK(nrecs == 4 && is(3, LK_DIR_SEND, LK_HTTP_MSG_END, 0));

    reset();
    call(LK_DIR_RECV, GET, 10);
    call(LK_DIR_SEND, "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n", 20);
    CHECK(nrecs == 4 && is(3, LK_DIR_SEND, LK_HTTP_MSG_END, 0));
    /* A bare status line with no reason phrase parses the same way. */
    static const char BARE[] = "HTTP/1.1 204\r\n\r\n";

    reset();
    call(LK_DIR_RECV, GET, 10);
    call(LK_DIR_SEND, BARE, 20);
    CHECK(nrecs == 4 && is(2, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(BARE)));
    return 0;
}

/* Expect: 100-continue. The interim response is its own message type and does
 * *not* close the unit — the request it belongs to is still in flight, so the
 * final 200 must still find it in the FIFO. */
static int test_continue(void)
{
    static const char REQ[] =
        "POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n";
    static const char CONT[] = "HTTP/1.1 100 Continue\r\n\r\n";
    static const char HINTS[] = "HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n";
    static const char FIN[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    reset();
    call(LK_DIR_RECV, REQ, 10);
    CHECK(nrecs == 1 && is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, hl(REQ)));
    call(LK_DIR_SEND, CONT, 20);
    CHECK(nrecs == 2 && is(1, LK_DIR_SEND, LK_HTTP_MSG_INTER, hl(CONT)));
    call(LK_DIR_RECV, "data", 30);
    CHECK(nrecs == 4 && is(2, LK_DIR_RECV, LK_HTTP_MSG_DATA, 4));
    CHECK(is(3, LK_DIR_RECV, LK_HTTP_MSG_END, 4));
    /* 103 Early Hints is the same machinery, in front of the real answer. */
    call(LK_DIR_SEND, HINTS, 40);
    call(LK_DIR_SEND, FIN, 50);
    CHECK(nrecs == 7);
    CHECK(is(4, LK_DIR_SEND, LK_HTTP_MSG_INTER, hl(HINTS)));
    CHECK(is(5, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(FIN)) && is(6, LK_DIR_SEND, LK_HTTP_MSG_END, 0));
    return 0;
}

/* --- chunked -------------------------------------------------------------- */

/* Chunk sizes, a chunk extension, and a trailer section. 'D' reports decoded
 * body bytes, not the framing around them, so a chunked body and a
 * Content-Length one of the same size report the same number. */
static int test_chunked(void)
{
    static const char RESP[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                               "4\r\nabcd\r\n"
                               "3;ext=v\r\nefg\r\n"
                               "0\r\nX-Sum: 1\r\n\r\n";

    reset();
    call(LK_DIR_RECV, GET, 10);
    call(LK_DIR_SEND, RESP, 20);
    CHECK(nrecs == 6);
    CHECK(is(2, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(RESP)));
    CHECK(is(3, LK_DIR_SEND, LK_HTTP_MSG_DATA, 4));
    CHECK(is(4, LK_DIR_SEND, LK_HTTP_MSG_DATA, 3));
    /* ... and the 'E' arrives only after the trailer section's empty line. */
    CHECK(is(5, LK_DIR_SEND, LK_HTTP_MSG_END, 7));
    return 0;
}

/* A chunked body split so that a chunk-size line straddles two events: the
 * size is accumulated digit by digit, so no buffer and no special case. */
static int test_chunked_torn_size(void)
{
    reset();
    call(LK_DIR_RECV, GET, 10);
    call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na", 20);
    call(LK_DIR_SEND, "\r\n0123456789\r\n0\r\n\r\n", 21);
    CHECK(nrecs == 5);
    CHECK(is(3, LK_DIR_SEND, LK_HTTP_MSG_DATA, 10)); /* chunk-size "a", hex */
    CHECK(is(4, LK_DIR_SEND, LK_HTTP_MSG_END, 10));
    return 0;
}

/* A chunked *request* body with a trailer — Go and node both produce this
 * shape, and the М0 corpus records it against all four servers. */
static int test_chunked_request(void)
{
    static const char REQ[] = "POST /echo HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
                              "5\r\nhello\r\n0\r\n\r\n";

    reset();
    call(LK_DIR_RECV, REQ, 10);
    CHECK(nrecs == 3);
    CHECK(is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, hl(REQ)));
    CHECK(is(1, LK_DIR_RECV, LK_HTTP_MSG_DATA, 5));
    CHECK(is(2, LK_DIR_RECV, LK_HTTP_MSG_END, 5));
    return 0;
}

/* A malformed chunk-size line is corruption, not a body: the direction resyncs
 * rather than reading the rest of the connection at an offset. */
static int test_chunked_bad_size(void)
{
    reset();
    call(LK_DIR_RECV, GET, 10);
    call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", 20);
    CHECK(nrecs == 4 && note_is(3, LK_DIR_SEND, LK_HTTP_NOTE_CHUNK_BAD));
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    call(LK_DIR_SEND, EMPTY200, 30);
    CHECK(nresyncs == 1);
    CHECK(is(4, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(EMPTY200)));
    CHECK(recs[4].flags & LK_MSG_AFTER_RESYNC);
    return 0;
}

/* --- holes: the four degradations of РH4 ---------------------------------- */

/* A hole inside a Content-Length body costs nothing: the length was known in
 * advance, so the missing bytes are skipped arithmetically and still counted —
 * they were on the wire, total_len is honest, and byte accounting stays exact
 * under any capture budget. This is the case the design is built around. */
static int test_hole_in_body(void)
{
    reset();
    call(LK_DIR_RECV, GET, 10);
    call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n", 20);
    call(LK_DIR_SEND, "xxxxxxxxxx", 21);
    hole(LK_DIR_SEND, 900);
    nbytes(LK_DIR_SEND, "yyyyyyyyyy", 10, 22);
    hole(LK_DIR_SEND, 80);

    CHECK(is(3, LK_DIR_SEND, LK_HTTP_MSG_DATA, 10));
    CHECK(is(4, LK_DIR_SEND, LK_HTTP_MSG_DATA, 900));
    CHECK(is(5, LK_DIR_SEND, LK_HTTP_MSG_DATA, 10));
    CHECK(is(6, LK_DIR_SEND, LK_HTTP_MSG_DATA, 80));
    CHECK(is(7, LK_DIR_SEND, LK_HTTP_MSG_END, 1000)); /* every byte accounted once */
    CHECK(conn.frame[LK_DIR_SEND].st != LK_FR_DIRTY);
    CHECK(nresyncs == 0);
    /* The next response frames normally: the body ended exactly where the
     * header said it would. */
    call(LK_DIR_SEND, EMPTY200, 30);
    CHECK(is(8, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(EMPTY200)) && nresyncs == 0);
    return 0;
}

/* A hole that runs past the end of the body swallows the next head with it. */
static int test_hole_past_body(void)
{
    reset();
    call(LK_DIR_RECV, GET, 10);
    call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", 20);
    hole(LK_DIR_SEND, 150);
    CHECK(is(3, LK_DIR_SEND, LK_HTTP_MSG_DATA, 100));
    CHECK(is(4, LK_DIR_SEND, LK_HTTP_MSG_END, 100));
    CHECK(note_is(5, LK_DIR_SEND, LK_HTTP_NOTE_HEAD_HOLE));
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    return 0;
}

/* A hole on a header block. The block's end is now unknowable, so the
 * direction resyncs — but what did arrive is still published as a prefix: the
 * start line and the first fields come first and carry the method, the route
 * and the framing headers. A head longer than the capture budget is a normal
 * outcome, not an error (РH14, the `huge-head-cap2048` traces). */
static int test_hole_in_head(void)
{
    static const char PART[] = "GET /hello HTTP/1.1\r\nHost: h\r\nCookie: aaaa";

    reset();
    call(LK_DIR_RECV, PART, 10);
    hole(LK_DIR_RECV, 5000);

    CHECK(nrecs == 2);
    CHECK(is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(PART) - 1));
    CHECK(recs[0].flags & LK_MSG_BODY_TRUNC);
    CHECK(recs[0].ts == 10 && !memcmp(recs[0].body, "GET /hello HTTP/1.1", 19));
    CHECK(note_is(1, LK_DIR_RECV, LK_HTTP_NOTE_HEAD_HOLE));
    CHECK(conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);
    CHECK(reasm.st.msgs_trunc == 1);

    /* ... and the next request re-enters framing on its start line. */
    call(LK_DIR_RECV, GET, 20);
    CHECK(nresyncs == 1 && nrecs == 4);
    CHECK(is(2, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(GET) - 1));
    CHECK(recs[2].flags & LK_MSG_AFTER_RESYNC);
    return 0;
}

/* A hole at a message boundary: nothing to publish, and the next head is
 * somewhere inside the hole. */
static int test_hole_at_boundary(void)
{
    reset();
    call(LK_DIR_RECV, GET, 10);
    hole(LK_DIR_RECV, 300);
    CHECK(nrecs == 3 && note_is(2, LK_DIR_RECV, LK_HTTP_NOTE_HEAD_HOLE));
    CHECK(conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);
    return 0;
}

/* A hole inside a chunked body is the one that hurts (РH4): the sizes live in
 * the byte stream, so one lost chunk header and every byte after it is
 * misread. The unit is dropped and counted, never mis-attributed — and М0
 * measured chunked at a third to two thirds of the responses from a modern
 * backend, so this is a main-path degradation. */
static int test_hole_in_chunked(void)
{
    reset();
    call(LK_DIR_RECV, GET, 10);
    call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n", 20);
    CHECK(nrecs == 4 && is(3, LK_DIR_SEND, LK_HTTP_MSG_DATA, 4));
    hole(LK_DIR_SEND, 64);
    CHECK(nrecs == 5 && note_is(4, LK_DIR_SEND, LK_HTTP_NOTE_CHUNK_HOLE));
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    /* No 'E': the unit cannot be closed honestly, and М3 drops it on the
     * resync into units_dropped_resync. */
    call(LK_DIR_SEND, ERR500, 30);
    CHECK(nresyncs == 1 && is(5, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(ERR500)));
    return 0;
}

/* A header block over the message ceiling is corruption or an attack, not a
 * fat cookie jar: 16 KB is already four times what nginx accepts by default. */
static int test_head_too_big(void)
{
    static char big[LK_MSG_BODY_MAX + 4096];

    reset();
    memset(big, 'x', sizeof(big));
    memcpy(big, "GET /", 5); /* a real start line, then kilobytes of nothing */
    nbytes(LK_DIR_RECV, big, sizeof(big), 10);
    CHECK(note_is(0, LK_DIR_RECV, LK_HTTP_NOTE_HEAD_TOO_BIG));
    CHECK(conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);
    CHECK(conn.frame[LK_DIR_RECV].buf == NULL); /* the slab went back to the pool */
    /* Nothing was published as a head, and the scan that follows finds the
     * start line again, hits the ceiling again and stops — the recovery is
     * bounded by the input, it does not spin. */
    for (int i = 0; i < nrecs; i++)
        CHECK(recs[i].type == LK_HTTP_MSG_NOTE);
    CHECK(nrecs <= 4);

    /* The same head, arriving in pieces, trips the ceiling just the same. */
    reset();
    for (int i = 0; i < 3; i++)
        nbytes(LK_DIR_RECV, big, 8192, 10 + (__u64)i);
    CHECK(note_is(0, LK_DIR_RECV, LK_HTTP_NOTE_HEAD_TOO_BIG));
    for (int i = 0; i < nrecs; i++)
        CHECK(recs[i].type == LK_HTTP_MSG_NOTE); /* no head was ever published */
    return 0;
}

/* --- rejected heads ------------------------------------------------------- */

/* `Content-Length` together with `Transfer-Encoding` is the desynchronisation
 * primitive itself, and real servers do not agree on it (М0: nginx, node and
 * gunicorn answer 400, Go answers 200 and reads the chunked body). Nothing is
 * published: when two hops can disagree about where a message ends, any length
 * we pick is a guess, and a dropped unit is honest where a guessed one is not.
 *
 * The bytes after such a head are, in the corpus, a smuggled request — and the
 * anchor scan finds it, which is exactly the visible outcome we want. */
static int test_cl_te(void)
{
    static const char SMUGGLED[] = "GET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n";
    char blob[192];

    reset();
    snprintf(blob, sizeof(blob),
             "POST /echo HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked"
             "\r\n\r\n0\r\n\r\n%s",
             SMUGGLED);
    call(LK_DIR_RECV, blob, 10);
    CHECK(note_is(0, LK_DIR_RECV, LK_HTTP_NOTE_CL_TE));
    CHECK(nresyncs == 1);
    CHECK(is(1, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(SMUGGLED) - 1));
    CHECK(!memcmp(recs[1].body, "GET /smuggled", 13));
    return 0;
}

/* Duplicate Content-Length: identical values fold (RFC 9110 allows the
 * comma-separated form), conflicting ones are rejected like CL+TE. */
static int test_content_length_dups(void)
{
    reset();
    call(LK_DIR_RECV, GET, 5);
    call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 4, 4\r\n\r\nabcd", 20);
    CHECK(nrecs == 5 && is(4, LK_DIR_SEND, LK_HTTP_MSG_END, 4));

    reset();
    call(LK_DIR_RECV, GET, 5);
    call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 9\r\n\r\nabcd", 20);
    CHECK(nrecs == 3 && note_is(2, LK_DIR_SEND, LK_HTTP_NOTE_CL_BAD));

    reset();
    call(LK_DIR_RECV, GET, 5);
    call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 4x\r\n\r\n", 20);
    CHECK(nrecs == 3 && note_is(2, LK_DIR_SEND, LK_HTTP_NOTE_CL_BAD));
    return 0;
}

/* Field-line shapes that desynchronise header parsing between hops: obs-fold
 * (obsolete since RFC 9112 §5.2) and whitespace before the colon. */
static int test_bad_fields(void)
{
    reset();
    call(LK_DIR_RECV, "GET / HTTP/1.1\r\nHost: h\r\n\tfolded\r\n\r\n", 10);
    CHECK(nrecs == 1 && note_is(0, LK_DIR_RECV, LK_HTTP_NOTE_FIELD_BAD));

    reset();
    call(LK_DIR_RECV, "GET / HTTP/1.1\r\nContent-Length : 5\r\n\r\n", 10);
    CHECK(nrecs == 1 && note_is(0, LK_DIR_RECV, LK_HTTP_NOTE_FIELD_BAD));

    reset();
    call(LK_DIR_RECV, "GET / HTTP/1.1\r\nnocolon\r\n\r\n", 10);
    CHECK(nrecs == 1 && note_is(0, LK_DIR_RECV, LK_HTTP_NOTE_FIELD_BAD));
    return 0;
}

/* Start lines that are not HTTP/1.x: binary garbage (the `bad-request` trace),
 * HTTP/0.9's version-less form, and a version we do not speak. */
static int test_bad_start_lines(void)
{
    reset();
    nbytes(LK_DIR_RECV, "\x01\x02\x03\xff junk\r\n\r\n", 13, 10);
    CHECK(nrecs == 1 && note_is(0, LK_DIR_RECV, LK_HTTP_NOTE_BAD_HEAD));

    reset();
    call(LK_DIR_RECV, "GET /old\r\n\r\n", 10);
    CHECK(nrecs == 1 && note_is(0, LK_DIR_RECV, LK_HTTP_NOTE_BAD_HEAD));

    reset();
    call(LK_DIR_SEND, "HTTP/1.1 999 Nope\r\n\r\n", 10);
    CHECK(nrecs == 1 && note_is(0, LK_DIR_SEND, LK_HTTP_NOTE_BAD_HEAD));
    return 0;
}

/* Bare LF as a line terminator: accepted (servers disagree in practice, and an
 * observer that rejected it would go blind exactly where the server did not)
 * and reported once per connection, because knowing a client speaks LF-only is
 * what explains a later disagreement with an access log. */
static int test_lf_only(void)
{
    static const char LF[] = "GET /hello HTTP/1.1\nHost: h\n\n";

    reset();
    call(LK_DIR_RECV, LF, 10);
    CHECK(nrecs == 3);
    CHECK(note_is(0, LK_DIR_RECV, LK_HTTP_NOTE_LF_ONLY));
    CHECK(is(1, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(LF) - 1));
    CHECK(is(2, LK_DIR_RECV, LK_HTTP_MSG_END, 0));
    call(LK_DIR_RECV, "GET /again HTTP/1.1\nHost: h\n\n", 20);
    CHECK(nrecs == 5); /* the note is one-shot */
    return 0;
}

/* RFC 9112 §2.2: empty lines before a start line may be ignored, and clients
 * do send them. Stripping them is also what keeps the empty-line scanner from
 * reading the very first byte as the end of a block. */
static int test_leading_crlf(void)
{
    reset();
    call(LK_DIR_RECV, "\r\n\r\nGET /hello HTTP/1.1\r\nHost: h\r\n\r\n", 10);
    CHECK(nrecs == 2 && is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(GET) - 1));
    return 0;
}

/* --- blind zones (РH4) ---------------------------------------------------- */

/* The HTTP/2 preface is a valid-looking HTTP/1.1 head, which is why it is
 * checked before the request line is parsed. Past it lies HPACK, which this
 * agent deliberately does not speak — and with it goes gRPC. */
static int test_h2_preface(void)
{
    reset();
    call(LK_DIR_RECV, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x12\x04", 10);
    CHECK(nrecs == 1 && note_is(0, LK_DIR_RECV, LK_HTTP_NOTE_BLIND_H2));
    CHECK(conn.flags & LK_CONN_IGNORE);
    /* Nothing more is framed on this connection. */
    call(LK_DIR_RECV, GET, 20);
    CHECK(nrecs == 1);
    return 0;
}

/* `Upgrade:` in a request is not a blind zone by itself — measured, none of
 * the four М0 servers accepts an h2c upgrade, all four answer an ordinary
 * HTTP/1.1 200. Only the 101 makes it real. */
static int test_upgrade(void)
{
    static const char WSREQ[] =
        "GET /ws HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    static const char SWITCH[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";

    reset();
    call(LK_DIR_RECV, WSREQ, 10);
    CHECK(nrecs == 2 && is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(WSREQ) - 1));
    call(LK_DIR_SEND, SWITCH, 20);
    CHECK(nrecs == 5);
    /* not 'I': a 101 is the one 1xx that closes the unit */
    CHECK(is(2, LK_DIR_SEND, LK_HTTP_MSG_RESP, sizeof(SWITCH) - 1));
    CHECK(is(3, LK_DIR_SEND, LK_HTTP_MSG_END, 0));
    CHECK(note_is(4, LK_DIR_SEND, LK_HTTP_NOTE_BLIND_UPGRADE));
    CHECK(conn.flags & LK_CONN_IGNORE);

    /* h2c refused: the connection stays ordinary HTTP/1.1. */
    reset();
    call(LK_DIR_RECV,
         "GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n"
         "HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n",
         10);
    call(LK_DIR_SEND, OK2, 20);
    CHECK(!(conn.flags & LK_CONN_IGNORE));
    CHECK(nrecs == 5 && is(4, LK_DIR_SEND, LK_HTTP_MSG_END, 2));
    return 0;
}

/* CONNECT answered 2xx: everything after the response head is tunnel payload.
 * A refused CONNECT leaves an ordinary connection behind. */
static int test_connect(void)
{
    static const char CONN[] = "CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n";
    static const char EST[] = "HTTP/1.1 200 Connection Established\r\n\r\n";

    reset();
    call(LK_DIR_RECV, CONN, 10);
    call(LK_DIR_SEND, EST, 20);
    CHECK(nrecs == 5);
    CHECK(is(2, LK_DIR_SEND, LK_HTTP_MSG_RESP, sizeof(EST) - 1));
    CHECK(is(3, LK_DIR_SEND, LK_HTTP_MSG_END, 0));
    CHECK(note_is(4, LK_DIR_SEND, LK_HTTP_NOTE_BLIND_CONNECT));
    CHECK(conn.flags & LK_CONN_IGNORE);

    reset();
    call(LK_DIR_RECV, CONN, 10);
    call(LK_DIR_SEND, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", 20);
    CHECK(!(conn.flags & LK_CONN_IGNORE));
    CHECK(nrecs == 4 && is(3, LK_DIR_SEND, LK_HTTP_MSG_END, 0));
    return 0;
}

/* --- the shapes with no length -------------------------------------------- */

/* Rule 6: a response with neither a length nor chunking runs until the
 * connection closes — the normal shape for HTTP/1.0 backends, which is what
 * nginx speaks to upstreams by default. Body bytes are reported as they
 * arrive; the closing 'E' is CONN_CLOSE's, i.e. М3's. */
static int test_until_close(void)
{
    static const char OLD[] = "HTTP/1.0 200 OK\r\n\r\nbody bytes";

    reset();
    call(LK_DIR_RECV, GET, 10);
    call(LK_DIR_SEND, OLD, 20);
    call(LK_DIR_SEND, "more", 21);
    hole(LK_DIR_SEND, 7);
    CHECK(nrecs == 6);
    CHECK(is(2, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(OLD)));
    CHECK(is(3, LK_DIR_SEND, LK_HTTP_MSG_DATA, 10));
    CHECK(is(4, LK_DIR_SEND, LK_HTTP_MSG_DATA, 4));
    CHECK(is(5, LK_DIR_SEND, LK_HTTP_MSG_DATA, 7)); /* holes count as bytes */
    return 0;
}

/* A request with no framing header has no body, whatever follows it: rule 5.
 * The bytes after it are the next request, not a body. */
static int test_request_without_length(void)
{
    static const char P[] = "POST /x HTTP/1.1\r\nHost: h\r\n\r\n";
    static const char G[] = "GET /y HTTP/1.1\r\nHost: h\r\n\r\n";
    char blob[128];

    reset();
    snprintf(blob, sizeof(blob), "%s%s", P, G);
    call(LK_DIR_RECV, blob, 10);
    CHECK(nrecs == 4);
    CHECK(is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(P) - 1));
    CHECK(is(1, LK_DIR_RECV, LK_HTTP_MSG_END, 0));
    CHECK(is(2, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(G) - 1));
    CHECK(is(3, LK_DIR_RECV, LK_HTTP_MSG_END, 0));
    return 0;
}

/* РH4's `sendfile` degradation, the old-kernel case: the head promised a body,
 * not one byte of it came through the socket, and here is the next status
 * line. Since ~6.5 the kernel routes splice through sendmsg and this never
 * fires (М0 recon item 1) — but 5.15 is in the support matrix, so it is
 * exercised synthetically rather than by trusting the local kernel. */
static int test_body_unseen(void)
{
    static const char PROMISE[] = "HTTP/1.1 200 OK\r\nContent-Length: 8192\r\n\r\n";

    reset();
    call(LK_DIR_RECV, GET, 10);
    call(LK_DIR_SEND, PROMISE, 20);
    call(LK_DIR_SEND, OK2, 30);
    CHECK(nrecs == 8);
    CHECK(is(2, LK_DIR_SEND, LK_HTTP_MSG_RESP, sizeof(PROMISE) - 1));
    CHECK(note_is(3, LK_DIR_SEND, LK_HTTP_NOTE_BODY_UNSEEN));
    CHECK(is(4, LK_DIR_SEND, LK_HTTP_MSG_END, 0)); /* bytes_out is a lower bound */
    CHECK(is(5, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(OK2)));
    CHECK(is(6, LK_DIR_SEND, LK_HTTP_MSG_DATA, 2));
    CHECK(is(7, LK_DIR_SEND, LK_HTTP_MSG_END, 2));
    CHECK(conn.frame[LK_DIR_SEND].st != LK_FR_DIRTY);
    return 0;
}

/* --- resync (Р10 for HTTP) ------------------------------------------------ */

/* The strongest anchors of the three protocols, and they survive being torn
 * across events. Keeping the matched bytes is what lets framing resume *at*
 * the start line rather than after it — the method and the target are not lost
 * with the anchor, which is the difference between a recovered unit and a
 * dropped one. */
static int test_resync_torn_anchor(void)
{
    reset();
    conn.frame[LK_DIR_RECV].st = LK_FR_DIRTY;
    conn.frame[LK_DIR_SEND].st = LK_FR_DIRTY;

    nbytes(LK_DIR_RECV, "junk\xff\xfe GE", 9, 10);
    CHECK(nrecs == 0 && nresyncs == 0);
    call(LK_DIR_RECV, "T /hello HTTP/1.1\r\nHost: h\r\n\r\n", 11);
    CHECK(nresyncs == 1);
    CHECK(is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(GET) - 1));
    CHECK(!memcmp(recs[0].body, GET, sizeof(GET) - 1));
    CHECK(recs[0].flags & LK_MSG_AFTER_RESYNC);

    nbytes(LK_DIR_SEND, "\x00\x01 HTTP/1.", 10, 20);
    CHECK(nresyncs == 1);
    call(LK_DIR_SEND, "1 200 OK\r\nContent-Length: 0\r\n\r\n", 21);
    CHECK(nresyncs == 2);
    CHECK(is(2, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(EMPTY200)));
    return 0;
}

/* A false anchor — "GET " inside a body, an HTML page quoting HTTP — costs one
 * wrongly-framed head, which then fails the start-line parse and returns to
 * the scan. Documented, counted, self-correcting. */
static int test_false_anchor(void)
{
    reset();
    conn.frame[LK_DIR_RECV].st = LK_FR_DIRTY;
    call(LK_DIR_RECV, "...GET nothing-like-a-request\r\n\r\n", 10);
    CHECK(nresyncs == 1);
    CHECK(note_is(0, LK_DIR_RECV, LK_HTTP_NOTE_BAD_HEAD));
    CHECK(conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);
    call(LK_DIR_RECV, GET, 20);
    CHECK(nresyncs == 2 && is(1, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(GET) - 1));
    return 0;
}

/* An anchor cannot span a hole: the candidate bytes are dropped, as PG's 'Z'
 * match is. */
static int test_anchor_across_hole(void)
{
    reset();
    conn.frame[LK_DIR_RECV].st = LK_FR_DIRTY;
    nbytes(LK_DIR_RECV, "GE", 2, 10);
    hole(LK_DIR_RECV, 4);
    call(LK_DIR_RECV, "T /x HTTP/1.1\r\n\r\n", 11);
    CHECK(nresyncs == 0 && nrecs == 0);
    call(LK_DIR_RECV, GET, 12);
    CHECK(nresyncs == 1 && is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(GET) - 1));
    return 0;
}

/* The generic guards run before the fork, so a stream protocol inherits them:
 * an off-anomaly dirties the direction through the generic path and the framer
 * resynchronises on the next start line rather than framing corrupt input. */
static int test_off_anomaly(void)
{
    reset();
    feed(LK_DIR_RECV, 50, 60, "\x01\x02\x03\x04\x05\x06\x07\x08", 8, 10);
    CHECK(reasm.st.off_anomalies == 1);
    CHECK(conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);
    call(LK_DIR_RECV, GET, 20);
    CHECK(nresyncs == 1 && is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(GET) - 1));
    return 0;
}

/* Pipelining deeper than the in-flight ring: rather than let responses pair
 * with the wrong requests, the framer says so and every response until the
 * ring drains frames from its own headers alone. */
static int test_pipeline_overflow(void)
{
    int notes = 0;

    reset();
    for (int i = 0; i < LK_HTTP_MAX_INFLIGHT + 2; i++)
        call(LK_DIR_RECV, "HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n", 10 + (__u64)i);
    for (int i = 0; i < nrecs; i++)
        notes +=
            recs[i].type == LK_HTTP_MSG_NOTE && recs[i].len == (__u32)LK_HTTP_NOTE_PIPELINE_OVER;
    CHECK(notes == 2);
    /* A HEAD response now frames by its own headers — which is the safe
     * direction to be wrong in: a body is expected, not skipped. */
    reset();
    for (int i = 0; i < LK_HTTP_MAX_INFLIGHT + 1; i++)
        call(LK_DIR_RECV, "GET /x HTTP/1.1\r\nHost: h\r\n\r\n", 10 + (__u64)i);
    for (int i = 0; i < LK_HTTP_MAX_INFLIGHT + 1; i++)
        call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nz", 50 + (__u64)i);
    CHECK(conn.frame[LK_DIR_SEND].st != LK_FR_DIRTY);
    return 0;
}

/* A response with no request in flight (the request direction resynced, or we
 * joined mid-connection) still frames from its own headers. */
static int test_response_without_request(void)
{
    reset();
    call(LK_DIR_SEND, OK2, 20);
    CHECK(nrecs == 3 && is(0, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(OK2)));
    CHECK(is(2, LK_DIR_SEND, LK_HTTP_MSG_END, 2));
    return 0;
}

/* РH15, the invariant the whole track is measured against: a PG connection
 * frames exactly as before while an HTTP one shares the framer. */
static int test_pg_unaffected_alongside(void)
{
    static struct lk_conn pgconn;
    __u8 wire[64];

    reset();
    memset(&pgconn, 0, sizeof(pgconn));
    pgconn.ops = &lk_proto_pg_ops;
    pgconn.frame[LK_DIR_RECV].startup_done = 1;
    wire[0] = 'Q';
    wire[1] = wire[2] = wire[3] = 0;
    wire[4] = 13;
    memcpy(wire + 5, "select 1", 9);

    call(LK_DIR_RECV, GET, 10);
    lk_frame_bytes(&reasm, &pgconn, LK_DIR_RECV, wire, 14, 20);
    call(LK_DIR_SEND, OK2, 30);

    CHECK(is(0, LK_DIR_RECV, LK_HTTP_MSG_REQ, sizeof(GET) - 1));
    CHECK(is(2, LK_DIR_RECV, 'Q', 13) && recs[2].cap == 9);
    CHECK(!strcmp(recs[2].body, "select 1"));
    CHECK(is(3, LK_DIR_SEND, LK_HTTP_MSG_RESP, hl(OK2)));
    CHECK(pgconn.frame[LK_DIR_RECV].st == LK_FR_HEADER && pgconn.frame_state == NULL);
    return 0;
}

/* --- http_wire.h ---------------------------------------------------------- */

/* The bounded cursor and the shape rules the framer stands on. Every helper
 * takes an explicit length; none of them may read past it, which is what the
 * fuzz target exercises at scale and what these cases pin by construction. */
/* --- the display mask (РH3/РH12, М6) -------------------------------------- */

/* What `--messages --hexdump` and lkt_messages show is not what the handler
 * parses: the credential headers are blanked and the credential-shaped query
 * values overwritten, on the viewer's own copy, before a byte reaches a
 * terminal. Driven through lk_msg_body_for_display, which is the function both
 * viewers call — testing lk_proto_http_ops.mask_body directly would test a hook
 * nobody is obliged to route through. */
static int test_display_mask(void)
{
    static const char req[] = "GET /a?page=1&token=s3cr3t HTTP/1.1\r\n"
                              "Host: h\r\n"
                              "Authorization: Basic YWRtaW46aHVudGVyMg==\r\n"
                              "Cookie: session=deadbeefcafe\r\n"
                              "User-Agent: curl/8.5.0\r\n\r\n";
    struct lk_msg m = {.type = LK_HTTP_MSG_REQ,
                       .len = sizeof(req) - 1,
                       .body_cap = sizeof(req) - 1,
                       .body = (const __u8 *)req};
    __u8 out[512];
    __u32 n = lk_msg_body_for_display(&lk_proto_http_ops, &m, out, sizeof(out));

    CHECK(n == sizeof(req) - 1); /* same length: the hexdump's offsets still hold */
    out[n] = '\0';
    CHECK(!strstr((char *)out, "s3cr3t"));
    CHECK(!strstr((char *)out, "YWRtaW46aHVudGVyMg"));
    CHECK(!strstr((char *)out, "deadbeefcafe"));
    /* Masked, not deleted, and only where it had to be: the framing of the head
     * — start line, version, field names, the harmless header — is exactly what
     * came off the wire, or the view stops being useful for debugging framing. */
    CHECK(strstr((char *)out, "GET /a?page=1&token=****** HTTP/1.1"));
    CHECK(strstr((char *)out, "Authorization: ***"));
    CHECK(strstr((char *)out, "Cookie: ***"));
    CHECK(strstr((char *)out, "User-Agent: curl/8.5.0"));
    /* The source is untouched — the handler above still needs `Authorization`
     * when `--http-user basic` asks for the name half (РH10). */
    CHECK(strstr(req, "YWRtaW46aHVudGVyMg") != NULL);

    /* A message with no body of its own carries nothing to mask, and PG has
     * nothing to hide in a republished message at all: both paths must still
     * produce the bytes the viewer asked for. */
    {
        struct lk_msg d = {.type = LK_HTTP_MSG_DATA, .len = 4096};

        CHECK(lk_msg_body_for_display(&lk_proto_http_ops, &d, out, sizeof(out)) == 0);
    }
    {
        static const char q[] = "select 1";
        struct lk_msg pgm = {.type = 'Q', .len = 13, .body_cap = 8, .body = (const __u8 *)q};

        CHECK(lk_msg_body_for_display(&lk_proto_pg_ops, &pgm, out, sizeof(out)) == 8);
        CHECK(!memcmp(out, q, 8));
    }
    return 0;
}

static int test_wire(void)
{
    struct http_span m, t, v;
    struct http_head h;
    __u64 cl;
    __u16 code;
    __u8 minor;

    /* case-insensitive names, byte-exact values */
    CHECK(http_span_eq_ci(http_span("Content-Length", 14), "content-length"));
    CHECK(!http_span_eq_ci(http_span("Content-Lengt", 13), "content-length"));
    CHECK(!http_span_eq_ci(http_span("Content-Lengthy", 15), "content-length"));
    CHECK(http_span_eq_ci(http_span(NULL, 0), ""));

    /* token lists */
    CHECK(http_list_has(http_span("keep-alive, Upgrade", 19), "upgrade"));
    CHECK(!http_list_has(http_span("keep-alive", 10), "upgrade"));
    CHECK(http_span_eq_ci(http_list_last(http_span("gzip, chunked", 13)), "chunked"));
    CHECK(http_span_eq_ci(http_list_last(http_span("chunked, gzip", 13)), "gzip"));
    CHECK(http_list_last(http_span("", 0)).n == 0);

    /* Content-Length: one value, or a list of identical ones */
    CHECK(http_parse_content_length(http_span("42", 2), &cl) && cl == 42);
    CHECK(http_parse_content_length(http_span("5, 5", 4), &cl) && cl == 5);
    CHECK(!http_parse_content_length(http_span("5, 6", 4), &cl));
    CHECK(!http_parse_content_length(http_span("", 0), &cl));
    CHECK(!http_parse_content_length(http_span("-1", 2), &cl));
    CHECK(!http_parse_content_length(http_span("99999999999999999999", 20), &cl));

    /* start lines */
    CHECK(http_parse_req_line(http_span("GET /a?b=c HTTP/1.1", 19), &m, &t, &minor));
    CHECK(minor == 1 && http_span_eq_ci(m, "get") && t.n == 6);
    CHECK(http_parse_req_line(http_span("GET http://h/a HTTP/1.0", 23), &m, &t, &minor));
    CHECK(minor == 0 && t.n == 10); /* absolute-form */
    CHECK(http_parse_req_line(http_span("OPTIONS * HTTP/1.1", 18), &m, &t, &minor) && t.n == 1);
    CHECK(!http_parse_req_line(http_span("GET /a HTTP/2.0", 15), &m, &t, &minor));
    CHECK(!http_parse_req_line(http_span("GET /a", 6), &m, &t, &minor));
    CHECK(!http_parse_req_line(http_span("GET  HTTP/1.1", 13), &m, &t, &minor));
    CHECK(!http_parse_req_line(http_span("GET /a HTTP/1.1 x", 17), &m, &t, &minor));
    CHECK(http_method_id(http_span("PATCH", 5)) == HTTP_M_PATCH);
    CHECK(http_method_id(http_span("PROPFIND", 8)) == HTTP_M_OTHER);
    CHECK(http_method_id(http_span("get", 3)) == HTTP_M_OTHER); /* case-sensitive */

    CHECK(http_parse_status_line(http_span("HTTP/1.1 200 OK", 15), &code, &minor));
    CHECK(code == 200 && minor == 1);
    CHECK(http_parse_status_line(http_span("HTTP/1.0 204", 12), &code, &minor) && code == 204);
    CHECK(!http_parse_status_line(http_span("HTTP/1.1 20", 11), &code, &minor));
    CHECK(!http_parse_status_line(http_span("HTTP/1.1 600 X", 14), &code, &minor));
    CHECK(!http_parse_status_line(http_span("HTTP/1.1 200OK", 14), &code, &minor));

    /* the header iterator: names trimmed, values trimmed, empty line ends it */
    http_head_init(&h, "GET / HTTP/1.1\r\nA:  x \r\nB:\r\n\r\nbody", 34);
    CHECK(http_head_line(&h, &v) && v.n == 14);
    CHECK(http_head_field(&h, &m, &v) && http_span_eq_ci(m, "a") && v.n == 1 && v.p[0] == 'x');
    CHECK(http_head_field(&h, &m, &v) && http_span_eq_ci(m, "b") && v.n == 0);
    CHECK(!http_head_field(&h, &m, &v) && !(h.flags & HTTP_HEAD_BAD));

    /* a head cut mid-line is readable up to the cut, and says so */
    http_head_init(&h, "GET / HTTP/1.1\r\nHost: partia", 28);
    CHECK(http_head_line(&h, &v) && v.n == 14);
    CHECK(http_head_field(&h, &m, &v) && (h.flags & HTTP_HEAD_NO_EOL));
    CHECK(!http_head_line(&h, &v));

    http_head_init(&h, "GET / HTTP/1.1\n", 15);
    CHECK(http_head_line(&h, &v) && (h.flags & HTTP_HEAD_LF_ONLY) && v.n == 14);

    /* zero-length input: every accessor is a no-op, none of them reads */
    http_head_init(&h, NULL, 0);
    CHECK(!http_head_line(&h, &v));
    CHECK(!http_head_field(&h, &m, &v));
    return 0;
}

int main(void)
{
    if (test_get() || test_head_torn() || test_keepalive_pipelined() || test_no_body_statuses() ||
        test_continue() || test_chunked() || test_chunked_torn_size() || test_chunked_request() ||
        test_chunked_bad_size() || test_hole_in_body() || test_hole_past_body() ||
        test_hole_in_head() || test_hole_at_boundary() || test_hole_in_chunked() ||
        test_head_too_big() || test_cl_te() || test_content_length_dups() || test_bad_fields() ||
        test_bad_start_lines() || test_lf_only() || test_leading_crlf() || test_h2_preface() ||
        test_upgrade() || test_connect() || test_until_close() || test_request_without_length() ||
        test_body_unseen() || test_resync_torn_anchor() || test_false_anchor() ||
        test_anchor_across_hole() || test_off_anomaly() || test_pipeline_overflow() ||
        test_response_without_request() || test_pg_unaffected_alongside() || test_display_mask() ||
        test_wire())
        return 1;
    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    free(conn.frame_state);
    lk_reasm_free(&reasm);
    printf("ok\n");
    return 0;
}
