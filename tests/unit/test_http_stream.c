// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the framer's stream mode (РH1, PLAN-HTTP.md М1) — the second
 * framing mode of lk_proto_ops, driven through the very lk_reasm_data path the
 * agent uses, with HTTP as its only implementation.
 *
 * What is asserted here is the *seam*, not HTTP: that a LK_PROTO_F_STREAM
 * protocol receives the byte stream after every generic step and none of the
 * message-machine ones; that lk_reasm_emit/lk_reasm_resync keep the lk_msg
 * contract and the counters the message mode keeps; that frame_state and the
 * borrowed slab follow the connection through every removal path; and — the
 * point of the whole exercise (РH15) — that a stream protocol on one
 * connection changes nothing for a PG connection on the same framer.
 *
 * HTTP's own behaviour — heads, bodies, the four degradations, the anchors —
 * belongs to test_http_frame.c (М2). This file uses the smallest HTTP that
 * will drive the seam and asserts nothing about its meaning. */
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

struct rec {
    __u64 ts;
    __u8 dir;
    char type;
    __u16 flags;
    __u32 len, cap;
    __u8 body[64]; /* prefix copy: lk_msg.body is valid only in the callback */
};

static struct rec recs[16];
static int nrecs;
static int nresyncs;

static void on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct rec *r = &recs[nrecs % 16];
    __u32 nbody = m->body_cap < sizeof(r->body) ? m->body_cap : (__u32)sizeof(r->body);

    (void)ctx;
    (void)c;
    nrecs++;
    r->ts = m->ts_ns;
    r->dir = dir;
    r->type = m->type;
    r->flags = m->flags;
    r->len = m->len;
    r->cap = m->body_cap;
    memset(r->body, 0, sizeof(r->body));
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
        __u8 raw[sizeof(struct lk_ev_data) + 32768];
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

static void feed_call(enum lk_dir dir, const void *p, __u32 n, __u64 ts)
{
    feed(dir, n, 0, p, n, ts);
}

static const char REQ[] = "GET /hello HTTP/1.1\r\nHost: h\r\n\r\n";
static const char RESP[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

/* --- tests ---------------------------------------------------------------- */

/* The seam itself: bytes reach the protocol, messages come back out through
 * lk_reasm_emit, and none of the message-machine state was touched on the way.
 * The generic counters are kept in one place for both modes. */
static int test_stream_reaches_protocol(void)
{
    reset();
    feed_call(LK_DIR_RECV, REQ, sizeof(REQ) - 1, 100);
    feed_call(LK_DIR_SEND, RESP, sizeof(RESP) - 1, 200);

    CHECK(nrecs == 5); /* R E | S D E */
    CHECK(recs[0].dir == LK_DIR_RECV && recs[0].ts == 100);
    CHECK(recs[0].cap == sizeof(REQ) - 1 && !memcmp(recs[0].body, REQ, 20));
    CHECK(recs[2].dir == LK_DIR_SEND && recs[2].ts == 200);
    CHECK(reasm.st.msgs == 5 && reasm.st.holes == 0 && reasm.st.resyncs == 0);
    /* The message machine never ran: no header accumulated, no body buffered,
     * no state left behind. */
    CHECK(conn.frame[LK_DIR_RECV].hdr_len == 0 && conn.frame[LK_DIR_RECV].buf == NULL);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_HEADER);
    CHECK(conn.frame_state != NULL);
    return 0;
}

/* The scratch a stream framer needs comes from the reassembly slab pool, not
 * from frame_state (which must stay one flat allocation) and not from a
 * private malloc: it is parked in lk_frame.buf, so Р11's ceiling covers it and
 * the connection table frees it on every removal path. The message boundary
 * gives it back. */
static int test_slab_borrowed_and_returned(void)
{
    reset();
    feed_call(LK_DIR_RECV, REQ, 12, 10); /* half a head: the slab is taken */
    CHECK(nrecs == 0);
    CHECK(conn.frame[LK_DIR_RECV].buf != NULL);
    CHECK(conn.frame[LK_DIR_RECV].buf_len == 12);
    CHECK(reasm.pool_n == 0);

    feed_call(LK_DIR_RECV, REQ + 12, sizeof(REQ) - 13, 11);
    CHECK(nrecs == 2);
    CHECK(conn.frame[LK_DIR_RECV].buf == NULL); /* ... and given back */
    CHECK(reasm.pool_n == 1);
    return 0;
}

/* A hole reaches the protocol as a hole and is counted generically, whatever
 * the protocol then decides it means. */
static int test_hole_counted(void)
{
    struct http_frame *hf;

    reset();
    /* An uncaptured call tail: 200 bytes promised, 8 captured. The remainder
     * is only recognised at the next call — the generic lazy-tail rule. */
    feed(LK_DIR_SEND, 200, 0, RESP, 8, 10);
    CHECK(reasm.st.holes == 0);
    feed_call(LK_DIR_SEND, RESP, sizeof(RESP) - 1, 20);
    CHECK(reasm.st.holes == 1 && reasm.st.hole_bytes == 192);

    /* An intra-call gap between two chunks is a hole of known size too. */
    static __u8 filler[100];

    memset(filler, 'b', sizeof(filler));
    feed(LK_DIR_RECV, 100, 0, filler, 10, 30);
    feed(LK_DIR_RECV, 100, 40, filler, 60, 31);
    CHECK(reasm.st.holes == 2 && reasm.st.hole_bytes == 192 + 30);

    hf = conn.frame_state;
    CHECK(hf != NULL);
    CHECK(hf->d[LK_DIR_SEND].events == 2 && hf->d[LK_DIR_SEND].holes == 1);
    CHECK(hf->d[LK_DIR_RECV].events == 2 && hf->d[LK_DIR_RECV].holes == 1);
    /* off tracks every byte the direction owned, captured or not. */
    CHECK(hf->d[LK_DIR_SEND].off == 8 + 192 + sizeof(RESP) - 1);
    CHECK(hf->d[LK_DIR_RECV].off == 10 + 30 + 60);
    return 0;
}

/* Loss dirties both directions before the framer ever sees the next byte (the
 * conn table's seq detector; a synthetic or lazily created entry starts that
 * way). A stream protocol leaves that state itself, through lk_reasm_resync:
 * the counter and the callback fire once and the next message is stamped
 * LK_MSG_AFTER_RESYNC. */
static int test_resync_from_dirty(void)
{
    reset();
    conn.flags |= LK_CONN_SYNTHETIC;
    conn.frame[LK_DIR_RECV].st = LK_FR_DIRTY;
    conn.frame[LK_DIR_SEND].st = LK_FR_DIRTY;

    feed_call(LK_DIR_SEND, RESP, sizeof(RESP) - 1, 10);
    CHECK(nresyncs == 1 && reasm.st.resyncs == 1);
    CHECK(nrecs == 3 && (recs[0].flags & LK_MSG_AFTER_RESYNC));
    CHECK(conn.frame[LK_DIR_SEND].st != LK_FR_DIRTY);

    /* Only the direction that got bytes resynchronised; the stamp is one-shot. */
    feed_call(LK_DIR_SEND, RESP, sizeof(RESP) - 1, 20);
    CHECK(nresyncs == 1 && !(recs[3 % 16].flags & LK_MSG_AFTER_RESYNC));
    CHECK(conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);

    feed_call(LK_DIR_RECV, REQ, sizeof(REQ) - 1, 30);
    CHECK(nresyncs == 2);
    return 0;
}

/* The generic guards run *before* the fork, so a stream protocol inherits them
 * unchanged: a deliberate blind zone (LK_CONN_IGNORE) and ciphertext on a TLS
 * connection never reach the protocol at all. */
static int test_generic_guards_apply(void)
{
    reset();
    conn.flags |= LK_CONN_IGNORE;
    feed_call(LK_DIR_RECV, REQ, sizeof(REQ) - 1, 10);
    CHECK(nrecs == 0 && conn.frame_state == NULL);

    reset();
    conn.flags |= LK_CONN_TLS;
    feed_call(LK_DIR_RECV, REQ, sizeof(REQ) - 1, 10);
    CHECK(nrecs == 0 && conn.frame_state == NULL);
    return 0;
}

/* An off-anomaly (off past total_len) dirties the direction through the
 * generic path; the stream framer then resynchronises on its own anchor rather
 * than silently framing corrupt input. */
static int test_off_anomaly(void)
{
    reset();
    feed(LK_DIR_SEND, 50, 60, "\x01\x02\x03\x04\x05\x06\x07\x08", 8, 10);
    CHECK(reasm.st.off_anomalies == 1);
    CHECK(nrecs == 0 && nresyncs == 0);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);

    feed_call(LK_DIR_SEND, RESP, sizeof(RESP) - 1, 20);
    CHECK(nresyncs == 1 && (recs[0].flags & LK_MSG_AFTER_RESYNC));
    return 0;
}

/* РH15, the invariant the whole track is measured against: a PG connection
 * frames exactly as before while an HTTP one shares the framer. The two use
 * disjoint state (lk_frame vs frame_state) and only meet in the counters. */
static int test_pg_unaffected_alongside(void)
{
    static struct lk_conn pgconn;
    __u8 wire[64];
    __u32 n;

    reset();
    memset(&pgconn, 0, sizeof(pgconn));
    pgconn.ops = &lk_proto_pg_ops;
    pgconn.frame[LK_DIR_RECV].startup_done = 1;

    /* 'Q' + len(4+9) + "select 1" — a plain simple query. */
    wire[0] = 'Q';
    wire[1] = 0;
    wire[2] = 0;
    wire[3] = 0;
    wire[4] = 13;
    memcpy(wire + 5, "select 1", 9);
    n = 14;

    feed_call(LK_DIR_RECV, REQ, sizeof(REQ) - 1, 10);
    lk_frame_bytes(&reasm, &pgconn, LK_DIR_RECV, wire, n, 20);
    feed_call(LK_DIR_SEND, RESP, sizeof(RESP) - 1, 30);

    CHECK(nrecs == 6);
    CHECK(recs[2].type == 'Q' && recs[2].len == 13 && recs[2].cap == 9);
    CHECK(!strcmp((char *)recs[2].body, "select 1"));
    /* The PG connection ran the message machine: header consumed, back at a
     * message boundary, and it grew no stream state. */
    CHECK(pgconn.frame[LK_DIR_RECV].st == LK_FR_HEADER && pgconn.frame_state == NULL);
    CHECK(conn.frame_state != NULL);
    return 0;
}

int main(void)
{
    if (test_stream_reaches_protocol() || test_slab_borrowed_and_returned() ||
        test_hole_counted() || test_resync_from_dirty() || test_generic_guards_apply() ||
        test_off_anomaly() || test_pg_unaffected_alongside())
        return 1;
    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    free(conn.frame_state);
    lk_reasm_free(&reasm);
    printf("ok\n");
    return 0;
}
