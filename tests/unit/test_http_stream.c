// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the framer's stream mode (РH1, PLAN-HTTP.md М1) — the second
 * framing mode of lk_proto_ops, driven through the very lk_reasm_data path the
 * agent uses, with the М1 HTTP stub as its only implementation.
 *
 * What is asserted here is the *seam*, not HTTP: that a LK_PROTO_F_STREAM
 * protocol receives the byte stream after every generic step and none of the
 * message-machine ones; that lk_reasm_emit/lk_reasm_resync keep the lk_msg
 * contract and the counters the message mode keeps; that frame_state follows
 * the connection through every removal path; and — the point of the whole
 * exercise (РH15) — that a stream protocol on one connection changes nothing
 * for a PG connection on the same framer.
 *
 * The М1 stub's own behaviour (one message per capture event, typed by
 * direction) is asserted as a contract because that is what the М1 acceptance
 * check runs over the trace corpus; М2 replaces it with the real framer and
 * this file keeps only the seam tests. */
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
    __u32 nbody = m->body_cap < sizeof(r->body) ? m->body_cap : sizeof(r->body);

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

/* The baseline contract: every captured event becomes exactly one message,
 * typed by direction, carrying that event's bytes and timestamp. Nothing is
 * accumulated across events and no header is parsed — the М1 stub frames
 * nothing, which is what makes "one message per event" checkable over the М0
 * corpus. */
static int test_event_per_message(void)
{
    reset();
    feed_call(LK_DIR_RECV, REQ, sizeof(REQ) - 1, 100);
    feed_call(LK_DIR_SEND, RESP, sizeof(RESP) - 1, 200);

    CHECK(nrecs == 2);
    CHECK(recs[0].type == LK_HTTP_MSG_REQ && recs[0].dir == LK_DIR_RECV);
    CHECK(recs[0].ts == 100 && recs[0].len == sizeof(REQ) - 1);
    CHECK(recs[0].cap == sizeof(REQ) - 1 && !memcmp(recs[0].body, REQ, 20));
    CHECK(recs[1].type == LK_HTTP_MSG_RESP && recs[1].dir == LK_DIR_SEND);
    CHECK(recs[1].ts == 200 && recs[1].len == sizeof(RESP) - 1);
    CHECK(recs[0].flags == 0 && recs[1].flags == 0);
    CHECK(reasm.st.msgs == 2 && reasm.st.holes == 0 && reasm.st.resyncs == 0);
    /* The message machine never ran: no header was accumulated, no body
     * buffered, no state left behind. */
    CHECK(conn.frame[LK_DIR_RECV].hdr_len == 0 && conn.frame[LK_DIR_RECV].buf == NULL);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_HEADER);
    return 0;
}

/* A chunk larger than the body-prefix ceiling is published as a prefix with
 * LK_MSG_BODY_TRUNC, and the truncation counter follows — lk_reasm_emit keeps
 * the same accounting the message mode does. */
static int test_body_trunc(void)
{
    static __u8 big[LK_MSG_BODY_MAX + 1024];

    reset();
    memset(big, 'x', sizeof(big));
    feed_call(LK_DIR_SEND, big, sizeof(big), 10);

    CHECK(nrecs == 1);
    CHECK(recs[0].len == sizeof(big) && recs[0].cap == LK_MSG_BODY_MAX);
    CHECK(recs[0].flags & LK_MSG_BODY_TRUNC);
    CHECK(reasm.st.msgs == 1 && reasm.st.msgs_trunc == 1);
    return 0;
}

/* A hole reaches the protocol as a hole and is counted generically; the stub
 * publishes no message for it (there is nothing to publish — the bytes are
 * gone), and framing continues on the next event. */
static int test_hole_counted_not_emitted(void)
{
    struct http_frame *hf;

    reset();
    /* An uncaptured call tail: 200 bytes promised, 8 captured. The remainder
     * is only recognised at the next call — the generic lazy-tail rule. */
    feed(LK_DIR_SEND, 200, 0, RESP, 8, 10);
    CHECK(nrecs == 1 && reasm.st.holes == 0);
    feed_call(LK_DIR_SEND, RESP, sizeof(RESP) - 1, 20);
    CHECK(nrecs == 2);
    CHECK(reasm.st.holes == 1 && reasm.st.hole_bytes == 192);

    /* An intra-call gap between two chunks is a hole of known size too. */
    static __u8 filler[100];

    memset(filler, 'b', sizeof(filler));
    feed(LK_DIR_RECV, 100, 0, filler, 10, 30);
    feed(LK_DIR_RECV, 100, 40, filler, 60, 31);
    CHECK(nrecs == 4);
    CHECK(reasm.st.holes == 2 && reasm.st.hole_bytes == 192 + 30);

    hf = conn.frame_state;
    CHECK(hf != NULL);
    CHECK(hf->events[LK_DIR_SEND] == 2 && hf->holes[LK_DIR_SEND] == 1);
    CHECK(hf->events[LK_DIR_RECV] == 2 && hf->holes[LK_DIR_RECV] == 1);
    /* off tracks every byte the direction owned, captured or not. */
    CHECK(hf->off[LK_DIR_SEND] == 8 + 192 + sizeof(RESP) - 1);
    CHECK(hf->off[LK_DIR_RECV] == 10 + 30 + 60);
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
    CHECK(nrecs == 1 && (recs[0].flags & LK_MSG_AFTER_RESYNC));
    CHECK(conn.frame[LK_DIR_SEND].st != LK_FR_DIRTY);

    /* Only the direction that got bytes resynchronised; the stamp is one-shot. */
    feed_call(LK_DIR_SEND, RESP, sizeof(RESP) - 1, 20);
    CHECK(nresyncs == 1 && nrecs == 2 && !(recs[1].flags & LK_MSG_AFTER_RESYNC));
    CHECK(conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);

    feed_call(LK_DIR_RECV, REQ, sizeof(REQ) - 1, 30);
    CHECK(nresyncs == 2 && nrecs == 3 && (recs[2].flags & LK_MSG_AFTER_RESYNC));
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
 * generic path; the stream framer then resynchronises on the next sane event
 * rather than silently framing corrupt input. */
static int test_off_anomaly(void)
{
    reset();
    feed(LK_DIR_SEND, 50, 60, RESP, 8, 10);
    CHECK(reasm.st.off_anomalies == 1);
    CHECK(nrecs == 1 && nresyncs == 1 && (recs[0].flags & LK_MSG_AFTER_RESYNC));
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

    CHECK(nrecs == 3);
    CHECK(recs[0].type == LK_HTTP_MSG_REQ);
    CHECK(recs[1].type == 'Q' && recs[1].len == 13 && recs[1].cap == 9);
    CHECK(!strcmp((char *)recs[1].body, "select 1"));
    CHECK(recs[2].type == LK_HTTP_MSG_RESP);
    /* The PG connection ran the message machine: header consumed, back at a
     * message boundary, and it grew no stream state. */
    CHECK(pgconn.frame[LK_DIR_RECV].st == LK_FR_HEADER && pgconn.frame_state == NULL);
    CHECK(conn.frame_state != NULL);
    return 0;
}

int main(void)
{
    if (test_event_per_message() || test_body_trunc() || test_hole_counted_not_emitted() ||
        test_resync_from_dirty() || test_generic_guards_apply() || test_off_anomaly() ||
        test_pg_unaffected_alongside())
        return 1;
    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    free(conn.frame_state);
    lk_reasm_free(&reasm);
    printf("ok\n");
    return 0;
}
