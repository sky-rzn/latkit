// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the streaming framer (task 2.3): synthetic data events go
 * through the same lk_reasm_data path the agent uses. Scenarios from
 * STAGE2.md: a message split over chunks and calls; several messages in one
 * chunk; a body larger than LK_MSG_BODY_MAX; a body fully covered by a known
 * hole (header seen — sync holds); a hole over a header (dirty); a chunk
 * missing inside a call; startup framing; len sanity; off anomalies;
 * timestamp attribution (Р13). */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reassembly.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* --- captured sink output ------------------------------------------------ */

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

static void on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct rec *r = &recs[nrecs % 16];

    (void)ctx;
    (void)c;
    nrecs++;
    r->ts = m->ts_ns;
    r->dir = dir;
    r->type = m->type;
    r->flags = m->flags;
    r->len = m->len;
    r->cap = m->body_cap;
    memcpy(r->body, m->body, m->body_cap < sizeof(r->body) ? m->body_cap : sizeof(r->body));
}

static struct lk_reasm reasm;
static struct lk_conn conn;

static void reset(void)
{
    static const struct lk_msg_sink sink = {.on_msg = on_msg};

    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    memset(&conn, 0, sizeof(conn));
    lk_reasm_init(&reasm, &sink);
    nrecs = 0;
}

/* --- builders ------------------------------------------------------------ */

static void wr32(__u8 *p, __u32 v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

static __u32 pgmsg(__u8 *out, char type, const void *body, __u32 blen)
{
    out[0] = type;
    wr32(out + 1, blen + 4);
    if (blen)
        memcpy(out + 5, body, blen);
    return blen + 5;
}

static __u32 pgstartup(__u8 *out, __u32 code, const void *body, __u32 blen)
{
    wr32(out, blen + 8);
    wr32(out + 4, code);
    if (blen)
        memcpy(out + 8, body, blen);
    return blen + 8;
}

/* One data event: a chunk of a call. Callers model calls by off/total. */
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

/* A fully captured call in one chunk — the common case. */
static void feed_call(enum lk_dir dir, const void *p, __u32 n, __u64 ts)
{
    feed(dir, n, 0, p, n, ts);
}

static int frame_clean(enum lk_dir dir)
{
    return conn.frame[dir].st == LK_FR_HEADER;
}

/* --- tests ---------------------------------------------------------------- */

/* Several messages in one chunk split cleanly and share the chunk's ts
 * (Р13); an empty-body message emits with cap 0. */
static int test_multiple_in_one_chunk(void)
{
    __u8 wire[256];
    __u32 n = 0;

    reset();
    n += pgmsg(wire + n, 'T', "fields", 6);
    n += pgmsg(wire + n, 'D', "row-1", 5);
    n += pgmsg(wire + n, 'n', NULL, 0); /* NoData: len == 4, empty body */
    n += pgmsg(wire + n, 'Z', "I", 1);
    feed_call(LK_DIR_SEND, wire, n, 777);

    CHECK(nrecs == 4);
    CHECK(recs[0].type == 'T' && recs[0].len == 10 && recs[0].cap == 6);
    CHECK(memcmp(recs[0].body, "fields", 6) == 0);
    CHECK(recs[1].type == 'D' && recs[1].len == 9 && recs[1].cap == 5);
    CHECK(recs[2].type == 'n' && recs[2].len == 4 && recs[2].cap == 0);
    CHECK(recs[3].type == 'Z' && recs[3].len == 5 && recs[3].body[0] == 'I');
    for (int i = 0; i < 4; i++) {
        CHECK(recs[i].ts == 777 && recs[i].dir == LK_DIR_SEND);
        CHECK(recs[i].flags == 0);
    }
    CHECK(frame_clean(LK_DIR_SEND));
    CHECK(reasm.st.msgs == 4 && reasm.st.holes == 0);
    return 0;
}

/* A message torn across chunks and calls reassembles; its ts is the event
 * of the first header byte, even when the header itself is split (Р13). */
static int test_split_across_calls(void)
{
    __u8 wire[64];
    __u32 n = pgmsg(wire, 'D', "hello, world", 12);

    reset();
    CHECK(n == 17);
    /* Call 1 (6 bytes) arrives as two chunks: 3 bytes of header + the rest. */
    feed(LK_DIR_SEND, 6, 0, wire, 3, 100);
    feed(LK_DIR_SEND, 6, 3, wire + 3, 3, 105);
    CHECK(nrecs == 0); /* body incomplete, buffered */
    /* Call 2 delivers the remaining 11 bytes. */
    feed_call(LK_DIR_SEND, wire + 6, 11, 200);

    CHECK(nrecs == 1);
    CHECK(recs[0].type == 'D' && recs[0].len == 16 && recs[0].cap == 12);
    CHECK(memcmp(recs[0].body, "hello, world", 12) == 0);
    CHECK(recs[0].ts == 100 && recs[0].flags == 0);
    CHECK(frame_clean(LK_DIR_SEND));
    return 0;
}

/* A body larger than LK_MSG_BODY_MAX: the prefix is captured, the tail is
 * skipped by len, the next message frames normally. */
static int test_body_over_max(void)
{
    static __u8 wire[LK_MSG_BODY_MAX + 4096];
    __u32 body_len = LK_MSG_BODY_MAX + 3000;
    __u32 n;

    reset();
    wire[0] = 'D';
    wr32(wire + 1, body_len + 4);
    for (__u32 i = 0; i < body_len; i++)
        wire[5 + i] = (__u8)i;
    n = 5 + body_len;
    n += pgmsg(wire + n, 'Z', "I", 1);

    /* Feed as fully captured calls of 4096 — the PG output-buffer pattern. */
    for (__u32 pos = 0; pos < n; pos += 4096) {
        __u32 sz = n - pos < 4096 ? n - pos : 4096;

        feed_call(LK_DIR_SEND, wire + pos, sz, 300 + pos);
    }

    CHECK(nrecs == 2);
    CHECK(recs[0].type == 'D' && recs[0].len == body_len + 4);
    CHECK(recs[0].cap == LK_MSG_BODY_MAX && (recs[0].flags & LK_MSG_BODY_TRUNC));
    CHECK(recs[0].ts == 300);
    for (int i = 0; i < 64; i++)
        CHECK(recs[0].body[i] == (__u8)i);
    CHECK(recs[1].type == 'Z' && !(recs[1].flags & LK_MSG_BODY_TRUNC));
    CHECK(frame_clean(LK_DIR_SEND));
    CHECK(reasm.st.msgs_trunc == 1);

    /* A body of exactly LK_MSG_BODY_MAX is complete: no TRUNC, no skip. */
    reset();
    wr32(wire + 1, LK_MSG_BODY_MAX + 4);
    n = 5 + LK_MSG_BODY_MAX;
    feed_call(LK_DIR_SEND, wire, n, 400);
    CHECK(nrecs == 1 && recs[0].cap == LK_MSG_BODY_MAX && recs[0].flags == 0);
    CHECK(frame_clean(LK_DIR_SEND));
    return 0;
}

/* The capture budget cuts a call after the message header: the body becomes
 * a hole of known size, the message emits with the captured prefix and sync
 * holds — the defining property of Р9. */
static int test_body_in_known_hole(void)
{
    __u8 wire[256];
    __u32 n;

    /* Header only captured: total covers header + 1000-byte body, budget
     * left just 5 bytes. The tail hole is flushed by the next call. */
    reset();
    wire[0] = 'D';
    wr32(wire + 1, 1004);
    feed(LK_DIR_SEND, 1005, 0, wire, 5, 500);
    CHECK(nrecs == 0);
    n = pgmsg(wire, 'Z', "I", 1);
    feed_call(LK_DIR_SEND, wire, n, 600);

    CHECK(nrecs == 2);
    CHECK(recs[0].type == 'D' && recs[0].len == 1004 && recs[0].cap == 0);
    CHECK((recs[0].flags & LK_MSG_BODY_TRUNC) && recs[0].ts == 500);
    CHECK(recs[1].type == 'Z');
    CHECK(frame_clean(LK_DIR_SEND));
    CHECK(reasm.st.holes == 1 && reasm.st.hole_bytes == 1000);
    CHECK(reasm.st.hdr_holes == 0);

    /* Same with a partially captured body: the prefix survives. */
    reset();
    wire[0] = 'D';
    wr32(wire + 1, 104);
    memcpy(wire + 5, "0123456789", 10);
    feed(LK_DIR_SEND, 105, 0, wire, 15, 700); /* header + 10 of 100 body bytes */
    n = pgmsg(wire, 'Z', "I", 1);
    feed_call(LK_DIR_SEND, wire, n, 800);

    CHECK(nrecs == 2);
    CHECK(recs[0].type == 'D' && recs[0].cap == 10 && (recs[0].flags & LK_MSG_BODY_TRUNC));
    CHECK(memcmp(recs[0].body, "0123456789", 10) == 0);
    CHECK(recs[1].type == 'Z' && frame_clean(LK_DIR_SEND));
    return 0;
}

/* A hole that lands on a message header loses sync: the direction goes
 * dirty and later events are discarded until the task-2.4 resync. */
static int test_hole_over_header(void)
{
    __u8 wire[64];
    __u32 n;

    reset();
    feed(LK_DIR_SEND, 100, 0, NULL, 0, 900); /* nothing captured of the call */
    CHECK(nrecs == 0);
    n = pgmsg(wire, 'Z', "I", 1);
    feed_call(LK_DIR_SEND, wire, n, 1000); /* flushes hole(100) first */

    CHECK(nrecs == 0);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    CHECK(reasm.st.hdr_holes == 1);
    feed_call(LK_DIR_SEND, wire, n, 1100); /* still discarded */
    CHECK(nrecs == 0 && reasm.st.msgs == 0);
    return 0;
}

/* A chunk missing inside a call (off jumps forward) is a known hole: it cuts
 * the in-flight body, the remainder is skipped by len, sync holds. */
static int test_chunk_gap_in_call(void)
{
    static __u8 wire[2048];
    __u8 zmsg[8];
    __u32 n;

    reset();
    wire[0] = 'D';
    wr32(wire + 1, 1004);
    memset(wire + 5, 'x', 1000);
    /* One call of 1005 bytes; the middle chunk [205, 505) never arrives. */
    feed(LK_DIR_SEND, 1005, 0, wire, 205, 1200);
    feed(LK_DIR_SEND, 1005, 505, wire + 505, 500, 1210);
    n = pgmsg(zmsg, 'Z', "I", 1);
    feed_call(LK_DIR_SEND, zmsg, n, 1300);

    CHECK(nrecs == 2);
    CHECK(recs[0].type == 'D' && recs[0].cap == 200 && (recs[0].flags & LK_MSG_BODY_TRUNC));
    CHECK(recs[1].type == 'Z');
    CHECK(frame_clean(LK_DIR_SEND));
    CHECK(reasm.st.holes == 1 && reasm.st.hole_bytes == 300);
    CHECK(reasm.st.off_anomalies == 0);
    return 0;
}

/* Frontend startup framing (Р10 minimum for 2.3): length-only messages with
 * LK_MSG_STARTUP until a StartupMessage switches to normal framing, so the
 * SSLRequest -> StartupMessage prelude frames without a type byte. */
static int test_startup(void)
{
    static const __u8 params[] = "user\0postgres\0\0";
    __u8 wire[128];
    __u32 n;

    reset();
    n = pgstartup(wire, 80877103, NULL, 0); /* SSLRequest */
    feed_call(LK_DIR_RECV, wire, n, 2000);
    CHECK(nrecs == 1);
    CHECK(recs[0].type == 0 && (recs[0].flags & LK_MSG_STARTUP));
    CHECK(recs[0].len == 8 && recs[0].cap == 4);

    n = pgstartup(wire, LK_PG_PROTO_V3, params, sizeof(params));
    feed_call(LK_DIR_RECV, wire, n, 2100);
    CHECK(nrecs == 2);
    CHECK((recs[1].flags & LK_MSG_STARTUP) && recs[1].len == 8 + sizeof(params));
    CHECK(memcmp(recs[1].body + 4, params, sizeof(params)) == 0);

    n = pgmsg(wire, 'Q', "select 1", 8); /* normal framing from here on */
    feed_call(LK_DIR_RECV, wire, n, 2200);
    CHECK(nrecs == 3);
    CHECK(recs[2].type == 'Q' && !(recs[2].flags & LK_MSG_STARTUP));
    CHECK(recs[2].len == 12 && recs[2].cap == 8);
    CHECK(frame_clean(LK_DIR_RECV));
    return 0;
}

/* len sanity (Р10): < 4 (or < 8 for startup) and > 2^30 are corruption. */
static int test_bad_len(void)
{
    __u8 wire[8];

    reset();
    wire[0] = 'X';
    wr32(wire + 1, 3); /* len < 4 */
    feed_call(LK_DIR_SEND, wire, 5, 3000);
    CHECK(nrecs == 0 && conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    CHECK(reasm.st.bad_len == 1);

    reset();
    wire[0] = 'D';
    wr32(wire + 1, 0x7fffffff); /* len > 2^30 */
    feed_call(LK_DIR_SEND, wire, 5, 3100);
    CHECK(nrecs == 0 && conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    CHECK(reasm.st.bad_len == 1);

    reset();
    wr32(wire, 5); /* startup len < 8: no room for the code */
    feed_call(LK_DIR_RECV, wire, 4, 3200);
    CHECK(nrecs == 0 && conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);
    CHECK(reasm.st.bad_len == 1);
    return 0;
}

/* off anomalies (chunk arithmetic diverging from reality) dirty the
 * direction and are counted — never silent corruption. */
static int test_off_anomalies(void)
{
    __u8 wire[256];

    /* off going backwards within a call. */
    reset();
    wire[0] = 'D';
    wr32(wire + 1, 199);
    memset(wire + 5, 'y', 195);
    feed(LK_DIR_SEND, 200, 0, wire, 100, 4000);
    feed(LK_DIR_SEND, 200, 50, wire + 50, 10, 4010);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    CHECK(reasm.st.off_anomalies == 1 && nrecs == 0);

    /* off + cap_len past total_len. */
    reset();
    feed(LK_DIR_SEND, 100, 90, wire, 20, 4100);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    CHECK(reasm.st.off_anomalies == 1);

    /* total_len changing mid-call. */
    reset();
    feed(LK_DIR_SEND, 200, 0, wire, 100, 4200);
    feed(LK_DIR_SEND, 300, 100, wire + 100, 50, 4210);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    CHECK(reasm.st.off_anomalies == 1);
    return 0;
}

int main(void)
{
    if (test_multiple_in_one_chunk() || test_split_across_calls() || test_body_over_max() ||
        test_body_in_known_hole() || test_hole_over_header() || test_chunk_gap_in_call() ||
        test_startup() || test_bad_len() || test_off_anomalies())
        return 1;
    printf("ok\n");
    return 0;
}
