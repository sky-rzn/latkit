// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the MySQL classic-protocol framer (МYSQL.md М2,
 * src/proto/my/my_frame.c) — the test_reassembly.c matrix rerun over
 * lk_proto_my_ops plus the MySQL-only cases: 16MB continuation glue (bytes,
 * spill, hole and empty-terminator paths; torn glue), the connection phase
 * (greeting, HandshakeResponse, auth round-trips, the terminating OK),
 * frontend command typing by wire seq, the CLIENT_SSL and CLIENT_COMPRESS
 * transitions, and the РМ4 call-boundary resync anchors of both directions.
 * Same harness style: synthetic data events through lk_reasm_data. */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proto.h"

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
    __u8 type;
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
    r->type = (__u8)m->type;
    r->flags = m->flags;
    r->len = m->len;
    r->cap = m->body_cap;
    __u32 nbody = m->body_cap < sizeof(r->body) ? m->body_cap : sizeof(r->body);
    if (nbody)
        memcpy(r->body, m->body, nbody);
}

static int nresyncs;
static __u8 last_resync_dir;

static void on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    (void)ctx;
    (void)c;
    nresyncs++;
    last_resync_dir = dir;
}

static struct lk_reasm reasm;
static struct lk_conn conn;

/* Event flags feed() stamps on every event (LK_F_DECRYPTED mimics the uprobe
 * channel); cleared by reset(). */
static __u16 feed_flags;

static void reset(void)
{
    static const struct lk_msg_sink sink = {.on_msg = on_msg, .on_resync = on_resync};

    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    lk_reasm_free(&reasm);
    memset(&conn, 0, sizeof(conn));
    conn.ops = &lk_proto_my_ops;
    lk_reasm_init(&reasm, &sink);
    nrecs = 0;
    nresyncs = 0;
    feed_flags = 0;
}

/* Skip the connection phase: mid-session framing state, as after a completed
 * handshake (or a resync — do_resync forces the same bits). */
static void cmd_phase(void)
{
    conn.frame[LK_DIR_RECV].startup_done = 1;
    conn.frame[LK_DIR_SEND].startup_done = 1;
}

/* --- builders ------------------------------------------------------------ */

#define PKT_MAX 0xFFFFFFu

/* One classic packet: len(u24 LE) + seq + payload. */
static __u32 mypkt(__u8 *out, __u8 seq, const void *payload, __u32 len)
{
    out[0] = (__u8)len;
    out[1] = (__u8)(len >> 8);
    out[2] = (__u8)(len >> 16);
    out[3] = seq;
    if (len)
        memcpy(out + 4, payload, len);
    return len + 4;
}

/* A continuation-run head: header claiming 0xFFFFFF, no payload written. */
static void myhdr(__u8 *out, __u8 seq, __u32 len)
{
    out[0] = (__u8)len;
    out[1] = (__u8)(len >> 8);
    out[2] = (__u8)(len >> 16);
    out[3] = seq;
}

/* HandshakeResponse41 prefix: client capability flags (u32 LE) + max packet
 * size + charset + 23-byte filler; `tail` (user etc.) appended verbatim. */
static __u32 hs_response(__u8 *out, __u32 caps, const char *tail)
{
    __u32 n = 32;

    memset(out, 0, n);
    out[0] = (__u8)caps;
    out[1] = (__u8)(caps >> 8);
    out[2] = (__u8)(caps >> 16);
    out[3] = (__u8)(caps >> 24);
    if (tail) {
        memcpy(out + n, tail, strlen(tail) + 1);
        n += strlen(tail) + 1;
    }
    return n;
}

/* Client capability sets (my_frame reads only SSL/COMPRESS/ZSTD). */
#define CAPS_PLAIN    0x00000589u
#define CAPS_SSL      0x00000a89u /* CLIENT_SSL (0x800) set */
#define CAPS_COMPRESS 0x000005a9u /* CLIENT_COMPRESS (0x20) set */
#define CAPS_ZSTD     0x04000589u /* CLIENT_ZSTD_COMPRESSION_ALGORITHM */

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
    u.d.hdr.flags = feed_flags;
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

static int frame_clean(enum lk_dir dir)
{
    return conn.frame[dir].st == LK_FR_HEADER;
}

/* --- connection phase ----------------------------------------------------- */

/* Greeting -> HandshakeResponse -> auth round-trips -> OK: all framed and
 * flagged LK_MSG_STARTUP, none typed; the first command after OK is typed by
 * its command byte and unflagged; response packets stay type 0. */
static int test_connection_phase(void)
{
    static const __u8 greet[] = {0x0a, '8', '.', '4', '.', '1', '0', 0, 1, 0, 0, 0};
    static const __u8 auth_more[] = {0x01, 0x03};            /* fast-path ack */
    static const __u8 scramble[] = {0xde, 0xad, 0xbe, 0xef}; /* client raw reply */
    static const __u8 ok[] = {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
    __u8 wire[256], hs[64];
    __u32 n, hn;

    reset();
    n = mypkt(wire, 0, greet, sizeof(greet));
    feed_call(LK_DIR_SEND, wire, n, 100);
    CHECK(nrecs == 1);
    CHECK(recs[0].type == 0 && (recs[0].flags & LK_MSG_STARTUP));
    CHECK(recs[0].len == sizeof(greet) && recs[0].cap == sizeof(greet));
    CHECK(recs[0].ts == 100 && recs[0].dir == LK_DIR_SEND);

    hn = hs_response(hs, CAPS_PLAIN, "bob");
    n = mypkt(wire, 1, hs, hn);
    feed_call(LK_DIR_RECV, wire, n, 200);
    CHECK(nrecs == 2);
    CHECK(recs[1].type == 0 && (recs[1].flags & LK_MSG_STARTUP) && recs[1].len == hn);
    CHECK(!(conn.flags & (LK_CONN_TLS | LK_CONN_COMPRESS_PENDING)));

    n = mypkt(wire, 2, auth_more, sizeof(auth_more)); /* server: more data */
    feed_call(LK_DIR_SEND, wire, n, 300);
    n = mypkt(wire, 3, scramble, sizeof(scramble)); /* client: raw payload */
    feed_call(LK_DIR_RECV, wire, n, 400);
    CHECK(nrecs == 4);
    CHECK(recs[2].type == 0 && (recs[2].flags & LK_MSG_STARTUP));
    CHECK(recs[3].type == 0 && (recs[3].flags & LK_MSG_STARTUP)); /* seq != 0: no typing */

    n = mypkt(wire, 4, ok, sizeof(ok)); /* the exchange terminator */
    feed_call(LK_DIR_SEND, wire, n, 500);
    CHECK(nrecs == 5);
    CHECK(recs[4].type == 0 && (recs[4].flags & LK_MSG_STARTUP)); /* OK is handshake */
    CHECK(conn.frame[LK_DIR_SEND].startup_done);

    /* Command phase: COM_QUERY typed, not startup-flagged. */
    n = mypkt(wire, 0, "\x03select 1", 9);
    feed_call(LK_DIR_RECV, wire, n, 600);
    CHECK(nrecs == 6);
    CHECK(recs[5].type == 0x03 && !(recs[5].flags & LK_MSG_STARTUP));
    CHECK(recs[5].len == 9 && memcmp(recs[5].body, "\x03select 1", 9) == 0);

    /* Response burst in one chunk: column count, coldef, row, EOF — all
     * type 0, sharing the chunk's ts (Р13). */
    n = mypkt(wire, 1, "\x01", 1);
    n += mypkt(wire + n, 2, "def-col-meta", 12);
    n += mypkt(wire + n, 3,
               "\x01"
               "1",
               2);
    n += mypkt(wire + n, 4, "\xfe\x00\x00\x02\x00", 5);
    feed_call(LK_DIR_SEND, wire, n, 700);
    CHECK(nrecs == 10);
    for (int i = 6; i < 10; i++) {
        CHECK(recs[i].type == 0 && recs[i].flags == 0);
        CHECK(recs[i].ts == 700 && recs[i].dir == LK_DIR_SEND);
    }
    CHECK(recs[6].len == 1 && recs[6].body[0] == 0x01);
    CHECK(recs[9].len == 5 && recs[9].body[0] == 0xfe);
    CHECK(frame_clean(LK_DIR_SEND) && frame_clean(LK_DIR_RECV));
    CHECK(reasm.st.msgs == 10 && reasm.st.holes == 0 && reasm.st.bad_len == 0);
    return 0;
}

/* A packet torn across chunks and calls reassembles; ts is the event of the
 * first header byte even when the header itself is split (Р13). An empty
 * packet (LOAD DATA end marker) emits with cap 0. */
static int test_split_and_empty(void)
{
    __u8 wire[64];
    __u32 n;

    reset();
    cmd_phase();
    n = mypkt(wire, 0, "\x03insert into t values (1)", 25);
    CHECK(n == 29);
    feed(LK_DIR_RECV, 6, 0, wire, 3, 100); /* 3 bytes of header */
    feed(LK_DIR_RECV, 6, 3, wire + 3, 3, 105);
    CHECK(nrecs == 0);
    feed_call(LK_DIR_RECV, wire + 6, 23, 200);
    CHECK(nrecs == 1);
    CHECK(recs[0].type == 0x03 && recs[0].len == 25 && recs[0].cap == 25);
    CHECK(recs[0].ts == 100 && recs[0].flags == 0);
    CHECK(memcmp(recs[0].body, "\x03insert", 7) == 0);

    /* LOAD DATA end marker: an empty client packet at seq > 0. */
    n = mypkt(wire, 4, NULL, 0);
    feed_call(LK_DIR_RECV, wire, n, 300);
    CHECK(nrecs == 2);
    CHECK(recs[1].type == 0 && recs[1].len == 0 && recs[1].cap == 0);
    CHECK(frame_clean(LK_DIR_RECV));
    return 0;
}

/* A body larger than LK_MSG_BODY_MAX in a single wire packet: prefix +
 * TRUNC + arithmetic skip, next packet frames normally. */
static int test_body_over_max(void)
{
    static __u8 wire[LK_MSG_BODY_MAX + 8192];
    __u32 body_len = LK_MSG_BODY_MAX + 3000;
    __u32 n;

    reset();
    cmd_phase();
    myhdr(wire, 0, body_len);
    wire[4] = 0x03;
    for (__u32 i = 1; i < body_len; i++)
        wire[4 + i] = (__u8)i;
    n = 4 + body_len;
    n += mypkt(wire + n, 0, "\x0e", 1); /* COM_PING after it */

    for (__u32 pos = 0; pos < n; pos += 4096) {
        __u32 sz = n - pos < 4096 ? n - pos : 4096;

        feed_call(LK_DIR_RECV, wire + pos, sz, 300 + pos);
    }
    CHECK(nrecs == 2);
    CHECK(recs[0].type == 0x03 && recs[0].len == body_len);
    CHECK(recs[0].cap == LK_MSG_BODY_MAX && (recs[0].flags & LK_MSG_BODY_TRUNC));
    CHECK(recs[0].ts == 300);
    CHECK(recs[0].body[0] == 0x03 && recs[0].body[1] == 1 && recs[0].body[63] == 63);
    CHECK(recs[1].type == 0x0e && !(recs[1].flags & LK_MSG_BODY_TRUNC));
    CHECK(frame_clean(LK_DIR_RECV));
    CHECK(reasm.st.msgs_trunc == 1);
    return 0;
}

/* --- 16MB continuation glue (РМ3) ----------------------------------------- */

/* A logical packet of 0xFFFFFF + k bytes: two wire fragments glued into ONE
 * lk_msg — len is the logical total, the prefix comes from fragment 1 (here
 * collected across two chunks: the spill and the completion paths), the ts is
 * fragment 1's first header byte, the type is the command byte. */
static int test_glue_two_fragments(void)
{
    static __u8 buf[24 * 1024];
    __u32 cap = 4 + 20000, n;

    reset();
    cmd_phase();
    myhdr(buf, 0, PKT_MAX);
    buf[4] = 0x03; /* COM_QUERY */
    for (__u32 i = 1; i < 20000; i++)
        buf[4 + i] = (__u8)i;
    /* One call of header + 16MB-1, budget cut at 20004 captured bytes,
     * arriving as two chunks. */
    feed(LK_DIR_RECV, 4 + PKT_MAX, 0, buf, 8192, 100);
    feed(LK_DIR_RECV, 4 + PKT_MAX, 8192, buf + 8192, cap - 8192, 110);
    CHECK(nrecs == 0);

    /* Fragment 2 in its own call (flushes the tail hole of call 1 first). */
    n = mypkt(buf, 1, "tail-bytes-of-the-logical-packet", 32);
    feed_call(LK_DIR_RECV, buf, n, 200);
    CHECK(nrecs == 1);
    CHECK(recs[0].type == 0x03 && recs[0].dir == LK_DIR_RECV);
    CHECK(recs[0].len == PKT_MAX + 32);
    CHECK(recs[0].cap == LK_MSG_BODY_MAX && (recs[0].flags & LK_MSG_BODY_TRUNC));
    CHECK(recs[0].ts == 100);
    CHECK(recs[0].body[0] == 0x03 && recs[0].body[1] == 1 && recs[0].body[63] == 63);
    CHECK(frame_clean(LK_DIR_RECV));
    CHECK(reasm.st.msgs == 1 && reasm.st.msgs_trunc == 1);
    CHECK(reasm.st.bad_len == 0 && reasm.st.hdr_holes == 0);
    return 0;
}

/* A payload of exactly 0xFFFFFF: the sequence ends with an EMPTY fragment;
 * the glued message emits at that header, len = 0xFFFFFF. */
static int test_glue_exact_multiple(void)
{
    static __u8 buf[20 * 1024];
    __u32 n;

    reset();
    cmd_phase();
    myhdr(buf, 3, PKT_MAX); /* backend row burst mid-response: seq 3 */
    for (__u32 i = 0; i < 17000; i++)
        buf[4 + i] = (__u8)(i * 7);
    feed(LK_DIR_SEND, 4 + PKT_MAX, 0, buf, 17004, 100);
    CHECK(nrecs == 0);

    n = mypkt(buf, 4, NULL, 0); /* empty terminator, seq continues */
    feed_call(LK_DIR_SEND, buf, n, 200);
    CHECK(nrecs == 1);
    CHECK(recs[0].type == 0 && recs[0].len == PKT_MAX);
    CHECK(recs[0].cap == LK_MSG_BODY_MAX && (recs[0].flags & LK_MSG_BODY_TRUNC));
    CHECK(recs[0].ts == 100 && recs[0].body[1] == 7);
    CHECK(frame_clean(LK_DIR_SEND));
    return 0;
}

/* A hole cutting fragment 1 short of the full prefix: the partial prefix is
 * pinned, continuation fragments never top it up (their bytes are ~16MB into
 * the payload), and the final emit carries what was captured. */
static int test_glue_hole_in_first_fragment(void)
{
    static __u8 buf[8192];
    __u32 n;

    reset();
    cmd_phase();
    myhdr(buf, 0, PKT_MAX);
    buf[4] = 0x03;
    memset(buf + 5, 'q', 4999);
    feed(LK_DIR_RECV, 4 + PKT_MAX, 0, buf, 4 + 5000, 100); /* 5000 of the body */
    CHECK(nrecs == 0);

    n = mypkt(buf, 1, "end", 3);
    feed_call(LK_DIR_RECV, buf, n, 200);
    CHECK(nrecs == 1);
    CHECK(recs[0].type == 0x03 && recs[0].len == PKT_MAX + 3);
    CHECK(recs[0].cap == 5000 && (recs[0].flags & LK_MSG_BODY_TRUNC));
    CHECK(recs[0].body[0] == 0x03 && recs[0].body[1] == 'q');
    CHECK(frame_clean(LK_DIR_RECV));
    return 0;
}

/* A continuation header with the wrong seq: the glue is torn (misframing or
 * corruption) — the direction goes dirty via bad_len, nothing is emitted. */
static int test_glue_seq_mismatch(void)
{
    static __u8 buf[8192];
    __u32 n;

    reset();
    cmd_phase();
    myhdr(buf, 0, PKT_MAX);
    memset(buf + 4, 'x', 5000);
    feed(LK_DIR_RECV, 4 + PKT_MAX, 0, buf, 5004, 100);

    n = mypkt(buf, 7, "tail", 4); /* expected seq 1, got 7 */
    feed_call(LK_DIR_RECV, buf, n, 200);
    CHECK(nrecs == 0);
    CHECK(conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);
    CHECK(reasm.st.bad_len == 1);
    return 0;
}

/* A hole swallowing the continuation header: the glued message is dropped
 * (hdr_holes, dirty) — the same loss class as a PG header hole. */
static int test_glue_hole_over_cont_header(void)
{
    static __u8 buf[8192];
    __u32 n;

    reset();
    cmd_phase();
    myhdr(buf, 0, PKT_MAX);
    memset(buf + 4, 'x', 5000);
    feed(LK_DIR_RECV, 4 + PKT_MAX, 0, buf, 5004, 100);

    feed(LK_DIR_RECV, 50, 0, NULL, 0, 200); /* fragment 2's call fully lost */
    /* A mid-stream packet (seq 9: not a boundary anchor) flushes the hole and
     * is then discarded by the dirty direction. */
    n = mypkt(buf, 9, "zz", 2);
    feed_call(LK_DIR_RECV, buf, n, 300);
    CHECK(nrecs == 0);
    CHECK(conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);
    CHECK(reasm.st.hdr_holes == 1);
    CHECK(nresyncs == 0);
    return 0;
}

/* --- holes on a single packet (the Р9 invariants under my_ops) ------------- */

/* Header captured, body in a known hole: the packet emits with the captured
 * prefix (here none), sync holds. */
static int test_body_in_known_hole(void)
{
    __u8 wire[64];
    __u32 n;

    reset();
    cmd_phase();
    myhdr(wire, 1, 1000); /* backend packet, only the header captured */
    feed(LK_DIR_SEND, 4 + 1000, 0, wire, 4, 100);
    CHECK(nrecs == 0);
    n = mypkt(wire, 2, "\x00\x01\x00\x02\x00\x00\x00", 7); /* next packet: OK */
    feed_call(LK_DIR_SEND, wire, n, 200);
    CHECK(nrecs == 2);
    CHECK(recs[0].type == 0 && recs[0].len == 1000 && recs[0].cap == 0);
    CHECK((recs[0].flags & LK_MSG_BODY_TRUNC) && recs[0].ts == 100);
    CHECK(recs[1].len == 7 && recs[1].cap == 7);
    CHECK(frame_clean(LK_DIR_SEND));
    CHECK(reasm.st.holes == 1 && reasm.st.hole_bytes == 1000);
    CHECK(reasm.st.hdr_holes == 0);
    return 0;
}

/* A chunk missing inside a call: known hole, prefix survives, sync holds. */
static int test_chunk_gap_in_call(void)
{
    static __u8 wire[2048];
    __u8 pkt[16];
    __u32 n;

    reset();
    cmd_phase();
    myhdr(wire, 1, 1000);
    memset(wire + 4, 'r', 1000);
    feed(LK_DIR_SEND, 1004, 0, wire, 204, 100); /* [204, 504) lost */
    feed(LK_DIR_SEND, 1004, 504, wire + 504, 500, 110);
    n = mypkt(pkt, 2, "\xfe\x00\x00\x02\x00", 5);
    feed_call(LK_DIR_SEND, pkt, n, 200);
    CHECK(nrecs == 2);
    CHECK(recs[0].cap == 200 && (recs[0].flags & LK_MSG_BODY_TRUNC));
    CHECK(recs[1].body[0] == 0xfe);
    CHECK(frame_clean(LK_DIR_SEND));
    CHECK(reasm.st.holes == 1 && reasm.st.hole_bytes == 300);
    CHECK(reasm.st.off_anomalies == 0);
    return 0;
}

/* A hole over a packet header loses sync until an anchor (РМ4). */
static int test_hole_over_header(void)
{
    __u8 wire[64];
    __u32 n;

    reset();
    cmd_phase();
    feed(LK_DIR_SEND, 100, 0, NULL, 0, 100); /* whole call lost */
    n = mypkt(wire, 5, "mid-response", 12);  /* seq 5: not an anchor */
    feed_call(LK_DIR_SEND, wire, n, 200);    /* flushes hole(100) -> dirty */
    CHECK(nrecs == 0);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    CHECK(reasm.st.hdr_holes == 1);
    feed_call(LK_DIR_SEND, wire, n, 300); /* still discarded */
    CHECK(nrecs == 0 && reasm.st.msgs == 0);
    return 0;
}

/* --- TLS / compression transitions ---------------------------------------- */

/* CLIENT_SSL in the (short) HandshakeResponse: the connection flips to TLS,
 * ciphertext in the same chunk and every later socket event is discarded
 * without dirty counters ticking. */
static int test_ssl(void)
{
    static const __u8 greet[] = {0x0a, '8', '.', '4', 0};
    __u8 wire[128], hs[64];
    __u32 n, hn;

    reset();
    n = mypkt(wire, 0, greet, sizeof(greet));
    feed_call(LK_DIR_SEND, wire, n, 100);

    hn = hs_response(hs, CAPS_SSL, NULL); /* 32 bytes: the short form */
    n = mypkt(wire, 1, hs, hn);
    memcpy(wire + n, "\x16\x03\x01\xff\xff", 5); /* TLS ClientHello-ish tail */
    feed_call(LK_DIR_RECV, wire, n + 5, 200);
    CHECK(nrecs == 2);
    CHECK((recs[1].flags & LK_MSG_STARTUP) && recs[1].len == 32);
    CHECK(conn.flags & LK_CONN_TLS);
    CHECK(!conn.frame[LK_DIR_RECV].startup_done); /* handshake repeats in TLS */
    CHECK(reasm.st.tls_conns == 1);
    CHECK(reasm.st.bad_len == 0 && reasm.st.hdr_holes == 0);

    feed_call(LK_DIR_RECV, wire, 6, 300); /* ciphertext: into the void */
    feed_call(LK_DIR_SEND, wire, 6, 400);
    CHECK(nrecs == 2 && reasm.st.msgs == 2);
    CHECK(reasm.st.bad_len == 0 && reasm.st.off_anomalies == 0);
    return 0;
}

/* The decrypted channel after a TLS flip: framing restarts (the router calls
 * lk_conn_tls_reset_framing), the *full* HandshakeResponse repeats inside TLS
 * — still carrying CLIENT_SSL, which must now read as the real handshake, not
 * as another short SSLRequest — and the first command after auth is typed.
 * The mysql-8.4 client also writes header and payload in separate SSL_write
 * calls; the packet must reassemble across those call boundaries. */
static int test_tls_decrypted_channel(void)
{
    static const __u8 ok[] = {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
    __u8 wire[128], hs[64];
    __u32 n, hn;

    reset();
    conn.flags |= LK_CONN_TLS; /* post-flip: the router reset the framing */
    feed_flags = LK_F_DECRYPTED;

    hn = hs_response(hs, CAPS_SSL, "bob"); /* the inner, full response */
    n = mypkt(wire, 2, hs, hn);
    feed(LK_DIR_RECV, 4, 0, wire, 4, 100); /* header in its own call */
    feed_call(LK_DIR_RECV, wire + 4, n - 4, 110);
    CHECK(nrecs == 1);
    CHECK(recs[0].type == 0 && (recs[0].flags & LK_MSG_STARTUP) && recs[0].len == hn);
    CHECK(conn.frame[LK_DIR_RECV].startup_done); /* consumed as the handshake */

    n = mypkt(wire, 3, ok, sizeof(ok));
    feed_call(LK_DIR_SEND, wire, n, 200);
    n = mypkt(wire, 0, "\x03select 1", 9);
    feed(LK_DIR_RECV, 4, 0, wire, 4, 300); /* split header again */
    feed_call(LK_DIR_RECV, wire + 4, n - 4, 310);
    CHECK(nrecs == 3);
    CHECK(recs[2].type == 0x03 && !(recs[2].flags & LK_MSG_STARTUP));
    CHECK(recs[2].len == 9 && recs[2].ts == 300);
    CHECK(frame_clean(LK_DIR_RECV) && frame_clean(LK_DIR_SEND));
    CHECK(reasm.st.bad_len == 0);
    return 0;
}

/* CLIENT_COMPRESS: the handshake frames in plaintext, the final OK flips the
 * connection into the РМ7 blind zone (IGNORE) — compressed framing is never
 * parsed, later events are discarded. */
static int test_compress(void)
{
    static const __u8 greet[] = {0x0a, '1', '0', '.', '1', '1', 0};
    static const __u8 ok[] = {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
    __u8 wire[128], hs[64];
    __u32 n, hn;

    reset();
    n = mypkt(wire, 0, greet, sizeof(greet));
    feed_call(LK_DIR_SEND, wire, n, 100);

    hn = hs_response(hs, CAPS_COMPRESS, "alice");
    n = mypkt(wire, 1, hs, hn);
    feed_call(LK_DIR_RECV, wire, n, 200);
    CHECK(conn.flags & LK_CONN_COMPRESS_PENDING);
    CHECK(!(conn.flags & LK_CONN_IGNORE)); /* auth still travels uncompressed */

    n = mypkt(wire, 2, ok, sizeof(ok));
    feed_call(LK_DIR_SEND, wire, n, 300);
    CHECK(nrecs == 3);
    CHECK((recs[2].flags & LK_MSG_STARTUP) && recs[2].body[0] == 0x00);
    CHECK(conn.flags & LK_CONN_IGNORE);

    /* Compressed frames from here on: discarded, no counters ticking. */
    n = mypkt(wire, 0, "\x03garbage", 8);
    feed_call(LK_DIR_RECV, wire, n, 400);
    feed_call(LK_DIR_SEND, wire, n, 500);
    CHECK(nrecs == 3 && reasm.st.msgs == 3);
    CHECK(reasm.st.bad_len == 0);

    /* Same negotiation via the zstd flag. */
    reset();
    n = mypkt(wire, 0, greet, sizeof(greet));
    feed_call(LK_DIR_SEND, wire, n, 100);
    hn = hs_response(hs, CAPS_ZSTD, NULL);
    n = mypkt(wire, 1, hs, hn);
    feed_call(LK_DIR_RECV, wire, n, 200);
    CHECK(conn.flags & LK_CONN_COMPRESS_PENDING);
    return 0;
}

/* --- resynchronisation (РМ4) ----------------------------------------------- */

/* Frontend anchor: only a call boundary with seq 0 and a known command byte
 * re-enters framing; mid-call commands, nonzero seqs, unknown bytes and
 * header-only boundaries do not. */
static int test_resync_frontend(void)
{
    __u8 wire[64];
    __u32 n;

    reset();
    cmd_phase();
    feed(LK_DIR_RECV, 50, 0, NULL, 0, 100); /* whole call lost */
    n = mypkt(wire, 3, "load-data-chunk", 15);
    feed_call(LK_DIR_RECV, wire, n, 200); /* flushes the hole -> dirty */
    CHECK(conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY && nrecs == 0);

    /* A valid command mid-call (off != 0): not a boundary. */
    n = mypkt(wire, 0, "\x03select 1", 9);
    feed(LK_DIR_RECV, n + 10, 10, wire, n, 300);
    CHECK(nresyncs == 0 && conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);

    /* A boundary with seq != 0: rejected. */
    n = mypkt(wire, 2, "\x03select 1", 9);
    feed_call(LK_DIR_RECV, wire, n, 400);
    CHECK(nresyncs == 0);

    /* A boundary whose first payload byte is no known command: rejected. */
    n = mypkt(wire, 0, "\x77junk", 5);
    feed_call(LK_DIR_RECV, wire, n, 500);
    CHECK(nresyncs == 0);

    /* A header-only boundary (command byte not captured): rejected. */
    n = mypkt(wire, 0, "\x03select 1", 9);
    feed(LK_DIR_RECV, n, 0, wire, 4, 600);
    CHECK(nresyncs == 0 && conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);

    /* The real thing: boundary + seq 0 + COM_QUERY. */
    feed_call(LK_DIR_RECV, wire, n, 700);
    CHECK(nresyncs == 1 && last_resync_dir == LK_DIR_RECV);
    CHECK(nrecs == 1);
    CHECK(recs[0].type == 0x03 && (recs[0].flags & LK_MSG_AFTER_RESYNC));
    CHECK(recs[0].len == 9 && !(recs[0].flags & LK_MSG_STARTUP));
    CHECK(frame_clean(LK_DIR_RECV));
    CHECK(reasm.st.resyncs == 1);
    return 0;
}

/* Backend anchor (weak): a call boundary at seq 1 with a sane len — a
 * response head; mid-response boundaries (higher seq) are rejected. */
static int test_resync_backend(void)
{
    __u8 wire[64];
    __u32 n;

    reset();
    cmd_phase();
    feed(LK_DIR_SEND, 100, 0, NULL, 0, 100);
    n = mypkt(wire, 5, "rows-tail", 9); /* seq 5: mid-response, no anchor */
    feed_call(LK_DIR_SEND, wire, n, 200);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY && nresyncs == 0);

    n = mypkt(wire, 1, "\x01", 1); /* next response head: column count */
    n += mypkt(wire + n, 2, "col-def", 7);
    feed_call(LK_DIR_SEND, wire, n, 300);
    CHECK(nresyncs == 1 && last_resync_dir == LK_DIR_SEND);
    CHECK(nrecs == 2);
    CHECK(recs[0].len == 1 && (recs[0].flags & LK_MSG_AFTER_RESYNC));
    CHECK(recs[1].len == 7 && !(recs[1].flags & LK_MSG_AFTER_RESYNC));
    CHECK(frame_clean(LK_DIR_SEND));
    return 0;
}

/* The PG ReadyForQuery pattern in a dirty MySQL stream is NOT an anchor:
 * resync_scan never matches, and the 'Z'-headed boundary fails both seq
 * checks. */
static int test_no_pg_anchor(void)
{
    __u8 wire[64];

    reset();
    cmd_phase();
    feed(LK_DIR_SEND, 100, 0, NULL, 0, 100);
    memcpy(wire, "Z\x00\x00\x00\x05I", 6);
    feed_call(LK_DIR_SEND, wire, 6, 200); /* hole flush -> dirty; no match */
    feed_call(LK_DIR_SEND, wire, 6, 300);
    CHECK(nresyncs == 0 && nrecs == 0);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    return 0;
}

/* A synthetic connection (agent attached mid-session): both directions born
 * dirty, each joins through its own call-boundary anchor; commands are typed
 * from the first resynced packet on, nothing is startup-flagged. */
static int test_synthetic_midsession(void)
{
    __u8 wire[64];
    __u32 n;

    reset();
    conn.flags |= LK_CONN_SYNTHETIC;
    conn.frame[LK_DIR_SEND].st = LK_FR_DIRTY;
    conn.frame[LK_DIR_RECV].st = LK_FR_DIRTY;

    n = mypkt(wire, 0, "\x03select now()", 13);
    feed_call(LK_DIR_RECV, wire, n, 100);
    CHECK(nresyncs == 1 && nrecs == 1);
    CHECK(recs[0].type == 0x03 && (recs[0].flags & LK_MSG_AFTER_RESYNC));
    CHECK(!(recs[0].flags & LK_MSG_STARTUP)); /* a command implies cmd phase */

    n = mypkt(wire, 1, "\x01", 1); /* its response head */
    feed_call(LK_DIR_SEND, wire, n, 200);
    CHECK(nresyncs == 2 && nrecs == 2);
    CHECK(recs[1].type == 0 && (recs[1].flags & LK_MSG_AFTER_RESYNC));
    CHECK(!(recs[1].flags & LK_MSG_STARTUP));
    CHECK(frame_clean(LK_DIR_SEND) && frame_clean(LK_DIR_RECV));
    CHECK(reasm.st.resyncs == 2);
    return 0;
}

/* off anomalies dirty the direction under my_ops exactly as under PG. */
static int test_off_anomaly(void)
{
    __u8 wire[256];

    reset();
    cmd_phase();
    myhdr(wire, 1, 195);
    memset(wire + 4, 'y', 195);
    feed(LK_DIR_SEND, 199, 0, wire, 100, 100);
    feed(LK_DIR_SEND, 199, 50, wire + 50, 10, 110); /* off went backwards */
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    CHECK(reasm.st.off_anomalies == 1 && nrecs == 0);
    return 0;
}

int main(void)
{
    if (test_connection_phase() || test_split_and_empty() || test_body_over_max() ||
        test_glue_two_fragments() || test_glue_exact_multiple() ||
        test_glue_hole_in_first_fragment() || test_glue_seq_mismatch() ||
        test_glue_hole_over_cont_header() || test_body_in_known_hole() ||
        test_chunk_gap_in_call() || test_hole_over_header() || test_ssl() ||
        test_tls_decrypted_channel() || test_compress() || test_resync_frontend() ||
        test_resync_backend() || test_no_pg_anchor() || test_synthetic_midsession() ||
        test_off_anomaly())
        return 1;
    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    lk_reasm_free(&reasm);
    printf("ok\n");
    return 0;
}
