// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the TLS decrypted-channel routing (task 6.4, Р38/Р36). These
 * drive the shared pipeline (lk_pipeline_feed) over synthetic ringbuf records —
 * no BPF, no libssl — asserting the three routing invariants:
 *
 *   (a) once a connection goes TLS, ciphertext socket events are dropped before
 *       the seq detector and never reach the framer, while decrypted events
 *       (LK_F_DECRYPTED) are framed;
 *   (b) the framer is reset to startup on the TLS transition, so the first
 *       decrypted frontend event parses as the real StartupMessage (Р36);
 *   (c) the decrypted channel has its own seq space — a decrypted gap dirties
 *       the (plaintext) framer, a dropped-ciphertext "gap" does not, and the
 *       two seq spaces never interfere.
 */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conn_table.h"
#include "latkit.h"
#include "pipeline.h"
#include "reassembly.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* --- message-collecting framer sink --------------------------------------- */

struct rec {
    __u8 dir;
    char type;
    __u16 flags;
    __u32 len;
};

static struct rec recs[32];
static int nrecs;

static void on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    (void)ctx;
    (void)c;
    if (nrecs >= (int)(sizeof(recs) / sizeof(recs[0])))
        return;
    recs[nrecs++] = (struct rec){.dir = dir, .type = m->type, .flags = m->flags, .len = m->len};
}

/* --- synthetic-record builder --------------------------------------------- */

#define COOKIE 0xABCDEF01ULL

static struct lk_pipeline pipe;
static __u32 raw_seq;    /* socket seq space */
static __u32 tls_seq;    /* decrypted seq space */
static __u64 ts = 1000;

static void reset_pipe(void)
{
    static const struct lk_msg_sink sink = {.on_msg = on_msg};

    lk_pipeline_fini(&pipe);
    lk_pipeline_init(&pipe, LK_MAX_CONNS_DEFAULT, 600ULL * 1000000000ULL, &sink);
    nrecs = 0;
    raw_seq = 0;
    tls_seq = 0;
    ts = 1000;
}

static void wr32(__u8 *p, __u32 v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

static __u32 pgmsg(__u8 *out, char type, const void *body, __u32 blen)
{
    out[0] = (__u8)type;
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

static void feed_open(struct lk_pipeline_ev *ev)
{
    struct lk_ev_conn c = {0};

    c.hdr.conn_id = COOKIE;
    c.hdr.ts_ns = ts;
    c.hdr.seq = raw_seq++;
    c.hdr.type = LK_EV_CONN_OPEN;
    c.tuple.family = 2;
    c.tuple.sport = 51000;
    c.tuple.dport = 5432;
    ts += 10;
    lk_pipeline_feed(&pipe, &c, sizeof(c), ev);
}

/* One data event with an explicit seq (so tests can inject gaps). `decrypted`
 * picks the seq space + the LK_F_DECRYPTED flag; the caller advances the right
 * counter itself when it wants a hole. */
static void feed_data(enum lk_dir dir, __u32 seq, const __u8 *p, __u32 n, bool decrypted,
                      struct lk_pipeline_ev *ev)
{
    __u8 raw[sizeof(struct lk_ev_data) + 512];
    struct lk_ev_data *d = (void *)raw;

    memset(d, 0, sizeof(*d));
    d->hdr.conn_id = COOKIE;
    d->hdr.ts_ns = ts;
    d->hdr.seq = seq;
    d->hdr.type = LK_EV_DATA;
    d->hdr.dir = dir;
    d->hdr.flags = decrypted ? LK_F_DECRYPTED : 0;
    ts += 10;
    d->total_len = n;
    d->off = 0;
    d->cap_len = n;
    if (n)
        memcpy(d->payload, p, n);
    lk_pipeline_feed(&pipe, d, sizeof(*d) + n, ev);
}

static void feed_raw(enum lk_dir dir, const __u8 *p, __u32 n, struct lk_pipeline_ev *ev)
{
    feed_data(dir, raw_seq++, p, n, false, ev);
}

static void feed_dec(enum lk_dir dir, const __u8 *p, __u32 n, struct lk_pipeline_ev *ev)
{
    feed_data(dir, tls_seq++, p, n, true, ev);
}

/* Negotiate TLS on the socket: OPEN, SSLRequest (RECV), 'S' reply (SEND). After
 * this the connection carries LK_CONN_TLS and the framer has been reset. */
static int negotiate_tls(void)
{
    struct lk_pipeline_ev ev;
    __u8 w[64];
    __u32 n;

    feed_open(&ev);
    n = pgstartup(w, LK_PG_SSL_REQUEST, NULL, 0);
    feed_raw(LK_DIR_RECV, w, n, &ev);
    CHECK(ev.conn && (ev.conn->flags & LK_CONN_SSL_REPLY));

    memcpy(w, "S\x16\x03\x01\x02\x00", 6); /* 'S' + first ciphertext bytes */
    feed_raw(LK_DIR_SEND, w, 6, &ev);
    CHECK(ev.conn && (ev.conn->flags & LK_CONN_TLS));
    CHECK(ev.tls_now);
    return 0;
}

/* (a) Ciphertext socket events on a TLS connection are dropped before the seq
 * detector and never framed; decrypted events are framed. */
static int test_route_drop_and_frame(void)
{
    struct lk_pipeline_ev ev;
    const struct lk_conn_table_stats *cs;
    __u8 w[128];
    __u32 n;

    reset_pipe();
    if (negotiate_tls())
        return 1;

    /* Two framer messages so far: the SSLRequest (startup) and the 'S' reply. */
    CHECK(nrecs == 2);
    CHECK(recs[0].dir == LK_DIR_RECV && (recs[0].flags & LK_MSG_STARTUP));
    CHECK(recs[1].dir == LK_DIR_SEND && recs[1].type == 'S' && recs[1].len == 0);

    cs = lk_conn_table_stats(pipe.conns);
    CHECK(cs->tls_socket_dropped == 0);

    /* Ciphertext handshake bytes on both directions — every one dropped. */
    memset(w, 0xa5, 48);
    feed_raw(LK_DIR_RECV, w, 48, &ev);
    CHECK(ev.tls_socket_dropped && !ev.lost);
    feed_raw(LK_DIR_SEND, w, 48, &ev);
    CHECK(ev.tls_socket_dropped);
    CHECK(nrecs == 2); /* nothing framed */
    cs = lk_conn_table_stats(pipe.conns);
    CHECK(cs->tls_socket_dropped == 2);

    /* Decrypted StartupMessage (frontend) — framed as a startup message. */
    n = pgstartup(w, LK_PG_PROTO_V3, "user\0postgres\0database\0postgres", 32);
    feed_dec(LK_DIR_RECV, w, n, &ev);
    CHECK(!ev.tls_socket_dropped && !ev.decrypted_early);
    CHECK(nrecs == 3);
    CHECK(recs[2].dir == LK_DIR_RECV && recs[2].type == 0 && (recs[2].flags & LK_MSG_STARTUP));
    return 0;
}

/* (b) The framer reset on the TLS transition lets the decrypted stream parse
 * from a StartupMessage into normal framing; also a direct check of
 * lk_conn_tls_reset_framing clearing a dirtied/mid-message frame. */
static int test_frame_reset_startup(void)
{
    struct lk_pipeline_ev ev;
    struct lk_conn *c;
    __u8 w[128];
    __u32 n;

    reset_pipe();
    if (negotiate_tls())
        return 1;
    c = lk_conn_table_peek(pipe.conns, COOKIE);
    CHECK(c);
    /* Reset left both directions in startup/header state (Р36). */
    CHECK(c->frame[LK_DIR_RECV].st == LK_FR_HEADER && !c->frame[LK_DIR_RECV].startup_done);
    CHECK(c->frame[LK_DIR_SEND].st == LK_FR_HEADER);

    /* Decrypted StartupMessage flips the frontend into normal framing... */
    n = pgstartup(w, LK_PG_PROTO_V3, "user\0postgres\0database\0postgres", 32);
    feed_dec(LK_DIR_RECV, w, n, &ev);
    CHECK(c->frame[LK_DIR_RECV].startup_done);
    /* ...so a following decrypted 'Q' parses as a normal typed message. */
    n = pgmsg(w, 'Q', "select 1", 9);
    feed_dec(LK_DIR_RECV, w, n, &ev);
    CHECK(nrecs == 4);
    CHECK(recs[3].type == 'Q' && recs[3].len == 13 && !(recs[3].flags & LK_MSG_STARTUP));

    /* Direct: reset clears a dirtied, mid-message frame with a live buffer. */
    c->frame[LK_DIR_RECV].st = LK_FR_DIRTY;
    c->frame[LK_DIR_RECV].startup_done = 1;
    c->frame[LK_DIR_RECV].buf = malloc(16);
    c->frame[LK_DIR_RECV].buf_len = 8;
    c->frame[LK_DIR_SEND].st = LK_FR_BODY;
    lk_conn_tls_reset_framing(c);
    CHECK(c->frame[LK_DIR_RECV].st == LK_FR_HEADER && !c->frame[LK_DIR_RECV].startup_done);
    CHECK(c->frame[LK_DIR_RECV].buf == NULL && c->frame[LK_DIR_RECV].buf_len == 0);
    CHECK(c->frame[LK_DIR_SEND].st == LK_FR_HEADER);
    return 0;
}

/* (c) The decrypted seq space is independent: a decrypted gap dirties the
 * plaintext framer and reports loss; a dropped-ciphertext seq jump does not
 * touch the decrypted space or the framer. */
static int test_decrypted_seq_hole(void)
{
    struct lk_pipeline_ev ev;
    struct lk_conn *c;
    __u8 w[128];
    __u32 n;

    reset_pipe();
    if (negotiate_tls())
        return 1;
    c = lk_conn_table_peek(pipe.conns, COOKIE);
    CHECK(c);

    /* First decrypted event seeds the decrypted seq baseline (no loss). */
    n = pgstartup(w, LK_PG_PROTO_V3, "user\0postgres\0database\0postgres", 32);
    feed_dec(LK_DIR_RECV, w, n, &ev); /* tls_seq 0 */
    CHECK(!ev.lost && c->frame[LK_DIR_RECV].startup_done);

    /* Ciphertext socket events with a big raw-seq jump are dropped — no loss
     * reported, framer untouched (still clean, startup_done kept). */
    raw_seq += 5; /* pretend 5 ciphertext events were lost */
    memset(w, 0xa5, 32);
    feed_raw(LK_DIR_SEND, w, 32, &ev);
    CHECK(ev.tls_socket_dropped && !ev.lost);
    CHECK(c->frame[LK_DIR_RECV].st != LK_FR_DIRTY && c->frame[LK_DIR_SEND].st != LK_FR_DIRTY);

    /* Now punch a hole in the decrypted seq space: skip tls_seq 1 and 2. */
    tls_seq += 2; /* next decrypted event is tls_seq 3, 2 lost */
    n = pgmsg(w, 'Q', "select 1", 9);
    feed_dec(LK_DIR_RECV, w, n, &ev);
    /* The gap is detected in the decrypted seq space only: loss reported, the
     * decrypted counter accrues it, the raw counter stays clean (Р38). */
    CHECK(ev.lost == 2);
    CHECK(c->tls_dropped == 2 && c->dropped == 0);
    /* The gap dirtied the (plaintext) framer both directions (Р9). This 'Q' is
     * a frontend call boundary, so RECV immediately resyncs on it and emits the
     * message with LK_MSG_AFTER_RESYNC; SEND has no such anchor and stays dirty. */
    CHECK(c->frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    CHECK(nrecs >= 1 && recs[nrecs - 1].type == 'Q' &&
          (recs[nrecs - 1].flags & LK_MSG_AFTER_RESYNC));
    return 0;
}

/* Defensive: a decrypted event on a connection that never went TLS is flagged
 * (Р38 order says it cannot happen) but still framed best-effort. */
static int test_decrypted_early(void)
{
    struct lk_pipeline_ev ev;
    __u8 w[128];
    __u32 n;

    reset_pipe();
    feed_open(&ev);
    n = pgstartup(w, LK_PG_PROTO_V3, "user\0postgres\0database\0postgres", 32);
    feed_dec(LK_DIR_RECV, w, n, &ev);
    CHECK(ev.decrypted_early);
    CHECK(ev.conn && !(ev.conn->flags & LK_CONN_TLS));
    CHECK(nrecs == 1 && (recs[0].flags & LK_MSG_STARTUP));
    return 0;
}

int main(void)
{
    if (test_route_drop_and_frame())
        return 1;
    printf("ok tls-route drop+frame\n");
    if (test_frame_reset_startup())
        return 1;
    printf("ok tls-route frame-reset\n");
    if (test_decrypted_seq_hole())
        return 1;
    printf("ok tls-route decrypted-seq-hole\n");
    if (test_decrypted_early())
        return 1;
    printf("ok tls-route decrypted-early\n");
    lk_pipeline_fini(&pipe);
    printf("ok\n");
    return 0;
}
