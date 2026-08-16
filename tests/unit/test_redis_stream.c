// SPDX-License-Identifier: GPL-2.0
/* The invariant МR1 is accepted on (PLAN-REDIS.md): **the framer's output does
 * not depend on where the stream was cut**. The same bytes fed as one syscall,
 * as one syscall per byte, and at pseudo-random boundaries must produce exactly
 * the same messages — same directions, same type bytes, same wire lengths, same
 * flags, same published bodies.
 *
 * It is the twin of test_http_stream.c's role for the HTTP track and it earns
 * its place for a reason particular to RESP: this framer has two body paths.
 * A value contained in one capture event is published straight out of the
 * capture buffer with no copy at all; a value that spans events is copied into a
 * borrowed slab, piece by piece, and published from there. Two paths that must
 * agree byte for byte is exactly the shape of bug that hides until production,
 * and the only honest way to state "they agree" is to run every cut.
 *
 * The stream deliberately contains one of everything the machine can be in the
 * middle of when a cut lands: a length line, a bulk payload, the CRLF after a
 * payload, an aggregate between elements, a nested aggregate, an inline line,
 * an attribute prefix, a push, and a value longer than the prefix ceiling.
 *
 * Clean input only, and that is not a hedge but the statement of the property:
 * a *hole* is not a chunk boundary — it is bytes that were never seen — and
 * where a hole lands genuinely changes what can be framed after it. Holes are
 * test_redis_frame.c's. */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reassembly.h"
#include "redis.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* --- captured sink output ------------------------------------------------- */

#define MAXREC   64
#define BODYKEEP 64

struct rec {
    __u8 dir;
    char type;
    __u16 flags;
    __u32 len, cap;
    __u8 body[BODYKEEP];
    __u32 nbody;
};

static struct rec recs[MAXREC];
static int nrecs, nresyncs;

static void on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct rec *r = &recs[nrecs % MAXREC];

    (void)ctx;
    (void)c;
    nrecs++;
    memset(r, 0, sizeof(*r));
    r->dir = dir;
    r->type = m->type;
    r->flags = m->flags;
    r->len = m->len;
    r->cap = m->body_cap;
    r->nbody = m->body_cap < BODYKEEP ? m->body_cap : BODYKEEP;
    if (r->nbody)
        memcpy(r->body, m->body, r->nbody);
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
    free(conn.frame_state);
    lk_reasm_free(&reasm);
    memset(&conn, 0, sizeof(conn));
    conn.ops = &lk_proto_redis_ops;
    lk_reasm_init(&reasm, &sink);
    nrecs = 0;
    nresyncs = 0;
}

/* One fully captured syscall. Every cut in this file is a *call* boundary, the
 * hardest case for the framer to be indifferent to: it is the one boundary the
 * resync anchors care about, so if anything ever came to depend on it outside a
 * dirty direction, this is where it would show. */
static void feed(enum lk_dir dir, const __u8 *p, __u32 n, __u64 ts)
{
    static union {
        struct lk_ev_data d;
        __u8 raw[sizeof(struct lk_ev_data) + 65536];
    } u;

    memset(&u.d, 0, sizeof(u.d));
    u.d.hdr.ts_ns = ts;
    u.d.hdr.dir = dir;
    u.d.total_len = n;
    u.d.off = 0;
    u.d.cap_len = n;
    if (n)
        memcpy(u.d.payload, p, n);
    lk_reasm_data(&reasm, &conn, dir, &u.d, n);
}

/* --- the stream ----------------------------------------------------------- */

/* A direction's worth of bytes and how they are meant to be read. */
struct stream {
    enum lk_dir dir;
    __u8 *p;
    __u32 n;
};

static __u8 fe_buf[70000], be_buf[70000];
static struct stream fe = {LK_DIR_RECV, fe_buf, 0};
static struct stream be = {LK_DIR_SEND, be_buf, 0};

static void add(struct stream *s, const char *lit)
{
    __u32 n = (__u32)strlen(lit);

    memcpy(s->p + s->n, lit, n);
    s->n += n;
}

static void add_bulk(struct stream *s, __u32 payload, char fill)
{
    s->n += (__u32)sprintf((char *)s->p + s->n, "$%u\r\n", payload);
    memset(s->p + s->n, fill, payload);
    s->n += payload;
    add(s, "\r\n");
}

static void build_streams(void)
{
    fe.n = be.n = 0;

    /* A pipeline of three, an inline command, blank lines that are not
     * commands, and a value bigger than the prefix ceiling. */
    add(&fe, "*3\r\n$3\r\nSET\r\n$4\r\nlk:k\r\n$5\r\nhello\r\n");
    add(&fe, "*2\r\n$3\r\nGET\r\n$4\r\nlk:k\r\n");
    add(&fe, "*1\r\n$4\r\nPING\r\n");
    add(&fe, "PING\r\n");
    add(&fe, "\r\n\n");
    add(&fe, "ECHO hi\n");
    add(&fe, "*3\r\n$3\r\nSET\r\n$4\r\nbig1\r\n");
    add_bulk(&fe, 40000, 'y'); /* past LK_MSG_BODY_MAX: published truncated */
    add(&fe, "*1\r\n$4\r\nQUIT\r\n");

    /* Scalars of both versions, an empty and a null bulk, nesting, a map whose
     * count is pairs, an attribute prefix and the value it prefixes, a push. */
    add(&be, "+OK\r\n");
    add(&be, "$5\r\nhello\r\n");
    add(&be, "$-1\r\n*-1\r\n*0\r\n$0\r\n\r\n_\r\n#t\r\n,3.141\r\n(123456789012345678\r\n");
    add(&be, "=9\r\ntxt:hello\r\n!5\r\nOOPS!\r\n~2\r\n:1\r\n:2\r\n");
    add(&be, "*3\r\n*2\r\n$1\r\na\r\n$1\r\nb\r\n:7\r\n%1\r\n$1\r\nk\r\n$1\r\nv\r\n");
    add(&be, "|1\r\n$3\r\nttl\r\n:90\r\n$2\r\nhi\r\n");
    add(&be, ">3\r\n$7\r\nmessage\r\n$2\r\nch\r\n$2\r\nhi\r\n");
    add_bulk(&be, 40000, 'z');
    add(&be, "+PONG\r\n");
}

/* --- the runs ------------------------------------------------------------- */

/* One run over both directions with a given cutter: `next(remaining, seed)`
 * returns how many bytes the next syscall carries. Both directions are fed
 * alternately so that the two machines interleave the way they do on a socket. */
typedef __u32 (*cutter)(__u32 left, unsigned *state);

static void run(cutter cut, unsigned seed)
{
    __u32 fo = 0, bo = 0;
    unsigned st = seed;
    __u64 ts = 1000;

    reset();
    while (fo < fe.n || bo < be.n) {
        if (fo < fe.n) {
            __u32 k = cut(fe.n - fo, &st);

            feed(LK_DIR_RECV, fe.p + fo, k, ts++);
            fo += k;
        }
        if (bo < be.n) {
            __u32 k = cut(be.n - bo, &st);

            feed(LK_DIR_SEND, be.p + bo, k, ts++);
            bo += k;
        }
    }
}

static __u32 cut_whole(__u32 left, unsigned *st)
{
    (void)st;
    return left > 60000 ? 60000 : left;
}

static __u32 cut_byte(__u32 left, unsigned *st)
{
    (void)left;
    (void)st;
    return 1;
}

/* xorshift rather than rand(): the cut sequence has to be the same on every
 * platform and every libc, or a failure here is not reproducible. */
static __u32 cut_random(__u32 left, unsigned *st)
{
    unsigned x = *st;
    __u32 k;

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *st = x;
    k = 1 + x % 700; /* straddles both the 512-byte budget and the small values */
    return k < left ? k : left;
}

/* --- comparison ----------------------------------------------------------- */

static struct rec ref[MAXREC];
static int nref;

/* Compared **per direction**, and only per direction. How the two directions
 * interleave with each other really does depend on the cutting — that is the
 * socket's doing and the reason the two machines are independent — but the
 * sequence of values within one direction is the protocol, and it may not move
 * one message. */
static int same_dir(const char *what, enum lk_dir dir)
{
    int ia = 0, ib = 0, k = 0;

    for (;;) {
        while (ia < nref && ref[ia].dir != dir)
            ia++;
        while (ib < nrecs && recs[ib].dir != dir)
            ib++;
        if (ia >= nref || ib >= nrecs)
            break;

        struct rec *a = &ref[ia], *b = &recs[ib];

        if (a->type != b->type || a->len != b->len || a->cap != b->cap || a->flags != b->flags ||
            a->nbody != b->nbody || memcmp(a->body, b->body, a->nbody)) {
            fprintf(stderr,
                    "FAIL %s: %s message %d differs: got '%c' len=%u cap=%u fl=%x,"
                    " reference '%c' len=%u cap=%u fl=%x\n",
                    what, dir == LK_DIR_RECV ? "fe>" : "<be", k, b->type, b->len, b->cap, b->flags,
                    a->type, a->len, a->cap, a->flags);
            return 1;
        }
        ia++;
        ib++;
        k++;
    }
    while (ia < nref && ref[ia].dir != dir)
        ia++;
    while (ib < nrecs && recs[ib].dir != dir)
        ib++;
    if (ia != nref || ib != nrecs) {
        fprintf(stderr, "FAIL %s: %s ran out after %d messages (reference %s)\n", what,
                dir == LK_DIR_RECV ? "fe>" : "<be", k, ia == nref ? "shorter" : "longer");
        return 1;
    }
    return 0;
}

static int same_as_ref(const char *what)
{
    if (nrecs != nref) {
        fprintf(stderr, "FAIL %s: %d messages, reference has %d\n", what, nrecs, nref);
        return 1;
    }
    return same_dir(what, LK_DIR_RECV) || same_dir(what, LK_DIR_SEND);
}

int main(void)
{
    char name[32];

    build_streams();

    /* The reference: everything in as few syscalls as the harness allows, so
     * every value that can be contiguous is, and the no-copy path is the one
     * that produced it. */
    run(cut_whole, 0);
    if (nrecs <= 0 || nrecs > MAXREC) {
        fprintf(stderr, "FAIL: reference run produced %d messages\n", nrecs);
        return 1;
    }
    if (nresyncs) {
        fprintf(stderr, "FAIL: clean input resynchronised %d times\n", nresyncs);
        return 1;
    }
    nref = nrecs;
    memcpy(ref, recs, sizeof(ref));

    /* One syscall per byte: every value now takes the slab path, and every
     * possible boundary is exercised at once. */
    run(cut_byte, 0);
    if (same_as_ref("byte-at-a-time") || nresyncs)
        return 1;

    /* And a hundred pseudo-random cuttings, which is where a boundary lands in
     * the middle of a length line, of a payload, of the CRLF after one, and
     * between the elements of an aggregate. */
    for (unsigned seed = 1; seed <= 100; seed++) {
        run(cut_random, seed);
        snprintf(name, sizeof(name), "random seed %u", seed);
        if (same_as_ref(name) || nresyncs)
            return 1;
    }

    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    free(conn.frame_state);
    lk_reasm_free(&reasm);
    printf("ok\n");
    return 0;
}
