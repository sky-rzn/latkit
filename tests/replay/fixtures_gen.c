// SPDX-License-Identifier: GPL-2.0
#include "fixtures_gen.h"

#include <stdlib.h>
#include <string.h>

#include "latkit.h"
#include "reassembly.h" /* LK_MSG_*, LK_PG_* codes */
#include "record.h"

/* --- trace builder -------------------------------------------------------- */

struct bld {
    struct fx *x;
    size_t cap;
    __u64 cookie;
    __u32 seq; /* per-conn event counter, as the kernel assigns it */
    __u64 ts;
    struct lk_tuple tuple;
    __u32 dropped;
};

static void put(struct bld *b, const void *p, size_t n)
{
    if (b->x->len + n > b->cap) {
        b->cap = (b->x->len + n) * 2 + 64;
        b->x->buf = realloc(b->x->buf, b->cap);
    }
    memcpy(b->x->buf + b->x->len, p, n);
    b->x->len += n;
}

/* One record: u32 length prefix (host order) + the record bytes (Р14). */
static void put_rec(struct bld *b, const void *rec, __u32 size)
{
    put(b, &size, sizeof(size));
    put(b, rec, size);
}

static void fill_hdr(struct bld *b, struct lk_ev_hdr *h, __u8 type, __u8 dir, __u16 flags)
{
    h->conn_id = b->cookie;
    h->ts_ns = b->ts;
    h->seq = b->seq++;
    h->type = type;
    h->dir = dir;
    h->flags = flags;
    b->ts += 10;
}

static void ev_open(struct bld *b, bool synthetic)
{
    struct lk_ev_conn c = {0};

    fill_hdr(b, &c.hdr, LK_EV_CONN_OPEN, 0, synthetic ? LK_F_SYNTHETIC : 0);
    c.tuple = b->tuple;
    c.pid = 4321;
    put_rec(b, &c, sizeof(c));
}

static void ev_close(struct bld *b)
{
    struct lk_ev_conn c = {0};

    fill_hdr(b, &c.hdr, LK_EV_CONN_CLOSE, 0, 0);
    c.tuple = b->tuple;
    c.conn_dropped = b->dropped;
    put_rec(b, &c, sizeof(c));
}

/* One data event (chunk of a send/recv call). total honest, budgets cut cap. */
static void ev_data(struct bld *b, enum lk_dir dir, __u32 total, __u32 off, const __u8 *p,
                    __u32 cap)
{
    __u8 raw[sizeof(struct lk_ev_data) + 8192];
    struct lk_ev_data *d = (void *)raw;

    memset(d, 0, sizeof(*d));
    fill_hdr(b, &d->hdr, LK_EV_DATA, dir, cap < total ? LK_F_TRUNC : 0);
    d->total_len = total;
    d->off = off;
    d->cap_len = cap;
    if (cap)
        memcpy(d->payload, p, cap);
    put_rec(b, d, sizeof(*d) + cap);
}

/* A fully captured call delivered as one chunk — the common case. */
static void call(struct bld *b, enum lk_dir dir, const __u8 *p, __u32 n)
{
    ev_data(b, dir, n, 0, p, n);
}

static void expect(struct bld *b, enum lk_dir dir, char type, __u32 len, __u16 flags)
{
    struct fx_msg *m = &b->x->msgs[b->x->nmsgs++];

    m->dir = dir;
    m->type = type;
    m->len = len;
    m->flags = flags;
}

/* --- PostgreSQL v3 wire helpers ------------------------------------------- */

static __u8 *be16(__u8 *p, __u16 v)
{
    *p++ = v >> 8;
    *p++ = v;
    return p;
}

static __u8 *be32(__u8 *p, __u32 v)
{
    *p++ = v >> 24;
    *p++ = v >> 16;
    *p++ = v >> 8;
    *p++ = v;
    return p;
}

/* type(1) + len(4) + body. Returns the total wire size. */
static __u32 pgmsg(__u8 *out, char type, const void *body, __u32 blen)
{
    out[0] = (__u8)type;
    be32(out + 1, blen + 4);
    if (blen)
        memcpy(out + 5, body, blen);
    return blen + 5;
}

/* len(4) + code(4) + body — the untyped startup framing. */
static __u32 pgstartup(__u8 *out, __u32 code, const void *body, __u32 blen)
{
    be32(out, blen + 8);
    be32(out + 4, code);
    if (blen)
        memcpy(out + 8, body, blen);
    return blen + 8;
}

/* Realistic-ish RowDescription / DataRow for a single-column int4 result, so
 * the traces resemble what a stage-3 parser will chew on. */
static __u32 row_desc(__u8 *out)
{
    __u8 body[64], *p = body;

    p = be16(p, 1);           /* field count */
    memcpy(p, "?column?", 9); /* name + NUL */
    p += 9;
    p = be32(p, 0);         /* table OID */
    p = be16(p, 0);         /* column attr */
    p = be32(p, 23);        /* type OID: int4 */
    p = be16(p, 4);         /* type len */
    p = be32(p, (__u32)-1); /* type mod */
    p = be16(p, 0);         /* format: text */
    return pgmsg(out, 'T', body, (__u32)(p - body));
}

static __u32 data_row(__u8 *out, const char *val)
{
    __u8 body[32], *p = body;
    __u32 vlen = (__u32)strlen(val);

    p = be16(p, 1); /* column count */
    p = be32(p, vlen);
    memcpy(p, val, vlen);
    p += vlen;
    return pgmsg(out, 'D', body, (__u32)(p - body));
}

/* Startup parameter list: key\0val\0...\0 — the trailing NUL of the literal is
 * the list terminator. */
static const char startup_params[] = "user\0postgres\0database\0postgres";
static const __u8 auth_ok[4] = {0}; /* AuthenticationOk: int32 0 */

/* Common prelude: OPEN + StartupMessage + AuthenticationOk + ReadyForQuery. */
static void prelude(struct bld *b)
{
    __u8 w[128];
    __u32 n;

    ev_open(b, false);
    n = pgstartup(w, LK_PG_PROTO_V3, startup_params, sizeof(startup_params));
    call(b, LK_DIR_RECV, w, n);
    expect(b, LK_DIR_RECV, 0, sizeof(startup_params) + 8, LK_MSG_STARTUP);
    n = pgmsg(w, 'R', auth_ok, sizeof(auth_ok));
    call(b, LK_DIR_SEND, w, n);
    expect(b, LK_DIR_SEND, 'R', 8, 0);
    n = pgmsg(w, 'Z', "I", 1);
    call(b, LK_DIR_SEND, w, n);
    expect(b, LK_DIR_SEND, 'Z', 5, 0);
}

static void bld_init(struct bld *b, struct fx *x)
{
    memset(b, 0, sizeof(*b));
    memset(x, 0, sizeof(*x));
    b->x = x;
    b->cookie = 0xC0FFEE01;
    b->ts = 1000;
    b->tuple.family = 2; /* AF_INET */
    b->tuple.saddr[0] = 127;
    b->tuple.saddr[3] = 1;
    b->tuple.daddr[0] = 127;
    b->tuple.daddr[3] = 1;
    b->tuple.sport = 51000;
    b->tuple.dport = 5432;
    x->clean = true;
    put(b, LK_RECORD_MAGIC, LK_RECORD_MAGIC_LEN);
}

/* --- fixtures ------------------------------------------------------------- */

/* psql simple query: startup -> auth -> Q -> T,D,C,Z -> Terminate. */
static void build_simple_query(struct fx *x)
{
    struct bld b;
    __u8 w[128];
    __u32 n;

    bld_init(&b, x);
    prelude(&b);

    n = pgmsg(w, 'Q', "select 1", 9); /* "select 1\0" */
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'Q', 13, 0);

    n = row_desc(w);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'T', n - 1, 0);
    n = data_row(w, "1");
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'D', n - 1, 0);
    n = pgmsg(w, 'C', "SELECT 1", 9);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'C', 13, 0);
    n = pgmsg(w, 'Z', "I", 1);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);

    n = pgmsg(w, 'X', NULL, 0); /* Terminate */
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);
    ev_close(&b);
}

/* pgbench-style extended protocol: a P/B/D/E/S batch in one call, the reply
 * (1,2,T,D,C,Z) in another — several messages per segment, split cleanly. */
static void build_extended(struct fx *x)
{
    struct bld b;
    __u8 w[256];
    __u32 n = 0;

    bld_init(&b, x);
    prelude(&b);

    /* Frontend: Parse, Bind, Describe(portal), Execute, Sync — one call. */
    n += pgmsg(w + n, 'P', "\0select 1\0\0\0", 12); /* name\0 query\0 nparams(2) */
    expect(&b, LK_DIR_RECV, 'P', 16, 0);
    n += pgmsg(w + n, 'B', "\0\0\0\0\0\0\0\0", 8);
    expect(&b, LK_DIR_RECV, 'B', 12, 0);
    n += pgmsg(w + n, 'D', "P\0", 2); /* describe portal, unnamed */
    expect(&b, LK_DIR_RECV, 'D', 6, 0);
    n += pgmsg(w + n, 'E', "\0\0\0\0\0", 5); /* portal\0 maxrows(4) */
    expect(&b, LK_DIR_RECV, 'E', 9, 0);
    n += pgmsg(w + n, 'S', NULL, 0); /* Sync */
    expect(&b, LK_DIR_RECV, 'S', 4, 0);
    call(&b, LK_DIR_RECV, w, n);

    /* Backend reply batch. */
    n = 0;
    n += pgmsg(w + n, '1', NULL, 0); /* ParseComplete */
    expect(&b, LK_DIR_SEND, '1', 4, 0);
    n += pgmsg(w + n, '2', NULL, 0); /* BindComplete */
    expect(&b, LK_DIR_SEND, '2', 4, 0);
    {
        __u32 t = row_desc(w + n);
        expect(&b, LK_DIR_SEND, 'T', t - 1, 0);
        n += t;
        t = data_row(w + n, "1");
        expect(&b, LK_DIR_SEND, 'D', t - 1, 0);
        n += t;
    }
    n += pgmsg(w + n, 'C', "SELECT 1", 9);
    expect(&b, LK_DIR_SEND, 'C', 13, 0);
    n += pgmsg(w + n, 'Z', "I", 1);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);
    call(&b, LK_DIR_SEND, w, n);

    n = pgmsg(w, 'X', NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);
    ev_close(&b);
}

/* Session with a break: a clean query, then a lost-event seq gap dirties both
 * directions; the backend resyncs on a ReadyForQuery anchor and the frontend
 * on its next call boundary, and framing recovers (Р10). */
static void build_session_gap(struct fx *x)
{
    struct bld b;
    __u8 w[128];
    __u32 n;

    bld_init(&b, x);
    prelude(&b);

    n = pgmsg(w, 'Q', "select 1", 9);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'Q', 13, 0);

    /* Two backend events are lost: bump seq so the next event reports a gap
     * of 2. The conn table dirties both directions before framing. */
    b.seq += 2;
    b.dropped += 2;
    /* The recovery event carries junk (tail of a lost message) then the
     * ReadyForQuery anchor; nothing after it in this chunk. */
    memset(w, 'x', 8);
    memcpy(w + 8, "Z\x00\x00\x00\x05I", 6);
    call(&b, LK_DIR_SEND, w, 14); /* backend resync, no message emitted */

    /* Frontend rejoins at a call boundary: a fresh query. */
    n = pgmsg(w, 'Q', "select 2", 9);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'Q', 13, LK_MSG_AFTER_RESYNC);

    /* Backend response; the first message carries the backend's AFTER_RESYNC. */
    n = row_desc(w);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'T', n - 1, LK_MSG_AFTER_RESYNC);
    n = data_row(w, "2");
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'D', n - 1, 0);
    n = pgmsg(w, 'C', "SELECT 1", 9);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'C', 13, 0);
    n = pgmsg(w, 'Z', "I", 1);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);

    n = pgmsg(w, 'X', NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);
    ev_close(&b);

    b.x->resyncs = 2;
}

/* SSL negotiation declined: SSLRequest -> 'N' -> plaintext startup + query. */
static void build_ssl_plain(struct fx *x)
{
    struct bld b;
    __u8 w[128];
    __u32 n;

    bld_init(&b, x);
    ev_open(&b, false);

    n = pgstartup(w, LK_PG_SSL_REQUEST, NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0, 8, LK_MSG_STARTUP);

    w[0] = 'N'; /* one-byte reply: continue in plaintext */
    call(&b, LK_DIR_SEND, w, 1);
    expect(&b, LK_DIR_SEND, 'N', 0, 0);

    n = pgstartup(w, LK_PG_PROTO_V3, startup_params, sizeof(startup_params));
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0, sizeof(startup_params) + 8, LK_MSG_STARTUP);
    n = pgmsg(w, 'R', auth_ok, sizeof(auth_ok));
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'R', 8, 0);
    n = pgmsg(w, 'Z', "I", 1);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);

    n = pgmsg(w, 'Q', "select 1", 9);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'Q', 13, 0);
    n = pgmsg(w, 'C', "SELECT 1", 9);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'C', 13, 0);
    n = pgmsg(w, 'Z', "I", 1);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);

    n = pgmsg(w, 'X', NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);
    ev_close(&b);
}

/* SSL accepted: SSLRequest -> 'S' -> the connection goes TLS, and every later
 * event (the ciphertext handshake and beyond) is silently discarded. */
static void build_ssl_tls(struct fx *x)
{
    struct bld b;
    __u8 w[128];
    __u32 n;

    bld_init(&b, x);
    ev_open(&b, false);

    n = pgstartup(w, LK_PG_SSL_REQUEST, NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0, 8, LK_MSG_STARTUP);

    /* 'S' plus the first ciphertext bytes in the same segment. */
    memcpy(w, "S\x16\x03\x01\x02\x00", 6);
    call(&b, LK_DIR_SEND, w, 6);
    expect(&b, LK_DIR_SEND, 'S', 0, 0);

    /* TLS ClientHello and application data — all discarded, no messages. */
    memset(w, 0xa5, 64);
    call(&b, LK_DIR_RECV, w, 64);
    call(&b, LK_DIR_SEND, w, 64);
    ev_close(&b);

    b.x->tls_conns = 1;
}

/* Agent attached mid-session (synthetic OPEN, startup never seen): both
 * directions start dirty and join through the same resync as a loss (Р10) —
 * backend on a ReadyForQuery anchor, frontend on its next call boundary. */
static void build_synthetic_midsession(struct fx *x)
{
    struct bld b;
    __u8 w[128];
    __u32 n;

    bld_init(&b, x);
    ev_open(&b, true); /* synthetic: conn table marks both directions dirty */

    /* Mid-stream backend bytes: tail of some lost message, then the anchor. */
    memset(w, 'x', 6);
    memcpy(w + 6, "Z\x00\x00\x00\x05I", 6);
    call(&b, LK_DIR_SEND, w, 12); /* backend resync, no message emitted */

    /* Frontend rejoins at a call boundary — straight into normal framing, no
     * startup (a resync means startup is long past). */
    n = pgmsg(w, 'Q', "select 1", 9);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'Q', 13, LK_MSG_AFTER_RESYNC);

    n = row_desc(w);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'T', n - 1, LK_MSG_AFTER_RESYNC);
    n = data_row(w, "1");
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'D', n - 1, 0);
    n = pgmsg(w, 'C', "SELECT 1", 9);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'C', 13, 0);
    n = pgmsg(w, 'Z', "I", 1);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);

    n = pgmsg(w, 'X', NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);
    ev_close(&b);

    b.x->resyncs = 2;
}

const struct fixture lk_fixtures[] = {
    {"simple_query", build_simple_query}, {"extended", build_extended},
    {"session_gap", build_session_gap},   {"ssl_plain", build_ssl_plain},
    {"ssl_tls", build_ssl_tls},           {"synthetic_midsession", build_synthetic_midsession},
};
const size_t lk_nfixtures = sizeof(lk_fixtures) / sizeof(lk_fixtures[0]);
