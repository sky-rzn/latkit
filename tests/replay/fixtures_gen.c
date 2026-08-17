// SPDX-License-Identifier: GPL-2.0
#include "fixtures_gen.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "latkit.h"
#include "proto.h"      /* LK_Q_* kinds, LK_QO_* flags */
#include "reassembly.h" /* LK_MSG_*, LK_PG_* codes */
#include "record.h"

/* --- trace builder -------------------------------------------------------- */

struct bld {
    struct fx *x;
    size_t cap;
    __u64 cookie;
    __u32 seq;     /* per-conn socket event counter, as the kernel assigns it */
    __u32 tls_seq; /* decrypted-channel counter (Р38): its own kernel seq space */
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

/* One decrypted data event (stage 6.4): an SSL_* uprobe chunk. It carries
 * LK_F_DECRYPTED and draws its seq from the connection's own decrypted space
 * (tls_seq), not the socket counter — exactly as the kernel emits it (Р35/Р38).
 * SSL_read = frontend = RECV, SSL_write = backend = SEND. */
static void ev_data_dec(struct bld *b, enum lk_dir dir, __u32 total, __u32 off, const __u8 *p,
                        __u32 cap)
{
    __u8 raw[sizeof(struct lk_ev_data) + 8192];
    struct lk_ev_data *d = (void *)raw;

    memset(d, 0, sizeof(*d));
    d->hdr.conn_id = b->cookie;
    d->hdr.ts_ns = b->ts;
    d->hdr.seq = b->tls_seq++;
    d->hdr.type = LK_EV_DATA;
    d->hdr.dir = dir;
    d->hdr.flags = LK_F_DECRYPTED | (cap < total ? LK_F_TRUNC : 0);
    b->ts += 10;
    d->total_len = total;
    d->off = off;
    d->cap_len = cap;
    if (cap)
        memcpy(d->payload, p, cap);
    put_rec(b, d, sizeof(*d) + cap);
}

/* A fully captured decrypted call in one chunk. */
static void call_dec(struct bld *b, enum lk_dir dir, const __u8 *p, __u32 n)
{
    ev_data_dec(b, dir, n, 0, p, n);
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

    /* AuthenticationOk emits one session; startup_params carries these labels. */
    b->x->sessions = 1;
    b->x->sess_user = "postgres";
    b->x->sess_db = "postgres";
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

    /* Q .. Z closes one SIMPLE unit: text "select 1", one row from "SELECT 1". */
    b.x->queries = 1;
    b.x->obs_kind = LK_Q_SIMPLE;
    b.x->obs_rows = 1;
    b.x->obs_flags = 0;
    b.x->obs_text = "select 1";
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

    /* Parse caches the unnamed statement "select 1"; Bind opens one EXTENDED
     * unit that resolves its text from the cache and closes on CommandComplete. */
    b.x->queries = 1;
    b.x->obs_kind = LK_Q_EXTENDED;
    b.x->obs_rows = 1;
    b.x->obs_flags = 0;
    b.x->obs_text = "select 1";
}

/* pgbench -M prepared: a named statement is Parsed once, then reused by two
 * Bind/Execute/Sync round-trips — both observations carry the cached text, no
 * NO_TEXT (the checklist's "prepared without NO_TEXT"). */
static void build_prepared(struct fx *x)
{
    struct bld b;
    __u8 w[256];
    __u32 n;

    bld_init(&b, x);
    prelude(&b);

    /* Parse a named statement "s1" -> "select 2". */
    n = pgmsg(w, 'P', "s1\0select 2\0\0\0", 14); /* name\0 query\0 nparams(2) */
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'P', 18, 0);
    n = pgmsg(w, '1', NULL, 0); /* ParseComplete */
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, '1', 4, 0);

    /* Two executions of s1, each Bind/Execute/Sync -> BindComplete, DataRow,
     * CommandComplete, ReadyForQuery. */
    for (int i = 0; i < 2; i++) {
        n = pgmsg(w, 'B', "\0s1\0\0\0\0\0", 8); /* portal\0 stmt "s1"\0 formats/values */
        call(&b, LK_DIR_RECV, w, n);
        expect(&b, LK_DIR_RECV, 'B', 12, 0);
        n = pgmsg(w, 'E', "\0\0\0\0\0", 5); /* portal\0 maxrows(4) */
        call(&b, LK_DIR_RECV, w, n);
        expect(&b, LK_DIR_RECV, 'E', 9, 0);
        n = pgmsg(w, 'S', NULL, 0); /* Sync */
        call(&b, LK_DIR_RECV, w, n);
        expect(&b, LK_DIR_RECV, 'S', 4, 0);

        n = pgmsg(w, '2', NULL, 0); /* BindComplete */
        call(&b, LK_DIR_SEND, w, n);
        expect(&b, LK_DIR_SEND, '2', 4, 0);
        n = data_row(w, "2");
        call(&b, LK_DIR_SEND, w, n);
        expect(&b, LK_DIR_SEND, 'D', n - 1, 0);
        n = pgmsg(w, 'C', "SELECT 1", 9);
        call(&b, LK_DIR_SEND, w, n);
        expect(&b, LK_DIR_SEND, 'C', 13, 0);
        n = pgmsg(w, 'Z', "I", 1);
        call(&b, LK_DIR_SEND, w, n);
        expect(&b, LK_DIR_SEND, 'Z', 5, 0);
    }

    n = pgmsg(w, 'X', NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);
    ev_close(&b);

    /* Two EXTENDED observations, both with the cached text and one row. */
    b.x->queries = 2;
    b.x->obs_kind = LK_Q_EXTENDED;
    b.x->obs_rows = 1;
    b.x->obs_flags = 0;
    b.x->obs_text = "select 2";
}

/* Pipelined batch with an error in the middle: three unnamed-statement units
 * Bound before any reply (each Parse overwrites the unnamed slot, exercising the
 * eviction-rescue of live references, Р17). The backend completes unit 1, errors
 * on unit 2, and skips to Sync — unit 3 is ABORTED. Exactly one ERROR + a tail
 * of ABORTED, all flagged PIPELINED. */
static void build_pipeline_error(struct fx *x)
{
    struct bld b;
    __u8 w[512];
    __u32 n = 0;
    const char *texts[3] = {"select 1", "select 2", "select 3"};

    bld_init(&b, x);
    prelude(&b);

    /* Frontend: P1 B1 E1  P2 B2 E2  P3 B3 E3  Sync — one call. */
    for (int i = 0; i < 3; i++) {
        __u8 parse[32];
        __u32 pn = 0;

        parse[pn++] = '\0';              /* unnamed statement */
        memcpy(parse + pn, texts[i], 9); /* "select N\0" */
        pn += 9;
        parse[pn++] = '\0';
        parse[pn++] = '\0'; /* nparams = 0 */
        n += pgmsg(w + n, 'P', parse, pn);
        expect(&b, LK_DIR_RECV, 'P', pn + 4, 0);
        n += pgmsg(w + n, 'B', "\0\0\0\0\0\0\0\0", 8); /* bind unnamed portal+stmt */
        expect(&b, LK_DIR_RECV, 'B', 12, 0);
        n += pgmsg(w + n, 'E', "\0\0\0\0\0", 5);
        expect(&b, LK_DIR_RECV, 'E', 9, 0);
    }
    n += pgmsg(w + n, 'S', NULL, 0);
    expect(&b, LK_DIR_RECV, 'S', 4, 0);
    call(&b, LK_DIR_RECV, w, n);

    /* Backend: unit 1 completes, unit 2 errors, then skip to the Sync's Z. */
    n = 0;
    n += pgmsg(w + n, '1', NULL, 0); /* ParseComplete (P1) */
    expect(&b, LK_DIR_SEND, '1', 4, 0);
    n += pgmsg(w + n, '2', NULL, 0); /* BindComplete (B1) */
    expect(&b, LK_DIR_SEND, '2', 4, 0);
    n += pgmsg(w + n, 'C', "SELECT 1", 9);
    expect(&b, LK_DIR_SEND, 'C', 13, 0);
    n += pgmsg(w + n, '1', NULL, 0); /* ParseComplete (P2) */
    expect(&b, LK_DIR_SEND, '1', 4, 0);
    {
        /* ErrorResponse for unit 2: S(everity)\0 C(ode) 42P01\0 end. */
        __u8 err[32];
        __u32 en = 0;

        err[en++] = 'S';
        memcpy(err + en, "ERROR", 6);
        en += 6;
        err[en++] = 'C';
        memcpy(err + en, "42P01", 6);
        en += 6;
        err[en++] = 0;
        n += pgmsg(w + n, 'E', err, en);
        expect(&b, LK_DIR_SEND, 'E', en + 4, 0);
    }
    n += pgmsg(w + n, 'Z', "I", 1);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);
    call(&b, LK_DIR_SEND, w, n);

    n = pgmsg(w, 'X', NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);
    ev_close(&b);

    /* Three observations: unit 1 EXTENDED (rows 1), unit 2 ERROR, unit 3
     * ABORTED. The last emitted is unit 3 — ABORTED | PIPELINED, its text still
     * "select 3" (rescued when P3 overwrote the unnamed slot). */
    b.x->queries = 3;
    b.x->errors_sql = 1;
    b.x->obs_kind = LK_Q_EXTENDED;
    b.x->obs_rows = 0;
    b.x->obs_flags = LK_QO_ABORTED | LK_QO_PIPELINED;
    b.x->obs_text = "select 3";
}

/* Bind on a statement name never Parsed (agent started late, eviction): the unit
 * is EXTENDED with LK_QO_NO_TEXT — honest latency, unknown text. */
static void build_bind_unknown(struct fx *x)
{
    struct bld b;
    __u8 w[128];
    __u32 n;

    bld_init(&b, x);
    prelude(&b);

    n = pgmsg(w, 'B', "\0nope\0\0\0\0\0", 10); /* portal\0 stmt "nope"\0 formats/values */
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'B', 14, 0);
    n = pgmsg(w, 'E', "\0\0\0\0\0", 5);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'E', 9, 0);
    n = pgmsg(w, 'S', NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'S', 4, 0);

    n = pgmsg(w, '2', NULL, 0); /* BindComplete */
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, '2', 4, 0);
    n = pgmsg(w, 'C', "SELECT 5", 9);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'C', 13, 0);
    n = pgmsg(w, 'Z', "I", 1);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);

    n = pgmsg(w, 'X', NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);
    ev_close(&b);

    /* One EXTENDED observation, no text, rows from the tag. */
    b.x->queries = 1;
    b.x->obs_kind = LK_Q_EXTENDED;
    b.x->obs_rows = 5;
    b.x->obs_flags = LK_QO_NO_TEXT;
    b.x->obs_text = NULL; /* NO_TEXT: nothing to compare */
}

/* CopyInResponse / CopyOutResponse body: overall format (0 = text), int16
 * column count, then one int16 format per column. Content is never parsed — this
 * is just a plausible shape. */
static __u32 copy_response(__u8 *out, char type)
{
    __u8 body[8], *p = body;

    *p++ = 0;       /* overall format: text */
    p = be16(p, 1); /* one column */
    p = be16(p, 0); /* column format: text */
    return pgmsg(out, type, body, (__u32)(p - body));
}

/* \copy FROM STDIN: Q "COPY ... FROM STDIN" -> CopyInResponse -> two CopyData
 * rows -> CopyDone -> CommandComplete "COPY 2" -> Z. One COPY_IN observation
 * whose text is the opening command, rows from the tag, bytes = summed CopyData
 * len (Р20). */
static void build_copy_in(struct fx *x)
{
    struct bld b;
    __u8 w[128];
    __u32 n;
    /* Two CopyData messages; bytes = sum of their protocol len (payload + 4). */
    const char *rows[2] = {"1\tone\n", "2\ttwo\n"};
    __u64 bytes = 0;

    bld_init(&b, x);
    prelude(&b);

    n = pgmsg(w, 'Q', "COPY t FROM STDIN", 18); /* "...\0" */
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'Q', 22, 0);

    n = copy_response(w, 'G');
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'G', n - 1, 0);

    for (int i = 0; i < 2; i++) {
        __u32 rl = (__u32)strlen(rows[i]);

        n = pgmsg(w, 'd', rows[i], rl);
        call(&b, LK_DIR_RECV, w, n);
        expect(&b, LK_DIR_RECV, 'd', rl + 4, 0);
        bytes += rl + 4;
    }
    n = pgmsg(w, 'c', NULL, 0); /* CopyDone */
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'c', 4, 0);

    n = pgmsg(w, 'C', "COPY 2", 7);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'C', 11, 0);
    n = pgmsg(w, 'Z', "I", 1);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);

    n = pgmsg(w, 'X', NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_kind = LK_Q_COPY_IN;
    b.x->obs_rows = 2;
    b.x->obs_bytes = bytes;
    b.x->obs_flags = 0;
    b.x->obs_text = "COPY t FROM STDIN";
}

/* \copy TO STDOUT: Q "COPY ... TO STDOUT" -> CopyOutResponse -> two CopyData
 * rows (backend direction) -> CopyDone -> CommandComplete "COPY 2" -> Z. One
 * COPY_OUT observation. */
static void build_copy_out(struct fx *x)
{
    struct bld b;
    __u8 w[128];
    __u32 n;
    const char *rows[2] = {"1\tone\n", "2\ttwo\n"};
    __u64 bytes = 0;

    bld_init(&b, x);
    prelude(&b);

    n = pgmsg(w, 'Q', "COPY t TO STDOUT", 17); /* "...\0" */
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'Q', 21, 0);

    n = copy_response(w, 'H');
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'H', n - 1, 0);

    for (int i = 0; i < 2; i++) {
        __u32 rl = (__u32)strlen(rows[i]);

        n = pgmsg(w, 'd', rows[i], rl);
        call(&b, LK_DIR_SEND, w, n);
        expect(&b, LK_DIR_SEND, 'd', rl + 4, 0);
        bytes += rl + 4;
    }
    n = pgmsg(w, 'c', NULL, 0); /* CopyDone (backend) */
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'c', 4, 0);

    n = pgmsg(w, 'C', "COPY 2", 7);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'C', 11, 0);
    n = pgmsg(w, 'Z', "I", 1);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);

    n = pgmsg(w, 'X', NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_kind = LK_Q_COPY_OUT;
    b.x->obs_rows = 2;
    b.x->obs_bytes = bytes;
    b.x->obs_flags = 0;
    b.x->obs_text = "COPY t TO STDOUT";
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
    b.x->sessions = 1; /* plaintext startup completes: one session */
    b.x->sess_user = "postgres";
    b.x->sess_db = "postgres";

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

    /* One SIMPLE unit over the plaintext-negotiated connection. */
    b.x->queries = 1;
    b.x->obs_kind = LK_Q_SIMPLE;
    b.x->obs_rows = 1;
    b.x->obs_flags = 0;
    b.x->obs_text = "select 1";
}

/* SSL accepted: SSLRequest -> 'S' -> the connection goes TLS. The ciphertext
 * socket events are dropped (Р38), but the real session now travels the
 * decrypted uprobe channel (LK_F_DECRYPTED, own seq space) — the framer is reset
 * to startup on the 'S' (Р36), so the StartupMessage inside TLS parses, and the
 * observation is indistinguishable from the plaintext ssl_plain twin. */
static void build_ssl_tls(struct fx *x)
{
    struct bld b;
    __u8 w[128];
    __u32 n;

    bld_init(&b, x);
    ev_open(&b, false);

    /* Socket-path negotiation: SSLRequest -> 'S'. */
    n = pgstartup(w, LK_PG_SSL_REQUEST, NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0, 8, LK_MSG_STARTUP);

    /* 'S' plus the first ciphertext bytes in the same segment. */
    memcpy(w, "S\x16\x03\x01\x02\x00", 6);
    call(&b, LK_DIR_SEND, w, 6);
    expect(&b, LK_DIR_SEND, 'S', 0, 0);

    /* Ciphertext handshake on the socket — every raw event now dropped, no
     * messages, no dirty counters. */
    memset(w, 0xa5, 64);
    call(&b, LK_DIR_RECV, w, 64);
    call(&b, LK_DIR_SEND, w, 64);

    /* Decrypted channel: the real StartupMessage and the whole session. */
    n = pgstartup(w, LK_PG_PROTO_V3, startup_params, sizeof(startup_params));
    call_dec(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0, sizeof(startup_params) + 8, LK_MSG_STARTUP);
    n = pgmsg(w, 'R', auth_ok, sizeof(auth_ok));
    call_dec(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'R', 8, 0);
    n = pgmsg(w, 'Z', "I", 1);
    call_dec(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);
    b.x->sessions = 1; /* the decrypted startup completes: one session */
    b.x->sess_user = "postgres";
    b.x->sess_db = "postgres";

    n = pgmsg(w, 'Q', "select 1", 9);
    call_dec(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'Q', 13, 0);
    n = pgmsg(w, 'C', "SELECT 1", 9);
    call_dec(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'C', 13, 0);
    n = pgmsg(w, 'Z', "I", 1);
    call_dec(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);

    n = pgmsg(w, 'X', NULL, 0);
    call_dec(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);

    /* A trailing ciphertext close-notify on the socket — dropped — then CLOSE. */
    memset(w, 0x5a, 32);
    call(&b, LK_DIR_SEND, w, 32);
    ev_close(&b);

    b.x->tls_conns = 1;

    /* One SIMPLE unit over the decrypted channel, same as ssl_plain. */
    b.x->queries = 1;
    b.x->obs_kind = LK_Q_SIMPLE;
    b.x->obs_rows = 1;
    b.x->obs_flags = 0;
    b.x->obs_text = "select 1";
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

/* A failing simple query: Q "select 1/0" -> ErrorResponse (SQLSTATE 22012,
 * division by zero) -> Z. The unit closes on Z carrying LK_QO_ERROR and the
 * SQLSTATE; errors_sql ticks. The mirror of build_simple_query's happy path. */
static void build_error(struct fx *x)
{
    struct bld b;
    __u8 w[128];
    __u32 n;

    bld_init(&b, x);
    prelude(&b);

    n = pgmsg(w, 'Q', "select 1/0", 11); /* "select 1/0\0" */
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'Q', 15, 0);

    {
        /* ErrorResponse: S(everity) ERROR\0 C(ode) 22012\0 terminator. */
        __u8 err[32];
        __u32 en = 0;

        err[en++] = 'S';
        memcpy(err + en, "ERROR", 6);
        en += 6;
        err[en++] = 'C';
        memcpy(err + en, "22012", 6);
        en += 6;
        err[en++] = 0;
        n = pgmsg(w, 'E', err, en);
        call(&b, LK_DIR_SEND, w, n);
        expect(&b, LK_DIR_SEND, 'E', en + 4, 0);
    }
    n = pgmsg(w, 'Z', "I", 1);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);

    n = pgmsg(w, 'X', NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);
    ev_close(&b);

    /* One SIMPLE observation, closed by the error: no rows, LK_QO_ERROR, and
     * the SQLSTATE extracted from the 'C' field. */
    b.x->queries = 1;
    b.x->errors_sql = 1;
    b.x->obs_kind = LK_Q_SIMPLE;
    b.x->obs_rows = 0;
    b.x->obs_flags = LK_QO_ERROR;
    b.x->obs_text = "select 1/0";
    b.x->obs_sqlstate = "22012";
}

/* A multi-statement simple query: Q "select 1; select 2" replies with two
 * result sets and two CommandCompletes before the single Z. It stays one unit
 * (the client blocks on Z), flagged LK_QO_MULTI_STMT, with the row counts of
 * both tags summed (1 + 2 = 3). */
static void build_multi_statement(struct fx *x)
{
    struct bld b;
    __u8 w[128];
    __u32 n;

    bld_init(&b, x);
    prelude(&b);

    n = pgmsg(w, 'Q', "select 1; select 2", 19); /* "...\0" */
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'Q', 23, 0);

    /* First statement: T, D, C "SELECT 1". */
    n = row_desc(w);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'T', n - 1, 0);
    n = data_row(w, "1");
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'D', n - 1, 0);
    n = pgmsg(w, 'C', "SELECT 1", 9);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'C', 13, 0);

    /* Second statement: T, D, C "SELECT 2". */
    n = row_desc(w);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'T', n - 1, 0);
    n = data_row(w, "2");
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'D', n - 1, 0);
    n = pgmsg(w, 'C', "SELECT 2", 9);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'C', 13, 0);

    n = pgmsg(w, 'Z', "I", 1);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 'Z', 5, 0);

    n = pgmsg(w, 'X', NULL, 0);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 'X', 4, 0);
    ev_close(&b);

    /* One SIMPLE observation: two CommandCompletes -> MULTI_STMT, rows summed. */
    b.x->queries = 1;
    b.x->obs_kind = LK_Q_SIMPLE;
    b.x->obs_rows = 3;
    b.x->obs_flags = LK_QO_MULTI_STMT;
    b.x->obs_text = "select 1; select 2";
}

/* A query cancellation: a fresh connection sends only a CancelRequest (a
 * startup-framed packet with the cancel code, carrying the target's backend PID
 * and secret key) and closes. The framer emits the one startup message and marks
 * the connection LK_CONN_CANCEL; the parser turns it into a CANCEL observation
 * with no session, no text and no timings (Р16). */
static void build_cancel(struct fx *x)
{
    struct bld b;
    __u8 w[32];
    __u32 n;
    /* CancelRequest body after the length+code framing: backend PID + secret
     * key (8 bytes); their contents are irrelevant, the parser never reads them. */
    static const __u8 pid_key[8] = {0, 0, 0x30, 0x39, 0xde, 0xad, 0xbe, 0xef};

    bld_init(&b, x);
    ev_open(&b, false);

    n = pgstartup(w, LK_PG_CANCEL_REQUEST, pid_key, sizeof(pid_key));
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0, sizeof(pid_key) + 8, LK_MSG_STARTUP);

    ev_close(&b);

    /* One CANCEL observation; no AuthenticationOk means no session. */
    b.x->queries = 1;
    b.x->obs_kind = LK_Q_CANCEL;
    b.x->obs_rows = 0;
    b.x->obs_flags = 0;
    b.x->obs_text = NULL; /* CANCEL carries no text */
}

/* ===========================================================================
 * MySQL classic-protocol fixtures (MYSQL.md М7) — the mirror of the PG set,
 * built as LKT1 traces of synthetic mysqld sessions in the same record format
 * `--record` produces. run_fixture routes a fixture whose .proto is "mysql"
 * through the MySQL framer + handler; a real `--record` capture of mysqld
 * drops in as another one of these without harness changes. Every builder
 * ends with COM_QUIT + CLOSE so the connection table returns to empty.
 * ===========================================================================
 */

/* --- little-endian + length-encoded wire writers --------------------------- */

static __u8 *le16(__u8 *p, __u16 v)
{
    *p++ = (__u8)v;
    *p++ = (__u8)(v >> 8);
    return p;
}

static __u8 *le24(__u8 *p, __u32 v)
{
    *p++ = (__u8)v;
    *p++ = (__u8)(v >> 8);
    *p++ = (__u8)(v >> 16);
    return p;
}

static __u8 *le32(__u8 *p, __u32 v)
{
    *p++ = (__u8)v;
    *p++ = (__u8)(v >> 8);
    *p++ = (__u8)(v >> 16);
    *p++ = (__u8)(v >> 24);
    return p;
}

/* Length-encoded integer (the fixtures only need the small forms). */
static __u8 *lenenc(__u8 *p, __u64 v)
{
    if (v < 251) {
        *p++ = (__u8)v;
    } else if (v < 0x10000) {
        *p++ = 0xfc;
        p = le16(p, (__u16)v);
    } else {
        *p++ = 0xfd;
        p = le24(p, (__u32)v);
    }
    return p;
}

/* Length-encoded string: lenenc length + the bytes. */
static __u8 *lenstr(__u8 *p, const char *s, __u32 n)
{
    p = lenenc(p, n);
    if (n)
        memcpy(p, s, n);
    return p + n;
}

static __u8 *lenstr0(__u8 *p, const char *s)
{
    return lenstr(p, s, (__u32)strlen(s));
}

/* One classic-protocol packet: len(u24, LE) + seq(u8) + body. Returns the
 * total wire size; the framer reports m->len == blen (the logical payload). */
static __u32 mypkt(__u8 *out, __u8 seq, const __u8 *body, __u32 blen)
{
    le24(out, blen);
    out[3] = seq;
    if (blen)
        memcpy(out + 4, body, blen);
    return blen + 4;
}

/* Client capability flags every plaintext fixture negotiates: mysql dialect
 * (the filler u32 is not MariaDB extended caps), CONNECT_WITH_DB, PROTOCOL_41,
 * TRANSACTIONS, MULTI_STATEMENTS, PLUGIN_AUTH, CONNECT_ATTRS (the app label),
 * DEPRECATE_EOF (the modern resultset shape — an OK-with-0xFE terminator, no
 * intermediate EOF). No CLIENT_SSL / _COMPRESS / PLUGIN_AUTH_LENENC. */
#define MY_FX_CAPS      0x01192209u
#define MY_FX_CAP_SSL   0x00000800u
#define MY_FX_CAP_COMPR 0x00000020u

/* Server status flags in OK / EOF terminators. */
#define MY_FX_ST_INTRANS    0x0001
#define MY_FX_ST_AUTOCOMMIT 0x0002
#define MY_FX_ST_MORE       0x0008
#define MY_FX_ST_CURSOR     0x0040
#define MY_FX_ST_LASTROW    0x0080

/* Initial Handshake (protocol 10). The session reads only the version; the
 * rest is realistic filler the parser skips. */
static __u32 my_greeting(__u8 *out)
{
    __u8 b[128], *p = b;

    *p++ = 10;             /* protocol version */
    memcpy(p, "8.4.0", 6); /* server_version + NUL */
    p += 6;
    p = le32(p, 1);  /* thread id */
    memset(p, 0, 8); /* auth-plugin-data part 1 */
    p += 8;
    *p++ = 0;            /* filler */
    p = le16(p, 0xffff); /* capability flags (lower) — server offer only */
    *p++ = 0xff;         /* charset (utf8mb4) */
    p = le16(p, MY_FX_ST_AUTOCOMMIT);
    p = le16(p, 0xffff); /* capability flags (upper) */
    *p++ = 21;           /* auth-plugin-data length */
    memset(p, 0, 10);    /* reserved */
    p += 10;
    memset(p, 0, 13); /* auth-plugin-data part 2 */
    p += 13;
    memcpy(p, "caching_sha2_password", 22); /* + NUL */
    p += 22;
    return mypkt(out, 0, b, (__u32)(p - b));
}

/* HandshakeResponse41: caps u32, max_packet u32, charset u8, 23-byte filler,
 * user\0, u8-len auth response (empty — never read, Р16), database\0, auth
 * plugin\0, connect-attrs (program_name=mysql -> the app label). */
static __u32 my_handshake_response(__u8 *out, __u32 caps)
{
    __u8 b[256], *p = b;
    __u8 kv[64], *k = kv;
    __u32 klen;

    p = le32(p, caps);
    p = le32(p, 0x01000000); /* max_packet 16 MB */
    *p++ = 0xff;             /* charset */
    memset(p, 0, 23);        /* filler (mysql dialect: mcaps stays 0) */
    p += 23;
    memcpy(p, "root", 5); /* user + NUL */
    p += 5;
    *p++ = 0;             /* auth response length 0 */
    memcpy(p, "test", 5); /* database + NUL */
    p += 5;
    memcpy(p, "caching_sha2_password", 22); /* plugin + NUL */
    p += 22;
    k = lenstr0(k, "program_name");
    k = lenstr0(k, "mysql");
    klen = (__u32)(k - kv);
    p = lenenc(p, klen); /* connect-attrs total length */
    memcpy(p, kv, klen);
    p += klen;
    return mypkt(out, 1, b, (__u32)(p - b));
}

/* OK packet (0x00 header). */
static __u32 my_ok(__u8 *out, __u8 seq, __u64 affected, __u16 status)
{
    __u8 b[16], *p = b;

    *p++ = 0x00;
    p = lenenc(p, affected);
    p = lenenc(p, 0); /* last_insert_id */
    p = le16(p, status);
    p = le16(p, 0); /* warnings */
    return mypkt(out, seq, b, (__u32)(p - b));
}

/* OK-with-0xFE terminator (CLIENT_DEPRECATE_EOF): closes a resultset. */
static __u32 my_eof(__u8 *out, __u8 seq, __u16 status)
{
    __u8 b[16], *p = b;

    *p++ = 0xfe;
    p = lenenc(p, 0); /* affected_rows */
    p = lenenc(p, 0); /* last_insert_id */
    p = le16(p, status);
    p = le16(p, 0); /* warnings */
    return mypkt(out, seq, b, (__u32)(p - b));
}

/* ERR packet: errno u16, '#' SQLSTATE(5), message. */
static __u32 my_err(__u8 *out, __u8 seq, __u16 code, const char *sqlstate, const char *msg)
{
    __u8 b[128], *p = b;
    __u32 ml = (__u32)strlen(msg);

    *p++ = 0xff;
    p = le16(p, code);
    *p++ = '#';
    memcpy(p, sqlstate, 5);
    p += 5;
    memcpy(p, msg, ml);
    p += ml;
    return mypkt(out, seq, b, (__u32)(p - b));
}

/* Result head: a lenenc column count. */
static __u32 my_colcount(__u8 *out, __u8 seq, __u32 count)
{
    __u8 b[8];

    return mypkt(out, seq, b, (__u32)(lenenc(b, count) - b));
}

/* A column definition (head byte is the lenenc "def" length, 0x03 — never
 * 0xFE/0xFF, so the reply machine skips it as metadata). */
static __u32 my_coldef(__u8 *out, __u8 seq, const char *name)
{
    __u8 b[128], *p = b;

    p = lenstr0(p, "def");  /* catalog */
    p = lenstr0(p, "test"); /* schema */
    p = lenstr0(p, "t");    /* table */
    p = lenstr0(p, "t");    /* org_table */
    p = lenstr0(p, name);   /* name */
    p = lenstr0(p, name);   /* org_name */
    *p++ = 0x0c;            /* length of the fixed-length fields */
    p = le16(p, 0x003f);    /* charset (binary) */
    p = le32(p, 11);        /* column length */
    *p++ = 0x03;            /* column type: LONG */
    p = le16(p, 0x0000);    /* flags */
    *p++ = 0x00;            /* decimals */
    p = le16(p, 0);         /* filler */
    return mypkt(out, seq, b, (__u32)(p - b));
}

/* A text-protocol row (one lenenc-string column). */
static __u32 my_textrow(__u8 *out, __u8 seq, const char *val)
{
    __u8 b[64];

    return mypkt(out, seq, b, (__u32)(lenstr0(b, val) - b));
}

/* A binary-protocol row (prepared resultset): 0x00 header + null bitmap +
 * values. Only counted by the reply machine, never parsed. */
static __u32 my_binrow(__u8 *out, __u8 seq)
{
    __u8 b[8], *p = b;

    *p++ = 0x00;    /* binary row packet header */
    *p++ = 0x00;    /* null bitmap */
    p = le32(p, 1); /* one 4-byte value */
    return mypkt(out, seq, b, (__u32)(p - b));
}

/* COM_QUERY (command byte 0x03) with the SQL text. */
static __u32 my_query_cmd(__u8 *out, const char *sql)
{
    __u8 b[512];
    __u32 sl = (__u32)strlen(sql);

    b[0] = 0x03;
    memcpy(b + 1, sql, sl);
    return mypkt(out, 0, b, 1 + sl);
}

/* COM_STMT_PREPARE (0x16) with the SQL text. */
static __u32 my_prepare_cmd(__u8 *out, const char *sql)
{
    __u8 b[512];
    __u32 sl = (__u32)strlen(sql);

    b[0] = 0x16;
    memcpy(b + 1, sql, sl);
    return mypkt(out, 0, b, 1 + sl);
}

/* COM_STMT_PREPARE_OK: 0x00, stmt_id u32, num_columns u16, num_params u16,
 * reserved u8, warnings u16. */
static __u32 my_prepare_ok(__u8 *out, __u8 seq, __u32 stmt_id, __u16 ncols, __u16 nparams)
{
    __u8 b[16], *p = b;

    *p++ = 0x00;
    p = le32(p, stmt_id);
    p = le16(p, ncols);
    p = le16(p, nparams);
    *p++ = 0x00;    /* reserved */
    p = le16(p, 0); /* warning count */
    return mypkt(out, seq, b, (__u32)(p - b));
}

/* COM_STMT_EXECUTE (0x17): stmt_id u32, flags u8, iteration u32. The
 * parameter tail is never parsed; `cursor` sets CURSOR_TYPE_READ_ONLY. */
static __u32 my_execute_cmd(__u8 *out, __u32 stmt_id, bool cursor)
{
    __u8 b[16], *p = b;

    *p++ = 0x17;
    p = le32(p, stmt_id);
    *p++ = cursor ? 0x01 : 0x00; /* CURSOR_TYPE_READ_ONLY */
    p = le32(p, 1);              /* iteration count */
    return mypkt(out, 0, b, (__u32)(p - b));
}

/* COM_STMT_FETCH (0x1c): stmt_id u32, rows-to-fetch u32. */
static __u32 my_fetch_cmd(__u8 *out, __u32 stmt_id, __u32 nrows)
{
    __u8 b[16], *p = b;

    *p++ = 0x1c;
    p = le32(p, stmt_id);
    p = le32(p, nrows);
    return mypkt(out, 0, b, (__u32)(p - b));
}

/* COM_STMT_CLOSE (0x19): stmt_id u32; no server reply. */
static __u32 my_close_cmd(__u8 *out, __u32 stmt_id)
{
    __u8 b[8], *p = b;

    *p++ = 0x19;
    p = le32(p, stmt_id);
    return mypkt(out, 0, b, (__u32)(p - b));
}

/* COM_QUIT (0x01): no reply, socket closes. */
static __u32 my_quit_cmd(__u8 *out)
{
    __u8 b = 0x01;

    return mypkt(out, 0, &b, 1);
}

static void mybld_init(struct bld *b, struct fx *x)
{
    bld_init(b, x);
    b->tuple.dport = 3306; /* the mysqld port (realism; run_fixture forces ops) */
}

/* Prelude: OPEN + greeting + HandshakeResponse41 + final OK — a complete
 * connection phase. Emits one session (user=root db=test app=mysql). All
 * three packets carry LK_MSG_STARTUP (the flag clears on the first command).
 * `caps` selects the plaintext / SSL / compressed handshake shape. */
static void my_prelude(struct bld *b, __u32 caps)
{
    __u8 w[512];
    __u32 n;

    ev_open(b, false);
    n = my_greeting(w);
    call(b, LK_DIR_SEND, w, n);
    expect(b, LK_DIR_SEND, 0, n - 4, LK_MSG_STARTUP);
    n = my_handshake_response(w, caps);
    call(b, LK_DIR_RECV, w, n);
    expect(b, LK_DIR_RECV, 0, n - 4, LK_MSG_STARTUP);
    n = my_ok(w, 2, 0, MY_FX_ST_AUTOCOMMIT);
    call(b, LK_DIR_SEND, w, n);
    expect(b, LK_DIR_SEND, 0, n - 4, LK_MSG_STARTUP);

    b->x->sessions = 1;
    b->x->sess_user = "root";
    b->x->sess_db = "test";
}

/* Append a full text-protocol SELECT resultset (colcount, one coldef, `nrows`
 * text rows, OK-0xFE terminator) as one backend call, seqs starting at
 * `seq0`. Its expect() lines are added in order. */
static void my_resultset(struct bld *b, __u8 seq0, int nrows, __u16 end_status)
{
    __u8 w[512];
    __u32 n = 0, t;
    __u8 seq = seq0;

    t = my_colcount(w + n, seq++, 1);
    expect(b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    t = my_coldef(w + n, seq++, "c");
    expect(b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    for (int i = 0; i < nrows; i++) {
        char v[2] = {(char)('1' + i), '\0'};

        t = my_textrow(w + n, seq++, v);
        expect(b, LK_DIR_SEND, 0, t - 4, 0);
        n += t;
    }
    t = my_eof(w + n, seq++, end_status);
    expect(b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    call(b, LK_DIR_SEND, w, n);
}

/* --- MySQL fixtures -------------------------------------------------------- */

/* mysql CLI simple query: handshake -> COM_QUERY "SELECT 1" -> 1-row resultset
 * -> COM_QUIT. One SIMPLE unit, one row, text "SELECT 1" (-> "select ?"). */
static void build_my_simple_query(struct fx *x)
{
    struct bld b;
    __u8 w[512];
    __u32 n;

    mybld_init(&b, x);
    my_prelude(&b, MY_FX_CAPS);

    n = my_query_cmd(w, "SELECT 1");
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x03, n - 4, 0);

    my_resultset(&b, 1, 1, MY_FX_ST_AUTOCOMMIT);

    n = my_quit_cmd(w);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x01, 1, 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_kind = LK_Q_SIMPLE;
    b.x->obs_rows = 1;
    b.x->obs_flags = 0;
    b.x->obs_text = "SELECT 1";
}

/* A failing query: COM_QUERY on a missing table -> ERR (errno 1146, SQLSTATE
 * 42S02). One SIMPLE unit closed by the error; errors_sql ticks. */
static void build_my_error(struct fx *x)
{
    struct bld b;
    __u8 w[512];
    __u32 n;

    mybld_init(&b, x);
    my_prelude(&b, MY_FX_CAPS);

    n = my_query_cmd(w, "SELECT * FROM missing");
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x03, n - 4, 0);

    n = my_err(w, 1, 1146, "42S02", "Table 'test.missing' doesn't exist");
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 0, n - 4, 0);

    n = my_quit_cmd(w);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x01, 1, 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->errors_sql = 1;
    b.x->obs_kind = LK_Q_SIMPLE;
    b.x->obs_rows = 0;
    b.x->obs_flags = LK_QO_ERROR;
    b.x->obs_text = "SELECT * FROM missing";
    b.x->obs_sqlstate = "42S02";
}

/* Multi-statement COM_QUERY "SELECT 1; SELECT 2": two resultsets, the first's
 * OK carrying SERVER_MORE_RESULTS_EXISTS, chained into one MULTI_STMT unit
 * with the row counts summed (1 + 1 = 2). */
static void build_my_multi_statement(struct fx *x)
{
    struct bld b;
    __u8 w[512];
    __u32 n;

    mybld_init(&b, x);
    my_prelude(&b, MY_FX_CAPS);

    n = my_query_cmd(w, "SELECT 1; SELECT 2");
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x03, n - 4, 0);

    /* First resultset: OK-0xFE carries MORE_RESULTS; seqs 1..4. */
    my_resultset(&b, 1, 1, MY_FX_ST_AUTOCOMMIT | MY_FX_ST_MORE);
    /* Second resultset: plain terminator; seqs continue at 5. */
    my_resultset(&b, 5, 1, MY_FX_ST_AUTOCOMMIT);

    n = my_quit_cmd(w);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x01, 1, 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_kind = LK_Q_SIMPLE;
    b.x->obs_rows = 2;
    b.x->obs_flags = LK_QO_MULTI_STMT;
    b.x->obs_text = "SELECT 1; SELECT 2";
}

/* Binary prepared statement: COM_STMT_PREPARE "SELECT ?" -> PREPARE_OK (id 1,
 * 1 col + 1 param) -> 2 metadata defs -> two COM_STMT_EXECUTE round-trips, each
 * a 1-row binary resultset -> COM_STMT_CLOSE. Two EXTENDED units, both with the
 * cached text "SELECT ?" (placeholder intact). */
static void build_my_prepared(struct fx *x)
{
    struct bld b;
    __u8 w[512];
    __u32 n, t;

    mybld_init(&b, x);
    my_prelude(&b, MY_FX_CAPS);

    n = my_prepare_cmd(w, "SELECT ?");
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x16, n - 4, 0);

    /* PREPARE_OK + the param def + the column def (DEPRECATE_EOF: no EOFs). */
    n = 0;
    t = my_prepare_ok(w + n, 1, 1, 1, 1);
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    t = my_coldef(w + n, 2, "?");
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    t = my_coldef(w + n, 3, "c");
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    call(&b, LK_DIR_SEND, w, n);

    for (int i = 0; i < 2; i++) {
        n = my_execute_cmd(w, 1, false);
        call(&b, LK_DIR_RECV, w, n);
        expect(&b, LK_DIR_RECV, 0x17, n - 4, 0);

        /* Binary resultset: colcount, coldef, one binary row, OK-0xFE. */
        n = 0;
        t = my_colcount(w + n, 1, 1);
        expect(&b, LK_DIR_SEND, 0, t - 4, 0);
        n += t;
        t = my_coldef(w + n, 2, "c");
        expect(&b, LK_DIR_SEND, 0, t - 4, 0);
        n += t;
        t = my_binrow(w + n, 3);
        expect(&b, LK_DIR_SEND, 0, t - 4, 0);
        n += t;
        t = my_eof(w + n, 4, MY_FX_ST_AUTOCOMMIT);
        expect(&b, LK_DIR_SEND, 0, t - 4, 0);
        n += t;
        call(&b, LK_DIR_SEND, w, n);
    }

    n = my_close_cmd(w, 1); /* COM_STMT_CLOSE: no reply */
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x19, n - 4, 0);

    n = my_quit_cmd(w);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x01, 1, 0);
    ev_close(&b);

    b.x->queries = 2;
    b.x->obs_kind = LK_Q_EXTENDED;
    b.x->obs_rows = 1;
    b.x->obs_flags = 0;
    b.x->obs_text = "SELECT ?";
}

/* LOAD DATA LOCAL INFILE: COM_QUERY -> 0xFB filename request -> client data
 * packets -> empty packet -> final OK (affected_rows = 2). One COPY_IN unit;
 * bytes = the summed data-packet payload, rows from the OK. */
static void build_my_load_data(struct fx *x)
{
    struct bld b;
    __u8 w[512];
    __u32 n, t;
    const char *rows[2] = {"1\tone\n", "2\ttwo\n"};
    __u64 bytes = 0;
    __u8 seq;

    mybld_init(&b, x);
    my_prelude(&b, MY_FX_CAPS);

    n = my_query_cmd(w, "LOAD DATA LOCAL INFILE 'x' INTO TABLE t");
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x03, n - 4, 0);

    /* 0xFB LOCAL INFILE request (the filename is not observable). */
    {
        __u8 body[64], *p = body;

        *p++ = 0xfb;
        memcpy(p, "x", 1);
        p += 1;
        n = mypkt(w, 1, body, (__u32)(p - body));
    }
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 0, n - 4, 0);

    /* Client data packets (seqs 2..) then the empty end-of-data packet. */
    n = 0;
    seq = 2;
    for (int i = 0; i < 2; i++) {
        __u32 rl = (__u32)strlen(rows[i]);

        t = mypkt(w + n, seq++, (const __u8 *)rows[i], rl);
        expect(&b, LK_DIR_RECV, 0, rl, 0);
        n += t;
        bytes += rl;
    }
    t = mypkt(w + n, seq++, NULL, 0); /* empty packet: end of data */
    expect(&b, LK_DIR_RECV, 0, 0, 0);
    n += t;
    call(&b, LK_DIR_RECV, w, n);

    n = my_ok(w, seq, 2, MY_FX_ST_AUTOCOMMIT); /* final OK: affected_rows = 2 */
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 0, n - 4, 0);

    n = my_quit_cmd(w);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x01, 1, 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_kind = LK_Q_COPY_IN;
    b.x->obs_rows = 2;
    b.x->obs_bytes = bytes;
    b.x->obs_flags = 0;
    b.x->obs_text = "LOAD DATA LOCAL INFILE 'x' INTO TABLE t";
}

/* Server-side cursor: COM_STMT_EXECUTE with CURSOR_TYPE_READ_ONLY opens a
 * cursor (metadata then an OK-0xFE carrying CURSOR_EXISTS — the SUSPENDED
 * terminator, no rows), then two COM_STMT_FETCH batches: the first still
 * SUSPENDED, the last draining (LAST_ROW_SENT, flags 0). Three EXTENDED units
 * sharing the cached text; rows 0 + 2 + 1. */
static void build_my_cursor_fetch(struct fx *x)
{
    struct bld b;
    __u8 w[512];
    __u32 n, t;

    mybld_init(&b, x);
    my_prelude(&b, MY_FX_CAPS);

    n = my_prepare_cmd(w, "SELECT id FROM t");
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x16, n - 4, 0);

    /* PREPARE_OK (id 7, 1 column, 0 params) + the column def. */
    n = 0;
    t = my_prepare_ok(w + n, 1, 7, 1, 0);
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    t = my_coldef(w + n, 2, "id");
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    call(&b, LK_DIR_SEND, w, n);

    /* EXECUTE with a cursor: colcount, coldef, OK-0xFE with CURSOR_EXISTS —
     * the terminator, no rows (the SUSPENDED execute unit). */
    n = my_execute_cmd(w, 7, true);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x17, n - 4, 0);
    n = 0;
    t = my_colcount(w + n, 1, 1);
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    t = my_coldef(w + n, 2, "id");
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    t = my_eof(w + n, 3, MY_FX_ST_AUTOCOMMIT | MY_FX_ST_CURSOR);
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    call(&b, LK_DIR_SEND, w, n);

    /* FETCH batch 1: two binary rows + OK-0xFE with CURSOR_EXISTS (SUSPENDED). */
    n = my_fetch_cmd(w, 7, 2);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x1c, n - 4, 0);
    n = 0;
    t = my_binrow(w + n, 1);
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    t = my_binrow(w + n, 2);
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    t = my_eof(w + n, 3, MY_FX_ST_AUTOCOMMIT | MY_FX_ST_CURSOR);
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    call(&b, LK_DIR_SEND, w, n);

    /* FETCH batch 2: one row + OK-0xFE with LAST_ROW_SENT (drained, flags 0). */
    n = my_fetch_cmd(w, 7, 2);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x1c, n - 4, 0);
    n = 0;
    t = my_binrow(w + n, 1);
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    t = my_eof(w + n, 2, MY_FX_ST_AUTOCOMMIT | MY_FX_ST_LASTROW);
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    call(&b, LK_DIR_SEND, w, n);

    n = my_close_cmd(w, 7);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x19, n - 4, 0);

    n = my_quit_cmd(w);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x01, 1, 0);
    ev_close(&b);

    b.x->queries = 3;
    b.x->obs_kind = LK_Q_EXTENDED;
    b.x->obs_rows = 1;  /* the last (draining) batch */
    b.x->obs_flags = 0; /* LAST_ROW_SENT: no SUSPENDED */
    b.x->obs_text = "SELECT id FROM t";
}

/* Compressed connection (РМ7 blind zone): the HandshakeResponse negotiates
 * CLIENT_COMPRESS, so the final OK flips the connection to IGNORE. The session
 * labels were on the wire in plaintext and are read; the compressed command
 * phase is never observed (queries = 0). */
static void build_my_compressed(struct fx *x)
{
    struct bld b;
    __u8 w[512];

    mybld_init(&b, x);
    my_prelude(&b, MY_FX_CAPS | MY_FX_CAP_COMPR);

    /* A compressed command packet: opaque to the framer once IGNORE is set —
     * no message, no observation. */
    memset(w, 0xa5, 32);
    call(&b, LK_DIR_RECV, w, 32);
    ev_close(&b);

    /* Session parsed from the plaintext handshake; no queries. */
    b.x->queries = 0;
}

/* TLS session: the socket path carries the greeting + the short SSLRequest
 * (CLIENT_SSL flips the connection to TLS), then ciphertext — dropped. The
 * real session travels the decrypted uprobe channel, where the full
 * HandshakeResponse repeats and the query parses in plaintext, so the
 * observation matches the cleartext twin. */
static void build_my_ssl(struct fx *x)
{
    struct bld b;
    __u8 w[512];
    __u32 n;

    mybld_init(&b, x);
    ev_open(&b, false);

    /* Socket: greeting, then the 32-byte SSLRequest (header only, CLIENT_SSL). */
    n = my_greeting(w);
    call(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 0, n - 4, LK_MSG_STARTUP);
    {
        __u8 b32[36], *p = b32;

        p = le32(p, MY_FX_CAPS | MY_FX_CAP_SSL);
        p = le32(p, 0x01000000); /* max_packet */
        *p++ = 0xff;             /* charset */
        memset(p, 0, 23);        /* filler — the packet ends here */
        p += 23;
        n = mypkt(w, 1, b32, (__u32)(p - b32));
    }
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0, n - 4, LK_MSG_STARTUP);

    /* Ciphertext on the socket: every raw event now dropped. */
    memset(w, 0xa5, 64);
    call(&b, LK_DIR_RECV, w, 64);
    call(&b, LK_DIR_SEND, w, 64);

    /* Decrypted channel: the full HandshakeResponse, the OK, then the query. */
    n = my_handshake_response(w, MY_FX_CAPS | MY_FX_CAP_SSL);
    call_dec(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0, n - 4, LK_MSG_STARTUP);
    n = my_ok(w, 2, 0, MY_FX_ST_AUTOCOMMIT);
    call_dec(&b, LK_DIR_SEND, w, n);
    expect(&b, LK_DIR_SEND, 0, n - 4, LK_MSG_STARTUP);
    b.x->sessions = 1;
    b.x->sess_user = "root";
    b.x->sess_db = "test";

    n = my_query_cmd(w, "SELECT 1");
    call_dec(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x03, n - 4, 0);
    {
        __u8 rw[256];
        __u32 rn = 0, t;
        __u8 seq = 1;

        t = my_colcount(rw + rn, seq++, 1);
        expect(&b, LK_DIR_SEND, 0, t - 4, 0);
        rn += t;
        t = my_coldef(rw + rn, seq++, "c");
        expect(&b, LK_DIR_SEND, 0, t - 4, 0);
        rn += t;
        t = my_textrow(rw + rn, seq++, "1");
        expect(&b, LK_DIR_SEND, 0, t - 4, 0);
        rn += t;
        t = my_eof(rw + rn, seq++, MY_FX_ST_AUTOCOMMIT);
        expect(&b, LK_DIR_SEND, 0, t - 4, 0);
        rn += t;
        call_dec(&b, LK_DIR_SEND, rw, rn);
    }

    n = my_quit_cmd(w);
    call_dec(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x01, 1, 0);

    /* A trailing ciphertext close-notify on the socket — dropped — then CLOSE. */
    memset(w, 0x5a, 32);
    call(&b, LK_DIR_SEND, w, 32);
    ev_close(&b);

    b.x->tls_conns = 1;
    b.x->queries = 1;
    b.x->obs_kind = LK_Q_SIMPLE;
    b.x->obs_rows = 1;
    b.x->obs_flags = 0;
    b.x->obs_text = "SELECT 1";
}

/* Agent attached mid-session (synthetic OPEN, handshake never seen): both
 * directions start dirty. The frontend rejoins on its command anchor (a seq-0
 * COM_QUERY), the backend on a response-head anchor (seq 1). The unit opened
 * by the command is dropped by the backend resync (Р19) — no observation, but
 * framing recovers cleanly. */
static void build_my_synthetic_midsession(struct fx *x)
{
    struct bld b;
    __u8 w[512];
    __u32 n, t;
    __u8 seq;

    mybld_init(&b, x);
    ev_open(&b, true); /* synthetic: both directions marked dirty */

    /* Frontend anchor: a fresh COM_QUERY at a call boundary. */
    n = my_query_cmd(w, "SELECT 1");
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x03, n - 4, LK_MSG_AFTER_RESYNC);

    /* Backend anchor: the response head (seq 1) at a call boundary. */
    n = 0;
    seq = 1;
    t = my_colcount(w + n, seq++, 1);
    expect(&b, LK_DIR_SEND, 0, t - 4, LK_MSG_AFTER_RESYNC);
    n += t;
    t = my_coldef(w + n, seq++, "c");
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    t = my_textrow(w + n, seq++, "1");
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    t = my_eof(w + n, seq++, MY_FX_ST_AUTOCOMMIT);
    expect(&b, LK_DIR_SEND, 0, t - 4, 0);
    n += t;
    call(&b, LK_DIR_SEND, w, n);

    n = my_quit_cmd(w);
    call(&b, LK_DIR_RECV, w, n);
    expect(&b, LK_DIR_RECV, 0x01, 1, 0);
    ev_close(&b);

    b.x->resyncs = 2;
}

/* --- HTTP/1.x wire helpers (PLAN-HTTP.md М8) ------------------------------
 * HTTP is text, so these fixtures are the traces themselves: the bytes below
 * are what a client and a server put on the wire, and the expectations beside
 * them are the five synthetic messages of РH3 the framer publishes for them —
 * 'R' request head, 'S' response head, 'I' interim, 'D' body bytes (count
 * only, never payload), 'E' body end, '!' framer note. The message characters
 * are spelled out rather than included from src/proto/http/http.h: the harness
 * links the protocol library, it does not share its internals, and a fixture
 * that agreed with the framer by construction would assert nothing.
 *
 * Where a Content-Length appears it is computed from the body it describes,
 * for the same reason: a fixture whose framing header disagreed with its own
 * body would be exercising the error path by accident. */

#define HTTP_FX_HOST "latkit.test"
#define HTTP_FX_UA   "curl/8.5.0"
/* The two fields every request in the set carries: the host that becomes the
 * `host` label (РH10) and the agent that becomes the session's app slot. */
#define HTTP_FX_HDRS "Host: " HTTP_FX_HOST "\r\nUser-Agent: " HTTP_FX_UA "\r\n"

/* Note codes, mirroring enum lk_http_note (http.h) — the value travels in the
 * '!' message's len field, so the expectation has to name it. */
#define FX_HTTP_NOTE_HEAD_HOLE     4
#define FX_HTTP_NOTE_BODY_UNSEEN   12
#define FX_HTTP_NOTE_BLIND_H2      15
#define FX_HTTP_NOTE_BLIND_UPGRADE 16
#define FX_HTTP_NOTE_BLIND_CONNECT 17

static void httpbld_init(struct bld *b, struct fx *x)
{
    bld_init(b, x);
    b->tuple.dport = 8080; /* an http port (realism; run_fixture forces ops) */

    /* Every HTTP fixture opens exactly one session, off the first request head
     * (there is no handshake to hang one on): the host in the db slot, the user
     * slot empty — HTTP usually carries no identity at all. */
    x->sessions = 1;
    x->sess_db = HTTP_FX_HOST;
    x->sess_user = "";
    x->obs_kind = LK_Q_REQUEST;
}

/* One fully captured call carrying `s`; returns its length. */
static __u32 http_call(struct bld *b, enum lk_dir dir, const char *s)
{
    __u32 n = (__u32)strlen(s);

    call(b, dir, (const __u8 *)s, n);
    return n;
}

/* A request head, alone in its call. `flags` carries LK_MSG_AFTER_RESYNC where
 * the fixture rejoins a stream. Rule 5 (no framing header, no body) closes the
 * message immediately, so a bodiless request is 'R' + an empty 'E'. */
static void http_req(struct bld *b, const char *head, bool body_follows, __u16 flags)
{
    __u32 n = http_call(b, LK_DIR_RECV, head);

    expect(b, LK_DIR_RECV, 'R', n, flags);
    if (!body_follows)
        expect(b, LK_DIR_RECV, 'E', 0, 0);
}

/* A response head and its body in one call — the common shape on the wire. An
 * empty body means the head said so (Content-Length: 0) or the request did
 * (HEAD, 204, 304): either way the framer closes the message at once. */
static void http_resp(struct bld *b, const char *head, const char *body, __u16 flags)
{
    char w[8192];
    __u32 hn = (__u32)strlen(head), bn = (__u32)strlen(body);

    memcpy(w, head, hn);
    memcpy(w + hn, body, bn);
    call(b, LK_DIR_SEND, (const __u8 *)w, hn + bn);
    expect(b, LK_DIR_SEND, 'S', hn, flags);
    if (bn)
        expect(b, LK_DIR_SEND, 'D', bn, 0);
    expect(b, LK_DIR_SEND, 'E', bn, 0);
}

/* A body in its own call: the shape that makes the four timings of РH5 visible
 * — the head and the last body byte land on different events, so the upload
 * interval (request) or the TTFB (response) is measurable rather than zero. */
static void http_body(struct bld *b, enum lk_dir dir, const char *body)
{
    __u32 n = http_call(b, dir, body);

    expect(b, dir, 'D', n, 0);
    expect(b, dir, 'E', n, 0);
}

/* The 200 every "and then an ordinary exchange" step in the set answers with. */
#define HTTP_FX_OK_HEAD "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\n"
#define HTTP_FX_OK_BODY "hello, world!"

/* --- HTTP fixtures --------------------------------------------------------- */

/* The base case: one GET, one 200 with a Content-Length body. Everything an
 * observation reports is present and nothing is degraded — the row every other
 * HTTP fixture is a deviation from. */
static void build_http_get(struct fx *x)
{
    struct bld b;

    httpbld_init(&b, x);
    ev_open(&b, false);
    http_req(&b, "GET /hello HTTP/1.1\r\n" HTTP_FX_HDRS "\r\n", false, 0);
    http_resp(&b, HTTP_FX_OK_HEAD, HTTP_FX_OK_BODY, 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "GET";
    b.x->obs_route = "/hello";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = 13;
    b.x->obs_text = "/hello";
}

/* A POST with a Content-Length body, uploaded in its own call: the shape РH5
 * exists for. The id in the path is what the route templater must collapse
 * (РH7) — `/orders/42/items` is one route, not one per order. */
static void build_http_post(struct fx *x)
{
    struct bld b;
    static const char body[] = "{\"sku\":\"ABC-1\",\"qty\":3}";
    char head[256];

    httpbld_init(&b, x);
    ev_open(&b, false);
    snprintf(head, sizeof(head),
             "POST /orders/42/items HTTP/1.1\r\n" HTTP_FX_HDRS
             "Content-Type: application/json\r\nContent-Length: %zu\r\n\r\n",
             sizeof(body) - 1);
    http_req(&b, head, true, 0);
    http_body(&b, LK_DIR_RECV, body);
    http_resp(&b, "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n", "ok", 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "POST";
    b.x->obs_route = "/orders/{id}/items";
    b.x->obs_status = 201;
    b.x->obs_bytes_in = sizeof(body) - 1;
    b.x->obs_bytes_out = 2;
    b.x->obs_text = "/orders/42/items";
}

/* A chunked *request* body with a trailer section. 'D' reports decoded bytes,
 * so the eleven bytes of "hello world" are eleven whichever framing carried
 * them — the invariant the chunked path exists to keep. */
static void build_http_chunked_req(struct fx *x)
{
    struct bld b;

    httpbld_init(&b, x);
    ev_open(&b, false);
    http_req(&b,
             "POST /upload HTTP/1.1\r\n" HTTP_FX_HDRS
             "Transfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n",
             true, 0);
    http_call(&b, LK_DIR_RECV, "5\r\nhello\r\n6\r\n world\r\n");
    expect(&b, LK_DIR_RECV, 'D', 5, 0);
    expect(&b, LK_DIR_RECV, 'D', 6, 0);
    http_call(&b, LK_DIR_RECV, "0\r\nX-Checksum: 0xdeadbeef\r\n\r\n");
    expect(&b, LK_DIR_RECV, 'E', 11, 0);
    http_resp(&b, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", "ok", 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "POST";
    b.x->obs_route = "/upload";
    b.x->obs_status = 200;
    b.x->obs_bytes_in = 11;
    b.x->obs_bytes_out = 2;
    b.x->obs_text = "/upload";
}

/* A chunked response delivered as three separate calls — Go's default shape
 * when it does not know the length in advance (М0 recon item 2), and the one
 * where the last body byte is far from the first: TTFB and duration differ. */
static void build_http_chunked_resp(struct fx *x)
{
    struct bld b;

    httpbld_init(&b, x);
    ev_open(&b, false);
    http_req(&b, "GET /stream HTTP/1.1\r\n" HTTP_FX_HDRS "\r\n", false, 0);

    {
        const char *head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                           "Transfer-Encoding: chunked\r\n\r\n";
        __u32 n = http_call(&b, LK_DIR_SEND, head);

        expect(&b, LK_DIR_SEND, 'S', n, 0);
    }
    for (int i = 0; i < 3; i++) {
        http_call(&b, LK_DIR_SEND, "4\r\nabcd\r\n");
        expect(&b, LK_DIR_SEND, 'D', 4, 0);
    }
    http_call(&b, LK_DIR_SEND, "0\r\n\r\n");
    expect(&b, LK_DIR_SEND, 'E', 12, 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "GET";
    b.x->obs_route = "/stream";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = 12;
    b.x->obs_text = "/stream";
}

/* Expect: 100-continue. The interim answer is 'I': it does not close the unit,
 * the final 200 does — and the unit is flagged, because the interval before the
 * body is a server round trip and not the client's upload time (РH5). */
static void build_http_continue(struct fx *x)
{
    struct bld b;
    static const char body[] = "0123456789abcdef";
    char head[256];
    __u32 n;

    httpbld_init(&b, x);
    ev_open(&b, false);
    snprintf(head, sizeof(head),
             "PUT /uploads/2026-08-12/report HTTP/1.1\r\n" HTTP_FX_HDRS
             "Expect: 100-continue\r\nContent-Length: %zu\r\n\r\n",
             sizeof(body) - 1);
    http_req(&b, head, true, 0);
    n = http_call(&b, LK_DIR_SEND, "HTTP/1.1 100 Continue\r\n\r\n");
    expect(&b, LK_DIR_SEND, 'I', n, 0);
    http_body(&b, LK_DIR_RECV, body);
    http_resp(&b, "HTTP/1.1 204 No Content\r\n\r\n", "", 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "PUT";
    /* Both a date and a word longer than the classifier's ceiling are ids by
     * РH7's rules; `/uploads` and the file name are not. */
    b.x->obs_route = "/uploads/{id}/report";
    b.x->obs_status = 204;
    b.x->obs_bytes_in = sizeof(body) - 1;
    b.x->obs_flags = LK_QO_EXPECT_CONT;
    b.x->obs_text = "/uploads/2026-08-12/report";
}

/* Four requests in one write and four responses in another: in-flight depth
 * above one (РH6). Every unit of the batch is flagged — none of them is
 * comparable with a standalone request, because the server's queue is in the
 * measurement. */
static void build_http_pipelined(struct fx *x)
{
    struct bld b;
    char w[2048];
    size_t off = 0;
    static const char *const paths[] = {"/a", "/b", "/c", "/d"};
    __u32 hn[4], rn;

    httpbld_init(&b, x);
    ev_open(&b, false);

    for (int i = 0; i < 4; i++) {
        int k =
            snprintf(w + off, sizeof(w) - off, "GET %s HTTP/1.1\r\n" HTTP_FX_HDRS "\r\n", paths[i]);

        hn[i] = (__u32)k;
        off += (size_t)k;
    }
    call(&b, LK_DIR_RECV, (const __u8 *)w, (__u32)off);
    for (int i = 0; i < 4; i++) {
        expect(&b, LK_DIR_RECV, 'R', hn[i], 0);
        expect(&b, LK_DIR_RECV, 'E', 0, 0);
    }

    off = 0;
    for (int i = 0; i < 4; i++) {
        int k = snprintf(w + off, sizeof(w) - off, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n%c",
                         'a' + i);

        off += (size_t)k;
    }
    rn = (__u32)(off / 4) - 1; /* the four heads are the same length */
    call(&b, LK_DIR_SEND, (const __u8 *)w, (__u32)off);
    for (int i = 0; i < 4; i++) {
        expect(&b, LK_DIR_SEND, 'S', rn, 0);
        expect(&b, LK_DIR_SEND, 'D', 1, 0);
        expect(&b, LK_DIR_SEND, 'E', 1, 0);
    }
    ev_close(&b);

    b.x->queries = 4;
    b.x->obs_op = "GET";
    b.x->obs_route = "/d";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = 1;
    b.x->obs_flags = LK_QO_PIPELINED;
    b.x->obs_text = "/d";
}

/* Fifty exchanges on one socket: the keep-alive case, where a framing error
 * anywhere would show up as a desynchronised remainder rather than as one bad
 * observation. Sequential requests are not pipelining and must not be flagged
 * as such. */
static void build_http_keepalive_50(struct fx *x)
{
    struct bld b;

    httpbld_init(&b, x);
    ev_open(&b, false);
    for (int i = 0; i < 50; i++) {
        http_req(&b, "GET /hello HTTP/1.1\r\n" HTTP_FX_HDRS "\r\n", false, 0);
        http_resp(&b, HTTP_FX_OK_HEAD, HTTP_FX_OK_BODY, 0);
    }
    ev_close(&b);

    b.x->queries = 50;
    b.x->obs_op = "GET";
    b.x->obs_route = "/hello";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = 13;
    b.x->obs_text = "/hello";
}

/* A 404: counted, given its own flag, and deliberately *not* an error — the
 * client asked for something that does not exist, the server did its job
 * (РH10). errors_sql stays at zero. */
static void build_http_404(struct fx *x)
{
    struct bld b;

    httpbld_init(&b, x);
    ev_open(&b, false);
    http_req(&b, "GET /nope HTTP/1.1\r\n" HTTP_FX_HDRS "\r\n", false, 0);
    http_resp(&b, "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\n", "not found", 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "GET";
    b.x->obs_route = "/nope";
    b.x->obs_status = 404;
    b.x->obs_bytes_out = 9;
    b.x->obs_flags = LK_QO_CLIENT_ERR;
    b.x->obs_text = "/nope";
}

/* A 500: the other half of РH10 — this one *is* an error, it ticks errors_sql
 * and it reaches latkit_http_errors_total under its exact code. */
static void build_http_500(struct fx *x)
{
    struct bld b;

    httpbld_init(&b, x);
    ev_open(&b, false);
    http_req(&b, "GET /boom HTTP/1.1\r\n" HTTP_FX_HDRS "\r\n", false, 0);
    http_resp(&b, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\n", "oops!", 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->errors_sql = 1;
    b.x->obs_op = "GET";
    b.x->obs_route = "/boom";
    b.x->obs_status = 500;
    b.x->obs_bytes_out = 5;
    b.x->obs_flags = LK_QO_ERROR;
    b.x->obs_text = "/boom";
}

/* A HEAD answered with a Content-Length describing a body that never comes,
 * followed by an ordinary GET on the same connection. Reading that length as a
 * body would swallow the next request whole: the GET being observed at all is
 * the assertion, and its 13 bytes are the proof the direction never drifted. */
static void build_http_head(struct fx *x)
{
    struct bld b;

    httpbld_init(&b, x);
    ev_open(&b, false);
    http_req(&b, "HEAD /hello HTTP/1.1\r\n" HTTP_FX_HDRS "\r\n", false, 0);
    http_resp(&b, HTTP_FX_OK_HEAD, "", 0);
    http_req(&b, "GET /hello HTTP/1.1\r\n" HTTP_FX_HDRS "\r\n", false, 0);
    http_resp(&b, HTTP_FX_OK_HEAD, HTTP_FX_OK_BODY, 0);
    ev_close(&b);

    b.x->queries = 2;
    b.x->obs_op = "GET";
    b.x->obs_route = "/hello";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = 13;
    b.x->obs_text = "/hello";
}

/* A websocket handshake. The handshake itself is an ordinary exchange and is
 * observed — the 101 is its status; only what follows is opaque, and the
 * connection is counted as a blind zone with its reason (РH4). */
static void build_http_upgrade_blind(struct fx *x)
{
    struct bld b;
    __u32 n;

    httpbld_init(&b, x);
    ev_open(&b, false);
    http_req(&b,
             "GET /ws HTTP/1.1\r\n" HTTP_FX_HDRS "Upgrade: websocket\r\nConnection: Upgrade\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
             false, 0);
    n = http_call(&b, LK_DIR_SEND,
                  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  "Connection: Upgrade\r\n"
                  "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n");
    expect(&b, LK_DIR_SEND, 'S', n, 0);
    expect(&b, LK_DIR_SEND, 'E', 0, 0);
    expect(&b, LK_DIR_SEND, '!', FX_HTTP_NOTE_BLIND_UPGRADE, 0);

    /* Opaque frames from here on: the connection is LK_CONN_IGNORE, so these
     * events are dropped before the framer ever sees them. */
    call(&b, LK_DIR_SEND, (const __u8 *)"\x81\x05hello", 7);
    call(&b, LK_DIR_RECV,
         (const __u8 *)"\x81\x85\x01\x02\x03\x04"
                       "abcde",
         11);
    ev_close(&b);

    b.x->queries = 1;
    b.x->blind_conns = 1;
    b.x->obs_op = "GET";
    b.x->obs_route = "/ws";
    b.x->obs_status = 101;
    b.x->obs_text = "/ws";
}

/* The HTTP/2 connection preface, by prior knowledge. Recognised, named and
 * counted — and with it goes gRPC (§8 of the plan). No observation is invented
 * out of HPACK bytes. */
static void build_http_h2_blind(struct fx *x)
{
    struct bld b;

    httpbld_init(&b, x);
    ev_open(&b, false);
    http_call(&b, LK_DIR_RECV, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    expect(&b, LK_DIR_RECV, '!', FX_HTTP_NOTE_BLIND_H2, 0);
    /* A SETTINGS frame and whatever follows: dropped, not framed. */
    call(&b, LK_DIR_RECV, (const __u8 *)"\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9);
    call(&b, LK_DIR_SEND, (const __u8 *)"\x00\x00\x00\x04\x01\x00\x00\x00\x00", 9);
    ev_close(&b);

    b.x->sessions = 0; /* no request head was ever parsed */
    b.x->sess_db = NULL;
    b.x->sess_user = NULL;
    b.x->blind_conns = 1;
}

/* A CONNECT tunnel: the exchange that sets it up is observed (method, status,
 * timings), the tunnel itself is a blind zone. There is no route — an
 * authority-form target is not a path, and reporting "/" for it would be a
 * label invented out of nothing. */
static void build_http_connect_blind(struct fx *x)
{
    struct bld b;
    __u32 n;

    httpbld_init(&b, x);
    ev_open(&b, false);
    http_req(&b,
             "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
             "User-Agent: " HTTP_FX_UA "\r\n\r\n",
             false, 0);
    n = http_call(&b, LK_DIR_SEND, "HTTP/1.1 200 Connection Established\r\n\r\n");
    expect(&b, LK_DIR_SEND, 'S', n, 0);
    expect(&b, LK_DIR_SEND, 'E', 0, 0);
    expect(&b, LK_DIR_SEND, '!', FX_HTTP_NOTE_BLIND_CONNECT, 0);
    call(&b, LK_DIR_RECV, (const __u8 *)"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00", 10);
    ev_close(&b);

    b.x->sess_db = "example.com:443";
    b.x->queries = 1;
    b.x->blind_conns = 1;
    b.x->obs_op = "CONNECT";
    /* An authority-form target is not a path: there is no route to template and
     * no target to report, and the observation says so instead of inventing a
     * "/" that would key a label. */
    b.x->obs_route = "";
    b.x->obs_status = 200;
    b.x->obs_flags = LK_QO_NO_TEXT;
    b.x->obs_text = "";
}

/* РH4's sendfile degradation: a megabyte promised by Content-Length, not one
 * byte of it on the socket, and then the status line of the next response. The
 * unit closes here with what was seen — a lower bound — and says so with
 * LK_QO_BODY_UNSEEN rather than reporting a body it never observed. */
static void build_http_sendfile_body_unseen(struct fx *x)
{
    struct bld b;
    __u32 n;

    httpbld_init(&b, x);
    ev_open(&b, false);
    http_req(&b, "GET /big.bin HTTP/1.1\r\n" HTTP_FX_HDRS "\r\n", false, 0);
    n = http_call(&b, LK_DIR_SEND,
                  "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                  "Content-Length: 1048576\r\n\r\n");
    expect(&b, LK_DIR_SEND, 'S', n, 0);

    http_req(&b, "GET /hello HTTP/1.1\r\n" HTTP_FX_HDRS "\r\n", false, 0);
    /* The next status line arrives where the body was owed: the note comes
     * first, then the empty 'E' that closes the abandoned message. */
    {
        char w[512];
        __u32 hn = (__u32)strlen(HTTP_FX_OK_HEAD);

        memcpy(w, HTTP_FX_OK_HEAD, hn);
        memcpy(w + hn, HTTP_FX_OK_BODY, 13);
        call(&b, LK_DIR_SEND, (const __u8 *)w, hn + 13);
        expect(&b, LK_DIR_SEND, '!', FX_HTTP_NOTE_BODY_UNSEEN, 0);
        expect(&b, LK_DIR_SEND, 'E', 0, 0);
        expect(&b, LK_DIR_SEND, 'S', hn, 0);
        expect(&b, LK_DIR_SEND, 'D', 13, 0);
        expect(&b, LK_DIR_SEND, 'E', 13, 0);
    }
    ev_close(&b);

    b.x->queries = 2;
    b.x->obs_op = "GET";
    b.x->obs_route = "/hello";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = 13;
    /* Marked pipelined, and rightly so: from the socket's side the second
     * request arrived while the first response was still owing a megabyte. The
     * client was not pipelining — it was waiting for bytes that went out
     * through sendfile — but an observer that claimed to know the difference
     * would be claiming to see the body it just admitted it cannot. */
    b.x->obs_flags = LK_QO_PIPELINED;
    b.x->obs_text = "/hello";
}

/* A header block bigger than the per-call capture budget (РH14): 4 KB of
 * cookie, 2 KB captured. This is the normal outcome for a fat header block, not
 * an error — the start line and the first fields come first, so the method and
 * the route survive and the observation is flagged as a prefix.
 *
 * The client writes the block in two calls, which is what the М0
 * `huge-head-cap2048` traces show curl doing and also what makes the
 * degradation visible where it happens: an under-captured call's tail is a hole
 * of known size, but it is detected lazily, when the *next* call on the
 * direction starts (Р9). Had the head been one write, the truncated 'R' would
 * surface only after the server had already answered. */
static void build_http_huge_head(struct fx *x)
{
    struct bld b;
    char head[4096];
    size_t off;

    httpbld_init(&b, x);
    ev_open(&b, false);

    off = (size_t)snprintf(head, sizeof(head),
                           "GET /profile/42 HTTP/1.1\r\n" HTTP_FX_HDRS "Cookie: session=");
    while (off < sizeof(head) - 2) {
        head[off] = (char)('A' + off % 26);
        off++;
    }
    memcpy(head + off, "\r\n", 2);
    off += 2;

    /* The call is honest about its length; the budget cut it at 2048 (Р9). */
    ev_data(&b, LK_DIR_RECV, (__u32)off, 0, (const __u8 *)head, 2048);
    /* The second write closes the first call: 2 KB of hole, so the block can
     * never be completed — what did arrive is published as a prefix, the note
     * names the reason, and the direction starts looking for an anchor. Its own
     * bytes are not one, and are dropped. */
    http_call(&b, LK_DIR_RECV, "X-Trace-Tag: last-header-line\r\n\r\n");
    expect(&b, LK_DIR_RECV, 'R', 2048, LK_MSG_BODY_TRUNC);
    expect(&b, LK_DIR_RECV, '!', FX_HTTP_NOTE_HEAD_HOLE, 0);
    http_resp(&b, HTTP_FX_OK_HEAD, HTTP_FX_OK_BODY, 0);

    /* The direction is scanning; the next request line is an anchor. */
    http_req(&b, "GET /hello HTTP/1.1\r\n" HTTP_FX_HDRS "\r\n", false, LK_MSG_AFTER_RESYNC);
    http_resp(&b, HTTP_FX_OK_HEAD, HTTP_FX_OK_BODY, 0);
    ev_close(&b);

    b.x->clean = false; /* the hole is the point of the fixture */
    b.x->resyncs = 1;
    b.x->queries = 2;
    b.x->obs_op = "GET";
    b.x->obs_route = "/hello";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = 13;
    b.x->obs_text = "/hello";
}

/* The agent attached mid-stream (synthetic OPEN, Р10): both directions start
 * dirty, in the middle of somebody else's response body. Neither is framed
 * until a textual anchor appears — and HTTP's are the strongest of the three
 * protocols, so recovery costs exactly one exchange. */
static void build_http_synthetic_midstream(struct fx *x)
{
    struct bld b;

    httpbld_init(&b, x);
    ev_open(&b, true); /* synthetic: both directions marked dirty */

    /* Mid-body debris, on both sides. Nothing here is a start line. */
    http_call(&b, LK_DIR_SEND, "...ody of a response we joined halfway through\r\n");
    http_call(&b, LK_DIR_RECV, "trailing bytes of a request body, equally opaque");

    http_req(&b, "GET /hello HTTP/1.1\r\n" HTTP_FX_HDRS "\r\n", false, LK_MSG_AFTER_RESYNC);
    http_resp(&b, HTTP_FX_OK_HEAD, HTTP_FX_OK_BODY, LK_MSG_AFTER_RESYNC);
    ev_close(&b);

    b.x->clean = false;
    b.x->resyncs = 2;
    b.x->queries = 1;
    b.x->obs_op = "GET";
    b.x->obs_route = "/hello";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = 13;
    b.x->obs_text = "/hello";
}

/* --- S3 wire helpers (PLAN-MINIO.md МS4) -----------------------------------
 * The same builders as the HTTP set — S3 *is* HTTP/1.1 and the framer is shared
 * byte for byte (РS1) — over MinIO's own header shapes, taken from the МS0
 * corpus rather than invented: the `Authorization` spelling minio-go writes (no
 * space after the comma), `x-amz-content-sha256` as the marker of an
 * `aws-chunked` upload (never `Content-Encoding`), `x-amz-request-id` on every
 * response, and `x-minio-error-code` on the one error that has no body to carry
 * a code. The point of a fixture here is not that HTTP framing works — the М8
 * set settles that — but that the *dialect* reads the same four things off it
 * every time: the operation, the bucket, the access key and the failure's name.
 *
 * Neither an object key nor a signature appears in any expectation below, and
 * that is checked rather than asserted: several of these fixtures carry keys
 * with characters a label may not contain, and the corpus-wide privacy check in
 * test_replay looks for them in the exposition. */

#define S3_FX_HOST   "minio.lktest:9000"
#define S3_FX_DOMAIN "minio.lktest" /* MINIO_DOMAIN, for the virtual-host form */
#define S3_FX_BUCKET "lkbucket"
#define S3_FX_AK     "lkroot"
#define S3_FX_UA     "MinIO (linux; amd64) minio-go/v7.0.70"
#define S3_FX_REQID  "185F3C0A9B2D4E71"
#define S3_FX_SIG    "5c1f7a0e0d3b4a2c9e8f7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928"
#define S3_FX_HOSTID "dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8"

/* The three fields every signed request carries. `X-Amz-Date` is here because
 * the head sizes the corpus measured (405..583 bytes) are made of these. */
#define S3_FX_HDRS                                                                                 \
    "Host: " S3_FX_HOST "\r\nUser-Agent: " S3_FX_UA "\r\nX-Amz-Date: 20260816T101112Z\r\n"

/* SigV4, in the spelling minio-go uses: no space after `aws4_request,`. Both
 * spellings are in the МS0 corpus and both are valid; this is the one the
 * client that generates most of MinIO's traffic writes. The dialect reads
 * `Credential=` and walks past `Signature=` without copying it (РS4). */
#define S3_FX_AUTH                                                                                 \
    "Authorization: AWS4-HMAC-SHA256 Credential=" S3_FX_AK                                         \
    "/20260816/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;"                 \
    "x-amz-date,Signature=" S3_FX_SIG "\r\n"

#define S3_FX_SHA256_EMPTY                                                                         \
    "X-Amz-Content-Sha256: "                                                                       \
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\n"

/* What MinIO puts on every response. The request id is the join key of the МS4
 * accuracy bench and reaches the span; the rest is here so the head is the size
 * a real one is. */
#define S3_FX_RESP_HDRS                                                                            \
    "Accept-Ranges: bytes\r\nServer: MinIO\r\nVary: Origin,Accept-Encoding\r\n"                    \
    "X-Amz-Id-2: " S3_FX_HOSTID "\r\nX-Amz-Request-Id: " S3_FX_REQID "\r\n"                        \
    "X-Content-Type-Options: nosniff\r\nDate: Sun, 16 Aug 2026 10:11:12 GMT\r\n"

/* The bounded prefix of a failing body the framer hands the dialect (РS5). The
 * value is spelled out rather than included from http.h for the same reason the
 * message characters are: a fixture that agreed with the framer by construction
 * would assert nothing. */
#define FX_S3_ERRB_MAX 256

/* An S3 error document, in MinIO's field order. `<Key>` and `<Resource>` sit
 * right after `<Code>` — which is the whole reason the prefix is bounded, read
 * once and never stored. */
static const char *s3_err_xml(char *buf, size_t cap, const char *code, const char *msg,
                              const char *key)
{
    snprintf(buf, cap,
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<Error><Code>%s</Code><Message>%s</Message>"
             "<Key>%s</Key><BucketName>" S3_FX_BUCKET "</BucketName>"
             "<Resource>/" S3_FX_BUCKET "/%s</Resource>"
             "<RequestId>" S3_FX_REQID "</RequestId>"
             "<HostId>" S3_FX_HOSTID "</HostId></Error>",
             code, msg, key, key);
    return buf;
}

/* n bytes of deterministic payload, NUL-terminated. The fixtures carry real
 * bodies so a Content-Length and what follows it can never disagree. */
static const char *s3_payload(char *buf, size_t n)
{
    for (size_t i = 0; i < n; i++)
        buf[i] = (char)('a' + i % 26);
    buf[n] = '\0';
    return buf;
}

static void s3bld_init(struct bld *b, struct fx *x)
{
    bld_init(b, x);
    b->tuple.dport = 9000; /* the port PLAN-MINIO.md writes; run_fixture forces ops */

    /* The session is the connection's opening statement (http_req.c): the first
     * request's bucket and access key, in the same two slots the base dialect
     * fills with a Host and nothing. Fixtures whose first request has neither
     * override both. */
    x->sessions = 1;
    x->sess_db = S3_FX_BUCKET;
    x->sess_user = S3_FX_AK;
    x->obs_kind = LK_Q_REQUEST;
    x->check_obj_bytes = true;
}

/* A response head alone in its call, so the body's first byte lands on a later
 * event and TTFB is a measurement rather than a zero (РH5). */
static void s3_resp_head(struct bld *b, const char *head)
{
    __u32 n = http_call(b, LK_DIR_SEND, head);

    expect(b, LK_DIR_SEND, 'S', n, 0);
}

/* A failing response, head and body in one call: 'S', then the bounded prefix
 * the dialect reads `<Code>` out of, then the body's own accounting. The prefix
 * is a message of its own precisely so that it is visible here — a body byte
 * reaching the handler is the one exception to "bodies are never read" and a
 * test set that could not see it would not be watching the exception. */
static void s3_resp_err(struct bld *b, const char *head, const char *body)
{
    char w[4096];
    __u32 hn = (__u32)strlen(head), bn = (__u32)strlen(body);

    memcpy(w, head, hn);
    memcpy(w + hn, body, bn);
    call(b, LK_DIR_SEND, (const __u8 *)w, hn + bn);
    expect(b, LK_DIR_SEND, 'S', hn, 0);
    expect(b, LK_DIR_SEND, 'X', bn > FX_S3_ERRB_MAX ? FX_S3_ERRB_MAX : bn, 0);
    expect(b, LK_DIR_SEND, 'D', bn, 0);
    expect(b, LK_DIR_SEND, 'E', bn, 0);
}

/* --- S3 fixtures ------------------------------------------------------------ */

/* The base case: one `GetObject`, path-style, signed, answered with a
 * Content-Length body of its own. Everything the dialect reports is present and
 * nothing is degraded — the row the other eleven are deviations from. */
static void build_s3_get(struct fx *x)
{
    struct bld b;
    char body[1025], head[512];

    s3bld_init(&b, x);
    ev_open(&b, false);
    http_req(&b,
             "GET /" S3_FX_BUCKET "/small.bin HTTP/1.1\r\n" S3_FX_HDRS S3_FX_SHA256_EMPTY S3_FX_AUTH
             "\r\n",
             false, 0);
    snprintf(head, sizeof(head),
             "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
             "Content-Type: application/octet-stream\r\nContent-Length: 1024\r\n"
             "ETag: \"9a0364b9e99bb480dd25e1f0284c8555\"\r\n\r\n");
    s3_resp_head(&b, head);
    http_body(&b, LK_DIR_SEND, s3_payload(body, 1024));
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "GET";
    b.x->obs_route = "GetObject";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = 1024;
    /* No `aws-chunked` framing to discount, so the object's size is the wire's:
     * the assertion is that the two agree, not that one was computed (РS6). */
    b.x->obs_obj_bytes = 1024;
    b.x->obs_err_name = "";
    b.x->obs_text = "/" S3_FX_BUCKET "/small.bin";
}

/* `PutObject` with an ordinary Content-Length body — the aws-cli / boto3 shape,
 * where the two byte counts agree by arithmetic. Uploaded in its own call, so
 * the client's transfer is an interval the upload family can hold (РH5). */
static void build_s3_put(struct fx *x)
{
    struct bld b;
    char body[8193], head[640];

    s3bld_init(&b, x);
    ev_open(&b, false);
    snprintf(head, sizeof(head),
             "PUT /" S3_FX_BUCKET "/report.bin HTTP/1.1\r\n" S3_FX_HDRS S3_FX_AUTH
             "Content-Length: 8192\r\nContent-Type: application/octet-stream\r\n"
             "X-Amz-Content-Sha256: UNSIGNED-PAYLOAD\r\n\r\n");
    http_req(&b, head, true, 0);
    http_body(&b, LK_DIR_RECV, s3_payload(body, 8192));
    http_resp(&b,
              "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
              "ETag: \"5d41402abc4b2a76b9719d911017c592\"\r\nContent-Length: 0\r\n\r\n",
              "", 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "PUT";
    b.x->obs_route = "PutObject";
    b.x->obs_status = 200;
    b.x->obs_bytes_in = 8192;
    b.x->obs_obj_bytes = 8192;
    b.x->obs_err_name = "";
    b.x->obs_text = "/" S3_FX_BUCKET "/report.bin";
}

/* РS6, the whole of it: an `aws-chunked` upload, where the wire count and the
 * object's size are different numbers and only one of them describes the data.
 * The framing is identified by `x-amz-content-sha256: STREAMING-…` and the size
 * by `x-amz-decoded-content-length` — never by `Content-Encoding`, which
 * minio-go does not send and which every MinIO-client upload would therefore
 * miss (МS0's first recorded finding).
 *
 * Note what the framer sees: an ordinary Content-Length body. The signed chunk
 * stream is HTTP payload, not HTTP chunking, so the 'D' count is the wire's and
 * the discount happens in the dialect — which is exactly the split the two
 * expectations below pin. */
static void build_s3_chunked_put(struct fx *x)
{
    struct bld b;
    /* One 16 KiB chunk and the closing one, signed: 21 + 64 + 2 bytes of chunk
     * header, the data, its CRLF, and an 86-byte final chunk — 175 bytes of
     * framing over 16384 of object. The corpus measures the same overhead at
     * scale (1050102 on the wire for 1048576 of object, 16 chunks), which is
     * where the ~0.13 % of §"Two sizes" comes from. */
    static const __u32 obj = 16384, wire = 16559;
    char head[768];
    char *body = malloc(wire + 1);

    s3bld_init(&b, x);
    ev_open(&b, false);
    snprintf(head, sizeof(head),
             "PUT /" S3_FX_BUCKET "/chunked.bin HTTP/1.1\r\n" S3_FX_HDRS S3_FX_AUTH
             "Content-Encoding: aws-chunked\r\n"
             "Content-Length: %u\r\nX-Amz-Decoded-Content-Length: %u\r\n"
             "X-Amz-Content-Sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n\r\n",
             wire, obj);
    http_req(&b, head, true, 0);
    /* The body's bytes are payload to the framer and are never parsed, so the
     * fixture carries a filler of the promised length rather than a hand-built
     * chunk chain: what is under test here is the arithmetic of two headers. */
    s3_payload(body, wire);
    /* Written in 8 KiB pieces, as a client does: the framer reports each call's
     * bytes with a 'D' and closes the body with an 'E' whose length is their
     * sum — the wire's, which is the number the dialect then has to discount. */
    for (__u32 off = 0; off < wire; off += 8192) {
        __u32 n = wire - off > 8192 ? 8192 : wire - off;

        call(&b, LK_DIR_RECV, (const __u8 *)body + off, n);
        expect(&b, LK_DIR_RECV, 'D', n, 0);
    }
    free(body);
    expect(&b, LK_DIR_RECV, 'E', wire, 0);
    http_resp(&b,
              "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
              "ETag: \"d41d8cd98f00b204e9800998ecf8427e-1\"\r\nContent-Length: 0\r\n\r\n",
              "", 0);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "PUT";
    b.x->obs_route = "PutObject";
    b.x->obs_status = 200;
    b.x->obs_bytes_in = wire; /* what crossed the socket */
    b.x->obs_obj_bytes = obj; /* what was stored */
    b.x->obs_err_name = "";
    b.x->obs_text = "/" S3_FX_BUCKET "/chunked.bin";
}

/* The four operations that share `?uploadId` and are told apart by the method
 * alone (МS0: "`?uploadId` alone selects four different operations"). Create,
 * two parts, complete — one connection, four observations, four distinct
 * operations, and the parts are the only two that reach the object-size
 * histogram. */
static void build_s3_multipart(struct fx *x)
{
    struct bld b;
    static const char *const upid = "ZDk3MGM5MzQtN2Y4Ni00YjE2LWE4MTgtM2M5ZmQ4MDkxYjRi";
    char head[768], body[4097], xml[512];

    s3bld_init(&b, x);
    ev_open(&b, false);

    snprintf(head, sizeof(head),
             "POST /" S3_FX_BUCKET
             "/big.bin?uploads= HTTP/1.1\r\n" S3_FX_HDRS S3_FX_AUTH S3_FX_SHA256_EMPTY
             "Content-Length: 0\r\n\r\n");
    http_req(&b, head, false, 0);
    snprintf(xml, sizeof(xml),
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<InitiateMultipartUploadResult><Bucket>" S3_FX_BUCKET "</Bucket>"
             "<Key>big.bin</Key><UploadId>%s</UploadId></InitiateMultipartUploadResult>",
             upid);
    snprintf(head, sizeof(head),
             "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
             "Content-Type: application/xml\r\nContent-Length: %zu\r\n\r\n",
             strlen(xml));
    http_resp(&b, head, xml, 0);

    for (int part = 1; part <= 2; part++) {
        snprintf(head, sizeof(head),
                 "PUT /" S3_FX_BUCKET "/big.bin?partNumber=%d&uploadId=%s "
                 "HTTP/1.1\r\n" S3_FX_HDRS S3_FX_AUTH
                 "Content-Length: 4096\r\nX-Amz-Content-Sha256: UNSIGNED-PAYLOAD\r\n\r\n",
                 part, upid);
        http_req(&b, head, true, 0);
        http_body(&b, LK_DIR_RECV, s3_payload(body, 4096));
        snprintf(head, sizeof(head),
                 "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
                 "ETag: \"7c4a8d09ca3762af61e59520943dc264\"\r\nContent-Length: 0\r\n\r\n");
        http_resp(&b, head, "", 0);
    }

    snprintf(head, sizeof(head),
             "POST /" S3_FX_BUCKET "/big.bin?uploadId=%s HTTP/1.1\r\n" S3_FX_HDRS S3_FX_AUTH
             "Content-Length: 234\r\nContent-Type: application/xml\r\n\r\n",
             upid);
    http_req(&b, head, true, 0);
    {
        /* The manifest: 234 bytes of XML naming the parts. A request body we do
         * not read, exactly like the key list of a DeleteObjects (§1). */
        char manifest[235];

        http_body(&b, LK_DIR_RECV, s3_payload(manifest, 234));
    }
    snprintf(xml, sizeof(xml),
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<CompleteMultipartUploadResult><Location>http://" S3_FX_HOST "/" S3_FX_BUCKET
             "/big.bin</Location><Bucket>" S3_FX_BUCKET "</Bucket><Key>big.bin</Key>"
             "<ETag>&#34;3858f62230ac3c915f300c664312c11f-2&#34;</ETag>"
             "</CompleteMultipartUploadResult>");
    snprintf(head, sizeof(head),
             "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
             "Content-Type: application/xml\r\nContent-Length: %zu\r\n\r\n",
             strlen(xml));
    http_resp(&b, head, xml, 0);
    ev_close(&b);

    b.x->queries = 4;
    b.x->obs_op = "POST";
    b.x->obs_route = "CompleteMultipartUpload";
    b.x->obs_status = 200;
    b.x->obs_bytes_in = 234;
    b.x->obs_bytes_out = (__u64)strlen(xml);
    /* The manifest is payload and is counted as bytes, but it is not an object:
     * the size the observation reports is the request body's, and МS2's rule
     * that only a data operation feeds the histogram is what keeps it out. */
    b.x->obs_obj_bytes = 234;
    b.x->obs_err_name = "";
    b.x->obs_text = "/" S3_FX_BUCKET "/big.bin?uploadId=ZDk3MGM5MzQtN2Y4Ni00YjE2LWE4MTgtM2M5ZmQ4"
                    "MDkxYjRi";
}

/* Two listings that are three different things to the classifier: a V2 listing
 * of a bucket, and a `ListBuckets` at service level where there is no bucket at
 * all. The empty dim slot is a distinct fact from a refused name (РS3) and the
 * exposition prints it as `-`.
 *
 * The V2 target also carries `max-keys`, whose *name* contains "key" — so the
 * redactor blanks its value in the raw target (РH12). Pinned rather than worked
 * around: substring matching is the documented rule, and a fixture that quietly
 * chose a key the rule misses would hide the one place an operator meets it. */
static void build_s3_list(struct fx *x)
{
    struct bld b;
    char head[768], xml[512];

    s3bld_init(&b, x);
    ev_open(&b, false);

    snprintf(head, sizeof(head),
             "GET /" S3_FX_BUCKET "?list-type=2&prefix=logs%%2F&delimiter=%%2F&max-keys=1000 "
             "HTTP/1.1\r\n" S3_FX_HDRS S3_FX_SHA256_EMPTY S3_FX_AUTH "\r\n");
    http_req(&b, head, false, 0);
    snprintf(xml, sizeof(xml),
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<ListBucketResult><Name>" S3_FX_BUCKET "</Name><Prefix>logs/</Prefix>"
             "<KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>"
             "<Contents><Key>logs/2026-08-16.log</Key><Size>4096</Size></Contents>"
             "</ListBucketResult>");
    snprintf(head, sizeof(head),
             "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
             "Content-Type: application/xml\r\nContent-Length: %zu\r\n\r\n",
             strlen(xml));
    http_resp(&b, head, xml, 0);

    http_req(&b, "GET / HTTP/1.1\r\n" S3_FX_HDRS S3_FX_SHA256_EMPTY S3_FX_AUTH "\r\n", false, 0);
    snprintf(xml, sizeof(xml),
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
             "<ListAllMyBucketsResult><Owner><ID>" S3_FX_AK "</ID></Owner><Buckets>"
             "<Bucket><Name>" S3_FX_BUCKET "</Name>"
             "<CreationDate>2026-08-16T09:00:00.000Z</CreationDate></Bucket>"
             "</Buckets></ListAllMyBucketsResult>");
    snprintf(head, sizeof(head),
             "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
             "Content-Type: application/xml\r\nContent-Length: %zu\r\n\r\n",
             strlen(xml));
    http_resp(&b, head, xml, 0);
    ev_close(&b);

    b.x->queries = 2;
    b.x->obs_op = "GET";
    b.x->obs_route = "ListBuckets";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = (__u64)strlen(xml);
    /* A listing's XML is payload and is counted in bytes, but it is not an
     * object and must not reach the size histogram — asserted in the metric
     * table, which is the only place the difference is visible. */
    b.x->obs_obj_bytes = (__u64)strlen(xml);
    b.x->obs_err_name = "";
    b.x->obs_text = "/";
}

/* РS5, the reason a body byte is read at all: two `404`s that are not the same
 * failure, and the two ways MinIO names them. The GET's error document carries
 * `<Code>NoSuchKey</Code>` — inside a prefix that also holds `<Key>` and
 * `<Resource>`, which is why the prefix is bounded and dropped. The HEAD has no
 * body to carry anything (`Content-Length: 0`), and MinIO fills the gap with
 * `X-Minio-Error-Code`; without it, boto3 reports such failures as the literal
 * string "404" and so would we. */
static void build_s3_error_404(struct fx *x)
{
    struct bld b;
    char xml[1024], head[768];

    s3bld_init(&b, x);
    ev_open(&b, false);

    http_req(&b,
             "GET /" S3_FX_BUCKET
             "/missing.bin HTTP/1.1\r\n" S3_FX_HDRS S3_FX_SHA256_EMPTY S3_FX_AUTH "\r\n",
             false, 0);
    s3_err_xml(xml, sizeof(xml), "NoSuchKey", "The specified key does not exist.", "missing.bin");
    snprintf(head, sizeof(head),
             "HTTP/1.1 404 Not Found\r\n" S3_FX_RESP_HDRS
             "Content-Type: application/xml\r\nContent-Length: %zu\r\n\r\n",
             strlen(xml));
    s3_resp_err(&b, head, xml);

    http_req(&b,
             "HEAD /" S3_FX_BUCKET
             "/missing.bin HTTP/1.1\r\n" S3_FX_HDRS S3_FX_SHA256_EMPTY S3_FX_AUTH "\r\n",
             false, 0);
    http_resp(&b,
              "HTTP/1.1 404 Not Found\r\n" S3_FX_RESP_HDRS
              "X-Minio-Error-Code: NoSuchKey\r\nX-Minio-Error-Desc: \"The specified key does "
              "not exist.\"\r\nContent-Length: 0\r\n\r\n",
              "", 0);
    ev_close(&b);

    b.x->queries = 2;
    b.x->obs_op = "HEAD";
    b.x->obs_route = "HeadObject";
    b.x->obs_status = 404;
    /* A 4xx is the client being told no, not the server failing: it is counted
     * apart and never reaches errors_sql (РH10). */
    b.x->obs_flags = LK_QO_CLIENT_ERR;
    b.x->obs_err_name = "NoSuchKey";
    b.x->obs_obj_bytes = 0;
    b.x->obs_text = "/" S3_FX_BUCKET "/missing.bin";
}

/* The other half of РS4: a request with a valid `Credential=` and a signature
 * that does not verify. The access key is still read and still labelled — "who
 * is hammering us with bad credentials" is the question this answers, and it
 * cannot be answered by a dialect that gave up on the request because the
 * server did. */
static void build_s3_error_403(struct fx *x)
{
    struct bld b;
    char xml[1024], head[768];

    s3bld_init(&b, x);
    ev_open(&b, false);
    http_req(&b,
             "GET /" S3_FX_BUCKET
             "/secret.bin HTTP/1.1\r\n" S3_FX_HDRS S3_FX_SHA256_EMPTY S3_FX_AUTH "\r\n",
             false, 0);
    s3_err_xml(xml, sizeof(xml), "SignatureDoesNotMatch",
               "The request signature we calculated does not match the signature you provided.",
               "secret.bin");
    snprintf(head, sizeof(head),
             "HTTP/1.1 403 Forbidden\r\n" S3_FX_RESP_HDRS
             "Content-Type: application/xml\r\nContent-Length: %zu\r\n\r\n",
             strlen(xml));
    s3_resp_err(&b, head, xml);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "GET";
    b.x->obs_route = "GetObject";
    b.x->obs_status = 403;
    b.x->obs_flags = LK_QO_CLIENT_ERR;
    b.x->obs_bytes_out = (__u64)strlen(xml);
    b.x->obs_obj_bytes = (__u64)strlen(xml);
    b.x->obs_err_name = "SignatureDoesNotMatch";
    b.x->obs_text = "/" S3_FX_BUCKET "/secret.bin";
}

/* A presigned URL: no `Authorization` header anywhere, the credential in the
 * query string, percent-encoded. The label is the same one a header would have
 * given (РS4) — and the signature beside it is blanked out of the raw target by
 * the redactor before it can reach a span (РH12), which is what the expected
 * text below spells out. */
static void build_s3_presigned(struct fx *x)
{
    struct bld b;
    char body[1025], head[768];

    s3bld_init(&b, x);
    ev_open(&b, false);
    snprintf(head, sizeof(head),
             "GET /" S3_FX_BUCKET "/small.bin?X-Amz-Algorithm=AWS4-HMAC-SHA256"
             "&X-Amz-Credential=" S3_FX_AK "%%2F20260816%%2Fus-east-1%%2Fs3%%2Faws4_request"
             "&X-Amz-Date=20260816T101112Z&X-Amz-Expires=3600"
             "&X-Amz-SignedHeaders=host&X-Amz-Signature=" S3_FX_SIG " HTTP/1.1\r\n" S3_FX_HDRS
             "\r\n");
    http_req(&b, head, false, 0);
    snprintf(head, sizeof(head),
             "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
             "Content-Type: application/octet-stream\r\nContent-Length: 1024\r\n\r\n");
    s3_resp_head(&b, head);
    http_body(&b, LK_DIR_SEND, s3_payload(body, 1024));
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "GET";
    b.x->obs_route = "GetObject";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = 1024;
    b.x->obs_obj_bytes = 1024;
    b.x->obs_err_name = "";
    /* `X-Amz-Credential` survives — it names the public half of the pair, which
     * is the label. `X-Amz-Signature` and `X-Amz-SignedHeaders` do not: both
     * contain "sig", and the rule is a substring match on the key. */
    b.x->obs_text = "/" S3_FX_BUCKET "/small.bin?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                    "&X-Amz-Credential=" S3_FX_AK "%2F20260816%2Fus-east-1%2Fs3%2Faws4_request"
                    "&X-Amz-Date=20260816T101112Z&X-Amz-Expires=3600"
                    "&X-Amz-SignedHeaders=***&X-Amz-Signature=***";
}

/* No credential carrier at all: the user slot stays empty and the exposition
 * prints `-`. Not an invented identity, and not the anonymous request folded in
 * with the signed ones. MinIO answers `403 AccessDenied` and closes the
 * connection without sending `Connection: close` (МS0's last finding), which is
 * why this fixture ends where it does. */
static void build_s3_anonymous(struct fx *x)
{
    struct bld b;
    char xml[1024], head[768];

    s3bld_init(&b, x);
    /* The first request carries no access key, so neither does the session. */
    x->sess_user = "";
    ev_open(&b, false);
    http_req(&b, "GET /" S3_FX_BUCKET "/small.bin HTTP/1.1\r\n" S3_FX_HDRS "\r\n", false, 0);
    s3_err_xml(xml, sizeof(xml), "AccessDenied", "Access Denied.", "small.bin");
    snprintf(head, sizeof(head),
             "HTTP/1.1 403 Forbidden\r\n" S3_FX_RESP_HDRS
             "Connection: close\r\nContent-Type: application/xml\r\nContent-Length: %zu\r\n\r\n",
             strlen(xml));
    s3_resp_err(&b, head, xml);
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "GET";
    b.x->obs_route = "GetObject";
    b.x->obs_status = 403;
    b.x->obs_flags = LK_QO_CLIENT_ERR;
    b.x->obs_bytes_out = (__u64)strlen(xml);
    b.x->obs_obj_bytes = (__u64)strlen(xml);
    b.x->obs_err_name = "AccessDenied";
    b.x->obs_text = "/" S3_FX_BUCKET "/small.bin";
}

/* MinIO talking to itself (РS2). Three shapes of it: the liveness probe a k8s
 * deployment runs all day, the admin API, and a peer call that a single node
 * answers `404 NoSuchBucket` — the case that decides the order of the checks,
 * because a bucket named `minio` is a perfectly legal name and reading the
 * first segment as one here would report a health check as an S3 operation.
 *
 * All three are observed and none of them is an operation: the exposition must
 * carry the internal counter and not one `latkit_s3_requests_total` series,
 * which is what the metric table asserts. On a distributed pool this is four
 * fifths of the port (МS0 recon item 6). */
static void build_s3_internal_path(struct fx *x)
{
    struct bld b;
    char xml[1024], head[768];
    static const char *const info = "{\"mode\":\"online\",\"region\":\"\",\"servers\":[]}";

    s3bld_init(&b, x);
    /* No bucket and no credential on the first request: both slots stay empty,
     * and the session says so rather than borrowing from a later one. */
    x->sess_db = "";
    x->sess_user = "";
    ev_open(&b, false);

    http_req(&b, "GET /minio/health/live HTTP/1.1\r\n" S3_FX_HDRS "\r\n", false, 0);
    http_resp(&b,
              "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
              "X-Minio-Deployment-Id: 7d5a1e2c-4b6f-4b2e-9a1d-0f3c2b1a4e5d\r\n"
              "Content-Length: 0\r\n\r\n",
              "", 0);

    http_req(
        &b, "GET /minio/admin/v3/info HTTP/1.1\r\n" S3_FX_HDRS S3_FX_SHA256_EMPTY S3_FX_AUTH "\r\n",
        false, 0);
    snprintf(head, sizeof(head),
             "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
             "Content-Type: application/json\r\nContent-Length: %zu\r\n\r\n",
             strlen(info));
    http_resp(&b, head, info, 0);

    http_req(&b,
             "GET /minio/storage/lkdisk/v51/readall?disk-id=x HTTP/1.1\r\n" S3_FX_HDRS
                 S3_FX_SHA256_EMPTY S3_FX_AUTH "\r\n",
             false, 0);
    s3_err_xml(xml, sizeof(xml), "NoSuchBucket", "The specified bucket does not exist.", "minio");
    snprintf(head, sizeof(head),
             "HTTP/1.1 404 Not Found\r\n" S3_FX_RESP_HDRS
             "Content-Type: application/xml\r\nContent-Length: %zu\r\n\r\n",
             strlen(xml));
    s3_resp_err(&b, head, xml);
    ev_close(&b);

    b.x->queries = 3;
    b.x->obs_op = "GET";
    b.x->obs_route = "internal";
    b.x->obs_status = 404;
    /* Internal *and* a client error: the observation is emitted with everything
     * it knows and one bit saying it is not an S3 operation. What that bit costs
     * it is every family but the counter — asserted in the metric table. */
    b.x->obs_flags = LK_QO_CLIENT_ERR | LK_QO_INTERNAL;
    b.x->obs_bytes_out = (__u64)strlen(xml);
    b.x->obs_obj_bytes = (__u64)strlen(xml);
    b.x->obs_err_name = "NoSuchBucket";
    b.x->obs_text = "/minio/storage/lkdisk/v51/readall?disk-id=x";
}

/* Virtual-host-style addressing (РS3): the bucket is the leading label of the
 * Host and the *whole* path is the key. Read path-style, `GET /small.bin` would
 * be a listing of a bucket called `small.bin` — which is why the form is a
 * decision made once, where the evidence is, and why it needs `--s3-domain`:
 * MinIO itself refuses this form unless MINIO_DOMAIN is set, so an agent that
 * guessed would be guessing about a server-side setting it cannot see. */
static void build_s3_vhost_style(struct fx *x)
{
    struct bld b;
    char body[1025], head[768];

    s3bld_init(&b, x);
    ev_open(&b, false);
    snprintf(head, sizeof(head),
             "GET /small.bin HTTP/1.1\r\nHost: " S3_FX_BUCKET "." S3_FX_HOST
             "\r\nUser-Agent: " S3_FX_UA
             "\r\nX-Amz-Date: 20260816T101112Z\r\n" S3_FX_SHA256_EMPTY S3_FX_AUTH "\r\n");
    http_req(&b, head, false, 0);
    snprintf(head, sizeof(head),
             "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
             "Content-Type: application/octet-stream\r\nContent-Length: 1024\r\n\r\n");
    s3_resp_head(&b, head);
    http_body(&b, LK_DIR_SEND, s3_payload(body, 1024));
    ev_close(&b);

    b.x->queries = 1;
    b.x->obs_op = "GET";
    b.x->obs_route = "GetObject";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = 1024;
    b.x->obs_obj_bytes = 1024;
    b.x->obs_err_name = "";
    b.x->obs_text = "/small.bin";
}

/* The agent attached mid-stream (Р10): both directions start dirty, in the
 * middle of somebody else's object body — which on this port is the common
 * case, since an object body is most of what the socket carries. Neither
 * direction is framed until a start line appears, and the debris below is
 * deliberately full of things that are nearly one. */
static void build_s3_synthetic_midstream(struct fx *x)
{
    struct bld b;
    char body[1025], head[768];

    s3bld_init(&b, x);
    ev_open(&b, true);
    http_call(&b, LK_DIR_SEND, "...the tail of an object body we joined halfway through\r\n");
    http_call(&b, LK_DIR_RECV, "8000\r\nchunk-signature=0f3c2b1a4e5d6c7b8a99\r\nopaque payload");

    http_req(&b,
             "GET /" S3_FX_BUCKET "/small.bin HTTP/1.1\r\n" S3_FX_HDRS S3_FX_SHA256_EMPTY S3_FX_AUTH
             "\r\n",
             false, LK_MSG_AFTER_RESYNC);
    snprintf(head, sizeof(head),
             "HTTP/1.1 200 OK\r\n" S3_FX_RESP_HDRS
             "Content-Type: application/octet-stream\r\nContent-Length: 1024\r\n\r\n");
    {
        __u32 n = http_call(&b, LK_DIR_SEND, head);

        expect(&b, LK_DIR_SEND, 'S', n, LK_MSG_AFTER_RESYNC);
    }
    http_body(&b, LK_DIR_SEND, s3_payload(body, 1024));
    ev_close(&b);

    b.x->clean = false;
    b.x->resyncs = 2;
    b.x->queries = 1;
    b.x->obs_op = "GET";
    b.x->obs_route = "GetObject";
    b.x->obs_status = 200;
    b.x->obs_bytes_out = 1024;
    b.x->obs_obj_bytes = 1024;
    b.x->obs_err_name = "";
    b.x->obs_text = "/" S3_FX_BUCKET "/small.bin";
}

/* --- Redis / RESP wire helpers (PLAN-REDIS.md МR8) --------------------------
 * The fifth fixture set, and the first that is not made of text lines. A RESP
 * value is typed, length-prefixed and nested, and the framer publishes one
 * message per **top-level value** (РR2) — so what a fixture has to be able to
 * say is not "this line" or "this packet" but "these values arrived in this
 * syscall", which is what struct rbatch below is.
 *
 * The batch is the shape rather than the value because **the batch is the thing
 * Redis does differently** (РR3): a pipeline of three commands is one write(2)
 * and three messages, the depth of that batch is itself an observation, and a
 * set that could only describe one value per call could not describe the normal
 * mode of every client library МR0 measured.
 *
 * No builder here asks the framer what it thinks. Every length below is the
 * arithmetic of the bytes the builder laid down, and every label is what
 * РR4–РR7 say the identity, the database, the user and the failure of that
 * exchange are; the type bytes are spelled as characters for the same reason the
 * HTTP set spells its own — a fixture that agreed with the code by construction
 * would assert nothing. */

#define FX_REDIS_MAX_VALS 8
#define FX_REDIS_BUF      1024

/* The `i` of redis.h: an inline command carries no RESP type byte, so the
 * framer gives it a synthetic one. Written out here, not included. */
#define FX_REDIS_MSG_INLINE 'i'

/* One syscall's worth of RESP, and the messages it has to become. */
struct rbatch {
    struct bld *b;
    char buf[FX_REDIS_BUF];
    __u32 n;
    __u32 len[FX_REDIS_MAX_VALS]; /* each value's whole size on the wire */
    char type[FX_REDIS_MAX_VALS]; /* ... and the type it is published under */
    __u32 nv;
};

static void rb_init(struct rbatch *rb, struct bld *b)
{
    memset(rb, 0, sizeof(*rb));
    rb->b = b;
}

/* Bytes that are not a value: the blank line an idle `telnet` or a healthcheck
 * script sends, which the server answers with nothing — so it must become no
 * message either, or the unit queue would wait for a reply nobody owes. */
static void rb_bytes(struct rbatch *rb, const char *s)
{
    __u32 n = (__u32)strlen(s);

    memcpy(rb->buf + rb->n, s, n);
    rb->n += n;
}

static void rb_open(struct rbatch *rb, char type)
{
    rb->type[rb->nv] = type;
    rb->len[rb->nv] = rb->n;
}

static void rb_close(struct rbatch *rb)
{
    rb->len[rb->nv] = rb->n - rb->len[rb->nv];
    rb->nv++;
}

/* A literal RESP value, written as it goes on the wire; its type is its first
 * byte, because on this protocol the dictionary is the protocol's own. */
static void rb_val(struct rbatch *rb, const char *s)
{
    rb_open(rb, s[0]);
    rb_bytes(rb, s);
    rb_close(rb);
}

/* An inline command — `PING\r\n` from telnet or a TCP probe. The raw line,
 * terminator included, is both the message's length and its body. */
static void rb_inline(struct rbatch *rb, const char *line)
{
    rb_open(rb, FX_REDIS_MSG_INLINE);
    rb_bytes(rb, line);
    rb_close(rb);
}

/* A command as a client writes it: an array of bulk strings, NULL-terminated
 * argument list. */
static void rb_cmd(struct rbatch *rb, ...)
{
    va_list ap;
    const char *a;
    char head[24];
    unsigned argc = 0;

    va_start(ap, rb);
    while ((a = va_arg(ap, const char *)) != NULL)
        argc++;
    va_end(ap);

    rb_open(rb, '*');
    snprintf(head, sizeof(head), "*%u\r\n", argc);
    rb_bytes(rb, head);
    va_start(ap, rb);
    while ((a = va_arg(ap, const char *)) != NULL) {
        snprintf(head, sizeof(head), "$%u\r\n", (unsigned)strlen(a));
        rb_bytes(rb, head);
        rb_bytes(rb, a);
        rb_bytes(rb, "\r\n");
    }
    va_end(ap);
    rb_close(rb);
}

/* The batch, as one captured call: every value in it becomes a message of its
 * own, in order. `flags` belongs to the first of them — LK_MSG_AFTER_RESYNC is
 * a statement about where framing resumed, and it resumes once. */
static void rb_send(struct rbatch *rb, enum lk_dir dir, __u16 flags)
{
    call(rb->b, dir, (const __u8 *)rb->buf, rb->n);
    for (__u32 i = 0; i < rb->nv; i++)
        expect(rb->b, dir, rb->type[i], rb->len[i], i ? 0 : flags);
    rb->n = 0;
    rb->nv = 0;
}

/* One command, alone in its call: the shape a client without a pipeline
 * produces, and the shape of most of this set. */
static void rb_send_cmd(struct rbatch *rb)
{
    rb_send(rb, LK_DIR_RECV, 0);
}

/* A reply, alone in its call — which is what makes a command's duration an
 * interval between two events rather than a zero. */
static void rb_reply(struct rbatch *rb, const char *v)
{
    rb_val(rb, v);
    rb_send(rb, LK_DIR_SEND, 0);
}

static void redisbld_init(struct bld *b, struct fx *x)
{
    bld_init(b, x);
    b->tuple.dport = 6379; /* the port РR1 writes; run_fixture forces the ops */

    /* No session on any redis fixture: RESP has no handshake to hang one on.
     * The database and the ACL user are connection state that moves mid-stream
     * (РR5/РR6) — a `SELECT` an hour in changes the label and nothing else — so
     * they travel on every observation rather than being announced once. */
    x->sessions = 0;
    x->obs_kind = LK_Q_COMMAND;
    /* Carried by every Redis observation: a command's text is its verb *and its
     * arguments*, and the arguments are keys and values. The identity that
     * replaces it is an index into a closed table (РR4); МR6's span renders
     * `GET ?` from that index, and nothing anywhere rebuilds the text. */
    x->obs_flags = LK_QO_NO_TEXT;
}

/* --- Redis fixtures --------------------------------------------------------- */

/* The base row the other twelve are deviations from: two commands, two replies,
 * one connection, nothing degraded. Both identities come out of the table, both
 * labels are the defaults a fresh connection has by protocol (database 0, user
 * `default`), and the reply's size is a number the value families can carry. */
static void build_redis_get_set(struct fx *x)
{
    struct bld b;
    struct rbatch rb;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, false);

    rb_cmd(&rb, "SET", "lk:k1", "value1", NULL); /* 36 bytes */
    rb_send_cmd(&rb);
    rb_reply(&rb, "+OK\r\n");

    rb_cmd(&rb, "GET", "lk:k1", NULL); /* 24 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "$6\r\nvalue1\r\n"); /* 12 */
    ev_close(&b);

    b.x->queries = 2;
    b.x->obs_route = "GET";
    b.x->obs_bytes_in = 24;
    b.x->obs_bytes_out = 12;
    b.x->obs_err_name = "";
}

/* РR3, the whole of it: three commands in one write(2) and three replies in
 * one. Every unit is in flight while the next arrives, so all three are
 * pipelined, all three report a batch depth of 3 — and the identities are
 * exactly the identities the same three commands would have had alone, which is
 * the property that makes a pipelined dashboard comparable with an unpipelined
 * one. */
static void build_redis_pipeline(struct fx *x)
{
    struct bld b;
    struct rbatch rb;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, false);

    rb_cmd(&rb, "SET", "lk:a", "1", NULL); /* 30 */
    rb_cmd(&rb, "GET", "lk:a", NULL);      /* 23 */
    rb_cmd(&rb, "INCR", "lk:n", NULL);     /* 24 */
    rb_send(&rb, LK_DIR_RECV, 0);

    rb_val(&rb, "+OK\r\n");     /* 5 */
    rb_val(&rb, "$1\r\n1\r\n"); /* 7 */
    rb_val(&rb, ":1\r\n");      /* 4 */
    rb_send(&rb, LK_DIR_SEND, 0);
    ev_close(&b);

    b.x->queries = 3;
    b.x->obs_route = "INCR";
    b.x->obs_bytes_in = 24;
    b.x->obs_bytes_out = 4;
    b.x->obs_err_name = "";
    b.x->obs_flags = LK_QO_NO_TEXT | LK_QO_PIPELINED;
}

/* РR9: the transaction, and the two things inside it that are not what they
 * look like. The commands between `MULTI` and `EXEC` are answered `+QUEUED` in
 * microseconds — they are commands and are counted, and their duration means
 * nothing, so they carry LK_QO_QUEUED and reach no histogram. The work is the
 * `EXEC`, and the interval an application waited is `MULTI` … the reply to it,
 * which is what `latkit_txn_duration_seconds` already means for PG and MySQL. */
static void build_redis_multi(struct fx *x)
{
    struct bld b;
    struct rbatch rb;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, false);

    rb_cmd(&rb, "MULTI", NULL); /* 15 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "+OK\r\n");

    rb_cmd(&rb, "SET", "lk:t", "1", NULL); /* 30 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "+QUEUED\r\n"); /* 9 */

    rb_cmd(&rb, "INCR", "lk:n", NULL); /* 24 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "+QUEUED\r\n");

    rb_cmd(&rb, "EXEC", NULL); /* 14 */
    rb_send_cmd(&rb);
    /* The array the transaction returns: one reply per queued command, and the
     * only value on the connection that describes real work. */
    rb_reply(&rb, "*2\r\n+OK\r\n:1\r\n"); /* 13 */
    ev_close(&b);

    b.x->queries = 4;
    b.x->obs_route = "EXEC";
    b.x->obs_bytes_in = 14;
    b.x->obs_bytes_out = 13;
    b.x->obs_err_name = "";
}

/* РR7's first half: a failure has a *symbol*, and the sentence after it has a
 * key in it. All three errors here are real Redis wordings, and two of them
 * name something that may never become a label — the key `lk:k1` and the
 * command a client made up. The identity of the third is `other` for the same
 * reason: the table is closed, and a client cannot name a series by inventing a
 * verb. */
static void build_redis_error(struct fx *x)
{
    struct bld b;
    struct rbatch rb;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, false);

    rb_cmd(&rb, "FROBNICATE", "lk:k1", NULL); /* 32 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "-ERR unknown command 'FROBNICATE', with args beginning with: 'lk:k1'\r\n");

    rb_cmd(&rb, "LPUSH", "lk:str", "x", NULL); /* 34 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n");

    rb_cmd(&rb, "EVALSHA", "0f3c2b1a4e5d6c7b8a99e1d2c3b4a5f60718293a", "0", NULL); /* 71 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "-NOSCRIPT No matching script. Please use EVAL.\r\n"); /* 48 */
    ev_close(&b);

    b.x->queries = 3;
    b.x->errors_sql = 3;
    b.x->obs_route = "EVALSHA";
    b.x->obs_bytes_in = 71;
    b.x->obs_bytes_out = 48;
    b.x->obs_err_name = "NOSCRIPT";
    b.x->obs_flags = LK_QO_NO_TEXT | LK_QO_ERROR;
}

/* РR7's second half, and the reason it is a decision rather than a detail: a
 * `-MOVED` is an error reply and is not a failure. A resharding cluster answers
 * them continuously, and in `errors_total` they would paint a healthy cluster
 * red for ever — so they have a counter of their own and carry the client-error
 * flag rather than the error one. The `-CROSSSLOT` beside them is the control:
 * a real refusal, on the same connection, in the error family and in no
 * redirect. */
static void build_redis_moved(struct fx *x)
{
    struct bld b;
    struct rbatch rb;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, false);

    rb_cmd(&rb, "GET", "lk:foo", NULL); /* 25 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "-MOVED 12539 10.0.0.3:6379\r\n");

    rb_cmd(&rb, "MGET", "lk:a", "lk:b", NULL); /* 34 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "-CROSSSLOT Keys in request don't hash to the same slot\r\n");

    rb_cmd(&rb, "GET", "lk:bar", NULL); /* 25 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "-ASK 8000 10.0.0.4:6379\r\n"); /* 25 */
    ev_close(&b);

    b.x->queries = 3;
    b.x->errors_sql = 1; /* the CROSSSLOT, and only it */
    b.x->obs_route = "GET";
    b.x->obs_bytes_in = 25;
    b.x->obs_bytes_out = 25;
    b.x->obs_err_name = "ASK";
    b.x->obs_flags = LK_QO_NO_TEXT | LK_QO_CLIENT_ERR;
}

/* РR8, which is a condition of correctness and not an optimisation: a delivery
 * answers nobody. The two `message` values below are not replies to anything,
 * and a queue that let them close units would leave every later command on this
 * connection paired with the wrong answer — plausibly, and for ever. The
 * confirmations *are* replies, which is the distinction RESP2 offers no type
 * byte for and the subscribe state has to make. */
static void build_redis_pubsub(struct fx *x)
{
    struct bld b;
    struct rbatch rb;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, false);

    rb_cmd(&rb, "SUBSCRIBE", "lk:chan", NULL); /* 32 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "*3\r\n$9\r\nsubscribe\r\n$7\r\nlk:chan\r\n:1\r\n");

    /* Two deliveries, arriving on their own like any published message. */
    rb_reply(&rb, "*3\r\n$7\r\nmessage\r\n$7\r\nlk:chan\r\n$5\r\nhello\r\n");
    rb_reply(&rb, "*3\r\n$7\r\nmessage\r\n$7\r\nlk:chan\r\n$5\r\nworld\r\n");

    rb_cmd(&rb, "UNSUBSCRIBE", "lk:chan", NULL); /* 35 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "*3\r\n$11\r\nunsubscribe\r\n$7\r\nlk:chan\r\n:0\r\n"); /* 39 */
    ev_close(&b);

    b.x->queries = 2; /* the two commands, and neither delivery */
    b.x->pushes = 2;
    b.x->obs_route = "UNSUBSCRIBE";
    b.x->obs_bytes_in = 35;
    b.x->obs_bytes_out = 39;
    b.x->obs_err_name = "";
}

/* RESP3, which МR0 measured being the default of two of the five client
 * libraries in scope — so this is a main path, not an exotic one. Four of the
 * types RESP2 does not have are here (`%` map, `>` push, `,` double, `_` null),
 * and the push is the one that matters: with a type byte of its own it needs no
 * subscribe state at all, and an `invalidate` nobody asked for closes no unit. */
static void build_redis_resp3(struct fx *x)
{
    struct bld b;
    struct rbatch rb;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, false);

    rb_cmd(&rb, "HELLO", "3", NULL); /* 22 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "%3\r\n$6\r\nserver\r\n$5\r\nredis\r\n$5\r\nproto\r\n:3\r\n$2\r\nid\r\n:42\r\n");

    rb_cmd(&rb, "CLIENT", "TRACKING", "ON", NULL); /* 38 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "+OK\r\n");

    /* The invalidation: a value the server sends because a key it told us about
     * changed. Nobody asked, so nobody is answered. */
    rb_reply(&rb, ">2\r\n$10\r\ninvalidate\r\n*1\r\n$5\r\nlk:k1\r\n");

    rb_cmd(&rb, "GET", "lk:k1", NULL); /* 24 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "_\r\n"); /* the RESP3 null: a miss, and not an error */

    rb_cmd(&rb, "ZSCORE", "lk:z", "m", NULL); /* 33 */
    rb_send_cmd(&rb);
    rb_reply(&rb, ",3.14\r\n"); /* 7 */
    ev_close(&b);

    b.x->queries = 4;
    b.x->pushes = 1;
    b.x->obs_route = "ZSCORE";
    b.x->obs_bytes_in = 33;
    b.x->obs_bytes_out = 7;
    b.x->obs_err_name = "";
}

/* РR10: the wait the *client* chose. A `BLPOP key 0` that sits for three
 * seconds because nothing was pushed is not a slow server, and in the same
 * histogram as a `GET` it decides the p99 of the whole instance. Both blocking
 * commands here are measured — an application waiting is a fact about that
 * application — in a family where they cannot decide anything else.
 *
 * The two `XREAD`s are the refinement, and the only place in the whole track
 * where an argument is read at all: the same verb blocks or does not depending
 * on a keyword, so the bit cannot come from the name. */
static void build_redis_blpop(struct fx *x)
{
    struct bld b;
    struct rbatch rb;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, false);

    rb_cmd(&rb, "RPUSH", "lk:q", "v", NULL); /* 32 */
    rb_send_cmd(&rb);
    rb_reply(&rb, ":1\r\n");

    rb_cmd(&rb, "BLPOP", "lk:q", "0", NULL); /* 32 */
    rb_send_cmd(&rb);
    b.ts += 3ull * 1000000000ull; /* three seconds of somebody else's patience */
    rb_reply(&rb, "*2\r\n$4\r\nlk:q\r\n$1\r\nv\r\n");

    rb_cmd(&rb, "XREAD", "COUNT", "10", "STREAMS", "lk:s", "0", NULL); /* 64 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "*-1\r\n"); /* nothing to read, at once */

    rb_cmd(&rb, "XREAD", "BLOCK", "100", "STREAMS", "lk:s", "$", NULL); /* 65 */
    rb_send_cmd(&rb);
    b.ts += 100ull * 1000000ull;
    rb_reply(&rb, "*-1\r\n"); /* 5 */
    ev_close(&b);

    b.x->queries = 4;
    b.x->obs_route = "XREAD";
    b.x->obs_bytes_in = 65;
    b.x->obs_bytes_out = 5;
    b.x->obs_err_name = "";
    b.x->obs_flags = LK_QO_NO_TEXT | LK_QO_BLOCKING;
}

/* РR6: the ACL user, in both forms that carry one, and the rule that decides
 * when a label moves — **the reply, never the command**. `AUTH lkuser lkpass`
 * succeeds and the next command is lkuser's; `AUTH lkuser wrongpass` is
 * answered `-WRONGPASS` and changes nothing; `HELLO 3 AUTH lkother lkpass`
 * names a user in the middle of an argument list and moves it again.
 *
 * Two passwords are on this wire and neither is read by anything: the name is a
 * separate element of the array, which is why this is the one protocol where
 * the identity can be on by default (contrast РH12's opt-in base64). */
static void build_redis_auth_acl(struct fx *x)
{
    struct bld b;
    struct rbatch rb;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, false);

    rb_cmd(&rb, "AUTH", "lkuser", "lkpass", NULL); /* 38 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "+OK\r\n");

    rb_cmd(&rb, "GET", "lk:k1", NULL); /* 24 — the first command that is lkuser's */
    rb_send_cmd(&rb);
    rb_reply(&rb, "$2\r\nv1\r\n");

    rb_cmd(&rb, "AUTH", "lkuser", "wrongpass", NULL); /* 41 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "-WRONGPASS invalid username-password pair or user is disabled.\r\n");

    rb_cmd(&rb, "HELLO", "3", "AUTH", "lkother", "lkpass", NULL); /* 57 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "%2\r\n$6\r\nserver\r\n$5\r\nredis\r\n$5\r\nproto\r\n:3\r\n");

    rb_cmd(&rb, "ACL", "WHOAMI", NULL); /* 25 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "$7\r\nlkother\r\n"); /* 13 */
    ev_close(&b);

    b.x->queries = 5;
    b.x->errors_sql = 1; /* the refused AUTH */
    b.x->obs_route = "ACL|WHOAMI";
    b.x->obs_bytes_in = 25;
    b.x->obs_bytes_out = 13;
    b.x->obs_err_name = "";
}

/* РR5: the database is connection state, and the same rule decides it. `SELECT
 * 3` is itself observed in the database it was issued *from*; the command after
 * it is in the new one. `SELECT 99` is a database this deployment does not have
 * — a number our own validator accepts and the server refuses — and the
 * connection stays where it was, because the label moves on the reply. */
static void build_redis_select(struct fx *x)
{
    struct bld b;
    struct rbatch rb;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, false);

    rb_cmd(&rb, "SELECT", "3", NULL); /* 23, observed in db 0 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "+OK\r\n");

    rb_cmd(&rb, "SET", "lk:k", "v", NULL); /* 30, in db 3 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "+OK\r\n");

    rb_cmd(&rb, "SELECT", "99", NULL); /* 24 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "-ERR DB index is out of range\r\n");

    rb_cmd(&rb, "GET", "lk:k", NULL); /* 23, still in db 3 */
    rb_send_cmd(&rb);
    rb_reply(&rb, "$1\r\nv\r\n"); /* 7 */
    ev_close(&b);

    b.x->queries = 4;
    b.x->errors_sql = 1;
    b.x->obs_route = "GET";
    b.x->obs_bytes_in = 23;
    b.x->obs_bytes_out = 7;
    b.x->obs_err_name = "";
}

/* Risk 1 of the plan, and its mitigation, in one trace: a 64 KiB reply captured
 * at the per-port budget of РR13 (512 bytes) and completed **by arithmetic**.
 * The hole falls inside a bulk payload, whose length is on the wire, so nothing
 * is lost but the bytes: the value is published with its true size and a
 * truncated body, the direction never loses sync, and the command after it
 * frames as if nothing had happened.
 *
 * The shape is also Р9's: an under-captured call's tail is only known to exist
 * when the *next* call on that direction starts, so the big value is published
 * late — after the `PING` that follows it was already sent. */
static void build_redis_big_bulk_hole(struct fx *x)
{
    struct bld b;
    struct rbatch rb;
    static const __u32 payload = 65536;
    char head[512];
    __u32 total, cap = 512, hn;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, false);

    rb_cmd(&rb, "GET", "lk:big", NULL); /* 25 */
    rb_send_cmd(&rb);

    /* `$65536\r\n` + the payload + `\r\n` — 65546 bytes on the wire, of which
     * the budget let 512 through. */
    hn = (__u32)snprintf(head, sizeof(head), "$%u\r\n", payload);
    total = hn + payload + 2;
    for (__u32 i = hn; i < cap; i++)
        head[i] = (char)('a' + i % 26);
    ev_data(&b, LK_DIR_SEND, total, 0, (const __u8 *)head, cap);

    /* A command in the other direction: it does not close the server's call, so
     * nothing is published yet. */
    rb_cmd(&rb, "PING", NULL); /* 14 */
    rb_send_cmd(&rb);

    /* ... and now the server's next call, which does. The hole is 65034 bytes
     * of bulk payload and costs a body prefix, not a resync. */
    rb_val(&rb, "+PONG\r\n");
    call(&b, LK_DIR_SEND, (const __u8 *)rb.buf, rb.n);
    expect(&b, LK_DIR_SEND, '$', total, LK_MSG_BODY_TRUNC);
    expect(&b, LK_DIR_SEND, '+', 7, 0);
    rb.n = rb.nv = 0;
    ev_close(&b);

    b.x->queries = 2;
    b.x->obs_route = "PING";
    b.x->obs_bytes_in = 14;
    b.x->obs_bytes_out = 7;
    b.x->obs_err_name = "";
    /* Pipelined, and rightly so — the same reading as the HTTP sendfile
     * fixture's: from the socket's side the `PING` went out while the `GET` was
     * still owing 65 KB. The client was not pipelining, it was reading a large
     * reply; an observer that claimed to know the difference would be claiming
     * to have seen the bytes it just reported as a hole. */
    b.x->obs_flags = LK_QO_NO_TEXT | LK_QO_PIPELINED;
}

/* Inline commands: not RESP at all, and a command all the same — `PING\r\n`
 * from a load balancer's TCP probe or a healthcheck script is exactly the
 * measurement РR15 says must not be swept into "internal". The blank line in
 * the middle is the counter-case: the server answers it with nothing, so it
 * must produce no message and open no unit. */
static void build_redis_inline(struct fx *x)
{
    struct bld b;
    struct rbatch rb;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, false);

    rb_inline(&rb, "PING\r\n"); /* 6 */
    rb_send(&rb, LK_DIR_RECV, 0);
    rb_reply(&rb, "+PONG\r\n");

    rb_inline(&rb, "ECHO hello\r\n"); /* 12 */
    rb_send(&rb, LK_DIR_RECV, 0);
    rb_reply(&rb, "$5\r\nhello\r\n");

    /* Somebody pressed return. No message, no unit, no reply. */
    rb_bytes(&rb, "\r\n");
    rb_send(&rb, LK_DIR_RECV, 0);

    rb_cmd(&rb, "PING", NULL); /* 14 — the same command, spoken properly */
    rb_send_cmd(&rb);
    rb_reply(&rb, "+PONG\r\n"); /* 7 */
    ev_close(&b);

    b.x->queries = 3;
    b.x->obs_route = "PING";
    b.x->obs_bytes_in = 14;
    b.x->obs_bytes_out = 7;
    b.x->obs_err_name = "";
}

/* The agent attached to a connection that was already open — which on this
 * protocol is what *every* restart looks like, because a client library holds
 * its pool for days (МR7 measured the same thing through TLS). Both directions
 * start dirty in the middle of somebody else's value, and neither is framed
 * until an anchor arrives at a syscall boundary: on the frontend an array
 * header whose first element is a plausible bulk, on the backend a valid type
 * byte, which is all a stream of payload will ever allow.
 *
 * The labels are the point of the fixture as much as the resync is: this
 * connection's `SELECT` and `AUTH` happened before we were watching, so its
 * database and user are `?`. A `0` there would be indistinguishable from the
 * truth on a dashboard, which is the one thing it must not be (РR5). */
static void build_redis_synthetic_midstream(struct fx *x)
{
    struct bld b;
    struct rbatch rb;

    redisbld_init(&b, x);
    rb_init(&rb, &b);
    ev_open(&b, true);

    /* Mid-value debris on both sides. Neither piece is an anchor: the reply
     * fragment does not begin with a type byte, and the command fragment does
     * not begin with `*`. */
    rb_bytes(&rb, "alue of a large reply we joined halfway through\r\n");
    rb_send(&rb, LK_DIR_SEND, 0);
    rb_bytes(&rb, "lk:some-key\r\n$5\r\nvalue\r\n");
    rb_send(&rb, LK_DIR_RECV, 0);

    rb_cmd(&rb, "GET", "lk:k1", NULL); /* 24 — an anchor, at a call boundary */
    rb_send(&rb, LK_DIR_RECV, LK_MSG_AFTER_RESYNC);
    rb_val(&rb, "$2\r\nv1\r\n");
    rb_send(&rb, LK_DIR_SEND, LK_MSG_AFTER_RESYNC);

    /* And this exchange produces **no observation**, which is the second half
     * of the fixture. The two directions recover independently, so at the moment
     * the reply direction found its anchor there was a command in flight that it
     * had not been watching when it started — and "the oldest unanswered command"
     * is the only correspondence RESP offers (РR3). The queue is dropped rather
     * than paired on a guess: one unit into units_dropped_resync, and the first
     * honest measurement is the exchange after it. */
    rb_cmd(&rb, "GET", "lk:k2", NULL); /* 24 */
    rb_send_cmd(&rb);
    rb_val(&rb, "$2\r\nv2\r\n"); /* 8 */
    rb_send(&rb, LK_DIR_SEND, 0);
    ev_close(&b);

    b.x->resyncs = 2;
    b.x->queries = 1;
    b.x->obs_route = "GET";
    b.x->obs_bytes_in = 24;
    b.x->obs_bytes_out = 8;
    b.x->obs_err_name = "";
}

const struct fixture lk_fixtures[] = {
    {"simple_query", build_simple_query, NULL, NULL},
    {"error", build_error, NULL, NULL},
    {"multi_statement", build_multi_statement, NULL, NULL},
    {"cancel", build_cancel, NULL, NULL},
    {"extended", build_extended, NULL, NULL},
    {"prepared", build_prepared, NULL, NULL},
    {"pipeline_error", build_pipeline_error, NULL, NULL},
    {"bind_unknown", build_bind_unknown, NULL, NULL},
    {"copy_in", build_copy_in, NULL, NULL},
    {"copy_out", build_copy_out, NULL, NULL},
    {"session_gap", build_session_gap, NULL, NULL},
    {"ssl_plain", build_ssl_plain, NULL, NULL},
    {"ssl_tls", build_ssl_tls, NULL, NULL},
    {"synthetic_midsession", build_synthetic_midsession, NULL, NULL},
    /* MySQL mirror set (MYSQL.md М7): framed and parsed as mysql. */
    {"my_simple_query", build_my_simple_query, "mysql", NULL},
    {"my_error", build_my_error, "mysql", NULL},
    {"my_multi_statement", build_my_multi_statement, "mysql", NULL},
    {"my_prepared", build_my_prepared, "mysql", NULL},
    {"my_load_data", build_my_load_data, "mysql", NULL},
    {"my_cursor_fetch", build_my_cursor_fetch, "mysql", NULL},
    {"my_compressed", build_my_compressed, "mysql", NULL},
    {"my_ssl", build_my_ssl, "mysql", NULL},
    {"my_synthetic_midsession", build_my_synthetic_midsession, "mysql", NULL},
    /* HTTP set (PLAN-HTTP.md М8): framed and parsed as http. */
    {"http_get", build_http_get, "http", NULL},
    {"http_post", build_http_post, "http", NULL},
    {"http_chunked_req", build_http_chunked_req, "http", NULL},
    {"http_chunked_resp", build_http_chunked_resp, "http", NULL},
    {"http_continue", build_http_continue, "http", NULL},
    {"http_pipelined", build_http_pipelined, "http", NULL},
    {"http_keepalive_50", build_http_keepalive_50, "http", NULL},
    {"http_404", build_http_404, "http", NULL},
    {"http_500", build_http_500, "http", NULL},
    {"http_head", build_http_head, "http", NULL},
    {"http_upgrade_blind", build_http_upgrade_blind, "http", NULL},
    {"http_h2_blind", build_http_h2_blind, "http", NULL},
    {"http_connect_blind", build_http_connect_blind, "http", NULL},
    {"http_sendfile_body_unseen", build_http_sendfile_body_unseen, "http", NULL},
    {"http_huge_head", build_http_huge_head, "http", NULL},
    {"http_synthetic_midstream", build_http_synthetic_midstream, "http", NULL},
    /* S3 set (PLAN-MINIO.md МS4): the http framer with the s3 dialect on top —
     * the same registry entry `--port 9000=s3` installs. */
    {"s3_get", build_s3_get, "s3", NULL},
    {"s3_put", build_s3_put, "s3", NULL},
    {"s3_chunked_put", build_s3_chunked_put, "s3", NULL},
    {"s3_multipart", build_s3_multipart, "s3", NULL},
    {"s3_list", build_s3_list, "s3", NULL},
    {"s3_error_404", build_s3_error_404, "s3", NULL},
    {"s3_error_403", build_s3_error_403, "s3", NULL},
    {"s3_presigned", build_s3_presigned, "s3", NULL},
    {"s3_anonymous", build_s3_anonymous, "s3", NULL},
    {"s3_internal_path", build_s3_internal_path, "s3", NULL},
    {"s3_vhost_style", build_s3_vhost_style, "s3", S3_FX_DOMAIN},
    {"s3_synthetic_midstream", build_s3_synthetic_midstream, "s3", NULL},
    /* Redis set (PLAN-REDIS.md МR8): its own framer and its own handler — the
     * first entry in the table that shares neither with anything above it. */
    {"redis_get_set", build_redis_get_set, "redis", NULL},
    {"redis_pipeline", build_redis_pipeline, "redis", NULL},
    {"redis_multi", build_redis_multi, "redis", NULL},
    {"redis_error", build_redis_error, "redis", NULL},
    {"redis_moved", build_redis_moved, "redis", NULL},
    {"redis_pubsub", build_redis_pubsub, "redis", NULL},
    {"redis_resp3", build_redis_resp3, "redis", NULL},
    {"redis_blpop", build_redis_blpop, "redis", NULL},
    {"redis_auth_acl", build_redis_auth_acl, "redis", NULL},
    {"redis_select", build_redis_select, "redis", NULL},
    {"redis_big_bulk_hole", build_redis_big_bulk_hole, "redis", NULL},
    {"redis_inline", build_redis_inline, "redis", NULL},
    {"redis_synthetic_midstream", build_redis_synthetic_midstream, "redis", NULL},
};
const size_t lk_nfixtures = sizeof(lk_fixtures) / sizeof(lk_fixtures[0]);
