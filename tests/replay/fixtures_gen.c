// SPDX-License-Identifier: GPL-2.0
#include "fixtures_gen.h"

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

const struct fixture lk_fixtures[] = {
    {"simple_query", build_simple_query, NULL},
    {"error", build_error, NULL},
    {"multi_statement", build_multi_statement, NULL},
    {"cancel", build_cancel, NULL},
    {"extended", build_extended, NULL},
    {"prepared", build_prepared, NULL},
    {"pipeline_error", build_pipeline_error, NULL},
    {"bind_unknown", build_bind_unknown, NULL},
    {"copy_in", build_copy_in, NULL},
    {"copy_out", build_copy_out, NULL},
    {"session_gap", build_session_gap, NULL},
    {"ssl_plain", build_ssl_plain, NULL},
    {"ssl_tls", build_ssl_tls, NULL},
    {"synthetic_midsession", build_synthetic_midsession, NULL},
    /* MySQL mirror set (MYSQL.md М7): framed and parsed as mysql. */
    {"my_simple_query", build_my_simple_query, "mysql"},
    {"my_error", build_my_error, "mysql"},
    {"my_multi_statement", build_my_multi_statement, "mysql"},
    {"my_prepared", build_my_prepared, "mysql"},
    {"my_load_data", build_my_load_data, "mysql"},
    {"my_cursor_fetch", build_my_cursor_fetch, "mysql"},
    {"my_compressed", build_my_compressed, "mysql"},
    {"my_ssl", build_my_ssl, "mysql"},
    {"my_synthetic_midsession", build_my_synthetic_midsession, "mysql"},
};
const size_t lk_nfixtures = sizeof(lk_fixtures) / sizeof(lk_fixtures[0]);
