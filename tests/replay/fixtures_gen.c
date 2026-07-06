// SPDX-License-Identifier: GPL-2.0
#include "fixtures_gen.h"

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

        parse[pn++] = '\0'; /* unnamed statement */
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

    *p++ = 0;         /* overall format: text */
    p = be16(p, 1);   /* one column */
    p = be16(p, 0);   /* column format: text */
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
    {"simple_query", build_simple_query},
    {"extended", build_extended},
    {"prepared", build_prepared},
    {"pipeline_error", build_pipeline_error},
    {"bind_unknown", build_bind_unknown},
    {"copy_in", build_copy_in},
    {"copy_out", build_copy_out},
    {"session_gap", build_session_gap},
    {"ssl_plain", build_ssl_plain},
    {"ssl_tls", build_ssl_tls},
    {"synthetic_midsession", build_synthetic_midsession},
};
const size_t lk_nfixtures = sizeof(lk_fixtures) / sizeof(lk_fixtures[0]);
