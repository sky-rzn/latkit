// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the MySQL prepared-statement cache (MYSQL.md М3, my_prep.c).
 * The pg_prep matrix transplanted to the u32-keyed cache:
 *
 *   - PREPARE -> PREPARE-OK binds the pending text to the stmt_id; the
 *     param/column metadata (with pre-DEPRECATE EOFs) is skipped by count;
 *   - EXECUTE resolves its text through the cache; an unknown / failed /
 *     closed id is honest NO_TEXT;
 *   - a failed PREPARE (ERR) caches nothing;
 *   - COM_STMT_CLOSE drops the entry without a server reply — and, pipelined
 *     behind a live EXECUTE, first rescues the unit's reference;
 *   - id reuse after CLOSE re-binds the slot (generation bump);
 *   - cache overflow evicts the LRU entry (prep_evictions);
 *   - COM_RESET_CONNECTION empties the cache;
 *   - a budget-truncated PREPARE caches the prefix (LK_QO_TEXT_TRUNC);
 *   - a PREPARE-OK header cut by the capture budget drops the pending text
 *     without counting a parse error.
 */
#include <linux/types.h>
#include <stdio.h>
#include <string.h>

#include "conn_table.h"
#include "my.h" /* internal: struct my_conn — white-box assertions */
#include "proto.h"
#include "reassembly.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

struct rec {
    int nqueries;
    struct lk_query_obs last;
    char last_text[256];
};

static void rec_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                         const struct lk_query_obs *o)
{
    struct rec *r = ctx;

    (void)c;
    (void)s;
    r->nqueries++;
    r->last = *o;
    r->last_text[0] = '\0';
    if (o->text && o->text_len < sizeof(r->last_text)) {
        memcpy(r->last_text, o->text, o->text_len);
        r->last_text[o->text_len] = '\0';
    }
    r->last.text = NULL;
}

/* --- packet builders (the test_my_query set, trimmed) ---------------------- */

static void feed(const struct lk_msg_sink *sink, struct lk_conn *c, enum lk_dir dir, char type,
                 __u16 flags, const void *body, __u32 n, __u64 ts)
{
    struct lk_msg m = {
        .ts_ns = ts, .type = type, .flags = flags, .len = n, .body_cap = n, .body = body};

    sink->on_msg(sink->ctx, c, dir, &m);
}

static void cmd(const struct lk_msg_sink *sink, struct lk_conn *c, const void *body, __u32 n,
                __u64 ts)
{
    feed(sink, c, LK_DIR_RECV, (char)((const __u8 *)body)[0], 0, body, n, ts);
}

static void be(const struct lk_msg_sink *sink, struct lk_conn *c, const void *body, __u32 n,
               __u64 ts)
{
    feed(sink, c, LK_DIR_SEND, 0, 0, body, n, ts);
}

static void prepare(const struct lk_msg_sink *sink, struct lk_conn *c, const char *sql, __u64 ts)
{
    __u8 body[128];
    __u32 n = (__u32)strlen(sql);

    body[0] = MY_COM_STMT_PREPARE;
    memcpy(body + 1, sql, n);
    cmd(sink, c, body, n + 1, ts);
}

/* COM_STMT_PREPARE_OK for stmt_id, no parameters/columns (metadata handled
 * where a test needs it explicitly). */
static void prep_ok(const struct lk_msg_sink *sink, struct lk_conn *c, __u32 id, __u16 ncols,
                    __u16 nparams, __u64 ts)
{
    __u8 body[12] = {0x00,
                     (__u8)id,
                     (__u8)(id >> 8),
                     (__u8)(id >> 16),
                     (__u8)(id >> 24),
                     (__u8)ncols,
                     (__u8)(ncols >> 8),
                     (__u8)nparams,
                     (__u8)(nparams >> 8),
                     0,
                     0,
                     0};

    be(sink, c, body, sizeof(body), ts);
}

static void execute(const struct lk_msg_sink *sink, struct lk_conn *c, __u32 id, __u64 ts)
{
    __u8 body[10] = {MY_COM_STMT_EXECUTE,
                     (__u8)id,
                     (__u8)(id >> 8),
                     (__u8)(id >> 16),
                     (__u8)(id >> 24),
                     0,
                     1,
                     0,
                     0,
                     0};

    cmd(sink, c, body, sizeof(body), ts);
}

static void stmt_close(const struct lk_msg_sink *sink, struct lk_conn *c, __u32 id, __u64 ts)
{
    __u8 body[5] = {MY_COM_STMT_CLOSE, (__u8)id, (__u8)(id >> 8), (__u8)(id >> 16),
                    (__u8)(id >> 24)};

    cmd(sink, c, body, sizeof(body), ts);
}

static void be_ok(const struct lk_msg_sink *sink, struct lk_conn *c, __u8 affected, __u64 ts)
{
    __u8 body[7] = {0x00, affected, 0, 0x02, 0x00, 0, 0};

    be(sink, c, body, sizeof(body), ts);
}

static void be_err(const struct lk_msg_sink *sink, struct lk_conn *c, __u64 ts)
{
    static const __u8 body[] = {0xff, 0x64, 0x04, '#', '4', '2', '0', '0', '0'};

    be(sink, c, body, sizeof(body), ts);
}

static void handshake(const struct lk_msg_sink *sink, struct lk_conn *c, __u32 caps)
{
    __u8 body[64];
    __u32 n = 0;
    static const __u8 greet[] = {10, '8', '.', '4', 0};
    static const __u8 ok[] = {0x00, 0, 0, 0x02, 0x00, 0, 0};

    feed(sink, c, LK_DIR_SEND, 0, LK_MSG_STARTUP, greet, sizeof(greet), 10);
    body[n++] = (__u8)caps;
    body[n++] = (__u8)(caps >> 8);
    body[n++] = (__u8)(caps >> 16);
    body[n++] = (__u8)(caps >> 24);
    memset(body + n, 0, 4 + 1 + 19 + 4);
    n += 28;
    memcpy(body + n, "u", 2);
    n += 2;
    body[n++] = 0;
    feed(sink, c, LK_DIR_RECV, 0, LK_MSG_STARTUP, body, n, 11);
    feed(sink, c, LK_DIR_SEND, 0, LK_MSG_STARTUP, ok, sizeof(ok), 12);
}

#define CAPS (MY_CAP_MYSQL | MY_CAP_PROTOCOL_41 | MY_CAP_DEPRECATE_EOF)

#define SETUP(caps)                                                                                \
    struct rec r = {0};                                                                            \
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};                               \
    struct lk_proto *p = lk_proto_my_new(&qs);                                                     \
    const struct lk_msg_sink *sink = lk_proto_sink(p);                                             \
    struct lk_conn c = {0};                                                                        \
    CHECK(p);                                                                                      \
    handshake(sink, &c, caps)

#define TEARDOWN()                                                                                 \
    do {                                                                                           \
        sink->on_conn_close(sink->ctx, &c);                                                        \
        lk_proto_free(p);                                                                          \
    } while (0)

/* --- tests ----------------------------------------------------------------- */

/* The happy path: prepare, execute twice, text resolved both times. */
static int test_prepare_execute(void)
{
    SETUP(CAPS);

    prepare(sink, &c, "SELECT * FROM t WHERE id = ?", 1000);
    prep_ok(sink, &c, 1, 0, 0, 1010);
    execute(sink, &c, 1, 2000);
    be_ok(sink, &c, 1, 2010);
    CHECK(r.nqueries == 1);
    CHECK(r.last.kind == LK_Q_EXTENDED);
    CHECK(strcmp(r.last_text, "SELECT * FROM t WHERE id = ?") == 0);
    CHECK(!(r.last.flags & (LK_QO_NO_TEXT | LK_QO_TEXT_TRUNC)));

    execute(sink, &c, 1, 3000);
    be_ok(sink, &c, 1, 3010);
    CHECK(r.nqueries == 2);
    CHECK(strcmp(r.last_text, "SELECT * FROM t WHERE id = ?") == 0);

    TEARDOWN();
    printf("ok prepare-execute\n");
    return 0;
}

/* Pre-DEPRECATE metadata: param defs, EOF, column defs, EOF — skipped by the
 * counts; the machine is coherent for the next exchange. */
static int test_prepare_metadata_old(void)
{
    SETUP(CAPS & ~MY_CAP_DEPRECATE_EOF);
    static const __u8 def[] = {3, 'd', 'e', 'f', 0};
    static const __u8 eof[] = {0xfe, 0, 0, 0, 0};

    prepare(sink, &c, "SELECT a, b FROM t WHERE id = ?", 1000);
    prep_ok(sink, &c, 9, 2, 1, 1010); /* 2 columns, 1 parameter */
    be(sink, &c, def, sizeof(def), 1011);
    be(sink, &c, eof, sizeof(eof), 1012); /* params EOF: not counted */
    be(sink, &c, def, sizeof(def), 1013);
    be(sink, &c, def, sizeof(def), 1014);
    be(sink, &c, eof, sizeof(eof), 1015); /* columns EOF */

    execute(sink, &c, 9, 2000);
    be_ok(sink, &c, 0, 2010);
    CHECK(r.nqueries == 1);
    CHECK(strcmp(r.last_text, "SELECT a, b FROM t WHERE id = ?") == 0);

    TEARDOWN();
    printf("ok prepare-metadata-old\n");
    return 0;
}

/* A failed prepare caches nothing; executing an unknown id is NO_TEXT. */
static int test_prepare_err(void)
{
    SETUP(CAPS);

    prepare(sink, &c, "SELECT broken(", 1000);
    be_err(sink, &c, 1010);
    CHECK(r.nqueries == 0); /* a failed prepare is not an observation */

    execute(sink, &c, 5, 2000); /* the id the server never granted */
    be_err(sink, &c, 2010);
    CHECK(r.nqueries == 1);
    CHECK(r.last.flags & LK_QO_NO_TEXT);
    CHECK(r.last.flags & LK_QO_ERROR);

    TEARDOWN();
    printf("ok prepare-err\n");
    return 0;
}

/* CLOSE drops the entry with no reply; the very next command still parses.
 * A CLOSE pipelined behind a live EXECUTE rescues the unit's text first. */
static int test_close_and_rescue(void)
{
    SETUP(CAPS);

    prepare(sink, &c, "SELECT rescue_me FROM t", 1000);
    prep_ok(sink, &c, 3, 0, 0, 1010);

    /* EXECUTE opens the unit, CLOSE lands before the reply (fire-and-forget):
     * the unit's cache reference must be rescued into its own copy. */
    execute(sink, &c, 3, 2000);
    stmt_close(sink, &c, 3, 2001);
    CHECK(lk_proto_stats(p)->units_dropped_resync == 0); /* no discipline hit */
    be_ok(sink, &c, 1, 2010);
    CHECK(r.nqueries == 1);
    CHECK(strcmp(r.last_text, "SELECT rescue_me FROM t") == 0);

    /* The id is gone from the cache now. */
    execute(sink, &c, 3, 3000);
    be_ok(sink, &c, 1, 3010);
    CHECK(r.nqueries == 2);
    CHECK(r.last.flags & LK_QO_NO_TEXT);

    TEARDOWN();
    printf("ok close-and-rescue\n");
    return 0;
}

/* The server reuses ids after CLOSE: a re-appearing id rebinds its slot. */
static int test_id_reuse(void)
{
    SETUP(CAPS);

    prepare(sink, &c, "SELECT old", 1000);
    prep_ok(sink, &c, 1, 0, 0, 1010);
    stmt_close(sink, &c, 1, 1020);
    prepare(sink, &c, "SELECT new", 2000);
    prep_ok(sink, &c, 1, 0, 0, 2010);

    execute(sink, &c, 1, 3000);
    be_ok(sink, &c, 0, 3010);
    CHECK(r.nqueries == 1);
    CHECK(strcmp(r.last_text, "SELECT new") == 0);

    TEARDOWN();
    printf("ok id-reuse\n");
    return 0;
}

/* Overflow: LK_MY_PREP_CACHE + 1 statements evict the LRU; the evicted id
 * turns NO_TEXT, a surviving one still resolves. */
static int test_eviction(void)
{
    SETUP(CAPS);
    char sql[32];

    for (unsigned i = 0; i < LK_MY_PREP_CACHE + 1; i++) {
        snprintf(sql, sizeof(sql), "SELECT %u", i);
        prepare(sink, &c, sql, 1000 + i * 10);
        prep_ok(sink, &c, 100 + i, 0, 0, 1005 + i * 10);
    }
    CHECK(lk_proto_stats(p)->prep_evictions == 1);

    execute(sink, &c, 100, 900000); /* the first id: LRU-evicted */
    be_ok(sink, &c, 0, 900010);
    CHECK(r.nqueries == 1 && (r.last.flags & LK_QO_NO_TEXT));

    execute(sink, &c, 100 + LK_MY_PREP_CACHE, 900100); /* the newest survives */
    be_ok(sink, &c, 0, 900110);
    CHECK(r.nqueries == 2);
    CHECK(strcmp(r.last_text, "SELECT 256") == 0);

    TEARDOWN();
    printf("ok eviction\n");
    return 0;
}

/* COM_RESET_CONNECTION: the server forgets every statement of the session. */
static int test_reset_connection(void)
{
    SETUP(CAPS);
    static const __u8 reset[] = {MY_COM_RESET_CONNECTION};

    prepare(sink, &c, "SELECT kept", 1000);
    prep_ok(sink, &c, 2, 0, 0, 1010);
    cmd(sink, &c, reset, sizeof(reset), 2000);
    be_ok(sink, &c, 0, 2010);

    execute(sink, &c, 2, 3000);
    be_ok(sink, &c, 0, 3010);
    CHECK(r.nqueries == 1);
    CHECK(r.last.flags & LK_QO_NO_TEXT);

    TEARDOWN();
    printf("ok reset-connection\n");
    return 0;
}

/* A budget-truncated PREPARE caches the prefix, flagged on the execute. */
static int test_prepare_trunc(void)
{
    SETUP(CAPS);
    static const char sql[] = "SELECT a_very_long_text FROM t";
    __u8 body[64];
    struct lk_msg m = {
        .ts_ns = 1000,
        .type = MY_COM_STMT_PREPARE,
        .flags = LK_MSG_BODY_TRUNC,
        .len = 1 + (__u32)strlen(sql),
        .body_cap = 9, /* command byte + "SELECT a" */
        .body = body,
    };

    body[0] = MY_COM_STMT_PREPARE;
    memcpy(body + 1, sql, strlen(sql));
    sink->on_msg(sink->ctx, &c, LK_DIR_RECV, &m);
    prep_ok(sink, &c, 4, 0, 0, 1010);

    execute(sink, &c, 4, 2000);
    be_ok(sink, &c, 0, 2010);
    CHECK(r.nqueries == 1);
    CHECK(r.last.flags & LK_QO_TEXT_TRUNC);
    CHECK(strcmp(r.last_text, "SELECT a") == 0);

    TEARDOWN();
    printf("ok prepare-trunc\n");
    return 0;
}

/* A PREPARE-OK whose fixed header is cut by the capture budget: the pending
 * text is dropped (unkeyable), no parse error on the truncated body. */
static int test_prep_ok_cut(void)
{
    SETUP(CAPS);
    static const __u8 cut[] = {0x00, 6, 0}; /* stmt_id torn */
    struct lk_msg m = {
        .ts_ns = 1010,
        .flags = LK_MSG_BODY_TRUNC,
        .len = 12,
        .body_cap = sizeof(cut),
        .body = cut,
    };

    prepare(sink, &c, "SELECT x", 1000);
    sink->on_msg(sink->ctx, &c, LK_DIR_SEND, &m);
    CHECK(lk_proto_stats(p)->parse_errors == 0);

    execute(sink, &c, 6, 2000); /* the id we never learned */
    be_ok(sink, &c, 0, 2010);
    CHECK(r.nqueries == 1);
    CHECK(r.last.flags & LK_QO_NO_TEXT);

    TEARDOWN();
    printf("ok prep-ok-cut\n");
    return 0;
}

int main(void)
{
    if (test_prepare_execute() || test_prepare_metadata_old() || test_prepare_err() ||
        test_close_and_rescue() || test_id_reuse() || test_eviction() || test_reset_connection() ||
        test_prepare_trunc() || test_prep_ok_cut())
        return 1;
    printf("ok\n");
    return 0;
}
