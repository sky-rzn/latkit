// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the prepared-statement cache (task 3.4, Р17). Drives the PG
 * handler through its lk_msg_sink with synthetic Parse/Bind/Close messages and
 * checks the cached text via the observations Bind + CommandComplete emit, plus
 * the white-box cache state (this test links the internal pg.h). Covers:
 *
 *   - a cache hit: Parse a named statement, Bind it -> the observation carries
 *     the cached text;
 *   - the unnamed statement is overwritten by each Parse;
 *   - Close ('S') drops a statement -> a later Bind is NO_TEXT;
 *   - LRU eviction past LK_PG_PREP_CACHE, with the eviction counter;
 *   - the eviction rescue: a unit bound to a slot that is evicted while it is
 *     still in flight keeps its text (copied into the unit, Р17).
 */
#include <linux/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "conn_table.h"
#include "pg.h" /* internal: struct pg_conn / pg_prep — white-box assertions */
#include "proto.h"
#include "reassembly.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* --- query-sink recorder -------------------------------------------------- */

struct rec {
    int nqueries;
    struct lk_query_obs last;
    char last_text[256];
    bool last_had_text;
};

static void rec_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                         const struct lk_query_obs *o)
{
    struct rec *r = ctx;

    (void)c;
    (void)s;
    r->nqueries++;
    r->last = *o;
    r->last_had_text = o->text != NULL;
    r->last_text[0] = '\0';
    if (o->text && o->text_len < sizeof(r->last_text)) {
        memcpy(r->last_text, o->text, o->text_len);
        r->last_text[o->text_len] = '\0';
    }
    r->last.text = NULL;
}

/* --- message plumbing ----------------------------------------------------- */

static __u64 g_ts = 1000;

static void feed(const struct lk_msg_sink *sink, struct lk_conn *c, enum lk_dir dir, char type,
                 __u16 flags, const void *body, __u32 body_cap)
{
    struct lk_msg m = {
        .ts_ns = g_ts++,
        .type = type,
        .flags = flags,
        .len = body_cap + 4,
        .body_cap = body_cap,
        .body = (const __u8 *)body,
    };

    sink->on_msg(sink->ctx, c, dir, &m);
}

/* Parse: statement name\0 query\0 int16 nparams(=0). */
static void parse_stmt(const struct lk_msg_sink *sink, struct lk_conn *c, const char *name,
                       const char *query)
{
    __u8 body[512];
    __u32 n = 0;
    __u32 nl = (__u32)strlen(name), ql = (__u32)strlen(query);

    memcpy(body + n, name, nl + 1);
    n += nl + 1;
    memcpy(body + n, query, ql + 1);
    n += ql + 1;
    body[n++] = 0;
    body[n++] = 0; /* nparams = 0 */
    feed(sink, c, LK_DIR_RECV, 'P', 0, body, n);
}

/* Bind: portal ""\0 statement name\0 then zeroed format/value counts. */
static void bind_stmt(const struct lk_msg_sink *sink, struct lk_conn *c, const char *name)
{
    __u8 body[128];
    __u32 n = 0;
    __u32 nl = (__u32)strlen(name);

    body[n++] = 0; /* unnamed portal */
    memcpy(body + n, name, nl + 1);
    n += nl + 1;
    body[n++] = 0;
    body[n++] = 0; /* nformats = 0 */
    body[n++] = 0;
    body[n++] = 0; /* nvalues = 0 */
    feed(sink, c, LK_DIR_RECV, 'B', 0, body, n);
}

/* Close a prepared statement: kind 'S' + name\0. */
static void close_stmt(const struct lk_msg_sink *sink, struct lk_conn *c, const char *name)
{
    __u8 body[128];
    __u32 n = 0;
    __u32 nl = (__u32)strlen(name);

    body[n++] = 'S';
    memcpy(body + n, name, nl + 1);
    n += nl + 1;
    feed(sink, c, LK_DIR_RECV, 'C', 0, body, n);
}

static void complete(const struct lk_msg_sink *sink, struct lk_conn *c, const char *tag)
{
    feed(sink, c, LK_DIR_SEND, 'C', 0, tag, (__u32)strlen(tag) + 1);
}

static void ready(const struct lk_msg_sink *sink, struct lk_conn *c, char status)
{
    feed(sink, c, LK_DIR_SEND, 'Z', 0, &status, 1);
}

/* Startup -> AuthenticationOk -> first Z: reach READY on a clean connection. */
static void handshake(const struct lk_msg_sink *sink, struct lk_conn *c)
{
    static const __u8 startup[] = {0, 0x03, 0, 0, 'u', 's', 'e', 'r', 0, 'm', 'e', 0, 0};
    static const __u8 auth_ok[4] = {0};

    feed(sink, c, LK_DIR_RECV, 0, LK_MSG_STARTUP, startup, sizeof(startup));
    feed(sink, c, LK_DIR_SEND, 'R', 0, auth_ok, sizeof(auth_ok));
    ready(sink, c, 'I');
}

/* --- tests ---------------------------------------------------------------- */

/* A named statement Parsed then Bound: the observation carries the cached SQL. */
static int test_cache_hit(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    parse_stmt(sink, &c, "s1", "select $1::int");
    bind_stmt(sink, &c, "s1");
    complete(sink, &c, "SELECT 1");
    ready(sink, &c, 'I');

    CHECK(r.nqueries == 1);
    CHECK(r.last.kind == LK_Q_EXTENDED);
    CHECK(!(r.last.flags & LK_QO_NO_TEXT));
    CHECK(strcmp(r.last_text, "select $1::int") == 0);
    CHECK(r.last.rows == 1);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok cache-hit\n");
    return 0;
}

/* The unnamed statement ("") is overwritten by every Parse. */
static int test_unnamed_overwrite(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    parse_stmt(sink, &c, "", "select 1");
    parse_stmt(sink, &c, "", "select 2"); /* overwrites the unnamed slot */
    bind_stmt(sink, &c, "");
    complete(sink, &c, "SELECT 1");
    ready(sink, &c, 'I');

    CHECK(r.nqueries == 1);
    CHECK(strcmp(r.last_text, "select 2") == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok unnamed-overwrite\n");
    return 0;
}

/* Close ('S') drops the statement -> a later Bind on the name is NO_TEXT. */
static int test_close_statement(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    parse_stmt(sink, &c, "s1", "select 1");
    close_stmt(sink, &c, "s1");
    bind_stmt(sink, &c, "s1"); /* the name is gone: NO_TEXT */
    complete(sink, &c, "SELECT 1");
    ready(sink, &c, 'I');

    CHECK(r.nqueries == 1);
    CHECK(r.last.flags & LK_QO_NO_TEXT);
    CHECK(!r.last_had_text);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok close-statement\n");
    return 0;
}

/* Filling the cache past LK_PG_PREP_CACHE evicts the LRU entry: the counter
 * climbs, the count stays capped, and the oldest name is gone. */
static int test_lru_eviction(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    char name[32];

    CHECK(p);
    handshake(sink, &c);

    /* "s0" is Parsed first and never touched again — it is the LRU. */
    for (int i = 0; i < LK_PG_PREP_CACHE + 1; i++) {
        snprintf(name, sizeof(name), "s%d", i);
        parse_stmt(sink, &c, name, "select 1");
    }

    struct pg_conn *pc = c.proto_state;

    CHECK(pc && pc->prep);
    CHECK(pc->prep->count == LK_PG_PREP_CACHE);          /* capped */
    CHECK(lk_proto_stats(p)->prep_evictions == 1);       /* one over the ceiling */

    /* The evicted "s0" is a miss now -> NO_TEXT; a survivor is still a hit. */
    bind_stmt(sink, &c, "s0");
    complete(sink, &c, "SELECT 1");
    ready(sink, &c, 'I');
    CHECK(r.last.flags & LK_QO_NO_TEXT);

    bind_stmt(sink, &c, "s5");
    complete(sink, &c, "SELECT 1");
    ready(sink, &c, 'I');
    CHECK(!(r.last.flags & LK_QO_NO_TEXT));
    CHECK(strcmp(r.last_text, "select 1") == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok lru-eviction\n");
    return 0;
}

/* Eviction rescue (Р17): a unit bound to a slot that is evicted while the unit
 * is still in flight keeps its text — copied into the unit before the slot is
 * reused, so the observation still carries the original SQL. */
static int test_eviction_rescue(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    char name[32];

    CHECK(p);
    handshake(sink, &c);

    /* Parse "keep", Bind it (opens an in-flight unit referencing the slot). */
    parse_stmt(sink, &c, "keep", "select keep");
    bind_stmt(sink, &c, "keep");

    /* Now overflow the cache so "keep"'s slot is the LRU and gets evicted while
     * the unit is still open. The Bind touched "keep"'s LRU stamp, so the fresh
     * Parses must all be newer — they are. */
    for (int i = 0; i < LK_PG_PREP_CACHE; i++) {
        snprintf(name, sizeof(name), "n%d", i);
        parse_stmt(sink, &c, name, "other");
    }
    CHECK(lk_proto_stats(p)->prep_evictions >= 1);

    /* The unit closes: its text was rescued into its own copy, not lost. */
    complete(sink, &c, "SELECT 3");
    ready(sink, &c, 'I');
    CHECK(r.nqueries == 1);
    CHECK(!(r.last.flags & LK_QO_NO_TEXT));
    CHECK(strcmp(r.last_text, "select keep") == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok eviction-rescue\n");
    return 0;
}

int main(void)
{
    if (test_cache_hit() || test_unnamed_overwrite() || test_close_statement() ||
        test_lru_eviction() || test_eviction_rescue())
        return 1;
    printf("ok\n");
    return 0;
}
