// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the MySQL query phase machine (MYSQL.md М3, my_query.c).
 * Synthetic packets through the handler's lk_msg_sink, observations out.
 * Covers:
 *
 *   - text resultsets in both shapes: pre-DEPRECATE (metadata EOF + EOF
 *     terminator) and DEPRECATE_EOF (0xFE-headed terminating OK), row counts
 *     and first-row/completion timings (ts_ready == ts_complete);
 *   - DML: rows from the OK's affected_rows;
 *   - errors: SQLSTATE + errno, LK_QO_ERROR; MariaDB progress packets
 *     (errno 0xFFFF) swallowed mid-reply;
 *   - multi-resultset chains (SERVER_MORE_RESULTS_EXISTS): one MULTI_STMT
 *     unit, row counts summed;
 *   - transactions: IN_TRANS edges -> on_txn;
 *   - LOAD DATA LOCAL: 0xFB -> COPY_IN, client bytes, rows from the final OK;
 *   - COM_QUERY under CLIENT_QUERY_ATTRIBUTES: text located past the
 *     attribute header (zero and non-zero parameter counts, NULL params) and
 *     the capability-unknown sniff (plan risk 4);
 *   - cursors: execute-with-cursor -> SUSPENDED, COM_STMT_FETCH batches, the
 *     drained fetch (LAST_ROW_SENT) closing plain;
 *   - honesty (Р19/РМ4): the frontend-anchor discipline dropping a unit whose
 *     reply tail is lost, resync drops, close drops, LK_QO_TEXT_TRUNC
 *     salvage, blind classifying packets;
 *   - binlog dump -> IGNORE + replication_conns; service commands and
 *     unknown commands observing nothing.
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

/* --- sink recorder --------------------------------------------------------- */

struct rec {
    int nqueries, ntxn, nerror;
    struct lk_query_obs last;
    char last_text[256];
    __u64 txn_start, txn_end;
    char txn_final;
};

static void rec_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                         const struct lk_query_obs *o)
{
    struct rec *r = ctx;

    (void)c;
    (void)s;
    r->nqueries++;
    if (o->flags & LK_QO_ERROR)
        r->nerror++;
    r->last = *o;
    r->last_text[0] = '\0';
    if (o->text && o->text_len < sizeof(r->last_text)) {
        memcpy(r->last_text, o->text, o->text_len);
        r->last_text[o->text_len] = '\0';
    }
    r->last.text = NULL; /* dangles after this call; use last_text */
}

static void rec_on_txn(void *ctx, const struct lk_conn *c, __u64 start_ns, __u64 end_ns,
                       char final_status)
{
    struct rec *r = ctx;

    (void)c;
    r->ntxn++;
    r->txn_start = start_ns;
    r->txn_end = end_ns;
    r->txn_final = final_status;
}

/* --- packet builders ------------------------------------------------------- */

static void feed(const struct lk_msg_sink *sink, struct lk_conn *c, enum lk_dir dir, char type,
                 __u16 flags, const void *body, __u32 n, __u64 ts)
{
    struct lk_msg m = {
        .ts_ns = ts, .type = type, .flags = flags, .len = n, .body_cap = n, .body = body};

    sink->on_msg(sink->ctx, c, dir, &m);
}

/* Frontend command: type = the command byte (the framer's seq-0 contract). */
static void cmd(const struct lk_msg_sink *sink, struct lk_conn *c, const void *body, __u32 n,
                __u64 ts)
{
    feed(sink, c, LK_DIR_RECV, (char)((const __u8 *)body)[0], 0, body, n, ts);
}

static void query(const struct lk_msg_sink *sink, struct lk_conn *c, const char *sql, __u64 ts)
{
    __u8 body[256];
    __u32 n = (__u32)strlen(sql);

    body[0] = MY_COM_QUERY;
    memcpy(body + 1, sql, n);
    cmd(sink, c, body, n + 1, ts);
}

/* Backend packet (untyped). */
static void be(const struct lk_msg_sink *sink, struct lk_conn *c, const void *body, __u32 n,
               __u64 ts)
{
    feed(sink, c, LK_DIR_SEND, 0, 0, body, n, ts);
}

static void be_ok(const struct lk_msg_sink *sink, struct lk_conn *c, __u8 affected, __u16 status,
                  __u64 ts)
{
    __u8 body[7] = {0x00, affected, 0, (__u8)status, (__u8)(status >> 8), 0, 0};

    be(sink, c, body, sizeof(body), ts);
}

/* Old-style EOF: 0xFE, warnings, status. */
static void be_eof(const struct lk_msg_sink *sink, struct lk_conn *c, __u16 status, __u64 ts)
{
    __u8 body[5] = {0xfe, 0, 0, (__u8)status, (__u8)(status >> 8)};

    be(sink, c, body, sizeof(body), ts);
}

/* DEPRECATE_EOF terminator: an OK with a 0xFE header. */
static void be_ok_fe(const struct lk_msg_sink *sink, struct lk_conn *c, __u8 affected, __u16 status,
                     __u64 ts)
{
    __u8 body[9] = {0xfe, affected, 0, (__u8)status, (__u8)(status >> 8), 0, 0, 'i', 'n'};

    be(sink, c, body, sizeof(body), ts);
}

static void be_err(const struct lk_msg_sink *sink, struct lk_conn *c, __u16 eno,
                   const char *sqlstate, __u64 ts)
{
    __u8 body[32];
    __u32 n = 0;

    body[n++] = 0xff;
    body[n++] = (__u8)eno;
    body[n++] = (__u8)(eno >> 8);
    body[n++] = '#';
    memcpy(body + n, sqlstate, 5);
    n += 5;
    memcpy(body + n, "boom", 4);
    n += 4;
    be(sink, c, body, n, ts);
}

static void be_count(const struct lk_msg_sink *sink, struct lk_conn *c, __u8 ncols, __u64 ts)
{
    be(sink, c, &ncols, 1, ts);
}

static void be_coldef(const struct lk_msg_sink *sink, struct lk_conn *c, __u64 ts)
{
    static const __u8 body[] = {3, 'd', 'e', 'f', 0, 0, 0}; /* catalog "def"... */

    be(sink, c, body, sizeof(body), ts);
}

static void be_row(const struct lk_msg_sink *sink, struct lk_conn *c, __u64 ts)
{
    static const __u8 body[] = {2, 'h', 'i'};

    be(sink, c, body, sizeof(body), ts);
}

/* Handshake to READY with the given client caps (and MariaDB extended caps). */
static void handshake(const struct lk_msg_sink *sink, struct lk_conn *c, __u32 caps, __u32 mcaps)
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
    memset(body + n, 0, 4 + 1 + 19);
    n += 24;
    body[n++] = (__u8)mcaps;
    body[n++] = (__u8)(mcaps >> 8);
    body[n++] = (__u8)(mcaps >> 16);
    body[n++] = (__u8)(mcaps >> 24);
    memcpy(body + n, "u", 2);
    n += 2;
    body[n++] = 0; /* auth len */
    feed(sink, c, LK_DIR_RECV, 0, LK_MSG_STARTUP, body, n, 11);
    feed(sink, c, LK_DIR_SEND, 0, LK_MSG_STARTUP, ok, sizeof(ok), 12);
}

#define CAPS_OLD (MY_CAP_MYSQL | MY_CAP_PROTOCOL_41 | MY_CAP_TRANSACTIONS)
#define CAPS_NEW (CAPS_OLD | MY_CAP_DEPRECATE_EOF)

/* One handler + connection per test. */
#define SETUP(caps, mcaps)                                                                         \
    struct rec r = {0};                                                                            \
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query, .on_txn = rec_on_txn};         \
    struct lk_proto *p = lk_proto_my_new(&qs);                                                     \
    const struct lk_msg_sink *sink = lk_proto_sink(p);                                             \
    struct lk_conn c = {0};                                                                        \
    CHECK(p);                                                                                      \
    handshake(sink, &c, caps, mcaps)

#define TEARDOWN()                                                                                 \
    do {                                                                                           \
        sink->on_conn_close(sink->ctx, &c);                                                        \
        lk_proto_free(p);                                                                          \
    } while (0)

/* --- tests ----------------------------------------------------------------- */

/* Pre-DEPRECATE text resultset: count, defs, EOF, rows, EOF terminator. */
static int test_select_old(void)
{
    SETUP(CAPS_OLD, 0);

    query(sink, &c, "SELECT * FROM t", 1000);
    be_count(sink, &c, 2, 1010);
    be_coldef(sink, &c, 1011);
    be_coldef(sink, &c, 1012);
    be_eof(sink, &c, 0x0002, 1013); /* metadata EOF: not a terminator */
    be_row(sink, &c, 1020);
    be_row(sink, &c, 1021);
    be_row(sink, &c, 1022);
    CHECK(r.nqueries == 0); /* not until the terminator */
    be_eof(sink, &c, 0x0002, 1030);

    CHECK(r.nqueries == 1);
    CHECK(r.last.kind == LK_Q_SIMPLE);
    CHECK(strcmp(r.last_text, "SELECT * FROM t") == 0);
    CHECK(r.last.rows == 3);
    CHECK(r.last.flags == 0);
    CHECK(r.last.ts_start_ns == 1000);
    CHECK(r.last.ts_first_row_ns == 1020);
    CHECK(r.last.ts_complete_ns == 1030);
    CHECK(r.last.ts_ready_ns == 1030); /* the single done-point */
    CHECK(r.last.txn_status == 'I');

    TEARDOWN();
    printf("ok select-old\n");
    return 0;
}

/* DEPRECATE_EOF resultset: no metadata EOF, a 0xFE-headed OK terminates. */
static int test_select_deprecate(void)
{
    SETUP(CAPS_NEW, 0);

    query(sink, &c, "SELECT 1", 1000);
    be_count(sink, &c, 1, 1010);
    be_coldef(sink, &c, 1011);
    be_row(sink, &c, 1020);
    be_ok_fe(sink, &c, 0, 0x0002, 1030);

    CHECK(r.nqueries == 1);
    CHECK(r.last.rows == 1);
    CHECK(r.last.ts_first_row_ns == 1020);
    CHECK(r.last.ts_complete_ns == 1030);

    TEARDOWN();
    printf("ok select-deprecate\n");
    return 0;
}

/* DML: an immediate OK, rows = affected_rows. */
static int test_dml(void)
{
    SETUP(CAPS_NEW, 0);

    query(sink, &c, "DELETE FROM t", 1000);
    be_ok(sink, &c, 5, 0x0002, 1010);

    CHECK(r.nqueries == 1);
    CHECK(r.last.rows == 5);
    CHECK(r.last.ts_first_row_ns == 0);

    TEARDOWN();
    printf("ok dml\n");
    return 0;
}

/* ERR closes the unit with the SQLSTATE. */
static int test_error(void)
{
    SETUP(CAPS_NEW, 0);

    query(sink, &c, "SELECT * FROM missing", 1000);
    be_err(sink, &c, 1146, "42S02", 1010);

    CHECK(r.nqueries == 1 && r.nerror == 1);
    CHECK(r.last.flags & LK_QO_ERROR);
    CHECK(strcmp(r.last.sqlstate, "42S02") == 0);
    CHECK(lk_proto_stats(p)->errors_sql == 1);

    TEARDOWN();
    printf("ok error\n");
    return 0;
}

/* A MariaDB progress packet (ERR, errno 0xFFFF under MARIADB_CLIENT_PROGRESS)
 * mid-reply is an event, not a terminator: the real terminator still closes. */
static int test_progress(void)
{
    SETUP(CAPS_OLD & ~MY_CAP_MYSQL, MY_MCAP_PROGRESS);
    static const __u8 progress[] = {0xff, 0xff, 0xff, 1, 0, 3, 42};

    query(sink, &c, "ALTER TABLE big ENGINE=InnoDB", 1000);
    be(sink, &c, progress, sizeof(progress), 1010);
    CHECK(r.nqueries == 0); /* swallowed */
    be_ok(sink, &c, 0, 0x0002, 1020);
    CHECK(r.nqueries == 1 && r.nerror == 0);

    TEARDOWN();
    printf("ok progress\n");
    return 0;
}

/* Multi-statement / multi-resultset: SERVER_MORE_RESULTS_EXISTS chains the
 * resultsets into one MULTI_STMT unit, rows summed. */
static int test_multi_resultset(void)
{
    SETUP(CAPS_NEW, 0);

    query(sink, &c, "SELECT 1; DELETE FROM t", 1000);
    be_count(sink, &c, 1, 1010);
    be_coldef(sink, &c, 1011);
    be_row(sink, &c, 1020);
    be_ok_fe(sink, &c, 0, 0x0008 | 0x0002, 1030); /* MORE_RESULTS: stay open */
    CHECK(r.nqueries == 0);
    be_ok(sink, &c, 4, 0x0002, 1040); /* the DELETE's OK: final */

    CHECK(r.nqueries == 1);
    CHECK(r.last.flags & LK_QO_MULTI_STMT);
    CHECK(r.last.rows == 5); /* 1 row packet + affected 4 */
    CHECK(r.last.ts_complete_ns == 1040);

    TEARDOWN();
    printf("ok multi-resultset\n");
    return 0;
}

/* Transactions: the IN_TRANS edge opens, the drop to idle emits on_txn. */
static int test_txn(void)
{
    SETUP(CAPS_NEW, 0);

    query(sink, &c, "BEGIN", 1000);
    be_ok(sink, &c, 0, MY_ST_IN_TRANS, 1010);
    CHECK(r.last.txn_status == 'T');
    query(sink, &c, "INSERT INTO t VALUES (1)", 2000);
    be_ok(sink, &c, 1, MY_ST_IN_TRANS, 2010);
    CHECK(r.ntxn == 0);
    query(sink, &c, "COMMIT", 3000);
    be_ok(sink, &c, 0, 0x0002, 3010);

    CHECK(r.ntxn == 1);
    CHECK(r.txn_start == 1010 && r.txn_end == 3010 && r.txn_final == 'T');
    CHECK(r.nqueries == 3);

    TEARDOWN();
    printf("ok txn\n");
    return 0;
}

/* LOAD DATA LOCAL: 0xFB + filename -> COPY_IN, client data packets counted by
 * length, the empty packet ends the stream, the final OK supplies rows. */
static int test_load_data(void)
{
    SETUP(CAPS_NEW, 0);
    static const __u8 infile[] = {0xfb, '/', 't', 'm', 'p', '/', 'f'};
    static const __u8 chunk[] = {'a', '\t', 'b', '\n', 'c', '\t', 'd', '\n'};

    query(sink, &c, "LOAD DATA LOCAL INFILE '/tmp/f' INTO TABLE t", 1000);
    be(sink, &c, infile, sizeof(infile), 1010);

    struct my_conn *pc = c.proto_state;

    CHECK(pc && pc->phase == MY_PH_INFILE);
    feed(sink, &c, LK_DIR_RECV, 0, 0, chunk, sizeof(chunk), 1020); /* data: untyped */
    feed(sink, &c, LK_DIR_RECV, 0, 0, chunk, sizeof(chunk), 1021);
    feed(sink, &c, LK_DIR_RECV, 0, 0, NULL, 0, 1022); /* the empty EOF packet */
    CHECK(r.nqueries == 0);
    be_ok(sink, &c, 2, 0x0002, 1030);

    CHECK(r.nqueries == 1);
    CHECK(r.last.kind == LK_Q_COPY_IN);
    CHECK(r.last.bytes == 2 * sizeof(chunk));
    CHECK(r.last.rows == 2);
    CHECK(pc->phase == MY_PH_READY);
    CHECK(strcmp(r.last_text, "LOAD DATA LOCAL INFILE '/tmp/f' INTO TABLE t") == 0);

    TEARDOWN();
    printf("ok load-data\n");
    return 0;
}

/* COM_QUERY with CLIENT_QUERY_ATTRIBUTES: zero params (the 8.x default), a
 * bound string parameter, and a NULL parameter (bitmap, no value bytes). */
static int test_query_attributes(void)
{
    SETUP(CAPS_NEW | MY_CAP_QUERY_ATTRIBUTES, 0);
    __u8 body[64];
    __u32 n;

    /* param_count=0, set_count=1 — the header every 8.x client sends. */
    n = 0;
    body[n++] = MY_COM_QUERY;
    body[n++] = 0x00;
    body[n++] = 0x01;
    memcpy(body + n, "SELECT 7", 8);
    n += 8;
    cmd(sink, &c, body, n, 1000);
    be_ok(sink, &c, 0, 0x0002, 1010);
    CHECK(r.nqueries == 1);
    CHECK(strcmp(r.last_text, "SELECT 7") == 0);

    /* One bound VAR_STRING attribute: bitmap, types+names, lenenc value. */
    n = 0;
    body[n++] = MY_COM_QUERY;
    body[n++] = 0x01; /* param_count */
    body[n++] = 0x01; /* param_set_count */
    body[n++] = 0x00; /* null bitmap: param 0 present */
    body[n++] = 0x01; /* new_params_bound */
    body[n++] = 0xfd; /* MYSQL_TYPE_VAR_STRING */
    body[n++] = 0x00; /* flags byte of the type pair */
    body[n++] = 2;    /* name lenenc "a1" */
    body[n++] = 'a';
    body[n++] = '1';
    body[n++] = 3; /* value lenenc "abc" */
    memcpy(body + n, "abc", 3);
    n += 3;
    memcpy(body + n, "SELECT 8", 8);
    n += 8;
    cmd(sink, &c, body, n, 2000);
    be_ok(sink, &c, 0, 0x0002, 2010);
    CHECK(r.nqueries == 2);
    CHECK(strcmp(r.last_text, "SELECT 8") == 0);

    /* A NULL attribute: present in the bitmap, absent from the values. */
    n = 0;
    body[n++] = MY_COM_QUERY;
    body[n++] = 0x01;
    body[n++] = 0x01;
    body[n++] = 0x01; /* null bitmap: param 0 is NULL */
    body[n++] = 0x01;
    body[n++] = 0x06; /* MYSQL_TYPE_NULL */
    body[n++] = 0x00;
    body[n++] = 0; /* empty name */
    memcpy(body + n, "SELECT 9", 8);
    n += 8;
    cmd(sink, &c, body, n, 3000);
    be_ok(sink, &c, 0, 0x0002, 3010);
    CHECK(r.nqueries == 3);
    CHECK(strcmp(r.last_text, "SELECT 9") == 0);

    TEARDOWN();
    printf("ok query-attributes\n");
    return 0;
}

/* Unknown caps (synthetic entry): the attribute header is sniffed — SQL never
 * starts with a NUL byte — and terminators classify by length alone. */
static int test_synthetic_sniff(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    __u8 body[32];
    __u32 n = 0;

    CHECK(p);
    c.flags = LK_CONN_SYNTHETIC;
    body[n++] = MY_COM_QUERY;
    body[n++] = 0x00;
    body[n++] = 0x01;
    memcpy(body + n, "SELECT a", 8);
    n += 8;
    cmd(sink, &c, body, n, 1000);
    be_count(sink, &c, 1, 1010);
    be_coldef(sink, &c, 1011);
    be_eof(sink, &c, 0x0002, 1012); /* len < 9: EOF shape by the heuristic */
    be_row(sink, &c, 1020);
    be_ok_fe(sink, &c, 0, 0x0002, 1030); /* len >= 9: OK shape */
    CHECK(r.nqueries == 1);
    CHECK(strcmp(r.last_text, "SELECT a") == 0);
    CHECK(r.last.rows == 1);

    /* And a plain query without the header is untouched by the sniff. */
    query(sink, &c, "SELECT b", 2000);
    be_ok(sink, &c, 0, 0x0002, 2010);
    CHECK(r.nqueries == 2);
    CHECK(strcmp(r.last_text, "SELECT b") == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok synthetic-sniff\n");
    return 0;
}

/* Cursors: a cursor-opening execute terminates on the metadata EOF carrying
 * CURSOR_EXISTS (no rows, SUSPENDED); FETCH batches carry rows, the last one
 * (LAST_ROW_SENT) closes plain. */
static int test_cursor_fetch(void)
{
    SETUP(CAPS_OLD, 0);
    static const __u8 prepare[] = {MY_COM_STMT_PREPARE, 'S', 'E', 'L', ' ', 'c'};
    static const __u8 prep_ok[] = {0x00, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}; /* id=7, 1 col, 0 par */
    static const __u8 execute[] = {MY_COM_STMT_EXECUTE, 7, 0, 0, 0, 0x01, 1, 0, 0, 0};
    static const __u8 fetch[] = {MY_COM_STMT_FETCH, 7, 0, 0, 0, 2, 0, 0, 0};

    cmd(sink, &c, prepare, sizeof(prepare), 1000);
    be(sink, &c, prep_ok, sizeof(prep_ok), 1010);
    be_coldef(sink, &c, 1011); /* the single column definition */
    be_eof(sink, &c, 0, 1012); /* trailing metadata EOF */

    cmd(sink, &c, execute, sizeof(execute), 2000);
    be_count(sink, &c, 1, 2010);
    be_coldef(sink, &c, 2011);
    be_eof(sink, &c, MY_ST_CURSOR_EXISTS, 2020); /* terminator: cursor open */
    CHECK(r.nqueries == 1);
    CHECK(r.last.kind == LK_Q_EXTENDED);
    CHECK(r.last.flags & LK_QO_SUSPENDED);
    CHECK(r.last.rows == 0);
    CHECK(strcmp(r.last_text, "SEL c") == 0); /* resolved through the cache */

    cmd(sink, &c, fetch, sizeof(fetch), 3000);
    be_row(sink, &c, 3010);
    be_row(sink, &c, 3011);
    be_eof(sink, &c, MY_ST_CURSOR_EXISTS, 3020);
    CHECK(r.nqueries == 2);
    CHECK(r.last.rows == 2);
    CHECK(r.last.flags & LK_QO_SUSPENDED);
    CHECK(strcmp(r.last_text, "SEL c") == 0);

    cmd(sink, &c, fetch, sizeof(fetch), 4000);
    be_row(sink, &c, 4010);
    be_eof(sink, &c, MY_ST_CURSOR_EXISTS | MY_ST_LAST_ROW_SENT, 4020);
    CHECK(r.nqueries == 3);
    CHECK(r.last.rows == 1);
    CHECK(!(r.last.flags & LK_QO_SUSPENDED)); /* drained */

    TEARDOWN();
    printf("ok cursor-fetch\n");
    return 0;
}

/* РМ4 discipline: a new command while a reply is open drops the stale unit —
 * its terminator fell into a hole — and the new unit completes normally. */
static int test_anchor_discipline(void)
{
    SETUP(CAPS_NEW, 0);

    query(sink, &c, "SELECT * FROM big", 1000);
    be_count(sink, &c, 1, 1010);
    be_coldef(sink, &c, 1011);
    be_row(sink, &c, 1020);
    /* ... the rest of the reply was lost; the client moved on. */
    query(sink, &c, "SELECT 2", 2000);
    CHECK(lk_proto_stats(p)->units_dropped_resync == 1);
    CHECK(r.nqueries == 0);
    be_ok(sink, &c, 0, 0x0002, 2010);
    CHECK(r.nqueries == 1);
    CHECK(strcmp(r.last_text, "SELECT 2") == 0);

    TEARDOWN();
    printf("ok anchor-discipline\n");
    return 0;
}

/* A resync drops the in-flight unit and resets the reply state. */
static int test_resync_drop(void)
{
    SETUP(CAPS_NEW, 0);

    query(sink, &c, "SELECT * FROM t", 1000);
    be_count(sink, &c, 1, 1010);
    sink->on_resync(sink->ctx, &c, LK_DIR_SEND);
    CHECK(lk_proto_stats(p)->units_dropped_resync == 1);
    be_row(sink, &c, 1020); /* stray: reply state was reset */
    be_eof(sink, &c, 0x0002, 1030);
    CHECK(r.nqueries == 0);

    query(sink, &c, "SELECT 1", 2000); /* the next command re-anchors */
    be_ok(sink, &c, 0, 0x0002, 2010);
    CHECK(r.nqueries == 1);

    TEARDOWN();
    printf("ok resync-drop\n");
    return 0;
}

/* A connection dying mid-query never emits the unit (Р19). */
static int test_close_drop(void)
{
    SETUP(CAPS_NEW, 0);

    query(sink, &c, "SELECT * FROM t", 1000);
    be_count(sink, &c, 1, 1010);
    sink->on_conn_close(sink->ctx, &c);
    CHECK(lk_proto_stats(p)->units_dropped_close == 1);
    CHECK(r.nqueries == 0);
    CHECK(c.proto_state == NULL);

    lk_proto_free(p);
    printf("ok close-drop\n");
    return 0;
}

/* A budget-truncated COM_QUERY salvages the text prefix (LK_QO_TEXT_TRUNC). */
static int test_text_trunc(void)
{
    SETUP(CAPS_NEW, 0);
    static const char sql[] = "SELECT something long";
    __u8 body[64];
    struct lk_msg m = {
        .ts_ns = 1000,
        .type = MY_COM_QUERY,
        .flags = LK_MSG_BODY_TRUNC,
        .len = 1 + (__u32)strlen(sql),
        .body_cap = 9, /* command byte + "SELECT s" */
        .body = body,
    };

    body[0] = MY_COM_QUERY;
    memcpy(body + 1, sql, strlen(sql));
    sink->on_msg(sink->ctx, &c, LK_DIR_RECV, &m);
    be_ok(sink, &c, 0, 0x0002, 1010);

    CHECK(r.nqueries == 1);
    CHECK(r.last.flags & LK_QO_TEXT_TRUNC);
    CHECK(strcmp(r.last_text, "SELECT s") == 0);

    TEARDOWN();
    printf("ok text-trunc\n");
    return 0;
}

/* A classifying reply packet whose body is entirely blind (capture hole):
 * the unit cannot be finished honestly and is dropped. */
static int test_blind_head(void)
{
    SETUP(CAPS_NEW, 0);
    struct lk_msg m = {
        .ts_ns = 1010, .flags = LK_MSG_BODY_TRUNC, .len = 7, .body_cap = 0, .body = NULL};

    query(sink, &c, "SELECT 1", 1000);
    sink->on_msg(sink->ctx, &c, LK_DIR_SEND, &m);
    CHECK(r.nqueries == 0);
    CHECK(lk_proto_stats(p)->units_dropped_resync == 1);

    TEARDOWN();
    printf("ok blind-head\n");
    return 0;
}

/* Service commands consume their replies without observations; an unknown
 * command is counted and its stray reply ignored. */
static int test_service_and_unknown(void)
{
    SETUP(CAPS_NEW, 0);
    static const __u8 ping[] = {0x0e};
    static const __u8 stats[] = {0x09};
    static const __u8 stat_reply[] = {'U', 'p', 't', 'i', 'm', 'e'};
    static const __u8 mystery[] = {0x77, 1, 2, 3};

    cmd(sink, &c, ping, sizeof(ping), 1000);
    be_ok(sink, &c, 0, 0x0002, 1010);
    cmd(sink, &c, stats, sizeof(stats), 2000);
    be(sink, &c, stat_reply, sizeof(stat_reply), 2010); /* a bare string */
    cmd(sink, &c, mystery, sizeof(mystery), 3000);
    be_ok(sink, &c, 0, 0x0002, 3010); /* stray: lands in MY_R_NONE */
    CHECK(r.nqueries == 0);
    CHECK(lk_proto_stats(p)->unknown_msgs == 1);

    query(sink, &c, "SELECT 1", 4000); /* the machine is still coherent */
    be_ok(sink, &c, 0, 0x0002, 4010);
    CHECK(r.nqueries == 1);

    TEARDOWN();
    printf("ok service-and-unknown\n");
    return 0;
}

/* COM_BINLOG_DUMP: the connection is a deliberate blind zone from here. */
static int test_binlog_ignore(void)
{
    SETUP(CAPS_NEW, 0);
    static const __u8 dump[] = {MY_COM_BINLOG_DUMP, 0, 0, 0, 0};

    cmd(sink, &c, dump, sizeof(dump), 1000);
    CHECK(lk_proto_stats(p)->replication_conns == 1);
    CHECK(c.flags & LK_CONN_IGNORE);
    query(sink, &c, "SELECT 1", 2000); /* nothing is observed past the flip */
    be_ok(sink, &c, 0, 0x0002, 2010);
    CHECK(r.nqueries == 0);

    TEARDOWN();
    printf("ok binlog-ignore\n");
    return 0;
}

/* A corrupt resultset head on a full body: parse_errors, unit dropped. */
static int test_corrupt_head(void)
{
    SETUP(CAPS_NEW, 0);
    static const __u8 bogus[] = {0xfc, 0xff}; /* lenenc u16 cut short: corrupt */

    query(sink, &c, "SELECT 1", 1000);
    be(sink, &c, bogus, sizeof(bogus), 1010);
    CHECK(lk_proto_stats(p)->parse_errors == 1);
    CHECK(r.nqueries == 0);

    query(sink, &c, "SELECT 2", 2000);
    be_ok(sink, &c, 0, 0x0002, 2010);
    CHECK(r.nqueries == 1); /* recovered on the next exchange */

    TEARDOWN();
    printf("ok corrupt-head\n");
    return 0;
}

int main(void)
{
    if (test_select_old() || test_select_deprecate() || test_dml() || test_error() ||
        test_progress() || test_multi_resultset() || test_txn() || test_load_data() ||
        test_query_attributes() || test_synthetic_sniff() || test_cursor_fetch() ||
        test_anchor_discipline() || test_resync_drop() || test_close_drop() || test_text_trunc() ||
        test_blind_head() || test_service_and_unknown() || test_binlog_ignore() ||
        test_corrupt_head())
        return 1;
    printf("ok\n");
    return 0;
}
