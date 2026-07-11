// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the simple-query state machine (task 3.3, Р16). Drives the PG
 * handler through its lk_msg_sink with synthetic messages and checks the
 * observations the query sink receives. Covers:
 *
 *   - the happy path: Q .. T,D,C,Z -> one SIMPLE observation, rows from the
 *     CommandComplete tag, first-row and completion timings;
 *   - a failing query: ErrorResponse contributes the SQLSTATE and LK_QO_ERROR;
 *   - a multi-statement Q ("select 1; select 2"): two CommandCompletes ->
 *     LK_QO_MULTI_STMT with the row counts summed;
 *   - an empty query string: EmptyQueryResponse -> LK_QO_EMPTY;
 *   - transactions: BEGIN / ... / COMMIT emits on_txn on the T -> I edge;
 *   - the honesty invariant: a unit open when the stream resyncs, or one seen
 *     on a synthetic connection, is never emitted (Р19);
 *   - the CommandComplete tag table (which verbs carry a row count);
 *   - a truncated Q salvages the text prefix and flags LK_QO_TEXT_TRUNC.
 */
#include <linux/types.h>
#include <stdio.h>
#include <string.h>

#include "conn_table.h"
#include "pg.h" /* internal: struct pg_conn, phase enum — white-box assertions */
#include "proto.h"
#include "reassembly.h" /* LK_MSG_* flags */

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
    int ntxn;
    int npipelined, nerror, naborted; /* observations carrying each flag */
    struct lk_query_obs last;
    char last_text[256];
    /* last on_txn */
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
    if (o->flags & LK_QO_PIPELINED)
        r->npipelined++;
    if (o->flags & LK_QO_ERROR)
        r->nerror++;
    if (o->flags & LK_QO_ABORTED)
        r->naborted++;
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

/* --- message plumbing ----------------------------------------------------- */

/* One message with an explicit timestamp (timings matter here). */
static void feed_ts(const struct lk_msg_sink *sink, struct lk_conn *c, enum lk_dir dir, char type,
                    __u16 flags, const void *body, __u32 body_cap, __u64 ts)
{
    struct lk_msg m = {
        .ts_ns = ts,
        .type = type,
        .flags = flags,
        .len = body_cap + 4,
        .body_cap = body_cap,
        .body = (const __u8 *)body,
    };

    sink->on_msg(sink->ctx, c, dir, &m);
}

/* A frontend Query 'Q': body is the SQL text plus its NUL terminator. */
static void q_simple(const struct lk_msg_sink *sink, struct lk_conn *c, const char *sql, __u64 ts)
{
    feed_ts(sink, c, LK_DIR_RECV, 'Q', 0, sql, (__u32)strlen(sql) + 1, ts);
}

/* A backend CommandComplete 'C': body is the tag plus its NUL. */
static void complete(const struct lk_msg_sink *sink, struct lk_conn *c, const char *tag, __u64 ts)
{
    feed_ts(sink, c, LK_DIR_SEND, 'C', 0, tag, (__u32)strlen(tag) + 1, ts);
}

/* A backend ReadyForQuery 'Z' with a transaction-status byte. */
static void ready(const struct lk_msg_sink *sink, struct lk_conn *c, char status, __u64 ts)
{
    feed_ts(sink, c, LK_DIR_SEND, 'Z', 0, &status, 1, ts);
}

/* Take a synthetic connection all the way to READY through a real startup so
 * the query phase is exercised on a non-degraded connection. */
static void handshake(const struct lk_msg_sink *sink, struct lk_conn *c)
{
    static const __u8 startup[] = {
        0,   0x03, 0,   0,   'u', 's', 'e', 'r', 0,   'm', 'e', 0, 'd',
        'a', 't',  'a', 'b', 'a', 's', 'e', 0,   'd', 'b', 0,   0}; /* code 0x00030000 + user=me +
                                                                       database=db */
    static const __u8 auth_ok[4] = {0};

    feed_ts(sink, c, LK_DIR_RECV, 0, LK_MSG_STARTUP, startup, sizeof(startup), 100);
    feed_ts(sink, c, LK_DIR_SEND, 'R', 0, auth_ok, sizeof(auth_ok), 110);
    ready(sink, c, 'I', 120); /* first ReadyForQuery: idle, no unit */
}

/* --- extended-protocol helpers -------------------------------------------- */

/* Parse: statement name\0 query\0 int16 nparams(=0). */
static void parse_stmt(const struct lk_msg_sink *sink, struct lk_conn *c, const char *name,
                       const char *query, __u64 ts)
{
    __u8 body[256];
    __u32 n = 0, nl = (__u32)strlen(name), ql = (__u32)strlen(query);

    memcpy(body + n, name, nl + 1);
    n += nl + 1;
    memcpy(body + n, query, ql + 1);
    n += ql + 1;
    body[n++] = 0;
    body[n++] = 0;
    feed_ts(sink, c, LK_DIR_RECV, 'P', 0, body, n, ts);
}

/* Bind: portal ""\0 statement name\0 zeroed format/value counts. */
static void bind_stmt(const struct lk_msg_sink *sink, struct lk_conn *c, const char *name, __u64 ts)
{
    __u8 body[128];
    __u32 n = 0, nl = (__u32)strlen(name);

    body[n++] = 0;
    memcpy(body + n, name, nl + 1);
    n += nl + 1;
    body[n++] = 0;
    body[n++] = 0;
    body[n++] = 0;
    body[n++] = 0;
    feed_ts(sink, c, LK_DIR_RECV, 'B', 0, body, n, ts);
}

static void execute(const struct lk_msg_sink *sink, struct lk_conn *c, __u64 ts)
{
    static const __u8 body[5] = {0}; /* portal ""\0 maxrows(4) */

    feed_ts(sink, c, LK_DIR_RECV, 'E', 0, body, sizeof(body), ts);
}

static void sync_msg(const struct lk_msg_sink *sink, struct lk_conn *c, __u64 ts)
{
    feed_ts(sink, c, LK_DIR_RECV, 'S', 0, "", 0, ts);
}

/* A backend ErrorResponse carrying just the SQLSTATE (field 'C'). */
static void error_resp(const struct lk_msg_sink *sink, struct lk_conn *c, const char *sqlstate,
                       __u64 ts)
{
    __u8 body[16];
    __u32 n = 0;

    body[n++] = 'C';
    memcpy(body + n, sqlstate, strlen(sqlstate) + 1);
    n += (__u32)strlen(sqlstate) + 1;
    body[n++] = 0; /* field-list terminator */
    feed_ts(sink, c, LK_DIR_SEND, 'E', 0, body, n, ts);
}

/* --- tests ---------------------------------------------------------------- */

/* Happy path: Q "select 1" -> RowDescription, DataRow, CommandComplete, Z.
 * One SIMPLE observation with rows=1, first-row and completion timings, and the
 * duration ts_complete - ts_start. */
static int test_happy_path(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query, .on_txn = rec_on_txn};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    q_simple(sink, &c, "select 1", 1000);
    feed_ts(sink, &c, LK_DIR_SEND, 'T', 0, "", 0, 1010); /* RowDescription */
    feed_ts(sink, &c, LK_DIR_SEND, 'D', 0, "", 0, 1020); /* DataRow: first row */
    feed_ts(sink, &c, LK_DIR_SEND, 'D', 0, "", 0, 1030); /* second row */
    complete(sink, &c, "SELECT 1", 1040);
    CHECK(r.nqueries == 0); /* not until Z */
    ready(sink, &c, 'I', 1050);

    CHECK(r.nqueries == 1);
    CHECK(r.last.kind == LK_Q_SIMPLE);
    CHECK(strcmp(r.last_text, "select 1") == 0);
    CHECK(r.last.rows == 1);
    CHECK(r.last.flags == 0);
    CHECK(r.last.ts_start_ns == 1000);
    CHECK(r.last.ts_first_row_ns == 1020); /* first DataRow only */
    CHECK(r.last.ts_complete_ns == 1040);
    CHECK(r.last.ts_ready_ns == 1050);
    CHECK(r.last.txn_status == 'I');
    CHECK(r.ntxn == 0); /* no BEGIN/COMMIT: not a tracked transaction */

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok happy-path\n");
    return 0;
}

/* A failing query: "select 1/0" -> ErrorResponse (SQLSTATE 22012), then Z. The
 * observation carries LK_QO_ERROR and the SQLSTATE; no row count. */
static int test_error(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    /* ErrorResponse fields: S(everity) ERROR, C(ode) 22012, M(essage), end. */
    __u8 err[64];
    __u32 n = 0;

    CHECK(p);
    handshake(sink, &c);

    err[n++] = 'S';
    memcpy(err + n, "ERROR", 6);
    n += 6;
    err[n++] = 'C';
    memcpy(err + n, "22012", 6);
    n += 6;
    err[n++] = 'M';
    memcpy(err + n, "division by zero", 17);
    n += 17;
    err[n++] = 0; /* field-list terminator */

    q_simple(sink, &c, "select 1/0", 2000);
    feed_ts(sink, &c, LK_DIR_SEND, 'E', 0, err, n, 2010);
    ready(sink, &c, 'I', 2020);

    CHECK(r.nqueries == 1);
    CHECK(r.last.flags & LK_QO_ERROR);
    CHECK(strcmp(r.last.sqlstate, "22012") == 0);
    CHECK(r.last.rows == 0);
    CHECK(r.last.ts_complete_ns == 2010);
    CHECK(lk_proto_stats(p)->errors_sql == 1);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok error\n");
    return 0;
}

/* Multi-statement simple query "select 1; select 2": two CommandCompletes
 * before Z -> one LK_QO_MULTI_STMT observation, rows summed (1 + 2 = 3). */
static int test_multi_stmt(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    q_simple(sink, &c, "select 1; select 2", 3000);
    complete(sink, &c, "SELECT 1", 3010);
    complete(sink, &c, "SELECT 2", 3020);
    ready(sink, &c, 'I', 3030);

    CHECK(r.nqueries == 1);
    CHECK(r.last.flags & LK_QO_MULTI_STMT);
    CHECK(r.last.rows == 3); /* 1 + 2 */
    CHECK(strcmp(r.last_text, "select 1; select 2") == 0);
    CHECK(r.last.ts_complete_ns == 3020); /* the last CommandComplete */

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok multi-stmt\n");
    return 0;
}

/* An empty query string: the backend answers EmptyQueryResponse, not
 * CommandComplete. One observation flagged LK_QO_EMPTY, rows 0. */
static int test_empty_query(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    q_simple(sink, &c, "", 4000);                        /* empty query */
    feed_ts(sink, &c, LK_DIR_SEND, 'I', 0, "", 0, 4010); /* EmptyQueryResponse */
    ready(sink, &c, 'I', 4020);

    CHECK(r.nqueries == 1);
    CHECK(r.last.flags & LK_QO_EMPTY);
    CHECK(r.last.rows == 0);
    CHECK(r.last_text[0] == '\0');

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok empty-query\n");
    return 0;
}

/* Transaction span: BEGIN moves the status I->T, a query runs inside, COMMIT
 * returns T->I and fires on_txn with the transaction's start/end. */
static int test_transaction(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query, .on_txn = rec_on_txn};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    /* BEGIN: Z reports 'T' — the transaction opens here. */
    q_simple(sink, &c, "begin", 5000);
    complete(sink, &c, "BEGIN", 5010);
    ready(sink, &c, 'T', 5020);
    CHECK(r.ntxn == 0); /* still open */
    CHECK(r.last.txn_status == 'T');
    CHECK(r.last.rows == 0); /* BEGIN carries no count */

    /* A query inside the transaction. */
    q_simple(sink, &c, "insert into t values (1)", 5030);
    complete(sink, &c, "INSERT 0 1", 5040);
    ready(sink, &c, 'T', 5050);
    CHECK(r.last.rows == 1); /* "INSERT 0 1" -> last token */
    CHECK(r.ntxn == 0);

    /* COMMIT: Z reports 'I' — the transaction closes, on_txn fires. */
    q_simple(sink, &c, "commit", 5060);
    complete(sink, &c, "COMMIT", 5070);
    ready(sink, &c, 'I', 5080);
    CHECK(r.ntxn == 1);
    CHECK(r.txn_start == 5020); /* the Z that entered 'T' */
    CHECK(r.txn_end == 5080);   /* the Z that returned to 'I' */
    CHECK(r.txn_final == 'T');
    CHECK(r.nqueries == 3);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok transaction\n");
    return 0;
}

/* Honesty (Р19): a unit open when the stream resyncs is dropped, and no unit
 * opens again until the first clean Z — a query observed through the gap is
 * never emitted. */
static int test_resync_drops_unit(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query, .on_txn = rec_on_txn};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    /* Open a transaction, then break the stream with a query in flight. */
    q_simple(sink, &c, "begin", 5900);
    complete(sink, &c, "BEGIN", 5910);
    ready(sink, &c, 'T', 5920);
    q_simple(sink, &c, "select slow()", 6000);
    sink->on_resync(sink->ctx, &c, LK_DIR_SEND);
    CHECK(lk_proto_stats(p)->units_dropped_resync == 1);

    CHECK(r.nqueries == 1); /* only the BEGIN observation so far */

    /* The next Q, seen while degraded, opens nothing even though a full C/Z
     * follows. */
    q_simple(sink, &c, "select 2", 6010);
    complete(sink, &c, "SELECT 1", 6020);
    ready(sink, &c, 'I', 6030); /* clean Z: ends the degraded window */
    CHECK(r.nqueries == 1);     /* the in-gap query was not emitted */

    /* After the clean Z, queries flow again. */
    q_simple(sink, &c, "select 3", 6040);
    complete(sink, &c, "SELECT 1", 6050);
    ready(sink, &c, 'I', 6060);
    CHECK(r.nqueries == 2);
    CHECK(strcmp(r.last_text, "select 3") == 0);
    /* The transaction open at the break is abandoned: no on_txn spans the gap
     * even though the post-gap Zs report status 'I' (Р19). */
    CHECK(r.ntxn == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok resync-drops-unit\n");
    return 0;
}

/* A synthetic connection starts READY-degraded: even a clean-looking Q .. Z is
 * not emitted until a first Z establishes the boundary (Р19). */
static int test_synthetic_degraded(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {.flags = LK_CONN_SYNTHETIC};

    CHECK(p);
    /* First message on the synthetic conn allocates state in READY-degraded. */
    q_simple(sink, &c, "select 1", 7000);
    complete(sink, &c, "SELECT 1", 7010);
    ready(sink, &c, 'I', 7020); /* the boundary-establishing Z */
    CHECK(r.nqueries == 0);

    q_simple(sink, &c, "select 2", 7030);
    complete(sink, &c, "SELECT 2", 7040);
    ready(sink, &c, 'I', 7050);
    CHECK(r.nqueries == 1);
    CHECK(r.last.rows == 2);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok synthetic-degraded\n");
    return 0;
}

/* The CommandComplete tag table: counted verbs take their last token, the rest
 * report 0, and a non-numeric tail is ignored rather than guessed. */
static int test_tag_table(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    struct {
        const char *tag;
        __u64 rows;
    } cases[] = {
        {"SELECT 42", 42}, {"INSERT 0 5", 5}, {"UPDATE 7", 7}, {"DELETE 3", 3},
        {"MOVE 9", 9},     {"FETCH 10", 10},  {"MERGE 4", 4},  {"COPY 100", 100},
        {"BEGIN", 0},      {"SET", 0},        {"COMMIT", 0},   {"CREATE TABLE", 0},
    };
    __u64 ts = 8000;

    CHECK(p);
    handshake(sink, &c);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        q_simple(sink, &c, "x", ts++);
        complete(sink, &c, cases[i].tag, ts++);
        ready(sink, &c, 'I', ts++);
        if (r.last.rows != cases[i].rows) {
            fprintf(stderr, "FAIL tag \"%s\": expected rows=%llu, got %llu\n", cases[i].tag,
                    (unsigned long long)cases[i].rows, (unsigned long long)r.last.rows);
            return 1;
        }
    }
    CHECK(r.nqueries == (int)(sizeof(cases) / sizeof(cases[0])));

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok tag-table\n");
    return 0;
}

/* A budget-truncated Q salvages the captured text prefix and flags it as such;
 * the observation is still emitted normally on Z. */
static int test_truncated_text(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    /* "select long..." captured as "select lo" with no NUL (budget cut). */
    feed_ts(sink, &c, LK_DIR_RECV, 'Q', LK_MSG_BODY_TRUNC, "select lo", 9, 9000);
    complete(sink, &c, "SELECT 100", 9010);
    ready(sink, &c, 'I', 9020);

    CHECK(r.nqueries == 1);
    CHECK(r.last.flags & LK_QO_TEXT_TRUNC);
    CHECK(strcmp(r.last_text, "select lo") == 0); /* no trailing NUL to strip */
    CHECK(r.last.rows == 100);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok truncated-text\n");
    return 0;
}

/* Extended protocol happy path: Parse/Bind/Execute/Sync, backend closes the unit
 * on CommandComplete (not Z). One EXTENDED observation with the cached text. */
static int test_extended_basic(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query, .on_txn = rec_on_txn};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    parse_stmt(sink, &c, "s1", "select $1", 1000);
    bind_stmt(sink, &c, "s1", 1010);
    execute(sink, &c, 1020);
    feed_ts(sink, &c, LK_DIR_SEND, 'D', 0, "", 0, 1030); /* DataRow */
    complete(sink, &c, "SELECT 1", 1040);                /* closes the EXTENDED unit */
    CHECK(r.nqueries == 0);                              /* batch emits at its Z */
    sync_msg(sink, &c, 1050);
    ready(sink, &c, 'I', 1060);

    CHECK(r.nqueries == 1);
    CHECK(r.last.kind == LK_Q_EXTENDED);
    CHECK(strcmp(r.last_text, "select $1") == 0);
    CHECK(r.last.rows == 1);
    CHECK(r.last.flags == 0);          /* not pipelined, no error */
    CHECK(r.last.ts_start_ns == 1010); /* the Bind, not the Parse */
    CHECK(r.last.ts_first_row_ns == 1030);
    CHECK(r.last.ts_complete_ns == 1040);
    CHECK(r.last.ts_ready_ns == 1060); /* the batch's Z (Р16) */

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok extended-basic\n");
    return 0;
}

/* Bind on a name never Parsed: EXTENDED unit with LK_QO_NO_TEXT, honest timings. */
static int test_bind_no_text(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    bind_stmt(sink, &c, "ghost", 2000); /* no prior Parse */
    execute(sink, &c, 2010);
    complete(sink, &c, "SELECT 7", 2020);
    sync_msg(sink, &c, 2030);
    ready(sink, &c, 'I', 2040);

    CHECK(r.nqueries == 1);
    CHECK(r.last.kind == LK_Q_EXTENDED);
    CHECK(r.last.flags & LK_QO_NO_TEXT);
    CHECK(r.last_text[0] == '\0');
    CHECK(r.last.rows == 7);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok bind-no-text\n");
    return 0;
}

/* Pipelining: two Binds before any reply. Both observations are flagged
 * LK_QO_PIPELINED and closed FIFO by their CommandCompletes. */
static int test_pipelining(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    parse_stmt(sink, &c, "a", "select 1", 3000);
    parse_stmt(sink, &c, "b", "select 2", 3010);
    bind_stmt(sink, &c, "a", 3020);
    execute(sink, &c, 3030);
    bind_stmt(sink, &c, "b", 3040); /* second unit in flight -> pipelined */
    execute(sink, &c, 3050);
    sync_msg(sink, &c, 3060);

    complete(sink, &c, "SELECT 10", 3070); /* closes unit a (head) */
    complete(sink, &c, "SELECT 20", 3080); /* closes unit b */
    CHECK(r.nqueries == 0);                /* both wait for the batch's Z */

    ready(sink, &c, 'I', 3090); /* emits the whole batch, FIFO */
    CHECK(r.nqueries == 2);
    CHECK(r.npipelined == 2);              /* both units flagged pipelined */
    CHECK(r.last.flags & LK_QO_PIPELINED); /* unit b, last emitted */
    CHECK(strcmp(r.last_text, "select 2") == 0);
    CHECK(r.last.rows == 20);
    CHECK(r.last.ts_ready_ns == 3090); /* the shared Z */

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok pipelining\n");
    return 0;
}

/* An error mid-batch: the erroring unit gets LK_QO_ERROR, every later unit of
 * the batch gets LK_QO_ABORTED, and the phase skips to the Sync's Z (Р16). */
static int test_batch_error_abort(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    /* Three pipelined units; the backend errors on the first reply. */
    parse_stmt(sink, &c, "a", "select 1", 4000);
    bind_stmt(sink, &c, "a", 4010);
    execute(sink, &c, 4020);
    bind_stmt(sink, &c, "a", 4030);
    execute(sink, &c, 4040);
    bind_stmt(sink, &c, "a", 4050);
    execute(sink, &c, 4060);
    sync_msg(sink, &c, 4070);

    error_resp(sink, &c, "23505", 4080); /* unit 1 errors -> aborts 2 and 3 */
    CHECK(r.nqueries == 0);              /* nothing emitted until the batch's Z */

    ready(sink, &c, 'I', 4090); /* the Sync's Z emits the whole batch */
    CHECK(r.nqueries == 3);

    /* Exactly one ERROR (with the SQLSTATE) and a tail of two ABORTED. */
    CHECK(r.nerror == 1);
    CHECK(r.naborted == 2);
    CHECK(strcmp(r.last.sqlstate, "") == 0); /* the aborted tail carries no state */
    CHECK(lk_proto_stats(p)->errors_sql == 1);
    CHECK(r.last.flags & LK_QO_ABORTED); /* last emitted is the tail */
    CHECK(!(r.last.flags & LK_QO_ERROR));

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok batch-error-abort\n");
    return 0;
}

/* Overflowing the in-flight ring makes the connection LOSSY: no observation is
 * emitted until the next clean Z, and units_dropped_overflow is bumped (Р16). */
static int test_overflow_lossy(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    __u64 ts = 5000;

    CHECK(p);
    handshake(sink, &c);

    parse_stmt(sink, &c, "a", "select 1", ts++);
    /* Bind more units than the ring holds, all before any reply. */
    for (int i = 0; i < LK_PG_MAX_INFLIGHT + 5; i++) {
        bind_stmt(sink, &c, "a", ts++);
        execute(sink, &c, ts++);
    }
    CHECK(lk_proto_stats(p)->units_dropped_overflow == 5);

    /* Replies now arrive; while LOSSY nothing is emitted. */
    for (int i = 0; i < LK_PG_MAX_INFLIGHT; i++)
        complete(sink, &c, "SELECT 1", ts++);
    CHECK(r.nqueries == 0);

    ready(sink, &c, 'I', ts++); /* clean Z ends the LOSSY window */
    CHECK(r.nqueries == 0);     /* the overflowed batch emitted nothing */

    /* After the Z, tracking resumes cleanly. */
    parse_stmt(sink, &c, "b", "select 2", ts++);
    bind_stmt(sink, &c, "b", ts++);
    execute(sink, &c, ts++);
    complete(sink, &c, "SELECT 2", ts++);
    ready(sink, &c, 'I', ts++);
    CHECK(r.nqueries == 1);
    CHECK(strcmp(r.last_text, "select 2") == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok overflow-lossy\n");
    return 0;
}

/* PortalSuspended closes an extended unit with LK_QO_SUSPENDED (Execute hit its
 * row limit). */
static int test_suspended(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    parse_stmt(sink, &c, "s", "select * from big", 6000);
    bind_stmt(sink, &c, "s", 6010);
    execute(sink, &c, 6020);
    feed_ts(sink, &c, LK_DIR_SEND, 'D', 0, "", 0, 6030); /* a row */
    feed_ts(sink, &c, LK_DIR_SEND, 's', 0, "", 0, 6040); /* PortalSuspended */
    CHECK(r.nqueries == 0);                              /* still waits for the Z */
    sync_msg(sink, &c, 6050);
    ready(sink, &c, 'I', 6060);

    CHECK(r.nqueries == 1);
    CHECK(r.last.flags & LK_QO_SUSPENDED);
    CHECK(strcmp(r.last_text, "select * from big") == 0);
    CHECK(r.last.ts_complete_ns == 6040); /* PortalSuspended, not the Z */
    CHECK(r.last.ts_ready_ns == 6060);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok suspended\n");
    return 0;
}

/* FunctionCall: a FUNCTION unit with no text, closed by the following Z like a
 * simple query (FunctionCallResponse then ReadyForQuery, no CommandComplete). */
static int test_function_call(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    feed_ts(sink, &c, LK_DIR_RECV, 'F', 0, "\0\0\0\1\0\0", 6, 7000); /* FunctionCall */
    feed_ts(sink, &c, LK_DIR_SEND, 'V', 0, "", 0, 7010);             /* FunctionCallResponse */
    CHECK(r.nqueries == 0);                                          /* waits for Z */
    ready(sink, &c, 'I', 7020);

    CHECK(r.nqueries == 1);
    CHECK(r.last.kind == LK_Q_FUNCTION);
    CHECK(r.last.flags & LK_QO_NO_TEXT);
    CHECK(r.last.ts_ready_ns == 7020);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok function-call\n");
    return 0;
}

/* COPY FROM STDIN (Р20): Q "COPY .. FROM STDIN" opens the unit, CopyInResponse
 * turns it into COPY_IN, the frontend CopyData messages sum their bytes, and the
 * "COPY n" CommandComplete + Z emit one COPY_IN observation. */
static int test_copy_in(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    static const __u8 gbody[5] = {0}; /* format + ncols + col formats */
    static const __u8 dbody[8] = {0};

    CHECK(p);
    handshake(sink, &c);

    q_simple(sink, &c, "COPY t FROM STDIN", 1000);
    feed_ts(sink, &c, LK_DIR_SEND, 'G', 0, gbody, sizeof(gbody), 1010); /* CopyInResponse */
    feed_ts(sink, &c, LK_DIR_RECV, 'd', 0, dbody, sizeof(dbody), 1020); /* CopyData: len 12 */
    feed_ts(sink, &c, LK_DIR_RECV, 'd', 0, dbody, sizeof(dbody), 1030); /* len 12 */
    feed_ts(sink, &c, LK_DIR_RECV, 'c', 0, "", 0, 1040);                /* CopyDone */
    complete(sink, &c, "COPY 2", 1050);
    CHECK(r.nqueries == 0); /* simple COPY emits at its Z */
    ready(sink, &c, 'I', 1060);

    CHECK(r.nqueries == 1);
    CHECK(r.last.kind == LK_Q_COPY_IN);
    CHECK(r.last.rows == 2);
    CHECK(r.last.bytes == 24); /* two CopyData, len = body_cap + 4 = 12 each */
    CHECK(strcmp(r.last_text, "COPY t FROM STDIN") == 0);
    CHECK(r.last.flags == 0);

    /* The connection is back to READY: a normal query flows again. */
    q_simple(sink, &c, "select 1", 1070);
    complete(sink, &c, "SELECT 1", 1080);
    ready(sink, &c, 'I', 1090);
    CHECK(r.nqueries == 2);
    CHECK(r.last.kind == LK_Q_SIMPLE);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok copy-in\n");
    return 0;
}

/* COPY TO STDOUT: CopyOutResponse -> backend CopyData -> "COPY n". One COPY_OUT
 * observation with the backend bytes. */
static int test_copy_out(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    static const __u8 hbody[5] = {0};
    static const __u8 dbody[8] = {0};

    CHECK(p);
    handshake(sink, &c);

    q_simple(sink, &c, "COPY t TO STDOUT", 2000);
    feed_ts(sink, &c, LK_DIR_SEND, 'H', 0, hbody, sizeof(hbody), 2010); /* CopyOutResponse */
    feed_ts(sink, &c, LK_DIR_SEND, 'd', 0, dbody, sizeof(dbody), 2020);
    feed_ts(sink, &c, LK_DIR_SEND, 'd', 0, dbody, sizeof(dbody), 2030);
    feed_ts(sink, &c, LK_DIR_SEND, 'c', 0, "", 0, 2040); /* CopyDone (backend) */
    complete(sink, &c, "COPY 2", 2050);
    ready(sink, &c, 'I', 2060);

    CHECK(r.nqueries == 1);
    CHECK(r.last.kind == LK_Q_COPY_OUT);
    CHECK(r.last.rows == 2);
    CHECK(r.last.bytes == 24);
    CHECK(strcmp(r.last_text, "COPY t TO STDOUT") == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok copy-out\n");
    return 0;
}

/* CopyBothResponse (Р20/Р21): a walsender/replication stream. The connection
 * goes IGNORE, emits nothing, bumps replication_conns, and is flagged
 * LK_CONN_REPLICATION so userspace can flip it to HEADERS capture. */
static int test_replication(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    static const __u8 wbody[7] = {0};
    static const __u8 dbody[8] = {0};

    CHECK(p);
    handshake(sink, &c);

    q_simple(sink, &c, "START_REPLICATION SLOT s LOGICAL 0/0", 3000);
    feed_ts(sink, &c, LK_DIR_SEND, 'W', 0, wbody, sizeof(wbody), 3010); /* CopyBothResponse */
    CHECK(lk_proto_stats(p)->replication_conns == 1);
    CHECK(c.flags & LK_CONN_REPLICATION);

    /* WAL data now streams both ways: all ignored, no observation ever. */
    for (int i = 0; i < 5; i++)
        feed_ts(sink, &c, LK_DIR_SEND, 'd', 0, dbody, sizeof(dbody), 3020 + i);
    CHECK(r.nqueries == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok replication\n");
    return 0;
}

/* Parse-error path (Р18): a CommandComplete whose tag has no NUL terminator on a
 * *full* body is corruption (not budget truncation). It bumps parse_errors,
 * drops the in-flight unit, and resets to the next clean Z — after which queries
 * flow again. */
static int test_corrupt_body(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    /* A truncated tag (no NUL, but LK_MSG_BODY_TRUNC set) is *not* an error: the
     * statement still completed, the count is just unknown. */
    q_simple(sink, &c, "select trunc", 3900);
    feed_ts(sink, &c, LK_DIR_SEND, 'C', LK_MSG_BODY_TRUNC, "SELECT", 6, 3910);
    ready(sink, &c, 'I', 3920);
    CHECK(r.nqueries == 1);
    CHECK(lk_proto_stats(p)->parse_errors == 0);
    CHECK(r.last.rows == 0); /* count unknown, but the unit was emitted */

    /* A full body with no terminator is corruption: parse_errors, unit dropped. */
    q_simple(sink, &c, "select 1", 4000);
    feed_ts(sink, &c, LK_DIR_SEND, 'C', 0, "SELECT 1", 8, 4010); /* full body, no NUL */
    CHECK(lk_proto_stats(p)->parse_errors == 1);
    ready(sink, &c, 'I', 4020);
    CHECK(r.nqueries == 1); /* the corrupt query was dropped, not emitted */

    /* The clean Z above ended the degraded window; queries flow again. */
    q_simple(sink, &c, "select 2", 4030);
    complete(sink, &c, "SELECT 1", 4040);
    ready(sink, &c, 'I', 4050);
    CHECK(r.nqueries == 2);
    CHECK(strcmp(r.last_text, "select 2") == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok corrupt-body\n");
    return 0;
}

/* Honesty (Р19): a unit still in flight when the connection closes is dropped,
 * never emitted — a request cut off by a disconnect is not an observation. */
static int test_close_drops_inflight(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    handshake(sink, &c);

    q_simple(sink, &c, "select pg_sleep(10)", 5000); /* never gets its Z */
    sink->on_conn_close(sink->ctx, &c);              /* connection dies mid-query */

    CHECK(r.nqueries == 0);
    CHECK(lk_proto_stats(p)->units_dropped_close == 1);

    lk_proto_free(p);
    printf("ok close-drops-inflight\n");
    return 0;
}

int main(void)
{
    if (test_happy_path() || test_error() || test_multi_stmt() || test_empty_query() ||
        test_transaction() || test_resync_drops_unit() || test_synthetic_degraded() ||
        test_tag_table() || test_truncated_text() || test_extended_basic() || test_bind_no_text() ||
        test_pipelining() || test_batch_error_abort() || test_overflow_lossy() ||
        test_suspended() || test_function_call() || test_copy_in() || test_copy_out() ||
        test_replication() || test_corrupt_body() || test_close_drops_inflight())
        return 1;
    printf("ok\n");
    return 0;
}
