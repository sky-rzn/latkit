// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the startup / auth / session layer (task 3.2, Р16). Drives the
 * PG handler through its lk_msg_sink with synthetic messages and inspects the
 * per-connection state directly (white-box: the test includes the internal
 * pg.h) as well as the observations the query sink receives. Covers:
 *
 *   - a normal handshake: StartupMessage parameters land in the session, and
 *     AuthenticationOk emits on_session exactly once and moves to READY;
 *   - ParameterStatus contributes server_version to the labels;
 *   - the security invariant: a PasswordMessage body is never read — no byte of
 *     it reaches the session;
 *   - a budget-truncated startup salvages the readable prefix and flags the
 *     session incomplete;
 *   - a synthetic (mid-session) connection sees no startup, so no session is
 *     emitted and the labels stay unknown;
 *   - CancelRequest emits a CANCEL observation and parks the connection.
 */
#include <linux/types.h>
#include <stdio.h>
#include <string.h>

#include "conn_table.h"
#include "pg.h" /* internal: struct pg_conn, phase enum — white-box assertions */
#include "proto.h"
#include "reassembly.h" /* LK_MSG_* flags, LK_PG_* startup codes */

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* --- query-sink recorder -------------------------------------------------- */

struct rec {
    int nsessions;
    int nqueries;
    int ncancel;
    struct lk_session last_session;
    struct lk_query_obs last_obs;
};

static void rec_on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    struct rec *r = ctx;

    (void)c;
    r->nsessions++;
    r->last_session = *s;
}

static void rec_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                         const struct lk_query_obs *o)
{
    struct rec *r = ctx;

    (void)c;
    (void)s;
    r->nqueries++;
    r->last_obs = *o;
    if (o->kind == LK_Q_CANCEL)
        r->ncancel++;
}

/* --- message plumbing ----------------------------------------------------- */

static void feed(const struct lk_msg_sink *sink, struct lk_conn *c, enum lk_dir dir, char type,
                 __u16 flags, const __u8 *body, __u32 body_cap)
{
    struct lk_msg m = {
        .ts_ns = 1000,
        .type = type,
        .flags = flags,
        .len = body_cap + 4, /* protocol len: body + the 4-byte length field */
        .body_cap = body_cap,
        .body = body,
    };

    sink->on_msg(sink->ctx, c, dir, &m);
}

static __u32 put_be32(__u8 *p, __u32 v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
    return 4;
}

/* Append a NUL-terminated string, return bytes written (incl. the NUL). */
static __u32 put_cstr(__u8 *p, const char *s)
{
    __u32 n = (__u32)strlen(s) + 1;

    memcpy(p, s, n);
    return n;
}

/* A v3 StartupMessage body: code(4) + key\0val\0... + the empty-key
 * terminator. Returns the body length (== body_cap for a full capture). */
static __u32 build_startup(__u8 *buf)
{
    __u32 n = put_be32(buf, LK_PG_PROTO_V3);

    n += put_cstr(buf + n, "user");
    n += put_cstr(buf + n, "postgres");
    n += put_cstr(buf + n, "database");
    n += put_cstr(buf + n, "mydb");
    n += put_cstr(buf + n, "application_name");
    n += put_cstr(buf + n, "psql");
    buf[n++] = 0; /* empty key: end of the parameter list */
    return n;
}

/* Access the handler's private per-connection state for white-box checks. */
static struct pg_conn *pc_of(struct lk_conn *c)
{
    return c->proto_state;
}

/* --- tests ---------------------------------------------------------------- */

/* Full handshake: params parsed, on_session on AuthenticationOk, then a late
 * ParameterStatus adds server_version to the live labels. */
static int test_normal_handshake(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    __u8 body[256];
    __u32 n;

    CHECK(p);

    n = build_startup(body);
    feed(sink, &c, LK_DIR_RECV, 0, LK_MSG_STARTUP, body, n);

    struct pg_conn *pc = pc_of(&c);

    CHECK(pc && pc->phase == PG_PH_AUTH);
    CHECK(strcmp(pc->session.user, "postgres") == 0);
    CHECK(strcmp(pc->session.database, "mydb") == 0);
    CHECK(strcmp(pc->session.app, "psql") == 0);
    CHECK(pc->session.complete); /* whole startup captured */
    CHECK(r.nsessions == 0);     /* not emitted until AuthenticationOk */

    /* AuthenticationOk: int32 code 0. */
    const __u8 auth_ok[4] = {0, 0, 0, 0};

    feed(sink, &c, LK_DIR_SEND, 'R', 0, auth_ok, sizeof(auth_ok));
    CHECK(pc->phase == PG_PH_READY);
    CHECK(r.nsessions == 1);
    CHECK(strcmp(r.last_session.user, "postgres") == 0);
    CHECK(strcmp(r.last_session.database, "mydb") == 0);
    CHECK(r.last_session.complete);

    /* ParameterStatus server_version -> label, refining the live session. */
    __u8 ps[64];

    n = put_cstr(ps, "server_version");
    n += put_cstr(ps + n, "16.2 (Debian)");
    feed(sink, &c, LK_DIR_SEND, 'S', 0, ps, n);
    CHECK(strcmp(pc->session.server_version, "16.2 (Debian)") == 0);

    /* An unrelated ParameterStatus is ignored, not misfiled. */
    n = put_cstr(ps, "client_encoding");
    n += put_cstr(ps + n, "UTF8");
    feed(sink, &c, LK_DIR_SEND, 'S', 0, ps, n);
    CHECK(strcmp(pc->session.server_version, "16.2 (Debian)") == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok normal-handshake\n");
    return 0;
}

/* A non-zero auth code (MD5/SASL/...) is not AuthenticationOk: keep waiting in
 * AUTH, emit nothing. */
static int test_auth_pending(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    __u8 body[256];
    __u32 n;

    CHECK(p);
    n = build_startup(body);
    feed(sink, &c, LK_DIR_RECV, 0, LK_MSG_STARTUP, body, n);

    __u8 md5[4];

    put_be32(md5, 5); /* AuthenticationMD5Password */
    feed(sink, &c, LK_DIR_SEND, 'R', 0, md5, sizeof(md5));
    CHECK(pc_of(&c)->phase == PG_PH_AUTH);
    CHECK(r.nsessions == 0);

    /* The real AuthenticationOk then completes it. */
    const __u8 auth_ok[4] = {0};

    feed(sink, &c, LK_DIR_SEND, 'R', 0, auth_ok, sizeof(auth_ok));
    CHECK(pc_of(&c)->phase == PG_PH_READY);
    CHECK(r.nsessions == 1);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok auth-pending\n");
    return 0;
}

/* Security invariant (Р16): the PasswordMessage body is never read — no byte of
 * it reaches any session field. */
static int test_password_not_read(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    __u8 body[256];
    __u32 n;
    static const char secret[] = "hunter2-s3cr3t";

    CHECK(p);
    n = build_startup(body);
    feed(sink, &c, LK_DIR_RECV, 0, LK_MSG_STARTUP, body, n);

    /* PasswordMessage 'p': the whole body is the password. */
    feed(sink, &c, LK_DIR_RECV, 'p', 0, (const __u8 *)secret, (__u32)sizeof(secret));

    struct pg_conn *pc = pc_of(&c);

    /* No field mentions the password, and the handshake state is untouched. */
    CHECK(pc->phase == PG_PH_AUTH);
    CHECK(!strstr(pc->session.user, "hunter"));
    CHECK(!strstr(pc->session.database, "hunter"));
    CHECK(!strstr(pc->session.app, "hunter"));
    CHECK(!strstr(pc->session.server_version, "hunter"));
    CHECK(strcmp(pc->session.user, "postgres") == 0); /* startup labels intact */

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok password-not-read\n");
    return 0;
}

/* Budget-truncated startup: the captured prefix is salvaged (including a value
 * cut mid-string), the session is flagged incomplete, and nothing runs off the
 * end of the buffer. */
static int test_truncated_startup(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    __u8 body[256];
    __u32 n;

    CHECK(p);
    /* code + "user\0postgres\0database\0myd"  — the database value is cut with
     * no terminator, and the capture stops there (no trailing NUL, no more
     * pairs). LK_MSG_BODY_TRUNC marks it as a budget cut, not corruption. */
    n = put_be32(body, LK_PG_PROTO_V3);
    n += put_cstr(body + n, "user");
    n += put_cstr(body + n, "postgres");
    n += put_cstr(body + n, "database");
    memcpy(body + n, "myd", 3); /* no NUL: the value is truncated */
    n += 3;
    feed(sink, &c, LK_DIR_RECV, 0, LK_MSG_STARTUP | LK_MSG_BODY_TRUNC, body, n);

    struct pg_conn *pc = pc_of(&c);

    CHECK(pc->phase == PG_PH_AUTH);
    CHECK(strcmp(pc->session.user, "postgres") == 0); /* fully captured pair */
    CHECK(strcmp(pc->session.database, "myd") == 0);  /* salvaged prefix */
    CHECK(pc->session.app[0] == '\0');                /* never reached */
    CHECK(!pc->session.complete);

    /* AuthenticationOk still establishes the (partial) session. */
    const __u8 auth_ok[4] = {0};

    feed(sink, &c, LK_DIR_SEND, 'R', 0, auth_ok, sizeof(auth_ok));
    CHECK(r.nsessions == 1);
    CHECK(!r.last_session.complete);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok truncated-startup\n");
    return 0;
}

/* Synthetic (mid-session) connection: startup was never seen, so the parser
 * starts in READY-degraded — no session is emitted and the labels stay unknown
 * even when an AuthenticationOk-shaped message arrives. */
static int test_synthetic_no_session(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {.flags = LK_CONN_SYNTHETIC};
    const __u8 auth_ok[4] = {0};

    CHECK(p);
    /* First message on a synthetic conn: allocates state in READY, not STARTUP. */
    feed(sink, &c, LK_DIR_SEND, 'R', LK_MSG_AFTER_RESYNC, auth_ok, sizeof(auth_ok));

    struct pg_conn *pc = pc_of(&c);

    CHECK(pc && pc->phase == PG_PH_READY);
    CHECK(r.nsessions == 0);            /* no on_session without startup */
    CHECK(pc->session.user[0] == '\0'); /* labels unknown */
    CHECK(!pc->session.complete);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok synthetic-no-session\n");
    return 0;
}

/* SSLRequest is not a StartupMessage: the parser stays in STARTUP (the framer
 * handles the reply), and the v3 StartupMessage that follows drives the real
 * session. */
static int test_ssl_then_startup(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    __u8 body[256];
    __u32 n;

    CHECK(p);
    n = put_be32(body, LK_PG_SSL_REQUEST);
    feed(sink, &c, LK_DIR_RECV, 0, LK_MSG_STARTUP, body, n);
    CHECK(pc_of(&c)->phase == PG_PH_STARTUP); /* still waiting for the real one */
    CHECK(r.nsessions == 0);

    n = build_startup(body);
    feed(sink, &c, LK_DIR_RECV, 0, LK_MSG_STARTUP, body, n);
    CHECK(pc_of(&c)->phase == PG_PH_AUTH);
    CHECK(strcmp(pc_of(&c)->session.user, "postgres") == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok ssl-then-startup\n");
    return 0;
}

/* CancelRequest: a CANCEL observation, no timings, and the connection is parked
 * in IGNORE (nothing else travels on it). */
static int test_cancel(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_query = rec_on_query, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_pg_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    __u8 body[12];
    __u32 n;

    CHECK(p);
    /* CancelRequest body: code + backend pid + secret key (the parser only
     * reads the code). */
    n = put_be32(body, LK_PG_CANCEL_REQUEST);
    n += put_be32(body + n, 4321);       /* pid */
    n += put_be32(body + n, 0xdeadbeef); /* secret — never inspected */
    feed(sink, &c, LK_DIR_RECV, 0, LK_MSG_STARTUP, body, n);

    CHECK(r.nqueries == 1);
    CHECK(r.ncancel == 1);
    CHECK(r.last_obs.kind == LK_Q_CANCEL);
    CHECK(r.last_obs.ts_start_ns == 0); /* no timings */
    CHECK(r.nsessions == 0);
    CHECK(pc_of(&c)->phase == PG_PH_IGNORE);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok cancel\n");
    return 0;
}

int main(void)
{
    if (test_normal_handshake() || test_auth_pending() || test_password_not_read() ||
        test_truncated_startup() || test_synthetic_no_session() || test_ssl_then_startup() ||
        test_cancel())
        return 1;
    printf("ok\n");
    return 0;
}
