// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the MySQL connection phase (MYSQL.md М3, my_session.c).
 * Drives the handler through its lk_msg_sink with synthetic packets — the
 * framer's view: connection-phase packets are untyped and LK_MSG_STARTUP-
 * flagged, commands carry their byte in lk_msg.type — and checks the session
 * the query sink receives. Covers:
 *
 *   - the happy handshake: greeting / HandshakeResponse41 / final OK ->
 *     on_session with user, database, app (connect attrs) and version;
 *   - the MariaDB `5.5.5-` version prefix strip;
 *   - the short SSLRequest: capabilities recorded, session parsed from the
 *     full response that repeats inside TLS;
 *   - the auth cycle: AuthSwitchRequest / AuthMoreData pass-through (bodies
 *     never parsed), ERR -> no session;
 *   - `_client_name` as the app fallback when program_name is absent;
 *   - a response truncated by the capture budget: labels salvaged,
 *     complete=false;
 *   - live labels: COM_INIT_DB commits on OK (not on ERR), COM_CHANGE_USER
 *     re-auths and commits user+db, SESSION_TRACK_SCHEMA follows `USE db`;
 *   - synthetic entry: no handshake, no session, caps unknown;
 *   - the promote path: the final OK lost to a hole, the first command
 *     salvages the session (incomplete);
 *   - compression (РМ7): labels parsed, then the connection goes blind.
 */
#include <linux/types.h>
#include <stdio.h>
#include <string.h>

#include "conn_table.h"
#include "my.h" /* internal: struct my_conn, phases — white-box assertions */
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
    int nsessions;
    int nqueries;
    struct lk_session last;
};

static void rec_on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    struct rec *r = ctx;

    (void)c;
    r->nsessions++;
    r->last = *s;
}

static void rec_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                         const struct lk_query_obs *o)
{
    struct rec *r = ctx;

    (void)c;
    (void)s;
    (void)o;
    r->nqueries++;
}

/* --- packet builders ------------------------------------------------------- */

static void feed(const struct lk_msg_sink *sink, struct lk_conn *c, enum lk_dir dir, char type,
                 __u16 flags, const void *body, __u32 n, __u64 ts)
{
    struct lk_msg m = {
        .ts_ns = ts, .type = type, .flags = flags, .len = n, .body_cap = n, .body = body};

    sink->on_msg(sink->ctx, c, dir, &m);
}

/* Server greeting: protocol 10 + version cstring (the only fields read). */
static void greeting(const struct lk_msg_sink *sink, struct lk_conn *c, const char *ver)
{
    __u8 body[64];
    __u32 n = 0;

    body[n++] = 10;
    memcpy(body + n, ver, strlen(ver) + 1);
    n += (__u32)strlen(ver) + 1;
    feed(sink, c, LK_DIR_SEND, 0, LK_MSG_STARTUP, body, n, 100);
}

/* HandshakeResponse41: caps, filler, user, auth(u8-len), db, [attrs]. attrs
 * is a preassembled lenenc key/value blob (NULL = none). */
static __u32 build_response(__u8 *body, __u32 caps, __u32 mcaps, const char *user, const char *db,
                            const __u8 *attrs, __u32 attrs_len)
{
    __u32 n = 0;

    body[n++] = (__u8)caps;
    body[n++] = (__u8)(caps >> 8);
    body[n++] = (__u8)(caps >> 16);
    body[n++] = (__u8)(caps >> 24);
    memset(body + n, 0, 4); /* max_packet_size */
    n += 4;
    body[n++] = 0x2d; /* charset */
    memset(body + n, 0, 19);
    n += 19;
    body[n++] = (__u8)mcaps;
    body[n++] = (__u8)(mcaps >> 8);
    body[n++] = (__u8)(mcaps >> 16);
    body[n++] = (__u8)(mcaps >> 24);
    if (!user)
        return n; /* the short SSLRequest ends right here */
    memcpy(body + n, user, strlen(user) + 1);
    n += (__u32)strlen(user) + 1;
    body[n++] = 0; /* auth response length (u8): empty */
    if (caps & MY_CAP_CONNECT_WITH_DB) {
        memcpy(body + n, db, strlen(db) + 1);
        n += (__u32)strlen(db) + 1;
    }
    if (caps & MY_CAP_PLUGIN_AUTH) {
        memcpy(body + n, "mysql_native_password", 22);
        n += 22;
    }
    if (caps & MY_CAP_CONNECT_ATTRS) {
        body[n++] = (__u8)attrs_len; /* lenenc total (fits a byte here) */
        memcpy(body + n, attrs, attrs_len);
        n += attrs_len;
    }
    return n;
}

static void response(const struct lk_msg_sink *sink, struct lk_conn *c, __u32 caps, __u32 mcaps,
                     const char *user, const char *db, const __u8 *attrs, __u32 attrs_len)
{
    __u8 body[256];
    __u32 n = build_response(body, caps, mcaps, user, db, attrs, attrs_len);

    feed(sink, c, LK_DIR_RECV, 0, LK_MSG_STARTUP, body, n, 110);
}

/* Final auth OK: affected=0, insert_id=0, status, warnings. */
static void auth_ok(const struct lk_msg_sink *sink, struct lk_conn *c)
{
    static const __u8 body[7] = {0x00, 0, 0, 0x02, 0x00, 0, 0};

    feed(sink, c, LK_DIR_SEND, 0, LK_MSG_STARTUP, body, sizeof(body), 120);
}

/* A frontend command packet: type = the command byte. */
static void cmd(const struct lk_msg_sink *sink, struct lk_conn *c, const void *body, __u32 n,
                __u64 ts)
{
    feed(sink, c, LK_DIR_RECV, (char)((const __u8 *)body)[0], 0, body, n, ts);
}

/* Backend OK with a status word (command phase, untyped). */
static void be_ok(const struct lk_msg_sink *sink, struct lk_conn *c, __u16 status, __u64 ts)
{
    __u8 body[7] = {0x00, 0, 0, (__u8)status, (__u8)(status >> 8), 0, 0};

    feed(sink, c, LK_DIR_SEND, 0, 0, body, sizeof(body), ts);
}

#define BASE_CAPS                                                                                  \
    (MY_CAP_MYSQL | MY_CAP_PROTOCOL_41 | MY_CAP_TRANSACTIONS | MY_CAP_CONNECT_WITH_DB |            \
     MY_CAP_PLUGIN_AUTH | MY_CAP_DEPRECATE_EOF)

/* program_name=app1 as a connect-attrs blob. */
static const __u8 ATTRS_PROGRAM[] = {12,  'p', 'r', 'o', 'g', 'r', 'a', 'm', '_',
                                     'n', 'a', 'm', 'e', 4,   'a', 'p', 'p', '1'};
static const __u8 ATTRS_CLIENT[] = {12,  '_', 'c', 'l', 'i', 'e', 'n', 't', '_', 'n',
                                    'a', 'm', 'e', 5,   'l', 'i', 'b', 'm', 'y'};

/* --- tests ----------------------------------------------------------------- */

static int test_happy_handshake(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    struct my_conn *pc;

    CHECK(p);
    greeting(sink, &c, "8.4.10");
    response(sink, &c, BASE_CAPS | MY_CAP_CONNECT_ATTRS, 0, "bob", "shop", ATTRS_PROGRAM,
             sizeof(ATTRS_PROGRAM));
    CHECK(r.nsessions == 0); /* not until the final OK */
    auth_ok(sink, &c);

    CHECK(r.nsessions == 1);
    CHECK(strcmp(r.last.user, "bob") == 0);
    CHECK(strcmp(r.last.database, "shop") == 0);
    CHECK(strcmp(r.last.app, "app1") == 0);
    CHECK(strcmp(r.last.server_version, "8.4.10") == 0);
    CHECK(r.last.complete);

    pc = c.proto_state;
    CHECK(pc && pc->phase == MY_PH_READY && pc->caps_known);
    CHECK(pc->caps == (BASE_CAPS | MY_CAP_CONNECT_ATTRS));
    CHECK(lk_proto_stats(p)->sessions == 1);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok happy-handshake\n");
    return 0;
}

/* MariaDB: the 5.5.5- replication-compat prefix is stripped; a client with
 * CLIENT_MYSQL clear exposes its extended caps through the filler u32. */
static int test_mariadb(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    struct my_conn *pc;

    CHECK(p);
    greeting(sink, &c, "5.5.5-10.11.6-Mar");
    response(sink, &c, (BASE_CAPS & ~(MY_CAP_MYSQL | MY_CAP_DEPRECATE_EOF)), MY_MCAP_PROGRESS,
             "root", "test", NULL, 0);
    auth_ok(sink, &c);

    CHECK(r.nsessions == 1);
    CHECK(strcmp(r.last.server_version, "10.11.6-Mar") == 0);
    pc = c.proto_state;
    CHECK(pc && pc->mcaps == MY_MCAP_PROGRESS);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok mariadb\n");
    return 0;
}

/* The mysql-dialect client (CLIENT_MYSQL set): the filler u32 is noise, not
 * MariaDB caps — it must be ignored even when nonzero. */
static int test_filler_not_mcaps(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    struct my_conn *pc;

    CHECK(p);
    greeting(sink, &c, "8.4.10");
    response(sink, &c, BASE_CAPS, 0xdeadbeef, "u", "d", NULL, 0);
    auth_ok(sink, &c);
    pc = c.proto_state;
    CHECK(pc && pc->mcaps == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok filler-not-mcaps\n");
    return 0;
}

/* Short SSLRequest, then the full response repeating inside TLS (М5): the
 * session comes from the decrypted copy; the short packet only records caps. */
static int test_ssl_request(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    struct my_conn *pc;

    CHECK(p);
    greeting(sink, &c, "8.4.10");
    response(sink, &c, BASE_CAPS | 0x00000800u /* CLIENT_SSL */, 0, NULL, NULL, NULL, 0);
    pc = c.proto_state;
    CHECK(pc && pc->sess == MY_S_RESPONSE); /* still awaiting the real one */
    CHECK(r.nsessions == 0);

    /* The full response arrives on the decrypted channel. */
    response(sink, &c, BASE_CAPS | 0x00000800u, 0, "tls_user", "tls_db", NULL, 0);
    auth_ok(sink, &c);
    CHECK(r.nsessions == 1);
    CHECK(strcmp(r.last.user, "tls_user") == 0);
    CHECK(strcmp(r.last.database, "tls_db") == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok ssl-request\n");
    return 0;
}

/* Auth switch round-trips: bodies pass through unparsed, the session waits
 * for the final OK; an ERR instead means no session at all. */
static int test_auth_cycle(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    static const __u8 auth_switch[] = {0xfe, 'c', 'a', 'c', 'h', 'i', 'n', 'g', 0};
    static const __u8 more_data[] = {0x01, 0x04};
    static const __u8 raw_reply[] = {0xaa, 0xbb, 0xcc};

    CHECK(p);
    greeting(sink, &c, "8.4.10");
    response(sink, &c, BASE_CAPS, 0, "u", "d", NULL, 0);
    feed(sink, &c, LK_DIR_SEND, 0, LK_MSG_STARTUP, auth_switch, sizeof(auth_switch), 111);
    feed(sink, &c, LK_DIR_RECV, 0, LK_MSG_STARTUP, raw_reply, sizeof(raw_reply), 112);
    feed(sink, &c, LK_DIR_SEND, 0, LK_MSG_STARTUP, more_data, sizeof(more_data), 113);
    CHECK(r.nsessions == 0);
    auth_ok(sink, &c);
    CHECK(r.nsessions == 1);
    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);

    /* Auth failure: ERR ends the exchange, no session. */
    struct rec r2 = {0};
    struct lk_query_sink qs2 = {.ctx = &r2, .on_session = rec_on_session};
    struct lk_proto *p2 = lk_proto_my_new(&qs2);
    const struct lk_msg_sink *sink2 = lk_proto_sink(p2);
    struct lk_conn c2 = {0};
    static const __u8 err[] = {0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0', 'n', 'o'};

    greeting(sink2, &c2, "8.4.10");
    response(sink2, &c2, BASE_CAPS, 0, "u", "d", NULL, 0);
    feed(sink2, &c2, LK_DIR_SEND, 0, LK_MSG_STARTUP, err, sizeof(err), 114);
    CHECK(r2.nsessions == 0);
    CHECK(lk_proto_stats(p2)->sessions == 0);

    sink2->on_conn_close(sink2->ctx, &c2);
    lk_proto_free(p2);
    printf("ok auth-cycle\n");
    return 0;
}

/* _client_name labels the app only when program_name is absent. */
static int test_app_fallback(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};

    CHECK(p);
    greeting(sink, &c, "8.4.10");
    response(sink, &c, BASE_CAPS | MY_CAP_CONNECT_ATTRS, 0, "u", "d", ATTRS_CLIENT,
             sizeof(ATTRS_CLIENT));
    auth_ok(sink, &c);
    CHECK(r.nsessions == 1);
    CHECK(strcmp(r.last.app, "libmy") == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok app-fallback\n");
    return 0;
}

/* A response cut mid-user by the capture budget: the prefix is salvaged and
 * the session is honest about being incomplete. */
static int test_truncated_response(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    __u8 body[256];
    __u32 n = build_response(body, BASE_CAPS, 0, "someuser", "somedb", NULL, 0);
    __u32 cut = 32 + 4; /* caps block + "some": the user's NUL is gone */
    struct lk_msg m = {
        .ts_ns = 110,
        .flags = LK_MSG_STARTUP | LK_MSG_BODY_TRUNC,
        .len = n,
        .body_cap = cut,
        .body = body,
    };

    CHECK(p);
    greeting(sink, &c, "8.4.10");
    sink->on_msg(sink->ctx, &c, LK_DIR_RECV, &m);

    struct my_conn *pc = c.proto_state;

    CHECK(pc);
    CHECK(strcmp(pc->session.user, "some") == 0); /* salvaged prefix */
    /* The exchange still ends with an OK — session emitted, incomplete. */
    auth_ok(sink, &c);
    CHECK(r.nsessions == 1);
    CHECK(!r.last.complete);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok truncated-response\n");
    return 0;
}

/* COM_INIT_DB: the db label changes on OK and only on OK. */
static int test_init_db(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    static const __u8 use_other[] = {MY_COM_INIT_DB, 'o', 't', 'h', 'e', 'r'};
    static const __u8 use_bad[] = {MY_COM_INIT_DB, 'n', 'o', 'p', 'e'};
    static const __u8 err[] = {0xff, 0x19, 0x04, '#', '4', '2', '0', '0', '0'};
    struct my_conn *pc;

    CHECK(p);
    greeting(sink, &c, "8.4.10");
    response(sink, &c, BASE_CAPS, 0, "u", "start_db", NULL, 0);
    auth_ok(sink, &c);
    pc = c.proto_state;
    CHECK(pc);

    cmd(sink, &c, use_other, sizeof(use_other), 200);
    CHECK(strcmp(pc->session.database, "start_db") == 0); /* not yet */
    be_ok(sink, &c, 0, 210);
    CHECK(strcmp(pc->session.database, "other") == 0);
    CHECK(r.nqueries == 0); /* a service command is not an observation (РМ8) */

    cmd(sink, &c, use_bad, sizeof(use_bad), 220);
    feed(sink, &c, LK_DIR_SEND, 0, 0, err, sizeof(err), 230);
    CHECK(strcmp(pc->session.database, "other") == 0); /* ERR commits nothing */

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok init-db\n");
    return 0;
}

/* COM_CHANGE_USER: an auth cycle in the command phase; user+db commit on the
 * final OK, the prepared-statement cache is dropped, no second on_session. */
static int test_change_user(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    __u8 body[64];
    __u32 n = 0;
    struct my_conn *pc;

    CHECK(p);
    greeting(sink, &c, "8.4.10");
    response(sink, &c, BASE_CAPS, 0, "olduser", "olddb", NULL, 0);
    auth_ok(sink, &c);
    pc = c.proto_state;
    CHECK(pc);

    body[n++] = MY_COM_CHANGE_USER;
    memcpy(body + n, "newuser", 8);
    n += 8;
    body[n++] = 0; /* auth response length */
    memcpy(body + n, "newdb", 6);
    n += 6;
    cmd(sink, &c, body, n, 300);
    CHECK(pc->phase == MY_PH_HANDSHAKE && pc->sess == MY_S_AUTH);
    CHECK(strcmp(pc->session.user, "olduser") == 0); /* not until OK */
    feed(sink, &c, LK_DIR_SEND, 0, 0, (const __u8[]){0x00, 0, 0, 0x02, 0x00, 0, 0}, 7, 310);

    CHECK(strcmp(pc->session.user, "newuser") == 0);
    CHECK(strcmp(pc->session.database, "newdb") == 0);
    CHECK(pc->phase == MY_PH_READY);
    CHECK(r.nsessions == 1); /* label update, not a new session */

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok change-user\n");
    return 0;
}

/* SESSION_TRACK_SCHEMA in an OK (a plain `USE db` under CLIENT_SESSION_TRACK)
 * updates the live db label. */
static int test_session_track_schema(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    static const __u8 use_q[] = {MY_COM_QUERY, 'U', 'S', 'E', ' ', 'w', 'w'};
    /* OK + SERVER_SESSION_STATE_CHANGED + track blob {schema: "ww"}. */
    static const __u8 ok[] = {0x00, 0, 0, 0x00, 0x40, 0, 0, /* header..warnings */
                              0,                            /* info: empty lenenc str */
                              5,                            /* state blob total */
                              0x01, 3, 2, 'w',  'w'};       /* SCHEMA, len, lenenc "ww" */
    struct my_conn *pc;

    CHECK(p);
    greeting(sink, &c, "8.4.10");
    response(sink, &c, BASE_CAPS | MY_CAP_SESSION_TRACK, 0, "u", "d", NULL, 0);
    auth_ok(sink, &c);
    pc = c.proto_state;
    CHECK(pc);

    cmd(sink, &c, use_q, sizeof(use_q), 400);
    feed(sink, &c, LK_DIR_SEND, 0, 0, ok, sizeof(ok), 410);
    CHECK(strcmp(pc->session.database, "ww") == 0);
    CHECK(r.nqueries == 1); /* USE is a COM_QUERY: it is an observation */

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok session-track-schema\n");
    return 0;
}

/* Synthetic entry: no handshake will ever come — the connection starts in
 * READY with unknown caps and no labels; no session is emitted. */
static int test_synthetic(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    static const __u8 q[] = {MY_COM_QUERY, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'};
    static const __u8 ok[] = {0x00, 0, 0, 0x02, 0x00, 0, 0};
    struct my_conn *pc;

    CHECK(p);
    c.flags = LK_CONN_SYNTHETIC;
    cmd(sink, &c, q, sizeof(q), 500);
    pc = c.proto_state;
    CHECK(pc && pc->phase != MY_PH_HANDSHAKE && !pc->caps_known);
    feed(sink, &c, LK_DIR_SEND, 0, 0, ok, sizeof(ok), 510);
    CHECK(r.nsessions == 0);
    CHECK(r.nqueries == 1); /* the unit itself is honest */

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok synthetic\n");
    return 0;
}

/* The final OK fell into a hole: the first command promotes the phase and
 * salvages the session (labels known from the response, incomplete). */
static int test_promote(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    static const __u8 q[] = {MY_COM_QUERY, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'};
    static const __u8 ok[] = {0x00, 0, 0, 0x02, 0x00, 0, 0};

    CHECK(p);
    greeting(sink, &c, "8.4.10");
    response(sink, &c, BASE_CAPS, 0, "u", "d", NULL, 0);
    /* No auth OK — straight to a command (the framer already forced the
     * command phase on its side). */
    cmd(sink, &c, q, sizeof(q), 600);
    CHECK(r.nsessions == 1);
    CHECK(strcmp(r.last.user, "u") == 0);
    CHECK(!r.last.complete);
    feed(sink, &c, LK_DIR_SEND, 0, 0, ok, sizeof(ok), 610);
    CHECK(r.nqueries == 1);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok promote\n");
    return 0;
}

/* Compression (РМ7): the framer flips the connection to LK_CONN_IGNORE on
 * the final OK; the handler still emits the session (a named blind spot),
 * then observes nothing. */
static int test_compress_blind(void)
{
    struct rec r = {0};
    struct lk_query_sink qs = {.ctx = &r, .on_session = rec_on_session, .on_query = rec_on_query};
    struct lk_proto *p = lk_proto_my_new(&qs);
    const struct lk_msg_sink *sink = lk_proto_sink(p);
    struct lk_conn c = {0};
    static const __u8 q[] = {MY_COM_QUERY, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'};
    struct my_conn *pc;

    CHECK(p);
    greeting(sink, &c, "8.4.10");
    response(sink, &c, BASE_CAPS | 0x00000020u /* CLIENT_COMPRESS */, 0, "u", "d", NULL, 0);
    c.flags |= LK_CONN_IGNORE; /* what my_frame's pre_emit does on this OK */
    auth_ok(sink, &c);
    pc = c.proto_state;
    CHECK(pc && pc->phase == MY_PH_IGNORE);
    CHECK(r.nsessions == 1); /* labels were on the wire in plaintext */

    cmd(sink, &c, q, sizeof(q), 700); /* would be misframed garbage live */
    CHECK(r.nqueries == 0);

    sink->on_conn_close(sink->ctx, &c);
    lk_proto_free(p);
    printf("ok compress-blind\n");
    return 0;
}

int main(void)
{
    if (test_happy_handshake() || test_mariadb() || test_filler_not_mcaps() || test_ssl_request() ||
        test_auth_cycle() || test_app_fallback() || test_truncated_response() || test_init_db() ||
        test_change_user() || test_session_track_schema() || test_synthetic() || test_promote() ||
        test_compress_blind())
        return 1;
    printf("ok\n");
    return 0;
}
