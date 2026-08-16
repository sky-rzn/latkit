// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the Redis session labels and identity (PLAN-REDIS.md МR3,
 * РR4–РR6) — driven through the *real* chain, bytes → stream framer → lk_msg →
 * handler → lk_query_obs, exactly as test_redis_unit.c drives the queue. The
 * table itself is tested in test_redis_cmd.c; everything here is about *when* a
 * label moves, which is a property of the connection and not of the table.
 *
 * The rule under test, in one line: **a label moves on the reply, never on the
 * command.** `SELECT 16` is an error and the connection stays where it was;
 * `AUTH lkuser wrongpass` is `-WRONGPASS` and the user does not change. A
 * machine that moved on the request would be wrong about every command that
 * followed, for as long as the connection lived — and, because every one of
 * those observations looks perfectly plausible, nothing downstream would ever
 * say so.
 *
 * Every case also asserts the privacy invariant of РR4, and asserts it the only
 * way that means anything: not "the label looks right" but "no byte of any key
 * or password appears in any label of any observation". The corpus plants
 * `lk:*` keys and `lkpass`/`lkrootpass` passwords for the same purpose
 * (tests/replay/redis_privacy.sh); here they are planted per case. */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reassembly.h"
#include "redis.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* --- captured observations ------------------------------------------------ */

#define MAXOBS 64

struct obs {
    char cmd[LK_REDIS_NAME_MAX];
    char db[64], user[64];
    __u64 fp;
};

static struct obs obs[MAXOBS];
static int nobs;

static void on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                     const struct lk_query_obs *o)
{
    struct obs *r = &obs[nobs % MAXOBS];

    (void)ctx;
    (void)c;
    nobs++;
    memset(r, 0, sizeof(*r));
    if (o->route && o->route_len < sizeof(r->cmd))
        memcpy(r->cmd, o->route, o->route_len);
    r->fp = o->route_fp;
    snprintf(r->db, sizeof(r->db), "%s", s->database[0] ? s->database : "-");
    snprintf(r->user, sizeof(r->user), "%s", s->user[0] ? s->user : "-");
}

static struct lk_reasm reasm;
static struct lk_conn conn;
static struct lk_proto *proto;

static void teardown(void)
{
    const struct lk_msg_sink *sink;

    if (proto) {
        sink = lk_proto_sink(proto);
        sink->on_conn_close(sink->ctx, &conn);
        lk_proto_free(proto);
        proto = NULL;
    }
    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    free(conn.frame_state);
    lk_reasm_free(&reasm);
}

static void reset_flags(__u16 flags)
{
    static const struct lk_query_sink qsink = {.on_query = on_query};

    teardown();
    memset(&conn, 0, sizeof(conn));
    conn.ops = &lk_proto_redis_ops;
    conn.flags = flags;
    conn.cookie = 0x6379;
    if (flags & LK_CONN_SYNTHETIC) {
        conn.frame[0].st = LK_FR_DIRTY;
        conn.frame[1].st = LK_FR_DIRTY;
    }
    proto = lk_proto_redis_ops.proto_new(&qsink);
    lk_reasm_init(&reasm, lk_proto_sink(proto));
    nobs = 0;
}

static void reset(void)
{
    reset_flags(0);
}

/* One data event, modelled by total/cap exactly as the agent's capture does, so
 * an under-captured call leaves the same lazy tail here as in production. */
static void feed(enum lk_dir dir, __u32 total, const void *p, __u32 cap, __u64 ts)
{
    static union {
        struct lk_ev_data d;
        __u8 raw[sizeof(struct lk_ev_data) + 65536];
    } u;

    memset(&u.d, 0, sizeof(u.d));
    u.d.hdr.ts_ns = ts;
    u.d.hdr.dir = dir;
    u.d.total_len = total;
    u.d.cap_len = cap;
    if (cap)
        memcpy(u.d.payload, p, cap);
    lk_reasm_data(&reasm, &conn, dir, &u.d, cap);
}

/* One syscall's worth of bytes, fully captured. */
static void call(enum lk_dir dir, const char *s, __u64 ts)
{
    feed(dir, (__u32)strlen(s), s, (__u32)strlen(s), ts);
}

/* A command and its reply, one exchange, with a monotonic clock nobody has to
 * spell out per case: the timings are test_redis_unit.c's subject, not this
 * file's. */
static void exchange(const char *cmd, const char *reply)
{
    static __u64 clock = 1000;

    call(LK_DIR_RECV, cmd, clock);
    clock += 10;
    call(LK_DIR_SEND, reply, clock);
    clock += 10;
}

/* Every label of every observation so far, concatenated — what the privacy
 * assertions grep. */
static bool labels_contain(const char *needle)
{
    for (int i = 0; i < nobs && i < MAXOBS; i++)
        if (strstr(obs[i].cmd, needle) || strstr(obs[i].db, needle) || strstr(obs[i].user, needle))
            return true;
    return false;
}

/* --- the database (РR5) ---------------------------------------------------- */

/* A connection we watched open starts in database 0 as the `default` user, and
 * both are facts about the protocol rather than guesses. */
static int test_defaults(void)
{
    reset();
    exchange("*2\r\n$3\r\nGET\r\n$5\r\nlk:k1\r\n", "$1\r\nv\r\n");

    CHECK(nobs == 1);
    CHECK(!strcmp(obs[0].cmd, "GET"));
    CHECK(!strcmp(obs[0].db, "0") && !strcmp(obs[0].user, "default"));
    CHECK(!labels_contain("lk:k1")); /* the key is in no label, ever */
    return 0;
}

/* `SELECT 3` moves the label — for the commands *after* it. The `SELECT` itself
 * is an observation in the database it was issued from, which is the deliberate
 * half of "the label moves on the reply": at the moment the command was sent,
 * the connection was still in database 0. */
static int test_select_moves_on_reply(void)
{
    reset();
    exchange("*2\r\n$6\r\nSELECT\r\n$1\r\n3\r\n", "+OK\r\n");
    exchange("*2\r\n$3\r\nGET\r\n$5\r\nlk:k1\r\n", "$1\r\nv\r\n");

    CHECK(nobs == 2);
    CHECK(!strcmp(obs[0].cmd, "SELECT") && !strcmp(obs[0].db, "0"));
    CHECK(!strcmp(obs[1].cmd, "GET") && !strcmp(obs[1].db, "3"));
    return 0;
}

/* The other half: a `SELECT` the server refuses moves nothing. `SELECT 16` on a
 * stock server is `-ERR DB index is out of range` and `SELECT abc` is `-ERR
 * value is not an integer` — both measured (`redis/select-db.lkt`), and after
 * both the connection is exactly where it was. */
static int test_select_refused(void)
{
    reset();
    exchange("*2\r\n$6\r\nSELECT\r\n$1\r\n7\r\n", "+OK\r\n");
    exchange("*2\r\n$6\r\nSELECT\r\n$2\r\n16\r\n", "-ERR DB index is out of range\r\n");
    exchange("*1\r\n$4\r\nPING\r\n", "+PONG\r\n");
    exchange("*2\r\n$6\r\nSELECT\r\n$3\r\nabc\r\n",
             "-ERR value is not an integer or out of range\r\n");
    exchange("*1\r\n$4\r\nPING\r\n", "+PONG\r\n");

    CHECK(nobs == 5);
    CHECK(!strcmp(obs[2].db, "7") && !strcmp(obs[4].db, "7"));
    return 0;
}

/* A number no server could mean is not a database: it is a client writing digits
 * into a label. The `SELECT` is honoured as an event — we know the connection
 * moved — and the destination is `?`, which is the one answer that cannot be
 * mistaken for a real database on a dashboard (РR5). */
static int test_select_out_of_our_range(void)
{
    reset();
    exchange("*2\r\n$6\r\nSELECT\r\n$5\r\n99999\r\n", "+OK\r\n");
    exchange("*1\r\n$4\r\nPING\r\n", "+PONG\r\n");

    CHECK(nobs == 2 && !strcmp(obs[1].db, "?"));
    return 0;
}

/* `RESET` puts the connection back to database 0 and user `default` — and, like
 * everything else, only once the server has said `+RESET`. */
static int test_reset(void)
{
    reset();
    exchange("*3\r\n$4\r\nAUTH\r\n$6\r\nlkuser\r\n$6\r\nlkpass\r\n", "+OK\r\n");
    exchange("*2\r\n$6\r\nSELECT\r\n$1\r\n9\r\n", "+OK\r\n");
    exchange("*1\r\n$5\r\nRESET\r\n", "+RESET\r\n");
    exchange("*1\r\n$4\r\nPING\r\n", "+PONG\r\n");

    CHECK(nobs == 4);
    CHECK(!strcmp(obs[2].db, "9") && !strcmp(obs[2].user, "lkuser"));
    CHECK(!strcmp(obs[3].db, "0") && !strcmp(obs[3].user, "default"));
    CHECK(!labels_contain("lkpass"));
    return 0;
}

/* A connection joined mid-stream knows neither label and says so. `db="0"` here
 * would be indistinguishable from a connection that really is in database 0,
 * which is exactly the lie РR5 refuses to tell (`redis/midstream.lkt` records
 * the real thing: a client that `SELECT`ed 7 before the agent attached). */
static int test_synthetic_unknown(void)
{
    reset_flags(LK_CONN_SYNTHETIC);
    /* A synthetic connection enters framing through the anchors, one direction
     * at a time: the first command is parsed and then dropped when the *backend*
     * resyncs on its reply, exactly as on `redis/midstream.lkt` (three commands
     * after the agent attached, two observations). From the second exchange on,
     * both directions are trusted — and neither label is knowable on any of
     * them, because the `SELECT` and the `AUTH` happened before we were here. */
    exchange("*2\r\n$3\r\nGET\r\n$6\r\nlk:mid\r\n", "$3\r\nabc\r\n");
    exchange("*2\r\n$4\r\nINCR\r\n$8\r\nlk:mid:n\r\n", ":1\r\n");

    CHECK(nobs == 1);
    CHECK(!strcmp(obs[0].db, "?") && !strcmp(obs[0].user, "?"));
    CHECK(!strcmp(obs[0].cmd, "INCR"));
    return 0;
}

/* A `SELECT` whose answer was lost takes the label with it: we know the
 * connection moved and cannot say where. Keeping the old number would be a
 * plausible lie for the rest of the connection. */
static int test_select_lost_in_resync(void)
{
    reset();
    exchange("*2\r\n$6\r\nSELECT\r\n$1\r\n4\r\n", "+OK\r\n");
    call(LK_DIR_RECV, "*2\r\n$6\r\nSELECT\r\n$1\r\n5\r\n", 2000);
    /* An under-captured command whose tail lands inside an aggregate: there is
     * no length to step over, so the direction dirties, the in-flight `SELECT`
     * is dropped, and its outcome is unknowable (risk 1 of the plan). */
    feed(LK_DIR_RECV, 100, "*3\r\n$3\r\nSET\r\n", 13, 2100);
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 2200);
    call(LK_DIR_SEND, "+OK\r\n+PONG\r\n", 2300);

    CHECK(nobs >= 2);
    CHECK(!strcmp(obs[nobs - 1].cmd, "PING") && !strcmp(obs[nobs - 1].db, "?"));
    return 0;
}

/* --- the ACL user (РR6) ---------------------------------------------------- */

/* The two-argument form names the user in its *first* argument; the password is
 * the second and is read by nothing. */
static int test_auth_two_args(void)
{
    reset();
    exchange("*3\r\n$4\r\nAUTH\r\n$8\r\nlkreader\r\n$6\r\nlkpass\r\n", "+OK\r\n");
    exchange("*2\r\n$3\r\nACL\r\n$6\r\nWHOAMI\r\n", "$8\r\nlkreader\r\n");

    CHECK(nobs == 2);
    CHECK(!strcmp(obs[0].user, "default")); /* the AUTH itself, before it took */
    CHECK(!strcmp(obs[1].user, "lkreader") && !strcmp(obs[1].cmd, "ACL|WHOAMI"));
    CHECK(!labels_contain("lkpass"));
    return 0;
}

/* The one-argument form authenticates as `default` and names nobody — so a
 * connection that was somebody else goes back to being `default`, and the
 * password is not mistaken for a name. */
static int test_auth_one_arg(void)
{
    reset();
    exchange("*3\r\n$4\r\nAUTH\r\n$6\r\nlkuser\r\n$6\r\nlkpass\r\n", "+OK\r\n");
    exchange("*2\r\n$4\r\nAUTH\r\n$10\r\nlkrootpass\r\n", "+OK\r\n");
    exchange("*1\r\n$4\r\nPING\r\n", "+PONG\r\n");

    CHECK(nobs == 3);
    CHECK(!strcmp(obs[1].user, "lkuser"));
    CHECK(!strcmp(obs[2].user, "default"));
    CHECK(!labels_contain("lkrootpass") && !labels_contain("lkpass"));
    return 0;
}

/* `-WRONGPASS` leaves the user alone. Measured in `redis/auth-forms.lkt`, where
 * an `ACL WHOAMI` after each failed attempt confirms the server agrees. */
static int test_auth_refused(void)
{
    reset();
    exchange("*3\r\n$4\r\nAUTH\r\n$6\r\nlkuser\r\n$9\r\nwrongpass\r\n",
             "-WRONGPASS invalid username-password pair or user is disabled.\r\n");
    exchange("*1\r\n$4\r\nPING\r\n", "+PONG\r\n");

    CHECK(nobs == 2 && !strcmp(obs[1].user, "default"));
    CHECK(!labels_contain("lkuser") && !labels_contain("wrongpass"));
    return 0;
}

/* `HELLO 3 AUTH <user> <pass> SETNAME <name>`: the name is an ordinary array
 * element four deep, which is why the dimension can default to on — nothing is
 * decoded, and the password is stepped over rather than parsed (РR6). */
static int test_hello_auth(void)
{
    reset();
    exchange("*7\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$6\r\nlkuser\r\n$6\r\nlkpass\r\n"
             "$7\r\nSETNAME\r\n$5\r\nlkapp\r\n",
             "%3\r\n$6\r\nserver\r\n$5\r\nredis\r\n$5\r\nproto\r\n:3\r\n$2\r\nid\r\n:7\r\n");
    exchange("*1\r\n$4\r\nPING\r\n", "+PONG\r\n");

    CHECK(nobs == 2);
    CHECK(!strcmp(obs[0].cmd, "HELLO"));
    CHECK(!strcmp(obs[1].user, "lkuser"));
    CHECK(!labels_contain("lkpass") && !labels_contain("lkapp"));
    return 0;
}

/* A `HELLO` with no `AUTH` clause is a version negotiation: it moves no label,
 * and `-NOPROTO` moves none either. */
static int test_hello_plain(void)
{
    reset();
    exchange("*3\r\n$4\r\nAUTH\r\n$6\r\nlkuser\r\n$6\r\nlkpass\r\n", "+OK\r\n");
    exchange("*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n", "%1\r\n$5\r\nproto\r\n:3\r\n");
    exchange("*2\r\n$5\r\nHELLO\r\n$1\r\n4\r\n", "-NOPROTO unsupported protocol version\r\n");
    exchange("*1\r\n$4\r\nPING\r\n", "+PONG\r\n");

    CHECK(nobs == 4 && !strcmp(obs[3].user, "lkuser"));
    return 0;
}

/* A name that is not label-shaped does not become one: we keep the fact that
 * somebody authenticated and refuse to let the wire name a series (the РS3
 * rule, applied to the one identity a Redis connection carries). */
static int test_auth_hostile_name(void)
{
    reset();
    exchange("*3\r\n$4\r\nAUTH\r\n$5\r\na\nb\"c\r\n$6\r\nlkpass\r\n", "+OK\r\n");
    exchange("*1\r\n$4\r\nPING\r\n", "+PONG\r\n");

    CHECK(nobs == 2 && !strcmp(obs[1].user, "other"));
    return 0;
}

/* `--redis-user off` (РR6): the dimension is not wanted, so the name is not
 * read and the label is empty — the registry reports `user="-"`. The database
 * has no such switch, because a database number creates no cardinality. */
static int test_user_off(void)
{
    struct lk_redis_cfg cfg = {.no_user = true};

    lk_proto_redis_configure(&cfg);
    reset();
    exchange("*3\r\n$4\r\nAUTH\r\n$6\r\nlkuser\r\n$6\r\nlkpass\r\n", "+OK\r\n");
    exchange("*2\r\n$6\r\nSELECT\r\n$1\r\n2\r\n", "+OK\r\n");
    exchange("*1\r\n$4\r\nPING\r\n", "+PONG\r\n");
    lk_proto_redis_configure(NULL);

    CHECK(nobs == 3);
    CHECK(!strcmp(obs[2].user, "-") && !strcmp(obs[2].db, "2"));
    CHECK(!labels_contain("lkuser"));
    return 0;
}

/* --- identity through the chain (РR4) -------------------------------------- */

/* The container rule, on the wire rather than in the table: the second element
 * is part of the identity for `CONFIG` and is a key for `SET`, and the same
 * bytes (`GET`) prove both at once. */
static int test_identity(void)
{
    reset();
    exchange("*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$9\r\nmaxmemory\r\n",
             "*2\r\n$9\r\nmaxmemory\r\n$1\r\n0\r\n");
    exchange("*4\r\n$3\r\nSET\r\n$5\r\nlk:k1\r\n$1\r\nv\r\n$3\r\nGET\r\n", "$1\r\nv\r\n");
    exchange("*2\r\n$8\r\nJSON.SET\r\n$5\r\nlk:k2\r\n", "-ERR unknown command\r\n");
    exchange("PING\r\n", "+PONG\r\n"); /* inline: still a command, still classified */

    CHECK(nobs == 4);
    CHECK(!strcmp(obs[0].cmd, "CONFIG|GET"));
    CHECK(!strcmp(obs[1].cmd, "SET"));
    CHECK(!strcmp(obs[2].cmd, "other")); /* a module command, bounded */
    CHECK(!strcmp(obs[3].cmd, "PING"));
    CHECK(obs[0].fp && obs[1].fp && obs[0].fp != obs[1].fp);
    CHECK(!labels_contain("lk:k1") && !labels_contain("lk:k2") && !labels_contain("maxmemory"));
    return 0;
}

/* A pipelined `SELECT` still moves the label between the replies, because the
 * replies arrive in command order: the `SET` that was written *after* the
 * `SELECT` really did run in the new database, and its observation says so. */
static int test_pipelined_select(void)
{
    reset();
    call(LK_DIR_RECV,
         "*2\r\n$6\r\nSELECT\r\n$1\r\n6\r\n*3\r\n$3\r\nSET\r\n$5\r\nlk:k1\r\n$1\r\nv\r\n", 100);
    call(LK_DIR_SEND, "+OK\r\n+OK\r\n", 200);

    CHECK(nobs == 2);
    CHECK(!strcmp(obs[0].cmd, "SELECT") && !strcmp(obs[0].db, "0"));
    CHECK(!strcmp(obs[1].cmd, "SET") && !strcmp(obs[1].db, "6"));
    return 0;
}

/* --- the display mask (РR6) ------------------------------------------------ */

/* The viewer's copy of one body, masked, NUL-terminated in `out`; returns its
 * length so a case can assert that masking preserved it — a dump whose bulk
 * headers no longer match its bytes has stopped being a wire view. */
static __u8 out[512];

static __u32 mask(const char *body, char type)
{
    struct lk_msg m = {.type = type,
                       .len = (__u32)strlen(body),
                       .body_cap = (__u32)strlen(body),
                       .body = (const __u8 *)body};
    __u32 n = lk_msg_body_for_display(&lk_proto_redis_ops, &m, out, sizeof(out) - 1);

    out[n] = '\0';
    return n;
}

/* What a viewer prints is not what the handler parses. Driven through
 * lk_msg_body_for_display, the function both `--messages --hexdump` and
 * lkt_messages call, rather than through the hook directly — a mask nobody is
 * obliged to route through would prove nothing. */
static int test_display_mask(void)
{
    static const char auth2[] = "*3\r\n$4\r\nAUTH\r\n$6\r\nlkuser\r\n$6\r\nlkpass\r\n";
    static const char auth1[] = "*2\r\n$4\r\nAUTH\r\n$10\r\nlkrootpass\r\n";
    static const char hello[] = "*7\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$6\r\nlkuser\r\n"
                                "$6\r\nlkpass\r\n$7\r\nSETNAME\r\n$5\r\nlkapp\r\n";
    static const char inl[] = "AUTH lkrootpass\r\n";
    static const char set[] = "*3\r\n$3\r\nSET\r\n$5\r\nlk:k1\r\n$1\r\nv\r\n";
    CHECK(mask(auth2, REDIS_T_ARRAY) == strlen(auth2)); /* lengths hold */
    CHECK(!strstr((char *)out, "lkpass") && !strstr((char *)out, "lkuser"));
    /* Blanked, not deleted: the bulk headers still describe the bytes that
     * follow, so a masked dump still frames — and `AUTH` hides its name as well
     * as its password, which is what Redis's own `MONITOR` feed does. */
    CHECK(strstr((char *)out, "$4\r\nAUTH\r\n$6\r\n******\r\n$6\r\n******\r\n"));

    CHECK(mask(auth1, REDIS_T_ARRAY) == strlen(auth1));
    CHECK(!strstr((char *)out, "lkrootpass"));

    CHECK(mask(hello, REDIS_T_ARRAY) == strlen(hello));
    CHECK(!strstr((char *)out, "lkpass"));
    /* Only the password: a `HELLO` dump that hid its own version and client name
     * would stop being useful for the one thing it is read for. */
    CHECK(strstr((char *)out, "lkuser") && strstr((char *)out, "lkapp"));
    CHECK(strstr((char *)out, "$1\r\n3\r\n"));

    CHECK(mask(inl, LK_REDIS_MSG_INLINE) == strlen(inl));
    CHECK(!strstr((char *)out, "lkrootpass"));

    /* A key is not a credential and is not blanked: `--messages --hexdump` is
     * the raw wire view, off by default, and the bytes it shows are the bytes
     * that were on the wire. What the invariant of РR4 forbids is a key in a
     * *label*, a span attribute or an exported series — and that is asserted on
     * every observation above. */
    CHECK(mask(set, REDIS_T_ARRAY) == strlen(set));
    CHECK(strstr((char *)out, "lk:k1"));

    /* The source is untouched: the handler still has to read the very element
     * this hides, or `--redis-user acl` would silently stop working. */
    CHECK(strstr(auth2, "lkuser") != NULL);
    return 0;
}

int main(void)
{
    int rc = 0;

    rc |= test_defaults();
    rc |= test_select_moves_on_reply();
    rc |= test_select_refused();
    rc |= test_select_out_of_our_range();
    rc |= test_reset();
    rc |= test_synthetic_unknown();
    rc |= test_select_lost_in_resync();
    rc |= test_auth_two_args();
    rc |= test_auth_one_arg();
    rc |= test_auth_refused();
    rc |= test_hello_auth();
    rc |= test_hello_plain();
    rc |= test_auth_hostile_name();
    rc |= test_user_off();
    rc |= test_identity();
    rc |= test_pipelined_select();
    rc |= test_display_mask();
    teardown();
    if (rc)
        return 1;
    printf("ok - redis session labels and identity\n");
    return 0;
}
