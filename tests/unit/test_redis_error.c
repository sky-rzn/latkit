// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the Redis error vocabulary (PLAN-REDIS.md МR4, РR7) — driven
 * through the real chain, bytes → stream framer → lk_msg → handler →
 * lk_query_obs, exactly as test_redis_unit.c and test_redis_labels.c drive the
 * queue and the session.
 *
 * Two claims, and each of them is a different kind of wrong if it fails:
 *
 *   - **the failure is named by its symbol and by nothing else.** `-WRONGTYPE
 *     Operation against a key holding the wrong kind of value` is one error
 *     whatever key it was about, and the sentence after the symbol holds that
 *     key, a slot number or a node address. So `err_name` is a pointer into the
 *     closed vocabulary of norm_redis.c — the tests below check the *pointer*,
 *     not the spelling, because a lucky copy of the wire would spell the same
 *     and mean the opposite.
 *   - **`-MOVED` and `-ASK` are not failures.** A resharding cluster answers
 *     them continuously and every client retries and carries on; counted as
 *     errors they would paint a healthy cluster red for ever. They carry
 *     LK_QO_CLIENT_ERR — the flag a 4xx carries in HTTP — a counter of their
 *     own, and not LK_QO_ERROR. `-MISCONF` and `-LOADING` are the opposite case
 *     and stay errors: those are the server refusing to work. */
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
    const char *err; /* the *pointer* the handler reported, not a copy */
    char cmd[LK_REDIS_NAME_MAX];
    __u16 flags;
};

static struct obs obs[MAXOBS];
static int nobs;

static void on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                     const struct lk_query_obs *o)
{
    struct obs *r = &obs[nobs % MAXOBS];

    (void)ctx;
    (void)c;
    (void)s;
    nobs++;
    memset(r, 0, sizeof(*r));
    r->err = o->err_name;
    r->flags = o->flags;
    if (o->route && o->route_len < sizeof(r->cmd))
        memcpy(r->cmd, o->route, o->route_len);
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

static void reset(void)
{
    static const struct lk_query_sink qsink = {.on_query = on_query};

    teardown();
    memset(&conn, 0, sizeof(conn));
    conn.ops = &lk_proto_redis_ops;
    conn.cookie = 0x6379;
    proto = lk_proto_redis_ops.proto_new(&qsink);
    lk_reasm_init(&reasm, lk_proto_sink(proto));
    nobs = 0;
}

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

static void call(enum lk_dir dir, const char *s, __u64 ts)
{
    feed(dir, (__u32)strlen(s), s, (__u32)strlen(s), ts);
}

/* One `GET lk:k` and the reply under test. The command never varies: what is
 * being read is always the *server's* value. */
static void answered(const char *reply)
{
    static __u64 clock = 1000;

    call(LK_DIR_RECV, "*2\r\n$3\r\nGET\r\n$4\r\nlk:k\r\n", clock);
    clock += 10;
    call(LK_DIR_SEND, reply, clock);
    clock += 10;
}

static const struct lk_proto_stats *stats(void)
{
    return lk_proto_stats(proto);
}

/* Is this pointer one the vocabulary owns? The whole closed-set claim in one
 * comparison — and the reason the observation carries a pointer and not a copy:
 * a copy could have come from anywhere, and this could not. */
static bool is_table_name(const char *p)
{
    for (uint32_t i = 0; i < lk_redis_err_count(); i++)
        if (p == lk_redis_err_at(i, NULL))
            return true;
    return false;
}

static bool err_is(int i, const char *name)
{
    return obs[i].err && is_table_name(obs[i].err) && !strcmp(obs[i].err, name);
}

/* --- the vocabulary -------------------------------------------------------- */

/* Every symbol the МR0 corpus produced, in the shape the server sends it: the
 * symbol, a space, and a sentence for a human. What reaches the observation is
 * the first token, and the sentence — which names the key, the command and the
 * ACL rule — reaches nothing. */
static int test_symbols(void)
{
    static const struct {
        const char *reply, *want;
    } cases[] = {
        {"-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", "WRONGTYPE"},
        {"-ERR unknown command 'NOSUCHCOMMAND'\r\n", "ERR"},
        {"-NOSCRIPT No matching script\r\n", "NOSCRIPT"},
        {"-NOAUTH Authentication required.\r\n", "NOAUTH"},
        {"-NOPERM User lkreader has no permissions to run the 'set' command\r\n", "NOPERM"},
        {"-WRONGPASS invalid username-password pair or user is disabled.\r\n", "WRONGPASS"},
        {"-EXECABORT Transaction discarded because of previous errors.\r\n", "EXECABORT"},
        {"-NOPROTO unsupported protocol version\r\n", "NOPROTO"},
        {"-CROSSSLOT Keys in request don't hash to the same slot\r\n", "CROSSSLOT"},
        /* The states of a server that is up and refusing to work. They are
         * errors precisely because they are the server's own condition — the
         * distinction that makes a redirect *not* one (РR7). */
        {"-LOADING Redis is loading the dataset in memory\r\n", "LOADING"},
        {"-MISCONF Errors writing to the AOF file\r\n", "MISCONF"},
        {"-BUSY Redis is busy running a script\r\n", "BUSY"},
        {"-OOM command not allowed when used memory > 'maxmemory'.\r\n", "OOM"},
        {"-READONLY You can't write against a read only replica.\r\n", "READONLY"},
        {"-UNBLOCKED client unblocked via CLIENT UNBLOCK\r\n", "UNBLOCKED"},
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        reset();
        answered(cases[i].reply);
        CHECK(nobs == 1);
        CHECK(err_is(0, cases[i].want));
        /* An error is an error: the flag, the counter, and no redirect. */
        CHECK(obs[0].flags & LK_QO_ERROR);
        CHECK(!(obs[0].flags & LK_QO_CLIENT_ERR));
        CHECK(stats()->errors_sql == 1 && stats()->redirects == 0);
    }
    return 0;
}

/* A symbol nobody defined. A Lua script may answer
 * `redis.error_reply('CUSTOMERR …')` (measured, `redis/eval-scripts.lkt`) and a
 * module may invent anything at all, so an unfolded token would be a series name
 * chosen by whoever is talking to the server. */
static int test_unknown_symbol_is_other(void)
{
    reset();
    answered("-CUSTOMERR something a script made up\r\n");
    CHECK(nobs == 1 && err_is(0, "other"));
    CHECK(obs[0].flags & LK_QO_ERROR);

    /* Case is not folded: an error symbol is upper-case by protocol convention,
     * and a lower-case token is a script's invention rather than the server's —
     * which is the very difference `other` exists to record. */
    reset();
    answered("-wrongtype not the server's spelling\r\n");
    CHECK(nobs == 1 && err_is(0, "other"));

    /* An error line with no symbol at all, and one with nothing but a symbol:
     * neither may reach a label with a byte of the wire in it. */
    reset();
    answered("-\r\n");
    CHECK(nobs == 1 && err_is(0, "other"));
    return 0;
}

/* RESP3's blob error carries the same symbol behind a length header, and the
 * length is not what bounds the read — the prefix is (`redis/types3.lkt`). */
static int test_blob_error(void)
{
    reset();
    answered("!41\r\nWRONGTYPE Operation against a key holding\r\n");
    CHECK(nobs == 1 && err_is(0, "WRONGTYPE"));
    CHECK(obs[0].flags & LK_QO_ERROR);
    return 0;
}

/* The reader, on a body the value's own bytes outran. A published prefix can be
 * shorter than the value — the capture budget of РR13 is 512 bytes and a
 * `-NOPERM` sentence can be longer — so the rule is the one redis_read_argv
 * already applies to a verb: a token is whole only if something *ended* it
 * inside the prefix. `NOPE` is not the symbol the server sent, and folding it to
 * `other` because the vocabulary happens not to have it would be the right
 * answer arrived at by luck.
 *
 * Tested against the reader directly, since the shapes that produce a short body
 * — a lost reassembly slab, a body past LK_MSG_BODY_MAX — are properties of the
 * capture rather than of any traffic a test can send. (A capture *hole* inside
 * an error line is a different matter and is the case below.) */
static int test_truncated_symbol(void)
{
    struct lk_msg m = {.type = REDIS_T_ERROR, .len = 68};
    struct lk_redis_arg w;

    m.body = (const __u8 *)"-NOPE";
    m.body_cap = 5;
    w = redis_read_word(&m, m.body, m.body_cap);
    CHECK(!w.n && lk_redis_err(w.p, w.n).name == lk_redis_err_at(lk_redis_err_count() - 1, NULL));

    /* Cut *after* the symbol, and the symbol is whole: the space that ended it
     * is inside the prefix. This is the common case at a 512-byte budget. */
    m.body = (const __u8 *)"-WRONGTYPE Operation against a key holding";
    m.body_cap = 41;
    w = redis_read_word(&m, m.body, m.body_cap);
    CHECK(w.n == 9 && !memcmp(w.p, "WRONGTYPE", 9));

    /* No body at all — the slab could not be borrowed, so the value is framed
     * correctly and published without one. Nothing is known and nothing is
     * guessed. */
    w = redis_read_word(&m, NULL, 0);
    CHECK(!w.n && !w.p);
    return 0;
}

/* A capture hole *inside* an error line is not a truncated symbol, it is a lost
 * direction: a line has no length to step over, so the framer resyncs and the
 * queued unit is dropped rather than emitted with a symbol nobody read. An
 * observation with a plausible error name and an unknown command is exactly the
 * kind of number this handler exists not to produce (Р19, risk 1). */
static int test_hole_in_an_error_line(void)
{
    reset();
    call(LK_DIR_RECV, "*2\r\n$3\r\nGET\r\n$4\r\nlk:k\r\n", 100);
    feed(LK_DIR_SEND, 68, "-NOPERM this user has no permi", 30, 200);
    call(LK_DIR_SEND, "+PONG\r\n", 300); /* the new call reveals the hole */

    CHECK(nobs == 0);
    CHECK(stats()->units_dropped_resync == 1);
    CHECK(stats()->errors_sql == 0 && stats()->redirects == 0);
    return 0;
}

/* --- redirects are not failures (РR7) -------------------------------------- */

/* `-MOVED 12182 127.0.0.1:6392`: the client asked the wrong node and is being
 * told which one to ask. Its own counter, the client-error flag, and *not* the
 * error one — the МR4 acceptance in one test.
 *
 * The node address in the message is the other half of why the symbol is folded:
 * `MOVED 12182 127.0.0.1:6392` as a label would be one series per slot per node,
 * which is the cardinality explosion the closed vocabulary exists to prevent. */
static int test_moved(void)
{
    reset();
    answered("-MOVED 12182 127.0.0.1:6392\r\n");

    CHECK(nobs == 1 && err_is(0, "MOVED"));
    CHECK(obs[0].flags & LK_QO_CLIENT_ERR);
    CHECK(!(obs[0].flags & LK_QO_ERROR));
    CHECK(stats()->redirects == 1 && stats()->errors_sql == 0);
    return 0;
}

/* `-ASK 14758 127.0.0.1:6390`: the slot is migrating and this one command
 * should go elsewhere. Its own kind, because "the slot has moved" and "the slot
 * is moving" are different facts about a cluster — the first is a client with a
 * stale map, the second is a resharding in progress. */
static int test_ask(void)
{
    reset();
    answered("-ASK 14758 127.0.0.1:6390\r\n");

    CHECK(nobs == 1 && err_is(0, "ASK"));
    CHECK((obs[0].flags & LK_QO_CLIENT_ERR) && !(obs[0].flags & LK_QO_ERROR));
    CHECK(stats()->redirects == 1 && stats()->errors_sql == 0);
    return 0;
}

/* A cluster under a client that guesses wrong is mostly redirects and sometimes
 * a real error, and the two counters have to stay apart across a whole
 * connection — which is what the dashboard actually shows. */
static int test_redirects_and_errors_together(void)
{
    reset();
    answered("-MOVED 1 127.0.0.1:6391\r\n");
    answered("-CROSSSLOT Keys in request don't hash to the same slot\r\n");
    answered("-ASK 2 127.0.0.1:6392\r\n");
    answered("$1\r\nv\r\n");

    CHECK(nobs == 4);
    CHECK(err_is(0, "MOVED") && err_is(1, "CROSSSLOT") && err_is(2, "ASK"));
    CHECK(!obs[3].err && !(obs[3].flags & (LK_QO_ERROR | LK_QO_CLIENT_ERR)));
    CHECK(stats()->redirects == 2 && stats()->errors_sql == 1);
    return 0;
}

/* --- what is not an error --------------------------------------------------- */

/* A null is not a failure. `GET` of a key that does not exist is `$-1` (RESP2)
 * or `_` (RESP3), and both are the ordinary answer to an ordinary question —
 * counting them as errors would make a cache-miss-heavy workload look broken,
 * which is exactly the mistake `MOVED` would be. */
static int test_null_is_not_an_error(void)
{
    reset();
    answered("$-1\r\n");
    answered("_\r\n");
    answered("*-1\r\n");

    CHECK(nobs == 3);
    for (int i = 0; i < 3; i++) {
        CHECK(!obs[i].err);
        CHECK(!(obs[i].flags & (LK_QO_ERROR | LK_QO_CLIENT_ERR)));
    }
    CHECK(stats()->errors_sql == 0 && stats()->redirects == 0);
    return 0;
}

/* An error inside a pub/sub push closes no unit and is therefore no
 * observation's outcome: the queue rule of РR8 comes first, and the error
 * machinery must not quietly resurrect a value the queue refused. */
static int test_error_in_push_is_not_an_outcome(void)
{
    reset();
    call(LK_DIR_RECV, "*2\r\n$9\r\nSUBSCRIBE\r\n$2\r\nc1\r\n", 100);
    call(LK_DIR_SEND, "*3\r\n$9\r\nsubscribe\r\n$2\r\nc1\r\n:1\r\n", 110);
    CHECK(nobs == 1 && !obs[0].err);

    call(LK_DIR_SEND, "*3\r\n$7\r\nmessage\r\n$2\r\nc1\r\n$2\r\nhi\r\n", 200);
    CHECK(nobs == 1 && stats()->pushes == 1);
    CHECK(stats()->errors_sql == 0);
    return 0;
}

/* The vocabulary is a *set*, and the set is what bounds the label. Checked here
 * against the table itself rather than a copy of it, so a new symbol cannot be
 * added in one place and forgotten in another. */
static int test_vocabulary_is_closed(void)
{
    uint32_t n = lk_redis_err_count();
    const char *prev = NULL;

    CHECK(n > 20);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t len = 0;
        const char *name = lk_redis_err_at(i, &len);

        CHECK(name && len == strlen(name));
        /* C-sorted, which is what the binary search in norm_redis.c needs and
         * what a hand-added entry in the wrong place would silently break —
         * `other` last, since it is the answer to a miss and never a match. */
        if (prev && i + 1 < n)
            CHECK(strcmp(prev, name) < 0);
        prev = name;
    }
    CHECK(!strcmp(lk_redis_err_at(n - 1, NULL), "other"));
    /* Out of range is `other` and not a crash: an id is an index and every
     * accessor in this tree clamps rather than trusts. */
    CHECK(lk_redis_err_at(n + 100, NULL) == lk_redis_err_at(n - 1, NULL));
    return 0;
}

int main(void)
{
    if (test_symbols() || test_unknown_symbol_is_other() || test_blob_error() ||
        test_truncated_symbol() || test_hole_in_an_error_line() || test_moved() || test_ask() ||
        test_redirects_and_errors_together() || test_null_is_not_an_error() ||
        test_error_in_push_is_not_an_outcome() || test_vocabulary_is_closed())
        return 1;
    teardown();
    printf("ok\n");
    return 0;
}
