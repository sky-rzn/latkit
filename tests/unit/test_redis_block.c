// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the blocking family (PLAN-REDIS.md МR4, РR10) — the same real
 * chain as the other Redis unit tests: bytes → stream framer → lk_msg → handler
 * → lk_query_obs.
 *
 * `BLPOP lk:q 30` waits up to thirty seconds for somebody *else* to push. The
 * number that comes out of it is real, and it describes the client's own
 * patience and the traffic of a third party — not the server, which was idle
 * throughout. One of these in the same histogram as `GET` decides the p99 of the
 * whole instance, so the observation is made, flagged LK_QO_BLOCKING, and kept
 * out of the general distribution (МR5 gives it
 * `latkit_redis_blocking_seconds`).
 *
 * The interesting half is `XREAD`, and it is the only place in this tree where
 * an argument past the identity is looked at at all. The server flags `XREAD`
 * and `XREADGROUP` blocking unconditionally, but `XREAD COUNT 10 STREAMS s 0`
 * returns at once and `XREAD BLOCK 300 STREAMS s $` does not (measured,
 * `redis/blocking.lkt`) — so the bit has to be refined by the presence of a
 * keyword. Never by its value, and never past `STREAMS`, after which every
 * element is a key and a stream may perfectly well be *called* `BLOCK`. */
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
    __u64 dur;
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
    r->flags = o->flags;
    r->dur = o->ts_complete_ns - o->ts_start_ns;
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

/* Build a RESP array out of its elements, which is what makes the argument
 * cases below readable: the question is always "which words does this command
 * carry", and spelling `$5\r\nBLOCK\r\n` by hand hides it. */
static const char *cmd(const char *const *argv, unsigned n)
{
    static char buf[1024];
    int off = snprintf(buf, sizeof(buf), "*%u\r\n", n);

    for (unsigned i = 0; i < n; i++)
        off += snprintf(buf + off, sizeof(buf) - (size_t)off, "$%u\r\n%s\r\n",
                        (unsigned)strlen(argv[i]), argv[i]);
    return buf;
}

/* One command and its reply, on a clock that advances by a stated wait — the
 * wait is the subject here, so it is spelled out per case. */
static void exchange(const char *const *argv, unsigned n, const char *reply, __u64 wait)
{
    static __u64 clock = 1000;

    call(LK_DIR_RECV, cmd(argv, n), clock);
    call(LK_DIR_SEND, reply, clock + wait);
    clock += wait + 100;
}

#define ARGV(...)              ((const char *const[]){__VA_ARGS__})
#define NARG(...)              (sizeof((const char *const[]){__VA_ARGS__}) / sizeof(const char *))
#define SEND(reply, wait, ...) exchange(ARGV(__VA_ARGS__), NARG(__VA_ARGS__), reply, wait)

/* --- the commands the server itself flags ---------------------------------- */

/* `BLPOP` in both its endings: the timeout the client chose (a null after a
 * whole second of nothing) and the event that arrived first. Neither number
 * says anything about the server, which is why they belong in the same family
 * as each other and in no other. */
static int test_blpop(void)
{
    reset();
    SEND("*-1\r\n", 1000000000ull, "BLPOP", "lk:q", "1");
    SEND("*2\r\n$4\r\nlk:q\r\n$5\r\nwoken\r\n", 500000000ull, "BLPOP", "lk:q", "5");

    CHECK(nobs == 2);
    CHECK(!strcmp(obs[0].cmd, "BLPOP") && (obs[0].flags & LK_QO_BLOCKING));
    CHECK(!strcmp(obs[1].cmd, "BLPOP") && (obs[1].flags & LK_QO_BLOCKING));
    /* The duration is measured and reported; what the flag says is which family
     * it belongs in, not that it is unknown. */
    CHECK(obs[0].dur == 1000000000ull && obs[1].dur == 500000000ull);
    /* A timeout is not an error: `*-1` is `BLPOP` saying nobody pushed. */
    CHECK(!(obs[0].flags & LK_QO_ERROR));
    return 0;
}

/* The rest of the family the server flags, each with the shape it really has.
 * `WAIT` and `WAITAOF` block on replication rather than on a key and belong
 * here for the same reason: the wait is an argument of the command. */
static int test_family(void)
{
    reset();
    SEND("*2\r\n$4\r\nlk:q\r\n$1\r\nv\r\n", 10, "BRPOP", "lk:q", "0");
    SEND("$1\r\nv\r\n", 10, "BLMOVE", "lk:a", "lk:b", "LEFT", "RIGHT", "0");
    SEND("*-1\r\n", 10, "BLMPOP", "0.3", "1", "lk:q", "LEFT");
    SEND("*2\r\n$4\r\nlk:z\r\n$1\r\n1\r\n", 10, "BZPOPMIN", "lk:z", "0");
    SEND(":0\r\n", 10, "WAIT", "0", "100");
    SEND("*2\r\n:0\r\n:0\r\n", 10, "WAITAOF", "0", "0", "100");

    CHECK(nobs == 6);
    for (int i = 0; i < nobs; i++)
        CHECK(obs[i].flags & LK_QO_BLOCKING);
    return 0;
}

/* ... and the ordinary commands beside them, which is the half that would go
 * unnoticed if the bit were set too widely: the general histogram would empty
 * out and nothing would look wrong. */
static int test_ordinary_commands_are_not_blocking(void)
{
    reset();
    SEND("+OK\r\n", 10, "SET", "lk:a", "1");
    SEND("$1\r\nv\r\n", 10, "GET", "lk:a");
    SEND(":1\r\n", 10, "RPUSH", "lk:q", "v");
    /* `LPOP`, the non-blocking twin of `BLPOP`, and `BITPOS`, whose name starts
     * with a `B` — the bit comes from the table and not from a prefix. */
    SEND("$1\r\nv\r\n", 10, "LPOP", "lk:q");
    SEND(":0\r\n", 10, "BITPOS", "lk:b", "1");

    CHECK(nobs == 5);
    for (int i = 0; i < nobs; i++)
        CHECK(!(obs[i].flags & LK_QO_BLOCKING));
    return 0;
}

/* --- the keyword, which is the only argument ever read (РR10) -------------- */

/* The same command, blocking or not depending on one word. This is the
 * refinement РR10 asks for and the reason the table's bit is the server's answer
 * and not the final one. */
static int test_xread(void)
{
    reset();
    /* Immediate: a count and a starting id, no wait. */
    SEND("*1\r\n$8\r\nlk:strea\r\n", 10, "XREAD", "COUNT", "10", "STREAMS", "lk:stream", "0");
    /* Blocking: the client asked for up to 300 ms. */
    SEND("*-1\r\n", 300000000ull, "XREAD", "BLOCK", "300", "STREAMS", "lk:stream", "$");
    /* Both, in the order a client library writes them. */
    SEND("*-1\r\n", 10, "XREAD", "COUNT", "10", "BLOCK", "0", "STREAMS", "lk:stream", "$");
    /* Lower case, as go-redis sends everything. */
    SEND("*-1\r\n", 10, "xread", "block", "0", "streams", "lk:stream", "$");

    CHECK(nobs == 4);
    CHECK(!strcmp(obs[0].cmd, "XREAD") && !(obs[0].flags & LK_QO_BLOCKING));
    CHECK(obs[1].flags & LK_QO_BLOCKING);
    CHECK(obs[2].flags & LK_QO_BLOCKING);
    CHECK(!strcmp(obs[3].cmd, "XREAD") && (obs[3].flags & LK_QO_BLOCKING));
    return 0;
}

/* `XREADGROUP` puts the keyword further out — behind `GROUP g c` and an optional
 * `COUNT n` — which is why the handler reads LK_REDIS_ARGV_MAX elements for
 * these two commands and LK_REDIS_ARGV_LABELS for every other. */
static int test_xreadgroup(void)
{
    reset();
    SEND("*1\r\n$1\r\nx\r\n", 10, "XREADGROUP", "GROUP", "g1", "c1", "STREAMS", "lk:stream", ">");
    SEND("*-1\r\n", 10, "XREADGROUP", "GROUP", "g1", "c1", "BLOCK", "0", "STREAMS", "lk:stream",
         ">");
    SEND("*-1\r\n", 10, "XREADGROUP", "GROUP", "g1", "c1", "COUNT", "10", "BLOCK", "0", "NOACK",
         "STREAMS", "lk:stream", ">");

    CHECK(nobs == 3);
    CHECK(!strcmp(obs[0].cmd, "XREADGROUP") && !(obs[0].flags & LK_QO_BLOCKING));
    CHECK(obs[1].flags & LK_QO_BLOCKING);
    CHECK(obs[2].flags & LK_QO_BLOCKING);
    return 0;
}

/* A stream *named* `BLOCK` is a legal key, and after `STREAMS` every element is
 * one. The scan stops there — otherwise the key would decide the family, which
 * is the same mistake as a key deciding a label. */
static int test_stream_named_block(void)
{
    reset();
    SEND("*1\r\n$1\r\nx\r\n", 10, "XREAD", "COUNT", "2", "STREAMS", "BLOCK", "0");
    SEND("*1\r\n$1\r\nx\r\n", 10, "XREAD", "STREAMS", "BLOCK", "block", "0", "0");

    CHECK(nobs == 2);
    CHECK(!(obs[0].flags & LK_QO_BLOCKING));
    CHECK(!(obs[1].flags & LK_QO_BLOCKING));
    return 0;
}

/* The keyword outside the prefix the capture kept. The honest failure is that
 * the command reads as ordinary — the same thing that happens to a command whose
 * verb was cut off, and the same answer: what is not seen is not guessed at.
 * Named here so the limit is a stated property and not a surprise. */
static int test_keyword_past_the_budget(void)
{
    static char big[4096];
    int off = snprintf(big, sizeof(big), "*%u\r\n$5\r\nXREAD\r\n", 2 + 20 * 2 + 3);

    /* Twenty stream keys before the ids: `BLOCK` would be at element 46, past
     * LK_REDIS_ARGV_MAX. (The server would reject this order anyway — it is here
     * as the bound, not as traffic.) */
    off += snprintf(big + off, sizeof(big) - (size_t)off, "$5\r\nBLOCK\r\n$1\r\n0\r\n");
    for (int i = 0; i < 20; i++)
        off += snprintf(big + off, sizeof(big) - (size_t)off, "$8\r\nlk:pad%02d\r\n", i);
    for (int i = 0; i < 20; i++)
        off += snprintf(big + off, sizeof(big) - (size_t)off, "$1\r\n0\r\n");
    snprintf(big + off, sizeof(big) - (size_t)off, "$7\r\nSTREAMS\r\n$1\r\ns\r\n$1\r\n0\r\n");

    reset();
    call(LK_DIR_RECV, big, 100);
    call(LK_DIR_SEND, "*-1\r\n", 200);
    CHECK(nobs == 1 && !strcmp(obs[0].cmd, "XREAD"));
    /* `BLOCK` is element 1 here, well inside the read — the bound is the *other*
     * direction, and this asserts the read reaches as far as it claims to. */
    CHECK(obs[0].flags & LK_QO_BLOCKING);
    return 0;
}

/* The classifier's own answer, checked without the handler around it: the table
 * bit for the twelve the server flags, the keyword refinement for the two, and
 * `other` for a command the table does not know. */
static int test_classifier(void)
{
    struct lk_redis_argv v = {0};
    uint16_t id;

    v.a[0].p = "BLPOP";
    v.a[0].n = 5;
    v.n = 1;
    id = lk_redis_cmd(&v);
    CHECK(lk_redis_cmd_flags(id) & LK_REDIS_C_BLOCKING);
    CHECK(lk_redis_cmd_blocking(id, &v));

    v.a[0].p = "GET";
    v.a[0].n = 3;
    id = lk_redis_cmd(&v);
    CHECK(!lk_redis_cmd_blocking(id, &v));

    /* A bare `XREAD` carries the server's bit and the keyword refinement says
     * no — which is also what an argument list cut short by the budget looks
     * like, and the safe answer for both. */
    v.a[0].p = "XREAD";
    v.a[0].n = 5;
    id = lk_redis_cmd(&v);
    CHECK(lk_redis_cmd_flags(id) & (LK_REDIS_C_BLOCKING | LK_REDIS_C_ARGBLOCK));
    CHECK(!lk_redis_cmd_blocking(id, &v));

    /* A module command the table does not know is not blocking, because nothing
     * is known about it at all (РR4: no guessing from a name). */
    v.a[0].p = "JSON.BLOCK";
    v.a[0].n = 10;
    id = lk_redis_cmd(&v);
    CHECK(id == lk_redis_cmd_other() && !lk_redis_cmd_blocking(id, &v));
    return 0;
}

int main(void)
{
    if (test_blpop() || test_family() || test_ordinary_commands_are_not_blocking() ||
        test_xread() || test_xreadgroup() || test_stream_named_block() ||
        test_keyword_past_the_budget() || test_classifier())
        return 1;
    teardown();
    printf("ok\n");
    return 0;
}
