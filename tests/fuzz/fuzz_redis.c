// SPDX-License-Identifier: GPL-2.0
/* RESP framer + handler libFuzzer target (PLAN-REDIS.md МR8; the fuzz_pg /
 * fuzz_my / fuzz_http harness transplanted to the fifth protocol, and the
 * fourth framer).
 *
 * What makes this target worth its own binary rather than a flag on another is
 * that RESP is the one wire format in the tree with **no self-describing
 * boundary above the value**: an array announces a count and not a size, so a
 * length that does not describe the wire is not recoverable by arithmetic the
 * way a PG or MySQL packet's is. The bytes that decide that are a client's:
 * `$536870913`, `*2147483648`, a bulk whose payload is not followed by CRLF, an
 * aggregate nested past our stack, a line with no terminator inside 64 KB. Each
 * of those is one mutation away from a valid command, and each has to end in a
 * note and a resync rather than in a read past a buffer — so this target drives
 * the exact production path they take: bytes -> framer (redis_frame.c) ->
 * lk_msg -> handler (redis.c) -> observation, through one function.
 *
 * Three invariants beyond "no crash", each of them a claim the milestone makes
 * in prose elsewhere:
 *
 *   1. **the message contract** (fz_check_redis_msg): a published type is a RESP
 *      type byte or one of the two synthetic ones, a length describes the wire,
 *      and a note carries a code the handler can name;
 *   2. **the identity is a table value** (РR4), whatever the input. `cmd` is the
 *      one label on this protocol that a client could hope to choose — it is
 *      read out of the first element of an array the client wrote — and the
 *      whole cardinality argument of риск 7 rests on it being an index into a
 *      closed table instead. Here that is checked against a mutator: no input
 *      may produce a `cmd` with a byte a Redis *key* could have put there;
 *   3. **the credential mask is total** (РR6). `redis_mask_body` is the one
 *      place in the tree that rewrites bytes for display, it runs over
 *      attacker-shaped arrays, and a mistake in it is a password on somebody's
 *      terminal rather than a wrong number. Every published frontend message is
 *      pushed through the real display path (lk_msg_body_for_display) and the
 *      result checked for the two properties a mask must have: it changes no
 *      length, and running it twice changes nothing more.
 *
 * The input feeds both directions of one connection — the RECV pass drives
 * commands, inline lines and the frontend anchor, the SEND pass replies, pushes
 * and the backend anchor — with holes between them, so the arithmetic bulk skip
 * (the one degradation on this protocol that costs nothing) and the resync scan
 * (the one that costs a queue) are both on the fuzzed path. Then the connection
 * closes, so the destroy hook frees per-connection state on the live agent's
 * path (Р15) and a leak surfaces under ASAN.
 *
 * Built only in the -DLATKIT_FUZZ=ON profile (clang; fuzzer,address,undefined).
 * The committed corpus is tests/fuzz/corpus/redis/; CI replays it — plus the
 * МR0 .lkt traces, whose raw record bytes are also valid framer input — with
 * -runs=0 as a regression test. */
#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "conn_table.h"
#include "fuzz_invariants.h"
#include "norm_redis.h" /* the identity table's own bounds (LK_REDIS_*_MAX) */
#include "proto.h"
#include "reassembly.h"

/* Input larger than this is clamped: the framer takes a __u32 length, and a
 * multi-megabyte single feed exercises nothing the low kilobytes do not. */
#define LK_FUZZ_MAX_INPUT (1u << 20)

/* РR4 from the outside. A command identity is `SET`, `CONFIG|GET` or `other`:
 * upper-case letters, digits and the three punctuation bytes real command names
 * contain (`_`, `-`, `.` — `OBJECT|HELP`, `CLIENT|NO-EVICT`, `LATENCY|DOCTOR`,
 * and the module names that fold to `other`), with at most one `|` joining two
 * of them. A Redis *key* is `lk:k1`, `user:42:session`, a channel is `news.tech`
 * — so the discriminating byte is the colon, and a space, a slash or a control
 * byte would mean something far worse got through.
 *
 * `other` is lower case and is the one exception, which is why it is compared
 * whole rather than pattern-matched: it is our word, not the wire's. */
static void fz_check_redis_ident(const char *p, __u32 n)
{
    __u32 bars = 0;

    FZ_ASSERT(n > 0 && n < LK_REDIS_NAME_MAX * 2);
    if (n == 5 && !memcmp(p, "other", 5))
        return;
    for (__u32 i = 0; i < n; i++) {
        char ch = p[i];

        if (ch == '|') {
            /* At most one, never leading, never trailing: `CONFIG|other` is the
             * only shape in which the lower-case word may appear. */
            FZ_ASSERT(++bars == 1 && i > 0 && i + 1 < n);
            if (n - i - 1 == 5 && !memcmp(p + i + 1, "other", 5))
                return;
            continue;
        }
        FZ_ASSERT((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' ||
                  ch == '.');
    }
}

/* The two label slots (РR5/РR6) and the symbolic failure (РR7). Each is a
 * bounded token, and the *contracts differ* — which is worth stating, because
 * the first version of this check got it wrong and the campaign said so within
 * the hour:
 *
 *   - the **database** is a number the agent formatted itself, or `?`. Its
 *     alphabet is closed because it is not copied from the wire at all: an
 *     unparsable or out-of-range `SELECT` yields the honest unknown (РR5).
 *   - the **user** is copied from the wire, and is therefore *validated* rather
 *     than assumed: printable ASCII with no space, quote or backslash
 *     (lk_redis_user_valid), and anything else folds to `other`. A colon
 *     passes — which looks alarming next to fz_check_redis_ident, where a colon
 *     is precisely the signature of a leaked key, and is right: a name only
 *     reaches this slot when the *server accepted an `AUTH` with it* (РR6), so
 *     the set of values is the operator's ACL list and not the client's
 *     imagination. Forbidding it here would be asserting a promise nothing
 *     makes.
 *   - the **error** is a pointer into the static vocabulary, never the sentence
 *     after the symbol — which names the key that had the wrong type and the
 *     node a `MOVED` points at. */
static void fz_check_redis_labels(const struct lk_session *s, const struct lk_query_obs *o)
{
    if (s) {
        size_t dn = strnlen(s->database, sizeof(s->database));
        size_t un = strnlen(s->user, sizeof(s->user));

        FZ_ASSERT(dn < sizeof(s->database) && un < sizeof(s->user));
        if (dn) {
            if (dn == 1 && s->database[0] == '?') {
                /* the honest unknown of РR5 */
            } else {
                FZ_ASSERT(dn <= 4); /* LK_REDIS_MAX_DB is 1024 */
                for (size_t i = 0; i < dn; i++)
                    FZ_ASSERT(s->database[i] >= '0' && s->database[i] <= '9');
            }
        }
        FZ_ASSERT(un < LK_REDIS_USER_MAX);
        for (size_t i = 0; i < un; i++) {
            unsigned char ch = (unsigned char)s->user[i];

            FZ_ASSERT(ch > ' ' && ch <= '~' && ch != '"' && ch != '\\');
        }
        fz_read_bytes(s->user, un);
    }
    if (o->err_name) {
        size_t en = strlen(o->err_name);

        FZ_ASSERT(en > 0 && en <= 24);
        for (size_t i = 0; i < en; i++)
            FZ_ASSERT((o->err_name[i] >= 'A' && o->err_name[i] <= 'Z') ||
                      (en == 5 && !memcmp(o->err_name, "other", 5)));
    }
}

static void fz_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                        const struct lk_query_obs *o)
{
    (void)ctx;
    (void)c;
    fz_check_obs(o);
    /* Every redis observation is one command and its answer — never a
     * statement, never an exchange (РR11). */
    FZ_ASSERT(o->kind == LK_Q_COMMAND);
    /* ... and it never carries text, whatever was on the wire: the arguments
     * are the values, and the identity is a table index. */
    FZ_ASSERT((o->flags & LK_QO_NO_TEXT) && !o->text && !o->text_len);
    if (o->route)
        fz_check_redis_ident(o->route, o->route_len);
    fz_check_redis_labels(s, o);
    if (o->redis) {
        /* МR6's two span numbers, and the reason they are numbers: how many
         * arguments a command had, never what they were. */
        fz_byte_sink += o->redis->pipeline_depth ^ o->redis->argc ^ o->redis->txn_size;
        FZ_ASSERT(o->redis->redirect <= LK_REDIS_RD_ASK);
    }
}

/* --- framer -> handler tee ------------------------------------------------- */
struct fz_tee {
    const struct lk_msg_sink *psink; /* = lk_proto_sink(proto) */
    const struct lk_proto_ops *ops;  /* for the display mask (РR6) */
};

/* РR6, on every frontend message the framer publishes: run the real display
 * path over the real body and hold its output to the two properties a mask has.
 * A copy, because that is what the hook is for — the handler downstream still
 * has to read the very element this hides, so masking in place would make
 * `--redis-user acl` silently stop working (redis.h). */
static void fz_mask_check(const struct fz_tee *t, const struct lk_msg *m)
{
    __u8 once[512], twice[sizeof(once)];
    __u32 n1, n2;

    if (!m->body_cap)
        return;
    n1 = lk_msg_body_for_display(t->ops, m, once, sizeof(once));
    FZ_ASSERT(n1 == (m->body_cap < sizeof(once) ? m->body_cap : sizeof(once)));
    n2 = lk_msg_body_for_display(t->ops, m, twice, sizeof(twice));
    FZ_ASSERT(n1 == n2 && !memcmp(once, twice, n1));
    /* Idempotent: a mask that changed its own output would mean it is deciding
     * where an element begins from bytes it has already rewritten. */
    if (t->ops->mask_body) {
        t->ops->mask_body(m, twice, n2);
        FZ_ASSERT(!memcmp(once, twice, n1));
    }
    fz_read_bytes(once, n1);
}

static void tee_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct fz_tee *t = ctx;

    fz_check_redis_msg(m);
    if (dir == LK_DIR_RECV)
        fz_mask_check(t, m);
    if (t->psink->on_msg)
        t->psink->on_msg(t->psink->ctx, c, dir, m);
}

static void tee_on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    const struct lk_msg_sink *ps = ((struct fz_tee *)ctx)->psink;

    if (ps->on_resync)
        ps->on_resync(ps->ctx, c, dir);
}

static void fz_on_destroy(void *ctx, struct lk_conn *c)
{
    const struct lk_msg_sink *ps = ((struct fz_tee *)ctx)->psink;

    if (ps->on_conn_close)
        ps->on_conn_close(ps->ctx, c);
}

static void fz_on_txn(void *ctx, const struct lk_conn *c, __u64 start_ns, __u64 end_ns,
                      char final_status)
{
    (void)ctx;
    (void)c;
    fz_byte_sink += start_ns ^ end_ns ^ (unsigned char)final_status;
}

/* One fuzz iteration: bytes -> lk_msg -> RESP handler, set up and torn down
 * from scratch so state never leaks between inputs. */
int lk_redis_fuzz_one(const uint8_t *data, size_t n)
{
    const struct lk_proto_ops *ops = lk_proto_find("redis", 5);
    struct lk_redis_cfg cfg = {0};
    struct lk_proto *proto;
    struct fz_tee tee = {0};
    struct lk_reasm reasm;
    struct lk_conn_table *tbl;
    struct lk_conn *c;
    struct lk_tuple tuple = {0};
    __u32 lost = 0;
    __u32 len = n > LK_FUZZ_MAX_INPUT ? LK_FUZZ_MAX_INPUT : (__u32)n;

    if (!ops)
        return 0;
    /* The one knob (РR6), derived from the input so a crash reproduces from the
     * file: with the user dimension off the ACL reader must not run at all, and
     * "does not run" is a different code path from "runs and finds nothing". */
    cfg.no_user = (n & 1) != 0;
    lk_proto_redis_configure(&cfg);
    proto = ops->proto_new(&(struct lk_query_sink){.on_query = fz_on_query, .on_txn = fz_on_txn});
    if (!proto)
        return 0;
    tee.psink = lk_proto_sink(proto);
    tee.ops = ops;
    lk_reasm_init(&reasm, &(struct lk_msg_sink){.ctx = &tee,
                                                .on_msg = tee_on_msg,
                                                .on_resync = tee_on_resync,
                                                .on_conn_close = fz_on_destroy});

    tbl = lk_conn_table_new(LK_MAX_CONNS_DEFAULT, 600ULL * 1000000000ULL);
    if (!tbl) {
        lk_proto_free(proto);
        return 0;
    }
    /* Force the redis framer/handler on every entry (else the PG default). */
    lk_conn_table_set_protos(tbl, NULL, 0, ops);
    lk_conn_table_on_destroy(tbl, fz_on_destroy, &tee);

    c = lk_conn_table_open(tbl, 0x1234, 0, 1000, &tuple, false, &lost);
    if (c) {
        /* The command pass in two calls: a value torn across a syscall boundary
         * is the shape that makes the framer keep a prefix in the slab, and the
         * boundary itself is what РR3 counts a batch by. Then a hole, which on
         * this protocol is free inside a bulk payload and fatal inside an
         * aggregate — both outcomes are reachable from here.
         *
         * The reply pass then runs the same bytes the other way: whatever they
         * are, the handler has to decide for each value whether it answers the
         * oldest command, is a push that answers nobody (РR8), or is an orphan.
         * A single input therefore exercises the queue as well as the framer. */
        lk_frame_bytes(&reasm, c, LK_DIR_RECV, data, len / 2, 2000);
        lk_frame_bytes(&reasm, c, LK_DIR_RECV, data + len / 2, len - len / 2, 2001);
        lk_frame_hole(&reasm, c, LK_DIR_RECV, 9);
        lk_frame_bytes(&reasm, c, LK_DIR_SEND, data, len, 3000);
        lk_frame_hole(&reasm, c, LK_DIR_SEND, 4096);
        lk_frame_bytes(&reasm, c, LK_DIR_SEND, data, len, 4000);
        lk_frame_bytes(&reasm, c, LK_DIR_RECV, data, len, 5000);
    }
    /* The close hook drops whatever is still in flight (РR3) and frees the
     * per-connection ring, which is 6 KB of state per connection. */
    lk_conn_table_close(tbl, 0x1234, 1, 6000, &lost);

    lk_conn_table_free(tbl);
    lk_reasm_free(&reasm);
    lk_proto_free(proto);
    lk_proto_redis_configure(NULL);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return lk_redis_fuzz_one(data, size);
}
