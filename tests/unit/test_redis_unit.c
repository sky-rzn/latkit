// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the Redis handler (PLAN-REDIS.md МR2, src/proto/redis/redis.c)
 * — the unit queue, the four timings, the pub/sub rule and the service
 * connections, driven through the *real* chain: bytes → stream framer → lk_msg →
 * handler → lk_query_obs. test_redis_frame.c already asserts on the message
 * stream, so everything here asserts on observations, which is what МR2
 * delivers.
 *
 * The bytes are fed exactly as a capture event would deliver them, holes and
 * under-captured calls included, because two of the properties under test only
 * exist at that level: the batch depth is "commands out of one syscall", and a
 * reply can arrive before the command it answers when that command was bigger
 * than the capture budget (Р9's lazy tail). A harness that fed whole strings
 * would prove neither.
 *
 * The matrix, in the order МR2 lists it: pipelining at depth 1, 2 and 100; the
 * ring overflowing; a reply with no command; a resync in the middle of a batch;
 * a subscription whose deliveries must not shift the pairing, in both protocol
 * versions; and the three shapes of traffic that are not a request/response
 * stream at all. */
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

#define MAXOBS 512

struct obs {
    __u64 ts_start, ts_req_done, ts_first_row, ts_complete, ts_ready;
    __u64 bytes_in, bytes_out;
    __u32 depth;
    __u16 flags;
    __u8 kind;
    bool have_redis;
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
    r->ts_start = o->ts_start_ns;
    r->ts_req_done = o->ts_req_done_ns;
    r->ts_first_row = o->ts_first_row_ns;
    r->ts_complete = o->ts_complete_ns;
    r->ts_ready = o->ts_ready_ns;
    r->bytes_in = o->bytes_in;
    r->bytes_out = o->bytes_out;
    r->flags = o->flags;
    r->kind = o->kind;
    r->have_redis = o->redis != NULL;
    if (o->redis)
        r->depth = o->redis->pipeline_depth;
}

static struct lk_reasm reasm;
static struct lk_conn conn;
static struct lk_proto *proto;

static void teardown(void)
{
    const struct lk_msg_sink *sink;

    if (proto) {
        /* The live path fires this from the connection table on every removal
         * path; here the test drives it, so proto_state is released down the
         * same code the agent runs (Р15). */
        sink = lk_proto_sink(proto);
        sink->on_conn_close(sink->ctx, &conn);
        lk_proto_free(proto);
        proto = NULL;
    }
    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    free(conn.frame_state); /* the conn table does this in the live path */
    lk_reasm_free(&reasm);
}

/* `flags` seeds lk_conn.flags — LK_CONN_SYNTHETIC is how a test says "we joined
 * this connection mid-stream". */
static void reset_flags(__u16 flags)
{
    static const struct lk_query_sink qsink = {.on_query = on_query};

    teardown();
    memset(&conn, 0, sizeof(conn));
    conn.ops = &lk_proto_redis_ops;
    conn.flags = flags;
    conn.cookie = 0x6379;
    if (flags & LK_CONN_SYNTHETIC) {
        /* What the connection table does for a synthetic entry: framing can only
         * enter through a resync (Р10). */
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

/* One data event, modelled by off/total exactly as the agent's capture does, so
 * an under-captured call leaves the same lazy tail here as in production. */
static void feed(enum lk_dir dir, __u32 total, __u32 off, const void *p, __u32 cap, __u64 ts)
{
    static union {
        struct lk_ev_data d;
        __u8 raw[sizeof(struct lk_ev_data) + 65536];
    } u;

    memset(&u.d, 0, sizeof(u.d));
    u.d.hdr.ts_ns = ts;
    u.d.hdr.dir = dir;
    u.d.total_len = total;
    u.d.off = off;
    u.d.cap_len = cap;
    if (cap)
        memcpy(u.d.payload, p, cap);
    lk_reasm_data(&reasm, &conn, dir, &u.d, cap);
}

/* A whole syscall's worth of bytes, fully captured — one batch. */
static void call(enum lk_dir dir, const char *s, __u64 ts)
{
    feed(dir, (__u32)strlen(s), 0, s, (__u32)strlen(s), ts);
}

static void close_conn(__u64 ts)
{
    const struct lk_msg_sink *sink = lk_proto_sink(proto);

    conn.last_activity_ns = ts;
    sink->on_conn_close(sink->ctx, &conn);
}

static const struct lk_proto_stats *stats(void)
{
    return lk_proto_stats(proto);
}

static struct redis_conn *rconn(void)
{
    return conn.proto_state;
}

/* --- the ordinary shapes --------------------------------------------------- */

/* One command, one reply, one observation. The timings are the two RESP has and
 * no more: the command's first byte and the reply's last one — ts_req_done and
 * ts_first_row stay zero because the protocol has nothing to put in them, and a
 * consumer reading a TTFB out of this would be reading an invention (РR11). */
static int test_one_command(void)
{
    reset();
    call(LK_DIR_RECV, "*3\r\n$3\r\nSET\r\n$4\r\nlk:k\r\n$5\r\nhello\r\n", 100);
    call(LK_DIR_SEND, "+OK\r\n", 400);

    CHECK(nobs == 1);
    CHECK(obs[0].ts_start == 100 && obs[0].ts_complete == 400);
    CHECK(obs[0].ts_ready == 400 && !obs[0].ts_req_done && !obs[0].ts_first_row);
    CHECK(obs[0].bytes_in == 34 && obs[0].bytes_out == 5);
    CHECK(obs[0].have_redis && obs[0].depth == 1);
    CHECK(!(obs[0].flags & LK_QO_PIPELINED));
    CHECK(stats()->queries == 1 && stats()->orphan_msgs == 0 && stats()->pushes == 0);
    return 0;
}

/* An inline command is a command: `PING\r\n` from a healthcheck script gets a
 * reply and therefore an observation, and half the connections in a typical
 * deployment carry nothing else. */
static int test_inline_command(void)
{
    reset();
    call(LK_DIR_RECV, "PING\r\n", 10);
    call(LK_DIR_SEND, "+PONG\r\n", 20);
    /* An empty line is not a command — the server answers nothing — so it must
     * not open a unit that would then swallow the next reply. */
    call(LK_DIR_RECV, "\r\n", 30);
    call(LK_DIR_RECV, "ECHO hi\r\n", 40);
    call(LK_DIR_SEND, "$2\r\nhi\r\n", 50);

    CHECK(nobs == 2);
    CHECK(obs[0].ts_start == 10 && obs[0].ts_complete == 20);
    CHECK(obs[1].ts_start == 40 && obs[1].ts_complete == 50);
    CHECK(stats()->orphan_msgs == 0);
    return 0;
}

/* A frontend `*0` / `*-1` is a complete value the server answers with nothing at
 * all. It must not open a unit: the queue would be one ahead from then on, and
 * every later observation would be a plausible number belonging to the previous
 * command. */
static int test_empty_command_opens_nothing(void)
{
    reset();
    call(LK_DIR_RECV, "*0\r\n*-1\r\n*1\r\n$4\r\nPING\r\n", 10);
    call(LK_DIR_SEND, "+PONG\r\n", 20);

    CHECK(nobs == 1);
    CHECK(obs[0].ts_start == 10 && obs[0].ts_complete == 20);
    CHECK(obs[0].depth == 1); /* two non-commands do not deepen the batch */
    CHECK(stats()->orphan_msgs == 0);
    return 0;
}

/* --- pipelining (РR3) ------------------------------------------------------ */

/* Depth 2 in one write: both units carry LK_QO_PIPELINED — the first one's
 * duration is honest, the second one's start reflects a client that was not
 * waiting — and both report the batch they came out of. */
static int test_pipeline_two(void)
{
    reset();
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nPING\r\n", 10);
    call(LK_DIR_SEND, "+PONG\r\n", 20);
    call(LK_DIR_SEND, "+PONG\r\n", 30);

    CHECK(nobs == 2);
    CHECK(obs[0].ts_start == 10 && obs[0].ts_complete == 20);
    CHECK(obs[1].ts_start == 10 && obs[1].ts_complete == 30);
    CHECK((obs[0].flags & LK_QO_PIPELINED) && (obs[1].flags & LK_QO_PIPELINED));
    CHECK(obs[0].depth == 2 && obs[1].depth == 2);
    return 0;
}

/* memtier's `--pipeline 100`, which is also what every client library's own
 * batching API produces (МR0 measured five of them at exactly 100). One write,
 * one hundred units, one hundred observations in order. */
static int test_pipeline_hundred(void)
{
    char batch[100 * 14 + 1];
    __u32 off = 0;

    reset();
    for (int i = 0; i < 100; i++)
        off += (__u32)sprintf(batch + off, "*1\r\n$4\r\nPING\r\n");
    call(LK_DIR_RECV, batch, 10);
    for (int i = 0; i < 100; i++)
        call(LK_DIR_SEND, "+PONG\r\n", 100 + (__u64)i);

    CHECK(nobs == 100);
    for (int i = 0; i < 100; i++) {
        CHECK(obs[i].ts_start == 10 && obs[i].ts_complete == 100 + (__u64)i);
        CHECK(obs[i].depth == 100);
        CHECK(obs[i].flags & LK_QO_PIPELINED);
    }
    CHECK(stats()->orphan_msgs == 0 && stats()->units_dropped_overflow == 0);
    return 0;
}

/* Two batches, and the first one's depth survives the second one starting: a
 * command whose batch has been superseded reads the depth frozen into it, not
 * the one being counted now. */
static int test_batch_depth_frozen(void)
{
    reset();
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nPING\r\n", 10); /* batch of 2 */
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 20);                     /* batch of 1 */
    call(LK_DIR_SEND, "+PONG\r\n+PONG\r\n+PONG\r\n", 30);

    CHECK(nobs == 3);
    CHECK(obs[0].depth == 2 && obs[1].depth == 2 && obs[2].depth == 1);
    return 0;
}

/* A batch split across two syscalls is two batches, because that is what the
 * question means: go-redis writes 100 commands as 18 + 82 (measured), and the
 * second write did not wait for the first to be answered either. */
static int test_batch_split_across_calls(void)
{
    reset();
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nPING\r\n", 10);
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 11);
    call(LK_DIR_SEND, "+PONG\r\n+PONG\r\n+PONG\r\n", 20);

    CHECK(nobs == 3);
    CHECK(obs[0].depth == 2 && obs[1].depth == 2 && obs[2].depth == 1);
    /* ... and all three are pipelined: none of them was waited for. */
    for (int i = 0; i < 3; i++)
        CHECK(obs[i].flags & LK_QO_PIPELINED);
    return 0;
}

/* A command torn across two syscalls belongs to the call it *started* in — the
 * batch is where the client began writing, not where it happened to stop. */
static int test_torn_command_keeps_its_batch(void)
{
    reset();
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n*2\r\n$3\r\nGET\r\n", 10);
    call(LK_DIR_RECV, "$4\r\nlk:k\r\n", 20);
    call(LK_DIR_SEND, "+PONG\r\n$5\r\nhello\r\n", 30);

    CHECK(nobs == 2);
    CHECK(obs[0].ts_start == 10 && obs[1].ts_start == 10);
    CHECK(obs[0].depth == 2 && obs[1].depth == 2);
    return 0;
}

/* Past the ring the *newest* command is dropped, which is what keeps the queue a
 * FIFO: the units still in it pair with their replies correctly and only the
 * tail of the batch is lost. The replies to the dropped commands are skipped by
 * count, not mistaken for orphans. */
static int test_overflow(void)
{
    const int n = LK_REDIS_MAX_INFLIGHT + 8;

    reset();
    for (int i = 0; i < n; i++)
        call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 10 + (__u64)i);
    for (int i = 0; i < n; i++)
        call(LK_DIR_SEND, "+PONG\r\n", 1000 + (__u64)i);

    CHECK(nobs == LK_REDIS_MAX_INFLIGHT);
    CHECK(stats()->units_dropped_overflow == 8);
    CHECK(stats()->orphan_msgs == 0);
    /* The surviving units are the oldest eight-and-something hundred, in order. */
    CHECK(obs[0].ts_start == 10 && obs[0].ts_complete == 1000);
    return 0;
}

/* --- replies with nobody to answer ----------------------------------------- */

/* A reply on a connection we have watched from its first byte, with nothing in
 * flight, is a message we had no business losing — the definition of an orphan.
 * It is not a parse error: the bytes were fine. */
static int test_orphan_reply(void)
{
    reset();
    call(LK_DIR_SEND, "+PONG\r\n", 10);

    CHECK(nobs == 0);
    CHECK(stats()->orphan_msgs == 1 && stats()->parse_errors == 0);
    return 0;
}

/* On a connection joined mid-stream the same reply is the *expected* shape, and
 * counting it would swamp the tally exactly where it stops meaning anything. It
 * stops being expected at the first command, which is the first boundary the
 * frontend anchor can vouch for. */
static int test_orphan_suppressed_when_degraded(void)
{
    reset_flags(LK_CONN_SYNTHETIC);
    /* The backend anchor is a valid type byte at a call boundary. */
    call(LK_DIR_SEND, "+PONG\r\n", 10);
    CHECK(stats()->orphan_msgs == 0);

    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 20); /* the frontend anchor */
    call(LK_DIR_SEND, "+PONG\r\n", 30);
    CHECK(nobs == 1 && obs[0].ts_start == 20);

    call(LK_DIR_SEND, "+PONG\r\n", 40); /* now it counts */
    CHECK(stats()->orphan_msgs == 1);
    return 0;
}

/* Р9's lazy tail, and the reason the handler holds a reply instead of orphaning
 * it: a command bigger than the capture budget has an uncaptured tail, and the
 * framer only learns that tail existed when the *next* call on that direction
 * starts. So the reply is published first. Without the memo the pairing would
 * slip by one and stay slipped — three plausible durations belonging to the
 * wrong commands, which is the failure mode the queue exists to prevent
 * (measured on `redis/bigvalue.lkt`, where it cost one observation of four). */
static int test_reply_before_its_command(void)
{
    reset();
    /* A 1 KB `SET` of which 34 bytes were captured: the value stays open. */
    feed(LK_DIR_RECV, 1024, 0, "*3\r\n$3\r\nSET\r\n$4\r\nlk:k\r\n$993\r\nxxxxx", 34, 100);
    CHECK(nobs == 0);
    call(LK_DIR_SEND, "+OK\r\n", 200); /* the reply arrives first */
    CHECK(nobs == 0 && stats()->orphan_msgs == 0);

    /* The next call closes the previous one: its tail becomes a hole, the
     * command is published, and it claims the reply that was waiting. */
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 300);
    CHECK(nobs == 1);
    CHECK(obs[0].ts_start == 100 && obs[0].ts_complete == 200);
    CHECK(obs[0].bytes_in == 1024 && obs[0].bytes_out == 5);

    call(LK_DIR_SEND, "+PONG\r\n", 400);
    CHECK(nobs == 2 && obs[1].ts_start == 300 && obs[1].ts_complete == 400);
    CHECK(stats()->orphan_msgs == 0);
    return 0;
}

/* A reply spanning several capture events is timed to its *last* byte: a 17 MB
 * `KEYS *` takes 212 writes on the wire (`redis/keys-1m.lkt`), and timing it to
 * the first would report the server as faster than it was. */
static int test_reply_end_timestamp(void)
{
    reset();
    call(LK_DIR_RECV, "*2\r\n$3\r\nGET\r\n$4\r\nlk:k\r\n", 100);
    feed(LK_DIR_SEND, 4008, 0, "$3999\r\nxxxx", 11, 200);
    CHECK(nobs == 0);
    feed(LK_DIR_SEND, 4008, 11, "yyyy", 4, 300); /* the rest is uncaptured tail */
    CHECK(nobs == 0);

    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 400);
    call(LK_DIR_SEND, "+PONG\r\n", 500); /* the new call reveals the tail hole */

    CHECK(nobs == 2);
    CHECK(obs[0].ts_start == 100);
    /* The last event that actually carried bytes of the value, not the one that
     * merely revealed how many were missing. */
    CHECK(obs[0].ts_complete == 300 && obs[0].bytes_out == 4008);
    CHECK(obs[1].ts_start == 400 && obs[1].ts_complete == 500);
    return 0;
}

/* --- pub/sub (РR8) --------------------------------------------------------- */

/* RESP2: a delivery is an ordinary array and is told from a reply by the kind
 * word in its first element. Let one close a unit and every latency on the
 * connection afterwards belongs to the wrong command — which is why this is a
 * correctness test and not a counting one. */
static int test_resp2_subscription(void)
{
    reset();
    call(LK_DIR_RECV, "*2\r\n$9\r\nSUBSCRIBE\r\n$7\r\nlk:chan\r\n", 100);
    call(LK_DIR_SEND, "*3\r\n$9\r\nsubscribe\r\n$7\r\nlk:chan\r\n:1\r\n", 110);
    CHECK(nobs == 1 && obs[0].ts_start == 100 && obs[0].ts_complete == 110);

    /* Three publications by somebody else: counted, and they close nothing. */
    for (int i = 0; i < 3; i++)
        call(LK_DIR_SEND, "*3\r\n$7\r\nmessage\r\n$7\r\nlk:chan\r\n$2\r\nhi\r\n", 200 + (__u64)i);
    CHECK(nobs == 1);
    CHECK(stats()->pushes == 3 && stats()->orphan_msgs == 0);

    /* A `PING` while subscribed answers `*2 ["pong", ""]` — an array, not
     * `+PONG` (measured, `redis/pubsub.lkt`). Its first element is no kind word,
     * so it is an ordinary reply and closes the unit it should. */
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 300);
    call(LK_DIR_SEND, "*2\r\n$4\r\npong\r\n$0\r\n\r\n", 310);
    CHECK(nobs == 2 && obs[1].ts_start == 300 && obs[1].ts_complete == 310);
    CHECK(stats()->pushes == 3);
    return 0;
}

/* One `SUBSCRIBE a b` is one command and **two** confirmations, one per channel.
 * The first answers the unit; the second answers nothing still queued, and both
 * closing a unit and calling the extra one an orphan would be wrong — the first
 * would credit the next command with a latency it never had, the second would
 * report a loss where nothing was lost. */
static int test_multi_channel_subscribe(void)
{
    reset();
    call(LK_DIR_RECV, "*3\r\n$9\r\nSUBSCRIBE\r\n$2\r\nc1\r\n$2\r\nc2\r\n", 100);
    call(LK_DIR_SEND, "*3\r\n$9\r\nsubscribe\r\n$2\r\nc1\r\n:1\r\n", 110);
    call(LK_DIR_SEND, "*3\r\n$9\r\nsubscribe\r\n$2\r\nc2\r\n:2\r\n", 120);

    CHECK(nobs == 1 && obs[0].ts_complete == 110);
    CHECK(stats()->pushes == 1 && stats()->orphan_msgs == 0);

    /* And the queue is still aligned: the next command gets its own reply. */
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 200);
    call(LK_DIR_SEND, "*2\r\n$4\r\npong\r\n$0\r\n\r\n", 210);
    CHECK(nobs == 2 && obs[1].ts_start == 200 && obs[1].ts_complete == 210);
    return 0;
}

/* RESP3: the confirmation of a SUBSCRIBE *is* a push, so "a push never closes a
 * unit" — what РR8 proposed — would leave every SUBSCRIBE unit open for ever.
 * The kind word decides here too, and an ordinary command keeps working while
 * subscribed, which is the branch where the queue and the push stream genuinely
 * interleave (measured, `redis/pubsub3.lkt`). */
static int test_resp3_subscription(void)
{
    reset();
    call(LK_DIR_RECV, "*2\r\n$9\r\nSUBSCRIBE\r\n$7\r\nlk:chan\r\n", 100);
    call(LK_DIR_SEND, ">3\r\n$9\r\nsubscribe\r\n$7\r\nlk:chan\r\n:1\r\n", 110);
    CHECK(nobs == 1 && obs[0].ts_complete == 110);

    call(LK_DIR_RECV, "*2\r\n$3\r\nGET\r\n$4\r\nlk:k\r\n", 200);
    call(LK_DIR_SEND, ">3\r\n$7\r\nmessage\r\n$7\r\nlk:chan\r\n$2\r\nhi\r\n", 210);
    CHECK(nobs == 1); /* the delivery is not the answer to the GET */
    call(LK_DIR_SEND, "$5\r\nhello\r\n", 220);
    CHECK(nobs == 2 && obs[1].ts_start == 200 && obs[1].ts_complete == 220);
    CHECK(stats()->pushes == 1);
    return 0;
}

/* A client-side-caching invalidation is a push nobody asked for and arrives on a
 * connection that never subscribed to anything (`redis/tracking.lkt`). The `>`
 * type byte says so without any connection state at all. */
static int test_invalidate_push(void)
{
    reset();
    call(LK_DIR_RECV, "*2\r\n$3\r\nGET\r\n$4\r\nlk:k\r\n", 100);
    call(LK_DIR_SEND, ">2\r\n$10\r\ninvalidate\r\n*1\r\n$4\r\nlk:k\r\n", 110);
    CHECK(nobs == 0 && stats()->pushes == 1);
    call(LK_DIR_SEND, "$5\r\nhello\r\n", 120);
    CHECK(nobs == 1 && obs[0].ts_complete == 120);
    return 0;
}

/* An attribute is a *prefix* to the value that follows and never a reply of its
 * own. Closing a unit on one would answer this command with the decoration and
 * every later command with the previous command's reply. */
static int test_attribute_closes_nothing(void)
{
    reset();
    call(LK_DIR_RECV, "*2\r\n$3\r\nGET\r\n$4\r\nlk:k\r\n", 100);
    call(LK_DIR_SEND, "|1\r\n$3\r\nttl\r\n:60\r\n", 110);
    CHECK(nobs == 0 && stats()->pushes == 0);
    call(LK_DIR_SEND, "$5\r\nhello\r\n", 120);
    CHECK(nobs == 1 && obs[0].ts_complete == 120);
    CHECK(stats()->orphan_msgs == 0);
    return 0;
}

/* An array whose first element happens to be the word "message" is an ordinary
 * reply on a connection that never subscribed — a `LRANGE` may perfectly well
 * return one. The kind words are read only where they mean something. */
static int test_kind_words_only_when_subscribed(void)
{
    reset();
    call(LK_DIR_RECV, "*4\r\n$6\r\nLRANGE\r\n$4\r\nlk:l\r\n$1\r\n0\r\n$2\r\n-1\r\n", 100);
    call(LK_DIR_SEND, "*3\r\n$7\r\nmessage\r\n$7\r\nlk:chan\r\n$2\r\nhi\r\n", 110);

    CHECK(nobs == 1 && obs[0].ts_complete == 110);
    CHECK(stats()->pushes == 0 && stats()->orphan_msgs == 0);
    return 0;
}

/* --- loss and lifetime ----------------------------------------------------- */

/* A hole in the middle of a batch is unrecoverable by construction: an aggregate
 * carries an element count and not a byte length, so there is no arithmetic that
 * steps over it and no way to know how many commands went past unseen. Every
 * queued unit goes — an observation that survived a resync would pair a command
 * with somebody else's answer (Р19, risk 1 of the plan). */
static int test_resync_drops_the_queue(void)
{
    reset();
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nPING\r\n", 10);
    CHECK(rconn()->open_seq - rconn()->head_seq == 2);

    /* An under-captured call whose tail lands inside an aggregate. */
    feed(LK_DIR_RECV, 100, 0, "*3\r\n$3\r\nSET\r\n", 13, 20);
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 30);

    CHECK(stats()->units_dropped_resync == 2);
    CHECK(nobs == 0);
    /* ... and the direction came back at the next call boundary, with a unit of
     * its own that pairs correctly. */
    call(LK_DIR_SEND, "+PONG\r\n", 40);
    CHECK(nobs == 1 && obs[0].ts_start == 30 && obs[0].ts_complete == 40);
    return 0;
}

/* A command still waiting for its reply when the socket dies is not an
 * observation: unlike HTTP, where a bodiless response is *completed* by the
 * close, RESP has no reply whose end is the connection's end (Р19). */
static int test_close_drops_the_queue(void)
{
    reset();
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 10);
    close_conn(20);

    CHECK(nobs == 0);
    CHECK(stats()->units_dropped_close == 1);
    CHECK(conn.proto_state == NULL); /* Р15: released on every removal path */
    return 0;
}

/* Risk 4's backstop. Pub/Sub and RESP3 pushes are recognised, but Redis has
 * other ways to put an unsolicited value on the wire, and one unrecognised one
 * would leave the queue permanently one behind. A queue older than any legal
 * blocking command is flushed rather than trusted — `BLPOP key 0` blocks for
 * ever and is legal, so the units go and the connection stays. */
static int test_unit_timeout(void)
{
    reset();
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 10);
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 20 + LK_REDIS_UNIT_TIMEOUT_NS);

    CHECK(stats()->units_dropped_close == 1);
    call(LK_DIR_SEND, "+PONG\r\n", 30 + LK_REDIS_UNIT_TIMEOUT_NS);
    CHECK(nobs == 1);
    CHECK(obs[0].ts_start == 20 + LK_REDIS_UNIT_TIMEOUT_NS);
    return 0;
}

/* --- the connections that are not a request/response stream (РR14) --------- */

/* After `PSYNC` the connection carries an RDB image and then a stream of write
 * commands *from the server*, none of which answers anything. Parsing that as
 * replies is not a degradation, it is guaranteed nonsense. */
static int test_psync_ignored(void)
{
    reset();
    call(LK_DIR_RECV, "*3\r\n$5\r\nPSYNC\r\n$1\r\n?\r\n$2\r\n-1\r\n", 10);

    CHECK(conn.flags & LK_CONN_IGNORE);
    CHECK(stats()->replication_conns == 1);
    /* The framer discards everything from here: the propagated writes that
     * follow produce neither observations nor orphans. */
    call(LK_DIR_SEND, "+FULLRESYNC abc 0\r\n", 20);
    call(LK_DIR_SEND, "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n", 30);
    CHECK(nobs == 0 && stats()->orphan_msgs == 0);
    return 0;
}

/* A replication link joined *after* its handshake — which is what the МR0
 * corpus actually contains (`libs/java-pipeline.lkt`) — leaves only one mark on
 * the wire: the replica's periodic `REPLCONF ACK`. Only a replica sends
 * `REPLCONF` at all, so any of them is the marker. */
static int test_replconf_ack_ignored(void)
{
    reset_flags(LK_CONN_SYNTHETIC);
    call(LK_DIR_RECV, "*3\r\n$8\r\nREPLCONF\r\n$3\r\nACK\r\n$3\r\n123\r\n", 10);

    CHECK(conn.flags & LK_CONN_IGNORE);
    CHECK(stats()->replication_conns == 1);
    call(LK_DIR_SEND, "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n", 20);
    CHECK(nobs == 0 && stats()->orphan_msgs == 0);
    return 0;
}

/* `MONITOR` turns the connection into a feed of every *other* client's commands,
 * one simple string each. Its own reason, because "there is a replica here" and
 * "somebody left a debugging tool attached to a single-threaded server" are
 * different facts about a deployment. */
static int test_monitor_ignored(void)
{
    reset();
    call(LK_DIR_RECV, "*1\r\n$7\r\nMONITOR\r\n", 10);

    CHECK(conn.flags & LK_CONN_IGNORE);
    CHECK(stats()->monitor_conns == 1 && stats()->replication_conns == 0);
    call(LK_DIR_SEND, "+OK\r\n", 20);
    call(LK_DIR_SEND, "+1786889998.9 [0 127.0.0.1:47914] \"SET\" \"lk:mon\" \"v\"\r\n", 30);
    CHECK(nobs == 0 && stats()->orphan_msgs == 0);
    return 0;
}

/* The verb is read for four questions and never as an identity: a key that
 * spells `MONITOR` is an argument, and arguments decide nothing here (РR4). */
static int test_verb_is_not_the_key(void)
{
    reset();
    call(LK_DIR_RECV, "*2\r\n$3\r\nGET\r\n$7\r\nMONITOR\r\n", 10);
    call(LK_DIR_SEND, "$3\r\nabc\r\n", 20);

    CHECK(!(conn.flags & LK_CONN_IGNORE));
    CHECK(stats()->monitor_conns == 0);
    CHECK(nobs == 1 && obs[0].ts_complete == 20);
    return 0;
}

/* `RESET` leaves subscribe mode, and the connection is an ordinary client again
 * — including for the kind-word rule, which is the part of `RESET` this
 * milestone owns (the database, the user and the transaction are МR3's and
 * МR4's). */
static int test_reset_leaves_subscribe_mode(void)
{
    reset();
    call(LK_DIR_RECV, "*2\r\n$9\r\nSUBSCRIBE\r\n$2\r\nc1\r\n", 10);
    call(LK_DIR_SEND, "*3\r\n$9\r\nsubscribe\r\n$2\r\nc1\r\n:1\r\n", 20);
    CHECK(rconn()->sub);

    call(LK_DIR_RECV, "*1\r\n$5\r\nRESET\r\n", 30);
    CHECK(!rconn()->sub);
    call(LK_DIR_SEND, "+RESET\r\n", 40);
    CHECK(nobs == 2 && obs[1].ts_start == 30 && obs[1].ts_complete == 40);
    return 0;
}

int main(void)
{
    if (test_one_command() || test_inline_command() || test_empty_command_opens_nothing() ||
        test_pipeline_two() || test_pipeline_hundred() || test_batch_depth_frozen() ||
        test_batch_split_across_calls() || test_torn_command_keeps_its_batch() || test_overflow() ||
        test_orphan_reply() || test_orphan_suppressed_when_degraded() ||
        test_reply_before_its_command() || test_reply_end_timestamp() ||
        test_resp2_subscription() || test_multi_channel_subscribe() || test_resp3_subscription() ||
        test_invalidate_push() || test_attribute_closes_nothing() ||
        test_kind_words_only_when_subscribed() || test_resync_drops_the_queue() ||
        test_close_drops_the_queue() || test_unit_timeout() || test_psync_ignored() ||
        test_replconf_ack_ignored() || test_monitor_ignored() || test_verb_is_not_the_key() ||
        test_reset_leaves_subscribe_mode())
        return 1;
    teardown();
    printf("ok\n");
    return 0;
}
