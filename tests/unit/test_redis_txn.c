// SPDX-License-Identifier: GPL-2.0
/* Unit tests for `MULTI`/`EXEC` (PLAN-REDIS.md МR4, РR9) — the same real chain
 * as the rest of the Redis unit tests: bytes → stream framer → lk_msg → handler
 * → lk_query_obs plus, here, the transaction callback.
 *
 * Two things are being measured and they are not the same thing:
 *
 *   - the commands **inside** a transaction are answered `+QUEUED` in
 *     microseconds. The server has done nothing but write them down, so their
 *     duration measures how fast it can say "noted" — real observations
 *     (`commands_total` counts them) whose latency is worth nothing at all, and
 *     which in a histogram beside real work drag every percentile down. They
 *     carry LK_QO_QUEUED and the facade skips the histogram.
 *   - the **transaction** is the interval `MULTI` → the reply to `EXEC`. That is
 *     what the application waited for, and it is the same thing
 *     `latkit_txn_duration_seconds` already means for PG and MySQL — the one
 *     place in this track where a cache fits an existing database family exactly.
 *
 * The five endings the МR0 corpus recorded are each a case below, because each
 * of them ends the transaction differently and one of them (`WATCH` broken) is
 * not an error at all: `EXEC` answers a **null**, and a machine reading only the
 * error bit would call a rolled-back transaction committed. */
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

/* --- captured observations and transactions -------------------------------- */

#define MAXOBS 64

struct obs {
    char cmd[LK_REDIS_NAME_MAX];
    __u64 dur;
    __u16 flags;
};

struct txn {
    __u64 start, end;
    char final;
};

static struct obs obs[MAXOBS];
static struct txn txn[MAXOBS];
static int nobs, ntxn;

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

static void on_txn(void *ctx, const struct lk_conn *c, __u64 start_ns, __u64 end_ns, char final)
{
    struct txn *t = &txn[ntxn % MAXOBS];

    (void)ctx;
    (void)c;
    ntxn++;
    t->start = start_ns;
    t->end = end_ns;
    t->final = final;
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
    static const struct lk_query_sink qsink = {.on_query = on_query, .on_txn = on_txn};

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
    nobs = ntxn = 0;
}

static void reset(void)
{
    reset_flags(0);
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

/* An exchange on a clock that advances by a known amount, so the transaction's
 * interval can be asserted exactly rather than "greater than zero" — which is
 * the claim the МR4 acceptance actually makes about it. Each command starts at
 * a multiple of 100 and is answered 10 later. */
static __u64 clock;

static void exchange(const char *cmd, const char *reply)
{
    call(LK_DIR_RECV, cmd, clock);
    call(LK_DIR_SEND, reply, clock + 10);
    clock += 100;
}

static void close_conn(void)
{
    const struct lk_msg_sink *sink = lk_proto_sink(proto);

    sink->on_conn_close(sink->ctx, &conn);
}

#define MULTI   "*1\r\n$5\r\nMULTI\r\n"
#define EXEC    "*1\r\n$4\r\nEXEC\r\n"
#define DISCARD "*1\r\n$7\r\nDISCARD\r\n"
#define SET     "*3\r\n$3\r\nSET\r\n$4\r\nlk:a\r\n$1\r\n1\r\n"
#define INCR    "*2\r\n$4\r\nINCR\r\n$4\r\nlk:n\r\n"
#define QUEUED  "+QUEUED\r\n"

static void begin(void)
{
    reset();
    clock = 1000;
}

/* --- the five endings ------------------------------------------------------ */

/* Commit. Three observations inside the transaction carry LK_QO_QUEUED and the
 * three that bracket them do not; the interval runs from the `MULTI`'s first
 * byte to the last byte of the reply to `EXEC`, which here is 1000 → 1310. */
static int test_commit(void)
{
    begin();
    exchange(MULTI, "+OK\r\n");            /* 1000 … 1010 */
    exchange(SET, QUEUED);                 /* 1100 … 1110 */
    exchange(INCR, QUEUED);                /* 1200 … 1210 */
    exchange(EXEC, "*2\r\n+OK\r\n:1\r\n"); /* 1300 … 1310 */

    CHECK(nobs == 4 && ntxn == 1);
    CHECK(!strcmp(obs[0].cmd, "MULTI") && !(obs[0].flags & LK_QO_QUEUED));
    CHECK(!strcmp(obs[1].cmd, "SET") && (obs[1].flags & LK_QO_QUEUED));
    CHECK(!strcmp(obs[2].cmd, "INCR") && (obs[2].flags & LK_QO_QUEUED));
    CHECK(!strcmp(obs[3].cmd, "EXEC") && !(obs[3].flags & LK_QO_QUEUED));
    /* A queued command is still an observation with a duration on it — the
     * flag says the duration means nothing, and it is the facade that acts on
     * that (metrics.c). The handler does not invent a zero. */
    CHECK(obs[1].dur == 10);
    CHECK(txn[0].start == 1000 && txn[0].end == 1310 && txn[0].final == 'I');
    return 0;
}

/* `DISCARD`: nothing runs, and the interval is reported as thrown away. A
 * transaction that was abandoned on purpose is not a failure of anything, but it
 * is also not a commit, and `latkit_txn_duration_seconds` splits exactly there. */
static int test_discard(void)
{
    begin();
    exchange(MULTI, "+OK\r\n");
    exchange(SET, QUEUED);
    exchange(DISCARD, "+OK\r\n");

    CHECK(nobs == 3 && ntxn == 1);
    CHECK(txn[0].start == 1000 && txn[0].end == 1210 && txn[0].final == 'E');
    CHECK(!(obs[2].flags & LK_QO_QUEUED)); /* the `DISCARD` itself is not queued */
    return 0;
}

/* A queue-time error poisons the transaction: the offending command is refused
 * *instead* of being queued — so it is an ordinary error with an ordinary
 * duration, not a `+QUEUED` — and the `EXEC` after it is `-EXECABORT`. */
static int test_execabort(void)
{
    begin();
    exchange(MULTI, "+OK\r\n");
    exchange("*1\r\n$13\r\nNOSUCHCOMMAND\r\n", "-ERR unknown command 'NOSUCHCOMMAND'\r\n");
    exchange(SET, QUEUED);
    exchange(EXEC, "-EXECABORT Transaction discarded because of previous errors.\r\n");

    CHECK(nobs == 4 && ntxn == 1);
    CHECK(!strcmp(obs[1].cmd, "other"));
    CHECK((obs[1].flags & LK_QO_ERROR) && !(obs[1].flags & LK_QO_QUEUED));
    CHECK((obs[3].flags & LK_QO_ERROR) && !(obs[3].flags & LK_QO_QUEUED));
    CHECK(txn[0].final == 'E' && txn[0].end == 1310);
    return 0;
}

/* A run-time error is an element *inside* the array `EXEC` returns, and the
 * transaction commits regardless (notes-redisproto.md §"Transactions"). The
 * top-level value is an array, so nothing about it is an error — and reading
 * inside it would be reading a value, which this tree does not do. */
static int test_runtime_error_still_commits(void)
{
    begin();
    exchange(MULTI, "+OK\r\n");
    exchange("*3\r\n$5\r\nLPUSH\r\n$4\r\nlk:s\r\n$1\r\nx\r\n", QUEUED);
    exchange(SET, QUEUED);
    exchange(EXEC, "*2\r\n-WRONGTYPE Operation against a key\r\n+OK\r\n");

    CHECK(nobs == 4 && ntxn == 1);
    CHECK(!(obs[3].flags & LK_QO_ERROR) && obs[3].dur == 10);
    CHECK(txn[0].final == 'I');
    return 0;
}

/* A broken `WATCH`: `EXEC` answers `*-1` in RESP2 and `_` in RESP3 — a **null,
 * not an error** — and the transaction did not happen. This is the case that
 * makes the verdict need more than the error bit. */
static int test_watch_aborts(void)
{
    begin();
    exchange("*2\r\n$5\r\nWATCH\r\n$4\r\nlk:w\r\n", "+OK\r\n");
    exchange(MULTI, "+OK\r\n");
    exchange(INCR, QUEUED);
    exchange(EXEC, "*-1\r\n");

    CHECK(nobs == 4 && ntxn == 1);
    CHECK(!(obs[3].flags & LK_QO_ERROR)); /* a null is not a failure */
    CHECK(txn[0].start == 1100 && txn[0].final == 'E');

    /* RESP3 spells the same thing `_`. */
    begin();
    exchange(MULTI, "+OK\r\n");
    exchange(INCR, QUEUED);
    exchange(EXEC, "_\r\n");
    CHECK(ntxn == 1 && txn[0].final == 'E');

    /* ... and `*0`, which is a transaction that ran no commands, committed.
     * The two differ by one byte on the wire and by everything here. */
    begin();
    exchange(MULTI, "+OK\r\n");
    exchange(EXEC, "*0\r\n");
    CHECK(ntxn == 1 && txn[0].final == 'I');
    return 0;
}

/* Abandoned: the connection dies with the transaction open. Nothing is
 * reported — the interval has no end, and Р19 says an observation may not span a
 * disconnect. Truncating it at the close would invent a transaction the
 * application never completed. */
static int test_abandoned(void)
{
    begin();
    exchange(MULTI, "+OK\r\n");
    exchange(SET, QUEUED);
    close_conn();

    CHECK(nobs == 2 && ntxn == 0);
    return 0;
}

/* --- the shapes that must not move the interval ----------------------------- */

/* A nested `MULTI` is `-ERR MULTI calls can not be nested` and the transaction
 * already open survives untouched. If the second `MULTI` moved the start stamp,
 * the interval would begin at the wrong command and be short by however long the
 * transaction had already been running. */
static int test_nested_multi(void)
{
    begin();
    exchange(MULTI, "+OK\r\n");
    exchange(MULTI, "-ERR MULTI calls can not be nested\r\n");
    exchange(EXEC, "*0\r\n");

    CHECK(nobs == 3 && ntxn == 1);
    CHECK(obs[1].flags & LK_QO_ERROR);
    CHECK(txn[0].start == 1000 && txn[0].end == 1210 && txn[0].final == 'I');
    return 0;
}

/* `EXEC` and `DISCARD` outside a transaction are `-ERR … without MULTI`: real
 * observations, and no interval to report. Also the shape of a connection joined
 * mid-stream, where the `MULTI` happened before we were watching — one
 * transaction missing is the honest answer, one measured from an invented start
 * is not. */
static int test_exec_without_multi(void)
{
    begin();
    exchange(EXEC, "-ERR EXEC without MULTI\r\n");
    exchange(DISCARD, "-ERR DISCARD without MULTI\r\n");

    CHECK(nobs == 2 && ntxn == 0);
    CHECK((obs[0].flags & LK_QO_ERROR) && (obs[1].flags & LK_QO_ERROR));
    return 0;
}

/* A `MULTI` the server refused opens nothing at all, so the `EXEC` that follows
 * has no interval to close. (`MULTI` is refused inside a subscribe-mode
 * connection on RESP2, among other places.) */
static int test_refused_multi_opens_nothing(void)
{
    begin();
    exchange(MULTI, "-ERR MULTI is not allowed in this context\r\n");
    exchange(EXEC, "-ERR EXEC without MULTI\r\n");

    CHECK(nobs == 2 && ntxn == 0);
    return 0;
}

/* `RESET` returns the connection to a virgin state, and that includes throwing
 * away an open transaction (РR5's twin rule). Reported as aborted, because that
 * is what happened to it. */
static int test_reset_discards(void)
{
    begin();
    exchange(MULTI, "+OK\r\n");
    exchange(SET, QUEUED);
    exchange("*1\r\n$5\r\nRESET\r\n", "+RESET\r\n");

    CHECK(nobs == 3 && ntxn == 1);
    CHECK(txn[0].start == 1000 && txn[0].end == 1210 && txn[0].final == 'E');
    return 0;
}

/* A resync in the middle of a transaction takes the interval with it: after a
 * hole we cannot say how many commands went past unseen, so the `EXEC` we might
 * see later would close an interval over an unknown stretch of time (Р19, and
 * the same rule that drops the in-flight units). */
static int test_resync_drops_the_transaction(void)
{
    begin();
    exchange(MULTI, "+OK\r\n");
    exchange(SET, QUEUED);
    /* An under-captured call whose tail lands inside an aggregate: the framer
     * cannot step over it, and the direction goes dirty. */
    feed(LK_DIR_RECV, 100, "*3\r\n$3\r\nSET\r\n", 13, clock);
    clock += 100;
    exchange(EXEC, "*0\r\n");

    CHECK(ntxn == 0);
    return 0;
}

/* The whole transaction in one syscall, which is what every client library
 * measured in МR0 actually does: the queue and the transaction machine have to
 * agree about a batch, since the `+QUEUED` replies arrive together and the
 * pairing is order and nothing else. */
static int test_pipelined_transaction(void)
{
    begin();
    call(LK_DIR_RECV, MULTI SET INCR EXEC, 1000);
    call(LK_DIR_SEND, "+OK\r\n" QUEUED QUEUED "*2\r\n+OK\r\n:1\r\n", 2000);

    CHECK(nobs == 4 && ntxn == 1);
    CHECK(!strcmp(obs[0].cmd, "MULTI") && !strcmp(obs[3].cmd, "EXEC"));
    CHECK((obs[1].flags & LK_QO_QUEUED) && (obs[2].flags & LK_QO_QUEUED));
    CHECK(!(obs[0].flags & LK_QO_QUEUED) && !(obs[3].flags & LK_QO_QUEUED));
    CHECK(txn[0].start == 1000 && txn[0].end == 2000 && txn[0].final == 'I');
    return 0;
}

/* `+QUEUED` is read off the reply and not deduced from a `MULTI` we saw, which
 * is what makes it right on a connection joined mid-stream: the transaction
 * started before we were watching, its commands are still not latencies, and the
 * interval is still not reported. */
static int test_midstream_queued(void)
{
    reset_flags(LK_CONN_SYNTHETIC);
    clock = 1000;
    /* The first exchange is what re-enters framing on both directions, and its
     * unit goes with the backend's resync — a connection joined mid-stream costs
     * one exchange, which is МR2's rule and not this milestone's. */
    exchange(SET, QUEUED);
    exchange(SET, QUEUED);
    exchange(EXEC, "*1\r\n+OK\r\n");

    CHECK(nobs == 2 && ntxn == 0);
    CHECK(obs[0].flags & LK_QO_QUEUED);
    CHECK(!strcmp(obs[1].cmd, "EXEC") && !(obs[1].flags & LK_QO_QUEUED));
    return 0;
}

int main(void)
{
    if (test_commit() || test_discard() || test_execabort() || test_runtime_error_still_commits() ||
        test_watch_aborts() || test_abandoned() || test_nested_multi() ||
        test_exec_without_multi() || test_refused_multi_opens_nothing() || test_reset_discards() ||
        test_resync_drops_the_transaction() || test_pipelined_transaction() ||
        test_midstream_queued())
        return 1;
    teardown();
    printf("ok\n");
    return 0;
}
