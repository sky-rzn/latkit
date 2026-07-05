// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the connection table (task 2.2). The seq-hole scenarios are
 * carried over from the stage-1 seqtrack tests (consecutive seqs silent,
 * forward jumps report the exact hole size, stragglers not double-counted,
 * CLOSE frees the entry, colliding cookies independent), plus the table
 * behaviour on top: holes dirty both directions, the LRU ceiling and the
 * idle sweep evict, an entry re-created after eviction starts dirty. */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conn_table.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static const struct lk_tuple tuple = {.family = 2 /* AF_INET */, .sport = 12345, .dport = 5432};

static bool is_dirty(const struct lk_conn *c)
{
    return c->frame[LK_DIR_SEND].st == LK_FR_DIRTY && c->frame[LK_DIR_RECV].st == LK_FR_DIRTY;
}

/* Seq-hole detection: the seqtrack scenarios on the table API. */
static int test_seq_holes(void)
{
    struct lk_conn_table *t = lk_conn_table_new(LK_MAX_CONNS_DEFAULT, 600ULL * 1000000000);
    struct lk_conn *c;
    __u32 lost;

    CHECK(t);

    /* A clean consecutive stream never reports and stays clean. */
    c = lk_conn_table_open(t, 1, 0, 100, &tuple, false, &lost);
    CHECK(c && lost == 0);
    CHECK(!(c->flags & LK_CONN_SYNTHETIC) && !is_dirty(c));
    CHECK(c->tuple.dport == 5432);
    CHECK(lk_conn_table_data(t, 1, 1, 110, &lost) == c && lost == 0);
    CHECK(lk_conn_table_data(t, 1, 2, 120, &lost) == c && lost == 0);
    CHECK(!is_dirty(c) && c->dropped == 0);
    CHECK(c->last_activity_ns == 120);

    /* seq jumping to 5 -> skipping 3,4 means exactly 2 lost events; the hole
     * dirties both directions (seq is per-connection, Р9). */
    CHECK(lk_conn_table_data(t, 1, 5, 130, &lost) == c && lost == 2);
    CHECK(is_dirty(c) && c->dropped == 2);
    CHECK(lk_conn_table_data(t, 1, 6, 140, &lost) == c && lost == 0); /* stream resumes */

    /* An out-of-order straggler (two CPUs racing reserve after fetch_add)
     * steps backward: not loss, and last_seq must not regress — the next
     * in-order event stays silent. */
    CHECK(lk_conn_table_data(t, 1, 4, 150, &lost) == c && lost == 0);
    CHECK(lk_conn_table_data(t, 1, 7, 160, &lost) == c && lost == 0);

    /* A duplicate of the current seq is not loss either. */
    CHECK(lk_conn_table_data(t, 1, 7, 170, &lost) == c && lost == 0);

    /* Connections do not interfere: a second cookie starts its own stream.
     * Note: an unknown cookie on a data event is a lazy (dirty) create. */
    c = lk_conn_table_data(t, 2, 0, 200, &lost);
    CHECK(c && lost == 0 && is_dirty(c));
    CHECK(lk_conn_table_data(t, 1, 8, 210, &lost) && lost == 0);
    CHECK(lk_conn_table_data(t, 2, 3, 220, &lost) == c && lost == 2);

    /* The gap check still runs on the closing event itself... */
    lk_conn_table_close(t, 2, 6, 230, &lost);
    CHECK(lost == 2);
    /* ...and CLOSE frees the entry: the same cookie restarts from scratch
     * (cookies are never reused by the kernel, but a lost-and-recreated
     * entry must not inherit stale state). */
    c = lk_conn_table_open(t, 2, 100, 240, &tuple, false, &lost);
    CHECK(c && lost == 0 && !is_dirty(c) && c->dropped == 0);
    lk_conn_table_close(t, 2, 101, 250, &lost);
    CHECK(lost == 0);

    /* CLOSE for a cookie that was never seen (its whole life was lost or
     * predates the agent) must not report or crash. */
    lk_conn_table_close(t, 999, 50, 260, &lost);
    CHECK(lost == 0);

    /* First sighting mid-stream (agent started late): seq != 0 alone is not
     * reported as a gap — there is no baseline to compare against. */
    c = lk_conn_table_data(t, 3, 40, 300, &lost);
    CHECK(c && lost == 0);
    CHECK(lk_conn_table_data(t, 3, 41, 310, &lost) == c && lost == 0);

    /* Synthetic OPEN (startup not seen) starts dirty right away: framing can
     * only enter through the resync path (Р10). */
    c = lk_conn_table_open(t, 4, 0, 400, &tuple, true, &lost);
    CHECK(c && (c->flags & LK_CONN_SYNTHETIC) && is_dirty(c));

    /* Cookies that collide into one bucket chain stay independent: with the
     * default max_conns the table sizes itself to 4096 buckets, so 3x that
     * guarantees chains formed; re-walk them. */
    {
        const __u64 base = 1000, n = 3 * 4096;

        for (__u64 ck = base; ck < base + n; ck++) {
            CHECK(lk_conn_table_data(t, ck, 0, 500, &lost) && lost == 0);
            CHECK(lk_conn_table_data(t, ck, 1, 510, &lost) && lost == 0);
        }
        for (__u64 ck = base; ck < base + n; ck++)
            CHECK(lk_conn_table_data(t, ck, 4, 520, &lost) && lost == 2);
    }

    lk_conn_table_free(t);
    return 0;
}

/* LRU ceiling: creation past max_conns evicts the least recently active
 * entry, and its traffic re-creates it as dirty (Р12). */
static int test_lru_eviction(void)
{
    struct lk_conn_table *t = lk_conn_table_new(4, 600ULL * 1000000000);
    const struct lk_conn_table_stats *st = lk_conn_table_stats(t);
    struct lk_conn *c;
    __u32 lost;

    CHECK(t);

    for (__u64 ck = 1; ck <= 4; ck++)
        CHECK(lk_conn_table_open(t, ck, 0, 100 + ck, &tuple, false, &lost));
    CHECK(st->active == 4 && st->created == 4 && st->evicted_lru == 0);

    /* Touch cookie 1 so cookie 2 becomes the coldest, then push past the
     * ceiling: 2 must be the one evicted. */
    CHECK(lk_conn_table_data(t, 1, 1, 200, &lost));
    CHECK(lk_conn_table_open(t, 5, 0, 210, &tuple, false, &lost));
    CHECK(st->active == 4 && st->evicted_lru == 1);

    /* Cookie 1 survived: still clean, tuple intact, seq stream continuous. */
    c = lk_conn_table_data(t, 1, 2, 220, &lost);
    CHECK(c && lost == 0 && !is_dirty(c) && c->tuple.dport == 5432);

    /* Cookie 2 was evicted while alive: its resumed traffic re-creates the
     * entry dirty (the kernel will not resend a synthetic OPEN), with no
     * tuple, no synthetic flag, and no gap reported (no seq baseline). */
    c = lk_conn_table_data(t, 2, 7, 230, &lost);
    CHECK(c && lost == 0);
    CHECK(is_dirty(c) && !(c->flags & LK_CONN_SYNTHETIC) && c->tuple.dport == 0);
    /* ...at the cost of evicting the next coldest (cookie 3). */
    CHECK(st->active == 4 && st->evicted_lru == 2 && st->created == 6);

    lk_conn_table_free(t);
    return 0;
}

/* Idle sweep: entries whose last activity is older than the timeout go away;
 * fresher ones stay. Time is caller-supplied, so the test owns the clock. */
static int test_idle_sweep(void)
{
    const __u64 timeout = 600ULL * 1000000000;
    struct lk_conn_table *t = lk_conn_table_new(LK_MAX_CONNS_DEFAULT, timeout);
    const struct lk_conn_table_stats *st = lk_conn_table_stats(t);
    struct lk_conn *c;
    __u32 lost;

    CHECK(t);

    CHECK(lk_conn_table_open(t, 1, 0, 1000, &tuple, false, &lost));
    CHECK(lk_conn_table_open(t, 2, 0, 2000, &tuple, false, &lost));

    /* Nothing is due yet: cookie 1 expires only at 1000 + timeout. */
    CHECK(lk_conn_table_sweep(t, 1000 + timeout - 1) == 0);
    CHECK(st->active == 2);

    /* Cookie 1 is due, cookie 2 (fresher) is not. */
    CHECK(lk_conn_table_sweep(t, 1000 + timeout) == 1);
    CHECK(st->active == 1 && st->evicted_idle == 1);

    /* Activity resets the clock: touch cookie 2, then sweep at its original
     * deadline — it must survive. */
    CHECK(lk_conn_table_data(t, 2, 1, 5000, &lost));
    CHECK(lk_conn_table_sweep(t, 2000 + timeout) == 0);
    CHECK(lk_conn_table_sweep(t, 5000 + timeout) == 1);
    CHECK(st->active == 0 && st->evicted_idle == 2);

    /* A swept-while-alive connection resumes as dirty, same as LRU. */
    c = lk_conn_table_data(t, 2, 9, 6000, &lost);
    CHECK(c && lost == 0 && is_dirty(c));

    lk_conn_table_free(t);
    return 0;
}

/* The stats the 10 s line reports: created/closed/active add up, gap
 * counters accumulate. */
static int test_stats(void)
{
    struct lk_conn_table *t = lk_conn_table_new(LK_MAX_CONNS_DEFAULT, 600ULL * 1000000000);
    const struct lk_conn_table_stats *st = lk_conn_table_stats(t);
    __u32 lost;

    CHECK(t);

    for (__u64 ck = 1; ck <= 10; ck++)
        CHECK(lk_conn_table_open(t, ck, 0, ck, &tuple, false, &lost));
    for (__u64 ck = 1; ck <= 7; ck++)
        lk_conn_table_close(t, ck, 1, 100 + ck, &lost);
    CHECK(st->created == 10 && st->closed == 7 && st->active == 3);

    CHECK(lk_conn_table_data(t, 8, 4, 200, &lost) && lost == 3);
    CHECK(lk_conn_table_data(t, 9, 2, 210, &lost) && lost == 1);
    CHECK(st->seq_gaps == 2 && st->lost_events == 4);

    lk_conn_table_free(t);
    return 0;
}

/* The destroy hook must fire on every path an entry can leave the table so the
 * protocol handler frees lk_conn.proto_state (Р15): CONN_CLOSE, LRU eviction,
 * idle sweep, and table teardown. Each entry here carries a heap proto_state
 * that the hook frees — under ASAN a missed path leaks (or a double hit
 * double-frees), so this exercises correctness beyond the call count. */
static void on_destroy_free(void *ctx, struct lk_conn *c)
{
    (*(int *)ctx)++;
    free(c->proto_state); /* free(NULL) is fine for hookless-state entries */
    c->proto_state = NULL;
}

static int test_proto_state_hook(void)
{
    const __u64 timeout = 600ULL * 1000000000;
    struct lk_conn_table *t = lk_conn_table_new(2, timeout); /* small: force LRU */
    int calls = 0;
    struct lk_conn *c;
    __u32 lost;

    CHECK(t);
    lk_conn_table_on_destroy(t, on_destroy_free, &calls);

    /* CONN_CLOSE frees proto_state. */
    c = lk_conn_table_open(t, 1, 0, 100, &tuple, false, &lost);
    CHECK(c);
    CHECK((c->proto_state = calloc(1, 32)));
    lk_conn_table_close(t, 1, 1, 110, &lost);
    CHECK(calls == 1);

    /* LRU eviction (past max_conns=2) frees the coldest entry's proto_state. */
    c = lk_conn_table_open(t, 10, 0, 200, &tuple, false, &lost);
    CHECK((c->proto_state = calloc(1, 32)));
    c = lk_conn_table_open(t, 11, 0, 210, &tuple, false, &lost);
    CHECK((c->proto_state = calloc(1, 32)));
    c = lk_conn_table_open(t, 12, 0, 220, &tuple, false, &lost); /* evicts cookie 10 */
    CHECK((c->proto_state = calloc(1, 32)));
    CHECK(calls == 2);

    /* Idle sweep frees proto_state of everything past the deadline (11 and 12). */
    CHECK(lk_conn_table_sweep(t, 220 + timeout) == 2);
    CHECK(calls == 4);

    /* Table teardown frees proto_state of every survivor. */
    c = lk_conn_table_open(t, 20, 0, 300, &tuple, false, &lost);
    CHECK((c->proto_state = calloc(1, 32)));
    lk_conn_table_free(t);
    CHECK(calls == 5);
    return 0;
}

int main(void)
{
    if (test_seq_holes() || test_lru_eviction() || test_idle_sweep() || test_stats() ||
        test_proto_state_hook())
        return 1;
    printf("ok\n");
    return 0;
}
