// SPDX-License-Identifier: GPL-2.0
/* Unit tests (task 1.7) for the seq-hole detector: consecutive seqs are
 * silent, forward jumps report the exact hole size, out-of-order stragglers
 * are not double-counted, CLOSE frees the entry, and colliding cookies keep
 * independent state. */
#include <linux/types.h>
#include <stdio.h>

#include "seqtrack.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static struct lk_seqtrack tab;

int main(void)
{
    /* A clean consecutive stream never reports. */
    CHECK(lk_seqtrack_check(&tab, 1, 0, false) == 0); /* first sighting */
    CHECK(lk_seqtrack_check(&tab, 1, 1, false) == 0);
    CHECK(lk_seqtrack_check(&tab, 1, 2, false) == 0);

    /* seq jumping 3 -> skipping 3,4 means exactly 2 lost events. */
    CHECK(lk_seqtrack_check(&tab, 1, 5, false) == 2);
    CHECK(lk_seqtrack_check(&tab, 1, 6, false) == 0); /* stream resumes */

    /* An out-of-order straggler (two CPUs racing reserve after fetch_add)
     * steps backward: not loss, and last_seq must not regress — the next
     * in-order event stays silent. */
    CHECK(lk_seqtrack_check(&tab, 1, 4, false) == 0);
    CHECK(lk_seqtrack_check(&tab, 1, 7, false) == 0);

    /* A duplicate of the current seq is not loss either. */
    CHECK(lk_seqtrack_check(&tab, 1, 7, false) == 0);

    /* Connections do not interfere: a second cookie starts its own stream. */
    CHECK(lk_seqtrack_check(&tab, 2, 0, false) == 0);
    CHECK(lk_seqtrack_check(&tab, 1, 8, false) == 0);
    CHECK(lk_seqtrack_check(&tab, 2, 3, false) == 2);

    /* The gap check still runs on the closing event itself... */
    CHECK(lk_seqtrack_check(&tab, 2, 6, true) == 2);
    /* ...and CLOSE frees the entry: the same cookie restarts from scratch
     * (cookies are never reused by the kernel, but a lost-and-recreated
     * entry must not inherit stale state). */
    CHECK(lk_seqtrack_check(&tab, 2, 100, false) == 0);
    CHECK(lk_seqtrack_check(&tab, 2, 101, true) == 0);

    /* CLOSE for a cookie that was never seen (its whole life was lost or
     * predates the agent) must not report or crash. */
    CHECK(lk_seqtrack_check(&tab, 999, 50, true) == 0);

    /* First sighting mid-stream (agent started late): seq != 0 alone is not
     * reported as a gap — there is no baseline to compare against. */
    CHECK(lk_seqtrack_check(&tab, 3, 40, false) == 0);
    CHECK(lk_seqtrack_check(&tab, 3, 41, false) == 0);

    /* Cookies that collide into one bucket chain stay independent: the
     * Fibonacci-hash bucket is (cookie * K) >> 32 & 4095, so cookies whose
     * product differs only below bit 32+... — easier: hammer one bucket by
     * brute force over a range and verify per-cookie streams. */
    {
        __u32 hits = 0;

        for (__u64 c = 100; c < 100 + 3 * LK_SEQTRACK_BUCKETS; c++) {
            CHECK(lk_seqtrack_check(&tab, c, 0, false) == 0);
            CHECK(lk_seqtrack_check(&tab, c, 1, false) == 0);
            hits++;
        }
        /* 3x bucket count guarantees chains formed; re-walk them. */
        for (__u64 c = 100; c < 100 + 3 * LK_SEQTRACK_BUCKETS; c++)
            CHECK(lk_seqtrack_check(&tab, c, 4, false) == 2);
        CHECK(hits == 3 * LK_SEQTRACK_BUCKETS);
    }

    lk_seqtrack_clear(&tab);
    /* After clear the table is reusable from scratch. */
    CHECK(lk_seqtrack_check(&tab, 1, 0, false) == 0);
    CHECK(lk_seqtrack_check(&tab, 1, 1, true) == 0);
    lk_seqtrack_clear(&tab);

    printf("ok\n");
    return 0;
}
