/* SPDX-License-Identifier: GPL-2.0 */
/* Per-connection seq-hole detector (task 1.5): cookie -> last seen seq, a
 * chained hash table. This is the stub of the stage-2 "dirty connection"
 * flag, not a full conn table: entries appear on the first event of a
 * connection and are freed on CONN_CLOSE. Connections whose CLOSE was lost
 * leave their entry behind — bounded cleanup is a stage-2 concern, stated in
 * STAGE1.md. */
#ifndef LATKIT_SEQTRACK_H
#define LATKIT_SEQTRACK_H

#include <linux/types.h>
#include <stdbool.h>

#define LK_SEQTRACK_BUCKETS 4096 /* power of two; matches the conns map scale /16 */

struct lk_seqtrack_ent {
    struct lk_seqtrack_ent *next;
    __u64 cookie;
    __u32 last_seq;
};

struct lk_seqtrack {
    struct lk_seqtrack_ent *bucket[LK_SEQTRACK_BUCKETS];
};

/* Feed one event through the detector; returns the number of events lost
 * before this one (seq jumped forward past last_seq + 1), 0 otherwise.
 * `closing` frees the connection's entry after the check.
 * A backward step is not loss: seq assignment (fetch_add in the kernel) and
 * ringbuf reserve are not one atomic step, so two CPUs can submit adjacent
 * seqs out of order. Such a pair first reports a spurious 1-event gap, then
 * the straggler arrives — rare enough to tolerate in stage 1. */
__u32 lk_seqtrack_check(struct lk_seqtrack *t, __u64 cookie, __u32 seq, bool closing);

/* Free every entry (test teardown; the agent just exits). */
void lk_seqtrack_clear(struct lk_seqtrack *t);

#endif /* LATKIT_SEQTRACK_H */
