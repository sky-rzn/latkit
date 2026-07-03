// SPDX-License-Identifier: GPL-2.0
#include "seqtrack.h"

#include <stdlib.h>

static struct lk_seqtrack_ent **seq_bucket(struct lk_seqtrack *t, __u64 cookie)
{
    /* Fibonacci hash: cookies are sequential, spread them. */
    return &t->bucket[(cookie * 0x9E3779B97F4A7C15ULL) >> 32 & (LK_SEQTRACK_BUCKETS - 1)];
}

__u32 lk_seqtrack_check(struct lk_seqtrack *t, __u64 cookie, __u32 seq, bool closing)
{
    struct lk_seqtrack_ent **slot = seq_bucket(t, cookie), *e;
    __u32 lost = 0;

    for (e = *slot; e; e = e->next)
        if (e->cookie == cookie)
            break;

    if (!e) {
        if (closing)
            return 0;
        e = malloc(sizeof(*e));
        if (!e)
            return 0; /* degrade to no detection, not to exit */
        e->cookie = cookie;
        e->last_seq = seq;
        e->next = *slot;
        *slot = e;
        return 0;
    }

    if (seq > e->last_seq + 1)
        lost = seq - (e->last_seq + 1);
    if (seq > e->last_seq)
        e->last_seq = seq;

    if (closing) {
        for (; *slot != e; slot = &(*slot)->next)
            ;
        *slot = e->next;
        free(e);
    }
    return lost;
}

void lk_seqtrack_clear(struct lk_seqtrack *t)
{
    for (unsigned i = 0; i < LK_SEQTRACK_BUCKETS; i++) {
        while (t->bucket[i]) {
            struct lk_seqtrack_ent *e = t->bucket[i];

            t->bucket[i] = e->next;
            free(e);
        }
    }
}
