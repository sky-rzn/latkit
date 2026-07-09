// SPDX-License-Identifier: GPL-2.0
/* See timebase.h. */
#include "timebase.h"

#include <time.h>

void lk_timebase_sample(struct lk_timebase *tb)
{
    struct timespec real, mono;

    /* Read them back to back: the tiny gap between the two reads is bounded by a
     * couple of syscalls and shows up as a sub-microsecond error in the offset,
     * far below the export interval and any consumer's resolution. */
    if (clock_gettime(CLOCK_REALTIME, &real) || clock_gettime(CLOCK_MONOTONIC, &mono)) {
        tb->offset_ns = 0;
        return;
    }
    int64_t real_ns = (int64_t)real.tv_sec * 1000000000LL + real.tv_nsec;
    int64_t mono_ns = (int64_t)mono.tv_sec * 1000000000LL + mono.tv_nsec;

    tb->offset_ns = real_ns - mono_ns;
}

uint64_t lk_wall_ns(const struct lk_timebase *tb, uint64_t mono_ns)
{
    int64_t wall = (int64_t)mono_ns + tb->offset_ns;

    return wall > 0 ? (uint64_t)wall : 0;
}
