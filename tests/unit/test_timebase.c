// SPDX-License-Identifier: GPL-2.0
/* Timebase tests (task 5.2): the offset arithmetic is exact, and a live sample
 * places a monotonic "now" within a second of the realtime "now". */
#include "timebase.h"

#include <stdio.h>
#include <time.h>

static int failures;
#define EXPECT(cond, msg)                                                                          \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: %s\n", msg);                                                             \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

int main(void)
{
    struct lk_timebase tb = {.offset_ns = 1000};

    EXPECT(lk_wall_ns(&tb, 5) == 1005, "offset applied: 5 + 1000 = 1005");
    tb.offset_ns = -10;
    EXPECT(lk_wall_ns(&tb, 3) == 0, "underflow clamps to 0");

    /* Live sample: wall(mono_now) must land near realtime_now. */
    {
        struct timespec mono, real;

        lk_timebase_sample(&tb);
        clock_gettime(CLOCK_MONOTONIC, &mono);
        clock_gettime(CLOCK_REALTIME, &real);
        uint64_t mono_ns = (uint64_t)mono.tv_sec * 1000000000ULL + mono.tv_nsec;
        uint64_t real_ns = (uint64_t)real.tv_sec * 1000000000ULL + real.tv_nsec;
        uint64_t wall = lk_wall_ns(&tb, mono_ns);
        uint64_t diff = wall > real_ns ? wall - real_ns : real_ns - wall;

        EXPECT(diff < 1000000000ULL, "sampled wall within 1s of realtime");
    }

    printf(failures ? "\n%d FAILURES\n" : "\nall timebase tests passed\n", failures);
    return failures ? 1 : 0;
}
