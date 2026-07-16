/* SPDX-License-Identifier: GPL-2.0 */
/* Shared harness for the hot-path micro-benchmarks (tests/bench/micro).
 *
 * The whole point of these benches is the per-op heap churn the two hottest
 * paths carry (Р11 reassembly body-prefix buffer, Р32 span text): a malloc on
 * every op paired with a free one drain/message-boundary later. So the headline
 * number is not ns/op but *allocs/op*. It reads ~1.0 today; when the span text
 * moves to an init-time arena (and, if ever, the frame buffer too) it should
 * fall to ~0, and this harness makes that visible without a profiler.
 *
 * Allocation accounting is done with the linker's --wrap (see CMakeLists.txt):
 * every malloc/calloc/realloc/free issued by the linked module code is
 * redirected to the __wrap_* shims in bench_wrap.c, counted, and forwarded to
 * the real allocator. */
#ifndef LATKIT_BENCH_UTIL_H
#define LATKIT_BENCH_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct bench_alloc {
    unsigned long long calls; /* malloc + calloc + realloc */
    unsigned long long frees; /* free(non-NULL) */
    unsigned long long bytes; /* requested bytes */
};

extern struct bench_alloc g_alloc; /* defined in bench_wrap.c */

/* Reset the counters after setup, right before the timed loop, so only the
 * steady-state churn is measured (the one-time table/ring allocations are not
 * the subject). */
static inline void bench_alloc_reset(void)
{
    g_alloc.calls = 0;
    g_alloc.frees = 0;
    g_alloc.bytes = 0;
}

static inline uint64_t bench_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Iteration count: argv[1] if given, else a default that runs in a fraction of
 * a second (CTest smoke). Standalone, pass a bigger N for a stable figure. */
static inline uint64_t bench_iters(int argc, char **argv, uint64_t dflt)
{
    if (argc > 1) {
        unsigned long long v = strtoull(argv[1], NULL, 10);

        if (v)
            return v;
    }
    return dflt;
}

static inline void bench_report(const char *name, uint64_t ns, uint64_t ops)
{
    double per = ops ? (double)ns / (double)ops : 0.0;

    printf("%-14s %10llu ops  %8.2f ns/op  %8.2f Mop/s   "
           "allocs/op %.3f  frees/op %.3f  bytes/op %6.1f\n",
           name, (unsigned long long)ops, per, per > 0 ? 1000.0 / per : 0.0,
           ops ? (double)g_alloc.calls / (double)ops : 0.0,
           ops ? (double)g_alloc.frees / (double)ops : 0.0,
           ops ? (double)g_alloc.bytes / (double)ops : 0.0);
}

#endif /* LATKIT_BENCH_UTIL_H */
