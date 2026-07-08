// SPDX-License-Identifier: GPL-2.0
/* See selfstats.h. The standard Prometheus process_* collectors, sourced
 * straight from the OS at each dump:
 *
 *   - process_cpu_seconds_total   = getrusage(RUSAGE_SELF) user + system time;
 *   - process_resident_memory_bytes = /proc/self/statm resident pages * pagesize;
 *   - process_start_time_seconds  = wall-clock epoch captured at lk_selfstats_new
 *     (the agent creates it during startup, so this is process start to the
 *     second — the accuracy Prometheus expects of this series).
 *
 * Failures degrade gracefully: a series is simply not written that dump. */
#include "selfstats.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>
#include <sys/time.h>

struct lk_selfstats {
    double start_time; /* Unix epoch seconds at construction */
};

struct lk_selfstats *lk_selfstats_new(void)
{
    struct lk_selfstats *ss = calloc(1, sizeof(*ss));
    struct timespec ts;

    if (!ss)
        return NULL;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
        ss->start_time = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
    else
        ss->start_time = (double)time(NULL);
    return ss;
}

void lk_selfstats_free(struct lk_selfstats *ss)
{
    free(ss);
}

/* Resident set size in bytes from /proc/self/statm (field 2 = resident pages),
 * or 0 if the file cannot be read/parsed. */
static double resident_bytes(void)
{
    unsigned long total_pages, resident_pages;
    FILE *f = fopen("/proc/self/statm", "r");
    int n;

    if (!f)
        return 0;
    n = fscanf(f, "%lu %lu", &total_pages, &resident_pages);
    fclose(f);
    if (n != 2)
        return 0;
    return (double)resident_pages * (double)sysconf(_SC_PAGESIZE);
}

void lk_selfstats_provide(void *ctx, struct lk_metrics *m)
{
    struct lk_selfstats *ss = ctx;
    struct rusage ru;
    double rss;

    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        double cpu = (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec / 1e6 +
                     (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec / 1e6;

        lk_metrics_set_counter(m, "process_cpu_seconds_total",
                               "Total user and system CPU time spent in seconds.", cpu);
    }

    rss = resident_bytes();
    if (rss > 0)
        lk_metrics_set_gauge(m, "process_resident_memory_bytes", "Resident memory size in bytes.",
                             rss);

    lk_metrics_set_gauge(m, "process_start_time_seconds",
                         "Start time of the process since unix epoch in seconds.", ss->start_time);
}
