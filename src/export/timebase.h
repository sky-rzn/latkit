/* SPDX-License-Identifier: GPL-2.0 */
/* Monotonic -> wall-clock conversion (Р33, STAGE5.md task 5.2). Every timestamp
 * in the pipeline is bpf_ktime_get_ns (CLOCK_MONOTONIC, Р13); the export side
 * needs Unix epoch nanoseconds (OTLP *_unix_nano — the Prometheus text format
 * carries no timestamps and must not). This is the single seam that converts:
 *
 *   offset = clock_gettime(REALTIME) - clock_gettime(MONOTONIC)
 *   wall(mono) = mono + offset
 *
 * The offset is re-sampled on every export tick rather than cached forever: an
 * NTP step moves REALTIME but not MONOTONIC, and the offset must follow so the
 * absolute timestamps stay honest (durations, being monotonic differences, are
 * unaffected by a step within an interval — see docs/notes-export.md). Pure: a
 * couple of clock_gettime reads, no libbpf, no heap. */
#ifndef LATKIT_TIMEBASE_H
#define LATKIT_TIMEBASE_H

#include <stdint.h>

struct lk_timebase {
    int64_t offset_ns; /* REALTIME - MONOTONIC, in nanoseconds */
};

/* Sample the current REALTIME-MONOTONIC offset into tb. Call once per export. */
void lk_timebase_sample(struct lk_timebase *tb);

/* Convert a CLOCK_MONOTONIC nanosecond stamp to Unix-epoch nanoseconds using
 * the sampled offset. Clamped to 0 on the (impossible in practice) underflow. */
uint64_t lk_wall_ns(const struct lk_timebase *tb, uint64_t mono_ns);

#endif /* LATKIT_TIMEBASE_H */
