/* SPDX-License-Identifier: GPL-2.0 */
/* Ringbuf consumer: decode records, feed the connection table (task 2.2 —
 * seq-hole detection, idle sweep, LRU ceiling), print events and the
 * periodic stats line (moved out of main.c, task 2.1). Talks to the BPF side
 * through bpf_map handles only, so it does not depend on the skeleton;
 * stage 2.3+ routes data events into the framer here. */
#ifndef LATKIT_EVENTS_H
#define LATKIT_EVENTS_H

#include <linux/types.h>
#include <stdbool.h>

struct bpf_map;
struct lk_loop;

struct lk_events_cfg {
    struct bpf_map *ringbuf; /* `events` map */
    struct bpf_map *stats;   /* `stats` per-CPU counters */
    struct bpf_map *conns;   /* kernel conn registry, for --cap-headers */
    __u32 max_conns;         /* userspace conn table ceiling (LRU past it) */
    __u32 conn_idle_timeout_sec; /* idle sweep threshold */
    bool hexdump;
    bool cap_headers;
};

struct lk_events;

struct lk_events *lk_events_new(const struct lk_events_cfg *cfg);
void lk_events_free(struct lk_events *e);

/* Register the ringbuf fd (consume on readiness) and the 10 s stats task. */
int lk_events_register(struct lk_events *e, struct lk_loop *loop);

/* One stats line to stderr; the loop calls this periodically, main calls it
 * once more for the final totals on shutdown. */
void lk_events_print_stats(struct lk_events *e);

#endif /* LATKIT_EVENTS_H */
