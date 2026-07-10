/* SPDX-License-Identifier: GPL-2.0 */
/* cgroup filter lifecycle (task 7.1, Р48): the BPF-map facing half of the
 * cgroup filter. Owns the `cgroups` / `cgroup_on` maps, resolves --cgroup glob
 * patterns to cgroup ids (cgroup_match.c) and keeps the maps in sync on a timer
 * so a pod recreated under the same glob is re-picked up without an agent
 * restart. The pure matching/diffing core lives in cgroup_match.h; this module
 * is the only part that touches libbpf.
 *
 * Semantics mirror the port filter: no --cgroup means an empty map means the
 * filter is off (every cgroup passes). --cgroup requires a cgroup v2 unified
 * hierarchy; on a v1 host lk_cgroup_apply fails hard rather than silently
 * capturing nothing (cgroup ids are meaningless on v1). */
#ifndef LATKIT_CGROUP_FILTER_H
#define LATKIT_CGROUP_FILTER_H

#include <stdbool.h>

struct bpf_map; /* libbpf */
struct lk_loop; /* loop.h — for the re-resolve timer */
struct lk_cgroup;

struct lk_cgroup_cfg {
    const char *const *patterns; /* --cgroup globs (borrowed), relative to /sys/fs/cgroup */
    int npatterns;               /* 0 disables the filter entirely */
    unsigned rescan_sec;         /* re-resolve period (0 => no timer) */
};

/* Create the handle over the two filter maps. Borrows cfg (its pattern pointers
 * must outlive the handle — main's opt_* arrays do). npatterns == 0 yields a
 * disabled handle: every entry point below is then a no-op. Returns NULL on OOM. */
struct lk_cgroup *lk_cgroup_new(struct bpf_map *cgroups, struct bpf_map *cgroup_on,
                                const struct lk_cgroup_cfg *cfg);

/* First resolve + map fill, after latkit_bpf__load and before attach (so the
 * filter is live before the first event, like fill_ports). Verifies the cgroup
 * v2 hierarchy first; on a v1 host with --cgroup this returns -1 with a message
 * (fatal start). A glob that matches nothing is not fatal — it leaves the map
 * empty (filter off) and warns, so the operator sees the misconfig via the
 * latkit_cgroup_filter_paths gauge (Р48). Returns 0, or -1 on a fatal error. */
int lk_cgroup_apply(struct lk_cgroup *t);

/* Arm the re-resolve timer on the loop (no-op when disabled or rescan_sec 0). */
int lk_cgroup_register(struct lk_cgroup *t, struct lk_loop *loop);

/* Number of cgroupfs paths the last resolve matched — the value behind the
 * latkit_cgroup_filter_paths gauge. 0 while disabled. */
int lk_cgroup_paths(const struct lk_cgroup *t);

/* Whether --cgroup was given at all (the filter is configured, even if it
 * currently matches nothing). Drives whether the gauge is exported. */
bool lk_cgroup_enabled(const struct lk_cgroup *t);

void lk_cgroup_free(struct lk_cgroup *t); /* NULL-safe */

#endif /* LATKIT_CGROUP_FILTER_H */
