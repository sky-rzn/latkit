/* SPDX-License-Identifier: GPL-2.0 */
/* cgroup filter core (task 7.1, Р48): the libbpf-free half of the cgroup filter
 * — glob matching, cgroup-id resolution and re-resolve diffing — kept separate
 * from the BPF-map glue (cgroup_filter.c) so it links into the offline unit
 * tests without libbpf or privileges. Pure apart from the filesystem reads in
 * cg_resolve (opendir + name_to_handle_at over the cgroupfs tree). */
#ifndef LATKIT_CGROUP_MATCH_H
#define LATKIT_CGROUP_MATCH_H

#include <linux/types.h>
#include <stdbool.h>

#include "latkit.h" /* LK_MAX_CGROUPS */

/* The set of distinct cgroup ids a resolve produced (deduped). Bounded by the
 * `cgroups` map capacity; ids beyond that are dropped (and counted by the
 * caller through the returned path count vs. n). */
struct cg_idset {
    __u64 ids[LK_MAX_CGROUPS];
    int n;
};

/* Glob match of a cgroup path relative to the cgroup root, e.g.
 * "system.slice/docker-abc.scope" against "system.slice/docker-*".
 * Semantics (Р48): a normal segment's `*` matches any run of characters within
 * one path segment (never crossing '/'), `?` matches one such character, and a
 * segment that is exactly "**" matches zero or more whole segments. Both strings
 * are split on '/'; matching is segment-by-segment. */
bool cg_glob_match(const char *pattern, const char *path);

/* Add id to the set, deduplicating. Returns true if stored (or already present),
 * false only when the set is full and the id is new. */
bool cg_idset_add(struct cg_idset *s, __u64 id);

/* Diff two id sets for the map update: ids in `next` but not `cur` go to add[],
 * ids in `cur` but not `next` go to del[]. Callers size add[]/del[] at
 * LK_MAX_CGROUPS. Order within the outputs is unspecified. */
void cg_idset_diff(const struct cg_idset *cur, const struct cg_idset *next, __u64 *add, int *nadd,
                   __u64 *del, int *ndel);

/* Resolve every pattern against the cgroupfs mounted at `root` (normally
 * "/sys/fs/cgroup"): walk the tree, glob-match each directory's relative path,
 * and record the cgroup id of every match into *out (deduped). *npaths receives
 * the number of matched directories (which the gauge reports; it can exceed
 * out->n when several paths share an id or the set overflowed). Returns 0, or
 * -1 if `root` could not be opened. Matched paths beyond LK_MAX_CGROUPS ids are
 * still counted in *npaths but not stored. */
int cg_resolve(const char *root, const char *const *patterns, int npatterns, struct cg_idset *out,
               int *npaths);

/* cgroup id of a single cgroupfs directory, via name_to_handle_at (the stable
 * id that matches bpf_get_current_cgroup_id on a v2 hierarchy). Returns 0 on
 * success, -1 otherwise. Exposed for the unit tests. */
int cg_path_id(const char *path, __u64 *id);

#endif /* LATKIT_CGROUP_MATCH_H */
