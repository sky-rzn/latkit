// SPDX-License-Identifier: GPL-2.0
/* cgroup filter lifecycle (task 7.1, Р48). See cgroup_filter.h. The pure glob /
 * id-resolution / diff logic is in cgroup_match.c; here we hold the BPF maps,
 * apply the resolve result as a diff (add new ids, drop stale ones), toggle the
 * cgroup_on flag that tells the BPF predicate the filter is active, and re-run
 * the resolve on a timer. */
#include <errno.h>
#include <linux/magic.h> /* CGROUP2_SUPER_MAGIC */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/vfs.h>

#include <bpf/libbpf.h>

#include "cgroup_filter.h"
#include "cgroup_match.h"
#include "loop.h"

#define CGROUP_ROOT "/sys/fs/cgroup"

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

struct lk_cgroup {
    struct bpf_map *cgroups;   /* id -> u8, the filter set */
    struct bpf_map *cgroup_on; /* 1-entry array: 1 while `cgroups` is non-empty */
    struct lk_cgroup_cfg cfg;
    bool enabled;            /* --cgroup given (npatterns > 0) */
    struct cg_idset current; /* ids currently in the map (userspace mirror) */
    int npaths;              /* matched cgroupfs paths at the last resolve */
    bool warned_empty;       /* rate-limit the "matched nothing" warning */
};

struct lk_cgroup *lk_cgroup_new(struct bpf_map *cgroups, struct bpf_map *cgroup_on,
                                const struct lk_cgroup_cfg *cfg)
{
    struct lk_cgroup *t = calloc(1, sizeof(*t));

    if (!t)
        return NULL;
    t->cgroups = cgroups;
    t->cgroup_on = cgroup_on;
    t->cfg = *cfg;
    t->enabled = cfg->npatterns > 0;
    return t;
}

/* Reflect current.n into the cgroup_on flag the BPF predicate reads: non-empty
 * set => filter active, empty => off (captures everything, like `ports`). */
static int set_active_flag(struct lk_cgroup *t)
{
    __u32 zero = 0, on = t->current.n > 0 ? 1 : 0;

    return bpf_map__update_elem(t->cgroup_on, &zero, sizeof(zero), &on, sizeof(on), BPF_ANY);
}

/* Apply `next` to the map as a diff against t->current, then adopt it. Returns 0
 * or a negative errno from a map op (a failed op is logged and skipped so the
 * rest of the diff still lands). */
static int apply_diff(struct lk_cgroup *t, const struct cg_idset *next)
{
    __u64 add[LK_MAX_CGROUPS], del[LK_MAX_CGROUPS];
    int nadd, ndel, rc = 0;

    cg_idset_diff(&t->current, next, add, &nadd, del, &ndel);

    for (int i = 0; i < ndel; i++) {
        if (bpf_map__delete_elem(t->cgroups, &del[i], sizeof(del[i]), 0)) {
            rc = -errno;
            fprintf(stderr, "warn: cgroup filter: drop id %llu failed: %s\n",
                    (unsigned long long)del[i], strerror(errno));
        } else {
            fprintf(stderr, "latkit: cgroup filter: removed cgroup id %llu\n",
                    (unsigned long long)del[i]);
        }
    }
    for (int i = 0; i < nadd; i++) {
        __u8 one = 1;

        if (bpf_map__update_elem(t->cgroups, &add[i], sizeof(add[i]), &one, sizeof(one), BPF_ANY)) {
            rc = -errno;
            fprintf(stderr, "warn: cgroup filter: add id %llu failed: %s\n",
                    (unsigned long long)add[i], strerror(errno));
        } else {
            fprintf(stderr, "latkit: cgroup filter: added cgroup id %llu\n",
                    (unsigned long long)add[i]);
        }
    }

    t->current = *next;
    if (set_active_flag(t))
        rc = rc ? rc : -errno;
    return rc;
}

/* Resolve the globs and push the result into the maps. Warns (once per empty
 * streak) when the filter is configured but matched nothing — that leaves the
 * map empty, i.e. the filter off, which the operator must notice (Р48). */
static void resolve_and_apply(struct lk_cgroup *t)
{
    struct cg_idset next = {0};
    int npaths = 0;

    if (cg_resolve(CGROUP_ROOT, t->cfg.patterns, t->cfg.npatterns, &next, &npaths)) {
        fprintf(stderr, "warn: cgroup filter: cannot read %s: %s\n", CGROUP_ROOT, strerror(errno));
        return;
    }
    t->npaths = npaths;
    apply_diff(t, &next);

    if (npaths == 0) {
        if (!t->warned_empty)
            fprintf(stderr,
                    "warn: cgroup filter: no cgroupfs path matched the --cgroup pattern(s); "
                    "the filter is OFF (capturing all cgroups). Check the glob.\n");
        t->warned_empty = true;
    } else {
        t->warned_empty = false;
    }
}

/* The mount at /sys/fs/cgroup must be a cgroup v2 unified hierarchy for
 * bpf_get_current_cgroup_id (and name_to_handle_at ids) to mean anything. */
static bool cgroup_v2(void)
{
    struct statfs sfs;

    if (statfs(CGROUP_ROOT, &sfs))
        return false;
    return sfs.f_type == CGROUP2_SUPER_MAGIC;
}

int lk_cgroup_apply(struct lk_cgroup *t)
{
    if (!t || !t->enabled)
        return 0;

    if (!cgroup_v2()) {
        fprintf(stderr,
                "latkit: --cgroup requires a cgroup v2 unified hierarchy at %s; "
                "this host is cgroup v1 (or %s is not a cgroup2 mount)\n",
                CGROUP_ROOT, CGROUP_ROOT);
        return -1;
    }
    resolve_and_apply(t);
    return 0;
}

static void cgroup_rescan(void *ctx)
{
    resolve_and_apply(ctx);
}

int lk_cgroup_register(struct lk_cgroup *t, struct lk_loop *loop)
{
    if (!t || !t->enabled || t->cfg.rescan_sec == 0)
        return 0;
    return lk_loop_every(loop, t->cfg.rescan_sec, cgroup_rescan, t);
}

int lk_cgroup_paths(const struct lk_cgroup *t)
{
    return t && t->enabled ? t->npaths : 0;
}

bool lk_cgroup_enabled(const struct lk_cgroup *t)
{
    return t && t->enabled;
}

void lk_cgroup_free(struct lk_cgroup *t)
{
    free(t);
}
