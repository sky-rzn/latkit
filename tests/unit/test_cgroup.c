// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the cgroup filter core (task 7.1, Р48): the libbpf-free glob
 * matcher, the id-set diff that drives the map re-resolve, and the cgroupfs
 * resolver against a synthetic directory tree. The BPF-map glue (cgroup_filter.c)
 * is not exercised here — these are the pure functions STAGE7.md asks to cover:
 * glob matching, diff logic, and "filter set but nothing matched -> 0 paths". */
#define _GNU_SOURCE
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cgroup_match.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static int test_glob(void)
{
    /* Literal, exact depth. */
    CHECK(cg_glob_match("system.slice/docker-x.scope", "system.slice/docker-x.scope"));
    CHECK(!cg_glob_match("system.slice/docker-x.scope", "system.slice/docker-y.scope"));

    /* `*` within a segment, not crossing '/'. */
    CHECK(cg_glob_match("system.slice/docker-*", "system.slice/docker-abc.scope"));
    CHECK(cg_glob_match("system.slice/docker-*.scope", "system.slice/docker-abc.scope"));
    CHECK(!cg_glob_match("system.slice/docker-*", "system.slice/other.scope"));
    CHECK(!cg_glob_match("a/*", "a/b/c")); /* * must not swallow the '/' */
    CHECK(cg_glob_match("a/*", "a/b"));
    CHECK(cg_glob_match("*/*", "a/b"));

    /* Segment-count must match exactly for a *-only pattern. */
    CHECK(!cg_glob_match("a/b", "a"));     /* pattern longer */
    CHECK(!cg_glob_match("a/b", "a/b/c")); /* path longer */
    CHECK(!cg_glob_match("a", "a/b"));

    /* `?` matches exactly one char within a segment. */
    CHECK(cg_glob_match("pod?", "podX"));
    CHECK(!cg_glob_match("pod?", "podXY"));
    CHECK(!cg_glob_match("pod?", "pod"));

    /* `**` spans zero or more whole segments. */
    CHECK(cg_glob_match("kubepods.slice/**/podabc", "kubepods.slice/a/b/podabc"));
    CHECK(cg_glob_match("kubepods.slice/**/podabc", "kubepods.slice/podabc")); /* zero segments */
    CHECK(cg_glob_match("kubepods.slice/**", "kubepods.slice/a/b/c"));         /* trailing ** */
    CHECK(cg_glob_match("kubepods.slice/**", "kubepods.slice/a"));
    CHECK(!cg_glob_match("kubepods.slice/**/podabc", "kubepods.slice/a/b/podxyz"));
    CHECK(cg_glob_match("**/podabc", "a/b/podabc")); /* leading ** */

    /* The k8s shape from Р48: burstable pod path with a uid glob. */
    CHECK(cg_glob_match("kubepods.slice/kubepods-burstable.slice/kubepods-*-pod*",
                        "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podDEAD_BEEF"));

    /* A leading '/' on either side is tolerated. */
    CHECK(cg_glob_match("/system.slice/docker-*", "system.slice/docker-1"));
    return 0;
}

static int test_idset(void)
{
    struct cg_idset s = {0};

    CHECK(cg_idset_add(&s, 10));
    CHECK(cg_idset_add(&s, 20));
    CHECK(cg_idset_add(&s, 10)); /* dedup: still true, no growth */
    CHECK(s.n == 2);

    /* Fill to capacity, then reject a new id. */
    struct cg_idset full = {0};

    for (int i = 0; i < LK_MAX_CGROUPS; i++)
        CHECK(cg_idset_add(&full, 1000 + i));
    CHECK(full.n == LK_MAX_CGROUPS);
    CHECK(!cg_idset_add(&full, 999));      /* new id, no room */
    CHECK(cg_idset_add(&full, 1000));      /* already present -> ok */
    return 0;
}

static int test_diff(void)
{
    struct cg_idset cur = {0}, next = {0};
    __u64 add[LK_MAX_CGROUPS], del[LK_MAX_CGROUPS];
    int nadd, ndel;

    cg_idset_add(&cur, 1);
    cg_idset_add(&cur, 2);
    cg_idset_add(&cur, 3);
    cg_idset_add(&next, 2); /* 1,3 removed; 4 added; 2 kept */
    cg_idset_add(&next, 4);

    cg_idset_diff(&cur, &next, add, &nadd, del, &ndel);
    CHECK(nadd == 1 && add[0] == 4);
    CHECK(ndel == 2); /* 1 and 3, order unspecified */
    CHECK((del[0] == 1 && del[1] == 3) || (del[0] == 3 && del[1] == 1));

    /* No change -> empty diff. */
    cg_idset_diff(&next, &next, add, &nadd, del, &ndel);
    CHECK(nadd == 0 && ndel == 0);

    /* Empty -> populated: all adds, no dels (the initial resolve). */
    struct cg_idset empty = {0};

    cg_idset_diff(&empty, &next, add, &nadd, del, &ndel);
    CHECK(nadd == 2 && ndel == 0);

    /* Populated -> empty: all dels (a pod that vanished). */
    cg_idset_diff(&next, &empty, add, &nadd, del, &ndel);
    CHECK(nadd == 0 && ndel == 2);
    return 0;
}

/* Build a throwaway cgroupfs-shaped tree under `root` and resolve globs over it. */
static int mkchild(const char *root, const char *rel)
{
    char p[512];

    snprintf(p, sizeof(p), "%s/%s", root, rel);
    return mkdir(p, 0755);
}

static int test_resolve(void)
{
    char root[] = "/tmp/lk_cgtestXXXXXX"; /* mkdtemp lives on the real fs, not the arg */

    if (!mkdtemp(root)) {
        fprintf(stderr, "FAIL: mkdtemp: %m\n");
        return 1;
    }

    /* system.slice/{docker-1,docker-2,sshd.service}, plus a nested pod tree. */
    CHECK(mkchild(root, "system.slice") == 0);
    CHECK(mkchild(root, "system.slice/docker-1.scope") == 0);
    CHECK(mkchild(root, "system.slice/docker-2.scope") == 0);
    CHECK(mkchild(root, "system.slice/sshd.service") == 0);
    CHECK(mkchild(root, "kubepods.slice") == 0);
    CHECK(mkchild(root, "kubepods.slice/pod-a") == 0);
    CHECK(mkchild(root, "kubepods.slice/pod-a/container") == 0);

    const char *docker[] = {"system.slice/docker-*.scope"};
    struct cg_idset ids = {0};
    int npaths = 0;

    CHECK(cg_resolve(root, docker, 1, &ids, &npaths) == 0);
    CHECK(npaths == 2); /* both docker scopes, not sshd */

    /* A pattern that matches nothing -> 0 paths, empty set (the misconfig case
     * that drives latkit_cgroup_filter_paths to 0 with a warn, Р48). */
    const char *nomatch[] = {"system.slice/nope-*"};
    struct cg_idset none = {0};
    int n0 = 0;

    CHECK(cg_resolve(root, nomatch, 1, &none, &n0) == 0);
    CHECK(n0 == 0 && none.n == 0);

    /* `**` reaches the nested container dir. */
    const char *deep[] = {"kubepods.slice/**/container"};
    struct cg_idset dset = {0};
    int nd = 0;

    CHECK(cg_resolve(root, deep, 1, &dset, &nd) == 0);
    CHECK(nd == 1);

    /* Re-resolve diff: name_to_handle_at ids are only available on some
     * filesystems (tmpfs on old kernels lacks exportfs). Only assert the id-level
     * behaviour when the resolver actually produced ids; the path counts above
     * are the filesystem-independent contract. */
    if (ids.n == 2) {
        __u64 id_before;
        char p[512];

        snprintf(p, sizeof(p), "%s/system.slice/docker-1.scope", root);
        CHECK(cg_path_id(p, &id_before) == 0);

        /* Recreate docker-1 -> new inode -> new id; the diff should surface one
         * add and one del (a pod recreated under the same glob). */
        rmdir(p);
        CHECK(mkdir(p, 0755) == 0);

        struct cg_idset ids2 = {0};
        int np2 = 0;

        CHECK(cg_resolve(root, docker, 1, &ids2, &np2) == 0);
        CHECK(np2 == 2 && ids2.n == 2);

        __u64 add[LK_MAX_CGROUPS], del[LK_MAX_CGROUPS];
        int nadd, ndel;

        cg_idset_diff(&ids, &ids2, add, &nadd, del, &ndel);
        CHECK(nadd == 1 && ndel == 1); /* the recreated scope swapped id */
    } else {
        fprintf(stderr, "note: name_to_handle_at unavailable on this fs; "
                        "id-diff assertions skipped (path counts still checked)\n");
    }

    /* Best-effort cleanup (leaf-first); a leftover temp dir is harmless. */
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", root);
    if (system(cmd)) { /* ignore */
    }
    return 0;
}

int main(void)
{
    if (test_glob() || test_idset() || test_diff() || test_resolve())
        return 1;
    printf("test_cgroup: all cases passed\n");
    return 0;
}
