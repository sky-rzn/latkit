// SPDX-License-Identifier: GPL-2.0
/* cgroup filter core (task 7.1, Р48): glob matching, cgroup-id resolution and
 * re-resolve diffing, free of libbpf so it links into the unit tests. See
 * cgroup_match.h for the contract. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "cgroup_match.h"

/* Match one path segment against one pattern segment: `*` spans any run of
 * characters (within the segment — the caller never passes a '/'), `?` matches
 * exactly one. Classic backtracking glob, bounded by the segment lengths. */
static bool seg_match(const char *pat, size_t patlen, const char *seg, size_t seglen)
{
    size_t p = 0, s = 0, star_p = (size_t)-1, star_s = 0;

    while (s < seglen) {
        if (p < patlen && (pat[p] == '?' || pat[p] == seg[s])) {
            p++;
            s++;
        } else if (p < patlen && pat[p] == '*') {
            star_p = p++;    /* remember the star and the input position ... */
            star_s = s;      /* ... to backtrack to on a later mismatch */
        } else if (star_p != (size_t)-1) {
            p = star_p + 1;  /* the star swallows one more input char */
            s = ++star_s;
        } else {
            return false;
        }
    }
    while (p < patlen && pat[p] == '*') /* trailing stars match the empty tail */
        p++;
    return p == patlen;
}

/* Recursive segment-wise match. pat/path point at the current segment; each is
 * NUL-terminated, segments joined by '/'. A "**" segment matches zero or more
 * whole path segments (so it recurses, trying every split). */
static bool glob_rec(const char *pat, const char *path)
{
    const char *pseg_end = strchrnul(pat, '/');
    size_t plen = (size_t)(pseg_end - pat);

    if (plen == 2 && pat[0] == '*' && pat[1] == '*') {
        const char *pnext = *pseg_end ? pseg_end + 1 : pseg_end;

        /* "**" as the last segment matches the whole remaining path. */
        if (!*pnext)
            return true;
        /* Otherwise "**" consumes zero or more whole segments: try to match the
         * rest of the pattern at the current position and at every subsequent
         * segment start. */
        for (const char *p = path;; ) {
            const char *slash;

            if (glob_rec(pnext, p))
                return true;
            slash = strchr(p, '/');
            if (!slash) /* no deeper segment start: exhausted */
                return false;
            p = slash + 1;
        }
    }

    if (!*path)
        return false; /* pattern has a segment left but the path is exhausted */

    const char *sseg_end = strchrnul(path, '/');
    size_t slen = (size_t)(sseg_end - path);

    if (!seg_match(pat, plen, path, slen))
        return false;

    /* Both advance a segment; end when both are consumed together. */
    const char *pnext = *pseg_end ? pseg_end + 1 : pseg_end;
    const char *snext = *sseg_end ? sseg_end + 1 : sseg_end;

    if (!*pnext && !*snext)
        return true;
    if (!*pnext || !*snext)
        return false; /* one ran out of segments before the other */
    return glob_rec(pnext, snext);
}

bool cg_glob_match(const char *pattern, const char *path)
{
    /* Tolerate (and ignore) a leading '/' on either side so callers can pass
     * absolute-looking patterns; the resolver feeds root-relative paths. */
    while (*pattern == '/')
        pattern++;
    while (*path == '/')
        path++;
    if (!*pattern)
        return !*path;
    return glob_rec(pattern, path);
}

bool cg_idset_add(struct cg_idset *s, __u64 id)
{
    for (int i = 0; i < s->n; i++)
        if (s->ids[i] == id)
            return true;
    if (s->n >= LK_MAX_CGROUPS)
        return false;
    s->ids[s->n++] = id;
    return true;
}

static bool idset_has(const struct cg_idset *s, __u64 id)
{
    for (int i = 0; i < s->n; i++)
        if (s->ids[i] == id)
            return true;
    return false;
}

void cg_idset_diff(const struct cg_idset *cur, const struct cg_idset *next, __u64 *add, int *nadd,
                   __u64 *del, int *ndel)
{
    *nadd = 0;
    *ndel = 0;
    for (int i = 0; i < next->n; i++)
        if (!idset_has(cur, next->ids[i]))
            add[(*nadd)++] = next->ids[i];
    for (int i = 0; i < cur->n; i++)
        if (!idset_has(next, cur->ids[i]))
            del[(*ndel)++] = cur->ids[i];
}

int cg_path_id(const char *path, __u64 *id)
{
    /* name_to_handle_at on cgroupfs returns an 8-byte handle equal to the
     * kernfs id — the same value bpf_get_current_cgroup_id() reports. Requesting
     * exactly 8 bytes keeps the handle to that id (no privilege needed; only
     * open_by_handle_at is privileged). The union (not a wrapping struct)
     * reserves room past the flexible f_handle[] without tripping clang's
     * -Wgnu-variable-sized-type-not-at-end. */
    union {
        struct file_handle fh;
        char storage[sizeof(struct file_handle) + 8];
    } h;
    int mount_id;

    h.fh.handle_bytes = sizeof(h.storage) - sizeof(struct file_handle);
    if (name_to_handle_at(AT_FDCWD, path, &h.fh, &mount_id, 0))
        return -1;
    if (h.fh.handle_bytes < sizeof(__u64))
        return -1;
    memcpy(id, h.fh.f_handle, sizeof(*id));
    return 0;
}

/* Depth-first walk of the cgroupfs subtree rooted at (dirfd, relpath). For each
 * directory, test its root-relative path against every pattern and record a
 * match; then recurse into children. rootlen is the byte length of the cgroup
 * root prefix in `abspath`, so abspath+rootlen (skipping the '/') is the
 * relative path handed to the matcher. */
static void walk(const char *abspath, size_t rootlen, const char *const *patterns, int npatterns,
                 struct cg_idset *out, int *npaths)
{
    const char *rel = abspath + rootlen;
    DIR *d;
    struct dirent *de;

    while (*rel == '/')
        rel++;

    /* The root itself (rel == "") is never a filter target. */
    if (*rel) {
        for (int i = 0; i < npatterns; i++) {
            if (!cg_glob_match(patterns[i], rel))
                continue;
            __u64 id;

            (*npaths)++;
            if (cg_path_id(abspath, &id) == 0)
                cg_idset_add(out, id);
            break; /* one path counts once regardless of how many patterns hit */
        }
    }

    d = opendir(abspath);
    if (!d)
        return;
    while ((de = readdir(d))) {
        char child[4096];

        if (de->d_name[0] == '.' &&
            (de->d_name[1] == '\0' || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;
        /* cgroupfs entries are either directories or control files; only dirs
         * are cgroups. DT_UNKNOWN falls back to a stat via the recursion's
         * opendir failing on non-dirs, so an explicit check keeps it cheap. */
        if (de->d_type != DT_DIR && de->d_type != DT_UNKNOWN)
            continue;
        if ((size_t)snprintf(child, sizeof(child), "%s/%s", abspath, de->d_name) >= sizeof(child))
            continue;
        if (de->d_type == DT_UNKNOWN) {
            struct stat st;

            if (stat(child, &st) || !S_ISDIR(st.st_mode))
                continue;
        }
        walk(child, rootlen, patterns, npatterns, out, npaths);
    }
    closedir(d);
}

int cg_resolve(const char *root, const char *const *patterns, int npatterns, struct cg_idset *out,
               int *npaths)
{
    DIR *probe;

    out->n = 0;
    *npaths = 0;
    if (npatterns <= 0)
        return 0;

    probe = opendir(root);
    if (!probe)
        return -1;
    closedir(probe);

    walk(root, strlen(root), patterns, npatterns, out, npaths);
    return 0;
}
