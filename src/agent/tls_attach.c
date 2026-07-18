// SPDX-License-Identifier: GPL-2.0
/* TLS uprobe attach lifecycle. Attaches the SSL_read/SSL_write(_ex) data probes
 * and the SSL_set_fd/rfd/wfd + SSL_free bridge probes to libssl with pid=-1 so
 * every process mapping that file (present and future postgres backends, every
 * mysqld session thread) is covered. The libssl is either an explicit --libssl
 * path or, under --tls auto, discovered by scanning /proc: the maps of every
 * comm-matching process (default: the DB-server set {postgres, mysqld,
 * mariadbd}, РМ10; --tls-comm narrows to one name) are searched for a libssl.so
 * mapping, each in-container path is resolved through /proc/<pid>/root, and
 * distinct files (by device+inode) are attached once. A periodic rescan picks
 * up libssl paths that appear later (a cluster restart or a second install).
 * Forked backends need no rescan thanks to pid=-1.
 *
 * The scan matches the /proc/<pid>/comm of the top-level pid dirs, i.e. the
 * *process* (main-thread) comm — deliberately not the per-thread comm the BPF
 * filter sees: MySQL 8.x renames session threads to `connection` while the
 * process stays `mysqld` (main.c widens the kernel filter accordingly). */
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <bpf/libbpf.h>

#include "latkit.skel.h"
#include "loop.h"
#include "tls_attach.h"

/* One uprobe target: a skeleton program, the libssl symbol it hooks, and
 * whether it is the return probe. `optional` symbols (the _ex calls, the rfd/wfd
 * setters) may be absent on an older/minimal OpenSSL and are skipped without
 * downgrading to error. */
struct lk_tls_probe {
    struct bpf_program *(*prog)(struct latkit_bpf *);
    const char *symbol;
    bool retprobe;
    bool optional;
};

/* Accessors: the skeleton exposes programs as direct struct fields, so a table
 * of member pointers needs these tiny getters. */
#define P(field)                                                                                   \
    static struct bpf_program *tls_prog_##field(struct latkit_bpf *s)                              \
    {                                                                                              \
        return s->progs.field;                                                                     \
    }
P(lk_ssl_write)
P(lk_ssl_write_ret)
P(lk_ssl_write_ex)
P(lk_ssl_write_ex_ret)
P(lk_ssl_read)
P(lk_ssl_read_ret)
P(lk_ssl_read_ex)
P(lk_ssl_read_ex_ret)
P(lk_ssl_set_fd)
P(lk_ssl_set_rfd)
P(lk_ssl_set_wfd)
P(lk_ssl_free)
#undef P

static const struct lk_tls_probe tls_probes[] = {
    {tls_prog_lk_ssl_write, "SSL_write", false, false},
    {tls_prog_lk_ssl_write_ret, "SSL_write", true, false},
    {tls_prog_lk_ssl_write_ex, "SSL_write_ex", false, true},
    {tls_prog_lk_ssl_write_ex_ret, "SSL_write_ex", true, true},
    {tls_prog_lk_ssl_read, "SSL_read", false, false},
    {tls_prog_lk_ssl_read_ret, "SSL_read", true, false},
    {tls_prog_lk_ssl_read_ex, "SSL_read_ex", false, true},
    {tls_prog_lk_ssl_read_ex_ret, "SSL_read_ex", true, true},
    /* Bridge probes: SSL_set_fd is the primary SSL*->cookie link, SSL_free the
     * cleanup - both present in every OpenSSL. The rfd/wfd variants are rarely
     * used (separate read/write fds) and tolerated absent. */
    {tls_prog_lk_ssl_set_fd, "SSL_set_fd", false, false},
    {tls_prog_lk_ssl_set_rfd, "SSL_set_rfd", false, true},
    {tls_prog_lk_ssl_set_wfd, "SSL_set_wfd", false, true},
    {tls_prog_lk_ssl_free, "SSL_free", false, false},
};
#define TLS_NPROBES (sizeof(tls_probes) / sizeof(tls_probes[0]))

/* Ceiling on distinct libssl files attached - several DB installs on one
 * host is unusual; more than this is almost certainly a scan gone wrong. */
#define TLS_MAX_PATHS 32

/* Default comms the AUTO scan looks for (РМ10): every server latkit speaks the
 * protocol of. NULL-terminated; --tls-comm replaces the whole list with one
 * name. Exposed for main.c, which derives the kernel-side thread-comm filter
 * from the same set. */
const char *const lk_tls_default_comms[] = {"postgres", "mysqld", "mariadbd", NULL};

/* An attached libssl, identified by its file so a rescan never double-attaches
 * the same binary (many backends map it; its /proc/<pid>/root path differs per
 * pid but the device+inode do not). */
struct lk_tls_file {
    dev_t dev;
    ino_t ino;
};

struct lk_tls {
    struct latkit_bpf *skel;
    struct lk_tls_cfg cfg;
    bool enabled;               /* AUTO, or an explicit --libssl: SSL_* programs loaded */
    const char *explicit_path;  /* --libssl PATH, or NULL for the /proc scan */
    const char *single_comm[2]; /* backing store when --tls-comm narrows the scan */
    const char *const *comms;   /* NULL-terminated comm list to scan for (never empty) */
    struct bpf_link **links;    /* grown as paths are attached */
    int nlinks, links_cap;
    struct lk_tls_file files[TLS_MAX_PATHS];
    int nfiles;
    bool any_partial; /* an attached file was missing a mandatory/optional symbol */
    enum lk_tls_state state;
};

/* Append one link to the growable array; on OOM the link is destroyed (its
 * uprobe would otherwise leak and outlive the handle). */
static int link_append(struct lk_tls *t, struct bpf_link *link)
{
    if (t->nlinks == t->links_cap) {
        int cap = t->links_cap ? t->links_cap * 2 : (int)TLS_NPROBES;
        struct bpf_link **p = realloc(t->links, (size_t)cap * sizeof(*p));

        if (!p) {
            bpf_link__destroy(link);
            return -1;
        }
        t->links = p;
        t->links_cap = cap;
    }
    t->links[t->nlinks++] = link;
    return 0;
}

static bool file_known(const struct lk_tls *t, dev_t dev, ino_t ino)
{
    for (int i = 0; i < t->nfiles; i++)
        if (t->files[i].dev == dev && t->files[i].ino == ino)
            return true;
    return false;
}

/* Attach the whole probe set to one libssl binary at `path`. Returns the number
 * of probes attached (0 if none - e.g. not actually a libssl); sets *full when
 * every probe attached. Absent optional symbols are skipped silently. A mandatory
 * symbol that fails to attach warns and drops the file to partial. */
static unsigned attach_path(struct lk_tls *t, const char *path, bool *full)
{
    unsigned attached = 0, mandatory = 0, mandatory_ok = 0;

    for (size_t i = 0; i < TLS_NPROBES; i++) {
        const struct lk_tls_probe *pr = &tls_probes[i];
        LIBBPF_OPTS(bpf_uprobe_opts, opts, .func_name = pr->symbol, .retprobe = pr->retprobe);
        struct bpf_link *link;

        if (!pr->optional)
            mandatory++;

        /* pid = -1: attach to every process mapping this libssl, including
         * backends forked after us - no rescan needed for fork coverage. */
        link = bpf_program__attach_uprobe_opts(pr->prog(t->skel), -1, path, 0, &opts);
        if (!link) {
            if (!pr->optional)
                fprintf(stderr, "warn: TLS uprobe %s%s on %s failed: %s\n", pr->symbol,
                        pr->retprobe ? " (ret)" : "", path, strerror(errno));
            continue;
        }
        if (link_append(t, link)) {
            fprintf(stderr, "warn: TLS uprobe bookkeeping OOM\n");
            break;
        }
        attached++;
        if (!pr->optional)
            mandatory_ok++;
    }

    *full = (mandatory_ok == mandatory && attached == TLS_NPROBES);
    return attached;
}

/* Record and attach one discovered/explicit libssl file. Deduped by device+inode
 * so a rescan (or several backends sharing the file) attaches it once. Returns 1
 * if newly attached, 0 if already known or not attachable, <0 on the file table
 * being full. */
static int attach_file(struct lk_tls *t, const char *host_path)
{
    struct stat st;
    unsigned n;
    bool full;

    if (stat(host_path, &st))
        return 0; /* vanished between scan and attach: ignore */
    if (file_known(t, st.st_dev, st.st_ino))
        return 0;
    if (t->nfiles == TLS_MAX_PATHS) {
        fprintf(stderr, "warn: TLS: too many libssl paths (>%d), ignoring %s\n", TLS_MAX_PATHS,
                host_path);
        return -1;
    }

    n = attach_path(t, host_path, &full);
    if (n == 0)
        return 0; /* nothing attached: not a usable libssl */

    t->files[t->nfiles].dev = st.st_dev;
    t->files[t->nfiles].ino = st.st_ino;
    t->nfiles++;
    if (!full)
        t->any_partial = true;
    fprintf(stderr, "latkit: TLS uprobes attached on %s (%u probes%s)\n", host_path, n,
            full ? "" : ", partial");
    return 1;
}

/* Read /proc/<pid>/comm into buf (newline stripped). Returns 0 on success. */
static int read_comm(const char *pid, char *buf, size_t sz)
{
    char path[NAME_MAX + 16]; /* pid is a /proc d_name; size for the worst case
                               * (gcc -Wformat-truncation counts it at -O2) */
    FILE *f;
    size_t n;

    snprintf(path, sizeof(path), "/proc/%s/comm", pid);
    f = fopen(path, "re");
    if (!f)
        return -1;
    n = fread(buf, 1, sz - 1, f);
    fclose(f);
    if (n == 0)
        return -1;
    if (buf[n - 1] == '\n')
        n--;
    buf[n] = '\0';
    return 0;
}

/* Scan one process's maps for a libssl.so mapping and attach it (via its
 * /proc/<pid>/root view, so a container's copy is reachable from the host). A
 * process may map libssl in several segments, attach_file's inode dedup collapses
 * them. Returns the number of newly attached files. */
static int scan_pid_maps(struct lk_tls *t, const char *pid)
{
    char path[64], line[512];
    int newly = 0;
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    f = fopen(path, "re");
    if (!f)
        return 0;

    while (fgets(line, sizeof(line), f)) {
        char host[PATH_MAX];
        char *p = strchr(line, '/'); /* the pathname is the first '/' on the line */
        size_t len;

        if (!p || !strstr(p, "libssl.so"))
            continue;
        len = strlen(p);
        if (len && p[len - 1] == '\n')
            p[--len] = '\0';

        /* The path is in the target's mount namespace. Reach it from the host
         * through /proc/<pid>/root (identity on a host process). */
        if ((size_t)snprintf(host, sizeof(host), "/proc/%s/root%s", pid, p) >= sizeof(host))
            continue;
        if (attach_file(t, host) == 1)
            newly++;
    }
    fclose(f);
    return newly;
}

static bool comm_in_scan_set(const struct lk_tls *t, const char *comm)
{
    for (const char *const *c = t->comms; *c; c++)
        if (!strcmp(comm, *c))
            return true;
    return false;
}

/* Walk /proc, attach the libssl of every comm-matching process not yet attached.
 * Returns the number of newly attached files. */
static int scan_proc(struct lk_tls *t)
{
    struct dirent *de;
    int newly = 0;
    DIR *proc;

    proc = opendir("/proc");
    if (!proc) {
        fprintf(stderr, "warn: TLS scan: cannot open /proc: %s\n", strerror(errno));
        return 0;
    }
    while ((de = readdir(proc))) {
        char comm[32];

        if (de->d_name[0] < '0' || de->d_name[0] > '9') /* pid dirs only */
            continue;
        if (read_comm(de->d_name, comm, sizeof(comm)) || !comm_in_scan_set(t, comm))
            continue;
        newly += scan_pid_maps(t, de->d_name);
    }
    closedir(proc);
    return newly;
}

static void update_state(struct lk_tls *t)
{
    if (t->nfiles == 0)
        t->state = LK_TLS_STATE_NONE;
    else if (t->any_partial)
        t->state = LK_TLS_STATE_PARTIAL;
    else
        t->state = LK_TLS_STATE_OK;
}

struct lk_tls *lk_tls_new(struct latkit_bpf *skel, const struct lk_tls_cfg *cfg)
{
    struct lk_tls *t = calloc(1, sizeof(*t));

    if (!t)
        return NULL;
    t->skel = skel;
    t->cfg = *cfg;
    t->state = LK_TLS_STATE_NONE;
    t->explicit_path = cfg->libssl_override;
    if (cfg->comm_filter && cfg->comm_filter[0]) {
        t->single_comm[0] = cfg->comm_filter;
        t->comms = t->single_comm;
    } else {
        t->comms = lk_tls_default_comms;
    }
    /* Enabled when there is anything to attach to: an explicit path always, or
     * AUTO which will scan. OFF with no --libssl loads none of the SSL_* programs
     * so the verifier never sees them. */
    t->enabled = cfg->libssl_override || cfg->mode == LK_TLS_AUTO;

    /* libbpf never auto-attaches a bare SEC("uprobe") (no target in the section
     * name), but be explicit, we attach these by hand. When disabled, drop them
     * from the load entirely. */
    for (size_t i = 0; i < TLS_NPROBES; i++) {
        struct bpf_program *p = tls_probes[i].prog(skel);

        bpf_program__set_autoattach(p, false);
        if (!t->enabled)
            bpf_program__set_autoload(p, false);
    }
    return t;
}

int lk_tls_attach(struct lk_tls *t)
{
    if (!t || !t->enabled)
        return 0; /* OFF: soft none, not an error */

    if (t->explicit_path) {
        /* An explicit --libssl must resolve: a bad path is fatal on start, like a
         * failed port bind. */
        struct stat st;

        if (stat(t->explicit_path, &st)) {
            fprintf(stderr, "latkit: --libssl %s: %s\n", t->explicit_path, strerror(errno));
            return -1;
        }
        if (attach_file(t, t->explicit_path) != 1 || t->nfiles == 0) {
            fprintf(stderr, "latkit: --libssl %s: no SSL_* symbols attached\n", t->explicit_path);
            return -1;
        }
        update_state(t);
        return 0;
    }

    /* AUTO: scanning is best effort - no libssl found is a soft none (the agent
     * still serves plaintext), logged so the operator can tell why TLS is dark. */
    scan_proc(t);
    update_state(t);
    if (t->nfiles == 0) {
        fprintf(stderr, "latkit: TLS uprobes: no libssl found for comm");
        for (const char *const *c = t->comms; *c; c++)
            fprintf(stderr, "%s '%s'", c == t->comms ? "" : " /", *c);
        fprintf(stderr, ", TLS connections will be dropped\n");
    }
    return 0;
}

/* Rescan timer body: attach any libssl that showed up since the last pass. */
static void tls_rescan(void *ctx)
{
    struct lk_tls *t = ctx;
    int newly = scan_proc(t);

    if (newly > 0)
        update_state(t);
}

int lk_tls_register(struct lk_tls *t, struct lk_loop *loop)
{
    /* Only AUTO rescans: an explicit --libssl is a fixed target, and pid=-1
     * already covers backends forked into it. */
    if (!t || !t->enabled || t->explicit_path || t->cfg.rescan_sec == 0)
        return 0;
    return lk_loop_every(loop, t->cfg.rescan_sec, tls_rescan, t);
}

void lk_tls_free(struct lk_tls *t)
{
    if (!t)
        return;
    for (int i = 0; i < t->nlinks; i++)
        bpf_link__destroy(t->links[i]);
    free(t->links);
    free(t);
}

enum lk_tls_state lk_tls_status(const struct lk_tls *t)
{
    return t ? t->state : LK_TLS_STATE_NONE;
}
