// SPDX-License-Identifier: GPL-2.0
/* See tls_go.h. Three steps per binary — resolve, decode, attach — and a
 * refusal at every point where guessing would be cheaper than being sure.
 *
 * The one thing worth restating here, because it is the reason this file is not
 * six lines of bpf_program__attach_uprobe_opts: a return probe on Go code has
 * to be an *entry* probe placed at a return instruction. Everything else
 * follows from that — the symbol size, the instruction decode, the per-function
 * list of offsets, and the rule that a function whose body does not decode
 * cleanly is left alone entirely (entry probe included: an entry with no return
 * would only fill a map with calls nobody ever completes). */
#include "tls_go.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <bpf/libbpf.h>
#include <elf.h>

#include "elf_syms.h"
#include "go_pclntab.h"
#include "latkit.skel.h"
#include "loop.h"
#include "x86_len.h"

/* Ceiling on return sites hooked per function. crypto/tls's Read and Write have
 * a handful each; a body that somehow has more than this is not the function we
 * think it is, and lk_x86_find_rets refuses rather than hooking a prefix of the
 * exits (which would look like packet loss, not like a bug). */
#define TLS_GO_MAX_RETS 64

/* Largest function body decoded. Both targets are well under 4 KiB; the bound
 * is what keeps a corrupt size from turning into a large allocation. */
#define TLS_GO_MAX_BODY (64 * 1024)

/* Largest `.gopclntab` read into memory. Caddy's is a few MB; the ceiling is
 * there so a corrupt section header cannot become a huge allocation. */
#define TLS_GO_MAX_PCLNTAB (64u << 20)

/* The two halves of the Go plaintext boundary. Method symbols are spelled by
 * the compiler exactly like this, package path and pointer receiver included. */
struct lk_go_target {
    const char *symbol;
    struct bpf_program *(*entry)(struct latkit_bpf *);
    struct bpf_program *(*ret)(struct latkit_bpf *);
};

#define P(field)                                                                                   \
    static struct bpf_program *go_prog_##field(struct latkit_bpf *s)                               \
    {                                                                                              \
        return s->progs.field;                                                                     \
    }
P(lk_go_tls_write)
P(lk_go_tls_write_ret)
P(lk_go_tls_read)
P(lk_go_tls_read_ret)
#undef P

static const struct lk_go_target go_targets[] = {
    {"crypto/tls.(*Conn).Write", go_prog_lk_go_tls_write, go_prog_lk_go_tls_write_ret},
    {"crypto/tls.(*Conn).Read", go_prog_lk_go_tls_read, go_prog_lk_go_tls_read_ret},
};
#define GO_NTARGETS (sizeof(go_targets) / sizeof(go_targets[0]))

/* One configured binary and the identity it was attached with, so the re-check
 * timer can tell "same file" from "replaced in place". */
struct lk_go_file {
    const char *path;
    dev_t dev;
    ino_t ino;
    bool attached;  /* probes are live on this inode */
    bool partial;   /* one of the two directions could not be hooked */
    int first_link; /* index into links[] of its first probe, for re-attach */
    int nlinks;
};

struct lk_tls_go {
    struct latkit_bpf *skel;
    struct lk_tls_go_cfg cfg;
    bool enabled;
    struct lk_go_file files[LK_TLS_GO_MAX_PATHS];
    int nfiles;
    struct bpf_link **links;
    int nlinks, links_cap;
};

static int link_append(struct lk_tls_go *t, struct bpf_link *link)
{
    if (t->nlinks == t->links_cap) {
        int cap = t->links_cap ? t->links_cap * 2 : 16;
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

/* Attach one program at one file offset of `path`, pid = -1 (every process
 * running this binary, now and later). */
static int attach_at(struct lk_tls_go *t, struct bpf_program *prog, const char *path,
                     unsigned long off)
{
    LIBBPF_OPTS(bpf_uprobe_opts, opts, .retprobe = false);
    struct bpf_link *link = bpf_program__attach_uprobe_opts(prog, -1, path, off, &opts);

    if (!link) {
        fprintf(stderr, "warn: Go TLS uprobe at %s+0x%lx failed: %s\n", path, off, strerror(errno));
        return -1;
    }
    return link_append(t, link);
}

/* Resolve a function through Go's own function table, for the binaries that
 * have no symbol table — which, measured in М0, is every Go server this track
 * names (Caddy, Traefik, MinIO all ship `-ldflags "-s -w"`). The table is read
 * whole and parsed by go_pclntab.c; this function is only the ELF plumbing
 * around it. Returns 0, or -1 with nothing said (the caller reports).
 *
 * The section-name lookup covers a statically linked Go binary, which is what
 * those three are. A cgo/externally-linked one keeps its pclntab inside
 * .data.rel.ro with no section of its own — finding it there means scanning for
 * the header, and none of the servers in scope needs that today. */
static int resolve_pclntab(struct lk_elf *elf, const char *path, const char *symbol,
                           struct lk_elf_func *out)
{
    uint64_t off, size, vaddr, fnsize, text_addr = 0;
    uint8_t *tab;
    int rc;

    if (lk_elf_section(elf, ".gopclntab", &off, &size, NULL))
        return -1;
    /* The base the table's entry offsets are relative to; see go_pclntab.h. */
    if (lk_elf_section(elf, ".text", NULL, NULL, &text_addr))
        return -1;
    if (!size || size > TLS_GO_MAX_PCLNTAB)
        return -1;
    tab = malloc((size_t)size);
    if (!tab)
        return -1;
    if (lk_elf_read_at(elf, off, tab, (size_t)size)) {
        free(tab);
        return -1;
    }
    rc = lk_go_pclntab_find(tab, (size_t)size, text_addr, symbol, &vaddr, &fnsize);
    free(tab);
    if (rc == -2) {
        fprintf(stderr,
                "warn: Go TLS: %s has a .gopclntab this build does not parse "
                "(Go 1.17 or older?)\n",
                path);
        return -1;
    }
    if (rc)
        return -1; /* the name is simply not in this binary */
    if (lk_elf_vaddr_to_off(elf, vaddr, &off))
        return -1;
    out->vaddr = vaddr;
    out->file_off = off;
    out->size = fnsize;
    return 0;
}

/* Where a function is, by whichever of the two tables the binary still has. The
 * symbol table is tried first — it is exact, and it is what a self-built server
 * carries — and Go's own function table second. */
static int resolve_func(struct lk_elf *elf, const char *path, const char *symbol,
                        struct lk_elf_func *out)
{
    if (lk_elf_find_func(elf, symbol, out) == 0)
        return 0;
    return resolve_pclntab(elf, path, symbol, out);
}

/* Resolve one target function and hook it: entry probe at its first byte,
 * return probe at every `ret` the decoder finds. Returns 1 when hooked, 0 when
 * the function is absent or undecodable (a counted hole in coverage, reported
 * by the caller), <0 on a hard failure. */
static int hook_function(struct lk_tls_go *t, struct lk_elf *elf, const char *path,
                         const struct lk_go_target *tg)
{
    uint32_t rets[TLS_GO_MAX_RETS];
    struct lk_elf_func fn;
    uint8_t *body;
    int nrets;

    if (resolve_func(elf, path, tg->symbol, &fn)) {
        fprintf(stderr, "warn: Go TLS: %s has no %s (not a Go TLS server?)\n", path, tg->symbol);
        return 0;
    }
    if (fn.size > TLS_GO_MAX_BODY) {
        fprintf(stderr, "warn: Go TLS: %s %s is %llu bytes, not decoding it\n", path, tg->symbol,
                (unsigned long long)fn.size);
        return 0;
    }
    body = malloc((size_t)fn.size);
    if (!body)
        return -1;
    if (lk_elf_read_at(elf, fn.file_off, body, (size_t)fn.size)) {
        free(body);
        return -1;
    }

    /* The decode is the safety gate: a body we cannot walk end to end gives us
     * no trustworthy instruction boundary, and a uprobe on a non-boundary
     * corrupts the target process. Leaving the function unhooked costs one
     * direction of one binary and is visible in the log and in the state
     * gauge. */
    nrets = lk_x86_find_rets(body, (size_t)fn.size, rets, TLS_GO_MAX_RETS);
    free(body);
    if (nrets <= 0) {
        fprintf(stderr, "warn: Go TLS: %s %s did not decode (%s), leaving it unhooked\n", path,
                tg->symbol, nrets == 0 ? "no return instruction" : "unsupported instruction");
        return 0;
    }

    if (attach_at(t, tg->entry(t->skel), path, (unsigned long)fn.file_off))
        return 0; /* no entry probe: the return probes would have nothing to pair with */
    for (int i = 0; i < nrets; i++)
        if (attach_at(t, tg->ret(t->skel), path, (unsigned long)(fn.file_off + rets[i])))
            return -1; /* half-hooked returns: bookkeeping OOM, not a soft miss */
    fprintf(stderr, "latkit: Go TLS uprobes on %s %s (entry + %d return site(s))\n", path,
            tg->symbol, nrets);
    return 1;
}

/* Attach both directions of one binary. Returns 1 if anything was hooked. */
static int attach_file(struct lk_tls_go *t, struct lk_go_file *f)
{
    struct lk_elf *elf = lk_elf_open(f->path);
    int hooked = 0;
    struct stat st;

    if (!elf) {
        fprintf(stderr, "latkit: --tls-go %s: not a readable 64-bit ELF binary\n", f->path);
        return 0;
    }
    if (lk_elf_machine(elf) != EM_X86_64) {
        /* The instruction decoder is x86-64; an arm64 Go binary needs an arm64
         * one (РH13.3 keeps that a separate task). Refusing beats attaching
         * return probes at offsets computed from the wrong ISA. */
        fprintf(stderr, "latkit: --tls-go %s: only x86-64 binaries are supported in v1\n", f->path);
        lk_elf_close(elf);
        return 0;
    }
    /* No symbol table is the normal case for a distributed Go binary (М0), not
     * an error: the function table below answers the same question. Only a
     * binary with neither is dark, and hook_function says so per function. */
    if (!lk_elf_has_symtab(elf) && lk_elf_section(elf, ".gopclntab", NULL, NULL, NULL))
        fprintf(stderr,
                "warn: --tls-go %s: neither a symbol table nor a .gopclntab section — "
                "nothing to resolve crypto/tls through\n",
                f->path);

    f->first_link = t->nlinks;
    for (size_t i = 0; i < GO_NTARGETS; i++) {
        int rc = hook_function(t, elf, f->path, &go_targets[i]);

        if (rc < 0) {
            lk_elf_close(elf);
            return -1;
        }
        if (rc)
            hooked++;
        else
            f->partial = true;
    }
    lk_elf_close(elf);
    if (!hooked)
        return 0;

    f->nlinks = t->nlinks - f->first_link;
    f->attached = true;
    if (!stat(f->path, &st)) {
        f->dev = st.st_dev;
        f->ino = st.st_ino;
    }
    return 1;
}

struct lk_tls_go *lk_tls_go_new(struct latkit_bpf *skel, const struct lk_tls_go_cfg *cfg)
{
    struct lk_tls_go *t = calloc(1, sizeof(*t));

    if (!t)
        return NULL;
    t->skel = skel;
    t->cfg = *cfg;
    t->enabled = cfg->npaths > 0;
    for (int i = 0; i < cfg->npaths && i < LK_TLS_GO_MAX_PATHS; i++)
        t->files[t->nfiles++].path = cfg->paths[i];

    /* Off by default in every sense: the programs are not loaded, and the
     * socket path's per-thread hint (cfg_go_tls) is not written either — a
     * PG/MySQL deployment must not pay a map update per send/recv for a channel
     * it does not use (РH15). */
    skel->rodata->cfg_go_tls = t->enabled;
    for (size_t i = 0; i < GO_NTARGETS; i++) {
        struct bpf_program *progs[2] = {go_targets[i].entry(skel), go_targets[i].ret(skel)};

        for (int k = 0; k < 2; k++) {
            bpf_program__set_autoattach(progs[k], false);
            if (!t->enabled)
                bpf_program__set_autoload(progs[k], false);
        }
    }
    return t;
}

int lk_tls_go_attach(struct lk_tls_go *t)
{
    if (!t || !t->enabled)
        return 0;

    for (int i = 0; i < t->nfiles; i++) {
        int rc = attach_file(t, &t->files[i]);

        if (rc < 0)
            return -1;
        if (rc == 0) {
            /* An explicitly named binary that cannot be hooked is a config
             * error, not a soft miss: the operator pointed at this file. */
            fprintf(stderr, "latkit: --tls-go %s: nothing attached\n", t->files[i].path);
            return -1;
        }
    }
    return 0;
}

/* Re-check timer: a binary replaced in place keeps its path and changes its
 * inode, and uprobes stay bound to the inode they were created on — so the new
 * process runs unobserved until something notices. This is that something. The
 * old links are dropped and the new file is hooked from scratch. */
static void tls_go_rescan(void *ctx)
{
    struct lk_tls_go *t = ctx;

    for (int i = 0; i < t->nfiles; i++) {
        struct lk_go_file *f = &t->files[i];
        struct stat st;

        if (!f->attached || stat(f->path, &st))
            continue;
        if (st.st_dev == f->dev && st.st_ino == f->ino)
            continue;
        fprintf(stderr, "latkit: --tls-go %s changed on disk, re-attaching\n", f->path);
        for (int k = f->first_link; k < f->first_link + f->nlinks && k < t->nlinks; k++) {
            bpf_link__destroy(t->links[k]);
            t->links[k] = NULL;
        }
        f->attached = false;
        f->partial = false;
        f->nlinks = 0;
        if (attach_file(t, f) <= 0)
            fprintf(stderr, "warn: --tls-go %s: re-attach failed, TLS on it is dark\n", f->path);
    }
}

int lk_tls_go_register(struct lk_tls_go *t, struct lk_loop *loop)
{
    if (!t || !t->enabled || t->cfg.rescan_sec == 0)
        return 0;
    return lk_loop_every(loop, t->cfg.rescan_sec, tls_go_rescan, t);
}

void lk_tls_go_free(struct lk_tls_go *t)
{
    if (!t)
        return;
    for (int i = 0; i < t->nlinks; i++)
        bpf_link__destroy(t->links[i]); /* NULL-safe (dropped by a rescan) */
    free(t->links);
    free(t);
}

bool lk_tls_go_enabled(const struct lk_tls_go *t)
{
    return t && t->enabled;
}

int lk_tls_go_files(const struct lk_tls_go *t)
{
    int n = 0;

    if (!t)
        return 0;
    for (int i = 0; i < t->nfiles; i++)
        n += t->files[i].attached;
    return n;
}

bool lk_tls_go_partial(const struct lk_tls_go *t)
{
    if (!t)
        return false;
    for (int i = 0; i < t->nfiles; i++)
        if (t->files[i].partial)
            return true;
    return false;
}
