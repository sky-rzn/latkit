// SPDX-License-Identifier: GPL-2.0
/* TLS uprobe attach lifecycle (stage 6, Р39). Stage 6.1 scope: attach the
 * SSL_read/SSL_write(_ex) uprobe+uretprobe pairs to one explicit libssl path
 * (--libssl), pid=-1 so every process mapping that file — present and future
 * postgres backends — is covered. Scanning /proc, container path resolution and
 * the rescan timer are stage 6.3. */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "latkit.skel.h"
#include "tls_attach.h"

/* One uprobe target: a skeleton program, the libssl symbol it hooks, and
 * whether it is the return probe. `optional` symbols (the _ex calls) may be
 * absent on an older OpenSSL and are skipped without downgrading to error. */
struct lk_tls_probe {
    struct bpf_program *(*prog)(struct latkit_bpf *);
    const char *symbol;
    bool retprobe;
    bool optional;
};

/* Accessors: the skeleton exposes programs as direct struct fields, so a table
 * of member pointers needs these tiny getters. */
#define P(field)                                                                                   \
    static struct bpf_program *tls_prog_##field(struct latkit_bpf *s) { return s->progs.field; }
P(lk_ssl_write)
P(lk_ssl_write_ret)
P(lk_ssl_write_ex)
P(lk_ssl_write_ex_ret)
P(lk_ssl_read)
P(lk_ssl_read_ret)
P(lk_ssl_read_ex)
P(lk_ssl_read_ex_ret)
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
};
#define TLS_NPROBES (sizeof(tls_probes) / sizeof(tls_probes[0]))

struct lk_tls {
    struct latkit_bpf *skel;
    struct lk_tls_cfg cfg;
    const char *binary_path; /* libssl to attach to; NULL when disabled */
    struct bpf_link *links[TLS_NPROBES];
    int nlinks;
    enum lk_tls_state state;
};

struct lk_tls *lk_tls_new(struct latkit_bpf *skel, const struct lk_tls_cfg *cfg)
{
    struct lk_tls *t = calloc(1, sizeof(*t));

    if (!t)
        return NULL;
    t->skel = skel;
    t->cfg = *cfg;
    t->state = LK_TLS_STATE_NONE;

    /* Stage 6.1: only the explicit path attaches. AUTO scanning arrives in
     * 6.3; until then AUTO without --libssl attaches nothing (soft none). */
    if (cfg->libssl_override)
        t->binary_path = cfg->libssl_override;

    /* libbpf never auto-attaches a bare SEC("uprobe") (no target in the section
     * name), but be explicit; we attach these by hand in lk_tls_attach. When no
     * uprobes will be attached at all, drop them from the load entirely so the
     * verifier does not even see them. */
    for (size_t i = 0; i < TLS_NPROBES; i++) {
        struct bpf_program *p = tls_probes[i].prog(skel);

        bpf_program__set_autoattach(p, false);
        if (!t->binary_path)
            bpf_program__set_autoload(p, false);
    }
    return t;
}

int lk_tls_attach(struct lk_tls *t)
{
    unsigned attached = 0, mandatory = 0, mandatory_ok = 0;

    if (!t || !t->binary_path)
        return 0; /* disabled: soft none, not an error (Р39) */

    for (size_t i = 0; i < TLS_NPROBES; i++) {
        const struct lk_tls_probe *pr = &tls_probes[i];
        LIBBPF_OPTS(bpf_uprobe_opts, opts, .func_name = pr->symbol, .retprobe = pr->retprobe);
        struct bpf_link *link;

        if (!pr->optional)
            mandatory++;

        /* pid = -1: attach to every process mapping this libssl, including
         * backends forked after us — no rescan needed for fork coverage. */
        link = bpf_program__attach_uprobe_opts(pr->prog(t->skel), -1, t->binary_path, 0, &opts);
        if (!link) {
            /* A missing symbol (old OpenSSL without _ex) is expected; anything
             * else on a mandatory symbol is worth a warning. */
            if (!pr->optional)
                fprintf(stderr, "warn: TLS uprobe %s%s on %s failed: %s\n", pr->symbol,
                        pr->retprobe ? " (ret)" : "", t->binary_path, strerror(errno));
            continue;
        }
        t->links[t->nlinks++] = link;
        attached++;
        if (!pr->optional)
            mandatory_ok++;
    }

    if (attached == 0)
        t->state = LK_TLS_STATE_NONE;
    else if (mandatory_ok == mandatory && attached == TLS_NPROBES)
        t->state = LK_TLS_STATE_OK;
    else
        t->state = LK_TLS_STATE_PARTIAL;

    if (t->state == LK_TLS_STATE_NONE)
        fprintf(stderr, "latkit: TLS uprobes: no SSL_* symbols attached on %s\n", t->binary_path);
    else
        fprintf(stderr, "latkit: TLS uprobes attached on %s (%u probes)\n", t->binary_path,
                attached);
    return 0;
}

void lk_tls_free(struct lk_tls *t)
{
    if (!t)
        return;
    for (int i = 0; i < t->nlinks; i++)
        bpf_link__destroy(t->links[i]);
    free(t);
}

enum lk_tls_state lk_tls_status(const struct lk_tls *t)
{
    return t ? t->state : LK_TLS_STATE_NONE;
}
