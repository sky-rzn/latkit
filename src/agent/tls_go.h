/* SPDX-License-Identifier: GPL-2.0 */
/* Go crypto/tls uprobe attach lifecycle (РH13.3, PLAN-HTTP.md М7): the
 * Go-facing half of the decrypted channel, the twin of tls_attach.h.
 *
 * Why a second module at all. The OpenSSL channel hooks a *shared library*, by
 * symbol name, and lets the kernel place the probe: one `libssl.so`, every
 * process that maps it, entry and return handled by uprobe/uretprobe. A Go
 * server links its TLS in — there is no libssl to find — and cannot be
 * uretprobed at all: the kernel's return trampoline lives on the stack, and the
 * Go runtime moves goroutine stacks when they grow. So this module does by hand
 * what libbpf does for a symbol, and then some:
 *
 *   1. read the binary's symbol table for `crypto/tls.(*Conn).Read/Write`
 *      (elf_syms.h) — a stripped binary stops here, honestly and loudly;
 *   2. decode the function body to find every `ret` (x86_len.h), refusing the
 *      function outright if the walk is not clean — a probe on a byte that is
 *      not an instruction boundary would corrupt the observed process;
 *   3. attach the entry program at the function and the return program at each
 *      of those offsets, pid = -1, so every present and future process running
 *      that binary is covered.
 *
 * What is *not* here, deliberately: any knowledge of Go's data structures. The
 * plaintext-to-connection correlation runs entirely in the kernel through the
 * socket path (РH13.3), so nothing in this module depends on the layout of
 * tls.Conn, net.Conn or the runtime's internals — the parts of Go that change
 * every release. What it does depend on is the register ABI of Go 1.17+ and the
 * x86-64 instruction encoding, both of which are documented and stable.
 *
 * Scope of v1: x86-64 binaries. An arm64 target is refused with a message
 * rather than probed wrongly. */
#ifndef LATKIT_TLS_GO_H
#define LATKIT_TLS_GO_H

#include <stdbool.h>

struct latkit_bpf; /* the generated skeleton (latkit.skel.h) */
struct lk_loop;    /* the event loop (loop.h), for the re-attach timer */
struct lk_tls_go;

/* Ceiling on --tls-go binaries. More than a couple of Go servers on one host
 * beside the agent is already unusual. */
#define LK_TLS_GO_MAX_PATHS 4

struct lk_tls_go_cfg {
    const char *const *paths; /* --tls-go PATH, repeatable */
    int npaths;
    unsigned rescan_sec; /* re-check the paths every N s (0 => never) */
};

/* Create the handle and decide autoload of the Go programs. MUST be called
 * after latkit_bpf__open() and BEFORE latkit_bpf__load(): with no --tls-go the
 * four programs are marked autoload=off, so the verifier never sees them and
 * the socket path's per-thread hint (cfg_go_tls) stays off. Returns NULL on
 * OOM. */
struct lk_tls_go *lk_tls_go_new(struct latkit_bpf *skel, const struct lk_tls_go_cfg *cfg);

/* Attach the entry and return probes to every configured binary. Call after
 * latkit_bpf__attach(). An explicitly named binary that cannot be hooked — not
 * an ELF, not x86-64, stripped, or a body that will not decode — is a startup
 * error, like a bad --libssl: the operator asked for this binary by name.
 * Returns 0, or <0. */
int lk_tls_go_attach(struct lk_tls_go *t);

/* Register the re-check timer: a binary replaced in place (a container image
 * update, a package upgrade) gets a new inode, and uprobes follow the old one.
 * The timer notices the change and re-attaches. No-op when disabled or when
 * rescan_sec is 0. */
int lk_tls_go_register(struct lk_tls_go *t, struct lk_loop *loop);

void lk_tls_go_free(struct lk_tls_go *t);

/* Was a Go binary requested at all, and did every requested one attach fully?
 * The pair feeds the `state` label of latkit_tls_attached (РH13.3): "go" when
 * the Go channel is the live one, "partial" when something was asked for and
 * only partly delivered. */
bool lk_tls_go_enabled(const struct lk_tls_go *t);
int lk_tls_go_files(const struct lk_tls_go *t);    /* binaries with probes live */
bool lk_tls_go_partial(const struct lk_tls_go *t); /* one direction went unhooked */

#endif /* LATKIT_TLS_GO_H */
