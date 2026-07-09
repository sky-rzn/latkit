/* SPDX-License-Identifier: GPL-2.0 */
/* TLS uprobe attach lifecycle (stage 6, Р39): the libssl-facing half of the
 * decrypted channel — everything about which binary to hook and when — kept out
 * of the BPF programs (latkit.bpf.c) and out of main/loader. The BPF side emits
 * plaintext with LK_F_DECRYPTED; this module decides where the SSL_* uprobes
 * land and owns their bpf_link lifetime.
 *
 * Stage 6.1 implements only the explicit-path form: --libssl PATH attaches the
 * uprobes to one given libssl, no /proc scanning. Auto-detection, container
 * path resolution and the periodic rescan are stage 6.3; the config carries the
 * fields already so the API does not churn.
 *
 * No I/O beyond libbpf attach; the caller (main.c) drives load order. */
#ifndef LATKIT_TLS_ATTACH_H
#define LATKIT_TLS_ATTACH_H

struct latkit_bpf; /* the generated skeleton (latkit.skel.h) */
struct lk_tls;

enum lk_tls_mode { LK_TLS_OFF = 0, LK_TLS_AUTO };

/* latkit_tls_attached{state}: none = no uprobes live, partial = some symbols
 * attached (e.g. an OpenSSL without the _ex calls), ok = the full set. */
enum lk_tls_state { LK_TLS_STATE_NONE = 0, LK_TLS_STATE_PARTIAL, LK_TLS_STATE_OK };

struct lk_tls_cfg {
    enum lk_tls_mode mode;       /* --tls: OFF (default, 6.1) or AUTO (scan, 6.3) */
    const char *libssl_override; /* --libssl PATH: attach here, skip the scan */
    const char *comm_filter;     /* --tls-comm: reserved for 6.3 */
    unsigned rescan_sec;         /* periodic rescan period; reserved for 6.3 */
};

/* Create the handle and decide autoload of the SSL_* programs. MUST be called
 * after latkit_bpf__open() and BEFORE latkit_bpf__load(): when no uprobes will
 * be attached (mode OFF and no --libssl) the SSL_* programs are marked
 * autoload=off so they are not even verified. In every case they are marked
 * autoattach=off — libbpf never auto-attaches a bare SEC("uprobe"); this module
 * attaches them explicitly in lk_tls_attach(). Returns NULL only on OOM. */
struct lk_tls *lk_tls_new(struct latkit_bpf *skel, const struct lk_tls_cfg *cfg);

/* Attach the SSL_* uprobe/uretprobe pairs to the configured libssl. Call after
 * latkit_bpf__attach(). Absent symbols (old OpenSSL without _ex) are skipped
 * without error; the resulting coverage is reflected by lk_tls_status. Returns
 * 0 (a soft miss — no libssl, nothing attached — is not an error, Р39), <0 only
 * on a hard failure. */
int lk_tls_attach(struct lk_tls *t);

/* Detach every uprobe link and free the handle. NULL-safe. */
void lk_tls_free(struct lk_tls *t);

enum lk_tls_state lk_tls_status(const struct lk_tls *t);

#endif /* LATKIT_TLS_ATTACH_H */
