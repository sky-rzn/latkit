/* SPDX-License-Identifier: GPL-2.0 */
/* TLS uprobe attach lifecycle: the libssl-facing half of the decrypted channel -
 * everything about which binary to hook and when - kept out of the BPF programs
 * (latkit.bpf.c) and out of main/loader. The BPF side emits plaintext with
 * LK_F_DECRYPTED; this module decides where the SSL_* uprobes land and owns
 * their bpf_link lifetime.
 *
 * Two ways to pick the libssl: --libssl PATH attaches to one given binary (no
 * scanning); --tls auto scans /proc for the libssl mapped by the DB-server
 * processes — process comm in {postgres, mysqld, mariadbd} by default (РМ10),
 * one --tls-comm name when narrowed — resolving each container path through
 * /proc/<pid>/root and deduping by inode, then rescans on a timer to pick up
 * newly started clusters. pid=-1 on every attach covers forked backends without
 * a rescan. MariaDB builds linked against bundled wolfSSL/GnuTLS map no libssl
 * and stay dark; latkit_tls_attached{state="none"} is the diagnostic.
 *
 * No I/O beyond libbpf attach and reading /proc; the caller (main.c) drives load
 * order and registers the rescan timer. */

#ifndef LATKIT_TLS_ATTACH_H
#define LATKIT_TLS_ATTACH_H

#include <stdbool.h>

struct latkit_bpf; /* the generated skeleton (latkit.skel.h) */
struct lk_loop;    /* the event loop (loop.h), for the rescan timer */
struct lk_tls;

enum lk_tls_mode { LK_TLS_OFF = 0, LK_TLS_AUTO };

/* latkit_tls_attached{state}: none = no uprobes live, partial = some symbols
 * attached (e.g. an OpenSSL without the _ex calls), ok = the full set.
 *
 * `go` is the one value this module never returns on its own (РH13.3): it means
 * "the live plaintext channel is the Go one, and it is complete", which is a
 * statement about both channels together — events.c combines the libssl status
 * below with the Go one (tls_go.h) into the single value the gauge carries. */
enum lk_tls_state {
    LK_TLS_STATE_NONE = 0,
    LK_TLS_STATE_PARTIAL,
    LK_TLS_STATE_OK,
    LK_TLS_STATE_GO,
    LK_TLS_STATE_MAX
};

struct lk_tls_cfg {
    enum lk_tls_mode mode;       /* --tls: OFF (default) or AUTO (scan /proc) */
    const char *libssl_override; /* --libssl PATH: attach here, skip the scan */
    const char *comm_filter;     /* --tls-comm: the one process comm to scan for;
                                  * NULL => the `comms` list below */
    const char *const *comms;    /* NULL-terminated scan set, derived by main.c from
                                  * the configured port protocols (РH13.1): the DB
                                  * servers, the OpenSSL web servers, or both. NULL
                                  * => lk_tls_default_comms, the DB-only default */
    unsigned rescan_sec;         /* AUTO rescan period for new libssl paths (0 => no rescan) */
    bool go_channel;             /* a --tls-go binary is attached too (tls_go.h): "no libssl
                                  * here" is then the expected shape of a Go server, not a
                                  * blind zone, and the startup log says so (РS8) */
};

/* The AUTO-scan process-comm sets, NULL-terminated, one per family of server
 * latkit speaks the protocol of. main.c picks the ones the configured ports
 * call for (РH13.1) and derives the kernel-side thread-comm filter from the same
 * lists (plus `connection`, the MySQL 8.x session-thread name).
 *
 * The HTTP set covers the servers that reach OpenSSL through a shared libssl.
 * The Go-based ones (Caddy, Traefik) are not there and never will be: they have
 * no libssl to find, and their plaintext comes from the separate Go channel
 * (tls_go.h), attached to the binary by name.
 *
 * The S3 set is the one exception to that rule, and only for the second consumer
 * (РS8): `minio` is in it not so the libssl scan can look for a library MinIO
 * does not map, but so the *uprobe gate* — derived from the same list — admits
 * the threads the Go channel's events come from. */
extern const char *const lk_tls_default_comms[]; /* postgres, mysqld, mariadbd */
extern const char *const lk_tls_http_comms[];    /* nginx, httpd, apache2, haproxy */
extern const char *const lk_tls_s3_comms[];      /* minio */

/* Create the handle and decide autoload of the SSL_* programs. MUST be called
 * after latkit_bpf__open() and BEFORE latkit_bpf__load(): when no uprobes will
 * be attached (mode OFF and no --libssl) the SSL_* programs are marked
 * autoload=off so they are not even verified. In every case they are marked
 * autoattach=off - libbpf never auto-attaches a bare SEC("uprobe"); this module
 * attaches them explicitly in lk_tls_attach(). Returns NULL only on OOM. */
struct lk_tls *lk_tls_new(struct latkit_bpf *skel, const struct lk_tls_cfg *cfg);

/* Attach the SSL_* uprobe/uretprobe pairs to the configured libssl. Call after
 * latkit_bpf__attach(). Absent symbols (old OpenSSL without _ex) are skipped
 * without error; the resulting coverage is reflected by lk_tls_status. Returns
 * 0 (a soft miss - no libssl, nothing attached - is not an error), <0 only
 * on a hard failure. */
int lk_tls_attach(struct lk_tls *t);

/* Register the AUTO-mode rescan timer on the event loop, so libssl paths that
 * appear after startup (a cluster restart, a second install) get attached
 * without an agent restart. No-op for OFF or an explicit --libssl (a fixed
 * target; pid=-1 already covers its forked backends). Call after lk_tls_attach
 * and once the loop exists. Returns 0, or <0 if the timer could not be armed. */
int lk_tls_register(struct lk_tls *t, struct lk_loop *loop);

/* Detach every uprobe link and free the handle. NULL-safe. */
void lk_tls_free(struct lk_tls *t);

enum lk_tls_state lk_tls_status(const struct lk_tls *t);

#endif /* LATKIT_TLS_ATTACH_H */
