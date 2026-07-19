// SPDX-License-Identifier: GPL-2.0
/* tlspipe (task 8.4, Р52): the TLS twin of pgstream. Replays the clean
 * fixture streams through a REAL SSL session over loopback — plaintext
 * SSLRequest/'S' prelude on the socket (exactly postgres' wire dance), then a
 * genuine libssl handshake, then the fixture bytes through SSL_write/SSL_read.
 * The agent's uprobe channel (stage 6, Р35–Р38) and the SSL*->cookie bridge
 * (Р37, including the SSL_set_fd fd->sock walk this matrix exists to stress)
 * therefore see the real thing on every kernel of the matrix, with no docker
 * and no postgres: both endpoints live in this process, linked against the
 * rootfs libssl.
 *
 * Thread layout is part of the test design: the SERVER side runs on the main
 * thread, whose comm is "tlspipe" — the value the agent is told to filter on
 * (--tls-comm tlspipe / --libssl). The CLIENT side runs on a thread renamed to
 * "tlspipe-cli": its SSL_* calls hit the same uprobes but fail the comm
 * filter, so client-side plaintext (which would parse as garbage — the
 * directions are inverted) never reaches the pipeline, just like a psql
 * client's libssl is kept out in production by the comm filter. Blocking
 * SSL_read provides the lockstep — each side walks the same op list and
 * naturally waits for its peer.
 *
 * -P SEC pauses after the FIRST server handshake, before any SSL_read/SSL_write
 * of data. In that window the only mechanism that can have filled the agent's
 * ssl_to_conn map is the SSL_set_fd walk (the nested-syscall fallback needs a
 * live SSL_read/SSL_write), so smoke.sh can distinguish "the walk works" from
 * "the fallback papered over it" with a bpftool map dump.
 *
 * Prints the summary line smoke.sh asserts against the agent's metrics:
 *   tlspipe: done conns=N queries=N sessions=N errors=N
 */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "fixture_stream.h"

static void die(const char *what)
{
    perror(what);
    exit(1);
}

static void die_ssl(const char *what)
{
    fprintf(stderr, "tlspipe: %s failed\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static void write_all(int fd, const __u8 *p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);

        if (w <= 0) {
            if (w < 0 && errno == EINTR)
                continue;
            die("write");
        }
        p += w;
        n -= (size_t)w;
    }
}

static void read_exact(int fd, __u8 *p, size_t n)
{
    while (n) {
        ssize_t r = read(fd, p, n);

        if (r <= 0) {
            if (r < 0 && errno == EINTR)
                continue;
            fprintf(stderr, "tlspipe: short read\n");
            exit(1);
        }
        p += r;
        n -= (size_t)r;
    }
}

static void ssl_write_all(SSL *ssl, const __u8 *p, size_t n)
{
    while (n) {
        int w = SSL_write(ssl, p, n > INT_MAX ? INT_MAX : (int)n);

        if (w <= 0)
            die_ssl("SSL_write");
        p += w;
        n -= (size_t)w;
    }
}

static void ssl_read_all(SSL *ssl, size_t n)
{
    __u8 buf[4096];

    while (n) {
        int r = SSL_read(ssl, buf, n < sizeof(buf) ? (int)n : (int)sizeof(buf));

        if (r <= 0)
            die_ssl("SSL_read");
        n -= (size_t)r;
    }
}

/* Self-signed cert + key, generated in memory (OpenSSL 3 API): no files to
 * ship, no openssl CLI dependency inside the VM. */
static void make_cert(SSL_CTX *ctx)
{
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    X509 *crt = X509_new();
    X509_NAME *name;

    if (!pkey || !crt)
        die_ssl("keygen");
    X509_set_version(crt, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(crt), 1);
    X509_gmtime_adj(X509_getm_notBefore(crt), -3600);
    X509_gmtime_adj(X509_getm_notAfter(crt), 86400L * 365);
    X509_set_pubkey(crt, pkey);
    name = X509_get_subject_name(crt);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"tlspipe", -1, -1,
                               0);
    X509_set_issuer_name(crt, name);
    if (!X509_sign(crt, pkey, EVP_sha256()))
        die_ssl("X509_sign");
    if (SSL_CTX_use_certificate(ctx, crt) != 1 || SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
        die_ssl("SSL_CTX_use_*");
    X509_free(crt);
    EVP_PKEY_free(pkey);
}

/* PG wire SSLRequest: int32 len = 8, int32 code = 80877103. */
static void sslrequest(__u8 *out)
{
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    out[3] = 8;
    out[4] = (__u8)(LK_PG_SSL_REQUEST >> 24);
    out[5] = (__u8)(LK_PG_SSL_REQUEST >> 16);
    out[6] = (__u8)(LK_PG_SSL_REQUEST >> 8);
    out[7] = (__u8)LK_PG_SSL_REQUEST;
}

struct client_task {
    const struct ks_stream *s;
    SSL_CTX *cctx;
    int cfd;
};

/* Client half of one connection: prelude, handshake, then its side of every
 * op. Runs under a different comm (see the header comment) so the agent's
 * uprobe filter drops everything this thread does in libssl. */
static void *client_main(void *arg)
{
    struct client_task *t = arg;
    const struct ks_stream *s = t->s;
    __u8 req[8], resp;
    SSL *ssl;

    prctl(PR_SET_NAME, "tlspipe-cli");

    sslrequest(req);
    write_all(t->cfd, req, sizeof(req));
    read_exact(t->cfd, &resp, 1);
    if (resp != 'S') {
        fprintf(stderr, "tlspipe: expected 'S', got %#x\n", resp);
        exit(1);
    }

    ssl = SSL_new(t->cctx);
    if (!ssl || SSL_set_fd(ssl, t->cfd) != 1)
        die_ssl("client SSL_new/set_fd");
    if (SSL_connect(ssl) != 1)
        die_ssl("SSL_connect");

    for (size_t i = 0; i < s->nops; i++) {
        const struct ks_op *op = &s->ops[i];

        if (op->dir == LK_DIR_RECV) /* frontend -> backend: client writes */
            ssl_write_all(ssl, s->bytes + op->off, op->len);
        else
            ssl_read_all(ssl, op->len);
    }

    /* Bidirectional shutdown, then close: SSL_read here consumes whatever the
     * server pushed outside the script (session tickets) plus its close_notify.
     * Closing with unread bytes in the receive queue would make the kernel
     * answer with RST instead of FIN, and an RST kills the server socket
     * (TCP_CLOSE fires) while its last decrypted event is still in flight —
     * the agent then sees data after CONN_CLOSE and resurrects the connection.
     * That race cost the cancel fixture its observation on the first live run;
     * a clean shutdown removes it deterministically. */
    SSL_shutdown(ssl);
    {
        __u8 b;

        while (SSL_read(ssl, &b, 1) > 0)
            ;
    }
    SSL_free(ssl);
    close(t->cfd);
    return NULL;
}

/* One fixture = one TLS connection. The server (this thread, comm "tlspipe")
 * is the captured side: local port filtered, SSL_read = frontend bytes,
 * SSL_write = backend bytes — the direction semantics of Р7/Р35. */
static void replay_conn(int lfd, const struct sockaddr_in *addr, const struct ks_stream *s,
                        SSL_CTX *sctx, SSL_CTX *cctx, int pause_sec)
{
    static bool paused_once;
    struct client_task task = {.s = s, .cctx = cctx};
    pthread_t cli;
    __u8 req[8];
    SSL *ssl;
    int sfd, one = 1;

    task.cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (task.cfd < 0)
        die("socket");
    if (connect(task.cfd, (const struct sockaddr *)addr, sizeof(*addr)))
        die("connect");
    sfd = accept(lfd, NULL, NULL);
    if (sfd < 0)
        die("accept");
    setsockopt(task.cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    if (pthread_create(&cli, NULL, client_main, &task))
        die("pthread_create");

    read_exact(sfd, req, sizeof(req)); /* SSLRequest (asserted client-side) */
    write_all(sfd, (const __u8 *)"S", 1);

    ssl = SSL_new(sctx);
    if (!ssl || SSL_set_fd(ssl, sfd) != 1)
        die_ssl("server SSL_new/set_fd");
    if (SSL_accept(ssl) != 1)
        die_ssl("SSL_accept");

    if (pause_sec && !paused_once) {
        /* No data SSL_read/SSL_write has run yet on the server comm: the walk
         * window for smoke.sh's bpftool check (see the header comment). */
        paused_once = true;
        printf("tlspipe: handshake done, pausing %ds\n", pause_sec);
        fflush(stdout);
        sleep((unsigned)pause_sec);
    }

    for (size_t i = 0; i < s->nops; i++) {
        const struct ks_op *op = &s->ops[i];

        if (op->dir == LK_DIR_RECV)
            ssl_read_all(ssl, op->len);
        else
            ssl_write_all(ssl, s->bytes + op->off, op->len);
    }

    /* Send our close_notify first (the client's drain loop waits for it), then
     * absorb the client's; the client closes first, so this side is a clean
     * passive close — the server socket reaches TCP_CLOSE right away (no
     * TIME_WAIT) and the agent gets its CONN_CLOSE. */
    SSL_shutdown(ssl);
    {
        __u8 b;

        while (SSL_read(ssl, &b, 1) > 0)
            ;
    }
    pthread_join(cli, NULL);
    SSL_free(ssl);
    close(sfd);
}

int main(int argc, char **argv)
{
    struct ks_stream ss[KS_MAX_STREAMS];
    struct sockaddr_in addr = {.sin_family = AF_INET};
    SSL_CTX *sctx, *cctx;
    int port = 5432, repeat = 1, pause_sec = 0, opt, lfd, one = 1;
    size_t n, conns = 0;

    while ((opt = getopt(argc, argv, "p:r:P:h")) != -1) {
        switch (opt) {
        case 'p':
            port = atoi(optarg);
            break;
        case 'r':
            repeat = atoi(optarg);
            break;
        case 'P':
            pause_sec = atoi(optarg);
            break;
        default:
            fprintf(stderr, "usage: %s [-p port] [-r repeat] [-P pause-sec]\n", argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }
    signal(SIGPIPE, SIG_IGN);

    n = ks_extract_all(true, NULL, ss, KS_MAX_STREAMS);
    if (!n) {
        fprintf(stderr, "tlspipe: no replayable fixtures\n");
        return 1;
    }

    sctx = SSL_CTX_new(TLS_server_method());
    cctx = SSL_CTX_new(TLS_client_method());
    if (!sctx || !cctx)
        die_ssl("SSL_CTX_new");
    make_cert(sctx);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);

    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0)
        die("socket");
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)))
        die("bind");
    if (listen(lfd, 8))
        die("listen");

    for (int r = 0; r < repeat; r++)
        for (size_t i = 0; i < n; i++) {
            fprintf(stderr, "tlspipe: replaying %s (%zu ops)\n", ss[i].name, ss[i].nops);
            replay_conn(lfd, &addr, &ss[i], sctx, cctx, pause_sec);
            conns++;
        }
    close(lfd);

    ks_print_summary("tlspipe", conns, ss, n, repeat);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    for (size_t i = 0; i < n; i++)
        free(ss[i].bytes);
    return 0;
}
