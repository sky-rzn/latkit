// SPDX-License-Identifier: GPL-2.0
/* pgstream (task 8.4, Р52): replays the byte streams of the clean fixtures
 * (tests/replay/fixtures_gen.c, via fixture_stream.h) through a REAL loopback
 * TCP connection — both endpoints in this one process, driven in lockstep, so
 * the agent's kernel capture sees genuine tcp_sendmsg/tcp_recvmsg calls with
 * exactly the fixture payloads on a port it filters. This is the plaintext
 * smoke load of the kernel matrix: no docker, no postgres, nothing but libc —
 * it runs identically inside a vmtest VM and on a live host
 * (tests/kernel/smoke.sh).
 *
 * Lockstep needs no threads: for each op the writer side write()s the whole
 * payload (it fits in the socket buffer), then the reader side read()s exactly
 * that many bytes — RECV ops flow client->server, SEND ops server->client, in
 * trace order, one connection per fixture. The reads are what make the
 * server-side tcp_recvmsg fire, so they are part of the test, not ceremony.
 *
 * Prints the summary line smoke.sh asserts against the agent's metrics:
 *   pgstream: done conns=N queries=N sessions=N errors=N
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fixture_stream.h"

static void die(const char *what)
{
    perror(what);
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

static void read_all(int fd, size_t n)
{
    __u8 buf[4096];

    while (n) {
        ssize_t r = read(fd, buf, n < sizeof(buf) ? n : sizeof(buf));

        if (r <= 0) {
            if (r < 0 && errno == EINTR)
                continue;
            fprintf(stderr, "pgstream: short read (%zd, %zu bytes left)\n", r, n);
            exit(1);
        }
        n -= (size_t)r;
    }
}

/* One fixture = one connection: connect, replay the ops in lockstep, close
 * client-first so the server socket passes through LAST_ACK to TCP_CLOSE and
 * the agent gets its CONN_CLOSE promptly (the client side ends in TIME_WAIT,
 * which the capture never sees — its local port is not filtered). */
static void replay_conn(int lfd, const struct sockaddr_in *addr, const struct ks_stream *s)
{
    int one = 1;
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    int sfd;

    if (cfd < 0)
        die("socket");
    if (connect(cfd, (const struct sockaddr *)addr, sizeof(*addr)))
        die("connect");
    sfd = accept(lfd, NULL, NULL);
    if (sfd < 0)
        die("accept");
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    for (size_t i = 0; i < s->nops; i++) {
        const struct ks_op *op = &s->ops[i];

        if (op->dir == LK_DIR_RECV) { /* frontend -> backend */
            write_all(cfd, s->bytes + op->off, op->len);
            read_all(sfd, op->len);
        } else { /* backend -> frontend */
            write_all(sfd, s->bytes + op->off, op->len);
            read_all(cfd, op->len);
        }
    }

    close(cfd);
    /* Wait for the client's FIN so the server close is a clean passive close. */
    {
        __u8 b;

        if (read(sfd, &b, 1) != 0)
            fprintf(stderr, "pgstream: %s: unexpected trailing bytes\n", s->name);
    }
    close(sfd);
}

int main(int argc, char **argv)
{
    struct ks_stream ss[KS_MAX_STREAMS];
    struct sockaddr_in addr = {.sin_family = AF_INET};
    int port = 5432, repeat = 1, opt, lfd, one = 1;
    const char *proto = NULL; /* NULL = pg; "mysql" with -m (МYSQL.md М7) */
    size_t n, conns = 0;

    while ((opt = getopt(argc, argv, "p:r:mh")) != -1) {
        switch (opt) {
        case 'p':
            port = atoi(optarg);
            break;
        case 'r':
            repeat = atoi(optarg);
            break;
        case 'm':
            proto = "mysql"; /* stream the mysql fixtures (agent: -p PORT=mysql) */
            break;
        default:
            fprintf(stderr, "usage: %s [-p port] [-r repeat] [-m]\n", argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    n = ks_extract_all(false, proto, ss, KS_MAX_STREAMS);
    if (!n) {
        fprintf(stderr, "pgstream: no replayable fixtures\n");
        return 1;
    }

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
            fprintf(stderr, "pgstream: replaying %s (%zu ops)\n", ss[i].name, ss[i].nops);
            replay_conn(lfd, &addr, &ss[i]);
            conns++;
        }
    close(lfd);

    ks_print_summary("pgstream", conns, ss, n, repeat);
    for (size_t i = 0; i < n; i++)
        free(ss[i].bytes);
    return 0;
}
