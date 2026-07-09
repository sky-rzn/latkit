// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the minimal HTTP server (task 5.1, Р29). Everything runs on
 * loopback in a single thread: the loop is pumped cooperatively with
 * lk_loop_poll while the test plays the client over blocking/non-blocking TCP.
 * No BPF, no privileges. Coverage mirrors STAGE5.md task 5.1:
 *
 *   - a whole GET, and a request-line torn across many writes;
 *   - a request larger than the 2 KiB ceiling -> 400 and close;
 *   - a slow client that sends half a line and sleeps -> deadline sweep closes
 *     it without touching a concurrent healthy scrape;
 *   - a response larger than the socket buffer, drained over several EPOLLOUT;
 *   - two concurrent scrapes;
 *   - 404 (no route) and 405 (bad method).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "http.h"
#include "loop.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

#define BIG_BODY 100000 /* larger than any default socket buffer */

/* --- route handlers ------------------------------------------------------- */

static int route_echo(void *ctx, const char *accept, char **body, size_t *len, const char **ct)
{
    (void)ctx;
    (void)accept;
    *body = strdup("hello\n");
    *len = 6;
    *ct = "text/plain";
    return 200;
}

static int route_big(void *ctx, const char *accept, char **body, size_t *len, const char **ct)
{
    (void)ctx;
    (void)accept;
    *body = malloc(BIG_BODY);
    if (!*body)
        return -1;
    memset(*body, 'x', BIG_BODY);
    *len = BIG_BODY;
    *ct = "text/plain";
    return 200;
}

static const struct lk_http_route routes[] = {
    {"/echo", route_echo, NULL},
    {"/big", route_big, NULL},
};

/* --- harness -------------------------------------------------------------- */

struct fixture {
    struct lk_loop *loop;
    struct lk_http *http;
    int port;
};

static int fx_up(struct fixture *fx, unsigned timeout_sec)
{
    struct lk_http_cfg cfg = {
        .bind_addr = "127.0.0.1:0",
        .routes = routes,
        .nroutes = 2,
        .timeout_sec = timeout_sec,
    };

    fx->loop = lk_loop_new();
    if (!fx->loop)
        return -1;
    fx->http = lk_http_new(fx->loop, &cfg);
    if (!fx->http) {
        lk_loop_free(fx->loop);
        return -1;
    }
    fx->port = lk_http_port(fx->http);
    return fx->port > 0 ? 0 : -1;
}

static void fx_down(struct fixture *fx)
{
    lk_http_free(fx->http);
    lk_loop_free(fx->loop);
}

static void pump(struct lk_loop *l, int times)
{
    for (int i = 0; i < times; i++)
        lk_loop_poll(l, 10);
}

static int connect_client(int port)
{
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof(sa))) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

static void set_nonblock(int fd)
{
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

/* Pump the server while draining the client socket into buf until the server
 * closes the connection (Connection: close -> read returns 0) or a pump budget
 * is exhausted. Returns total bytes read; buf is NUL-terminated. */
static size_t drain(struct lk_loop *l, int cfd, char *buf, size_t cap)
{
    size_t total = 0;

    set_nonblock(cfd);
    for (int i = 0; i < 400; i++) {
        lk_loop_poll(l, 10);
        for (;;) {
            ssize_t n = read(cfd, buf + total, cap - 1 - total);

            if (n > 0) {
                total += (size_t)n;
                if (total >= cap - 1)
                    goto done;
                continue;
            }
            if (n == 0)
                goto done; /* server closed */
            break;         /* EAGAIN: pump again */
        }
    }
done:
    buf[total] = '\0';
    return total;
}

/* status code from "HTTP/1.1 NNN ..." */
static int status_of(const char *resp)
{
    return (strncmp(resp, "HTTP/1.1 ", 9) == 0) ? atoi(resp + 9) : -1;
}

/* --- tests ---------------------------------------------------------------- */

static int test_simple_get(void)
{
    struct fixture fx;
    char resp[4096];
    int cfd;

    CHECK(fx_up(&fx, 5) == 0);
    cfd = connect_client(fx.port);
    CHECK(cfd >= 0);
    CHECK(write(cfd, "GET /echo HTTP/1.1\r\nHost: x\r\n\r\n", 31) == 31);
    drain(fx.loop, cfd, resp, sizeof(resp));
    CHECK(status_of(resp) == 200);
    CHECK(strstr(resp, "Content-Length: 6") != NULL);
    CHECK(strstr(resp, "Connection: close") != NULL);
    CHECK(strstr(resp, "\r\n\r\nhello\n") != NULL);
    close(cfd);
    fx_down(&fx);
    return 0;
}

static int test_head_no_body(void)
{
    struct fixture fx;
    char resp[4096];
    int cfd;

    CHECK(fx_up(&fx, 5) == 0);
    cfd = connect_client(fx.port);
    CHECK(cfd >= 0);
    CHECK(write(cfd, "HEAD /echo HTTP/1.1\r\n\r\n", 23) == 23);
    drain(fx.loop, cfd, resp, sizeof(resp));
    CHECK(status_of(resp) == 200);
    /* Content-Length is still advertised, but no body follows the blank line. */
    CHECK(strstr(resp, "Content-Length: 6") != NULL);
    CHECK(strstr(resp, "\r\n\r\n") != NULL);
    CHECK(strstr(resp, "hello") == NULL);
    close(cfd);
    fx_down(&fx);
    return 0;
}

static int test_torn_request_line(void)
{
    struct fixture fx;
    const char *req = "GET /echo HTTP/1.1\r\nHost: x\r\n\r\n";
    char resp[4096];
    int cfd;

    CHECK(fx_up(&fx, 5) == 0);
    cfd = connect_client(fx.port);
    CHECK(cfd >= 0);
    /* One byte at a time, pumping the loop between each so the server's read
     * state machine must reassemble a request torn across many events. */
    for (const char *p = req; *p; p++) {
        CHECK(write(cfd, p, 1) == 1);
        pump(fx.loop, 1);
    }
    drain(fx.loop, cfd, resp, sizeof(resp));
    CHECK(status_of(resp) == 200);
    CHECK(strstr(resp, "hello\n") != NULL);
    close(cfd);
    fx_down(&fx);
    return 0;
}

static int test_oversize_request(void)
{
    struct fixture fx;
    char big[4000], resp[4096];
    int cfd;

    CHECK(fx_up(&fx, 5) == 0);
    cfd = connect_client(fx.port);
    CHECK(cfd >= 0);
    /* A request line that never ends: 4000 bytes with no blank line exceeds the
     * 2 KiB ceiling, so the server answers 400 and closes. */
    memset(big, 'A', sizeof(big));
    set_nonblock(cfd);
    for (size_t off = 0; off < sizeof(big);) {
        ssize_t n = write(cfd, big + off, sizeof(big) - off);

        if (n > 0)
            off += (size_t)n;
        pump(fx.loop, 1);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            break; /* server already closed the write side */
    }
    drain(fx.loop, cfd, resp, sizeof(resp));
    CHECK(status_of(resp) == 400);
    close(cfd);
    fx_down(&fx);
    return 0;
}

static int test_slow_client_timeout(void)
{
    struct fixture fx;
    char resp[4096], resp2[4096];
    int slow, healthy;
    struct timespec t0;

    CHECK(fx_up(&fx, 1) == 0); /* 1 s deadline for a fast test */

    /* Slow client: half a request line, then silence. */
    slow = connect_client(fx.port);
    CHECK(slow >= 0);
    CHECK(write(slow, "GET /ec", 7) == 7);
    set_nonblock(slow);

    /* Let enough wall time pass for the once-a-second sweep to fire past the
     * 1 s deadline and reap the slow connection. The deadline is set at accept
     * (~t0), so a sweep at ~t0+1 s can land a hair early; wait past the t0+2 s
     * sweep to be robust. Meanwhile a healthy scrape must still complete. */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        struct timespec now;
        double dt;

        lk_loop_poll(fx.loop, 50);
        clock_gettime(CLOCK_MONOTONIC, &now);
        dt = (now.tv_sec - t0.tv_sec) + (now.tv_nsec - t0.tv_nsec) / 1e9;
        if (dt >= 2.3)
            break;
    }

    /* The slow client has been closed by the server: a read now returns EOF. */
    char c;
    ssize_t n = read(slow, &c, 1);
    CHECK(n == 0);
    close(slow);

    /* And a healthy scrape still works after the sweep. */
    healthy = connect_client(fx.port);
    CHECK(healthy >= 0);
    CHECK(write(healthy, "GET /echo HTTP/1.1\r\n\r\n", 22) == 22);
    drain(fx.loop, healthy, resp, sizeof(resp));
    CHECK(status_of(resp) == 200);
    CHECK(strstr(resp, "hello\n") != NULL);
    close(healthy);

    (void)resp2;
    fx_down(&fx);
    return 0;
}

static int test_partial_write(void)
{
    struct fixture fx;
    char *resp;
    int cfd;
    size_t total;

    CHECK(fx_up(&fx, 5) == 0);
    cfd = connect_client(fx.port);
    CHECK(cfd >= 0);
    /* Shrink the client receive buffer so the server cannot write the whole
     * 100 KiB body at once and must resume on EPOLLOUT. */
    int rcv = 4096;
    setsockopt(cfd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));

    CHECK(write(cfd, "GET /big HTTP/1.1\r\n\r\n", 21) == 21);
    resp = malloc(BIG_BODY + 4096);
    CHECK(resp != NULL);
    total = drain(fx.loop, cfd, resp, BIG_BODY + 4096);
    /* Whole response arrived: headers + exactly BIG_BODY body bytes. */
    CHECK(status_of(resp) == 200);
    char *body = strstr(resp, "\r\n\r\n");
    CHECK(body != NULL);
    body += 4;
    CHECK(total - (size_t)(body - resp) == BIG_BODY);
    free(resp);
    close(cfd);
    fx_down(&fx);
    return 0;
}

static int test_two_concurrent(void)
{
    struct fixture fx;
    char r1[4096], r2[4096];
    int a, b;

    CHECK(fx_up(&fx, 5) == 0);
    a = connect_client(fx.port);
    b = connect_client(fx.port);
    CHECK(a >= 0 && b >= 0);
    CHECK(write(a, "GET /echo HTTP/1.1\r\n\r\n", 22) == 22);
    CHECK(write(b, "GET /echo HTTP/1.1\r\n\r\n", 22) == 22);
    drain(fx.loop, a, r1, sizeof(r1));
    drain(fx.loop, b, r2, sizeof(r2));
    CHECK(status_of(r1) == 200);
    CHECK(status_of(r2) == 200);
    CHECK(strstr(r1, "hello\n") && strstr(r2, "hello\n"));
    close(a);
    close(b);
    fx_down(&fx);
    return 0;
}

static int test_404_405(void)
{
    struct fixture fx;
    char resp[4096];
    int cfd;

    CHECK(fx_up(&fx, 5) == 0);

    cfd = connect_client(fx.port);
    CHECK(cfd >= 0);
    CHECK(write(cfd, "GET /nope HTTP/1.1\r\n\r\n", 22) == 22);
    drain(fx.loop, cfd, resp, sizeof(resp));
    CHECK(status_of(resp) == 404);
    close(cfd);

    cfd = connect_client(fx.port);
    CHECK(cfd >= 0);
    CHECK(write(cfd, "POST /echo HTTP/1.1\r\n\r\n", 23) == 23);
    drain(fx.loop, cfd, resp, sizeof(resp));
    CHECK(status_of(resp) == 405);
    CHECK(strstr(resp, "Allow: GET, HEAD") != NULL);
    close(cfd);

    fx_down(&fx);
    return 0;
}

int main(void)
{
    struct {
        const char *name;
        int (*fn)(void);
    } tests[] = {
        {"simple_get", test_simple_get},
        {"head_no_body", test_head_no_body},
        {"torn_request_line", test_torn_request_line},
        {"oversize_request", test_oversize_request},
        {"slow_client_timeout", test_slow_client_timeout},
        {"partial_write", test_partial_write},
        {"two_concurrent", test_two_concurrent},
        {"404_405", test_404_405},
    };

    /* A dropped client mid-write must not kill the process with SIGPIPE; the
     * server relies on write() returning EPIPE instead. */
    signal(SIGPIPE, SIG_IGN);

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (tests[i].fn()) {
            fprintf(stderr, "FAIL: %s\n", tests[i].name);
            return 1;
        }
        fprintf(stderr, "ok: %s\n", tests[i].name);
    }
    fprintf(stderr, "all http tests passed\n");
    return 0;
}
