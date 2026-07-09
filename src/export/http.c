// SPDX-License-Identifier: GPL-2.0
/* See http.h. One listen fd plus a fixed pool of connection slots, all driven
 * through the shared epoll loop. A connection is a two-state machine:
 *
 *   READ_REQ  -- accumulate bytes until "\r\n\r\n"; parse the request line and
 *                headers; route; build the whole response in memory.
 *   WRITE_RESP-- drain the response buffer by EPOLLOUT readiness, then close.
 *
 * Level-triggered epoll means each handler simply retries the operation its
 * state calls for and tolerates EAGAIN, so the loop never needs to tell it which
 * readiness fired. Slow/hostile clients are contained by a hard connection cap,
 * a request-size ceiling and a per-connection deadline swept once a second. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* memmem, accept4, SOCK_NONBLOCK/SOCK_CLOEXEC */
#endif
#include "http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "loop.h"

#define LK_HTTP_MAX_CONN    8
#define LK_HTTP_REQ_MAX     2048 /* bytes of request (line + headers) accepted */
#define LK_HTTP_TIMEOUT_SEC 5
#define LK_HTTP_PATH_MAX    256
#define LK_HTTP_ACCEPT_MAX  256

enum conn_state { ST_FREE = 0, ST_READ, ST_WRITE };

struct http_conn {
    struct lk_http *h; /* back-pointer: the loop hands us just this ctx */
    int fd;
    enum conn_state state;
    uint64_t deadline_ns;
    char req[LK_HTTP_REQ_MAX];
    size_t req_len;
    char *resp; /* full response bytes (headers + optional body), malloc'd */
    size_t resp_len;
    size_t resp_off;
};

struct lk_http {
    struct lk_loop *loop;
    int lfd;
    int port;
    unsigned int timeout_sec;
    const struct lk_http_route *routes;
    int nroutes;
    void (*on_response)(void *ctx, const char *path, int code);
    void *cb_ctx;
    struct http_conn conns[LK_HTTP_MAX_CONN];
};

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static const char *reason_phrase(int code)
{
    switch (code) {
    case 200:
        return "OK";
    case 400:
        return "Bad Request";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 500:
        return "Internal Server Error";
    case 503:
        return "Service Unavailable";
    default:
        return "OK";
    }
}

/* --- connection slots ----------------------------------------------------- */

static struct http_conn *conn_alloc(struct lk_http *h)
{
    for (int i = 0; i < LK_HTTP_MAX_CONN; i++)
        if (h->conns[i].state == ST_FREE)
            return &h->conns[i];
    return NULL;
}

static void conn_close(struct http_conn *c)
{
    lk_loop_del_fd(c->h->loop, c->fd);
    close(c->fd);
    free(c->resp);
    c->resp = NULL;
    c->req_len = 0;
    c->resp_len = c->resp_off = 0;
    c->fd = -1;
    c->state = ST_FREE;
}

/* --- response construction ------------------------------------------------ */

/* Assemble status line + headers + (unless HEAD) body into c->resp. Takes
 * ownership of `body` (malloc'd or NULL) and frees it. Returns -1 if it cannot
 * allocate the response buffer (the caller then closes the connection). */
static int build_response(struct http_conn *c, int code, const char *ct, char *body,
                          size_t body_len, bool head_only, const char *extra_hdr)
{
    char hdr[512];
    int hn;
    size_t total;
    char *buf;

    hn = snprintf(hdr, sizeof(hdr),
                  "HTTP/1.1 %d %s\r\n"
                  "Content-Type: %s\r\n"
                  "Content-Length: %zu\r\n"
                  "%s"
                  "Connection: close\r\n"
                  "\r\n",
                  code, reason_phrase(code), ct ? ct : "text/plain; charset=utf-8", body_len,
                  extra_hdr ? extra_hdr : "");
    if (hn < 0 || hn >= (int)sizeof(hdr)) {
        free(body);
        return -1;
    }
    total = (size_t)hn + (head_only ? 0 : body_len);
    buf = malloc(total ? total : 1);
    if (!buf) {
        free(body);
        return -1;
    }
    memcpy(buf, hdr, hn);
    if (!head_only && body_len)
        memcpy(buf + hn, body, body_len);
    free(body);
    c->resp = buf;
    c->resp_len = total;
    c->resp_off = 0;
    return 0;
}

/* A tiny text body for the server-generated status responses (400/404/405/500).
 * Returns a malloc'd copy, or NULL (build_response then sends an empty body). */
static char *dup_msg(const char *s, size_t *len)
{
    size_t n = strlen(s);
    char *p = malloc(n + 1);

    if (!p) {
        *len = 0;
        return NULL;
    }
    memcpy(p, s, n + 1);
    *len = n;
    return p;
}

/* --- request parsing ------------------------------------------------------ */

/* Case-insensitive scan of the header block [hdrs, end) for "Accept:", copying
 * its trimmed value into out. Leaves out[0]=0 if absent. */
static void find_accept(const char *hdrs, const char *end, char *out, size_t outsz)
{
    const char *p = hdrs;

    out[0] = '\0';
    while (p < end) {
        const char *eol = memchr(p, '\n', end - p);
        size_t linelen = (eol ? eol : end) - p;

        if (linelen >= 7 && !strncasecmp(p, "accept:", 7)) {
            const char *v = p + 7;
            const char *ve = p + linelen;

            while (v < ve && (*v == ' ' || *v == '\t'))
                v++;
            while (ve > v && (ve[-1] == '\r' || ve[-1] == ' ' || ve[-1] == '\t'))
                ve--;
            size_t n = (size_t)(ve - v);

            if (n >= outsz)
                n = outsz - 1;
            memcpy(out, v, n);
            out[n] = '\0';
            return;
        }
        if (!eol)
            break;
        p = eol + 1;
    }
}

/* Parse the request now that c->req[0..req_len) holds a full header block ending
 * in the "\r\n\r\n" at hdr_end. Fills method/path/accept; returns 0, or an HTTP
 * status (400) on a malformed request line. */
static int parse_request(struct http_conn *c, size_t hdr_end, char *method, size_t methodsz,
                         char *path, size_t pathsz, char *accept, size_t acceptsz)
{
    const char *buf = c->req;
    const char *line_end = memchr(buf, '\r', c->req_len);
    const char *sp1, *sp2, *pp, *pe;
    size_t n;

    if (!line_end)
        return 400;

    /* METHOD SP PATH SP VERSION */
    sp1 = memchr(buf, ' ', line_end - buf);
    if (!sp1 || sp1 == buf)
        return 400;
    n = (size_t)(sp1 - buf);
    if (n >= methodsz)
        return 400;
    memcpy(method, buf, n);
    method[n] = '\0';

    pp = sp1 + 1;
    sp2 = memchr(pp, ' ', line_end - pp);
    if (!sp2 || sp2 == pp)
        return 400;
    /* Strip any query string: routing matches the path only. */
    pe = memchr(pp, '?', sp2 - pp);
    if (!pe)
        pe = sp2;
    n = (size_t)(pe - pp);
    if (n == 0 || n >= pathsz)
        return 400;
    memcpy(path, pp, n);
    path[n] = '\0';

    /* Version token must be present and look like HTTP/x. */
    if (sp2 + 1 >= line_end || strncmp(sp2 + 1, "HTTP/", 5) != 0)
        return 400;

    find_accept(line_end + 2, buf + hdr_end, accept, acceptsz);
    return 0;
}

/* Route the parsed request and build the response. Always sets c->resp (even on
 * error) unless it returns -1 (allocation failure -> caller closes). */
static int dispatch_request(struct http_conn *c, size_t hdr_end)
{
    struct lk_http *h = c->h;
    char method[8], path[LK_HTTP_PATH_MAX], accept[LK_HTTP_ACCEPT_MAX];
    const char *label = "other";
    char *body = NULL;
    size_t body_len = 0;
    const char *ct = NULL;
    bool head_only = false;
    int code;
    int rv;

    code = parse_request(c, hdr_end, method, sizeof(method), path, sizeof(path), accept,
                         sizeof(accept));
    if (code == 0) {
        bool is_get = !strcmp(method, "GET");
        bool is_head = !strcmp(method, "HEAD");

        head_only = is_head;
        if (!is_get && !is_head) {
            code = 405;
        } else {
            const struct lk_http_route *route = NULL;

            for (int i = 0; i < h->nroutes; i++)
                if (!strcmp(h->routes[i].path, path)) {
                    route = &h->routes[i];
                    break;
                }
            if (!route) {
                code = 404;
            } else {
                label = route->path;
                code = route->handle(route->ctx, accept[0] ? accept : NULL, &body, &body_len, &ct);
                if (code < 0) {
                    free(body);
                    body = NULL;
                    body_len = 0;
                    ct = NULL;
                    code = 500;
                }
            }
        }
    }

    /* Server-generated bodies for the non-2xx paths. A 200 handler owns its own
     * body/content-type set above. */
    if (code != 200 && !body)
        body = dup_msg(reason_phrase(code), &body_len);

    rv = build_response(c, code, ct, body, body_len, head_only,
                        code == 405 ? "Allow: GET, HEAD\r\n" : NULL);
    if (h->on_response)
        h->on_response(h->cb_ctx, label, code);
    return rv;
}

/* --- state machine -------------------------------------------------------- */

static int conn_write(struct http_conn *c)
{
    while (c->resp_off < c->resp_len) {
        /* MSG_NOSIGNAL: a peer that vanished mid-write must yield EPIPE, never a
         * process-wide SIGPIPE — the agent installs no SIGPIPE handler. */
        ssize_t n = send(c->fd, c->resp + c->resp_off, c->resp_len - c->resp_off, MSG_NOSIGNAL);

        if (n > 0) {
            c->resp_off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0; /* wait for the next EPOLLOUT */
        conn_close(c); /* peer gone or write error */
        return 0;
    }
    conn_close(c); /* Connection: close — done */
    return 0;
}

static int conn_read(struct http_conn *c)
{
    for (;;) {
        char *end;
        size_t hdr_end;
        ssize_t n = read(c->fd, c->req + c->req_len, sizeof(c->req) - c->req_len);

        if (n > 0) {
            c->req_len += (size_t)n;
        } else if (n == 0) {
            conn_close(c); /* EOF before a full request */
            return 0;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; /* wait for more */
        } else {
            conn_close(c);
            return 0;
        }

        /* Full header block? "\r\n\r\n" search over what we have. */
        end = memmem(c->req, c->req_len, "\r\n\r\n", 4);
        if (end) {
            hdr_end = (size_t)(end - c->req) + 4;
            if (dispatch_request(c, hdr_end) < 0) {
                conn_close(c); /* could not allocate a response */
                return 0;
            }
            c->state = ST_WRITE;
            if (lk_loop_mod_fd(c->h->loop, c->fd, false, true)) {
                conn_close(c);
                return 0;
            }
            return conn_write(c); /* try to send now; else EPOLLOUT resumes it */
        }

        /* No blank line yet and the request buffer is full: the client is
         * oversized or trickling garbage. Reject and close. */
        if (c->req_len == sizeof(c->req)) {
            char *body;
            size_t blen;

            body = dup_msg("request too large\n", &blen);
            if (build_response(c, 400, NULL, body, blen, false, NULL) < 0) {
                conn_close(c);
                return 0;
            }
            if (c->h->on_response)
                c->h->on_response(c->h->cb_ctx, "other", 400);
            c->state = ST_WRITE;
            if (lk_loop_mod_fd(c->h->loop, c->fd, false, true)) {
                conn_close(c);
                return 0;
            }
            return conn_write(c);
        }
        /* n>0 but no full request yet: loop to read again (drain the socket)
         * until EAGAIN. */
    }
}

static int on_conn(void *ctx)
{
    struct http_conn *c = ctx;

    return c->state == ST_WRITE ? conn_write(c) : conn_read(c);
}

static int on_accept(void *ctx)
{
    struct lk_http *h = ctx;

    for (;;) {
        int fd = accept4(h->lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        struct http_conn *c;

        if (fd < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            /* Transient accept errors (e.g. a connection reset before accept)
             * must not take down the loop; drop this one and keep serving. */
            return 0;
        }
        c = conn_alloc(h);
        if (!c) {
            close(fd); /* at the connection cap: shed load (Р29) */
            continue;
        }
        c->h = h;
        c->fd = fd;
        c->state = ST_READ;
        c->req_len = 0;
        c->resp = NULL;
        c->resp_len = c->resp_off = 0;
        c->deadline_ns = now_ns() + (uint64_t)h->timeout_sec * 1000000000ULL;
        if (lk_loop_add_fd(h->loop, fd, on_conn, c)) {
            close(fd);
            c->state = ST_FREE;
            c->fd = -1;
            continue;
        }
    }
}

/* Once-a-second sweep (Р29): close connections that have blown their deadline,
 * whether stuck mid-request (slowloris) or mid-response. */
static void on_sweep(void *ctx)
{
    struct lk_http *h = ctx;
    uint64_t now = now_ns();

    for (int i = 0; i < LK_HTTP_MAX_CONN; i++) {
        struct http_conn *c = &h->conns[i];

        if (c->state != ST_FREE && now >= c->deadline_ns)
            conn_close(c);
    }
}

/* --- listener setup ------------------------------------------------------- */

/* Split "ADDR:PORT" (or "[v6]:PORT") into host/port for getaddrinfo. */
static int split_addr(const char *bind_addr, char *host, size_t hostsz, char *port, size_t portsz)
{
    const char *colon;

    if (bind_addr[0] == '[') {
        const char *rb = strchr(bind_addr, ']');

        if (!rb || rb[1] != ':')
            return -1;
        size_t hn = (size_t)(rb - bind_addr - 1);

        if (hn >= hostsz)
            return -1;
        memcpy(host, bind_addr + 1, hn);
        host[hn] = '\0';
        colon = rb + 1;
    } else {
        colon = strrchr(bind_addr, ':');
        if (!colon)
            return -1;
        size_t hn = (size_t)(colon - bind_addr);

        if (hn == 0 || hn >= hostsz)
            return -1;
        memcpy(host, bind_addr, hn);
        host[hn] = '\0';
    }
    if (snprintf(port, portsz, "%s", colon + 1) >= (int)portsz)
        return -1;
    return 0;
}

static int listen_on(const char *bind_addr, int *out_port)
{
    struct addrinfo hints = {0}, *res = NULL;
    char host[128], port[16];
    int fd = -1, rc;

    if (split_addr(bind_addr, host, sizeof(host), port, sizeof(port))) {
        fprintf(stderr, "http: bad --prom-listen address '%s' (want ADDR:PORT)\n", bind_addr);
        return -1;
    }
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    rc = getaddrinfo(host, port, &hints, &res);
    if (rc) {
        fprintf(stderr, "http: cannot resolve '%s': %s\n", bind_addr, gai_strerror(rc));
        return -1;
    }
    fd = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, res->ai_protocol);
    if (fd < 0) {
        fprintf(stderr, "http: socket: %s\n", strerror(errno));
        goto out;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    if (bind(fd, res->ai_addr, res->ai_addrlen)) {
        fprintf(stderr, "http: bind %s: %s\n", bind_addr, strerror(errno));
        close(fd);
        fd = -1;
        goto out;
    }
    if (listen(fd, LK_HTTP_MAX_CONN)) {
        fprintf(stderr, "http: listen %s: %s\n", bind_addr, strerror(errno));
        close(fd);
        fd = -1;
        goto out;
    }

    /* Report the actually-bound port (the config may have asked for 0). */
    {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);

        *out_port = 0;
        if (!getsockname(fd, (struct sockaddr *)&ss, &sl)) {
            if (ss.ss_family == AF_INET)
                *out_port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
            else if (ss.ss_family == AF_INET6)
                *out_port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
        }
    }
out:
    freeaddrinfo(res);
    return fd;
}

struct lk_http *lk_http_new(struct lk_loop *loop, const struct lk_http_cfg *cfg)
{
    struct lk_http *h = calloc(1, sizeof(*h));

    if (!h)
        return NULL;
    h->loop = loop;
    h->routes = cfg->routes;
    h->nroutes = cfg->nroutes;
    h->timeout_sec = cfg->timeout_sec ? cfg->timeout_sec : LK_HTTP_TIMEOUT_SEC;
    h->on_response = cfg->on_response;
    h->cb_ctx = cfg->cb_ctx;
    for (int i = 0; i < LK_HTTP_MAX_CONN; i++)
        h->conns[i].fd = -1;

    h->lfd = listen_on(cfg->bind_addr, &h->port);
    if (h->lfd < 0) {
        free(h);
        return NULL;
    }
    if (lk_loop_add_fd(loop, h->lfd, on_accept, h)) {
        close(h->lfd);
        free(h);
        return NULL;
    }
    if (lk_loop_every(loop, 1, on_sweep, h)) {
        lk_loop_del_fd(loop, h->lfd);
        close(h->lfd);
        free(h);
        return NULL;
    }
    return h;
}

void lk_http_free(struct lk_http *h)
{
    if (!h)
        return;
    for (int i = 0; i < LK_HTTP_MAX_CONN; i++)
        if (h->conns[i].state != ST_FREE)
            conn_close(&h->conns[i]);
    if (h->lfd >= 0) {
        lk_loop_del_fd(h->loop, h->lfd);
        close(h->lfd);
    }
    free(h);
}

int lk_http_port(const struct lk_http *h)
{
    return h ? h->port : 0;
}
