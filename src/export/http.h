/* SPDX-License-Identifier: GPL-2.0 */
/* Minimal HTTP/1.1 server (Р29, STAGE5.md task 5.1): a small non-blocking state
 * machine living in the shared epoll loop (loop.h), with no third-party
 * dependency. It speaks a microscopic subset of the protocol — GET/HEAD, one
 * request-line plus headers up to a blank line (header contents ignored except
 * Accept, which is handed to the route for OpenMetrics negotiation later),
 * a single Content-Length'd body, Connection: close. Prometheus reopens the
 * connection per scrape without complaint, so keep-alive buys nothing.
 *
 * The agent faces the network, so the input is untrusted (Р18): every request
 * is bounded (size, count, time) and malformed input closes the connection with
 * a 4xx rather than wedging it.
 *
 * The server knows nothing about metrics: routes are plain callbacks. prom.c
 * (task 5.1) wires /metrics and /healthz on top; the encoder and the registry
 * stay out of here. Pure of libbpf; testable on loopback without BPF. */
#ifndef LATKIT_HTTP_H
#define LATKIT_HTTP_H

#include <stddef.h>

struct lk_loop;
struct lk_http;

/* A route handler for one exact path. On success it mallocs the response body
 * into *body (the server frees it), sets *body_len and *content_type (a string
 * literal or otherwise caller-owned, borrowed) and returns the HTTP status code
 * (usually 200). A negative return means "internal error" -> the server sends
 * 500 and frees anything left in *body. accept_hdr is the request's Accept
 * header value (NULL if absent), for content negotiation (Р30); unused in v1. */
struct lk_http_route {
    const char *path;
    int (*handle)(void *ctx, const char *accept_hdr, char **body, size_t *body_len,
                  const char **content_type);
    void *ctx;
};

struct lk_http_cfg {
    const char *bind_addr;              /* "ADDR:PORT", e.g. "127.0.0.1:9752"; port 0 = ephemeral */
    const struct lk_http_route *routes; /* borrowed, must outlive the server */
    int nroutes;
    unsigned int timeout_sec; /* per-connection deadline; 0 = default (5 s) */
    /* Optional accounting hook fired once per completed response (any code,
     * including server-generated 400/404/405). `path` is the matched route path
     * or "other" for anything unrouted. Borrowed; do not free. */
    void (*on_response)(void *ctx, const char *path, int code);
    void *cb_ctx;
};

/* Binds and listens (SO_REUSEADDR, non-blocking) and registers the listen fd in
 * the loop. Returns NULL on any failure (bind is fatal by design — Р29: no
 * silent fallback), logging the cause to stderr. */
struct lk_http *lk_http_new(struct lk_loop *loop, const struct lk_http_cfg *cfg);
void lk_http_free(struct lk_http *h);

/* The actually-bound TCP port in host byte order (useful when the config asked
 * for port 0). 0 before a successful bind. */
int lk_http_port(const struct lk_http *h);

#endif /* LATKIT_HTTP_H */
