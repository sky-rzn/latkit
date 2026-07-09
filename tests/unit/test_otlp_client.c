// SPDX-License-Identifier: GPL-2.0
/* OTLP client end-to-end on loopback (task 5.2): drives the real exporter state
 * machine (connect -> write -> read status) in the shared loop against a bare
 * TCP listener, with no BPF. Asserts the request is a well-formed OTLP POST
 * (path, content-type, a protobuf body whose first field is resource_metrics)
 * and that a 200 bumps latkit_otlp_exports_total{result="ok"}; then a second
 * export against a listener that replies 503 bumps result="error". Covers the
 * client the encoder tests cannot reach. Cooperative loop via lk_loop_poll. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* strcasestr, open_memstream, accept4 */
#endif
#include "loop.h"
#include "metrics.h"
#include "otlp.h"
#include "proto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int failures;
#define EXPECT(cond, msg)                                                                          \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: %s\n", msg);                                                             \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

static uint64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Read the current latkit_otlp_exports_total{...,result="<res>"} value. */
static long dump_export_count(struct lk_metrics *m, const char *res)
{
    char *buf = NULL;
    size_t sz = 0;
    FILE *f = open_memstream(&buf, &sz);
    long val = -1;
    char needle[64];

    lk_metrics_dump(m, f);
    fclose(f);
    snprintf(needle, sizeof(needle), "result=\"%s\"}", res);
    for (char *p = buf; (p = strstr(p, "latkit_otlp_exports_total"));) {
        char *nl = strchr(p, '\n');

        if (nl)
            *nl = '\0';
        if (strstr(p, needle)) {
            char *sp = strrchr(p, ' ');

            if (sp)
                val = atol(sp + 1);
        }
        if (!nl)
            break;
        *nl = '\n';
        p = nl + 1;
    }
    free(buf);
    return val;
}

static int listen_loopback(int *port)
{
    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in sa = {0};
    socklen_t sl = sizeof(sa);

    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) || listen(lfd, 4) ||
        getsockname(lfd, (struct sockaddr *)&sa, &sl)) {
        perror("listen_loopback");
        exit(2);
    }
    *port = ntohs(sa.sin_port);
    return lfd;
}

/* Drive the loop until the listener accepts one request; capture it, reply with
 * `status_line`, and keep polling so the client reads the response. Returns the
 * captured request bytes (malloc'd) and its length, or NULL on timeout. */
static char *serve_one(struct lk_loop *loop, int lfd, const char *status_line, size_t *out_len)
{
    uint64_t deadline = now_ms() + 8000;
    int cfd = -1;
    char *req = NULL;
    size_t req_len = 0, req_cap = 0;
    long content_len = -1;
    size_t hdr_end = 0;

    while (now_ms() < deadline) {
        lk_loop_poll(loop, 50);

        if (cfd < 0) {
            cfd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (cfd < 0)
                continue;
        }
        for (;;) {
            char tmp[4096];
            ssize_t n = recv(cfd, tmp, sizeof(tmp), 0);

            if (n > 0) {
                if (req_len + (size_t)n + 1 > req_cap) {
                    req_cap = (req_len + n + 1) * 2;
                    req = realloc(req, req_cap);
                }
                memcpy(req + req_len, tmp, n);
                req_len += n;
                req[req_len] = '\0';
            } else {
                break; /* EAGAIN or EOF: process what we have */
            }
        }
        if (!hdr_end && req) {
            char *e = strstr(req, "\r\n\r\n");

            if (e) {
                char *cl = strcasestr(req, "content-length:");

                hdr_end = (size_t)(e - req) + 4;
                if (cl)
                    content_len = atol(cl + 15);
            }
        }
        if (hdr_end && content_len >= 0 && req_len >= hdr_end + (size_t)content_len) {
            send(cfd, status_line, strlen(status_line), MSG_NOSIGNAL);
            close(cfd);
            /* let the client read the reply and settle back to idle */
            for (int i = 0; i < 10; i++)
                lk_loop_poll(loop, 20);
            *out_len = req_len;
            return req;
        }
    }
    free(req);
    return NULL;
}

int main(void)
{
    struct lk_loop *loop = lk_loop_new();
    struct lk_metrics *m = lk_metrics_new(NULL);
    struct lk_otlp *o;
    struct lk_otlp_cfg cfg = {0};
    char endpoint[64];
    int lfd, port;
    char *req;
    size_t rlen;

    if (!loop || !m) {
        printf("setup failed\n");
        return 2;
    }
    lfd = listen_loopback(&port);
    snprintf(endpoint, sizeof(endpoint), "http://127.0.0.1:%d", port);
    cfg.endpoint = endpoint;
    cfg.interval_sec = 1;

    o = lk_otlp_new(loop, m, &cfg);
    EXPECT(o != NULL, "exporter created");
    if (!o)
        return 2;

    /* First export: reply 200, expect result="ok" to advance. */
    req = serve_one(loop, lfd, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", &rlen);
    EXPECT(req != NULL, "request received");
    if (req) {
        EXPECT(!strncmp(req, "POST /v1/metrics HTTP/1.1", 25), "POST /v1/metrics request line");
        EXPECT(strcasestr(req, "content-type: application/x-protobuf") != NULL,
               "protobuf content-type");
        /* Body starts after the header block; its first byte is the tag for
         * ExportMetricsServiceRequest.resource_metrics (field 1, wire 2 = 0x0a). */
        {
            char *body = strstr(req, "\r\n\r\n");

            EXPECT(body && (unsigned char)body[4] == 0x0a, "body starts with resource_metrics tag");
        }
        free(req);
    }
    EXPECT(dump_export_count(m, "ok") >= 1, "exports_total{result=ok} >= 1");

    /* Second export: reply 503, expect result="error" to advance. */
    req = serve_one(loop, lfd, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
                    &rlen);
    EXPECT(req != NULL, "second request received");
    free(req);
    EXPECT(dump_export_count(m, "error") >= 1, "exports_total{result=error} >= 1");

    /* Spans (task 5.3): a fresh exporter with spans on, on its own loop and
     * metrics object. A dedicated loop matters — lk_otlp_free does not cancel the
     * export tick (the exporter's lifetime is the loop's in production), so an
     * exporter and the loop it drives must be torn down together, not reused.
     * Feeding one sampled observation makes the next tick POST metrics and then,
     * once that settles, POST /v1/traces carrying the span. */
    struct lk_loop *loop2 = lk_loop_new();
    struct lk_metrics *m2 = lk_metrics_new(NULL);
    struct lk_otlp *o2;

    cfg.span_sample_ratio = 1.0;
    cfg.span_seed = 1;
    o2 = (loop2 && m2) ? lk_otlp_new(loop2, m2, &cfg) : NULL;
    EXPECT(o2 != NULL, "exporter with spans created");
    if (o2) {
        const struct lk_query_sink *ss = lk_otlp_span_sink(o2);
        struct lk_conn c = {.cookie = 0x1234};
        struct lk_session sess = {0};
        struct lk_query_obs qo = {
            .ts_start_ns = 1000,
            .ts_complete_ns = 1000 + 5000000, /* 5 ms, measurable -> eligible */
            .text = "select 1",
            .text_len = 8,
            .rows = 1,
            .kind = LK_Q_SIMPLE,
        };
        char *traces = NULL;
        size_t tlen;

        EXPECT(ss != NULL, "span sink exposed");
        snprintf(sess.database, sizeof(sess.database), "%s", "appdb");
        if (ss)
            ss->on_query(ss->ctx, &c, &sess, &qo);

        /* First request the tick sends is metrics; then traces follows it. */
        for (int i = 0; i < 2 && !traces; i++) {
            char *req =
                serve_one(loop2, lfd, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", &tlen);

            EXPECT(req != NULL, "export request received");
            if (req && !strncmp(req, "POST /v1/traces", 15))
                traces = req;
            else
                free(req);
        }
        EXPECT(traces != NULL, "a POST /v1/traces was sent");
        if (traces) {
            char *body = strstr(traces, "\r\n\r\n");

            /* Body's first byte is ExportTraceServiceRequest.resource_spans
             * (field 1, wire 2 = 0x0a); the span carries db.system.name. */
            EXPECT(body && (unsigned char)body[4] == 0x0a,
                   "traces body starts with resource_spans");
            EXPECT(strstr(traces, "postgresql") != NULL, "span carries db.system.name=postgresql");
            EXPECT(strstr(traces, "select 1") != NULL, "span carries db.query.text");
            free(traces);
        }
        EXPECT(dump_export_count(m2, "ok") >= 1, "an OTLP export succeeded with spans on");
    }
    /* Tear the spans exporter down with its own loop (order: exporter, then the
     * loop whose tick still references it). */
    lk_otlp_free(o2);
    lk_loop_free(loop2);
    lk_metrics_free(m2);

    lk_otlp_free(o);
    lk_metrics_free(m);
    lk_loop_free(loop);
    close(lfd);
    printf(failures ? "\n%d FAILURES\n" : "\nall otlp client tests passed\n", failures);
    return failures ? 1 : 0;
}
