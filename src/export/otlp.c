// SPDX-License-Identifier: GPL-2.0
/* See otlp.h. Three halves: the metric encoder (metric view -> OTLP protobuf via
 * pbuf), the span encoder (task 5.3), and the non-blocking HTTP client that
 * POSTs both signals — one request in flight, in the shared loop.
 *
 * OTLP field numbers are inlined as literals from the (stable) proto schema —
 * metrics.proto, trace.proto, common.proto, resource.proto. The subset we touch:
 *   ExportMetricsServiceRequest { resource_metrics = 1 }   (== MetricsData wire)
 *   ResourceMetrics { resource = 1, scope_metrics = 2 }
 *   ScopeMetrics { scope = 1, metrics = 2 }
 *   Metric { name=1, description=2, gauge=5, sum=7, exponential_histogram=10 }
 *   Sum { data_points=1, aggregation_temporality=2, is_monotonic=3 }
 *   Gauge { data_points=1 }
 *   ExponentialHistogram { data_points=1, aggregation_temporality=2 }
 *   NumberDataPoint { start=2(fixed64), time=3(fixed64), as_double=4, attrs=7 }
 *   ExponentialHistogramDataPoint { attrs=1, start=2, time=3, count=4, sum=5,
 *     scale=6(sint32), zero_count=7, positive=8, zero_threshold=14 }
 *   Buckets { offset=1(sint32), bucket_counts=2(packed uint64) }
 *   ExportTraceServiceRequest { resource_spans = 1 }       (== TracesData wire)
 *   ResourceSpans { resource=1, scope_spans=2 }
 *   ScopeSpans { scope=1, spans=2 }
 *   Span { trace_id=1(bytes), span_id=2(bytes), name=5, kind=6, start=7(fixed64),
 *     end=8(fixed64), attributes=9, status=15 }
 *   Status { message=2, code=3 }   (STATUS_CODE_ERROR = 2)
 *   KeyValue { key=1, value=2 }  AnyValue { string_value=1, int_value=3 } */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "otlp.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "hist.h"
#include "loop.h"
#include "metrics.h"
#include "pbuf.h"
#include "spans.h"
#include "timebase.h"
#include "version.h"

#define OTLP_DEFAULT_INTERVAL       15
#define OTLP_DEFAULT_PORT           "4318"
#define OTLP_TIMEOUT_SEC            5
#define OTLP_TEMPORALITY_CUMULATIVE 2
#define OTLP_MAX_RES_ATTRS          32

#define OTLP_SPAN_KIND_CLIENT 3 /* SpanKind.SPAN_KIND_CLIENT */
#define OTLP_STATUS_ERROR     2 /* StatusCode.STATUS_CODE_ERROR */

/* --- shared attribute helpers -------------------------------------------- */

/* KeyValue{key, value:AnyValue{string_value}} at the given field number
 * (attributes are field 7 in NumberDataPoint, 1 in the histogram DP, 9 in Span
 * and 1 in Resource/Scope). */
static void enc_str_kv(struct pbuf *pb, uint32_t field, const char *key, const char *val)
{
    size_t kv = pb_submsg_begin(pb, field);
    size_t any;

    pb_field_string(pb, 1, key);
    any = pb_submsg_begin(pb, 2);
    pb_field_string(pb, 1, val ? val : "");
    pb_submsg_end(pb, any);
    pb_submsg_end(pb, kv);
}

/* Same, but the value carries an explicit length (raw SQL may not be a tidy
 * C-string once truncated to the byte budget). */
static void enc_str_kv_n(struct pbuf *pb, uint32_t field, const char *key, const char *val,
                         size_t vlen)
{
    size_t kv = pb_submsg_begin(pb, field);
    size_t any;

    pb_field_string(pb, 1, key);
    any = pb_submsg_begin(pb, 2);
    pb_field_bytes(pb, 1, val, vlen); /* AnyValue.string_value (LEN wire) */
    pb_submsg_end(pb, any);
    pb_submsg_end(pb, kv);
}

/* KeyValue{key, value:AnyValue{int_value}} (db.response.returned_rows). */
static void enc_int_kv(struct pbuf *pb, uint32_t field, const char *key, uint64_t val)
{
    size_t kv = pb_submsg_begin(pb, field);
    size_t any;

    pb_field_string(pb, 1, key);
    any = pb_submsg_begin(pb, 2);
    pb_field_varint(pb, 3, val); /* AnyValue.int_value */
    pb_submsg_end(pb, any);
    pb_submsg_end(pb, kv);
}

/* --- metric encoder ------------------------------------------------------- */

static void enc_attrs(struct pbuf *pb, uint32_t field, const struct lk_metric_view *v)
{
    for (uint32_t i = 0; i < v->nlabels; i++)
        enc_str_kv(pb, field, v->labels[i].key, v->labels[i].value);
}

/* NumberDataPoint (Sum/Gauge). start_time is emitted only for cumulative sums —
 * a gauge sample has no meaningful stream start. */
static void enc_number_dp(struct pbuf *pb, const struct lk_metric_view *v,
                          const struct lk_timebase *tb, uint64_t now, bool with_start)
{
    size_t dp = pb_submsg_begin(pb, 1); /* data_points */

    if (with_start)
        pb_field_fixed64(pb, 2, lk_wall_ns(tb, v->created_ns)); /* start_time_unix_nano */
    pb_field_fixed64(pb, 3, now);                               /* time_unix_nano */
    pb_field_double(pb, 4, v->val);                             /* as_double */
    enc_attrs(pb, 7, v);
    pb_submsg_end(pb, dp);
}

/* ExponentialHistogramDataPoint from the Р24 grid, taken as-is (Р31):
 * positive.offset = LK_HIST_MIN_INDEX, bucket_counts = the flat array with the
 * overflow cell folded into the top bucket; underflow -> zero_count with
 * zero_threshold = bound(MIN). */
static void enc_exp_hist_dp(struct pbuf *pb, const struct lk_metric_view *v,
                            const struct lk_timebase *tb, uint64_t now)
{
    const struct lk_hist *h = v->hist;
    size_t dp = pb_submsg_begin(pb, 1); /* data_points */
    size_t buckets;

    pb_field_fixed64(pb, 2, lk_wall_ns(tb, v->created_ns)); /* start_time_unix_nano */
    pb_field_fixed64(pb, 3, now);                           /* time_unix_nano */
    pb_field_varint(pb, 4, h->count);                       /* count */
    pb_field_double(pb, 5, h->sum);                         /* sum */
    pb_field_sint32(pb, 6, LK_HIST_SCHEMA);                 /* scale = 2 */
    pb_field_varint(pb, 7, h->underflow);                   /* zero_count */

    buckets = pb_submsg_begin(pb, 8); /* positive Buckets */
    pb_field_sint32(pb, 1, LK_HIST_MIN_INDEX);
    {
        size_t counts = pb_submsg_begin(pb, 2); /* bucket_counts, packed */

        for (int i = 0; i < LK_HIST_NBUCKETS; i++) {
            uint64_t c = h->bucket[i];

            if (i == LK_HIST_NBUCKETS - 1)
                c += h->overflow; /* >= bound(MAX) folds into the top bucket */
            pb_varint(pb, c);
        }
        pb_submsg_end(pb, counts);
    }
    pb_submsg_end(pb, buckets);

    pb_field_double(pb, 14, lk_hist_bound(LK_HIST_MIN_INDEX)); /* zero_threshold */
    enc_attrs(pb, 1, v);
    pb_submsg_end(pb, dp);
}

void lk_otlp_encode_metric(struct pbuf *pb, const struct lk_metric_view *v,
                           const struct lk_timebase *tb, uint64_t now_wall_ns)
{
    size_t metric = pb_submsg_begin(pb, 2); /* ScopeMetrics.metrics */
    size_t data;

    pb_field_string(pb, 1, v->name);
    if (v->help)
        pb_field_string(pb, 2, v->help); /* description */

    switch (v->type) {
    case LK_MT_COUNTER:
        data = pb_submsg_begin(pb, 7); /* Sum */
        enc_number_dp(pb, v, tb, now_wall_ns, true);
        pb_field_varint(pb, 2, OTLP_TEMPORALITY_CUMULATIVE);
        pb_field_bool(pb, 3, true); /* is_monotonic */
        pb_submsg_end(pb, data);
        break;
    case LK_MT_GAUGE:
        data = pb_submsg_begin(pb, 5); /* Gauge */
        enc_number_dp(pb, v, tb, now_wall_ns, false);
        pb_submsg_end(pb, data);
        break;
    case LK_MT_HIST:
        data = pb_submsg_begin(pb, 10); /* ExponentialHistogram */
        enc_exp_hist_dp(pb, v, tb, now_wall_ns);
        pb_field_varint(pb, 2, OTLP_TEMPORALITY_CUMULATIVE);
        pb_submsg_end(pb, data);
        break;
    }
    pb_submsg_end(pb, metric);
}

/* --- span encoder (task 5.3, Р32) ----------------------------------------- */

/* One Span into an open ScopeSpans (field 2). Attributes follow OTel database
 * semconv; the raw SQL leaves the agent only here (or its masked form). */
static void enc_span(struct pbuf *pb, const struct lk_span *sp, const struct lk_timebase *tb)
{
    size_t span = pb_submsg_begin(pb, 2); /* ScopeSpans.spans */

    pb_field_bytes(pb, 1, sp->trace_id, sizeof(sp->trace_id));
    pb_field_bytes(pb, 2, sp->span_id, sizeof(sp->span_id));
    pb_field_string(pb, 5, sp->name);
    pb_field_varint(pb, 6, OTLP_SPAN_KIND_CLIENT);
    pb_field_fixed64(pb, 7, lk_wall_ns(tb, sp->start_ns));
    pb_field_fixed64(pb, 8, lk_wall_ns(tb, sp->end_ns));

    enc_str_kv(pb, 9, "db.system.name", "postgresql");
    if (sp->db[0])
        enc_str_kv(pb, 9, "db.namespace", sp->db);
    if (sp->user[0])
        enc_str_kv(pb, 9, "db.user", sp->user);
    if (sp->text)
        enc_str_kv_n(pb, 9, "db.query.text", sp->text, sp->text_len);
    if (sp->have_rows)
        enc_int_kv(pb, 9, "db.response.returned_rows", sp->rows);
    if (sp->error) {
        size_t st;

        if (sp->sqlstate[0])
            enc_str_kv(pb, 9, "db.response.status_code", sp->sqlstate);
        st = pb_submsg_begin(pb, 15); /* Status */
        pb_field_varint(pb, 3, OTLP_STATUS_ERROR);
        pb_submsg_end(pb, st);
    }
    pb_submsg_end(pb, span);
}

/* --- client --------------------------------------------------------------- */

enum otlp_state { OT_IDLE = 0, OT_CONNECT, OT_WRITE, OT_READ };
enum otlp_signal { OTLP_SIG_METRICS = 0, OTLP_SIG_TRACES = 1, OTLP_NSIGNALS = 2 };

struct res_attr {
    char key[64];
    char val[128];
};

struct lk_otlp {
    struct lk_loop *loop;
    struct lk_metrics *metrics;
    struct lk_spans *spans; /* NULL when spans are disabled */

    char host[256];
    char port[16];
    char base[256];      /* endpoint base path (no trailing slash), "" if none */
    char hostport[288];  /* Host header value */
    char *extra_headers; /* joined "Key: Value\r\n" ... , or NULL */
    unsigned interval;
    const char *version;

    struct res_attr res[OTLP_MAX_RES_ATTRS];
    int nres;

    struct lk_timebase tb;

    /* cached resolution (first getaddrinfo result) */
    struct sockaddr_storage sa;
    socklen_t salen;
    int family, socktype, protocol;
    bool resolved;

    /* in-flight state machine */
    int fd;
    enum otlp_state state;
    enum otlp_signal cur; /* which signal is in flight */
    bool pending_traces;  /* traces due, waiting for the client to free up */
    uint64_t deadline_ns;
    char *req;
    size_t req_len, req_off;
    int status_code; /* parsed from the response status line, 0 until seen */
    char resp[512];
    size_t resp_len;

    uint64_t skip_until_ns; /* Retry-After pause */

    uint64_t exports_ok[OTLP_NSIGNALS], exports_err[OTLP_NSIGNALS], ticks_skipped;
};

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Parse http://host[:port][/path] into host/port and a cleaned base path (v1
 * signal paths are appended per request). Only http:// in v1 (Р31). Returns 0,
 * or -1 with a message. */
static int parse_endpoint(const char *ep, char *host, size_t hostsz, char *port, size_t portsz,
                          char *base, size_t basesz)
{
    const char *p, *hs, *he, *pstart = NULL, *pend = NULL, *path = NULL;

    if (strncasecmp(ep, "http://", 7) == 0) {
        p = ep + 7;
    } else if (strncasecmp(ep, "https://", 8) == 0) {
        fprintf(stderr,
                "otlp: https endpoints are not supported in v1 (use http:// to a "
                "sidecar Collector); '%s'\n",
                ep);
        return -1;
    } else {
        fprintf(stderr, "otlp: endpoint must start with http:// ('%s')\n", ep);
        return -1;
    }

    hs = p;
    if (*p == '[') { /* [IPv6]:port */
        const char *rb = strchr(p, ']');

        if (!rb)
            return -1;
        hs = p + 1;
        he = rb;
        p = rb + 1;
    } else {
        he = p;
        while (*he && *he != ':' && *he != '/')
            he++;
    }
    if (he == hs || (size_t)(he - hs) >= hostsz)
        return -1;
    memcpy(host, hs, he - hs);
    host[he - hs] = '\0';

    p = he;
    if (*p == ':') {
        pstart = ++p;
        while (*p && *p != '/')
            p++;
        pend = p;
    }
    if (*p == '/')
        path = p;

    if (pstart && pend > pstart) {
        if ((size_t)(pend - pstart) >= portsz)
            return -1;
        memcpy(port, pstart, pend - pstart);
        port[pend - pstart] = '\0';
    } else {
        snprintf(port, portsz, "%s", OTLP_DEFAULT_PORT);
    }

    /* Base path minus any trailing slash; "" when the endpoint has no path. */
    base[0] = '\0';
    if (path) {
        size_t n = strlen(path);

        while (n > 1 && path[n - 1] == '/')
            n--;
        if (n == 1 && path[0] == '/')
            n = 0; /* bare "/" -> no base */
        if (n >= basesz)
            return -1;
        memcpy(base, path, n);
        base[n] = '\0';
    }
    return 0;
}

static int otlp_resolve(struct lk_otlp *o)
{
    struct addrinfo hints = {0}, *ai = NULL;
    int rc;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(o->host, o->port, &hints, &ai);
    if (rc || !ai) {
        fprintf(stderr, "otlp: cannot resolve %s:%s: %s\n", o->host, o->port,
                rc ? gai_strerror(rc) : "no address");
        return -1;
    }
    memcpy(&o->sa, ai->ai_addr, ai->ai_addrlen);
    o->salen = ai->ai_addrlen;
    o->family = ai->ai_family;
    o->socktype = ai->ai_socktype;
    o->protocol = ai->ai_protocol;
    o->resolved = true;
    freeaddrinfo(ai);
    return 0;
}

static void otlp_maybe_traces(struct lk_otlp *o);

/* Tear down the in-flight request and return to idle. reresolve forces a fresh
 * getaddrinfo on the next attempt (used after connect/timeout failures, Р31). */
static void otlp_finish(struct lk_otlp *o, bool reresolve)
{
    if (o->fd >= 0) {
        lk_loop_del_fd(o->loop, o->fd);
        close(o->fd);
        o->fd = -1;
    }
    free(o->req);
    o->req = NULL;
    o->req_len = o->req_off = 0;
    o->resp_len = 0;
    o->status_code = 0;
    o->state = OT_IDLE;
    if (reresolve)
        o->resolved = false;
}

/* Finish the current request, then pump a pending traces export if one is
 * waiting (metrics and traces share the single in-flight slot). */
static void otlp_after(struct lk_otlp *o, bool reresolve)
{
    otlp_finish(o, reresolve);
    otlp_maybe_traces(o);
}

struct enc_ctx {
    struct pbuf *pb;
    const struct lk_timebase *tb;
    uint64_t now_wall;
};

static void enc_metric_cb(void *ctx, const struct lk_metric_view *v)
{
    struct enc_ctx *e = ctx;

    lk_otlp_encode_metric(e->pb, v, e->tb, e->now_wall);
}

static void enc_span_cb(void *ctx, const struct lk_span *sp)
{
    struct enc_ctx *e = ctx;

    enc_span(e->pb, sp, e->tb);
}

static void otlp_enc_resource(struct lk_otlp *o, struct pbuf *pb)
{
    size_t res = pb_submsg_begin(pb, 1); /* Resource */

    for (int i = 0; i < o->nres; i++)
        enc_str_kv(pb, 1, o->res[i].key, o->res[i].val);
    pb_submsg_end(pb, res);
}

static void otlp_enc_scope(struct lk_otlp *o, struct pbuf *pb)
{
    size_t sc = pb_submsg_begin(pb, 1); /* InstrumentationScope */

    pb_field_string(pb, 1, "latkit");
    pb_field_string(pb, 2, o->version);
    pb_submsg_end(pb, sc);
}

static void otlp_build_metrics(struct lk_otlp *o, struct pbuf *pb, uint64_t now_wall)
{
    struct enc_ctx ec = {.pb = pb, .tb = &o->tb, .now_wall = now_wall};
    size_t rm, sm;

    rm = pb_submsg_begin(pb, 1); /* resource_metrics */
    otlp_enc_resource(o, pb);
    sm = pb_submsg_begin(pb, 2); /* scope_metrics */
    otlp_enc_scope(o, pb);
    lk_metrics_iter(o->metrics, enc_metric_cb, &ec);
    pb_submsg_end(pb, sm);
    pb_submsg_end(pb, rm);
}

static void otlp_build_traces(struct lk_otlp *o, struct pbuf *pb, uint64_t now_wall)
{
    struct enc_ctx ec = {.pb = pb, .tb = &o->tb, .now_wall = now_wall};
    size_t rs, ss;

    rs = pb_submsg_begin(pb, 1); /* resource_spans */
    otlp_enc_resource(o, pb);
    ss = pb_submsg_begin(pb, 2); /* scope_spans */
    otlp_enc_scope(o, pb);
    lk_spans_drain(o->spans, enc_span_cb, &ec); /* consumes the ring */
    pb_submsg_end(pb, ss);
    pb_submsg_end(pb, rs);
}

/* Assemble the HTTP request (headers + protobuf body) into a single buffer for
 * the given signal. */
static int otlp_build_request(struct lk_otlp *o, enum otlp_signal sig, uint64_t now_wall)
{
    struct pbuf pb;
    char target[288];
    char hdr[1024];
    int hn;

    snprintf(target, sizeof(target), "%s/v1/%s", o->base,
             sig == OTLP_SIG_TRACES ? "traces" : "metrics");

    pb_init(&pb);
    if (sig == OTLP_SIG_TRACES)
        otlp_build_traces(o, &pb, now_wall);
    else
        otlp_build_metrics(o, &pb, now_wall);
    if (pb.oom) {
        pb_free(&pb);
        return -1;
    }
    hn = snprintf(hdr, sizeof(hdr),
                  "POST %s HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "Content-Type: application/x-protobuf\r\n"
                  "Content-Length: %zu\r\n"
                  "%s"
                  "Connection: close\r\n"
                  "\r\n",
                  target, o->hostport, pb.len, o->extra_headers ? o->extra_headers : "");
    if (hn < 0 || hn >= (int)sizeof(hdr)) {
        pb_free(&pb);
        return -1;
    }
    o->req = malloc((size_t)hn + pb.len);
    if (!o->req) {
        pb_free(&pb);
        return -1;
    }
    memcpy(o->req, hdr, hn);
    memcpy(o->req + hn, pb.buf, pb.len);
    o->req_len = (size_t)hn + pb.len;
    o->req_off = 0;
    pb_free(&pb);
    return 0;
}

static int on_conn(void *ctx);

/* Start an export of `sig` (client must be idle). Attributes failures to sig. */
static void otlp_send(struct lk_otlp *o, enum otlp_signal sig)
{
    uint64_t mono = now_ns();
    uint64_t wall;
    int fd, rc;

    o->cur = sig;
    lk_timebase_sample(&o->tb);
    wall = lk_wall_ns(&o->tb, mono);

    if (otlp_build_request(o, sig, wall)) {
        o->exports_err[sig]++;
        return;
    }
    if (!o->resolved && otlp_resolve(o)) {
        o->exports_err[sig]++;
        free(o->req);
        o->req = NULL;
        return; /* stay idle; the next tick retries the resolve */
    }

    fd = socket(o->family, o->socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, o->protocol);
    if (fd < 0) {
        o->exports_err[sig]++;
        free(o->req);
        o->req = NULL;
        return;
    }
    rc = connect(fd, (struct sockaddr *)&o->sa, o->salen);
    if (rc == 0) {
        o->state = OT_WRITE;
    } else if (errno == EINPROGRESS) {
        o->state = OT_CONNECT;
    } else {
        close(fd);
        o->exports_err[sig]++;
        o->resolved = false; /* connection setup failed: re-resolve next time */
        free(o->req);
        o->req = NULL;
        return;
    }
    o->fd = fd;
    o->deadline_ns = mono + (uint64_t)OTLP_TIMEOUT_SEC * 1000000000ULL;
    if (lk_loop_add_fd(o->loop, fd, on_conn, o) ||
        lk_loop_mod_fd(o->loop, fd, o->state == OT_READ, o->state != OT_READ)) {
        o->exports_err[sig]++;
        otlp_finish(o, true);
        return;
    }
    if (o->state == OT_WRITE)
        on_conn(o); /* already connected: try to write now */
}

/* Send a queued traces batch if the client is free (Р32: flush by tick or 3/4).
 * Only starts traces — metrics is driven solely by the interval tick. */
static void otlp_maybe_traces(struct lk_otlp *o)
{
    if (o->state != OT_IDLE || !o->pending_traces || !o->spans)
        return;
    o->pending_traces = false;
    if (lk_spans_queued(o->spans) == 0)
        return; /* nothing to send after all */
    otlp_send(o, OTLP_SIG_TRACES);
}

/* Parse "HTTP/1.1 NNN ..." -> NNN; 0 if the line is not yet complete/parseable. */
static int parse_status(const char *buf, size_t len)
{
    const char *sp;

    if (len < 12 || strncmp(buf, "HTTP/1.", 7) != 0)
        return 0;
    sp = memchr(buf, ' ', len);
    if (!sp || sp + 3 >= buf + len)
        return 0;
    return (sp[1] - '0') * 100 + (sp[2] - '0') * 10 + (sp[3] - '0');
}

/* Retry-After (seconds form only) scanned from the accumulated response head. */
static unsigned parse_retry_after(const char *buf, size_t len)
{
    for (size_t i = 0; i + 12 <= len; i++)
        if (!strncasecmp(buf + i, "retry-after:", 12)) {
            const char *v = buf + i + 12;
            const char *e = buf + len;
            unsigned secs = 0;
            bool any = false;

            while (v < e && (*v == ' ' || *v == '\t'))
                v++;
            while (v < e && *v >= '0' && *v <= '9') {
                secs = secs * 10 + (unsigned)(*v++ - '0');
                any = true;
            }
            return any ? secs : 0;
        }
    return 0;
}

static void otlp_on_response_done(struct lk_otlp *o)
{
    int code = o->status_code;

    if (code >= 200 && code < 300) {
        o->exports_ok[o->cur]++;
    } else {
        o->exports_err[o->cur]++;
        if (code == 429 || code == 503) {
            unsigned secs = parse_retry_after(o->resp, o->resp_len);

            if (!secs)
                secs = OTLP_TIMEOUT_SEC;
            o->skip_until_ns = now_ns() + (uint64_t)secs * 1000000000ULL;
        }
    }
    otlp_after(o, false); /* an HTTP reply means DNS is fine: keep the cache */
}

static int on_conn(void *ctx)
{
    struct lk_otlp *o = ctx;

    if (o->state == OT_CONNECT) {
        int err = 0;
        socklen_t l = sizeof(err);

        if (getsockopt(o->fd, SOL_SOCKET, SO_ERROR, &err, &l) || err) {
            o->exports_err[o->cur]++;
            otlp_after(o, true);
            return 0;
        }
        o->state = OT_WRITE;
        if (lk_loop_mod_fd(o->loop, o->fd, false, true)) {
            o->exports_err[o->cur]++;
            otlp_after(o, true);
            return 0;
        }
    }

    if (o->state == OT_WRITE) {
        while (o->req_off < o->req_len) {
            ssize_t n = send(o->fd, o->req + o->req_off, o->req_len - o->req_off, MSG_NOSIGNAL);

            if (n > 0) {
                o->req_off += (size_t)n;
            } else if (n < 0 && errno == EINTR) {
                continue;
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return 0; /* wait for the next EPOLLOUT */
            } else {
                o->exports_err[o->cur]++;
                otlp_after(o, true);
                return 0;
            }
        }
        o->state = OT_READ;
        if (lk_loop_mod_fd(o->loop, o->fd, true, false)) {
            o->exports_err[o->cur]++;
            otlp_after(o, true);
            return 0;
        }
    }

    if (o->state == OT_READ) {
        for (;;) {
            ssize_t n;

            if (o->resp_len >= sizeof(o->resp)) {
                otlp_on_response_done(o); /* head is enough; ignore the rest */
                return 0;
            }
            n = recv(o->fd, o->resp + o->resp_len, sizeof(o->resp) - o->resp_len, 0);
            if (n > 0) {
                o->resp_len += (size_t)n;
                if (!o->status_code)
                    o->status_code = parse_status(o->resp, o->resp_len);
            } else if (n == 0) {
                otlp_on_response_done(o); /* server closed (Connection: close) */
                return 0;
            } else if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            } else {
                o->exports_err[o->cur]++;
                otlp_after(o, true);
                return 0;
            }
        }
    }
    return 0;
}

static void on_tick(void *ctx)
{
    struct lk_otlp *o = ctx;
    uint64_t now = now_ns();

    if (now < o->skip_until_ns)
        return; /* honouring a Retry-After pause */

    /* Spans flush on the tick too; a full-enough ring may already have set this
     * via the watermark. */
    if (o->spans && lk_spans_queued(o->spans) > 0)
        o->pending_traces = true;

    if (o->state != OT_IDLE) {
        o->ticks_skipped++; /* metrics export still in flight (Р31): skip this tick */
        return;             /* pending_traces (if set) is sent when the client frees */
    }
    otlp_send(o, OTLP_SIG_METRICS); /* the tick owns metrics; traces follow it */
}

static void otlp_on_watermark(void *ctx)
{
    struct lk_otlp *o = ctx;

    o->pending_traces = true;
    otlp_maybe_traces(o);
}

static void on_sweep(void *ctx)
{
    struct lk_otlp *o = ctx;

    if (o->state != OT_IDLE && now_ns() >= o->deadline_ns) {
        o->exports_err[o->cur]++;
        otlp_after(o, true); /* stuck export: drop and re-resolve */
    }
}

static void otlp_provide(void *ctx, struct lk_metrics *m)
{
    struct lk_otlp *o = ctx;
    const char *help = "OTLP export attempts by signal and result.";

    lk_metrics_set_counter_l2(m, "latkit_otlp_exports_total", help, "signal", "metrics", "result",
                              "ok", (double)o->exports_ok[OTLP_SIG_METRICS]);
    lk_metrics_set_counter_l2(m, "latkit_otlp_exports_total", help, "signal", "metrics", "result",
                              "error", (double)o->exports_err[OTLP_SIG_METRICS]);
    if (o->spans) {
        lk_metrics_set_counter_l2(m, "latkit_otlp_exports_total", help, "signal", "traces",
                                  "result", "ok", (double)o->exports_ok[OTLP_SIG_TRACES]);
        lk_metrics_set_counter_l2(m, "latkit_otlp_exports_total", help, "signal", "traces",
                                  "result", "error", (double)o->exports_err[OTLP_SIG_TRACES]);
        lk_metrics_set_counter(m, "latkit_spans_sampled_total", "Queries sampled into spans (Р32).",
                               (double)lk_spans_sampled_total(o->spans));
        lk_metrics_set_counter(m, "latkit_spans_dropped_total",
                               "Sampled spans dropped because the ring was full.",
                               (double)lk_spans_dropped_total(o->spans));
    }
    lk_metrics_set_counter(m, "latkit_otlp_export_ticks_skipped_total",
                           "Export ticks skipped because the previous export was still in flight.",
                           (double)o->ticks_skipped);
}

/* --- resource attributes -------------------------------------------------- */

static void res_add(struct lk_otlp *o, const char *key, const char *val)
{
    if (o->nres >= OTLP_MAX_RES_ATTRS)
        return;
    snprintf(o->res[o->nres].key, sizeof(o->res[0].key), "%s", key);
    snprintf(o->res[o->nres].val, sizeof(o->res[0].val), "%s", val);
    o->nres++;
}

/* Split "key=value" and add it; a malformed pair (no '=') is skipped. */
static void res_add_pair(struct lk_otlp *o, const char *kv)
{
    const char *eq = strchr(kv, '=');
    char key[64];
    size_t kn;

    if (!eq || eq == kv)
        return;
    kn = (size_t)(eq - kv);
    if (kn >= sizeof(key))
        kn = sizeof(key) - 1;
    memcpy(key, kv, kn);
    key[kn] = '\0';
    res_add(o, key, eq + 1);
}

/* Join the custom header list into one "Key: Value\r\n"... block. Each entry is
 * already "Key: Value" (or "Key=Value", normalised to a colon). NULL if none. */
static char *join_headers(const char *const *headers, int n)
{
    size_t total = 0;
    char *buf, *p;

    if (n <= 0)
        return NULL;
    for (int i = 0; i < n; i++)
        total += strlen(headers[i]) + 2; /* + CRLF */
    buf = malloc(total + 1);
    if (!buf)
        return NULL;
    p = buf;
    for (int i = 0; i < n; i++) {
        const char *h = headers[i];
        const char *eq = strchr(h, ':') ? NULL : strchr(h, '=');
        size_t hn = strlen(h);

        if (eq) { /* "Key=Value" -> "Key: Value" */
            size_t kn = (size_t)(eq - h);

            memcpy(p, h, kn);
            p += kn;
            *p++ = ':';
            *p++ = ' ';
            memcpy(p, eq + 1, strlen(eq + 1));
            p += strlen(eq + 1);
        } else {
            memcpy(p, h, hn);
            p += hn;
        }
        *p++ = '\r';
        *p++ = '\n';
    }
    *p = '\0';
    return buf;
}

/* --- lifecycle ------------------------------------------------------------ */

/* Build the span collector if either predicate is configured (Р32). */
static struct lk_spans *otlp_make_spans(struct lk_otlp *o, const struct lk_otlp_cfg *cfg)
{
    struct lk_spans_cfg sc;

    if (cfg->span_sample_ratio <= 0.0 && cfg->span_slow_ms == 0)
        return NULL;
    memset(&sc, 0, sizeof(sc));
    sc.sample_ratio = cfg->span_sample_ratio;
    sc.slow_ns = (uint64_t)cfg->span_slow_ms * 1000000ULL;
    sc.text_max = cfg->span_text_max;
    sc.masked = cfg->span_masked;
    sc.seed = cfg->span_seed;
    sc.on_watermark = otlp_on_watermark;
    sc.watermark_ctx = o;
    return lk_spans_new(&sc);
}

struct lk_otlp *lk_otlp_new(struct lk_loop *loop, struct lk_metrics *m,
                            const struct lk_otlp_cfg *cfg)
{
    struct lk_otlp *o;
    char hostname[128];

    if (!cfg->endpoint || !cfg->endpoint[0]) {
        fprintf(stderr, "otlp: empty endpoint\n");
        return NULL;
    }
    o = calloc(1, sizeof(*o));
    if (!o)
        return NULL;
    o->loop = loop;
    o->metrics = m;
    o->fd = -1;
    o->state = OT_IDLE;
    o->interval = cfg->interval_sec ? cfg->interval_sec : OTLP_DEFAULT_INTERVAL;
    o->version = cfg->service_version ? cfg->service_version : LK_VERSION;

    if (parse_endpoint(cfg->endpoint, o->host, sizeof(o->host), o->port, sizeof(o->port), o->base,
                       sizeof(o->base))) {
        free(o);
        return NULL;
    }
    snprintf(o->hostport, sizeof(o->hostport), "%s:%s", o->host, o->port);

    /* Resource attributes: our defaults first, then the user's (which may
     * override by appearing later — dedup is the consumer's job). */
    res_add(o, "service.name",
            cfg->service_name && cfg->service_name[0] ? cfg->service_name : "latkit");
    res_add(o, "service.version", o->version);
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        hostname[sizeof(hostname) - 1] = '\0';
        res_add(o, "host.name", hostname);
    }
    for (int i = 0; i < cfg->nresource; i++)
        res_add_pair(o, cfg->resource_attrs[i]);

    o->extra_headers = join_headers(cfg->headers, cfg->nheaders);
    o->spans = otlp_make_spans(o, cfg);

    /* Resolve once up front, but tolerate a not-yet-up Collector: a failure
     * here just leaves resolved=false and the first tick retries (Р31). */
    otlp_resolve(o);

    if (lk_loop_every(loop, o->interval, on_tick, o) || lk_loop_every(loop, 1, on_sweep, o)) {
        lk_spans_free(o->spans);
        free(o->extra_headers);
        free(o);
        return NULL;
    }
    lk_metrics_add_provider(m, otlp_provide, o);
    return o;
}

const struct lk_query_sink *lk_otlp_span_sink(struct lk_otlp *o)
{
    return o->spans ? lk_spans_sink(o->spans) : NULL;
}

void lk_otlp_free(struct lk_otlp *o)
{
    if (!o)
        return;
    otlp_finish(o, false);
    lk_spans_free(o->spans);
    free(o->extra_headers);
    free(o);
}
