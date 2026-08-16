/* SPDX-License-Identifier: GPL-2.0 */
/* Span collector (Р32, STAGE5.md task 5.3): a third lk_query_sink alongside the
 * aggregator and the --queries logger. Where metrics keep only the normalised
 * fingerprint (Р28), a span carries what metrics cannot — the exact per-query
 * timings and the *raw* SQL of one sampled execution — so the two link up in
 * Grafana (metrics for the whole, a span for the specimen).
 *
 * Sampling is decided in on_query by two independent predicates (Р32): a
 * probabilistic ratio ("a representative slice") and a duration threshold ("all
 * the slow ones"); a query is sampled if either fires. The ratio draw is a pure
 * hash of (ts, cookie, seed) — no rand(3) on the hot path and deterministic
 * under a fixed seed for tests; the production seed comes from getrandom(2) so a
 * client cannot game which of its queries are sampled. Sampled queries are
 * copied (raw SQL bounded by text_max, since lk_query_obs.text dangles after the
 * callback, Р16) into a bounded FIFO ring; a full ring drops the newest and
 * bumps latkit_spans_dropped_total. The OTLP traces encoder drains the ring
 * (drop-and-count on a failed push — spans, unlike cumulative metrics, are a
 * best-effort signal).
 *
 * Pure like the rest of src/export: no libbpf, no sockets. The only I/O is the
 * one-shot getrandom for the id seed; timings stay CLOCK_MONOTONIC and convert
 * to wall clock at export through the timebase (Р33). */
#ifndef LATKIT_SPANS_H
#define LATKIT_SPANS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct lk_query_sink;

/* Ring depth (Р32) and the default per-span raw-text cap (--otlp-span-text-max). */
#define LK_SPAN_BUF          2048
#define LK_SPAN_TEXT_MAX_DEF 4096
#define LK_SPAN_NAME_MAX     64 /* span name = normalised text, truncated (Р32) */

/* Bounds on the HTTP half (РH11, PLAN-HTTP.md М6). Each is what an *attribute*
 * may usefully be, not what HTTP permits — a route longer than this is not a
 * route, and a client address is an address. tracestate is the exception: it is
 * carried whole or not at all, because a clipped list is malformed rather than
 * merely short, so its bound matches the handler's (LK_HTTP_TSTATE_MAX). */
#define LK_SPAN_ROUTE_MAX  128
#define LK_SPAN_METHOD_MAX 16
#define LK_SPAN_REQID_MAX  48
#define LK_SPAN_CTYPE_MAX  32
#define LK_SPAN_ADDR_MAX   46 /* INET6_ADDRSTRLEN */
#define LK_SPAN_TSTATE_MAX 256

struct lk_spans_cfg {
    double sample_ratio;             /* (0,1]; <= 0 disables the probabilistic predicate */
    uint64_t slow_ns;                /* > 0: also sample any query with duration >= slow_ns */
    uint32_t text_max;               /* cap on stored db.query.text bytes; 0 -> default */
    bool masked;                     /* store the normalised text as db.query.text (no literals) */
    uint64_t seed;                   /* sampling + id PRNG seed; 0 -> getrandom(2) */
    void (*on_watermark)(void *ctx); /* fired once when the ring crosses 3/4 full */
    void *watermark_ctx;
};

/* The HTTP half of a span (РH11, PLAN-HTTP.md М6), hung off lk_span by pointer
 * and NULL for the database protocols — which is what keeps a PG span exactly
 * the size and shape it was. It lives in an arena beside the text one, for the
 * same reason: 2048 slots of it is a megabyte of address space and only the
 * pages a real HTTP span writes ever become resident.
 *
 * Everything here is a copy: the observation's pointers dangle the moment the
 * callback returns (Р16), and a span sits in the ring until the next export. */
struct lk_span_http {
    char route[LK_SPAN_ROUTE_MAX];   /* http.route — the template, never the path */
    char method[LK_SPAN_METHOD_MAX]; /* http.request.method */
    char host[64];                   /* server.address (the request's own Host) */
    char req_id[LK_SPAN_REQID_MAX];  /* X-Request-Id: the accuracy bench's join key */
    char ctype[LK_SPAN_CTYPE_MAX];   /* response Content-Type, first token */
    char obj_version[48];            /* the version of the object touched, when the
                                        dialect has one (S3: `x-amz-version-id`,
                                        PLAN-MINIO.md РS4); "" otherwise */
    char client[LK_SPAN_ADDR_MAX];   /* client.address, from the connection tuple */
    char ua[64];                     /* user_agent.original (session app slot) */
    char tstate[LK_SPAN_TSTATE_MAX]; /* W3C tracestate, verbatim or absent */
    uint64_t bytes_in, bytes_out;    /* http.request/response.body.size */
    uint64_t req_done_ns;            /* РH5's inner points, as span attributes: the */
    uint64_t first_byte_ns;          /* ... upload end and the TTFB instant */
    uint16_t status;                 /* http.response.status_code */
    uint16_t client_port, server_port;
    uint8_t version;   /* HTTP/1.<version> */
    bool tls;          /* url.scheme: https when the bytes came through the TLS path */
    bool client_error; /* 4xx: not an error of the server's, and not a span error */
};

/* One collected span, drained by the OTLP traces encoder. Timings are still
 * CLOCK_MONOTONIC — the encoder converts them to Unix-epoch ns via the timebase
 * at export (Р33). text is a bounded copy of the raw (or, when masked, the
 * normalised) SQL — for an HTTP span, of the request target, already redacted by
 * the handler (РH12) — pointing into the collector's text arena (not owned by
 * the span, not freed per-drain); NULL on a NO_TEXT observation. */
struct lk_span {
    uint8_t trace_id[16];
    uint8_t span_id[8];
    uint8_t parent_id[8];      /* the caller's span id, from `traceparent` (РH11) */
    uint64_t start_ns, end_ns; /* mono (bpf_ktime_get_ns domain) */
    uint64_t rows;
    char name[LK_SPAN_NAME_MAX]; /* normalised text prefix / `METHOD /route` */
    char db[64], user[64];       /* db.namespace, db.user */
    const char *db_system;       /* OTel db.system.name; borrowed static string
                                    from lk_proto_ops.db_system (М6) */
    char *text;                  /* db.query.text / url.path bytes; NULL if none */
    uint32_t text_len;
    struct lk_span_http *http; /* the HTTP half; NULL for a database span */
    char sqlstate[6];          /* on error, C-string */
    uint16_t err_code;         /* vendor error code (MySQL errno); 0 = none (М6) */
    uint8_t kind;              /* enum lk_query_kind */
    uint8_t otel_kind;         /* enum lk_otel_kind: which semconv this span speaks */
    bool error;
    bool have_rows;
    bool have_parent; /* the request arrived inside somebody else's trace */
};

/* cfg is copied; NULL is not allowed (the exporter only builds this when spans
 * are enabled). Returns NULL on allocation failure. */
struct lk_spans *lk_spans_new(const struct lk_spans_cfg *cfg);
void lk_spans_free(struct lk_spans *s);

/* The tee sink handed to the parser (only on_query is populated). Borrowed —
 * valid for the collector's lifetime. */
const struct lk_query_sink *lk_spans_sink(struct lk_spans *s);

/* Pop every queued span in FIFO order into emit(), then clear the ring (each
 * span's text is freed after emit returns, so emit must copy what it needs). */
void lk_spans_drain(struct lk_spans *s, void (*emit)(void *ctx, const struct lk_span *sp),
                    void *ctx);

uint64_t lk_spans_sampled_total(const struct lk_spans *s);
uint64_t lk_spans_dropped_total(const struct lk_spans *s);
unsigned lk_spans_queued(const struct lk_spans *s);

#endif /* LATKIT_SPANS_H */
