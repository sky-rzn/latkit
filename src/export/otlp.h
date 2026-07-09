/* SPDX-License-Identifier: GPL-2.0 */
/* OTLP/HTTP push path (Р31, STAGE5.md task 5.2): maps the metrics registry to
 * the OTLP data model and POSTs it to an OpenTelemetry Collector, both by hand —
 * the protobuf writer (pbuf.h) and this encoder, no opentelemetry-cpp.
 *
 * Mapping (Р31): counters -> Sum{monotonic, cumulative}, gauges -> Gauge,
 * histograms -> ExponentialHistogram{scale=2} taking the Р24 grid as-is
 * (offset -53, underflow -> zero_count, overflow -> top bucket). Temporality is
 * cumulative; a data point's start_time_unix_nano is its series' created_ns
 * (Р31) so an evicted-and-returned fingerprint (Р23) begins a fresh stream — a
 * legal reset, never a shrinking cumulative. Timestamps go out in wall-clock ns
 * via the timebase (Р33).
 *
 * Delivery: POST <endpoint>/v1/metrics, application/x-protobuf, every
 * interval_sec. No queue, no retries — cumulative temporality makes a dropped
 * batch harmless (the next push carries the full state); a miss just bumps
 * latkit_otlp_exports_total{result="error"}. The client is a non-blocking state
 * machine in the shared loop with one export in flight; DNS is resolved once and
 * cached, re-resolved on connection errors. */
#ifndef LATKIT_OTLP_H
#define LATKIT_OTLP_H

#include <stdbool.h>
#include <stdint.h>

struct lk_loop;
struct lk_metrics;
struct lk_otlp;
struct pbuf;
struct lk_metric_view;
struct lk_timebase;
struct lk_query_sink;

struct lk_otlp_cfg {
    const char *endpoint;              /* http://host:port[/path]; enables the exporter */
    unsigned interval_sec;             /* export period; 0 -> default (15 s) */
    const char *const *headers;        /* extra request headers, each "Key: Value" */
    int nheaders;                      /* (e.g. auth for managed backends) */
    const char *const *resource_attrs; /* resource attributes, each "key=value" */
    int nresource;
    const char *service_name;    /* service.name (OTEL_SERVICE_NAME); NULL -> "latkit" */
    const char *service_version; /* service.version / scope version; NULL -> LK_VERSION */

    /* Spans (Р32, task 5.3): enabled when either predicate is set. The exporter
     * owns the span collector and POSTs traces to /v1/traces with the same
     * client, flushed on the export tick and when the ring crosses 3/4 full. */
    double span_sample_ratio; /* --otlp-spans RATIO; (0,1], 0 disables */
    unsigned span_slow_ms;    /* --otlp-spans-slow-ms; 0 disables the slow predicate */
    unsigned span_text_max;   /* --otlp-span-text-max bytes; 0 -> default (4 KiB) */
    bool span_masked;         /* --otlp-span-masked: db.query.text is normalised */
    uint64_t span_seed;       /* sampling/id seed; 0 -> random (getrandom) */
};

/* Creates the exporter, resolves the endpoint, registers the export tick and the
 * self-metric provider on m. Returns NULL on a bad endpoint or allocation
 * failure (the caller decides whether that is fatal). */
struct lk_otlp *lk_otlp_new(struct lk_loop *loop, struct lk_metrics *m,
                            const struct lk_otlp_cfg *cfg);
void lk_otlp_free(struct lk_otlp *o);

/* The span-collector tee sink for the parser, or NULL if spans are disabled.
 * Borrowed — valid for the exporter's lifetime (Р32). */
const struct lk_query_sink *lk_otlp_span_sink(struct lk_otlp *o);

/* --- encoder seam (exposed for unit tests) --------------------------------
 * Encode one metric view as an OTLP ScopeMetrics.metrics (field 2) Metric into
 * an open pbuf. The exporter calls this from the registry iterator; test_otlp_enc
 * drives it directly with hand-built views and a fixed timebase for deterministic
 * bytes. now_wall_ns is the export instant (Unix-epoch ns); the view's created_ns
 * is converted to the data point's start_time through tb. */
void lk_otlp_encode_metric(struct pbuf *pb, const struct lk_metric_view *v,
                           const struct lk_timebase *tb, uint64_t now_wall_ns);

#endif /* LATKIT_OTLP_H */
