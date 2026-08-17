// SPDX-License-Identifier: GPL-2.0
/* OTLP metric encoder tests (task 5.2). Rather than a brittle golden blob, this
 * decodes the writer's own output with a tiny protobuf reader and asserts the
 * OTLP structure and values: Sum/Gauge/ExponentialHistogram shape, cumulative
 * temporality, is_monotonic, the timestamps (via a fixed offset-0 timebase so
 * wall == mono == created_ns), and the Р24-grid mapping (scale=2, offset=-53,
 * underflow->zero_count, overflow->top bucket). The Collector in the e2e stand
 * (task 5.4) is the strict schema validator; this pins the mapping logic. */
#include "hist.h"
#include "metrics.h"
#include "otlp.h"
#include "pbuf.h"
#include "proto.h" /* enum lk_otel_kind (РH11) */
#include "spans.h"
#include "timebase.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define EXPECT(cond, msg)                                                                          \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: %s\n", msg);                                                             \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

/* --- minimal protobuf reader --------------------------------------------- */

struct rd {
    const uint8_t *p, *end;
};

struct field {
    uint32_t num, wire;
    uint64_t varint;     /* wire 0 */
    uint64_t i64;        /* wire 1 */
    const uint8_t *data; /* wire 2 */
    size_t len;
};

static uint64_t rd_varint(struct rd *r)
{
    uint64_t v = 0;
    int shift = 0;

    while (r->p < r->end && shift < 64) {
        uint8_t b = *r->p++;

        v |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80))
            break;
        shift += 7;
    }
    return v;
}

static bool next_field(struct rd *r, struct field *f)
{
    uint64_t tag;

    if (r->p >= r->end)
        return false;
    tag = rd_varint(r);
    f->num = (uint32_t)(tag >> 3);
    f->wire = (uint32_t)(tag & 7);
    f->data = NULL;
    f->len = 0;
    switch (f->wire) {
    case 0:
        f->varint = rd_varint(r);
        break;
    case 1:
        memcpy(&f->i64, r->p, 8);
        r->p += 8;
        break;
    case 2: {
        uint64_t l = rd_varint(r);

        f->data = r->p;
        f->len = l;
        r->p += l;
        break;
    }
    case 5:
        r->p += 4;
        break;
    }
    return true;
}

/* First field with the given number; returns false if absent. */
static bool find(const uint8_t *buf, size_t len, uint32_t num, struct field *out)
{
    struct rd r = {buf, buf + len};
    struct field f;

    while (next_field(&r, &f))
        if (f.num == num) {
            *out = f;
            return true;
        }
    return false;
}

static double as_double(uint64_t bits)
{
    double d;

    memcpy(&d, &bits, sizeof(d));
    return d;
}

static int32_t unzig(uint64_t v)
{
    return (int32_t)((v >> 1) ^ (~(v & 1) + 1));
}

/* --- tests --------------------------------------------------------------- */

#define CREATED 111111ULL
#define NOW     222222ULL

static void encode_one(struct pbuf *pb, const struct lk_metric_view *v)
{
    struct lk_timebase tb = {.offset_ns = 0}; /* wall == mono */

    pb_init(pb);
    lk_otlp_encode_metric(pb, v, &tb, NOW);
    EXPECT(!pb->oom, "encode did not OOM");
}

static void test_counter(void)
{
    struct lk_label labels[2] = {{"db", "app"}, {"user", "bob"}};
    struct lk_metric_view v = {
        .name = "latkit_thing_total",
        .type = LK_MT_COUNTER,
        .labels = labels,
        .nlabels = 2,
        .created_ns = CREATED,
        .val = 5.0,
    };
    struct pbuf pb;
    struct field metric, sum, dp, name, temp, mono, start, time, val;

    encode_one(&pb, &v);

    /* Top level: one ScopeMetrics.metrics (field 2) = Metric. */
    EXPECT(find(pb.buf, pb.len, 2, &metric), "counter: metric field present");
    EXPECT(find(metric.data, metric.len, 1, &name) && name.len == strlen(v.name) &&
               !memcmp(name.data, v.name, name.len),
           "counter: name matches");
    EXPECT(find(metric.data, metric.len, 7, &sum), "counter: Sum (field 7) present");

    EXPECT(find(sum.data, sum.len, 2, &temp) && temp.varint == 2,
           "counter: temporality CUMULATIVE");
    EXPECT(find(sum.data, sum.len, 3, &mono) && mono.varint == 1, "counter: is_monotonic true");
    EXPECT(find(sum.data, sum.len, 1, &dp), "counter: data point present");

    EXPECT(find(dp.data, dp.len, 2, &start) && start.i64 == CREATED, "counter: start_time=created");
    EXPECT(find(dp.data, dp.len, 3, &time) && time.i64 == NOW, "counter: time=now");
    EXPECT(find(dp.data, dp.len, 4, &val) && as_double(val.i64) == 5.0, "counter: as_double=5");

    /* Two attributes (field 7), each KeyValue{key, value{string}}. */
    {
        struct rd r = {dp.data, dp.data + dp.len};
        struct field f, key, av, sv;
        int nattr = 0;
        bool db_ok = false;

        while (next_field(&r, &f))
            if (f.num == 7) {
                nattr++;
                if (find(f.data, f.len, 1, &key) && key.len == 2 && !memcmp(key.data, "db", 2) &&
                    find(f.data, f.len, 2, &av) && find(av.data, av.len, 1, &sv) && sv.len == 3 &&
                    !memcmp(sv.data, "app", 3))
                    db_ok = true;
            }
        EXPECT(nattr == 2, "counter: two attributes");
        EXPECT(db_ok, "counter: db=app attribute decoded");
    }
    pb_free(&pb);
}

static void test_gauge(void)
{
    struct lk_metric_view v = {
        .name = "latkit_gauge",
        .type = LK_MT_GAUGE,
        .created_ns = CREATED,
        .val = 42.5,
    };
    struct pbuf pb;
    struct field metric, gauge, dp, start, time, val;

    encode_one(&pb, &v);
    EXPECT(find(pb.buf, pb.len, 2, &metric), "gauge: metric present");
    EXPECT(find(metric.data, metric.len, 5, &gauge), "gauge: Gauge (field 5) present");
    EXPECT(!find(metric.data, metric.len, 7, &(struct field){0}), "gauge: no Sum");
    EXPECT(find(gauge.data, gauge.len, 1, &dp), "gauge: data point present");
    EXPECT(!find(dp.data, dp.len, 2, &start), "gauge: no start_time");
    EXPECT(find(dp.data, dp.len, 3, &time) && time.i64 == NOW, "gauge: time=now");
    EXPECT(find(dp.data, dp.len, 4, &val) && as_double(val.i64) == 42.5, "gauge: as_double=42.5");
    pb_free(&pb);
}

static void test_hist(void)
{
    struct lk_hist h = {0};
    struct lk_metric_view v = {
        .name = "latkit_dur_seconds",
        .type = LK_MT_HIST,
        .created_ns = CREATED,
    };
    struct pbuf pb;
    struct field metric, eh, dp, temp, cnt, sum, scale, zc, zt, buckets, off, counts;

    lk_hist_observe(&h, 1.0);   /* grid index 0 -> OTLP bucket_counts[53] */
    lk_hist_observe(&h, 1e-9);  /* < bound(MIN) -> zero_count */
    lk_hist_observe(&h, 100.0); /* >= bound(MAX) -> overflow -> top bucket */
    v.hist = &h;

    encode_one(&pb, &v);
    EXPECT(find(pb.buf, pb.len, 2, &metric), "hist: metric present");
    EXPECT(find(metric.data, metric.len, 10, &eh), "hist: ExponentialHistogram (field 10) present");
    EXPECT(find(eh.data, eh.len, 2, &temp) && temp.varint == 2, "hist: temporality CUMULATIVE");
    EXPECT(find(eh.data, eh.len, 1, &dp), "hist: data point present");

    /* count (field 4) and zero_count (field 7) are OTLP `fixed64`, i.e. wire
     * type 1 — NOT varint. Encoding them as varint parses fine here but the
     * live Collector rejects it ("wrong wireType = 0 for field Count"), so the
     * wire type is asserted explicitly (regression: STAGE5.md task 5.4). */
    EXPECT(find(dp.data, dp.len, 4, &cnt) && cnt.wire == 1 && cnt.i64 == 3,
           "hist: count=3 (fixed64)");
    EXPECT(find(dp.data, dp.len, 5, &sum) && as_double(sum.i64) > 100.0, "hist: sum>100");
    EXPECT(find(dp.data, dp.len, 6, &scale) && unzig(scale.varint) == 2, "hist: scale=2");
    EXPECT(find(dp.data, dp.len, 7, &zc) && zc.wire == 1 && zc.i64 == 1,
           "hist: zero_count=1 (fixed64)");
    EXPECT(find(dp.data, dp.len, 14, &zt) && as_double(zt.i64) == lk_hist_bound(LK_HIST_MIN_INDEX),
           "hist: zero_threshold=bound(MIN)");

    EXPECT(find(dp.data, dp.len, 8, &buckets), "hist: positive buckets present");
    EXPECT(find(buckets.data, buckets.len, 1, &off) && unzig(off.varint) == LK_HIST_MIN_INDEX,
           "hist: offset=-53");
    EXPECT(find(buckets.data, buckets.len, 2, &counts), "hist: bucket_counts present");
    {
        struct rd r = {counts.data, counts.data + counts.len};
        uint64_t bc[LK_HIST_NBUCKETS];
        int n = 0;

        while (r.p < r.end && n < LK_HIST_NBUCKETS)
            bc[n++] = rd_varint(&r);
        EXPECT(n == LK_HIST_NBUCKETS, "hist: 77 packed bucket counts");
        EXPECT(n == LK_HIST_NBUCKETS && bc[53] == 1, "hist: bucket_counts[53]=1 (value 1.0s)");
        EXPECT(n == LK_HIST_NBUCKETS && bc[LK_HIST_NBUCKETS - 1] == 1,
               "hist: overflow folded into top bucket");
    }
    pb_free(&pb);
}

/* The size histogram (РH9) goes out as an explicit-bucket Histogram — a
 * different Metric field, a different data-point shape, and attributes in field
 * 9 rather than 1. Getting that last one wrong produces protobuf the Collector
 * accepts and silently drops the labels from, so it is asserted here. */
static void test_bhist(void)
{
    struct lk_bhist h = {0};
    struct lk_label lbl[1] = {{"route", "/orders/{id}"}};
    struct lk_metric_view v = {
        .name = "latkit_http_response_size_bytes",
        .type = LK_MT_HIST_BYTES,
        .labels = lbl,
        .nlabels = 1,
        .created_ns = CREATED,
    };
    struct pbuf pb;
    struct field metric, hi, dp, temp, cnt, sum, counts, bounds, attrs;

    lk_bhist_observe(&h, 100);        /* -> bucket 1, le=128 */
    lk_bhist_observe(&h, 3ull << 30); /* 3 GiB -> past the top boundary */

    v.bhist = &h;
    encode_one(&pb, &v);
    EXPECT(find(pb.buf, pb.len, 2, &metric), "bhist: metric present");
    EXPECT(find(metric.data, metric.len, 9, &hi), "bhist: Histogram (field 9) present");
    EXPECT(!find(metric.data, metric.len, 10, &(struct field){0}),
           "bhist: not an ExponentialHistogram");
    EXPECT(find(hi.data, hi.len, 2, &temp) && temp.varint == 2, "bhist: temporality CUMULATIVE");
    EXPECT(find(hi.data, hi.len, 1, &dp), "bhist: data point present");
    EXPECT(find(dp.data, dp.len, 4, &cnt) && cnt.wire == 1 && cnt.i64 == 2,
           "bhist: count=2 (fixed64)");
    EXPECT(find(dp.data, dp.len, 5, &sum) && as_double(sum.i64) > 3e9, "bhist: sum>3 GiB");
    EXPECT(find(dp.data, dp.len, 9, &attrs), "bhist: attributes in field 9");

    EXPECT(find(dp.data, dp.len, 6, &counts), "bhist: bucket_counts present");
    EXPECT(counts.len == 8 * (LK_BHIST_NBUCKETS + 1), "bhist: 26 packed fixed64 counts");
    EXPECT(find(dp.data, dp.len, 7, &bounds), "bhist: explicit_bounds present");
    EXPECT(bounds.len == 8 * LK_BHIST_NBUCKETS, "bhist: 25 packed bounds");
    {
        /* counts[1] is the 100-byte body, the last cell the 3 GiB overflow;
         * bounds[0] is 64 and the last is 1 GiB. */
        const uint8_t *c = counts.data, *b = bounds.data;
        uint64_t c1 = 0, clast = 0, b0 = 0, blast = 0;

        memcpy(&c1, c + 8, 8);
        memcpy(&clast, c + 8 * LK_BHIST_NBUCKETS, 8);
        memcpy(&b0, b, 8);
        memcpy(&blast, b + 8 * (LK_BHIST_NBUCKETS - 1), 8);
        EXPECT(c1 == 1, "bhist: bucket_counts[1]=1 (100 bytes)");
        EXPECT(clast == 1, "bhist: overflow cell=1 (3 GiB)");
        EXPECT(as_double(b0) == 64.0, "bhist: first bound = 64");
        EXPECT(as_double(blast) == 1073741824.0, "bhist: last bound = 1 GiB");
    }
    pb_free(&pb);
}

/* The object grid (РS7) goes through the same encoder and must go out as *its
 * own* bounds: the explicit_bounds array is what tells a backend where the
 * buckets are, so a histogram exported against the wrong grid is not a rounding
 * error but a wrong answer, and nothing downstream could detect it. */
static void test_bhist_object_grid(void)
{
    struct lk_bhist h = {0};
    struct lk_label lbl[1] = {{"op", "PutObject"}};
    struct lk_metric_view v = {
        .name = "latkit_s3_object_size_bytes",
        .type = LK_MT_HIST_BYTES,
        .labels = lbl,
        .nlabels = 1,
        .created_ns = CREATED,
    };
    struct pbuf pb;
    struct field metric, hi, dp, counts, bounds;

    lk_bhist_init(&h, LK_OHIST_MIN_LOG2, LK_OHIST_NBUCKETS);
    lk_bhist_observe(&h, 64ull << 20); /* a multipart part: le = 64 MiB */
    lk_bhist_observe(&h, 4ull << 40);  /* past 1 TiB: the overflow cell */

    v.bhist = &h;
    encode_one(&pb, &v);
    EXPECT(find(pb.buf, pb.len, 2, &metric), "ohist: metric present");
    EXPECT(find(metric.data, metric.len, 9, &hi), "ohist: Histogram (field 9) present");
    EXPECT(find(hi.data, hi.len, 1, &dp), "ohist: data point present");
    EXPECT(find(dp.data, dp.len, 6, &counts), "ohist: bucket_counts present");
    EXPECT(counts.len == 8 * (LK_OHIST_NBUCKETS + 1), "ohist: 32 packed fixed64 counts");
    EXPECT(find(dp.data, dp.len, 7, &bounds), "ohist: explicit_bounds present");
    EXPECT(bounds.len == 8 * LK_OHIST_NBUCKETS, "ohist: 31 packed bounds");
    {
        const uint8_t *c = counts.data, *b = bounds.data;
        uint64_t c16 = 0, clast = 0, b0 = 0, blast = 0;

        memcpy(&c16, c + 8 * 16, 8);
        memcpy(&clast, c + 8 * LK_OHIST_NBUCKETS, 8);
        memcpy(&b0, b, 8);
        memcpy(&blast, b + 8 * (LK_OHIST_NBUCKETS - 1), 8);
        EXPECT(c16 == 1, "ohist: bucket_counts[16]=1 (64 MiB)");
        EXPECT(clast == 1, "ohist: overflow cell=1 (4 TiB)");
        EXPECT(as_double(b0) == 1024.0, "ohist: first bound = 1 KiB");
        EXPECT(as_double(blast) == 1099511627776.0, "ohist: last bound = 1 TiB");
    }
    pb_free(&pb);
}

/* The redis value grid (РR11) is the third one through the same encoder, and
 * the check is the same one for the same reason — a distribution exported
 * against somebody else's boundaries is silently wrong. Its bottom is where the
 * point is: 8 B, four octaves below the default grid's first bound. */
static void test_bhist_value_grid(void)
{
    struct lk_bhist h = {0};
    struct lk_label lbl[1] = {{"cmd", "GET"}};
    struct lk_metric_view v = {
        .name = "latkit_redis_value_size_bytes",
        .type = LK_MT_HIST_BYTES,
        .labels = lbl,
        .nlabels = 1,
        .created_ns = CREATED,
    };
    struct pbuf pb;
    struct field metric, hi, dp, counts, bounds;

    lk_bhist_init(&h, LK_VHIST_MIN_LOG2, LK_VHIST_NBUCKETS);
    lk_bhist_observe(&h, 4);            /* `:1\r\n`: the first cell */
    lk_bhist_observe(&h, 512ull << 20); /* proto-max-bulk-len: overflow */

    v.bhist = &h;
    encode_one(&pb, &v);
    EXPECT(find(pb.buf, pb.len, 2, &metric), "vhist: metric present");
    EXPECT(find(metric.data, metric.len, 9, &hi), "vhist: Histogram (field 9) present");
    EXPECT(find(hi.data, hi.len, 1, &dp), "vhist: data point present");
    EXPECT(find(dp.data, dp.len, 6, &counts), "vhist: bucket_counts present");
    EXPECT(counts.len == 8 * (LK_VHIST_NBUCKETS + 1), "vhist: 22 packed fixed64 counts");
    EXPECT(find(dp.data, dp.len, 7, &bounds), "vhist: explicit_bounds present");
    EXPECT(bounds.len == 8 * LK_VHIST_NBUCKETS, "vhist: 21 packed bounds");
    {
        const uint8_t *c = counts.data, *b = bounds.data;
        uint64_t c0 = 0, clast = 0, b0 = 0, blast = 0;

        memcpy(&c0, c, 8);
        memcpy(&clast, c + 8 * LK_VHIST_NBUCKETS, 8);
        memcpy(&b0, b, 8);
        memcpy(&blast, b + 8 * (LK_VHIST_NBUCKETS - 1), 8);
        EXPECT(c0 == 1, "vhist: bucket_counts[0]=1 (a 4-byte reply)");
        EXPECT(clast == 1, "vhist: overflow cell=1 (512 MiB)");
        EXPECT(as_double(b0) == 8.0, "vhist: first bound = 8 B");
        EXPECT(as_double(blast) == 8388608.0, "vhist: last bound = 8 MiB");
    }
    pb_free(&pb);
}

/* --- span encoder (task 5.3, and the HTTP shape РH11 / М6) ---------------- */

/* Decode one Span out of a freshly encoded pbuf. */
static bool encode_span(struct pbuf *pb, const struct lk_span *sp, struct field *span)
{
    struct lk_timebase tb = {.offset_ns = 0};

    pb_init(pb);
    lk_otlp_encode_span(pb, sp, &tb);
    EXPECT(!pb->oom, "span: encode did not OOM");
    return find(pb->buf, pb->len, 2, span);
}

/* The attribute (field 9) with this key, as a string; NULL when absent. `out`
 * receives a NUL-terminated copy. */
static bool attr_str(const struct field *span, const char *key, char *out, size_t cap)
{
    struct rd r = {span->data, span->data + span->len};
    struct field f, k, av, sv;

    while (next_field(&r, &f)) {
        if (f.num != 9)
            continue;
        if (!find(f.data, f.len, 1, &k) || k.len != strlen(key) || memcmp(k.data, key, k.len))
            continue;
        if (!find(f.data, f.len, 2, &av) || !find(av.data, av.len, 1, &sv))
            return false;
        if (sv.len >= cap)
            return false;
        memcpy(out, sv.data, sv.len);
        out[sv.len] = '\0';
        return true;
    }
    return false;
}

/* The same, for an int_value attribute. */
static bool attr_int(const struct field *span, const char *key, uint64_t *out)
{
    struct rd r = {span->data, span->data + span->len};
    struct field f, k, av, iv;

    while (next_field(&r, &f)) {
        if (f.num != 9)
            continue;
        if (!find(f.data, f.len, 1, &k) || k.len != strlen(key) || memcmp(k.data, key, k.len))
            continue;
        if (!find(f.data, f.len, 2, &av) || !find(av.data, av.len, 3, &iv))
            return false;
        *out = iv.varint;
        return true;
    }
    return false;
}

/* A database span keeps the shape it has had since task 5.3: a *client* span
 * with db.* attributes and no parent. Pinned here because М6 put a branch in
 * front of it (РH15: nothing about PG/MySQL may move). */
static void test_span_db(void)
{
    struct lk_span sp = {
        .start_ns = CREATED,
        .end_ns = NOW,
        .db_system = "postgresql",
        .rows = 3,
        .have_rows = true,
    };
    struct pbuf pb;
    struct field span, kind;
    char buf[128];

    snprintf(sp.name, sizeof(sp.name), "select ?");
    snprintf(sp.db, sizeof(sp.db), "appdb");
    snprintf(sp.user, sizeof(sp.user), "alice");
    EXPECT(encode_span(&pb, &sp, &span), "db span: encoded");
    EXPECT(find(span.data, span.len, 6, &kind) && kind.varint == 3, "db span: kind CLIENT");
    EXPECT(!find(span.data, span.len, 4, &(struct field){0}), "db span: no parent_span_id");
    EXPECT(attr_str(&span, "db.system.name", buf, sizeof(buf)) && !strcmp(buf, "postgresql"),
           "db span: db.system.name");
    EXPECT(attr_str(&span, "db.namespace", buf, sizeof(buf)) && !strcmp(buf, "appdb"),
           "db span: db.namespace");
    EXPECT(!attr_str(&span, "http.route", buf, sizeof(buf)), "db span: no http attributes");
    pb_free(&pb);
}

/* The HTTP shape (РH11): a *server* span, a parent from the caller's
 * `traceparent`, the semconv attribute set — and not one db.* key. */
static void test_span_http(void)
{
    struct lk_span_http h = {
        .bytes_in = 11,
        .bytes_out = 4096,
        .status = 200,
        .client_port = 51000,
        .server_port = 8080,
        .version = 1,
    };
    struct lk_span sp = {
        .start_ns = CREATED,
        .end_ns = NOW,
        .otel_kind = LK_OTEL_KIND_HTTP,
        .http = &h,
        .have_parent = true,
        .text = "/orders/42?token=***",
        .text_len = 20,
    };
    struct pbuf pb;
    struct field span, kind, parent, tstate;
    uint64_t iv;
    char buf[128];

    snprintf(sp.name, sizeof(sp.name), "GET /orders/{id}");
    memset(sp.parent_id, 0xab, sizeof(sp.parent_id));
    snprintf(h.route, sizeof(h.route), "/orders/{id}");
    snprintf(h.method, sizeof(h.method), "GET");
    snprintf(h.host, sizeof(h.host), "shop.example");
    snprintf(h.ua, sizeof(h.ua), "curl/8.5.0");
    snprintf(h.client, sizeof(h.client), "10.0.0.7");
    snprintf(h.ctype, sizeof(h.ctype), "application/json");
    snprintf(h.req_id, sizeof(h.req_id), "8f14e45f");
    snprintf(h.tstate, sizeof(h.tstate), "rojo=00f067aa0ba902b7");

    EXPECT(encode_span(&pb, &sp, &span), "http span: encoded");
    /* The three fields that make it a *child server* span rather than a
     * standalone client one — the whole point of М6. */
    EXPECT(find(span.data, span.len, 6, &kind) && kind.varint == 2, "http span: kind SERVER");
    EXPECT(find(span.data, span.len, 4, &parent) && parent.len == 8, "http span: parent_span_id");
    EXPECT(find(span.data, span.len, 3, &tstate) && tstate.len == strlen(h.tstate),
           "http span: trace_state carried");

    EXPECT(attr_str(&span, "http.request.method", buf, sizeof(buf)) && !strcmp(buf, "GET"),
           "http span: http.request.method");
    EXPECT(attr_str(&span, "http.route", buf, sizeof(buf)) && !strcmp(buf, "/orders/{id}"),
           "http span: http.route");
    EXPECT(attr_int(&span, "http.response.status_code", &iv) && iv == 200,
           "http span: status_code as an int");
    EXPECT(attr_str(&span, "server.address", buf, sizeof(buf)) && !strcmp(buf, "shop.example"),
           "http span: server.address");
    EXPECT(attr_str(&span, "url.scheme", buf, sizeof(buf)) && !strcmp(buf, "http"),
           "http span: url.scheme");
    EXPECT(attr_str(&span, "url.path", buf, sizeof(buf)) && !strcmp(buf, "/orders/42?token=***"),
           "http span: url.path, redacted");
    EXPECT(attr_str(&span, "network.protocol.version", buf, sizeof(buf)) && !strcmp(buf, "1.1"),
           "http span: protocol version");
    EXPECT(attr_str(&span, "user_agent.original", buf, sizeof(buf)) && !strcmp(buf, "curl/8.5.0"),
           "http span: user_agent.original");
    EXPECT(attr_str(&span, "client.address", buf, sizeof(buf)) && !strcmp(buf, "10.0.0.7"),
           "http span: client.address");
    EXPECT(attr_int(&span, "http.response.body.size", &iv) && iv == 4096,
           "http span: response body size");
    EXPECT(!attr_str(&span, "db.system.name", buf, sizeof(buf)), "http span: no db.system.name");
    EXPECT(!attr_str(&span, "db.query.text", buf, sizeof(buf)), "http span: no db.query.text");
    EXPECT(!find(span.data, span.len, 15, &(struct field){0}), "http span: 200 sets no Status");

    /* https when the bytes arrived through the TLS path, and a 5xx — the only
     * status that is the *server's* failure — sets the span status (РH10). */
    h.tls = true;
    h.status = 503;
    sp.error = true;
    pb_free(&pb);
    EXPECT(encode_span(&pb, &sp, &span), "http span: re-encoded");
    EXPECT(attr_str(&span, "url.scheme", buf, sizeof(buf)) && !strcmp(buf, "https"),
           "http span: url.scheme https on TLS");
    EXPECT(find(span.data, span.len, 15, &(struct field){0}), "http span: 5xx sets Status");
    pb_free(&pb);
}

int main(void)
{
    test_counter();
    test_gauge();
    test_hist();
    test_bhist();
    test_bhist_object_grid();
    test_bhist_value_grid();
    test_span_db();
    test_span_http();
    printf(failures ? "\n%d FAILURES\n" : "\nall otlp encoder tests passed\n", failures);
    return failures ? 1 : 0;
}
