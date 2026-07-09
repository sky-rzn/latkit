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

int main(void)
{
    test_counter();
    test_gauge();
    test_hist();
    printf(failures ? "\n%d FAILURES\n" : "\nall otlp encoder tests passed\n", failures);
    return failures ? 1 : 0;
}
