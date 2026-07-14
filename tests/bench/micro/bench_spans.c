// SPDX-License-Identifier: GPL-2.0
/* Hot-path micro-bench: the span collector's per-query text allocation (Р32).
 *
 * spans.c mallocs a fresh db.query.text buffer for every sampled span
 * (fill_text_and_name -> malloc(n)) and frees it on drain. With sampling on,
 * that is one malloc + one free on the *hottest* path there is — every
 * completed query. This bench drives lk_query_sink at sample_ratio=1.0 so each
 * op allocates, draining whenever the fixed ring (LK_SPAN_BUF) fills so the
 * next op keeps allocating instead of being dropped. Baseline reads
 * allocs/op ~= 1.0; an init-time text arena should drive it to ~0. */
#include <string.h>

#include "bench_util.h"
#include "proto.h"
#include "spans.h"

/* A representative statement: a handful of literals so the normaliser does real
 * work, ~120 bytes so the malloc'd copy is a realistic size (< text_max=4096). */
static const char SQL[] =
    "SELECT id, name, email FROM users WHERE org_id = 42 AND status = 'active' "
    "AND created_at > '2026-01-01' ORDER BY created_at DESC LIMIT 50";

static volatile uint64_t g_sink; /* keep the drained work observable */

static void drain_emit(void *ctx, const struct lk_span *sp)
{
    (void)ctx;
    g_sink += sp->text_len + sp->name[0];
}

int main(int argc, char **argv)
{
    uint64_t n = bench_iters(argc, argv, 2000000);
    struct lk_spans_cfg cfg = {.sample_ratio = 1.0, .seed = 1};
    struct lk_spans *s = lk_spans_new(&cfg);
    struct lk_session sess;
    struct lk_conn c = {.cookie = 0x1234};
    unsigned infill = 0;
    uint64_t t0, t1;

    if (!s) {
        fprintf(stderr, "lk_spans_new failed\n");
        return 1;
    }
    memset(&sess, 0, sizeof(sess));
    snprintf(sess.database, sizeof(sess.database), "appdb");
    snprintf(sess.user, sizeof(sess.user), "alice");
    sess.complete = true;

    const struct lk_query_sink *sink = lk_spans_sink(s);
    struct lk_query_obs o = {
        .text = SQL,
        .text_len = (uint32_t)(sizeof(SQL) - 1),
        .rows = 2,
        .kind = LK_Q_SIMPLE,
    };

    bench_alloc_reset();
    t0 = bench_now_ns();
    for (uint64_t i = 0; i < n; i++) {
        o.ts_start_ns = 1000 + i;
        o.ts_complete_ns = o.ts_start_ns + 1000000; /* 1 ms: measurable duration */
        sink->on_query(sink->ctx, &c, &sess, &o);
        if (++infill == LK_SPAN_BUF) { /* ring full: drain frees the texts */
            lk_spans_drain(s, drain_emit, NULL);
            infill = 0;
        }
    }
    t1 = bench_now_ns();

    bench_report("spans/text", t1 - t0, n);
    if (g_alloc.calls == 0)
        fprintf(stderr, "warning: no allocations counted (wrap not linked?)\n");
    lk_spans_free(s);
    return 0;
}
