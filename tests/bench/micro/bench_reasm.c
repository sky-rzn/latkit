// SPDX-License-Identifier: GPL-2.0
/* Hot-path micro-bench: the reassembly body-prefix buffer (Р11).
 *
 * lk_frame_bytes mallocs f->buf when a message body's prefix arrives split
 * across event boundaries, and frees it at the message boundary (msg_reset).
 * Unlike the span text this fires only for messages torn across events, not
 * every message — but under load (large Query/Bind payloads, small capture
 * budget) it is exactly that: one malloc + one free per torn message.
 *
 * Each op frames a single backend 'D' message whose BODY bytes are delivered in
 * two events (header + first half, then the rest): the first event leaves an
 * incomplete prefix -> a body slab; the second completes it -> emit + recycle.
 *
 * Before the Р11 freelist this was one malloc + one free per op (allocs/op
 * ~= 1.0). The slab is now drawn from a fixed agent-wide freelist and returned
 * at the message boundary, so steady state is zero heap ops: only the very
 * first op mallocs, every op after it reuses the recycled slab -> allocs/op
 * -> 0. The wrap-liveness warning below is now a regression guard: the hot
 * path must not allocate per message. (Static-inlining the buffer into the
 * frame was rejected — 2 GiB at max_conns=65536; the freelist keeps churn out
 * without paying that.) */
#include <linux/types.h>
#include <string.h>

#include "bench_util.h"
#include "reassembly.h"

/* Body size of the framed message. <= LK_MSG_BODY_MAX so body_target == BODY
 * and the two events complete the message exactly (one malloc, no SKIP tail). */
#define BODY  512
#define SPLIT 256 /* body bytes carried by the first event */

static volatile uint64_t g_sink; /* keep emit observable */

static void on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    (void)ctx;
    (void)c;
    (void)dir;
    g_sink += m->body_cap;
}

/* One decoded data event: a chunk of a call at the given offset. */
static union {
    struct lk_ev_data d;
    __u8 raw[sizeof(struct lk_ev_data) + BODY + 64];
} ev;

static void feed(struct lk_reasm *r, struct lk_conn *c, __u32 total, __u32 off, const __u8 *p,
                 __u32 cap, __u64 ts)
{
    memset(&ev.d, 0, sizeof(ev.d));
    ev.d.hdr.ts_ns = ts;
    ev.d.hdr.dir = LK_DIR_SEND;
    ev.d.total_len = total;
    ev.d.off = off;
    ev.d.cap_len = cap;
    memcpy(ev.d.payload, p, cap);
    lk_reasm_data(r, c, LK_DIR_SEND, &ev.d, cap);
}

int main(int argc, char **argv)
{
    uint64_t n = bench_iters(argc, argv, 2000000);
    static const struct lk_msg_sink sink = {.on_msg = on_msg};
    struct lk_reasm reasm;
    struct lk_conn conn;
    __u8 wire[5 + BODY];
    const __u32 total = 5 + BODY;
    uint64_t t0, t1;

    /* One backend 'D' (DataRow) message: type + len(BE, incl. itself) + body. */
    wire[0] = 'D';
    wire[1] = (total - 1) >> 24;
    wire[2] = (total - 1) >> 16;
    wire[3] = (total - 1) >> 8;
    wire[4] = (__u8)(total - 1);
    memset(wire + 5, 'x', BODY);

    memset(&conn, 0, sizeof(conn));
    lk_reasm_init(&reasm, &sink);

    bench_alloc_reset();
    t0 = bench_now_ns();
    for (uint64_t i = 0; i < n; i++) {
        /* Event 1: header + first SPLIT body bytes -> incomplete prefix, malloc. */
        feed(&reasm, &conn, total, 0, wire, 5 + SPLIT, 1000 + i);
        /* Event 2: the remaining body -> completes, emit, msg_reset frees buf. */
        feed(&reasm, &conn, total, 5 + SPLIT, wire + 5 + SPLIT, BODY - SPLIT, 1000 + i);
    }
    t1 = bench_now_ns();

    bench_report("reasm/split", t1 - t0, n);
    if (reasm.st.msgs != n)
        fprintf(stderr, "warning: framed %llu msgs, expected %llu (framing off)\n",
                (unsigned long long)reasm.st.msgs, (unsigned long long)n);
    /* Regression guard (Р11 freelist): the hot path recycles, so only the
     * warm-up op may malloc. More than a couple of allocs over millions of ops
     * means the per-message churn is back. */
    if (n > 1000 && g_alloc.calls > 4)
        fprintf(stderr, "warning: %llu allocs over %llu ops — freelist not recycling?\n",
                (unsigned long long)g_alloc.calls, (unsigned long long)n);
    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    lk_reasm_free(&reasm); /* drain the recycled slab pool */
    return 0;
}
