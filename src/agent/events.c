// SPDX-License-Identifier: GPL-2.0
/* See events.h. Event handling is verbatim from stage-1 main.c: decode by
 * hdr.type, one line per event, payload hexdump behind --hexdump, per-conn
 * seq holes logged as they arrive, global stats summed from the per-CPU map.
 * Capture budget (task 1.6): --cap-headers exercises the per-connection
 * capture_mode control surface. */
#include "events.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include <bpf/libbpf.h>

#include "decode.h"
#include "latkit.h"
#include "loop.h"
#include "seqtrack.h"

#define LK_STATS_INTERVAL_SEC 10

struct lk_events {
    struct lk_events_cfg cfg;
    struct ring_buffer *rb;
    /* seq-hole detector state (task 1.5); the machinery lives in seqtrack.c
     * so tests/unit can exercise it. */
    struct lk_seqtrack seq_tab;
};

/* --- global stats (task 1.5) ---------------------------------------------
 * Sum the per-CPU `stats` counters and print one line to stderr; called
 * every LK_STATS_INTERVAL_SEC from the loop and once on exit. */
void lk_events_print_stats(struct lk_events *e)
{
    __u64 sum[LK_ST_MAX] = {0}, drops;
    int ncpus = libbpf_num_possible_cpus();
    __u64 *vals;

    if (ncpus < 1)
        return;
    vals = calloc(ncpus, sizeof(*vals));
    if (!vals)
        return;

    for (__u32 id = 0; id < LK_ST_MAX; id++) {
        if (bpf_map__lookup_elem(e->cfg.stats, &id, sizeof(id), vals, ncpus * sizeof(*vals), 0))
            continue; /* leaves the counter at 0 rather than aborting */
        for (int cpu = 0; cpu < ncpus; cpu++)
            sum[id] += vals[cpu];
    }
    free(vals);

    drops =
        sum[LK_ST_RESERVE_FAIL_DATA] + sum[LK_ST_RESERVE_FAIL_OPEN] + sum[LK_ST_RESERVE_FAIL_CLOSE];
    fprintf(stderr,
            "latkit: stats events=%llu drops=%llu (data %llu, open %llu, close %llu) "
            "bytes=%llu/%llu captured/total iter_unsupported=%llu recv_miss=%llu\n",
            (unsigned long long)sum[LK_ST_EVENTS], (unsigned long long)drops,
            (unsigned long long)sum[LK_ST_RESERVE_FAIL_DATA],
            (unsigned long long)sum[LK_ST_RESERVE_FAIL_OPEN],
            (unsigned long long)sum[LK_ST_RESERVE_FAIL_CLOSE],
            (unsigned long long)sum[LK_ST_BYTES_CAPTURED],
            (unsigned long long)sum[LK_ST_BYTES_TOTAL],
            (unsigned long long)sum[LK_ST_ITER_UNSUPPORTED],
            (unsigned long long)sum[LK_ST_RECV_STATE_MISS]);
}

/* xxd-style: offset, 16 hex bytes, ASCII column. */
static void hexdump(const __u8 *buf, __u32 len)
{
    for (__u32 off = 0; off < len; off += 16) {
        printf("  %08x: ", off);
        for (__u32 i = 0; i < 16; i++) {
            if (off + i < len)
                printf("%02x", buf[off + i]);
            else
                printf("  ");
            if (i % 2 == 1)
                printf(" ");
        }
        printf(" ");
        for (__u32 i = 0; i < 16 && off + i < len; i++) {
            __u8 c = buf[off + i];
            putchar(c >= 0x20 && c < 0x7f ? c : '.');
        }
        printf("\n");
    }
}

/* v4 addresses live in the first 4 bytes of the 16-byte array; tuple.family
 * carries the kernel AF_* value, which matches userspace. */
static const char *tuple_addr(const struct lk_tuple *t, const __u8 *addr, char *buf, size_t len)
{
    if (!inet_ntop(t->family, addr, buf, len))
        snprintf(buf, len, "?");
    return buf;
}

static void print_conn_event(const struct lk_ev_conn *ev)
{
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];

    printf("%llu %s conn=%llx seq=%u pid=%u netns=%u %s:%u -> %s:%u",
           (unsigned long long)ev->hdr.ts_ns, ev->hdr.type == LK_EV_CONN_OPEN ? "OPEN " : "CLOSE",
           (unsigned long long)ev->hdr.conn_id, ev->hdr.seq, ev->pid, ev->tuple.netns,
           tuple_addr(&ev->tuple, ev->tuple.saddr, src, sizeof(src)), ev->tuple.sport,
           tuple_addr(&ev->tuple, ev->tuple.daddr, dst, sizeof(dst)), ev->tuple.dport);
    if (ev->hdr.flags & LK_F_SYNTHETIC)
        printf(" synthetic");
    if (ev->hdr.flags & LK_F_GAP)
        printf(" gap");
    if (ev->hdr.type == LK_EV_CONN_CLOSE)
        printf(" dropped=%u", ev->conn_dropped);
    printf("\n");
}

static void print_data_event(const struct lk_ev_data *ev, __u32 cap, bool dump)
{
    printf("%llu %s conn=%llx seq=%u total=%u cap=%u off=%u%s%s\n",
           (unsigned long long)ev->hdr.ts_ns, ev->hdr.dir == LK_DIR_SEND ? "SEND " : "RECV ",
           (unsigned long long)ev->hdr.conn_id, ev->hdr.seq, ev->total_len, cap, ev->off,
           ev->hdr.flags & LK_F_TRUNC ? " trunc" : "", ev->hdr.flags & LK_F_GAP ? " gap" : "");
    if (dump && cap > 0)
        hexdump(ev->payload, cap);
}

/* --cap-headers test hook (task 1.6): flip the connection into HEADERS mode
 * by writing capture_mode into its live `conns` entry — the same control
 * surface the stage-3 parser will use, just with a trivial policy (every
 * connection, right at OPEN). The read-modify-write races with kernel-side
 * seq/dropped updates and can lose an increment (a spurious one-event "gap"
 * in the log); acceptable for a test hook, revisit with the real policy. */
static void set_cap_headers(struct bpf_map *conns, __u64 cookie)
{
    struct lk_conn_state st;

    if (bpf_map__lookup_elem(conns, &cookie, sizeof(cookie), &st, sizeof(st), 0))
        return; /* already closed or LRU-evicted */
    st.capture_mode = LK_CAP_HEADERS;
    if (bpf_map__update_elem(conns, &cookie, sizeof(cookie), &st, sizeof(st), BPF_EXIST))
        fprintf(stderr, "warn: conn=%llx: failed to set HEADERS mode\n",
                (unsigned long long)cookie);
}

static int handle_event(void *ctx, void *data, size_t size)
{
    struct lk_events *e = ctx;
    struct lk_ev_view v;
    __u32 lost;

    switch (lk_ev_decode(data, size, &v)) {
    case LK_DEC_CONN:
        lost = lk_seqtrack_check(&e->seq_tab, v.hdr->conn_id, v.hdr->seq,
                                 v.hdr->type == LK_EV_CONN_CLOSE);
        if (v.hdr->type == LK_EV_CONN_OPEN && e->cfg.cap_headers)
            set_cap_headers(e->cfg.conns, v.hdr->conn_id);
        print_conn_event(v.conn);
        break;
    case LK_DEC_DATA:
        lost = lk_seqtrack_check(&e->seq_tab, v.hdr->conn_id, v.hdr->seq, false);
        print_data_event(v.data, v.cap_len, e->cfg.hexdump);
        break;
    case LK_DEC_UNKNOWN:
        fprintf(stderr, "warn: unknown event type %u (size %zu)\n",
                ((const struct lk_ev_hdr *)data)->type, size);
        return 0;
    case LK_DEC_SHORT:
    default:
        return 0;
    }

    if (lost)
        fprintf(stderr, "latkit: conn=%llx gap detected (lost %u events)\n",
                (unsigned long long)v.hdr->conn_id, lost);
    return 0;
}

/* ringbuf readiness (loop handler): drain without a timeout — epoll already
 * told us there is data. */
static int on_ringbuf_ready(void *ctx)
{
    struct lk_events *e = ctx;
    int n = ring_buffer__consume(e->rb);

    if (n < 0) {
        fprintf(stderr, "ring_buffer__consume: %d\n", n);
        return n;
    }
    return 0;
}

static void on_stats_tick(void *ctx)
{
    lk_events_print_stats(ctx);
}

struct lk_events *lk_events_new(const struct lk_events_cfg *cfg)
{
    struct lk_events *e = calloc(1, sizeof(*e));

    if (!e)
        return NULL;
    e->cfg = *cfg;
    e->rb = ring_buffer__new(bpf_map__fd(cfg->ringbuf), handle_event, e, NULL);
    if (!e->rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        free(e);
        return NULL;
    }
    return e;
}

void lk_events_free(struct lk_events *e)
{
    if (!e)
        return;
    ring_buffer__free(e->rb);
    lk_seqtrack_clear(&e->seq_tab);
    free(e);
}

int lk_events_register(struct lk_events *e, struct lk_loop *loop)
{
    int err = lk_loop_add_fd(loop, ring_buffer__epoll_fd(e->rb), on_ringbuf_ready, e);

    if (err)
        return err;
    return lk_loop_every(loop, LK_STATS_INTERVAL_SEC, on_stats_tick, e);
}
