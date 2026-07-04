// SPDX-License-Identifier: GPL-2.0
/* See events.h. Decoded events feed the connection table (task 2.2): it
 * detects per-conn seq holes (logged as they arrive, both directions
 * dirtied) and is kept bounded by CONN_CLOSE, the 60 s idle sweep and the
 * --max-conns LRU ceiling. Data events then go through the streaming framer
 * (task 2.3), whose sink here is the --messages logger. Capture budget
 * (task 1.6): --cap-headers exercises the per-connection capture_mode
 * control surface. */
#include "events.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <bpf/libbpf.h>

#include "conn_table.h"
#include "decode.h"
#include "latkit.h"
#include "loop.h"
#include "reassembly.h"

#define LK_STATS_INTERVAL_SEC 10
#define LK_SWEEP_INTERVAL_SEC 60

struct lk_events {
    struct lk_events_cfg cfg;
    struct ring_buffer *rb;
    struct lk_conn_table *conns; /* userspace conn table (task 2.2) */
    struct lk_reasm reasm;       /* streaming framer (task 2.3) */
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

    const struct lk_conn_table_stats *cs = lk_conn_table_stats(e->conns);

    fprintf(stderr,
            "latkit: conns active=%u created=%llu closed=%llu "
            "evicted=%llu (lru %llu, idle %llu) gaps=%llu lost=%llu\n",
            cs->active, (unsigned long long)cs->created, (unsigned long long)cs->closed,
            (unsigned long long)(cs->evicted_lru + cs->evicted_idle),
            (unsigned long long)cs->evicted_lru, (unsigned long long)cs->evicted_idle,
            (unsigned long long)cs->seq_gaps, (unsigned long long)cs->lost_events);

    const struct lk_reasm_stats *rs = &e->reasm.st;

    fprintf(stderr,
            "latkit: msgs total=%llu trunc=%llu holes=%llu (%llu bytes) "
            "dirty: badlen=%llu hdr-hole=%llu off-anomaly=%llu\n",
            (unsigned long long)rs->msgs, (unsigned long long)rs->msgs_trunc,
            (unsigned long long)rs->holes, (unsigned long long)rs->hole_bytes,
            (unsigned long long)rs->bad_len, (unsigned long long)rs->hdr_holes,
            (unsigned long long)rs->off_anomalies);
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

/* --messages logger: the framer sink for stage 2 (stage 3 replaces it with
 * the parser). One line per reassembled message; --hexdump adds the captured
 * body prefix. fe> is the frontend->backend stream (RECV on the server
 * socket), <be the reverse. */
static void on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct lk_events *e = ctx;
    char type[8];

    if (!e->cfg.messages)
        return;
    if (m->flags & LK_MSG_STARTUP)
        snprintf(type, sizeof(type), "startup");
    else if (m->type >= 0x20 && m->type < 0x7f)
        snprintf(type, sizeof(type), "%c", m->type);
    else
        snprintf(type, sizeof(type), "0x%02x", (unsigned char)m->type);
    printf("%llu %s conn=%llx %s len=%u cap=%u%s%s\n", (unsigned long long)m->ts_ns,
           dir == LK_DIR_RECV ? "fe>" : "<be", (unsigned long long)c->cookie, type, m->len,
           m->body_cap, m->flags & LK_MSG_BODY_TRUNC ? " trunc" : "",
           m->flags & LK_MSG_AFTER_RESYNC ? " resync" : "");
    if (e->cfg.hexdump && m->body_cap)
        hexdump(m->body, m->body_cap);
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
        if (v.hdr->type == LK_EV_CONN_CLOSE) {
            lk_conn_table_close(e->conns, v.hdr->conn_id, v.hdr->seq, v.hdr->ts_ns, &lost);
        } else {
            lk_conn_table_open(e->conns, v.hdr->conn_id, v.hdr->seq, v.hdr->ts_ns, &v.conn->tuple,
                               v.hdr->flags & LK_F_SYNTHETIC, &lost);
            if (e->cfg.cap_headers)
                set_cap_headers(e->cfg.conns, v.hdr->conn_id);
        }
        if (e->cfg.events)
            print_conn_event(v.conn);
        break;
    case LK_DEC_DATA: {
        struct lk_conn *conn =
            lk_conn_table_data(e->conns, v.hdr->conn_id, v.hdr->seq, v.hdr->ts_ns, &lost);

        if (e->cfg.events)
            print_data_event(v.data, v.cap_len, e->cfg.hexdump);
        if (conn) /* NULL only on alloc failure: degrade to no framing */
            lk_reasm_data(&e->reasm, conn, v.hdr->dir, v.data, v.cap_len);
        break;
    }
    case LK_DEC_UNKNOWN:
        fprintf(stderr, "warn: unknown event type %u (size %zu)\n",
                ((const struct lk_ev_hdr *)data)->type, size);
        return 0;
    case LK_DEC_SHORT:
    default:
        return 0;
    }

    if (lost)
        fprintf(stderr, "latkit: conn=%llx gap detected (lost %u events), both directions dirty\n",
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

/* Idle sweep (Р12): the leak insurance for connections whose CLOSE was lost.
 * The sweep clock is CLOCK_MONOTONIC — the same clock as event timestamps
 * (bpf_ktime_get_ns), so last_activity_ns compares directly. */
static void on_sweep_tick(void *ctx)
{
    struct lk_events *e = ctx;
    struct timespec ts;
    unsigned int n;

    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        return;
    n = lk_conn_table_sweep(e->conns, (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec);
    if (n)
        fprintf(stderr, "latkit: idle sweep evicted %u connection(s)\n", n);
}

struct lk_events *lk_events_new(const struct lk_events_cfg *cfg)
{
    struct lk_events *e = calloc(1, sizeof(*e));

    if (!e)
        return NULL;
    e->cfg = *cfg;
    lk_reasm_init(&e->reasm, &(struct lk_msg_sink){.ctx = e, .on_msg = on_msg});
    e->conns = lk_conn_table_new(cfg->max_conns, cfg->conn_idle_timeout_sec * 1000000000ULL);
    if (!e->conns) {
        free(e);
        return NULL;
    }
    e->rb = ring_buffer__new(bpf_map__fd(cfg->ringbuf), handle_event, e, NULL);
    if (!e->rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        lk_conn_table_free(e->conns);
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
    lk_conn_table_free(e->conns);
    free(e);
}

int lk_events_register(struct lk_events *e, struct lk_loop *loop)
{
    int err = lk_loop_add_fd(loop, ring_buffer__epoll_fd(e->rb), on_ringbuf_ready, e);

    if (err)
        return err;
    err = lk_loop_every(loop, LK_STATS_INTERVAL_SEC, on_stats_tick, e);
    if (err)
        return err;
    return lk_loop_every(loop, LK_SWEEP_INTERVAL_SEC, on_sweep_tick, e);
}
