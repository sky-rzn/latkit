// SPDX-License-Identifier: GPL-2.0
/* See events.h. Decoded events feed the connection table (task 2.2): it
 * detects per-conn seq holes (logged as they arrive, both directions
 * dirtied) and is kept bounded by CONN_CLOSE, the 60 s idle sweep and the
 * --max-conns LRU ceiling. Data events then go through the streaming framer
 * (tasks 2.3/2.4), whose sink here is the --messages logger; resyncs are
 * logged to stderr, and a connection going TLS is switched to HEADERS
 * capture — no point shipping ciphertext through the ringbuf. Capture
 * budget (task 1.6): --cap-headers exercises the per-connection
 * capture_mode control surface. */
#include "events.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <bpf/libbpf.h>

#include "conn_table.h"
#include "decode.h"
#include "latkit.h"
#include "loop.h"
#include "pipeline.h"
#include "proto.h"
#include "reassembly.h"
#include "record.h"

#define LK_STATS_INTERVAL_SEC 10
#define LK_SWEEP_INTERVAL_SEC 60

struct lk_events {
    struct lk_events_cfg cfg;
    struct ring_buffer *rb;
    struct lk_pipeline pipe;              /* decode -> conn table -> framer (Р14) */
    struct lk_proto *proto;               /* PG handler: the standard framer sink */
    const struct lk_msg_sink *proto_sink; /* = lk_proto_sink(proto) */
    struct lk_recorder *rec;              /* --record trace writer, NULL when off */
};

/* --- --queries logger (stage 3): the standard consumer of the parser -------
 * Prints one line per session (AuthenticationOk) and per observation. Stage 4
 * replaces this consumer with the aggregator; the parser does not change. Task
 * 3.2 emits sessions and CANCEL observations — the full query line (timings,
 * rows, SQL) fills in with task 3.3. */
static const char *kind_str(__u8 kind)
{
    switch (kind) {
    case LK_Q_SIMPLE:
        return "simple";
    case LK_Q_EXTENDED:
        return "extended";
    case LK_Q_FUNCTION:
        return "function";
    case LK_Q_COPY_IN:
        return "copy_in";
    case LK_Q_COPY_OUT:
        return "copy_out";
    case LK_Q_CANCEL:
        return "cancel";
    default:
        return "?";
    }
}

static void on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    (void)ctx;
    printf("%llu session conn=%llx user=%s db=%s app=%s ver=%s%s\n",
           (unsigned long long)c->last_activity_ns, (unsigned long long)c->cookie,
           s->user[0] ? s->user : "?", s->database[0] ? s->database : "?",
           s->app[0] ? s->app : "?", s->server_version[0] ? s->server_version : "?",
           s->complete ? "" : " (incomplete)");
}

/* One line per observation (task 3.3). Duration is the honest per-query span
 * ts_complete - ts_start (Р16); the SQL text is truncated to 120 chars *in the
 * output only* — the observation still carries the full captured prefix. */
#define LK_QUERY_TEXT_LOG_MAX 120

static void on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                     const struct lk_query_obs *o)
{
    __u64 dur = o->ts_complete_ns > o->ts_start_ns ? o->ts_complete_ns - o->ts_start_ns : 0;
    int tlen = o->text_len > LK_QUERY_TEXT_LOG_MAX ? LK_QUERY_TEXT_LOG_MAX : (int)o->text_len;

    (void)ctx;
    printf("%llu query conn=%llx dur=%lluns kind=%s db=%s user=%s rows=%llu "
           "sqlstate=%s txn=%c flags=0x%x text=%.*s%s\n",
           (unsigned long long)o->ts_start_ns, (unsigned long long)c->cookie,
           (unsigned long long)dur, kind_str(o->kind), s->database[0] ? s->database : "?",
           s->user[0] ? s->user : "?", (unsigned long long)o->rows,
           (o->flags & LK_QO_ERROR) ? o->sqlstate : "-", o->txn_status ? o->txn_status : '?',
           o->flags, tlen, o->text ? o->text : "", o->text_len > LK_QUERY_TEXT_LOG_MAX ? "..." : "");
}

/* PG parser counters (stage 3). The skeleton (task 3.1) only tallies messages,
 * so print the totals plus the per-type breakdown its stubs produce — the
 * proof that live traffic is reaching the handler. Printable types show as the
 * PG letter, others as 0xNN; startup-framed messages have type 0. */
static void append_type_counts(char *buf, size_t n, const __u64 *by_type)
{
    size_t off = 0;

    for (unsigned t = 0; t < 256 && off < n; t++) {
        if (!by_type[t])
            continue;
        if (t >= 0x20 && t < 0x7f)
            off += snprintf(buf + off, off < n ? n - off : 0, " %c=%llu", (char)t,
                            (unsigned long long)by_type[t]);
        else
            off += snprintf(buf + off, off < n ? n - off : 0, " 0x%02x=%llu", t,
                            (unsigned long long)by_type[t]);
    }
}

static void print_proto_stats(const struct lk_proto_stats *ps)
{
    char fe[256] = {0}, be[256] = {0};

    fprintf(stderr, "latkit: pg msgs=%llu startup=%llu resyncs=%llu conns=%llu\n",
            (unsigned long long)ps->msgs, (unsigned long long)ps->startup_msgs,
            (unsigned long long)ps->resyncs, (unsigned long long)ps->conns);
    fprintf(stderr,
            "latkit: pg sessions=%llu queries=%llu errors_sql=%llu "
            "parse_errors=%llu unknown=%llu replication=%llu\n",
            (unsigned long long)ps->sessions, (unsigned long long)ps->queries,
            (unsigned long long)ps->errors_sql, (unsigned long long)ps->parse_errors,
            (unsigned long long)ps->unknown_msgs, (unsigned long long)ps->replication_conns);
    fprintf(stderr, "latkit: pg units_dropped resync=%llu close=%llu overflow=%llu\n",
            (unsigned long long)ps->units_dropped_resync, (unsigned long long)ps->units_dropped_close,
            (unsigned long long)ps->units_dropped_overflow);
    append_type_counts(fe, sizeof(fe), ps->by_type[LK_DIR_RECV]);
    append_type_counts(be, sizeof(be), ps->by_type[LK_DIR_SEND]);
    fprintf(stderr, "latkit: pg types fe:%s | be:%s\n", fe, be);
}

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

    const struct lk_conn_table_stats *cs = lk_conn_table_stats(e->pipe.conns);

    fprintf(stderr,
            "latkit: conns active=%u created=%llu closed=%llu "
            "evicted=%llu (lru %llu, idle %llu) gaps=%llu lost=%llu\n",
            cs->active, (unsigned long long)cs->created, (unsigned long long)cs->closed,
            (unsigned long long)(cs->evicted_lru + cs->evicted_idle),
            (unsigned long long)cs->evicted_lru, (unsigned long long)cs->evicted_idle,
            (unsigned long long)cs->seq_gaps, (unsigned long long)cs->lost_events);

    const struct lk_reasm_stats *rs = &e->pipe.reasm.st;

    fprintf(stderr,
            "latkit: msgs total=%llu trunc=%llu holes=%llu (%llu bytes) "
            "dirty: badlen=%llu hdr-hole=%llu off-anomaly=%llu "
            "resync=%llu tls=%llu\n",
            (unsigned long long)rs->msgs, (unsigned long long)rs->msgs_trunc,
            (unsigned long long)rs->holes, (unsigned long long)rs->hole_bytes,
            (unsigned long long)rs->bad_len, (unsigned long long)rs->hdr_holes,
            (unsigned long long)rs->off_anomalies, (unsigned long long)rs->resyncs,
            (unsigned long long)rs->tls_conns);

    print_proto_stats(lk_proto_stats(e->proto));
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

/* Framer sink installed by events.c: it tees every message into the PG parser
 * (the standard consumer since stage 3) and, when --messages is on, also logs
 * it. The stage-2 logger thus survives as a debug mirror alongside the parser
 * (STAGE3.md task 3.1). --hexdump adds the captured body prefix. fe> is the
 * frontend->backend stream (RECV on the server socket), <be the reverse. */
static void on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct lk_events *e = ctx;
    char type[8];

    if (e->proto_sink->on_msg)
        e->proto_sink->on_msg(e->proto_sink->ctx, c, dir, m);

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

/* Resync log pairs with the gap/dirty messages on stderr: "gap -> resync" in
 * the log is the loss-recovery cycle working as designed (Р10). */
static void on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    struct lk_events *e = ctx;

    fprintf(stderr, "latkit: conn=%llx resync (%s)\n", (unsigned long long)c->cookie,
            dir == LK_DIR_RECV ? "fe>" : "<be");
    if (e->proto_sink->on_resync)
        e->proto_sink->on_resync(e->proto_sink->ctx, c, dir);
}

/* Connection removed from the table (any path): let the parser free its
 * per-connection state (Р15). The pipeline routes the conn-table destroy hook
 * here through the framer sink. */
static void on_conn_close(void *ctx, struct lk_conn *c)
{
    struct lk_events *e = ctx;

    if (e->proto_sink->on_conn_close)
        e->proto_sink->on_conn_close(e->proto_sink->ctx, c);
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
    struct lk_pipeline_ev ev;

    /* --record (Р14): dump the record verbatim before decoding, so the trace
     * is exactly what the kernel emitted and replays through this same path. */
    lk_recorder_write(e->rec, data, size);

    lk_pipeline_feed(&e->pipe, data, size, &ev);
    switch (ev.status) {
    case LK_DEC_CONN:
        if (ev.view.hdr->type == LK_EV_CONN_OPEN && e->cfg.cap_headers)
            set_cap_headers(e->cfg.conns, ev.view.hdr->conn_id);
        if (e->cfg.events)
            print_conn_event(ev.view.conn);
        break;
    case LK_DEC_DATA:
        if (e->cfg.events)
            print_data_event(ev.view.data, ev.view.cap_len, e->cfg.hexdump);
        if (ev.tls_now) {
            /* TLS accepted: the ciphertext is useless to the framer, so
             * shrink what the kernel captures for this connection (the
             * plaintext source will be the stage-6 uprobe channel). */
            fprintf(stderr, "latkit: conn=%llx TLS detected, framing off\n",
                    (unsigned long long)ev.view.hdr->conn_id);
            set_cap_headers(e->cfg.conns, ev.view.hdr->conn_id);
        }
        break;
    case LK_DEC_UNKNOWN:
        fprintf(stderr, "warn: unknown event type %u (size %zu)\n",
                ((const struct lk_ev_hdr *)data)->type, size);
        return 0;
    case LK_DEC_SHORT:
    default:
        return 0;
    }

    if (ev.lost)
        fprintf(stderr, "latkit: conn=%llx gap detected (lost %u events), both directions dirty\n",
                (unsigned long long)ev.view.hdr->conn_id, ev.lost);
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
    n = lk_conn_table_sweep(e->pipe.conns, (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec);
    if (n)
        fprintf(stderr, "latkit: idle sweep evicted %u connection(s)\n", n);
}

struct lk_events *lk_events_new(const struct lk_events_cfg *cfg)
{
    struct lk_events *e = calloc(1, sizeof(*e));
    struct lk_msg_sink sink = {
        .ctx = e, .on_msg = on_msg, .on_resync = on_resync, .on_conn_close = on_conn_close};

    if (!e)
        return NULL;
    e->cfg = *cfg;
    /* The PG handler is the standard consumer of the framer (Р15). With
     * --queries its upward sink is the logger below (task 3.2: sessions +
     * CANCEL; the full query line arrives with 3.3); without it the parser
     * still runs and its counters still accrue, just with no per-observation
     * output. events.c's own message sink (above) tees messages into the parser
     * and mirrors them to the --messages logger. */
    e->proto = lk_proto_pg_new(cfg->queries ? &(struct lk_query_sink){.on_session = on_session,
                                                                       .on_query = on_query}
                                            : NULL);
    if (!e->proto) {
        free(e);
        return NULL;
    }
    e->proto_sink = lk_proto_sink(e->proto);
    if (lk_pipeline_init(&e->pipe, cfg->max_conns, cfg->conn_idle_timeout_sec * 1000000000ULL,
                         &sink)) {
        lk_proto_free(e->proto);
        free(e);
        return NULL;
    }
    if (cfg->record_path) {
        e->rec = lk_recorder_open(cfg->record_path);
        if (!e->rec) {
            fprintf(stderr, "failed to open --record file '%s': %s\n", cfg->record_path,
                    strerror(errno));
            lk_pipeline_fini(&e->pipe);
            lk_proto_free(e->proto);
            free(e);
            return NULL;
        }
    }
    e->rb = ring_buffer__new(bpf_map__fd(cfg->ringbuf), handle_event, e, NULL);
    if (!e->rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        lk_recorder_close(e->rec);
        lk_pipeline_fini(&e->pipe);
        lk_proto_free(e->proto);
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
    if (lk_recorder_close(e->rec))
        fprintf(stderr, "warn: --record file may be incomplete (write error)\n");
    /* Tear the table down first: its destroy hooks free every connection's
     * proto_state through the parser, which must still be alive here. */
    lk_pipeline_fini(&e->pipe);
    lk_proto_free(e->proto);
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
