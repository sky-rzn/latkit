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

#include "cgroup_filter.h"
#include "conn_table.h"
#include "decode.h"
#include "latkit.h"
#include "loop.h"
#include "metrics.h"
#include "otlp.h"
#include "pipeline.h"
#include "prom.h"
#include "proto.h"
#include "reassembly.h"
#include "record.h"
#include "selfstats.h"
#include "tls_attach.h"

#define LK_STATS_INTERVAL_SEC 10
#define LK_SWEEP_INTERVAL_SEC 60

struct lk_events {
    struct lk_events_cfg cfg;
    struct ring_buffer *rb;
    struct lk_pipeline pipe;              /* decode -> conn table -> framer (Р14) */
    struct lk_proto *proto;               /* PG handler: the standard framer sink */
    const struct lk_msg_sink *proto_sink; /* = lk_proto_sink(proto) */
    struct lk_recorder *rec;              /* --record trace writer, NULL when off */
    struct lk_metrics *metrics;           /* aggregator: the parser's standard consumer */
    const struct lk_query_sink *msink;    /* = lk_metrics_query_sink(metrics) */
    struct lk_query_sink qsink;           /* tee installed into the parser (below) */
    /* Fan-out list the tee drives (Р32): the aggregator always, plus the span
     * collector when spans are enabled. --queries is a separate debug mirror. */
    const struct lk_query_sink *qsinks[2];
    int n_qsinks;
    struct lk_selfstats *selfstats; /* process_* provider (task 4.4) */
    struct lk_prom *prom;           /* Prometheus /metrics server (task 5.1), NULL if off */
    struct lk_otlp *otlp;           /* OTLP/HTTP push exporter (task 5.2), NULL if off */
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
           s->user[0] ? s->user : "?", s->database[0] ? s->database : "?", s->app[0] ? s->app : "?",
           s->server_version[0] ? s->server_version : "?", s->complete ? "" : " (incomplete)");
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
           o->flags, tlen, o->text ? o->text : "",
           o->text_len > LK_QUERY_TEXT_LOG_MAX ? "..." : "");
}

/* Tee query sink (task 4.3, generalised to a list in task 5.3): the parser's
 * consumers are now a small fan-out — the metrics aggregator always, the span
 * collector when spans are on (Р32). --queries keeps the stage-3 logger, run
 * first as a debug mirror; the logger takes no ctx, so it is called with NULL.
 * on_txn has no log line and no span consumer. */
static void ev_on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    struct lk_events *e = ctx;

    if (e->cfg.queries)
        on_session(NULL, c, s);
    for (int i = 0; i < e->n_qsinks; i++)
        if (e->qsinks[i]->on_session)
            e->qsinks[i]->on_session(e->qsinks[i]->ctx, c, s);
}

static void ev_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                        const struct lk_query_obs *o)
{
    struct lk_events *e = ctx;

    if (e->cfg.queries)
        on_query(NULL, c, s, o);
    for (int i = 0; i < e->n_qsinks; i++)
        if (e->qsinks[i]->on_query)
            e->qsinks[i]->on_query(e->qsinks[i]->ctx, c, s, o);
}

static void ev_on_txn(void *ctx, const struct lk_conn *c, __u64 start_ns, __u64 end_ns,
                      char final_status)
{
    struct lk_events *e = ctx;

    for (int i = 0; i < e->n_qsinks; i++)
        if (e->qsinks[i]->on_txn)
            e->qsinks[i]->on_txn(e->qsinks[i]->ctx, c, start_ns, end_ns, final_status);
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
    fprintf(stderr,
            "latkit: pg units_dropped resync=%llu close=%llu overflow=%llu prep_evictions=%llu\n",
            (unsigned long long)ps->units_dropped_resync,
            (unsigned long long)ps->units_dropped_close,
            (unsigned long long)ps->units_dropped_overflow, (unsigned long long)ps->prep_evictions);
    append_type_counts(fe, sizeof(fe), ps->by_type[LK_DIR_RECV]);
    append_type_counts(be, sizeof(be), ps->by_type[LK_DIR_SEND]);
    fprintf(stderr, "latkit: pg types fe:%s | be:%s\n", fe, be);
}

/* Sum the per-CPU kernel `stats` counters into sum[]. Both the human stats line
 * and the metrics provider (Р27) read the kernel counters through here, so the
 * numbers in the log and in the exposition come from one source. Returns false
 * (sum left zeroed) if the CPU count is unavailable; a per-id lookup failure
 * leaves that counter at 0 rather than aborting the whole read. */
static bool sum_kernel_stats(struct lk_events *e, __u64 sum[LK_ST_MAX])
{
    int ncpus = libbpf_num_possible_cpus();
    __u64 *vals;

    memset(sum, 0, LK_ST_MAX * sizeof(sum[0]));
    if (ncpus < 1)
        return false;
    vals = calloc(ncpus, sizeof(*vals));
    if (!vals)
        return false;
    for (__u32 id = 0; id < LK_ST_MAX; id++) {
        if (bpf_map__lookup_elem(e->cfg.stats, &id, sizeof(id), vals, ncpus * sizeof(*vals), 0))
            continue; /* leaves the counter at 0 rather than aborting */
        for (int cpu = 0; cpu < ncpus; cpu++)
            sum[id] += vals[cpu];
    }
    free(vals);
    return true;
}

/* --- TLS self-metrics (Р41, stage 6.5) ------------------------------------
 * The stage-6 TLS observability series, poured from the same three sources the
 * plaintext self-metrics use: the kernel per-CPU counters (uprobe events,
 * decrypted bytes, correlation misses — `sum`, NULL if the map read failed),
 * the conn table (live/lifetime TLS connection counts, ciphertext drops), and
 * the uprobe manager (attach state). The two byte/event families carry no
 * {fn}/{dir} label: the kernel counts them without that split (the same
 * documented Р27 deviation as latkit_events_total), so the label the spec
 * sketches would always be a single value — omitted rather than faked. */
static void ev_provide_tls_stats(struct lk_events *e, struct lk_metrics *m, const __u64 *sum,
                                 const struct lk_conn_table_stats *cs)
{
    static const char *const states[] = {"none", "partial", "ok"};
    enum lk_tls_state st = e->cfg.tls ? lk_tls_status(e->cfg.tls) : LK_TLS_STATE_NONE;

    /* One series per state, 1 on the live one — a Prometheus enum gauge. */
    for (unsigned i = 0; i < 3; i++)
        lk_metrics_set_gauge_l(m, "latkit_tls_attached",
                               i == 0 ? "libssl uprobe attach state (1 on the active state)." : NULL,
                               "state", states[i], (unsigned)st == i ? 1.0 : 0.0);

    lk_metrics_set_gauge(m, "latkit_tls_connections", "TLS connections currently tracked.",
                         (double)cs->tls_active);
    lk_metrics_set_counter(m, "latkit_tls_connections_total",
                           "TLS connections seen since start.", (double)cs->tls_opened);
    lk_metrics_set_counter(m, "latkit_tls_socket_events_dropped_total",
                           "Ciphertext socket events dropped on TLS connections.",
                           (double)cs->tls_socket_dropped);

    if (sum) {
        lk_metrics_set_counter(m, "latkit_tls_uprobe_events_total",
                               "Decrypted plaintext events submitted from SSL_* uprobes.",
                               (double)sum[LK_ST_TLS_UPROBE_EVENTS]);
        lk_metrics_set_counter(m, "latkit_tls_decrypted_bytes_total",
                               "Decrypted plaintext bytes captured (cap_len).",
                               (double)sum[LK_ST_TLS_DECRYPTED_BYTES]);
        lk_metrics_set_counter(m, "latkit_tls_correlation_misses_total",
                               "Decrypted events dropped for a missing SSL-to-cookie link.",
                               (double)sum[LK_ST_TLS_CORR_MISS]);
    }
}

/* --- self-metric provider (task 4.4, Р27) ---------------------------------
 * events.c is the only place that touches libbpf, so this is where the kernel
 * per-CPU counters, the framer/parser/conn-table stats become metric series;
 * the facade stays oblivious to the BPF maps. Installed via
 * lk_metrics_add_provider, it runs at the top of every lk_metrics_dump — the
 * same source structs the 10 s stats line reads, so log and exposition agree. */
static void ev_provide_stats(void *ctx, struct lk_metrics *m)
{
    struct lk_events *e = ctx;
    __u64 sum[LK_ST_MAX];
    bool sum_ok = sum_kernel_stats(e, sum);

    if (sum_ok) {
        __u64 drops = sum[LK_ST_RESERVE_FAIL_DATA] + sum[LK_ST_RESERVE_FAIL_OPEN] +
                      sum[LK_ST_RESERVE_FAIL_CLOSE];

        lk_metrics_set_counter(m, "latkit_ringbuf_dropped_total",
                               "Ringbuf records the kernel could not reserve.", (double)drops);
        /* The kernel stats map counts records without a direction split, so this
         * family carries no {dir} label — a documented deviation from Р27. */
        lk_metrics_set_counter(m, "latkit_events_total", "Records submitted to the ringbuf.",
                               (double)sum[LK_ST_EVENTS]);
    }

    const struct lk_reasm_stats *rs = &e->pipe.reasm.st;

    lk_metrics_set_counter(m, "latkit_resync_total",
                           "Stream directions resynchronised after a loss.", (double)rs->resyncs);

    const struct lk_proto_stats *ps = lk_proto_stats(e->proto);

    lk_metrics_set_counter(m, "latkit_parse_errors_total",
                           "Protocol fields the parser rejected as corrupt.",
                           (double)ps->parse_errors);
    lk_metrics_set_counter(m, "latkit_unknown_msgs_total",
                           "Unknown message types skipped by length.", (double)ps->unknown_msgs);
    /* Р19 blind spot ("query cut off mid-flight") now has a counter, split by
     * why the in-flight unit was dropped. */
    lk_metrics_set_counter_l(m, "latkit_queries_dropped_total",
                             "In-flight query units dropped before completion.", "reason", "resync",
                             (double)ps->units_dropped_resync);
    lk_metrics_set_counter_l(m, "latkit_queries_dropped_total", NULL, "reason", "disconnect",
                             (double)ps->units_dropped_close);
    lk_metrics_set_counter_l(m, "latkit_queries_dropped_total", NULL, "reason", "overflow",
                             (double)ps->units_dropped_overflow);

    const struct lk_conn_table_stats *cs = lk_conn_table_stats(e->pipe.conns);

    lk_metrics_set_gauge(m, "latkit_connections_active", "Connections currently tracked.",
                         (double)cs->active);
    lk_metrics_set_counter(m, "latkit_connections_opened_total", "Connections opened since start.",
                           (double)cs->created);
    lk_metrics_set_counter_l(m, "latkit_conns_evicted_total", "Connections evicted from the table.",
                             "reason", "lru", (double)cs->evicted_lru);
    lk_metrics_set_counter_l(m, "latkit_conns_evicted_total", NULL, "reason", "idle",
                             (double)cs->evicted_idle);

    ev_provide_tls_stats(e, m, sum_ok ? sum : NULL, cs);

    /* cgroup filter observability (Р48): the number of cgroupfs paths the last
     * re-resolve matched. 0 while a --cgroup pattern is set exposes a misconfig
     * (the glob matched nothing, so the map is empty and the filter is off).
     * Exported only when --cgroup was given — a bare 0 otherwise would be noise. */
    if (lk_cgroup_enabled(e->cfg.cgroup))
        lk_metrics_set_gauge(m, "latkit_cgroup_filter_paths",
                             "cgroupfs paths currently matched by the --cgroup filter.",
                             (double)lk_cgroup_paths(e->cfg.cgroup));
}

/* /healthz liveness source (task 5.1): the Prometheus server lives in src/export
 * and must not touch libbpf, so it pulls the two counters it reports through
 * this callback — the same kernel `stats` map as the exposition and the log. */
static void ev_provide_health(void *ctx, struct lk_prom_health *out)
{
    struct lk_events *e = ctx;
    __u64 sum[LK_ST_MAX];

    if (!sum_kernel_stats(e, sum))
        return; /* out->valid stays false: the body omits the counters */
    out->events_total = sum[LK_ST_EVENTS];
    out->ringbuf_dropped_total =
        sum[LK_ST_RESERVE_FAIL_DATA] + sum[LK_ST_RESERVE_FAIL_OPEN] + sum[LK_ST_RESERVE_FAIL_CLOSE];
    out->valid = true;
}

/* --- global stats (task 1.5) ---------------------------------------------
 * Sum the per-CPU `stats` counters and print one line to stderr; called
 * every LK_STATS_INTERVAL_SEC from the loop and once on exit. */
void lk_events_print_stats(struct lk_events *e)
{
    __u64 sum[LK_ST_MAX], drops;

    if (!sum_kernel_stats(e, sum))
        return;

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
            "evicted=%llu (lru %llu, idle %llu) gaps=%llu lost=%llu tls_drop=%llu\n",
            cs->active, (unsigned long long)cs->created, (unsigned long long)cs->closed,
            (unsigned long long)(cs->evicted_lru + cs->evicted_idle),
            (unsigned long long)cs->evicted_lru, (unsigned long long)cs->evicted_idle,
            (unsigned long long)cs->seq_gaps, (unsigned long long)cs->lost_events,
            (unsigned long long)cs->tls_socket_dropped);

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

/* Flip a connection into HEADERS capture (Р21) by writing its cookie into the
 * `capmode` map. This is a blind insert into a map the kernel only reads, so —
 * unlike the stage-1 hook it replaces — there is no read-modify-write of
 * lk_conn_state and thus no race that could clobber the kernel's seq/dropped
 * counters. The entry ages out by LRU or is deleted on CONN_CLOSE. */
static void set_cap_headers(struct bpf_map *capmode, __u64 cookie)
{
    __u8 mode = LK_CAP_HEADERS;

    if (bpf_map__update_elem(capmode, &cookie, sizeof(cookie), &mode, sizeof(mode), BPF_ANY))
        fprintf(stderr, "warn: conn=%llx: failed to set HEADERS mode\n",
                (unsigned long long)cookie);
}

/* Capture policy (Р21): a connection whose payload will never be needed again —
 * TLS (ciphertext), CancelRequest, or a replication/walsender stream — is
 * flipped to HEADERS so its bytes stop travelling the ringbuf. Deliberately
 * one-directional and one-shot (LK_CONN_CAP_HEADERS guards against re-writing
 * the map on every subsequent event): no FULL<->HEADERS flapping, which at a
 * deep ringbuf would only mis-cut events already in flight. */
static void apply_cap_policy(struct lk_events *e, struct lk_conn *c)
{
    if (!c || (c->flags & LK_CONN_CAP_HEADERS))
        return;
    if (!(c->flags & (LK_CONN_TLS | LK_CONN_CANCEL | LK_CONN_REPLICATION)))
        return;
    set_cap_headers(e->cfg.capmode, c->cookie);
    c->flags |= LK_CONN_CAP_HEADERS;
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
        if (ev.view.hdr->type == LK_EV_CONN_OPEN && e->cfg.cap_headers && ev.conn) {
            /* --cap-headers test hook: cap every connection from its first byte. */
            set_cap_headers(e->cfg.capmode, ev.view.hdr->conn_id);
            ev.conn->flags |= LK_CONN_CAP_HEADERS;
        }
        if (ev.view.hdr->type == LK_EV_CONN_CLOSE)
            /* Drop the override so a recycled cookie starts at FULL (LRU would
             * eventually reclaim it anyway). */
            bpf_map__delete_elem(e->cfg.capmode, &ev.view.hdr->conn_id,
                                 sizeof(ev.view.hdr->conn_id), 0);
        if (e->cfg.events)
            print_conn_event(ev.view.conn);
        break;
    case LK_DEC_DATA:
        if (e->cfg.events)
            print_data_event(ev.view.data, ev.view.cap_len, e->cfg.hexdump);
        if (ev.tls_now)
            /* One-time log; the HEADERS flip itself is apply_cap_policy's job
             * (LK_CONN_TLS is set by now). Ciphertext socket events are dropped
             * from here on and the framer has been reset to startup — the
             * plaintext source is now the stage-6 uprobe channel (Р38). */
            fprintf(stderr, "latkit: conn=%llx TLS detected, switching to decrypted channel\n",
                    (unsigned long long)ev.view.hdr->conn_id);
        if (ev.decrypted_early)
            /* Р38 says 'S' precedes any decrypted byte; if this fires the
             * correlation or ordering assumption broke — frame it best-effort. */
            fprintf(stderr, "latkit: conn=%llx decrypted event before TLS handshake\n",
                    (unsigned long long)ev.view.hdr->conn_id);
        /* TLS / CANCEL / replication -> HEADERS (Р21). The PG parser ran inside
         * lk_pipeline_feed above, so a CopyBoth this event carried already set
         * LK_CONN_REPLICATION on ev.conn. */
        apply_cap_policy(e, ev.conn);
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

    /* The metrics aggregator (task 4.3) is the parser's standard consumer (Р26);
     * it is always present so counters accrue regardless of output flags. */
    struct lk_metrics_cfg mcfg;

    lk_metrics_cfg_defaults(&mcfg);
    if (cfg->top_queries)
        mcfg.top_queries = cfg->top_queries;
    if (cfg->query_label_len)
        mcfg.query_label_len = cfg->query_label_len;
    mcfg.first_row_hist = cfg->first_row_hist;
    e->metrics = lk_metrics_new(&mcfg);
    if (!e->metrics) {
        free(e);
        return NULL;
    }
    e->msink = lk_metrics_query_sink(e->metrics);
    e->qsinks[e->n_qsinks++] = e->msink; /* the aggregator; spans join in register */

    /* Self-metric providers (Р27), invoked at every dump: the agent-side
     * counters (kernel/framer/parser/conn-table) and process_* (getrusage /
     * procfs). Registered unconditionally — they only cost anything on a dump.
     * selfstats is optional; without it process_* is simply absent. */
    lk_metrics_add_provider(e->metrics, ev_provide_stats, e);
    e->selfstats = lk_selfstats_new();
    if (e->selfstats)
        lk_metrics_add_provider(e->metrics, lk_selfstats_provide, e->selfstats);

    /* Install a tee (ev_*) as the parser's upward sink: it fans every
     * observation into the aggregator and, with --queries, the stage-3 logger
     * (Р15). events.c's own message sink (above) similarly tees messages into
     * the parser and mirrors them to the --messages logger. */
    e->qsink = (struct lk_query_sink){
        .ctx = e, .on_session = ev_on_session, .on_query = ev_on_query, .on_txn = ev_on_txn};
    e->proto = lk_proto_pg_new(&e->qsink);
    if (!e->proto) {
        lk_selfstats_free(e->selfstats);
        lk_metrics_free(e->metrics);
        free(e);
        return NULL;
    }
    e->proto_sink = lk_proto_sink(e->proto);
    if (lk_pipeline_init(&e->pipe, cfg->max_conns, cfg->conn_idle_timeout_sec * 1000000000ULL,
                         &sink)) {
        lk_proto_free(e->proto);
        lk_selfstats_free(e->selfstats);
        lk_metrics_free(e->metrics);
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
            lk_metrics_free(e->metrics);
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
        lk_selfstats_free(e->selfstats);
        lk_metrics_free(e->metrics);
        free(e);
        return NULL;
    }
    return e;
}

/* Write the exposition to the --dump-metrics target (task 4.3). The registered
 * providers (task 4.4) refresh every self / connection series from its live
 * source inside lk_metrics_dump, so there is nothing to prime here. */
void lk_events_dump_metrics(struct lk_events *e)
{
    FILE *f = stderr;
    bool close_f = false;

    if (!e->cfg.dump_metrics)
        return;

    if (e->cfg.dump_metrics_path) {
        f = fopen(e->cfg.dump_metrics_path, "w");
        if (!f) {
            fprintf(stderr, "latkit: --dump-metrics: cannot open '%s': %s\n",
                    e->cfg.dump_metrics_path, strerror(errno));
            return;
        }
        close_f = true;
    }
    lk_metrics_dump(e->metrics, f);
    if (close_f)
        fclose(f);
}

void lk_events_free(struct lk_events *e)
{
    if (!e)
        return;
    /* Tear the HTTP server down first: it deregisters its fds from the loop, so
     * it must go before the loop is freed (main frees events before the loop). */
    lk_otlp_free(e->otlp);
    lk_prom_free(e->prom);
    ring_buffer__free(e->rb);
    if (lk_recorder_close(e->rec))
        fprintf(stderr, "warn: --record file may be incomplete (write error)\n");
    /* Tear the table down first: its destroy hooks free every connection's
     * proto_state through the parser, which must still be alive here. */
    lk_pipeline_fini(&e->pipe);
    lk_proto_free(e->proto);
    lk_selfstats_free(e->selfstats);
    lk_metrics_free(e->metrics);
    free(e);
}

static void on_dump_signal(void *ctx)
{
    lk_events_dump_metrics(ctx);
}

int lk_events_register(struct lk_events *e, struct lk_loop *loop)
{
    int err = lk_loop_add_fd(loop, ring_buffer__epoll_fd(e->rb), on_ringbuf_ready, e);

    if (err)
        return err;
    err = lk_loop_every(loop, LK_STATS_INTERVAL_SEC, on_stats_tick, e);
    if (err)
        return err;
    if (e->cfg.dump_metrics) /* SIGUSR1 -> dump the exposition on demand */
        lk_loop_on_sigusr1(loop, on_dump_signal, e);
    err = lk_loop_every(loop, LK_SWEEP_INTERVAL_SEC, on_sweep_tick, e);
    if (err)
        return err;

    /* Prometheus /metrics + /healthz server (task 5.1). A bind failure is fatal
     * by design (Р29): fail startup rather than silently run without the pull
     * endpoint. "none" opts out. */
    if (e->cfg.prom_listen && strcmp(e->cfg.prom_listen, "none") != 0) {
        struct lk_prom_cfg pc = {
            .bind_addr = e->cfg.prom_listen,
            .metrics = e->metrics,
            .health_fn = ev_provide_health,
            .health_ctx = e,
        };

        e->prom = lk_prom_new(loop, &pc);
        if (!e->prom) {
            fprintf(stderr, "latkit: cannot start Prometheus listener on %s\n", e->cfg.prom_listen);
            return -1;
        }
        fprintf(stderr, "latkit: serving Prometheus /metrics and /healthz on %s (port %d)\n",
                e->cfg.prom_listen, lk_prom_port(e->prom));
    }

    /* OTLP/HTTP push exporter (task 5.2, Р31). Enabled by an endpoint; a bad
     * endpoint (unparseable URL, https) is fatal like a bad bind — fail loudly
     * rather than run half-configured. A collector that is merely down at start
     * is tolerated (lk_otlp_new resolves lazily and drops batches meanwhile). */
    if (e->cfg.otlp_endpoint && e->cfg.otlp_endpoint[0]) {
        struct lk_otlp_cfg oc = {
            .endpoint = e->cfg.otlp_endpoint,
            .interval_sec = e->cfg.otlp_interval,
            .headers = e->cfg.otlp_headers,
            .nheaders = e->cfg.otlp_nheaders,
            .resource_attrs = e->cfg.otlp_resource,
            .nresource = e->cfg.otlp_nresource,
            .service_name = e->cfg.otlp_service_name,
            .span_sample_ratio = e->cfg.otlp_span_ratio,
            .span_slow_ms = e->cfg.otlp_span_slow_ms,
            .span_text_max = e->cfg.otlp_span_text_max,
            .span_masked = e->cfg.otlp_span_masked,
        };

        e->otlp = lk_otlp_new(loop, e->metrics, &oc);
        if (!e->otlp) {
            fprintf(stderr, "latkit: cannot start OTLP exporter for %s\n", e->cfg.otlp_endpoint);
            return -1;
        }
        fprintf(stderr, "latkit: exporting OTLP metrics to %s every %us\n", e->cfg.otlp_endpoint,
                e->cfg.otlp_interval ? e->cfg.otlp_interval : 15);

        /* Add the span collector to the parser's fan-out (Р32). The tee reads
         * qsinks[] live, so a sink added here — after the parser was built in
         * lk_events_new — takes effect on the next observation. */
        const struct lk_query_sink *ss = lk_otlp_span_sink(e->otlp);

        if (ss && e->n_qsinks < (int)(sizeof(e->qsinks) / sizeof(e->qsinks[0]))) {
            e->qsinks[e->n_qsinks++] = ss;
            fprintf(stderr, "latkit: OTLP spans enabled%s (ratio=%g slow=%ums)\n",
                    e->cfg.otlp_span_masked ? " (masked)" : "", e->cfg.otlp_span_ratio,
                    e->cfg.otlp_span_slow_ms);
        }
    } else if (e->cfg.otlp_span_ratio > 0 || e->cfg.otlp_span_slow_ms) {
        fprintf(stderr,
                "latkit: --otlp-spans* ignored without --otlp-endpoint (nowhere to send)\n");
    }
    return 0;
}
