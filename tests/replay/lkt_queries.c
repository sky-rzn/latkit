// SPDX-License-Identifier: GPL-2.0
/* Dev tool: the agent's --queries view over recorded LKT1 traces (MYSQL.md М3
 * and PLAN-HTTP.md М3 acceptance — "--queries over the М0 corpus yields the
 * expected observations, parse_errors == 0 on clean traces"). Replays each file
 * through the same lk_pipeline the live agent runs, with the *real* protocol
 * handler installed as the framer sink, and prints one line per session /
 * observation / transaction in the events.c --queries format, plus a per-file
 * parser summary.
 *
 *   lkt_queries [--proto pg|mysql|http] [--http-user basic] [--http-redact off]
 *              [--quiet] [--metrics] [--spans RATIO] FILE.lkt...
 *
 * --proto sets the protocol every connection frames and parses as (default pg,
 * the registry head). --quiet drops the per-observation lines, leaving the
 * summaries. --metrics additionally tees every observation into the real
 * aggregator and prints the Prometheus exposition once, after the last file
 * (PLAN-HTTP.md М5 acceptance: the families a recorded workload actually
 * produces, over the same registry the live agent runs). --spans RATIO tees
 * them into the real span collector as well and prints one line per sampled
 * span after each file (PLAN-HTTP.md М6 acceptance): with RATIO 0 the only
 * spans that appear are the ones an inbound `traceparent` asked for, which is
 * how the corpus proves parent-based sampling on real recorded traffic. Exit is
 * nonzero only when a file fails to replay; the counters are diagnostics — the
 * expectation tables live in the acceptance scripts (queries_traces.sh,
 * http_queries_traces.sh).
 *
 * An HTTP observation prints in its own shape rather than the query one: its
 * identity is a method and a target, its outcome a status, and it carries four
 * timings instead of two (РH5). Printing it through the SQL-shaped line would
 * hide exactly the fields the М3 acceptance table checks. */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "metrics.h"
#include "pipeline.h"
#include "proto.h"
#include "record.h"
#include "spans.h"

static bool quiet;
/* NULL unless --metrics: the aggregator every observation is teed into, kept
 * across the whole argument list so one exposition covers the corpus. */
static struct lk_metrics *metrics;
static const struct lk_query_sink *msink;
/* NULL unless --spans: the real collector (spans.c), with a fixed seed so a
 * ratio draw is reproducible across runs. */
static struct lk_spans *spans;
static const struct lk_query_sink *ssink;

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
    case LK_Q_REQUEST:
        return "request";
    default:
        return "?";
    }
}

static void on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    (void)ctx;
    if (msink)
        msink->on_session(msink->ctx, c, s);
    if (quiet)
        return;
    printf("session conn=%llx user=%s db=%s app=%s ver=%s%s\n", (unsigned long long)c->cookie,
           s->user[0] ? s->user : "?", s->database[0] ? s->database : "?", s->app[0] ? s->app : "?",
           s->server_version[0] ? s->server_version : "?", s->complete ? "" : " (incomplete)");
}

#define TEXT_LOG_MAX 120

/* Elapsed ns between two stamps, 0 when the later one is missing or the pair is
 * out of order — a degraded unit must print a zero, never a wrapped u64. */
static __u64 delta(__u64 from, __u64 to)
{
    return to > from ? to - from : 0;
}

/* One HTTP observation (РH5/РH10): method, target, status, the byte counts in
 * both directions, and the three intervals the four stamps define — upload (the
 * client's), ttfb and duration (the server's). */
static void on_http_query(const struct lk_conn *c, const struct lk_session *s,
                          const struct lk_query_obs *o)
{
    int tlen = o->text_len > TEXT_LOG_MAX ? TEXT_LOG_MAX : (int)o->text_len;

    /* The request id is printed beside the timings, not only in the span, so
     * this view is joinable with a server's own access log one request at a
     * time (PLAN-HTTP.md М8's accuracy bench). It is a correlation id the
     * client put on the wire for exactly that purpose — nothing РH12 protects. */
    printf("http conn=%llx method=%s status=%u dur=%lluns ttfb=%lluns upload=%lluns "
           "in=%llu out=%llu host=%s user=%s flags=0x%x reqid=%s route=%s target=%.*s%s\n",
           (unsigned long long)c->cookie, o->op ? o->op : "?", o->err_code,
           (unsigned long long)delta(o->ts_req_done_ns, o->ts_complete_ns),
           (unsigned long long)delta(o->ts_req_done_ns, o->ts_first_row_ns),
           (unsigned long long)delta(o->ts_start_ns, o->ts_req_done_ns),
           (unsigned long long)o->bytes_in, (unsigned long long)o->bytes_out,
           s->database[0] ? s->database : "-", s->user[0] ? s->user : "-", o->flags,
           o->http && o->http->req_id ? o->http->req_id : "-", o->route ? o->route : "-", tlen,
           o->text ? o->text : "", o->text_len > TEXT_LOG_MAX ? "..." : "");
}

static void on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                     const struct lk_query_obs *o)
{
    __u64 dur = o->ts_complete_ns > o->ts_start_ns ? o->ts_complete_ns - o->ts_start_ns : 0;
    int tlen = o->text_len > TEXT_LOG_MAX ? TEXT_LOG_MAX : (int)o->text_len;

    (void)ctx;
    if (msink)
        msink->on_query(msink->ctx, c, s, o);
    if (ssink)
        ssink->on_query(ssink->ctx, c, s, o);
    if (quiet)
        return;
    if (o->kind == LK_Q_REQUEST) {
        on_http_query(c, s, o);
        return;
    }
    printf("query conn=%llx dur=%lluns kind=%s db=%s user=%s rows=%llu bytes=%llu "
           "sqlstate=%s txn=%c flags=0x%x text=%.*s%s\n",
           (unsigned long long)c->cookie, (unsigned long long)dur, kind_str(o->kind),
           s->database[0] ? s->database : "?", s->user[0] ? s->user : "?",
           (unsigned long long)o->rows, (unsigned long long)o->bytes,
           (o->flags & LK_QO_ERROR) ? o->sqlstate : "-", o->txn_status ? o->txn_status : '?',
           o->flags, tlen, o->text ? o->text : "", o->text_len > TEXT_LOG_MAX ? "..." : "");
}

static void on_txn(void *ctx, const struct lk_conn *c, __u64 start_ns, __u64 end_ns,
                   char final_status)
{
    (void)ctx;
    if (msink)
        msink->on_txn(msink->ctx, c, start_ns, end_ns, final_status);
    if (quiet)
        return;
    printf("txn conn=%llx dur=%lluns final=%c\n", (unsigned long long)c->cookie,
           (unsigned long long)(end_ns > start_ns ? end_ns - start_ns : 0), final_status);
}

/* One sampled span, in a line the М6 acceptance script can grep. Everything the
 * OTLP encoder would put in the payload is here in the same words, so a check
 * written against this view is a check against what leaves the agent. */
static void hexid(char *out, const __u8 *id, unsigned n)
{
    static const char hex[] = "0123456789abcdef";

    for (unsigned i = 0; i < n; i++) {
        out[i * 2] = hex[id[i] >> 4];
        out[i * 2 + 1] = hex[id[i] & 15];
    }
    out[n * 2] = '\0';
}

static void print_span(void *ctx, const struct lk_span *sp)
{
    char trace[33], parent[17], self[17];
    const struct lk_span_http *h = sp->http;

    (void)ctx;
    hexid(trace, sp->trace_id, 16);
    hexid(parent, sp->parent_id, 8);
    hexid(self, sp->span_id, 8);
    printf("span trace=%s parent=%s span=%s kind=%s name=\"%s\"", trace,
           sp->have_parent ? parent : "-", self, h ? "server" : "client", sp->name);
    if (h)
        printf(" status=%u host=%s route=%s scheme=%s ver=1.%u ua=\"%s\" client=%s reqid=%s"
               " ctype=%s tstate=\"%s\" in=%llu out=%llu",
               h->status, h->host[0] ? h->host : "-", h->route[0] ? h->route : "-",
               h->tls ? "https" : "http", h->version & 1, h->ua, h->client[0] ? h->client : "-",
               h->req_id[0] ? h->req_id : "-", h->ctype[0] ? h->ctype : "-", h->tstate,
               (unsigned long long)h->bytes_in, (unsigned long long)h->bytes_out);
    printf(" path=%.*s\n", sp->text ? (int)sp->text_len : 1, sp->text ? sp->text : "-");
}

static int on_record(void *ctx, const void *data, __u32 size)
{
    struct lk_pipeline_ev ev;

    lk_pipeline_feed(ctx, data, size, &ev);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct lk_query_sink qsink = {
        .on_query = on_query, .on_session = on_session, .on_txn = on_txn};
    const struct lk_proto_ops *ops = lk_proto_registry[0];
    /* The handler settings the flags below fill, applied once after parsing:
     * lk_proto_http_configure replaces the whole configuration, so two flags
     * calling it in turn would silently undo each other. */
    struct lk_http_cfg hcfg = {0};
    int rc = 0, first = 1;

    while (first < argc && argv[first][0] == '-') {
        if (!strcmp(argv[first], "--quiet")) {
            quiet = true;
            first++;
        } else if (!strcmp(argv[first], "--metrics")) {
            struct lk_metrics_cfg cfg;

            lk_metrics_cfg_defaults(&cfg);
            cfg.first_row_hist = true; /* the http profile's TTFB is not optional */
            metrics = lk_metrics_new(&cfg);
            if (!metrics) {
                fprintf(stderr, "metrics init failed\n");
                return 2;
            }
            msink = lk_metrics_query_sink(metrics);
            first++;
        } else if (!strcmp(argv[first], "--spans") && first + 1 < argc) {
            /* A fixed seed, because a test that samples a different set on every
             * run is a test that fails on someone else's machine. Ratio 0 leaves
             * only the parent-based path (РH11). */
            struct lk_spans_cfg cfg = {.sample_ratio = atof(argv[first + 1]), .seed = 0x5eed};

            spans = lk_spans_new(&cfg);
            if (!spans) {
                fprintf(stderr, "span collector init failed\n");
                return 2;
            }
            ssink = lk_spans_sink(spans);
            first += 2;
        } else if (!strcmp(argv[first], "--http-user") && first + 1 < argc) {
            /* РH10, the agent's --http-user: off by default here too, so the
             * acceptance script has to ask for it explicitly to see a user. */
            hcfg.user_basic = !strcmp(argv[first + 1], "basic");
            first += 2;
        } else if (!strcmp(argv[first], "--http-redact") && first + 1 < argc) {
            /* РH12, the agent's --http-redact: on by default, here as there. */
            hcfg.no_redact = !strcmp(argv[first + 1], "off");
            first += 2;
        } else if (!strcmp(argv[first], "--proto") && first + 1 < argc) {
            ops = lk_proto_find(argv[first + 1], strlen(argv[first + 1]));
            if (!ops) {
                fprintf(stderr, "unknown protocol '%s'\n", argv[first + 1]);
                return 2;
            }
            first += 2;
        } else {
            break;
        }
    }
    if (first >= argc) {
        fprintf(stderr,
                "usage: %s [--proto pg|mysql|http] [--http-user basic] [--quiet]"
                " [--metrics] [--spans RATIO] [--http-redact on|off] FILE.lkt...\n",
                argv[0]);
        return 2;
    }
    lk_proto_http_configure(&hcfg);

    for (int i = first; i < argc; i++) {
        struct lk_pipeline pipe;
        struct lk_proto *proto = ops->proto_new(&qsink);

        if (!proto) {
            fprintf(stderr, "%s: handler init failed\n", argv[i]);
            return 2;
        }
        if (lk_pipeline_init(&pipe, 1024, ~0ull, lk_proto_sink(proto))) {
            fprintf(stderr, "%s: pipeline init failed\n", argv[i]);
            lk_proto_free(proto);
            return 2;
        }
        lk_conn_table_set_protos(pipe.conns, NULL, 0, ops);
        if (lk_replay_file(argv[i], on_record, &pipe)) {
            printf("%s: REPLAY FAILED (bad magic or truncated record)\n", argv[i]);
            rc = 1;
        } else {
            /* fini first: table teardown fires the close hooks, so in-flight
             * units land in units_dropped_close before the stats print. */
            lk_pipeline_fini(&pipe);
            const struct lk_proto_stats *ps = lk_proto_stats(proto);

            printf(
                "%s: proto=%s msgs=%llu sessions=%llu queries=%llu errors_sql=%llu"
                " parse_errors=%llu unknown=%llu resyncs=%llu"
                " dropped=%llu/%llu/%llu prep_evict=%llu repl=%llu"
                " blind=%llu orphan=%llu\n",
                argv[i], ops->name, (unsigned long long)ps->msgs, (unsigned long long)ps->sessions,
                (unsigned long long)ps->queries, (unsigned long long)ps->errors_sql,
                (unsigned long long)ps->parse_errors, (unsigned long long)ps->unknown_msgs,
                (unsigned long long)ps->resyncs, (unsigned long long)ps->units_dropped_resync,
                (unsigned long long)ps->units_dropped_close,
                (unsigned long long)ps->units_dropped_overflow,
                (unsigned long long)ps->prep_evictions, (unsigned long long)ps->replication_conns,
                (unsigned long long)ps->blind_conns, (unsigned long long)ps->orphan_msgs);
            /* Drained per file, so a span line sits with the observations it
             * came from — the ring is bounded and a whole corpus would overflow
             * it, which is a property of the collector, not of this tool. */
            if (spans)
                lk_spans_drain(spans, print_span, NULL);
            lk_proto_free(proto);
            continue;
        }
        lk_pipeline_fini(&pipe);
        lk_proto_free(proto);
    }
    if (metrics) {
        lk_metrics_dump(metrics, stdout);
        lk_metrics_free(metrics);
    }
    if (spans) {
        printf("spans: sampled=%llu dropped=%llu\n",
               (unsigned long long)lk_spans_sampled_total(spans),
               (unsigned long long)lk_spans_dropped_total(spans));
        lk_spans_free(spans);
    }
    return rc;
}
