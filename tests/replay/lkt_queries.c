// SPDX-License-Identifier: GPL-2.0
/* Dev tool: the agent's --queries view over recorded LKT1 traces (MYSQL.md
 * М3 acceptance — "--queries over the М0 corpus yields the expected
 * observations, parse_errors == 0 on clean traces"). Replays each file
 * through the same lk_pipeline the live agent runs, with the *real* protocol
 * handler installed as the framer sink, and prints one line per session /
 * observation / transaction in the events.c --queries format, plus a per-file
 * parser summary.
 *
 *   lkt_queries [--proto pg|mysql] [--quiet] FILE.lkt...
 *
 * --proto sets the protocol every connection frames and parses as (default
 * pg, the registry head). --quiet drops the per-observation lines, leaving
 * the summaries. Exit is nonzero only when a file fails to replay; the
 * counters are diagnostics — the expectation table lives in the acceptance
 * script (queries_traces.sh). */
#include <linux/types.h>
#include <stdio.h>
#include <string.h>

#include "pipeline.h"
#include "proto.h"
#include "record.h"

static bool quiet;

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
    if (quiet)
        return;
    printf("session conn=%llx user=%s db=%s app=%s ver=%s%s\n", (unsigned long long)c->cookie,
           s->user[0] ? s->user : "?", s->database[0] ? s->database : "?", s->app[0] ? s->app : "?",
           s->server_version[0] ? s->server_version : "?", s->complete ? "" : " (incomplete)");
}

#define TEXT_LOG_MAX 120

static void on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                     const struct lk_query_obs *o)
{
    __u64 dur = o->ts_complete_ns > o->ts_start_ns ? o->ts_complete_ns - o->ts_start_ns : 0;
    int tlen = o->text_len > TEXT_LOG_MAX ? TEXT_LOG_MAX : (int)o->text_len;

    (void)ctx;
    if (quiet)
        return;
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
    if (quiet)
        return;
    printf("txn conn=%llx dur=%lluns final=%c\n", (unsigned long long)c->cookie,
           (unsigned long long)(end_ns > start_ns ? end_ns - start_ns : 0), final_status);
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
    int rc = 0, first = 1;

    while (first < argc && argv[first][0] == '-') {
        if (!strcmp(argv[first], "--quiet")) {
            quiet = true;
            first++;
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
        fprintf(stderr, "usage: %s [--proto pg|mysql] [--quiet] FILE.lkt...\n", argv[0]);
        return 2;
    }

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
                " dropped=%llu/%llu/%llu prep_evict=%llu repl=%llu\n",
                argv[i], ops->name, (unsigned long long)ps->msgs, (unsigned long long)ps->sessions,
                (unsigned long long)ps->queries, (unsigned long long)ps->errors_sql,
                (unsigned long long)ps->parse_errors, (unsigned long long)ps->unknown_msgs,
                (unsigned long long)ps->resyncs, (unsigned long long)ps->units_dropped_resync,
                (unsigned long long)ps->units_dropped_close,
                (unsigned long long)ps->units_dropped_overflow,
                (unsigned long long)ps->prep_evictions, (unsigned long long)ps->replication_conns);
            lk_proto_free(proto);
            continue;
        }
        lk_pipeline_fini(&pipe);
        lk_proto_free(proto);
    }
    return rc;
}
