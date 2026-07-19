// SPDX-License-Identifier: GPL-2.0
/* Replay integration test (task 2.5): the whole userspace pipeline
 * (decode -> conn table -> framer) over recorded traces, with no BPF and no
 * privileges — the same lk_pipeline the live agent runs (Р14). For each
 * fixture it checks two things:
 *
 *   1. reproducibility: the committed tests/fixtures/<name>.lkt is byte-for-
 *      byte what the in-tree builder produces (a live --record capture would
 *      replace the builder without changing this harness);
 *   2. framing: replaying the committed file yields exactly the expected
 *      messages (dir/type/len/flags), the expected resync/tls counters, no
 *      unexpected dirtying, and a connection table that returns to empty.
 */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conn_table.h"
#include "fixtures_gen.h"
#include "metrics.h"
#include "pipeline.h"
#include "proto.h"
#include "record.h"
#include "spans.h"

#ifndef LK_FIXTURES_DIR
#define LK_FIXTURES_DIR "."
#endif

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* --- message-collecting sink + PG-parser tee ------------------------------
 * The pipeline sink both records the framer's message stream (the stage-2
 * framing assertions) and tees every message / resync / close into the PG
 * handler (Р15), whose query sink records the sessions and observations the
 * stage-3 assertions check. This mirrors how events.c wires the two together
 * over live traffic. */

struct collector {
    struct lk_pipeline pipe;
    struct lk_proto *proto;              /* handler under test (pg or mysql) */
    const struct lk_proto_ops *ops;      /* its framer/handler vtable */
    const struct lk_msg_sink *psink;     /* = lk_proto_sink(proto) */
    struct fx_msg got[FX_MAX_MSGS * 2];
    size_t ngot;
    bool overflow;

    /* Query-sink side: what the PG parser emitted upward. */
    size_t nsessions;
    size_t nqueries;
    struct lk_session last_session;
    struct lk_query_obs last_obs; /* text pointer nulled; see last_text */
    char last_text[256];          /* last_obs.text copied out (it dangles) */

    /* Aggregator (task 4.3): the same observations tee into the metrics facade,
     * exactly as events.c wires them over live traffic. */
    struct lk_metrics *metrics;
    const struct lk_query_sink *msink;

    /* Span collector (task 5.3): a third consumer at ratio=1.0, so every
     * observation with a measurable duration must become exactly one span. The
     * harness recomputes eligibility with the same predicate to cross-check. */
    struct lk_spans *spans;
    const struct lk_query_sink *ssink;
    size_t neligible;
    char last_elig_text[256];
    bool last_elig_error;
    char last_elig_sqlstate[6];
};

static void on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    struct collector *col = ctx;

    col->nsessions++;
    col->last_session = *s;
    if (col->msink->on_session)
        col->msink->on_session(col->msink->ctx, c, s);
}

static void on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                     const struct lk_query_obs *o)
{
    struct collector *col = ctx;

    col->nqueries++;
    col->last_obs = *o;
    /* o->text is only valid during this call; copy it out for the assertions. */
    col->last_text[0] = '\0';
    if (o->text && o->text_len < sizeof(col->last_text)) {
        memcpy(col->last_text, o->text, o->text_len);
        col->last_text[o->text_len] = '\0';
    }
    col->last_obs.text = NULL;
    if (col->msink->on_query)
        col->msink->on_query(col->msink->ctx, c, s, o);

    /* Recompute the span-eligibility predicate (measurable duration) and snapshot
     * the last eligible observation, then tee into the span collector. */
    if (o->ts_complete_ns > o->ts_start_ns) {
        col->neligible++;
        col->last_elig_text[0] = '\0';
        if (o->text && o->text_len < sizeof(col->last_elig_text)) {
            memcpy(col->last_elig_text, o->text, o->text_len);
            col->last_elig_text[o->text_len] = '\0';
        }
        col->last_elig_error = (o->flags & LK_QO_ERROR) != 0;
        snprintf(col->last_elig_sqlstate, sizeof(col->last_elig_sqlstate), "%s", o->sqlstate);
    }
    if (col->ssink->on_query)
        col->ssink->on_query(col->ssink->ctx, c, s, o);
}

static void on_txn(void *ctx, const struct lk_conn *c, __u64 start_ns, __u64 end_ns, char status)
{
    struct collector *col = ctx;

    if (col->msink->on_txn)
        col->msink->on_txn(col->msink->ctx, c, start_ns, end_ns, status);
}

static void on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct collector *col = ctx;

    if (col->ngot >= sizeof(col->got) / sizeof(col->got[0]))
        col->overflow = true;
    else
        col->got[col->ngot++] = (struct fx_msg){
            .dir = (__u8)dir,
            .type = m->type,
            .len = m->len,
            .flags = m->flags,
        };
    if (col->psink->on_msg)
        col->psink->on_msg(col->psink->ctx, c, dir, m);
}

static void on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    struct collector *col = ctx;

    if (col->psink->on_resync)
        col->psink->on_resync(col->psink->ctx, c, dir);
}

/* The pipeline routes the conn-table destroy hook here; forward it so the
 * parser frees proto_state on every removal path (Р15) — otherwise ASAN sees a
 * leak on teardown. */
static void on_conn_close(void *ctx, struct lk_conn *c)
{
    struct collector *col = ctx;

    if (col->psink->on_conn_close)
        col->psink->on_conn_close(col->psink->ctx, c);
}

static int feed_record(void *ctx, const void *data, __u32 size)
{
    struct lk_pipeline_ev ev;

    lk_pipeline_feed(&((struct collector *)ctx)->pipe, data, size, &ev);
    return 0;
}

/* --- helpers -------------------------------------------------------------- */

static __u8 *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long sz;
    __u8 *buf;

    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) || (sz = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
        fclose(f);
        return NULL;
    }
    buf = malloc((size_t)sz + 1);
    if (buf && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    if (buf)
        *len = (size_t)sz;
    return buf;
}

static const char *msg_str(const struct fx_msg *m, char *out, size_t n)
{
    snprintf(out, n, "dir=%u type=%d len=%u flags=0x%x", m->dir, m->type, m->len, m->flags);
    return out;
}

/* Capture a metrics dump into buf; returns the byte count (0 on failure). */
static size_t dump_metrics(struct lk_metrics *m, char *buf, size_t cap)
{
    FILE *f = tmpfile();
    size_t n;

    if (!f)
        return 0;
    lk_metrics_dump(m, f);
    rewind(f);
    n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    return n;
}

/* --- task 4.5: point assertions on the aggregated metrics dump ------------
 * The stage-3 fixtures replay into the metrics facade exactly as over live
 * traffic; here we pin what the M2 dump must show — the invariant that
 * observations become the expected series, and (for the loss / TLS fixtures)
 * that nothing survives a gap: no query series at all (Р19). Point asserts
 * rather than a golden dump: robust to incidental format churn, and they name
 * the invariant directly. db/user are "postgres" for every query-bearing
 * fixture (the shared prelude's startup params). */
struct metric_expect {
    const char *name;             /* fixture stem */
    const char *query;            /* normalized `query` label, or NULL = no query series */
    const char *code;             /* duration series code checked: "ok" | "error" */
    unsigned long long dur_count; /* latkit_query_duration_seconds_count for it */
    unsigned long long rows;      /* latkit_query_rows_total for `query` */
    unsigned series;              /* latkit_metric_series (query-keyed series held) */
    unsigned long long other;     /* latkit_queries_other_total */
    const char *sqlstate;         /* NULL, or a code whose errors_total must be 1 */
    /* Label triple on the query series. NULL falls back to the PG prelude's
     * postgres/postgres/pg — the MySQL rows override with test/root/mysql. */
    const char *db;
    const char *user;
    const char *proto;
};

static const struct metric_expect metric_expects[] = {
    {"simple_query", "select ?", "ok", 1, 1, 1, 0, NULL, NULL, NULL, NULL},
    {"error", "select ? / ?", "error", 1, 0, 1, 0, "22012", NULL, NULL, NULL},
    {"multi_statement", "select ? ; select ?", "ok", 1, 3, 1, 0, NULL, NULL, NULL, NULL},
    {"cancel", NULL, NULL, 0, 0, 0, 0, NULL, NULL, NULL, NULL},
    {"extended", "select ?", "ok", 1, 1, 1, 0, NULL, NULL, NULL, NULL},
    {"prepared", "select ?", "ok", 2, 2, 1, 0, NULL, NULL, NULL, NULL},
    /* pipelined batch: unit 1 ok, unit 2 errors, unit 3 aborted -> two series
     * ("select ?" ok + error), the error counter ticks, nothing folds to other. */
    {"pipeline_error", "select ?", "ok", 1, 1, 2, 0, "42P01", NULL, NULL, NULL},
    {"copy_in", "copy t from stdin", "ok", 1, 2, 1, 0, NULL, NULL, NULL, NULL},
    {"copy_out", "copy t to stdout", "ok", 1, 2, 1, 0, NULL, NULL, NULL, NULL},
    /* Р19: a lost-event gap dirties the connection; no observation survives it,
     * so the dump carries no query series at all. */
    {"session_gap", NULL, NULL, 0, 0, 0, 0, NULL, NULL, NULL, NULL},
    /* NO_TEXT (Bind on an un-Parsed name): honest latency under query="other". */
    {"bind_unknown", "other", "ok", 1, 5, 1, 1, NULL, NULL, NULL, NULL},
    {"ssl_plain", "select ?", "ok", 1, 1, 1, 0, NULL, NULL, NULL, NULL},
    /* Decrypted channel now carries the whole session (stage 6.4): the same
     * observation as its plaintext twin ssl_plain. */
    {"ssl_tls", "select ?", "ok", 1, 1, 1, 0, NULL, NULL, NULL, NULL},
    {"synthetic_midsession", NULL, NULL, 0, 0, 0, 0, NULL, NULL, NULL, NULL},

    /* --- MySQL mirror set (MYSQL.md М7): labels test/root/mysql -------------
     * The same invariants as the PG rows, carried on the proto="mysql" axis.
     * The RM6 proto label keeps these series apart from any PG series in a
     * mixed dump. */
    {"my_simple_query", "select ?", "ok", 1, 1, 1, 0, NULL, "test", "root", "mysql"},
    {"my_error", "select * from missing", "error", 1, 0, 1, 0, "42S02", "test", "root", "mysql"},
    {"my_multi_statement", "select ? ; select ?", "ok", 1, 2, 1, 0, NULL, "test", "root", "mysql"},
    {"my_prepared", "select ?", "ok", 2, 2, 1, 0, NULL, "test", "root", "mysql"},
    {"my_load_data", "load data local infile ? into table t", "ok", 1, 2, 1, 0, NULL, "test",
     "root", "mysql"},
    /* Cursor: execute + two fetches share the text; rows 0+2+1, all code=ok. */
    {"my_cursor_fetch", "select id from t", "ok", 3, 3, 1, 0, NULL, "test", "root", "mysql"},
    /* РМ7 blind zone: the handshake is parsed but no command is observed. */
    {"my_compressed", NULL, NULL, 0, 0, 0, 0, NULL, NULL, NULL, NULL},
    {"my_ssl", "select ?", "ok", 1, 1, 1, 0, NULL, "test", "root", "mysql"},
    {"my_synthetic_midsession", NULL, NULL, 0, 0, 0, 0, NULL, NULL, NULL, NULL},
};

/* Numeric value on the dump line that begins (at column 0) with `prefix` and is
 * followed by a space. Returns 1 and sets *out, or 0 if no such line exists. */
static int dump_line_val(const char *buf, const char *prefix, double *out)
{
    size_t plen = strlen(prefix);
    const char *p = buf;

    while ((p = strstr(p, prefix))) {
        if ((p == buf || p[-1] == '\n') && p[plen] == ' ') {
            *out = strtod(p + plen + 1, NULL);
            return 1;
        }
        p += plen;
    }
    return 0;
}

/* Assert one dump line's value equals `want` (the line must be present). */
static int check_line(const char *fixname, const char *buf, const char *prefix,
                      unsigned long long want)
{
    double v;

    if (!dump_line_val(buf, prefix, &v)) {
        fprintf(stderr, "FAIL %s: metrics dump missing line \"%s ...\"\n", fixname, prefix);
        return 1;
    }
    if ((unsigned long long)v != want) {
        fprintf(stderr, "FAIL %s: \"%s\" = %llu, expected %llu\n", fixname, prefix,
                (unsigned long long)v, want);
        return 1;
    }
    return 0;
}

/* Assert the dump has no line beginning with `prefix` (used to prove no query
 * series exist for the loss / TLS fixtures). */
static int check_absent(const char *fixname, const char *buf, const char *prefix)
{
    double v;

    if (dump_line_val(buf, prefix, &v)) {
        fprintf(stderr, "FAIL %s: metrics dump has unexpected \"%s\" = %g\n", fixname, prefix, v);
        return 1;
    }
    return 0;
}

static int check_metrics(const struct metric_expect *e, const char *buf)
{
    char pfx[512];
    const char *db = e->db ? e->db : "postgres";
    const char *user = e->user ? e->user : "postgres";
    const char *proto = e->proto ? e->proto : "pg";

    if (check_line(e->name, buf, "latkit_metric_series", e->series) ||
        check_line(e->name, buf, "latkit_queries_other_total", e->other))
        return 1;

    if (e->query) {
        snprintf(pfx, sizeof(pfx),
                 "latkit_query_duration_seconds_count{query=\"%s\",db=\"%s\","
                 "user=\"%s\",proto=\"%s\",code=\"%s\"}",
                 e->query, db, user, proto, e->code);
        if (check_line(e->name, buf, pfx, e->dur_count))
            return 1;
        snprintf(pfx, sizeof(pfx),
                 "latkit_query_rows_total{query=\"%s\",db=\"%s\",user=\"%s\","
                 "proto=\"%s\"}",
                 e->query, db, user, proto);
        if (check_line(e->name, buf, pfx, e->rows))
            return 1;
    } else {
        /* No observation survived: the query-keyed families must be empty. */
        if (check_absent(e->name, buf, "latkit_query_duration_seconds_count") ||
            check_absent(e->name, buf, "latkit_query_rows_total"))
            return 1;
    }

    if (e->sqlstate) {
        snprintf(pfx, sizeof(pfx),
                 "latkit_query_errors_total{sqlstate=\"%s\",db=\"%s\",user=\"%s\","
                 "proto=\"%s\"}",
                 e->sqlstate, db, user, proto);
        if (check_line(e->name, buf, pfx, 1))
            return 1;
    }
    return 0;
}

/* Drain callback: keep the last drained span's text / error status (Р32). */
struct last_span {
    bool any;
    char text[256];
    bool error;
    char sqlstate[6];
};

static void grab_last_span(void *ctx, const struct lk_span *sp)
{
    struct last_span *ls = ctx;

    ls->any = true;
    ls->text[0] = '\0';
    if (sp->text && sp->text_len < sizeof(ls->text)) {
        memcpy(ls->text, sp->text, sp->text_len);
        ls->text[sp->text_len] = '\0';
    }
    ls->error = sp->error;
    snprintf(ls->sqlstate, sizeof(ls->sqlstate), "%s", sp->sqlstate);
}

static int run_fixture(const struct fixture *fix)
{
    struct fx x;
    char path[1024];
    __u8 *committed;
    size_t clen;
    struct collector col;
    const struct lk_reasm_stats *rs;
    const struct lk_conn_table_stats *cs;

    fix->build(&x);
    CHECK(x.buf && x.len > 0);

    /* 1. Reproducibility: committed file == freshly built bytes. */
    snprintf(path, sizeof(path), "%s/%s.lkt", LK_FIXTURES_DIR, fix->name);
    committed = read_file(path, &clen);
    if (!committed) {
        fprintf(stderr,
                "FAIL %s: cannot read committed fixture %s "
                "(run gen_fixtures to create it)\n",
                fix->name, path);
        free(x.buf);
        return 1;
    }
    if (clen != x.len || memcmp(committed, x.buf, x.len)) {
        fprintf(stderr,
                "FAIL %s: committed fixture differs from builder "
                "(committed %zu bytes, built %zu) — regenerate with gen_fixtures\n",
                fix->name, clen, x.len);
        free(committed);
        free(x.buf);
        return 1;
    }

    /* 2. Replay the committed trace through the shared pipeline, teeing every
     * message into the PG handler. */
    memset(&col, 0, sizeof(col));
    col.metrics = lk_metrics_new(NULL);
    if (!col.metrics) {
        free(committed);
        free(x.buf);
        return 1;
    }
    col.msink = lk_metrics_query_sink(col.metrics);
    col.spans = lk_spans_new(&(struct lk_spans_cfg){.sample_ratio = 1.0, .seed = 1});
    if (!col.spans) {
        lk_metrics_free(col.metrics);
        free(committed);
        free(x.buf);
        return 1;
    }
    col.ssink = lk_spans_sink(col.spans);
    col.ops = fix->proto ? lk_proto_find(fix->proto, strlen(fix->proto)) : lk_proto_registry[0];
    if (!col.ops) {
        fprintf(stderr, "FAIL %s: unknown proto \"%s\"\n", fix->name, fix->proto);
        lk_spans_free(col.spans);
        lk_metrics_free(col.metrics);
        free(committed);
        free(x.buf);
        return 1;
    }
    col.proto = col.ops->proto_new(&(struct lk_query_sink){
        .ctx = &col, .on_session = on_session, .on_query = on_query, .on_txn = on_txn});
    if (!col.proto) {
        lk_spans_free(col.spans);
        lk_metrics_free(col.metrics);
        free(committed);
        free(x.buf);
        return 1;
    }
    col.psink = lk_proto_sink(col.proto);
    if (lk_pipeline_init(&col.pipe, LK_MAX_CONNS_DEFAULT, 600ULL * 1000000000ULL,
                         &(struct lk_msg_sink){.ctx = &col,
                                               .on_msg = on_msg,
                                               .on_resync = on_resync,
                                               .on_conn_close = on_conn_close})) {
        lk_proto_free(col.proto);
        lk_spans_free(col.spans);
        lk_metrics_free(col.metrics);
        free(committed);
        free(x.buf);
        return 1;
    }
    /* Force every connection to the fixture's protocol (the tuple's port is
     * incidental in the offline harness — set_protos with a NULL map installs
     * the default ops the framer and handler both key off c->ops). */
    lk_conn_table_set_protos(col.pipe.conns, NULL, 0, col.ops);
    if (lk_replay_mem(committed, clen, feed_record, &col)) {
        fprintf(stderr, "FAIL %s: malformed trace\n", fix->name);
        goto fail;
    }
    CHECK(!col.overflow);

    /* Message stream matches the expectation exactly. */
    if (col.ngot != x.nmsgs) {
        fprintf(stderr, "FAIL %s: expected %zu messages, got %zu\n", fix->name, x.nmsgs, col.ngot);
        goto fail;
    }
    for (size_t i = 0; i < x.nmsgs; i++) {
        if (memcmp(&col.got[i], &x.msgs[i], sizeof(struct fx_msg))) {
            char a[64], b[64];

            fprintf(stderr, "FAIL %s: message %zu: expected {%s}, got {%s}\n", fix->name, i,
                    msg_str(&x.msgs[i], a, sizeof(a)), msg_str(&col.got[i], b, sizeof(b)));
            goto fail;
        }
    }

    rs = &col.pipe.reasm.st;
    cs = lk_conn_table_stats(col.pipe.conns);
    if (x.clean && (rs->bad_len || rs->hdr_holes || rs->off_anomalies)) {
        fprintf(stderr, "FAIL %s: expected clean, got bad_len=%llu hdr_holes=%llu off=%llu\n",
                fix->name, (unsigned long long)rs->bad_len, (unsigned long long)rs->hdr_holes,
                (unsigned long long)rs->off_anomalies);
        goto fail;
    }
    if (rs->resyncs != x.resyncs) {
        fprintf(stderr, "FAIL %s: expected %llu resyncs, got %llu\n", fix->name,
                (unsigned long long)x.resyncs, (unsigned long long)rs->resyncs);
        goto fail;
    }
    if (rs->tls_conns != x.tls_conns) {
        fprintf(stderr, "FAIL %s: expected %llu tls_conns, got %llu\n", fix->name,
                (unsigned long long)x.tls_conns, (unsigned long long)rs->tls_conns);
        goto fail;
    }
    /* Every fixture closes its connection: the table must return to empty. */
    if (cs->active != 0) {
        fprintf(stderr, "FAIL %s: %u connection(s) left active\n", fix->name, cs->active);
        goto fail;
    }

    /* Stage-3 parser expectations (task 3.2): sessions and observations. */
    if (col.nsessions != x.sessions) {
        fprintf(stderr, "FAIL %s: expected %llu sessions, got %zu\n", fix->name,
                (unsigned long long)x.sessions, col.nsessions);
        goto fail;
    }
    if (x.sessions && (strcmp(col.last_session.user, x.sess_user) ||
                       strcmp(col.last_session.database, x.sess_db))) {
        fprintf(stderr, "FAIL %s: session labels expected user=%s db=%s, got user=%s db=%s\n",
                fix->name, x.sess_user, x.sess_db, col.last_session.user,
                col.last_session.database);
        goto fail;
    }
    if (col.nqueries != x.queries) {
        fprintf(stderr, "FAIL %s: expected %llu observations, got %zu\n", fix->name,
                (unsigned long long)x.queries, col.nqueries);
        goto fail;
    }
    if (lk_proto_stats(col.proto)->errors_sql != x.errors_sql) {
        fprintf(stderr, "FAIL %s: expected %llu errors_sql, got %llu\n", fix->name,
                (unsigned long long)x.errors_sql,
                (unsigned long long)lk_proto_stats(col.proto)->errors_sql);
        goto fail;
    }
    /* Last observation's fields (task 3.3): kind/rows/flags always, text and
     * SQLSTATE only when the fixture pins them. */
    if (x.queries) {
        if (col.last_obs.kind != x.obs_kind || col.last_obs.rows != x.obs_rows ||
            col.last_obs.flags != x.obs_flags || col.last_obs.bytes != x.obs_bytes) {
            fprintf(stderr,
                    "FAIL %s: obs expected kind=%u rows=%llu bytes=%llu flags=0x%x, "
                    "got kind=%u rows=%llu bytes=%llu flags=0x%x\n",
                    fix->name, x.obs_kind, (unsigned long long)x.obs_rows,
                    (unsigned long long)x.obs_bytes, x.obs_flags, col.last_obs.kind,
                    (unsigned long long)col.last_obs.rows, (unsigned long long)col.last_obs.bytes,
                    col.last_obs.flags);
            goto fail;
        }
        if (x.obs_text && strcmp(col.last_text, x.obs_text)) {
            fprintf(stderr, "FAIL %s: obs text expected \"%s\", got \"%s\"\n", fix->name,
                    x.obs_text, col.last_text);
            goto fail;
        }
        if (x.obs_sqlstate && strcmp(col.last_obs.sqlstate, x.obs_sqlstate)) {
            fprintf(stderr, "FAIL %s: obs sqlstate expected \"%s\", got \"%s\"\n", fix->name,
                    x.obs_sqlstate, col.last_obs.sqlstate);
            goto fail;
        }
    }

    /* Aggregator (task 4.3): the metrics dump must be deterministic — two dumps
     * of the same aggregated state are byte-identical (stable line order, no
     * addresses / iteration-order leakage). 4.5 layers golden-value asserts on
     * top of this. */
    {
        static char a[65536], b[65536];
        size_t na = dump_metrics(col.metrics, a, sizeof(a));
        size_t nb = dump_metrics(col.metrics, b, sizeof(b));

        if (!na || na != nb || memcmp(a, b, na)) {
            fprintf(stderr, "FAIL %s: metrics dump not deterministic\n", fix->name);
            goto fail;
        }

        /* Task 4.5: pin the aggregated series values against the expectation
         * table (the M2 invariant, and Р19 for the loss fixtures). */
        for (size_t k = 0; k < sizeof(metric_expects) / sizeof(metric_expects[0]); k++)
            if (!strcmp(metric_expects[k].name, fix->name)) {
                if (check_metrics(&metric_expects[k], a))
                    goto fail;
                break;
            }
    }

    /* Task 5.3: the span sink saw the same observations at ratio=1.0, so every
     * eligible obs (measurable duration) became exactly one span, none dropped,
     * and the last span mirrors the last eligible obs' raw text and error. */
    {
        struct last_span ls = {0};

        if (lk_spans_sampled_total(col.spans) != col.neligible) {
            fprintf(stderr, "FAIL %s: spans sampled=%llu, expected eligible=%zu\n", fix->name,
                    (unsigned long long)lk_spans_sampled_total(col.spans), col.neligible);
            goto fail;
        }
        if (lk_spans_dropped_total(col.spans) != 0) {
            fprintf(stderr, "FAIL %s: spans dropped=%llu, expected 0\n", fix->name,
                    (unsigned long long)lk_spans_dropped_total(col.spans));
            goto fail;
        }
        lk_spans_drain(col.spans, grab_last_span, &ls);
        if (col.neligible) {
            if (!ls.any || strcmp(ls.text, col.last_elig_text)) {
                fprintf(stderr, "FAIL %s: last span text \"%s\", expected \"%s\"\n", fix->name,
                        ls.text, col.last_elig_text);
                goto fail;
            }
            if (ls.error != col.last_elig_error ||
                (col.last_elig_error && strcmp(ls.sqlstate, col.last_elig_sqlstate))) {
                fprintf(stderr, "FAIL %s: last span error=%d/%s, expected %d/%s\n", fix->name,
                        ls.error, ls.sqlstate, col.last_elig_error, col.last_elig_sqlstate);
                goto fail;
            }
        }
    }

    /* Tear the table down first (its destroy hooks free proto_state through the
     * parser, which must still be alive), then release the handler. */
    lk_pipeline_fini(&col.pipe);
    lk_proto_free(col.proto);
    lk_spans_free(col.spans);
    lk_metrics_free(col.metrics);
    free(committed);
    free(x.buf);
    printf("ok %s (%zu msgs, %zu sessions)\n", fix->name, col.ngot, col.nsessions);
    return 0;

fail:
    lk_pipeline_fini(&col.pipe);
    lk_proto_free(col.proto);
    lk_spans_free(col.spans);
    lk_metrics_free(col.metrics);
    free(committed);
    free(x.buf);
    return 1;
}

/* --- recorder round-trip -------------------------------------------------- */
/* The fixtures lay down LKT bytes directly; this exercises the lk_recorder
 * writer the live agent uses (Р14), confirming a --record file reads back
 * byte-for-byte through lk_replay_file. */

struct rt_rec {
    __u32 size;
    __u8 bytes[64];
};
static const struct rt_rec rt_in[] = {
    {5, {1, 2, 3, 4, 5}},
    {1, {0xff}},
    {12, {'r', 'e', 'c', 'o', 'r', 'd', '-', 't', 'e', 's', 't', 0}},
};

struct rt_check {
    size_t idx;
    int failed;
};

static int rt_cb(void *ctx, const void *data, __u32 size)
{
    struct rt_check *rc = ctx;

    if (rc->idx >= sizeof(rt_in) / sizeof(rt_in[0]) || size != rt_in[rc->idx].size ||
        memcmp(data, rt_in[rc->idx].bytes, size)) {
        rc->failed = 1;
        return 1;
    }
    rc->idx++;
    return 0;
}

static int test_recorder_roundtrip(void)
{
    const char *path = "test_replay_roundtrip.tmp";
    struct lk_recorder *rec = lk_recorder_open(path);
    struct rt_check rc = {0};
    int rv;

    CHECK(rec);
    for (size_t i = 0; i < sizeof(rt_in) / sizeof(rt_in[0]); i++)
        lk_recorder_write(rec, rt_in[i].bytes, rt_in[i].size);
    CHECK(lk_recorder_close(rec) == 0);

    rv = lk_replay_file(path, rt_cb, &rc);
    remove(path);
    CHECK(rv == 0 && !rc.failed);
    CHECK(rc.idx == sizeof(rt_in) / sizeof(rt_in[0]));
    printf("ok recorder-roundtrip\n");
    return 0;
}

int main(void)
{
    for (size_t i = 0; i < lk_nfixtures; i++)
        if (run_fixture(&lk_fixtures[i]))
            return 1;
    if (test_recorder_roundtrip())
        return 1;
    printf("ok\n");
    return 0;
}
