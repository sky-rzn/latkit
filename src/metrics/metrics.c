// SPDX-License-Identifier: GPL-2.0
/* Metrics facade (Р26). Lifecycle + the aggregator (task 4.3) + the flat scalar
 * series (task 4.4 groundwork). It owns the registry (registry.c) — every
 * cardinality-controlled family lives there — and adds two facade-only pieces:
 *
 *   - the lk_query_sink: on_query normalises the SQL (norm_sql), selects the
 *     duration (Р25), maps the observation flags to codes (Р23/Р25/Р28) and
 *     fans the result into the registry; on_txn records the transaction span;
 *     on_session/on_query refresh a small per-connection (db,user) cache, since
 *     on_txn is handed only the connection and the sink has no close hook;
 *   - a fixed set of named scalar counters/gauges the caller sets before a dump
 *     (connections now, the self-metric providers in task 4.4).
 *
 * Pure: depends on norm_sql and the lk_query_obs contract (proto.h) for types
 * only — no libbpf, no I/O beyond the caller's FILE. */
#include "metrics.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "norm_s3.h"
#include "norm_sql.h"
#include "proto.h"
#include "registry.h"

#define LK_NS 1000000000.0 /* ns per second */

/* CLOCK_MONOTONIC now (ns): stamps a flat scalar's created_ns so its OTLP Sum
 * carries an honest start_time (Р31). Same clock as the registry and pipeline. */
static uint64_t mx_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Seconds between two pipeline timestamps, zero when the interval is missing or
 * inverted — a stamp that never arrived is 0, and "since the epoch" is a worse
 * answer than "no time at all". */
static double span_seconds(__u64 from, __u64 to)
{
    return to > from ? (double)(to - from) / LK_NS : 0.0;
}

/* on_txn (Р16) carries only the connection, and the query sink has no close
 * hook, so remember (db,user) per connection cookie in a fixed direct-mapped
 * cache refreshed on every session/query. A collision only mislabels a
 * transaction's db/user — never miscounts — so an unsynchronised cache is fine.
 * Bounded memory (~0.5 MiB), no growth under connection churn. */
#define LK_SESS_CACHE 4096u

struct sess_ent {
    uint64_t cookie;
    bool used;
    char db[64], user[64];
    const char *proto; /* lk_proto_ops.name (static string); NULL -> "pg" */
};

/* Flat named scalar series (Р27): connections in task 4.3, the self-metric
 * providers in 4.4. Each series is keyed by (name, one optional label); several
 * label values of one name form a single family. Bounded by the fixed set. */
enum { LK_SC_COUNTER, LK_SC_GAUGE };
/* Headroom for the per-protocol self-metric split (М6/РМ6): parser counters,
 * queries_dropped{reason} and ignored_conns{reason} are now emitted once per
 * registered protocol, several-fold more series than the flat pre-М6 set. */
#define LK_MAX_SCALARS 128

struct scalar {
    char name[64];
    char help[160];
    char label_key[16]; /* "" = no label */
    char label_val[32];
    char label_key2[16]; /* "" = no second label (Р29 http_requests_total) */
    char label_val2[32];
    int type;
    double value;
    uint64_t created_ns; /* mono; first sight of this series -> OTLP start_time (Р31) */
};

/* Self-metric providers (Р27): the fixed set of subsystems is tiny (kernel
 * stats, framer, parser, conn table, process_*), so a small table suffices. */
#define LK_MAX_PROVIDERS 8

struct provider {
    lk_metrics_provider_fn fn;
    void *ctx;
};

struct lk_metrics {
    struct lk_metrics_cfg cfg;
    struct lk_registry *reg;
    struct lk_query_sink sink;
    struct sess_ent sess[LK_SESS_CACHE];
    struct scalar scalars[LK_MAX_SCALARS];
    uint32_t n_scalars;
    struct provider providers[LK_MAX_PROVIDERS];
    uint32_t n_providers;
};

/* --- session-label cache -------------------------------------------------- */

static uint32_t sess_slot(uint64_t cookie)
{
    return (uint32_t)((cookie ^ (cookie >> 29)) & (LK_SESS_CACHE - 1));
}

static void sess_store(struct lk_metrics *m, uint64_t cookie, const char *db, const char *user,
                       const char *proto)
{
    struct sess_ent *e = &m->sess[sess_slot(cookie)];

    e->cookie = cookie;
    e->used = true;
    snprintf(e->db, sizeof(e->db), "%s", db ? db : "");
    snprintf(e->user, sizeof(e->user), "%s", user ? user : "");
    e->proto = proto; /* borrowed static string from lk_proto_ops.name */
}

static const struct sess_ent *sess_get(struct lk_metrics *m, uint64_t cookie)
{
    const struct sess_ent *e = &m->sess[sess_slot(cookie)];

    return (e->used && e->cookie == cookie) ? e : NULL;
}

/* --- lk_query_sink -------------------------------------------------------- */

static void mx_on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    sess_store(ctx, c->cookie, s->database, s->user, lk_conn_proto(c)->name);
}

/* One HTTP exchange -> the http (or s3) profile's families (РH9/РH10, М5;
 * РS7, МS2). Everything that differs from the database path is here rather than
 * in branches of mx_on_query below, because the two share almost nothing: the
 * identity is a (method, route) pair instead of normalised SQL, the outcome is
 * a status code whose 4xx half is the *client's* fault, and the timings are
 * РH5's four rather than Р25's two.
 *
 * The labels (РH10): the route in the dictionary slot, the request's own Host in
 * the db slot — not the connection's, since one keep-alive socket serves several
 * virtual hosts — and the user slot empty ("-") unless `--http-user basic` was
 * asked for. "-" rather than "": an empty label value means "absent" to
 * Prometheus, and these are present and deliberately anonymous.
 *
 * The S3 dialect is the same function because it is the same exchange: what the
 * dialect changed is what the slots *hold* (the operation, the bucket, the
 * access key — filled in by the handler, РS2/РS3/РS4), and the three things it
 * could not put in an existing slot arrive as their own fields on the
 * observation. They are the whole of the s3 branch below. */
static void mx_http_obs(struct lk_metrics *m, const struct lk_proto_ops *ops,
                        const struct lk_session *s, const struct lk_query_obs *o)
{
    struct lk_reg_obs ro = {0};
    bool s3 = ops->profile == LK_PROTO_PROF_S3;
    uint16_t fl = o->flags;
    char code[8];

    ro.profile = s3 ? LK_PROF_S3 : LK_PROF_HTTP;
    ro.proto = ops->name;
    /* MinIO's own surface is counted and reported nowhere else (РS2). Decided
     * by the dialect, which is the only component that knows what `/minio/` is;
     * everything below this line would otherwise report a health check as an
     * S3 operation with a latency and a bucket. */
    if (s3 && (fl & LK_QO_INTERNAL)) {
        ro.internal = true;
        lk_reg_observe(m->reg, &ro);
        return;
    }
    ro.db = s->database[0] ? s->database : "-";
    ro.user = s->user[0] ? s->user : "-";
    ro.op = o->op;
    ro.kind = o->kind;
    ro.has_duration = true;
    ro.sclass = o->err_code >= 100 && o->err_code < 600
                    ? (uint8_t)(LK_SCLASS_1XX + o->err_code / 100 - 1)
                    : LK_SCLASS_OTHER;
    /* РH10: a 5xx is the server failing and belongs in code="error"; a 4xx is
     * the client being told no, and folding it in would make every 404-heavy
     * service look broken. Both land in the per-code error counter. */
    ro.qcode = (fl & LK_QO_ERROR) ? LK_QCODE_ERROR : LK_QCODE_OK;
    ro.dcode = (fl & LK_QO_ERROR) ? LK_CODE_ERROR : LK_CODE_OK;
    if (o->err_code >= 400) {
        /* The failure's name, and for S3 that is not the status (РS5):
         * `NoSuchKey` and `NoSuchBucket` are both 404 and are two different
         * problems. The code is already folded to a known one or to `other` by
         * the dialect, so it is a bounded label; when no body carried one — a
         * failing HEAD from a server that sends no `x-minio-error-code` — the
         * status is the honest fallback and the label space is the http one. */
        snprintf(code, sizeof(code), "%u", o->err_code);
        ro.err_code = (s3 && o->err_name) ? o->err_name : code;
    }

    /* The four timings (РH5). The server's clock starts when the request body
     * ends, so a gigabyte upload is not a slow response; the upload interval is
     * its own family, and only for units where it means something — one with
     * `Expect: 100-continue` contains a server round trip, and one whose body
     * arrived in the same capture event as its head has no interval to report. */
    ro.dur_seconds = span_seconds(o->ts_req_done_ns, o->ts_complete_ns);
    if (o->ts_first_row_ns > o->ts_req_done_ns) {
        ro.has_first_row = true;
        ro.first_row_seconds = span_seconds(o->ts_req_done_ns, o->ts_first_row_ns);
    }
    if (!(fl & LK_QO_EXPECT_CONT) && o->ts_req_done_ns > o->ts_start_ns) {
        ro.has_upload = true;
        ro.upload_seconds = span_seconds(o->ts_start_ns, o->ts_req_done_ns);
    }

    ro.bytes_in = o->bytes_in;
    ro.bytes_out = o->bytes_out;
    /* A body the socket never carried (sendfile, or a connection that died
     * mid-transfer, РH4) makes bytes_out a lower bound. The counters still take
     * it — an undercount of a total is honest enough to graph — but the size
     * *distribution* would be actively misleading, so that unit is left out. */
    ro.has_size = !(fl & LK_QO_BODY_UNSEEN);
    /* What the distribution is *of*, and the two answers differ (РS6): an HTTP
     * response body, or the size of the object an S3 operation moved — with the
     * aws-chunked framing discounted, because a chunked upload's wire count
     * moves with the client's buffer size and would describe the client rather
     * than the objects.
     *
     * Three conditions, and each of them is the difference between a size
     * histogram and a body-size histogram (МS2): the operation must be one that
     * carries object data at all (a listing's XML is not an object, nor is an
     * error document); the server must have accepted it, since a refused upload
     * stored nothing; and there must have been a body, because `0` would
     * otherwise mean "an empty object" and every HEAD and DELETE would pile into
     * the first bucket. A genuinely empty object is indistinguishable from a
     * bodiless response here and is lost with them — it is also not a size
     * anybody plots. */
    ro.size_bytes = s3 ? o->obj_bytes : o->bytes_out;
    if (s3 && (!o->obj_bytes || o->err_code >= 400 || !lk_s3_op_is_data(o->route, o->route_len)))
        ro.has_size = false;

    /* The route is the only thing here that may become a label, and it is
     * already templated (РH7). No route — a CONNECT, or a head we never read —
     * folds into route="other" rather than inventing one. */
    if (o->route && o->route_len)
        ro.label = o->route, ro.fp = o->route_fp;
    else
        ro.force_other = true;

    lk_reg_observe(m->reg, &ro);
}

/* One observation -> the registry families. The flag mapping (Р23/Р25/Р28):
 *   - CANCEL         -> code=canceled, no latency, query="other";
 *   - ABORTED        -> code=aborted, no latency (killed by an earlier error);
 *   - ERROR          -> code=error + a duration + the SQLSTATE counter;
 *   - otherwise (incl. EMPTY / SUSPENDED, documented) -> code=ok + a duration. */
static void mx_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                        const struct lk_query_obs *o)
{
    struct lk_metrics *m = ctx;
    struct lk_reg_obs ro = {0};
    struct lk_norm_out norm;
    const struct lk_proto_ops *ops = lk_conn_proto(c);
    uint16_t fl = o->flags;

    sess_store(m, c->cookie, s->database, s->user, ops->name);
    if (ops->profile == LK_PROTO_PROF_HTTP || ops->profile == LK_PROTO_PROF_S3) {
        mx_http_obs(m, ops, s, o);
        return;
    }

    ro.db = s->database;
    ro.user = s->user;
    ro.proto = ops->name;
    ro.kind = o->kind;

    if (o->kind == LK_Q_CANCEL) {
        ro.qcode = LK_QCODE_CANCELED;
    } else if (fl & LK_QO_ABORTED) {
        ro.qcode = LK_QCODE_ABORTED;
    } else if (fl & LK_QO_ERROR) {
        ro.qcode = LK_QCODE_ERROR;
        ro.dcode = LK_CODE_ERROR;
        ro.has_duration = true;
        ro.err_code = o->sqlstate[0] ? o->sqlstate : NULL;
    } else {
        ro.qcode = LK_QCODE_OK;
        ro.dcode = LK_CODE_OK;
        ro.has_duration = true;
    }

    if (ro.has_duration) {
        /* Duration model (Р25): pipelined units share one Z, so their honest
         * per-query span is ts_complete - ts_start; a standalone unit uses
         * ts_ready (server done and ready for the next). Fall back to
         * ts_complete if the chosen stamp is somehow missing. */
        uint64_t start = o->ts_start_ns;
        uint64_t end = (fl & LK_QO_PIPELINED) ? o->ts_complete_ns : o->ts_ready_ns;

        if (end <= start)
            end = o->ts_complete_ns;
        ro.dur_seconds = end > start ? (double)(end - start) / LK_NS : 0.0;
        ro.rows = o->rows;
        if (o->ts_first_row_ns && o->ts_first_row_ns >= o->ts_start_ns) {
            ro.has_first_row = true;
            ro.first_row_seconds = (double)(o->ts_first_row_ns - o->ts_start_ns) / LK_NS;
        }
    }

    /* Text -> fingerprint + label, unless the observation carries none (Р28):
     * NO_TEXT / CANCEL / a null pointer all fold into query="other". */
    if ((fl & LK_QO_NO_TEXT) || o->kind == LK_Q_CANCEL || !o->text) {
        ro.force_other = true;
    } else {
        lk_norm_sql(o->text, o->text_len, ops->sql_dialect, &norm);
        ro.fp = norm.fp;
        ro.label = norm.text;
        ro.truncated = norm.trunc || (fl & LK_QO_TEXT_TRUNC);
    }

    lk_reg_observe(m->reg, &ro);
}

static void mx_on_txn(void *ctx, const struct lk_conn *c, __u64 start_ns, __u64 end_ns,
                      char final_status)
{
    struct lk_metrics *m = ctx;
    const struct sess_ent *e = sess_get(m, c->cookie);
    double dur = end_ns > start_ns ? (double)(end_ns - start_ns) / LK_NS : 0.0;
    /* Prefer the protocol cached with the session; fall back to the connection's
     * own ops if the txn fired before any session/query was cached. */
    const char *proto = (e && e->proto) ? e->proto : lk_conn_proto(c)->name;

    lk_reg_observe_txn(m->reg, e ? e->db : "", e ? e->user : "", proto, final_status == 'E', dur);
}

const struct lk_query_sink *lk_metrics_query_sink(struct lk_metrics *m)
{
    return &m->sink;
}

/* --- flat scalars --------------------------------------------------------- */

static void scalar_set(struct lk_metrics *m, const char *name, const char *help, const char *lkey,
                       const char *lval, const char *lkey2, const char *lval2, int type, double v)
{
    struct scalar *sc = NULL;

    lkey = lkey ? lkey : "";
    lval = lval ? lval : "";
    lkey2 = lkey2 ? lkey2 : "";
    lval2 = lval2 ? lval2 : "";
    for (uint32_t i = 0; i < m->n_scalars; i++)
        if (!strcmp(m->scalars[i].name, name) && !strcmp(m->scalars[i].label_key, lkey) &&
            !strcmp(m->scalars[i].label_val, lval) && !strcmp(m->scalars[i].label_key2, lkey2) &&
            !strcmp(m->scalars[i].label_val2, lval2)) {
            sc = &m->scalars[i];
            break;
        }
    if (!sc) {
        if (m->n_scalars >= LK_MAX_SCALARS)
            return; /* fixed metric set: silently ignore an unexpected overflow */
        sc = &m->scalars[m->n_scalars++];
        sc->created_ns = mx_now_ns();
        snprintf(sc->name, sizeof(sc->name), "%s", name);
        snprintf(sc->label_key, sizeof(sc->label_key), "%s", lkey);
        snprintf(sc->label_val, sizeof(sc->label_val), "%s", lval);
        snprintf(sc->label_key2, sizeof(sc->label_key2), "%s", lkey2);
        snprintf(sc->label_val2, sizeof(sc->label_val2), "%s", lval2);
    }
    sc->type = type;
    sc->value = v;
    if (help && help[0])
        snprintf(sc->help, sizeof(sc->help), "%s", help);
}

void lk_metrics_set_counter(struct lk_metrics *m, const char *name, const char *help, double v)
{
    scalar_set(m, name, help, NULL, NULL, NULL, NULL, LK_SC_COUNTER, v);
}

void lk_metrics_set_gauge(struct lk_metrics *m, const char *name, const char *help, double v)
{
    scalar_set(m, name, help, NULL, NULL, NULL, NULL, LK_SC_GAUGE, v);
}

void lk_metrics_set_counter_l(struct lk_metrics *m, const char *name, const char *help,
                              const char *label_key, const char *label_val, double v)
{
    scalar_set(m, name, help, label_key, label_val, NULL, NULL, LK_SC_COUNTER, v);
}

void lk_metrics_set_gauge_l(struct lk_metrics *m, const char *name, const char *help,
                            const char *label_key, const char *label_val, double v)
{
    scalar_set(m, name, help, label_key, label_val, NULL, NULL, LK_SC_GAUGE, v);
}

void lk_metrics_set_counter_l2(struct lk_metrics *m, const char *name, const char *help,
                               const char *label_key1, const char *label_val1,
                               const char *label_key2, const char *label_val2, double v)
{
    scalar_set(m, name, help, label_key1, label_val1, label_key2, label_val2, LK_SC_COUNTER, v);
}

void lk_metrics_add_provider(struct lk_metrics *m, lk_metrics_provider_fn fn, void *ctx)
{
    if (!fn || m->n_providers >= LK_MAX_PROVIDERS)
        return;
    m->providers[m->n_providers++] = (struct provider){.fn = fn, .ctx = ctx};
}

/* Sort key: family (name) first, then label value, so one HELP/TYPE header
 * covers a whole labeled family and its series print in a stable order. */
static int scalar_cmp(const void *a, const void *b)
{
    const struct scalar *x = a, *y = b;
    int c = strcmp(x->name, y->name);

    if (c)
        return c;
    c = strcmp(x->label_val, y->label_val);
    return c ? c : strcmp(x->label_val2, y->label_val2);
}

/* --- lifecycle + dump ----------------------------------------------------- */

void lk_metrics_cfg_defaults(struct lk_metrics_cfg *cfg)
{
    cfg->top_queries = LK_TOP_QUERIES_DEFAULT;
    cfg->query_label_len = LK_QUERY_LABEL_LEN_DEFAULT;
    cfg->max_session_dims = LK_MAX_SESSION_DIMS_DEFAULT;
    cfg->first_row_hist = false;
}

struct lk_metrics *lk_metrics_new(const struct lk_metrics_cfg *cfg)
{
    struct lk_metrics *m = calloc(1, sizeof(*m));

    if (!m)
        return NULL;
    if (cfg)
        m->cfg = *cfg;
    else
        lk_metrics_cfg_defaults(&m->cfg);
    m->reg = lk_reg_new(&m->cfg);
    if (!m->reg) {
        free(m);
        return NULL;
    }
    m->sink.ctx = m;
    m->sink.on_query = mx_on_query;
    m->sink.on_session = mx_on_session;
    m->sink.on_txn = mx_on_txn;
    return m;
}

void lk_metrics_free(struct lk_metrics *m)
{
    if (!m)
        return;
    lk_reg_free(m->reg);
    free(m);
}

int lk_metrics_dump(struct lk_metrics *m, FILE *f)
{
    struct scalar sorted[LK_MAX_SCALARS];
    const char *cur = NULL;
    int rv;

    /* Refresh the flat scalars from their live sources first (Р27): the kernel
     * counters, the framer/parser/conn-table stats and process_* are all pulled
     * in here, at the moment of the dump. */
    for (uint32_t i = 0; i < m->n_providers; i++)
        m->providers[i].fn(m->providers[i].ctx, m);
    /* The registry's own honesty gauge: the actual number of cardinality-
     * controlled series it holds (Р27). queries_other_total is emitted by the
     * registry dump itself. */
    lk_metrics_set_gauge(m, "latkit_metric_series", "Cardinality-controlled series currently held.",
                         (double)lk_reg_n_series(m->reg));

    rv = lk_reg_dump(m->reg, f);
    if (rv)
        return rv;

    /* Flat scalars after the registry families, sorted by (name, label) so each
     * labeled family gets one HELP/TYPE header followed by its series. */
    memcpy(sorted, m->scalars, m->n_scalars * sizeof(sorted[0]));
    qsort(sorted, m->n_scalars, sizeof(sorted[0]), scalar_cmp);
    for (uint32_t i = 0; i < m->n_scalars; i++) {
        const struct scalar *sc = &sorted[i];

        if (!cur || strcmp(cur, sc->name)) {
            cur = sc->name;
            /* One HELP/TYPE header per family. HELP may have been supplied on any
             * one of the family's label values (a labeled setter passes NULL for
             * the rest), so scan the contiguous group for the first non-empty. */
            const char *help = sc->help;

            for (uint32_t j = i; j < m->n_scalars && !help[0] && !strcmp(sorted[j].name, sc->name);
                 j++)
                help = sorted[j].help;
            if (help[0])
                fprintf(f, "# HELP %s %s\n", sc->name, help);
            fprintf(f, "# TYPE %s %s\n", sc->name, sc->type == LK_SC_GAUGE ? "gauge" : "counter");
        }
        if (sc->label_key[0] && sc->label_key2[0])
            fprintf(f, "%s{%s=\"%s\",%s=\"%s\"} %.17g\n", sc->name, sc->label_key, sc->label_val,
                    sc->label_key2, sc->label_val2, sc->value);
        else if (sc->label_key[0])
            fprintf(f, "%s{%s=\"%s\"} %.17g\n", sc->name, sc->label_key, sc->label_val, sc->value);
        else
            fprintf(f, "%s %.17g\n", sc->name, sc->value);
    }
    return 0;
}

void lk_metrics_iter(struct lk_metrics *m, lk_metrics_iter_fn fn, void *ctx)
{
    struct scalar sorted[LK_MAX_SCALARS];

    /* Refresh the flat scalars from their live sources first, exactly as a dump
     * does (Р27), so the values reflect the moment of the export. */
    for (uint32_t i = 0; i < m->n_providers; i++)
        m->providers[i].fn(m->providers[i].ctx, m);
    lk_metrics_set_gauge(m, "latkit_metric_series", "Cardinality-controlled series currently held.",
                         (double)lk_reg_n_series(m->reg));

    /* Registry families first (same order as the dump), then the flat scalars. */
    lk_reg_iter(m->reg, fn, ctx);

    memcpy(sorted, m->scalars, m->n_scalars * sizeof(sorted[0]));
    qsort(sorted, m->n_scalars, sizeof(sorted[0]), scalar_cmp);
    for (uint32_t i = 0; i < m->n_scalars; i++) {
        const struct scalar *sc = &sorted[i];
        struct lk_label lbl[2];
        struct lk_metric_view v = {
            .name = sc->name,
            .help = sc->help[0] ? sc->help : NULL,
            .type = sc->type == LK_SC_GAUGE ? LK_MT_GAUGE : LK_MT_COUNTER,
            .labels = lbl,
            .nlabels = 0,
            .created_ns = sc->created_ns,
            .val = sc->value,
        };

        if (sc->label_key[0]) {
            lbl[v.nlabels++] = (struct lk_label){sc->label_key, sc->label_val};
            if (sc->label_key2[0])
                lbl[v.nlabels++] = (struct lk_label){sc->label_key2, sc->label_val2};
        }
        fn(ctx, &v);
    }
}
