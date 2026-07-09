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

#include "norm_sql.h"
#include "proto.h"
#include "registry.h"

#define LK_NS 1000000000.0 /* ns per second */

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
};

/* Flat named scalar series (Р27): connections in task 4.3, the self-metric
 * providers in 4.4. Each series is keyed by (name, one optional label); several
 * label values of one name form a single family. Bounded by the fixed set. */
enum { LK_SC_COUNTER, LK_SC_GAUGE };
#define LK_MAX_SCALARS 64

struct scalar {
    char name[64];
    char help[160];
    char label_key[16]; /* "" = no label */
    char label_val[32];
    char label_key2[16]; /* "" = no second label (Р29 http_requests_total) */
    char label_val2[32];
    int type;
    double value;
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

static void sess_store(struct lk_metrics *m, uint64_t cookie, const char *db, const char *user)
{
    struct sess_ent *e = &m->sess[sess_slot(cookie)];

    e->cookie = cookie;
    e->used = true;
    snprintf(e->db, sizeof(e->db), "%s", db ? db : "");
    snprintf(e->user, sizeof(e->user), "%s", user ? user : "");
}

static const struct sess_ent *sess_get(struct lk_metrics *m, uint64_t cookie)
{
    const struct sess_ent *e = &m->sess[sess_slot(cookie)];

    return (e->used && e->cookie == cookie) ? e : NULL;
}

/* --- lk_query_sink -------------------------------------------------------- */

static void mx_on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    sess_store(ctx, c->cookie, s->database, s->user);
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
    uint16_t fl = o->flags;

    sess_store(m, c->cookie, s->database, s->user);

    ro.db = s->database;
    ro.user = s->user;
    ro.kind = o->kind;

    if (o->kind == LK_Q_CANCEL) {
        ro.qcode = LK_QCODE_CANCELED;
    } else if (fl & LK_QO_ABORTED) {
        ro.qcode = LK_QCODE_ABORTED;
    } else if (fl & LK_QO_ERROR) {
        ro.qcode = LK_QCODE_ERROR;
        ro.dcode = LK_CODE_ERROR;
        ro.has_duration = true;
        ro.sqlstate = o->sqlstate[0] ? o->sqlstate : NULL;
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
        lk_norm_sql(o->text, o->text_len, &norm);
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

    lk_reg_observe_txn(m->reg, e ? e->db : "", e ? e->user : "", final_status == 'E', dur);
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
