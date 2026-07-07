// SPDX-License-Identifier: GPL-2.0
/* Series registry with cardinality control (Р23, task 4.2). See registry.h for
 * the three defences (top-K LRU dictionary, doorkeeper, (db,user) limit) and
 * the contract; this file is the machinery.
 *
 * Layout:
 *   - entries[0..k-1] are the admittable query slots, entries[k] is the
 *     permanent query="other" pseudo-slot (never evicted). Admitted slots form
 *     an LRU list (head = MRU); free slots sit on a stack.
 *   - fp_hash is an open-addressed fingerprint -> slot index (linear probe,
 *     backward-shift deletion so no tombstones accumulate under churn).
 *   - the doorkeeper is a direct-mapped fp cache (Р23: "one hash probe").
 *   - dims[0..n_dims-1] are interned (db,user) pairs; dims[max_dims] is the
 *     (other,other) pseudo-pair. Linear scan — max_dims is tiny (32).
 *   - series are heap nodes in a chained hash keyed by (qslot,dim,code); each is
 *     also on its owning slot's list so eviction can fold them into `other`
 *     without scanning the whole table. */
#include "registry.h"

#include <stdlib.h>
#include <string.h>

#include "hist.h"

#define LK_DOORKEEPER_SLOTS 2048u /* Р23: N ~= 2K candidate fingerprints */
#define LK_MAX_SQLSTATES    64u   /* Р23: distinct SQLSTATE codes before "other" */

struct series {
    struct series *h_next; /* hash chain */
    struct series *q_next; /* owning slot's list (for the other-fold) */
    uint32_t qslot;        /* query slot, or r->k for "other" */
    uint32_t dim;          /* dim id, or r->max_dims for (other,other) */
    uint8_t code;          /* enum lk_code (ok|error) */
    uint64_t rows;         /* latkit_query_rows_total (summed over code at dump) */
    struct lk_hist dur;
    struct lk_hist *first_row; /* latkit_query_first_row_seconds, lazy (flag off = NULL) */
};

struct qentry {
    uint64_t fp;
    bool used;
    int32_t lru_prev, lru_next; /* indices into entries[], -1 = none */
    struct series *series;      /* head of this slot's series list */
    char label[LK_QUERY_LABEL_MAX];
};

struct dim {
    char db[64], user[64];
};

struct lk_registry {
    uint32_t k;         /* cfg.top_queries; entries has k+1 slots */
    uint32_t label_len; /* stored label chars, clamped [1, MAX-1] */
    uint32_t max_dims;  /* cfg.max_session_dims; dims has max_dims+1 slots */
    bool first_row;     /* cfg.first_row_hist: record the first-row histogram */

    struct qentry *entries;
    int32_t *fp_hash; /* [fp_hcap], slot index or -1 */
    uint32_t fp_hcap; /* power of two */
    int32_t *free_slots;
    uint32_t n_free;
    int32_t lru_head, lru_tail;

    uint64_t *door; /* [LK_DOORKEEPER_SLOTS], fp key or 0 = empty */

    struct dim *dims;
    uint32_t n_dims;

    struct series **sbuckets;
    uint32_t sbuckets_n; /* power of two */
    uint32_t n_series;

    /* Bounded label-keyed families, flat over the interned dimensions. dim ids
     * run [0, max_dims] (max_dims = the (other,other) pseudo-pair), so each is
     * sized ndims = max_dims + 1. */
    uint64_t *q_total;   /* [ndims][N_QKINDS][N_QCODES] latkit_queries_total */
    uint64_t *err_total; /* [MAX_SQLSTATES+1][ndims] latkit_query_errors_total */
    struct lk_hist *txn; /* [ndims][2] latkit_txn_duration_seconds (ok|aborted) */
    struct {
        char code[8];
    } sqlstates[LK_MAX_SQLSTATES]; /* interned SQLSTATEs */
    uint32_t n_sqlstates;

    uint64_t truncated_obs; /* latkit_queries_truncated_total */
    uint64_t total_obs;
    uint64_t other_obs;
};

static inline uint32_t reg_ndims(const struct lk_registry *r)
{
    return r->max_dims + 1;
}

/* --- small helpers -------------------------------------------------------- */

static uint32_t next_pow2(uint32_t x)
{
    uint32_t p = 1;

    while (p < x)
        p <<= 1;
    return p;
}

static uint64_t mix64(uint64_t x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    return x;
}

/* Copy up to label_len chars of `src` into `dst` (NUL-terminated), backing off
 * a partial trailing UTF-8 sequence so the label never ends mid-codepoint
 * (Р28). dst is LK_QUERY_LABEL_MAX bytes. */
static void utf8_trunc(const char *src, char *dst, uint32_t max_chars)
{
    size_t len = strlen(src);
    size_t n = len < max_chars ? len : max_chars;

    if (n < len)
        while (n > 0 && ((unsigned char)src[n] & 0xC0) == 0x80)
            n--; /* src[n] is a continuation byte: still inside a sequence */
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* --- fingerprint hash (open addressing, backward-shift delete) ------------ */

static uint32_t fp_home(const struct lk_registry *r, uint64_t fp)
{
    return (uint32_t)mix64(fp) & (r->fp_hcap - 1);
}

static int32_t fp_find(const struct lk_registry *r, uint64_t fp)
{
    for (uint32_t i = fp_home(r, fp);; i = (i + 1) & (r->fp_hcap - 1)) {
        int32_t s = r->fp_hash[i];

        if (s < 0)
            return -1;
        if (r->entries[s].fp == fp)
            return s;
    }
}

static void fp_insert(struct lk_registry *r, uint64_t fp, int32_t slot)
{
    uint32_t i = fp_home(r, fp);

    while (r->fp_hash[i] >= 0)
        i = (i + 1) & (r->fp_hcap - 1);
    r->fp_hash[i] = slot;
}

static void fp_remove(struct lk_registry *r, uint64_t fp)
{
    uint32_t mask = r->fp_hcap - 1;
    uint32_t i = fp_home(r, fp);

    while (r->fp_hash[i] < 0 || r->entries[r->fp_hash[i]].fp != fp)
        i = (i + 1) & mask;

    for (uint32_t j = i;;) {
        r->fp_hash[i] = -1;
        do {
            uint32_t home;

            j = (j + 1) & mask;
            if (r->fp_hash[j] < 0)
                return;
            home = fp_home(r, r->entries[r->fp_hash[j]].fp);
            /* keep probing while home is cyclically in (i, j] (can't move it) */
            if (i <= j ? (i < home && home <= j) : (i < home || home <= j))
                continue;
            break;
        } while (1);
        r->fp_hash[i] = r->fp_hash[j];
        i = j;
    }
}

/* --- LRU list ------------------------------------------------------------- */

static void lru_unlink(struct lk_registry *r, int32_t s)
{
    struct qentry *e = &r->entries[s];

    if (e->lru_prev >= 0)
        r->entries[e->lru_prev].lru_next = e->lru_next;
    else
        r->lru_head = e->lru_next;
    if (e->lru_next >= 0)
        r->entries[e->lru_next].lru_prev = e->lru_prev;
    else
        r->lru_tail = e->lru_prev;
}

static void lru_push_front(struct lk_registry *r, int32_t s)
{
    struct qentry *e = &r->entries[s];

    e->lru_prev = -1;
    e->lru_next = r->lru_head;
    if (r->lru_head >= 0)
        r->entries[r->lru_head].lru_prev = s;
    r->lru_head = s;
    if (r->lru_tail < 0)
        r->lru_tail = s;
}

static void lru_touch(struct lk_registry *r, int32_t s)
{
    if (r->lru_head == s)
        return;
    lru_unlink(r, s);
    lru_push_front(r, s);
}

/* --- series hash ---------------------------------------------------------- */

static uint64_t series_key(uint32_t qslot, uint32_t dim, uint8_t code)
{
    return ((uint64_t)qslot << 32) | ((uint64_t)dim << 8) | code;
}

static struct series *series_get(struct lk_registry *r, uint32_t qslot, uint32_t dim, uint8_t code)
{
    uint64_t key = series_key(qslot, dim, code);
    uint32_t b = (uint32_t)mix64(key) & (r->sbuckets_n - 1);
    struct series *s;

    for (s = r->sbuckets[b]; s; s = s->h_next)
        if (s->qslot == qslot && s->dim == dim && s->code == code)
            return s;

    s = calloc(1, sizeof(*s));
    if (!s)
        return NULL; /* out of memory: drop the observation, never crash */
    s->qslot = qslot;
    s->dim = dim;
    s->code = code;
    s->h_next = r->sbuckets[b];
    r->sbuckets[b] = s;
    s->q_next = r->entries[qslot].series;
    r->entries[qslot].series = s;
    r->n_series++;
    return s;
}

static void series_unlink_hash(struct lk_registry *r, struct series *victim)
{
    uint64_t key = series_key(victim->qslot, victim->dim, victim->code);
    uint32_t b = (uint32_t)mix64(key) & (r->sbuckets_n - 1);
    struct series **pp = &r->sbuckets[b];

    while (*pp && *pp != victim)
        pp = &(*pp)->h_next;
    if (*pp)
        *pp = victim->h_next;
}

/* --- dimensions ----------------------------------------------------------- */

static uint32_t intern_dim(struct lk_registry *r, const char *db, const char *user)
{
    for (uint32_t i = 0; i < r->n_dims; i++)
        if (!strcmp(r->dims[i].db, db) && !strcmp(r->dims[i].user, user))
            return i;
    if (r->n_dims >= r->max_dims)
        return r->max_dims; /* the (other,other) pseudo-pair */

    uint32_t id = r->n_dims++;
    snprintf(r->dims[id].db, sizeof(r->dims[id].db), "%s", db);
    snprintf(r->dims[id].user, sizeof(r->dims[id].user), "%s", user);
    return id;
}

/* Intern a SQLSTATE for latkit_query_errors_total (Р23): a linear scan capped at
 * LK_MAX_SQLSTATES, then the "other" pseudo-code at index LK_MAX_SQLSTATES. */
static uint32_t intern_sqlstate(struct lk_registry *r, const char *code)
{
    for (uint32_t i = 0; i < r->n_sqlstates; i++)
        if (!strcmp(r->sqlstates[i].code, code))
            return i;
    if (r->n_sqlstates >= LK_MAX_SQLSTATES)
        return LK_MAX_SQLSTATES;

    uint32_t id = r->n_sqlstates++;
    snprintf(r->sqlstates[id].code, sizeof(r->sqlstates[id].code), "%s", code);
    return id;
}

/* --- query dictionary: admit / evict / resolve ---------------------------- */

static int32_t admit(struct lk_registry *r, uint64_t fp, const char *label)
{
    int32_t s = r->free_slots[--r->n_free];
    struct qentry *e = &r->entries[s];

    e->fp = fp;
    e->used = true;
    e->series = NULL;
    utf8_trunc(label ? label : "", e->label, r->label_len);
    fp_insert(r, fp, s);
    lru_push_front(r, s);
    return s;
}

/* A series' lazily-allocated first-row histogram, created on first use (only
 * when the feature is on). NULL on OOM: caller drops the first-row observation,
 * never crashes. */
static struct lk_hist *series_first_row(struct series *s)
{
    if (!s->first_row)
        s->first_row = calloc(1, sizeof(*s->first_row));
    return s->first_row;
}

/* Fold the LRU slot's series into query="other" (Р23) and free the slot. */
static void evict_lru(struct lk_registry *r)
{
    int32_t t = r->lru_tail;
    struct qentry *e = &r->entries[t];
    struct series *s = e->series, *next;

    for (; s; s = next) {
        struct series *dst = series_get(r, r->k, s->dim, s->code);

        next = s->q_next;
        if (dst) {
            lk_hist_merge(&dst->dur, &s->dur);
            dst->rows += s->rows;
            if (s->first_row) {
                struct lk_hist *dfr = series_first_row(dst);

                if (dfr)
                    lk_hist_merge(dfr, s->first_row);
            }
        }
        series_unlink_hash(r, s);
        free(s->first_row);
        free(s);
        r->n_series--;
    }
    fp_remove(r, e->fp);
    lru_unlink(r, t);
    e->used = false;
    e->series = NULL;
    r->free_slots[r->n_free++] = t;
}

/* Map a fingerprint to the query slot to record under (Р23). */
static uint32_t resolve_query(struct lk_registry *r, uint64_t fp, const char *label)
{
    int32_t s = fp_find(r, fp);

    if (s >= 0) {
        lru_touch(r, s);
        return (uint32_t)s;
    }
    if (r->n_free > 0) /* room: admit on first sight */
        return (uint32_t)admit(r, fp, label);

    /* Dictionary full: doorkeeper. Admit only on the second appearance. */
    uint64_t key = fp ? fp : 1; /* 0 doubles as the empty sentinel */
    uint32_t d = (uint32_t)(key ^ (key >> 17)) & (LK_DOORKEEPER_SLOTS - 1);

    if (r->door[d] == key) {
        r->door[d] = 0;
        evict_lru(r);
        return (uint32_t)admit(r, fp, label);
    }
    r->door[d] = key;
    return r->k; /* query="other" */
}

/* --- public API ----------------------------------------------------------- */

void lk_reg_observe(struct lk_registry *r, const struct lk_reg_obs *o)
{
    uint32_t dim = intern_dim(r, o->db ? o->db : "", o->user ? o->user : "");
    uint32_t ndims = reg_ndims(r);
    uint8_t kind = o->kind < LK_N_QKINDS ? o->kind : LK_QK_SIMPLE;
    uint8_t qc = o->qcode < LK_N_QCODES ? o->qcode : LK_QCODE_OK;
    uint32_t qslot;
    struct series *s;

    /* latkit_queries_total{db,user,kind,code} — every observation. */
    r->q_total[(dim * LK_N_QKINDS + kind) * LK_N_QCODES + qc]++;
    if (o->truncated)
        r->truncated_obs++;
    if (o->sqlstate)
        r->err_total[intern_sqlstate(r, o->sqlstate) * ndims + dim]++;

    /* Aborted / canceled observations carry no latency: counters only (Р25). */
    if (!o->has_duration)
        return;

    /* Query-keyed families: forced "other" (NO_TEXT / CANCEL, Р28) skips the
     * dictionary so ad-hoc text never churns the top-K; otherwise resolve. */
    qslot = (o->force_other || !o->label) ? r->k : resolve_query(r, o->fp, o->label);
    s = series_get(r, qslot, dim, (uint8_t)o->dcode);

    r->total_obs++;
    if (qslot == r->k)
        r->other_obs++;
    if (!s)
        return;
    lk_hist_observe(&s->dur, o->dur_seconds);
    s->rows += o->rows;
    if (r->first_row && o->has_first_row) {
        struct lk_hist *fr = series_first_row(s);

        if (fr)
            lk_hist_observe(fr, o->first_row_seconds);
    }
}

void lk_reg_observe_txn(struct lk_registry *r, const char *db, const char *user, bool aborted,
                        double dur_seconds)
{
    uint32_t dim = intern_dim(r, db ? db : "", user ? user : "");

    lk_hist_observe(&r->txn[dim * 2 + (aborted ? 1u : 0u)], dur_seconds);
}

struct lk_registry *lk_reg_new(const struct lk_metrics_cfg *cfg)
{
    struct lk_metrics_cfg c;
    struct lk_registry *r;

    if (cfg)
        c = *cfg;
    else
        lk_metrics_cfg_defaults(&c);
    if (c.top_queries == 0)
        c.top_queries = LK_TOP_QUERIES_DEFAULT;
    if (c.max_session_dims == 0)
        c.max_session_dims = LK_MAX_SESSION_DIMS_DEFAULT;
    if (c.query_label_len == 0 || c.query_label_len >= LK_QUERY_LABEL_MAX)
        c.query_label_len = LK_QUERY_LABEL_MAX - 1;

    r = calloc(1, sizeof(*r));
    if (!r)
        return NULL;
    r->k = c.top_queries;
    r->label_len = c.query_label_len;
    r->max_dims = c.max_session_dims;
    r->first_row = c.first_row_hist;
    r->lru_head = r->lru_tail = -1;

    r->fp_hcap = next_pow2((r->k + 1) * 2);
    r->sbuckets_n = next_pow2(r->k * 4);
    if (r->sbuckets_n < 1024)
        r->sbuckets_n = 1024;

    uint32_t ndims = reg_ndims(r);

    r->entries = calloc(r->k + 1, sizeof(*r->entries));
    r->fp_hash = malloc(r->fp_hcap * sizeof(*r->fp_hash));
    r->free_slots = malloc(r->k * sizeof(*r->free_slots));
    r->door = calloc(LK_DOORKEEPER_SLOTS, sizeof(*r->door));
    r->dims = calloc(ndims, sizeof(*r->dims));
    r->sbuckets = calloc(r->sbuckets_n, sizeof(*r->sbuckets));
    r->q_total = calloc((size_t)ndims * LK_N_QKINDS * LK_N_QCODES, sizeof(*r->q_total));
    r->err_total = calloc((size_t)(LK_MAX_SQLSTATES + 1) * ndims, sizeof(*r->err_total));
    r->txn = calloc((size_t)ndims * 2, sizeof(*r->txn));
    if (!r->entries || !r->fp_hash || !r->free_slots || !r->door || !r->dims || !r->sbuckets ||
        !r->q_total || !r->err_total || !r->txn) {
        lk_reg_free(r);
        return NULL;
    }
    for (uint32_t i = 0; i < r->fp_hcap; i++)
        r->fp_hash[i] = -1;
    for (uint32_t i = 0; i < r->k; i++) /* LIFO stack of every real slot */
        r->free_slots[i] = (int32_t)(r->k - 1 - i);
    r->n_free = r->k;
    /* entries[k] is the permanent query="other" slot; dims[max] is (other,other). */
    snprintf(r->dims[r->max_dims].db, sizeof(r->dims[r->max_dims].db), "other");
    snprintf(r->dims[r->max_dims].user, sizeof(r->dims[r->max_dims].user), "other");
    return r;
}

void lk_reg_free(struct lk_registry *r)
{
    if (!r)
        return;
    if (r->sbuckets)
        for (uint32_t b = 0; b < r->sbuckets_n; b++) {
            struct series *s = r->sbuckets[b], *next;

            for (; s; s = next) {
                next = s->h_next;
                free(s->first_row);
                free(s);
            }
        }
    free(r->txn);
    free(r->err_total);
    free(r->q_total);
    free(r->sbuckets);
    free(r->dims);
    free(r->door);
    free(r->free_slots);
    free(r->fp_hash);
    free(r->entries);
    free(r);
}

/* --- introspection -------------------------------------------------------- */

uint32_t lk_reg_n_queries(const struct lk_registry *r)
{
    return r->k - r->n_free;
}
uint32_t lk_reg_n_dims(const struct lk_registry *r)
{
    return r->n_dims;
}
uint32_t lk_reg_n_series(const struct lk_registry *r)
{
    return r->n_series;
}
uint64_t lk_reg_total_obs(const struct lk_registry *r)
{
    return r->total_obs;
}
uint64_t lk_reg_other_obs(const struct lk_registry *r)
{
    return r->other_obs;
}
bool lk_reg_has_fp(const struct lk_registry *r, uint64_t fp)
{
    return fp_find(r, fp) >= 0;
}

uint64_t lk_reg_fp_count(const struct lk_registry *r, uint64_t fp)
{
    int32_t s = fp_find(r, fp);
    uint64_t total = 0;

    if (s < 0)
        return 0;
    for (const struct series *ser = r->entries[s].series; ser; ser = ser->q_next)
        total += ser->dur.count;
    return total;
}

uint64_t lk_reg_series_count_sum(const struct lk_registry *r)
{
    uint64_t total = 0;

    for (uint32_t b = 0; b < r->sbuckets_n; b++)
        for (const struct series *s = r->sbuckets[b]; s; s = s->h_next)
            total += s->dur.count;
    return total;
}

/* --- dump ----------------------------------------------------------------- */

#define LK_DUR_METRIC "latkit_query_duration_seconds"
#define LK_FR_METRIC  "latkit_query_first_row_seconds"
#define LK_TXN_METRIC "latkit_txn_duration_seconds"

/* Escaped db/user pair: worst case each 64-byte label doubles under escaping. */
#define ESC64 (2 * 64)

/* Escape a label value per the text format (Р28): backslash, double-quote and
 * newline. out must hold 2*strlen(s)+1. */
static void esc(const char *s, char *out)
{
    char *o = out;

    for (; *s; s++) {
        switch (*s) {
        case '\\':
            *o++ = '\\';
            *o++ = '\\';
            break;
        case '"':
            *o++ = '\\';
            *o++ = '"';
            break;
        case '\n':
            *o++ = '\\';
            *o++ = 'n';
            break;
        default:
            *o++ = *s;
        }
    }
    *o = '\0';
}

static const char *qkind_str(uint8_t k)
{
    static const char *const s[LK_N_QKINDS] = {"simple",  "extended", "function",
                                               "copy_in", "copy_out", "cancel"};
    return k < LK_N_QKINDS ? s[k] : "?";
}

static const char *qcode_str(uint8_t c)
{
    static const char *const s[LK_N_QCODES] = {"ok", "error", "aborted", "canceled"};
    return c < LK_N_QCODES ? s[c] : "?";
}

/* Order interned dimensions by (db,user) so the dump is stable regardless of
 * first-seen interning order. Insertion sort: ndims is tiny (<= max_dims + 1). */
static void order_dims(const struct lk_registry *r, uint32_t *ord, uint32_t ndims)
{
    for (uint32_t i = 0; i < ndims; i++)
        ord[i] = i;
    for (uint32_t i = 1; i < ndims; i++) {
        uint32_t v = ord[i], j = i;

        for (; j > 0; j--) {
            const struct dim *a = &r->dims[ord[j - 1]], *b = &r->dims[v];
            int c = strcmp(a->db, b->db);

            if (c == 0)
                c = strcmp(a->user, b->user);
            if (c <= 0)
                break;
            ord[j] = ord[j - 1];
        }
        ord[j] = v;
    }
}

/* --- query-keyed families (duration / rows / first_row) ------------------- */

struct dump_row {
    const struct series *s;
    const char *q, *db, *user;
    int code;
};

static int row_cmp(const void *a, const void *b)
{
    const struct dump_row *x = a, *y = b;
    int c;

    if ((c = strcmp(x->q, y->q)))
        return c;
    if ((c = strcmp(x->db, y->db)))
        return c;
    if ((c = strcmp(x->user, y->user)))
        return c;
    return x->code - y->code;
}

/* True when rows i and j share the (query,db,user) identity (they differ only
 * in `code`) — the group boundary for the code-free rows / first_row families. */
static bool same_qseries(const struct dump_row *a, const struct dump_row *b)
{
    return !strcmp(a->q, b->q) && !strcmp(a->db, b->db) && !strcmp(a->user, b->user);
}

static void write_qkeyed(const struct lk_registry *r, FILE *f, const struct dump_row *rows,
                         uint32_t n)
{
    /* duration: one histogram per (query,db,user,code). */
    fprintf(f, "# HELP " LK_DUR_METRIC " Server-side query latency in seconds.\n");
    fprintf(f, "# TYPE " LK_DUR_METRIC " histogram\n");
    for (uint32_t i = 0; i < n; i++) {
        char qe[2 * LK_QUERY_LABEL_MAX], dbe[ESC64], ue[ESC64];
        char labelset[2 * LK_QUERY_LABEL_MAX + 3 * ESC64 + 64];

        esc(rows[i].q, qe);
        esc(rows[i].db, dbe);
        esc(rows[i].user, ue);
        snprintf(labelset, sizeof(labelset), "query=\"%s\",db=\"%s\",user=\"%s\",code=\"%s\"", qe,
                 dbe, ue, rows[i].code == LK_CODE_ERROR ? "error" : "ok");
        lk_hist_write(&rows[i].s->dur, f, LK_DUR_METRIC, labelset);
    }

    /* rows_total: sum over code within each (query,db,user) group. */
    fprintf(f, "# HELP latkit_query_rows_total Rows returned/affected, from CommandComplete.\n");
    fprintf(f, "# TYPE latkit_query_rows_total counter\n");
    for (uint32_t i = 0; i < n;) {
        uint32_t j = i;
        uint64_t sum = 0;
        char qe[2 * LK_QUERY_LABEL_MAX], dbe[ESC64], ue[ESC64];

        for (; j < n && same_qseries(&rows[i], &rows[j]); j++)
            sum += rows[j].s->rows;
        esc(rows[i].q, qe);
        esc(rows[i].db, dbe);
        esc(rows[i].user, ue);
        fprintf(f, "latkit_query_rows_total{query=\"%s\",db=\"%s\",user=\"%s\"} %llu\n", qe, dbe,
                ue, (unsigned long long)sum);
        i = j;
    }

    /* first_row: merge the code series' histograms within each group (opt-in). */
    if (!r->first_row)
        return;
    fprintf(f, "# HELP " LK_FR_METRIC " Time to first row in seconds.\n");
    fprintf(f, "# TYPE " LK_FR_METRIC " histogram\n");
    for (uint32_t i = 0; i < n;) {
        uint32_t j = i;
        struct lk_hist acc = {0};
        bool any = false;
        char qe[2 * LK_QUERY_LABEL_MAX], dbe[ESC64], ue[ESC64];
        char labelset[2 * LK_QUERY_LABEL_MAX + 3 * ESC64];

        for (; j < n && same_qseries(&rows[i], &rows[j]); j++)
            if (rows[j].s->first_row) {
                lk_hist_merge(&acc, rows[j].s->first_row);
                any = true;
            }
        if (!any) {
            i = j;
            continue;
        }
        esc(rows[i].q, qe);
        esc(rows[i].db, dbe);
        esc(rows[i].user, ue);
        snprintf(labelset, sizeof(labelset), "query=\"%s\",db=\"%s\",user=\"%s\"", qe, dbe, ue);
        lk_hist_write(&acc, f, LK_FR_METRIC, labelset);
        i = j;
    }
}

int lk_reg_dump(const struct lk_registry *r, FILE *f)
{
    uint32_t ndims = reg_ndims(r);
    struct dump_row *rows = r->n_series ? malloc(r->n_series * sizeof(*rows)) : NULL;
    uint32_t *ord = malloc(ndims * sizeof(*ord));
    uint32_t n = 0;

    if ((r->n_series && !rows) || !ord) {
        free(rows);
        free(ord);
        return -1;
    }
    order_dims(r, ord, ndims);

    /* --- latkit_queries_total{db,user,kind,code} ------------------------- */
    fprintf(f, "# HELP latkit_queries_total Query observations by kind and outcome.\n");
    fprintf(f, "# TYPE latkit_queries_total counter\n");
    for (uint32_t oi = 0; oi < ndims; oi++) {
        uint32_t d = ord[oi];
        char dbe[ESC64], ue[ESC64];

        esc(r->dims[d].db, dbe);
        esc(r->dims[d].user, ue);
        for (uint8_t k = 0; k < LK_N_QKINDS; k++)
            for (uint8_t c = 0; c < LK_N_QCODES; c++) {
                uint64_t v = r->q_total[(d * LK_N_QKINDS + k) * LK_N_QCODES + c];

                if (v)
                    fprintf(f,
                            "latkit_queries_total{db=\"%s\",user=\"%s\",kind=\"%s\",code=\"%s\"} "
                            "%llu\n",
                            dbe, ue, qkind_str(k), qcode_str(c), (unsigned long long)v);
            }
    }

    /* --- query-keyed families ------------------------------------------- */
    for (uint32_t b = 0; b < r->sbuckets_n; b++)
        for (const struct series *s = r->sbuckets[b]; s; s = s->h_next) {
            const struct dim *d = &r->dims[s->dim];

            rows[n].s = s;
            rows[n].q = s->qslot == r->k ? "other" : r->entries[s->qslot].label;
            rows[n].db = d->db;
            rows[n].user = d->user;
            rows[n].code = s->code;
            n++;
        }
    if (n)
        qsort(rows, n, sizeof(*rows), row_cmp);
    write_qkeyed(r, f, rows, n);

    /* --- latkit_query_errors_total{sqlstate,db,user} -------------------- */
    fprintf(f, "# HELP latkit_query_errors_total Errors by SQLSTATE (query-independent).\n");
    fprintf(f, "# TYPE latkit_query_errors_total counter\n");
    {
        uint32_t sord[LK_MAX_SQLSTATES];

        for (uint32_t i = 0; i < r->n_sqlstates; i++)
            sord[i] = i;
        for (uint32_t i = 1; i < r->n_sqlstates; i++) { /* sort SQLSTATEs lexically */
            uint32_t v = sord[i], j = i;

            for (; j > 0 && strcmp(r->sqlstates[sord[j - 1]].code, r->sqlstates[v].code) > 0; j--)
                sord[j] = sord[j - 1];
            sord[j] = v;
        }
        /* real codes in order, then the "other" pseudo-code last */
        for (uint32_t si = 0; si <= r->n_sqlstates; si++) {
            uint32_t sq = si < r->n_sqlstates ? sord[si] : LK_MAX_SQLSTATES;
            const char *code = si < r->n_sqlstates ? r->sqlstates[sq].code : "other";

            for (uint32_t oi = 0; oi < ndims; oi++) {
                uint32_t d = ord[oi];
                uint64_t v = r->err_total[sq * ndims + d];
                char dbe[ESC64], ue[ESC64], ce[2 * sizeof(r->sqlstates[0].code)];

                if (!v)
                    continue;
                esc(code, ce);
                esc(r->dims[d].db, dbe);
                esc(r->dims[d].user, ue);
                fprintf(f,
                        "latkit_query_errors_total{sqlstate=\"%s\",db=\"%s\",user=\"%s\"} %llu\n",
                        ce, dbe, ue, (unsigned long long)v);
            }
        }
    }

    /* --- label-free counters -------------------------------------------- */
    fprintf(f, "# HELP latkit_queries_truncated_total Observations with truncated SQL text.\n");
    fprintf(f, "# TYPE latkit_queries_truncated_total counter\n");
    fprintf(f, "latkit_queries_truncated_total %llu\n", (unsigned long long)r->truncated_obs);
    fprintf(f, "# HELP latkit_queries_other_total Observations folded into query=\"other\".\n");
    fprintf(f, "# TYPE latkit_queries_other_total counter\n");
    fprintf(f, "latkit_queries_other_total %llu\n", (unsigned long long)r->other_obs);

    /* --- latkit_txn_duration_seconds{db,user,status} -------------------- */
    fprintf(f, "# HELP " LK_TXN_METRIC " Transaction duration in seconds.\n");
    fprintf(f, "# TYPE " LK_TXN_METRIC " histogram\n");
    for (uint32_t oi = 0; oi < ndims; oi++) {
        uint32_t d = ord[oi];
        char dbe[ESC64], ue[ESC64];

        esc(r->dims[d].db, dbe);
        esc(r->dims[d].user, ue);
        for (uint32_t st = 0; st < 2; st++) {
            const struct lk_hist *h = &r->txn[d * 2 + st];
            char labelset[3 * ESC64 + 64];

            if (!h->count)
                continue;
            snprintf(labelset, sizeof(labelset), "db=\"%s\",user=\"%s\",status=\"%s\"", dbe, ue,
                     st ? "aborted" : "ok");
            lk_hist_write(h, f, LK_TXN_METRIC, labelset);
        }
    }

    free(rows);
    free(ord);
    return 0;
}
