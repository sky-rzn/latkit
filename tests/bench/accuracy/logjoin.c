// SPDX-License-Identifier: GPL-2.0
/* logjoin — the accuracy cross-check of task 8.2 (Р50): join the agent's
 * --dump-metrics exposition with PostgreSQL's csvlog for the same workload and
 * measure how far the two views of one latency distribution sit apart.
 *
 * The join key is OUR normaliser: every statement text found in the csvlog is
 * run through the same lk_norm_sql the agent links (same code, same fp, same
 * canonical text), then clipped to the agent's query-label length — so a csvlog
 * line lands on exactly the series the agent aggregated it into.
 * pg_stat_statements.queryid never enters the join (its normalisation differs;
 * pgss stays a sanity source handled by run.sh).
 *
 * csvlog side (log_min_duration_statement=0):
 *   - `duration: X ms  statement: <sql>`             one sample (simple proto);
 *   - `duration: X ms  parse|bind <name>: <sql>`     phase, accumulated;
 *   - `duration: X ms  execute <name>: <sql>`        sample = execute + pending
 *     parse/bind of the session (extended protocol logs the phases separately;
 *     the agent times first-frontend-message -> ReadyForQuery, so the honest
 *     comparison is against the SUM of the phases — the documented caveat);
 *   - severity=ERROR rows with a statement                 one error sample;
 *   - connection_from = [local] rows are skipped entirely: unix-socket sessions
 *     (the stand's control plane) are invisible to the agent by design.
 *
 * Latency is compared three ways per query, to keep the grid's discretisation
 * error apart from the measurement offset (Р50):
 *   - raw:   percentile straight from the csvlog samples;
 *   - fine:  through the Р24 grid (2^(k/4) buckets) — what the agent's
 *            histogram stores internally, error <= one grid step (~9%);
 *   - grid:  through the classic export boundaries (every 4th grid bound,
 *            factor 2) — exactly what --dump-metrics exposes; the agent
 *            percentile is computed from those same boundaries with the same
 *            estimator, so agent-vs-grid compares identically discretised
 *            values and the delta is measurement, not bucketing.
 * The mean needs no such treatment: _sum in the exposition is exact, so
 * mean(agent) - mean(log) is the headline measurement offset.
 *
 * One trap the identical discretisation does NOT remove: when the offset moves
 * probability mass across a bucket boundary, the interpolated percentile shifts
 * by (mass moved) x (bucket width) — a factor-2 bucket AMPLIFIES a 5%-of-value
 * offset into a double-digit percentile delta while the distributions agree
 * perfectly. So the percentile GATE is offset-adjusted: log samples shifted by
 * the measured per-query mean offset, then discretised — that compares the
 * SHAPE of the two distributions under the model `agent = log + const`, which
 * is exactly the measurement model (the constant is the kernel/socket path the
 * agent deliberately includes). The unadjusted delta is still reported: it is
 * the honest "what you would see on a dashboard" number.
 *
 * Acceptance (-c): counts match exactly per query (ok and error separately),
 * per-SQLSTATE error totals match, and the offset-adjusted |p50/p95 agent vs
 * grid| <= tol% for queries with mean >= min-ms and enough samples. Exit 1 on
 * any failure.
 *
 * Pure offline tool: links latkit_norm + latkit_metrics (hist index/bound
 * arithmetic), reads files, prints a TSV + `#` summary lines. */
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hist.h"
#include "metrics.h" /* LK_QUERY_LABEL_MAX — the registry's stored-label cap */
#include "norm_sql.h"

#define MAX_LE     32 /* classic export has 19 finite les + +Inf */
#define MAX_STATES 64 /* distinct SQLSTATEs in one campaign */

/* csvlog columns (PostgreSQL 14+ has 26; only these are read). */
enum {
    COL_USER = 1,
    COL_DB = 2,
    COL_CONN = 4,
    COL_SESSION = 5,
    COL_SEVERITY = 11,
    COL_SQLSTATE = 12,
    COL_MESSAGE = 13,
    COL_QUERY = 19,
    COL_MIN = 22, /* accept any csvlog with at least this many columns */
};

static void *xrealloc(void *p, size_t n)
{
    p = realloc(p, n);
    if (!p) {
        fprintf(stderr, "logjoin: out of memory\n");
        exit(2);
    }
    return p;
}

/* --- growable sample vector (seconds) -------------------------------------- */

struct samples {
    double *v;
    size_t n, cap;
};

static void sample_add(struct samples *s, double sec)
{
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 64;
        s->v = xrealloc(s->v, s->cap * sizeof(*s->v));
    }
    s->v[s->n++] = sec;
}

/* --- one query as the agent dumped it -------------------------------------- */

struct agentq {
    char *label;          /* unescaped `query` label */
    double le[MAX_LE];    /* ok-code buckets summed over (db,user); +Inf = INFINITY */
    uint64_t cum[MAX_LE]; /* cumulative counts matching le[] */
    int nle;
    double sum_ok;        /* _sum over code="ok" series */
    uint64_t n_ok, n_err; /* _count over code="ok" / code="error" */
    uint64_t rows;        /* latkit_query_rows_total */
    bool joined;
    struct agentq *next; /* hash chain */
};

/* --- one query as the csvlog saw it ----------------------------------------- */

struct logq {
    uint64_t fp;
    char label[LK_QUERY_LABEL_MAX]; /* canonical text clipped like the agent's label */
    struct samples ok;              /* completed-statement durations, seconds */
    double sum_ok;
    uint64_t n_err;
    struct agentq *agent; /* joined agent row, NULL until joined */
};

/* --- tiny string-keyed hash (agent labels; extended-phase sessions) --------- */

static uint64_t str_hash(const char *s)
{
    uint64_t h = 1469598103934665603ull;

    for (; *s; s++)
        h = (h ^ (unsigned char)*s) * 1099511628211ull;
    return h;
}

#define AGENT_HBITS 12
static struct agentq *agent_tab[1u << AGENT_HBITS];

static struct agentq *agent_get(const char *label, bool create)
{
    uint32_t b = str_hash(label) & ((1u << AGENT_HBITS) - 1);
    struct agentq *a;

    for (a = agent_tab[b]; a; a = a->next)
        if (!strcmp(a->label, label))
            return a;
    if (!create)
        return NULL;
    a = xrealloc(NULL, sizeof(*a));
    memset(a, 0, sizeof(*a));
    a->label = xrealloc(NULL, strlen(label) + 1);
    strcpy(a->label, label);
    a->next = agent_tab[b];
    agent_tab[b] = a;
    return a;
}

/* Pending parse+bind seconds per csvlog session (extended protocol). */
struct sess {
    char *id;
    double pending;
    struct sess *next;
};
static struct sess *sess_tab[1u << AGENT_HBITS];

static struct sess *sess_get(const char *id)
{
    uint32_t b = str_hash(id) & ((1u << AGENT_HBITS) - 1);
    struct sess *s;

    for (s = sess_tab[b]; s; s = s->next)
        if (!strcmp(s->id, id))
            return s;
    s = xrealloc(NULL, sizeof(*s));
    s->id = xrealloc(NULL, strlen(id) + 1);
    strcpy(s->id, id);
    s->pending = 0;
    s->next = sess_tab[b];
    sess_tab[b] = s;
    return s;
}

/* --- fp-keyed log query table ----------------------------------------------- */

static struct logq **logqs;
static size_t n_logqs, cap_logqs;

static struct logq *logq_get(uint64_t fp, const char *label)
{
    for (size_t i = 0; i < n_logqs; i++) /* few dozen distinct fps: linear is fine */
        if (logqs[i]->fp == fp)
            return logqs[i];
    if (n_logqs == cap_logqs) {
        cap_logqs = cap_logqs ? cap_logqs * 2 : 64;
        logqs = xrealloc(logqs, cap_logqs * sizeof(*logqs));
    }
    struct logq *q = xrealloc(NULL, sizeof(*q));

    memset(q, 0, sizeof(*q));
    q->fp = fp;
    snprintf(q->label, sizeof(q->label), "%s", label);
    logqs[n_logqs++] = q;
    return q;
}

/* --- per-SQLSTATE error tallies ---------------------------------------------- */

static struct {
    char code[8];
    uint64_t log, agent;
} states[MAX_STATES];
static int n_states;

static void state_add(const char *code, bool agent_side, uint64_t n)
{
    int i;

    for (i = 0; i < n_states && strcmp(states[i].code, code); i++)
        ;
    if (i == n_states) {
        if (n_states == MAX_STATES)
            return;
        snprintf(states[n_states++].code, sizeof(states[0].code), "%s", code);
    }
    if (agent_side)
        states[i].agent += n;
    else
        states[i].log += n;
}

/* --- normalisation to the agent's label ------------------------------------- */

static uint32_t label_len = 255; /* the agent's effective --query-label-len default */

/* Same clip the registry applies (registry.c utf8_trunc): never mid-codepoint. */
static void utf8_trunc(const char *src, char *dst, uint32_t max_chars)
{
    size_t len = strlen(src);
    size_t n = len < max_chars ? len : max_chars;

    if (n < len)
        while (n > 0 && ((unsigned char)src[n] & 0xC0) == 0x80)
            n--;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static struct logq *logq_for_text(const char *sql)
{
    struct lk_norm_out norm;
    char label[LK_QUERY_LABEL_MAX];

    lk_norm_sql(sql, strlen(sql), LK_SQL_PG, &norm);
    utf8_trunc(norm.text, label, label_len);
    return logq_get(norm.fp, label);
}

/* --- dump (Prometheus text exposition) parser -------------------------------- */

struct lbl {
    const char *key;
    char *val;
};

/* Parse `name{k="v",...} value` in place. Returns the label count, -1 when the
 * line is not a sample. `name` and every label value are unescaped in place. */
static int parse_sample(char *line, char **name, struct lbl *lbls, int max, char **value)
{
    char *p = line;
    int n = 0;

    if (*p == '#' || *p == '\n' || !*p)
        return -1;
    *name = p;
    while (*p && *p != '{' && *p != ' ')
        p++;
    if (!*p)
        return -1;
    if (*p == ' ') {
        *p++ = '\0';
        *value = p;
        return 0;
    }
    *p++ = '\0'; /* consume '{' */
    while (*p && *p != '}') {
        if (n == max)
            return -1;
        lbls[n].key = p;
        while (*p && *p != '=')
            p++;
        if (*p != '=' || p[1] != '"')
            return -1;
        *p = '\0';
        p += 2;
        lbls[n].val = p;
        char *o = p;

        while (*p && *p != '"') {
            if (*p == '\\' && p[1]) {
                p++;
                *o++ = *p == 'n' ? '\n' : *p;
                p++;
            } else {
                *o++ = *p++;
            }
        }
        if (*p != '"')
            return -1;
        p++;
        *o = '\0';
        n++;
        if (*p == ',')
            p++;
    }
    if (*p != '}')
        return -1;
    p++;
    while (*p == ' ')
        p++;
    *value = p;
    return n;
}

static const char *lbl_get(const struct lbl *lbls, int n, const char *key)
{
    for (int i = 0; i < n; i++)
        if (!strcmp(lbls[i].key, key))
            return lbls[i].val;
    return NULL;
}

static double g_dropped, g_resync; /* validity counters out of the dump */
static uint64_t g_other_obs;       /* observations folded into query="other" */

static void agent_bucket_add(struct agentq *a, double le, uint64_t v)
{
    int i;

    for (i = 0; i < a->nle && a->le[i] != le; i++)
        ;
    if (i == a->nle) {
        if (a->nle == MAX_LE)
            return;
        a->le[a->nle++] = le;
    }
    a->cum[i] += v;
}

static void read_dump(const char *path)
{
    FILE *f = fopen(path, "r");
    char *line = NULL;
    size_t cap = 0;

    if (!f) {
        fprintf(stderr, "logjoin: %s: %s\n", path, strerror(errno));
        exit(2);
    }
    while (getline(&line, &cap, f) > 0) {
        char *name, *value;
        struct lbl lbls[8];
        int n = parse_sample(line, &name, lbls, 8, &value);

        if (n < 0)
            continue;
        if (!strcmp(name, "latkit_ringbuf_dropped_total")) {
            g_dropped += strtod(value, NULL);
            continue;
        }
        if (!strcmp(name, "latkit_resync_total")) {
            g_resync += strtod(value, NULL);
            continue;
        }
        if (!strcmp(name, "latkit_queries_other_total")) {
            g_other_obs = strtoull(value, NULL, 10);
            continue;
        }
        if (!strcmp(name, "latkit_query_errors_total")) {
            const char *st = lbl_get(lbls, n, "sqlstate");

            if (st)
                state_add(st, true, strtoull(value, NULL, 10));
            continue;
        }

        const char *q = lbl_get(lbls, n, "query");

        if (!q || !strcmp(q, "other"))
            continue;
        if (!strcmp(name, "latkit_query_rows_total")) {
            agent_get(q, true)->rows += strtoull(value, NULL, 10);
            continue;
        }

        const char *code = lbl_get(lbls, n, "code");

        if (!code)
            continue;
        if (!strcmp(name, "latkit_query_duration_seconds_count")) {
            if (!strcmp(code, "ok"))
                agent_get(q, true)->n_ok += strtoull(value, NULL, 10);
            else
                agent_get(q, true)->n_err += strtoull(value, NULL, 10);
        } else if (!strcmp(name, "latkit_query_duration_seconds_sum")) {
            if (!strcmp(code, "ok"))
                agent_get(q, true)->sum_ok += strtod(value, NULL);
        } else if (!strcmp(name, "latkit_query_duration_seconds_bucket")) {
            const char *le = lbl_get(lbls, n, "le");

            if (le && !strcmp(code, "ok"))
                agent_bucket_add(agent_get(q, true),
                                 strcmp(le, "+Inf") ? strtod(le, NULL) : INFINITY,
                                 strtoull(value, NULL, 10));
        }
    }
    free(line);
    fclose(f);
}

/* --- csvlog reader ------------------------------------------------------------ */

/* One RFC-4180 record (quoted fields, embedded newlines) into NUL-separated
 * fields inside a growing buffer. Returns the field count, 0 at EOF. */
#define MAX_FIELDS 32
static int csv_record(FILE *f, char **buf, size_t *cap, char *fields[MAX_FIELDS])
{
    size_t len = 0;
    int nf = 0, c;
    bool inq = false, any = false;
    size_t start = 0;

    for (;;) {
        c = getc(f);
        if (c == EOF) {
            if (!any)
                return 0;
            c = '\n';
        }
        if (len + 2 > *cap) {
            *cap = *cap ? *cap * 2 : 4096;
            *buf = xrealloc(*buf, *cap);
        }
        if (inq) {
            if (c == '"') {
                int c2 = getc(f);

                if (c2 == '"') {
                    (*buf)[len++] = '"';
                } else {
                    inq = false;
                    if (c2 != EOF)
                        ungetc(c2, f);
                }
            } else {
                (*buf)[len++] = (char)c;
            }
            any = true;
            continue;
        }
        if (c == '"') {
            inq = true;
            any = true;
        } else if (c == ',' || c == '\n') {
            (*buf)[len++] = '\0';
            if (nf < MAX_FIELDS)
                fields[nf++] = *buf + start;
            start = len;
            if (c == '\n') {
                if (any || nf > 1)
                    break;
                nf = 0; /* blank line */
                len = start = 0;
            } else {
                any = true;
            }
        } else if (c != '\r') {
            (*buf)[len++] = (char)c;
            any = true;
        }
    }
    /* Field pointers were taken as the buffer grew; recompute from offsets is
     * unnecessary because xrealloc may move the block only between records —
     * so re-derive them now, walking the NUL-separated buffer. */
    char *p = *buf;

    for (int i = 0; i < nf; i++) {
        fields[i] = p;
        p += strlen(p) + 1;
    }
    return nf;
}

/* "duration: 1.234 ms<tail>" -> seconds and the tail; false when not one. */
static bool parse_duration(const char *msg, double *sec, const char **tail)
{
    if (strncmp(msg, "duration: ", 10))
        return false;
    char *end;
    double ms = strtod(msg + 10, &end);

    if (end == msg + 10 || strncmp(end, " ms", 3))
        return false;
    *sec = ms / 1000.0;
    *tail = end + 3;
    return true;
}

static uint64_t g_log_lines, g_local_skipped;

static void read_csvlog(const char *path)
{
    FILE *f = fopen(path, "r");
    char *buf = NULL;
    size_t cap = 0;
    char *fields[MAX_FIELDS];
    int nf;

    if (!f) {
        fprintf(stderr, "logjoin: %s: %s\n", path, strerror(errno));
        exit(2);
    }
    while ((nf = csv_record(f, &buf, &cap, fields)) > 0) {
        if (nf < COL_MIN)
            continue;
        g_log_lines++;
        const char *conn = fields[COL_CONN];

        /* Unix-socket sessions (the stand's control plane) never cross the
         * capture point; keep both views of the workload identical. */
        if (!*conn || !strncmp(conn, "[local]", 7)) {
            g_local_skipped++;
            continue;
        }
        const char *sev = fields[COL_SEVERITY];

        if (!strcmp(sev, "ERROR")) {
            const char *sql = fields[COL_QUERY];

            if (*sql)
                logq_for_text(sql)->n_err++;
            if (*fields[COL_SQLSTATE])
                state_add(fields[COL_SQLSTATE], false, 1);
            sess_get(fields[COL_SESSION])->pending = 0; /* drop half-built phases */
            continue;
        }
        if (strcmp(sev, "LOG"))
            continue;

        double sec;
        const char *tail;

        if (!parse_duration(fields[COL_MESSAGE], &sec, &tail))
            continue;
        while (*tail == ' ')
            tail++;
        if (!strncmp(tail, "statement: ", 11)) {
            struct logq *q = logq_for_text(tail + 11);

            sample_add(&q->ok, sec);
            q->sum_ok += sec;
        } else if (!strncmp(tail, "parse ", 6) || !strncmp(tail, "bind ", 5)) {
            sess_get(fields[COL_SESSION])->pending += sec;
        } else if (!strncmp(tail, "execute ", 8)) {
            const char *sql = strchr(tail + 8, ':');
            struct sess *se = sess_get(fields[COL_SESSION]);

            if (sql) {
                struct logq *q = logq_for_text(sql + 1 + (sql[1] == ' '));
                double d = sec + se->pending;

                sample_add(&q->ok, d);
                q->sum_ok += d;
            }
            se->pending = 0;
        }
        /* bare "duration: X ms" (log_duration) carries no text: ignored */
    }
    free(buf);
    fclose(f);
}

/* --- percentiles ---------------------------------------------------------------- */

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;

    return x < y ? -1 : x > y;
}

/* Nearest-rank percentile of a sorted vector. */
static double quant_raw(const double *v, size_t n, double q)
{
    size_t r = (size_t)ceil(q * (double)n);

    if (r < 1)
        r = 1;
    if (r > n)
        r = n;
    return v[r - 1];
}

/* histogram_quantile: (upper-bound, cumulative-count) pairs sorted by bound,
 * +Inf last; linear interpolation inside the bucket, first bucket from 0,
 * the +Inf bucket answers with the highest finite bound (Prometheus rules —
 * the same estimator serves the agent's and the log's buckets, so estimator
 * bias cancels out of the comparison). */
static double hist_quantile(const double *ub, const uint64_t *cum, int n, double q)
{
    if (!n || !cum[n - 1])
        return 0;
    double rank = q * (double)cum[n - 1];
    int i = 0;

    while (i < n - 1 && (double)cum[i] < rank)
        i++;
    if (isinf(ub[i]))
        return i ? ub[i - 1] : 0;
    double lo = i ? ub[i - 1] : 0.0;
    uint64_t prev = i ? cum[i - 1] : 0;
    uint64_t inb = cum[i] - prev;

    if (!inb)
        return ub[i];
    return lo + (ub[i] - lo) * ((rank - (double)prev) / (double)inb);
}

/* The classic export boundaries (hist.c): every 4th grid index, le = 2^(lt/4). */
static const int classic_lt[] = {-52, -48, -44, -40, -36, -32, -28, -24, -20, -16,
                                 -12, -8,  -4,  0,   4,   8,   12,  16,  20};
#define N_CLASSIC ((int)(sizeof(classic_lt) / sizeof(classic_lt[0])))

/* Discretise samples exactly the way lk_hist + lk_hist_write would, then take
 * the quantile: through the fine Р24 grid or the classic factor-2 boundaries. */
static double quant_gridded(const double *v, size_t n, double q, bool fine)
{
    double ub[LK_HIST_NBUCKETS + 2];
    uint64_t cum[LK_HIST_NBUCKETS + 2];
    int nb = 0;

    if (fine) {
        for (int k = LK_HIST_MIN_INDEX; k <= LK_HIST_MAX_INDEX; k++)
            ub[nb++] = lk_hist_bound(k); /* underflow upper bound first */
        ub[nb++] = INFINITY;
    } else {
        for (int i = 0; i < N_CLASSIC; i++)
            ub[nb++] = lk_hist_bound(classic_lt[i]);
        ub[nb++] = INFINITY;
    }
    memset(cum, 0, sizeof(cum[0]) * nb);
    for (size_t i = 0; i < n; i++) {
        int idx = v[i] > 0 ? lk_hist_index(v[i]) : LK_HIST_MIN_INDEX - 1;
        int b;

        if (fine) {
            if (idx < LK_HIST_MIN_INDEX)
                b = 0;
            else if (idx >= LK_HIST_MAX_INDEX)
                b = nb - 1;
            else
                b = idx - LK_HIST_MIN_INDEX + 1;
        } else {
            for (b = 0; b < N_CLASSIC && idx >= classic_lt[b]; b++)
                ;
        }
        cum[b]++;
    }
    for (int b = 1; b < nb; b++)
        cum[b] += cum[b - 1];
    return hist_quantile(ub, cum, nb, q);
}

/* Agent-side quantile from the dump's (le, cum) pairs. */
static double agent_quantile(struct agentq *a, double q)
{
    /* insertion-sort by le; the dump is already ascending, this is a guard */
    for (int i = 1; i < a->nle; i++) {
        double le = a->le[i];
        uint64_t c = a->cum[i];
        int j = i;

        for (; j > 0 && a->le[j - 1] > le; j--) {
            a->le[j] = a->le[j - 1];
            a->cum[j] = a->cum[j - 1];
        }
        a->le[j] = le;
        a->cum[j] = c;
    }
    return hist_quantile(a->le, a->cum, a->nle, q);
}

/* --- main ------------------------------------------------------------------------ */

static int cmp_logq(const void *x, const void *y)
{
    const struct logq *a = *(struct logq *const *)x, *b = *(struct logq *const *)y;

    if (a->ok.n != b->ok.n)
        return a->ok.n < b->ok.n ? 1 : -1;
    return strcmp(a->label, b->label);
}

static void usage(void)
{
    fprintf(stderr,
            "usage: logjoin -d dump.prom [options] csvlog.csv...\n"
            "  -d FILE   latkit --dump-metrics exposition (required)\n"
            "  -l N      agent's effective --query-label-len (default 255)\n"
            "  -m MS     p50/p95 acceptance only for queries with mean >= MS (default 1.0)\n"
            "  -n N      ... and with at least N ok samples (default 50)\n"
            "  -t PCT    p50/p95 relative tolerance, percent (default 5)\n"
            "  -c        check: exit 1 when acceptance fails\n");
    exit(2);
}

int main(int argc, char **argv)
{
    const char *dump = NULL;
    double min_ms = 1.0, tol = 5.0;
    uint64_t min_samples = 50;
    bool check = false;
    int failures = 0, opt;

    while ((opt = getopt(argc, argv, "d:l:m:n:t:c")) != -1) {
        switch (opt) {
        case 'd':
            dump = optarg;
            break;
        case 'l':
            label_len = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'm':
            min_ms = strtod(optarg, NULL);
            break;
        case 'n':
            min_samples = strtoull(optarg, NULL, 10);
            break;
        case 't':
            tol = strtod(optarg, NULL);
            break;
        case 'c':
            check = true;
            break;
        default:
            usage();
        }
    }
    if (!dump || optind == argc)
        usage();
    if (!label_len || label_len >= LK_QUERY_LABEL_MAX)
        label_len = LK_QUERY_LABEL_MAX - 1;

    read_dump(dump);
    for (int i = optind; i < argc; i++)
        read_csvlog(argv[i]);

    /* join */
    for (size_t i = 0; i < n_logqs; i++) {
        struct logq *q = logqs[i];

        q->agent = agent_get(q->label, false);
        if (q->agent)
            q->agent->joined = true;
    }
    qsort(logqs, n_logqs, sizeof(*logqs), cmp_logq);

    printf("query\tn_log\tn_agent\terr_log\terr_agent\tmean_log_ms\tmean_agent_ms\toffset_us\t"
           "p50_raw_ms\tp50_fine_ms\tp50_grid_ms\tp50_agent_ms\tdp50_pct\tdp50_adj_pct\t"
           "p95_raw_ms\tp95_fine_ms\tp95_grid_ms\tp95_agent_ms\tdp95_pct\tdp95_adj_pct\t"
           "rows_agent\tverdict\n");

    double joined_sum_log = 0, joined_sum_agent = 0;
    uint64_t joined_n = 0, log_only = 0, agent_only = 0;

    for (size_t i = 0; i < n_logqs; i++) {
        struct logq *q = logqs[i];
        struct agentq *a = q->agent;
        char verdict[128] = "";

        if (!a) {
            log_only++;
            failures++;
            printf("%s\t%zu\t-\t%llu\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t"
                   "LOG-ONLY\n",
                   q->label, q->ok.n, (unsigned long long)q->n_err);
            continue;
        }
        if (a->n_ok != q->ok.n)
            snprintf(verdict + strlen(verdict), sizeof(verdict) - strlen(verdict),
                     "count(%llu!=%zu) ", (unsigned long long)a->n_ok, q->ok.n);
        if (a->n_err != q->n_err)
            snprintf(verdict + strlen(verdict), sizeof(verdict) - strlen(verdict),
                     "err(%llu!=%llu) ", (unsigned long long)a->n_err,
                     (unsigned long long)q->n_err);

        double mean_log = 0, mean_agent = 0, offset = 0;
        double p_raw[2] = {0, 0}, p_fine[2] = {0, 0}, p_grid[2] = {0, 0}, p_ag[2] = {0, 0};
        double dp[2] = {0, 0}, dpa[2] = {0, 0};
        static const double qq[2] = {0.50, 0.95};

        if (q->ok.n && a->n_ok) {
            qsort(q->ok.v, q->ok.n, sizeof(double), cmp_double);
            mean_log = q->sum_ok / (double)q->ok.n;
            mean_agent = a->sum_ok / (double)a->n_ok;
            offset = mean_agent - mean_log;
            double *shifted = xrealloc(NULL, q->ok.n * sizeof(double));

            for (size_t s = 0; s < q->ok.n; s++)
                shifted[s] = q->ok.v[s] + offset;
            for (int p = 0; p < 2; p++) {
                p_raw[p] = quant_raw(q->ok.v, q->ok.n, qq[p]);
                p_fine[p] = quant_gridded(q->ok.v, q->ok.n, qq[p], true);
                p_grid[p] = quant_gridded(q->ok.v, q->ok.n, qq[p], false);
                p_ag[p] = agent_quantile(a, qq[p]);
                dp[p] = p_grid[p] > 0 ? (p_ag[p] - p_grid[p]) / p_grid[p] * 100.0 : 0;
                /* the gate: same grid, log shifted by the measured offset —
                 * shape agreement under `agent = log + const` (see header) */
                double ps = quant_gridded(shifted, q->ok.n, qq[p], false);

                dpa[p] = ps > 0 ? (p_ag[p] - ps) / ps * 100.0 : 0;
            }
            free(shifted);
            /* p50/p95 acceptance: big-enough samples, and queries long enough
             * that the offset is relative noise rather than the whole number
             * (sub-ms is reported as a value, not gated — Р50). */
            if (q->ok.n >= min_samples && mean_log * 1000.0 >= min_ms) {
                if (fabs(dpa[0]) > tol)
                    snprintf(verdict + strlen(verdict), sizeof(verdict) - strlen(verdict),
                             "p50(%+.1f%%) ", dpa[0]);
                if (fabs(dpa[1]) > tol)
                    snprintf(verdict + strlen(verdict), sizeof(verdict) - strlen(verdict),
                             "p95(%+.1f%%) ", dpa[1]);
            }
            joined_sum_log += q->sum_ok;
            joined_sum_agent += a->sum_ok;
            joined_n += q->ok.n;
        }
        if (verdict[0])
            failures++;
        printf("%s\t%zu\t%llu\t%llu\t%llu\t%.4f\t%.4f\t%+.1f\t"
               "%.4f\t%.4f\t%.4f\t%.4f\t%+.2f\t%+.2f\t%.4f\t%.4f\t%.4f\t%.4f\t%+.2f\t%+.2f\t"
               "%llu\t%s\n",
               q->label, q->ok.n, (unsigned long long)a->n_ok, (unsigned long long)q->n_err,
               (unsigned long long)a->n_err, mean_log * 1e3, mean_agent * 1e3, offset * 1e6,
               p_raw[0] * 1e3, p_fine[0] * 1e3, p_grid[0] * 1e3, p_ag[0] * 1e3, dp[0], dpa[0],
               p_raw[1] * 1e3, p_fine[1] * 1e3, p_grid[1] * 1e3, p_ag[1] * 1e3, dp[1], dpa[1],
               (unsigned long long)a->rows, verdict[0] ? verdict : "ok");
    }

    /* agent series the log never produced (should not happen on a clean stand) */
    for (uint32_t b = 0; b < (1u << AGENT_HBITS); b++)
        for (struct agentq *a = agent_tab[b]; a; a = a->next)
            if (!a->joined) {
                agent_only++;
                failures++;
                printf("%s\t-\t%llu\t-\t%llu\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t%llu\t"
                       "AGENT-ONLY\n",
                       a->label, (unsigned long long)a->n_ok, (unsigned long long)a->n_err,
                       (unsigned long long)a->rows);
            }

    for (int i = 0; i < n_states; i++) {
        bool ok = states[i].log == states[i].agent;

        if (!ok)
            failures++;
        printf("# sqlstate %s: log=%llu agent=%llu %s\n", states[i].code,
               (unsigned long long)states[i].log, (unsigned long long)states[i].agent,
               ok ? "ok" : "MISMATCH");
    }
    if (g_other_obs) {
        printf("# WARNING: %llu observations folded into query=\"other\" — raise --top-queries\n",
               (unsigned long long)g_other_obs);
        failures++;
    }
    if (g_dropped || g_resync) {
        printf("# INVALID: dropped=%g resync=%g — a lossy run proves nothing (Р49/Р50)\n",
               g_dropped, g_resync);
        failures++;
    }
    printf("# log: %llu rows, %llu [local] control rows skipped\n", (unsigned long long)g_log_lines,
           (unsigned long long)g_local_skipped);
    printf("# join: %zu log queries, log-only=%llu agent-only=%llu\n", n_logqs,
           (unsigned long long)log_only, (unsigned long long)agent_only);
    if (joined_n)
        printf("# offset: mean agent-log over %llu joined samples = %+.1f us\n",
               (unsigned long long)joined_n,
               (joined_sum_agent - joined_sum_log) / (double)joined_n * 1e6);
    printf("# verdict: %s (%d failing checks)\n", failures ? "FAIL" : "PASS", failures);

    return check && failures ? 1 : 0;
}
