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
#include <time.h>

#include "hist.h"

/* CLOCK_MONOTONIC now, in nanoseconds — the same clock as the pipeline's event
 * timestamps (Р13), so a series' created_ns converts to wall time through the
 * one timebase (Р33). This is the registry's only OS read; like selfstats.c it
 * is a documented exception to "I/O only via FILE" (no libbpf, no heap). */
static uint64_t reg_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

#define LK_DOORKEEPER_SLOTS 2048u /* Р23: N ~= 2K candidate fingerprints */
#define LK_MAX_ERR_CODES    64u   /* Р23: distinct SQLSTATEs / HTTP statuses before "other" */
/* proto="pg"|"mysql"|"http" (РМ6/М6, РH9): an orthogonal bounded axis, so a
 * single-protocol deployment's (db,user) cardinality is byte-identical to before
 * — the label is simply pinned to the one protocol. Sized to the protocol
 * registry (LK_PROTO_MAX, raised to 8 for the HTTP track: pg + mysql + http +
 * the s3 dialect already filled the old ceiling of 4) with a spill slot; the
 * "other" proto never triggers in practice. */
#define LK_MAX_PROTOS 8u

/* The method / operation stored beside a slot's label (РH7): "GET", later an S3
 * operation name. Part of the slot's *identity* — the fingerprint covers it —
 * rather than a label resolved at print time, because two methods on one path
 * are two routes and must hold two dictionary slots. */
#define LK_REG_OP_MAX 16

struct series {
    struct series *h_next; /* hash chain */
    struct series *q_next; /* owning slot's list (for the other-fold) */
    uint32_t qslot;        /* query slot, or r->k for "other" */
    uint32_t dim;          /* dim id, or r->max_dims for (other,other) */
    uint32_t proto;        /* proto id (interned; LK_MAX_PROTOS = "other") */
    uint8_t code;          /* enum lk_code (ok|error) */
    uint64_t created_ns;   /* mono; when this stream began -> OTLP start_time (Р31) */
    uint64_t rows;         /* latkit_query_rows_total (summed over code at dump) */
    struct lk_hist dur;
    struct lk_hist *first_row; /* first_row / http TTFB, lazy (flag off = NULL) */

    /* http profile only (РH9), all lazy or zero-valued for a query series: the
     * per-class request tally, the two byte counters and the second and third
     * histograms. A PG series pays 56 bytes of zeroes for them next to its own
     * ~700 — the alternative was a second series type and a second hash table,
     * which is a lot of machinery to save a cache line.
     *
     * `tally` is the profile's total counter split along its own outcome axis:
     * the status class for http/s3, the outcome code for redis (МR5). One array
     * because the two axes are the same shape — a small closed set of values,
     * one series each — and the profile row says which vocabulary reads it. */
    uint64_t tally[LK_N_SCLASSES]; /* f_total, summed over the duration code */
    uint64_t bytes_in, bytes_out;
    struct lk_hist *upload; /* latkit_http_request_upload_seconds */
    struct lk_bhist *size;  /* latkit_http_response_size_bytes */
};

struct qentry {
    uint64_t fp;
    bool used;
    int32_t lru_prev, lru_next; /* indices into entries[], -1 = none */
    struct series *series;      /* head of this slot's series list */
    char label[LK_QUERY_LABEL_MAX];
    char op[LK_REG_OP_MAX]; /* http: the method; "" for the query profile */
};

struct dim {
    char db[64], user[64];
};

/* --- observation profiles (РH10) ------------------------------------------
 * Which families an observation touches, and under which label keys. The whole
 * difference between a database observation and an HTTP one lives in this
 * table: everything below it — admission, eviction, the dim limit, the sort,
 * the escaping, the OTLP views — is written once and reads the table. */
enum {
    RF_QTOTAL = 1u << 0,    /* latkit_queries_total{db,user,proto,kind,code} */
    RF_TOTAL = 1u << 1,     /* the slot-keyed total counter, split along the
                               profile's own outcome axis: latkit_http_requests_
                               total{...,status} / latkit_redis_commands_total
                               {...,code}. Unlike RF_QTOTAL it is recorded for
                               observations that carry no duration too (МR5) */
    RF_DURATION = 1u << 2,  /* the latency histogram (every profile has one) */
    RF_ROWS = 1u << 3,      /* latkit_query_rows_total */
    RF_FIRST_ROW = 1u << 4, /* second histogram, opt-in (cfg.first_row_hist) */
    RF_TTFB = 1u << 5,      /* ... same storage, always on (РH9: TTFB is headline) */
    RF_ERRORS = 1u << 6,    /* the error-code counter */
    RF_TRUNCATED = 1u << 7, /* latkit_queries_truncated_total */
    RF_OTHER = 1u << 8,     /* latkit_queries_other_total */
    RF_TXN = 1u << 9,       /* latkit_txn_duration_seconds — printed by the profile
                               that owns the family, for every protocol that fed
                               it: one name, one HELP/TYPE block (РR9) */
    RF_UPLOAD = 1u << 10,   /* latkit_http_request_upload_seconds */
    RF_BYTES = 1u << 11,    /* latkit_http_bytes_total{direction} */
    RF_SIZE = 1u << 12,     /* latkit_http_response_size_bytes / _s3_object_size_bytes
                               / _redis_value_size_bytes */
    RF_INTERNAL = 1u << 13, /* latkit_s3_internal_requests_total (РS2) */
    RF_BLOCKING = 1u << 14, /* latkit_redis_blocking_seconds (РR10) — the second
                               histogram's storage again, holding the one duration
                               that is the client's choice rather than the
                               server's work */
    RF_REDIRECT = 1u << 15, /* latkit_redis_redirects_total{kind} (РR7) */
    RF_DEPTH = 1u << 16,    /* latkit_redis_pipeline_depth (РR3) */
};

struct reg_family {
    const char *name, *help;
};

struct reg_profile {
    uint32_t families;
    /* Label keys. k_op is NULL for a profile whose slot identity is the text
     * alone; every other key is mandatory, because a family printed without a
     * key that is part of its identity emits duplicate series. Note that k_slot
     * and k_op are the two halves of the *dictionary slot*, whatever they are
     * called: for s3 the slot is the operation (`op="PutObject"`) and k_op is
     * still the HTTP verb (`method="PUT"`), because the fingerprint covers both
     * exactly as it does for a route. */
    const char *k_slot, *k_op, *k_db, *k_user, *k_err;
    /* f_total's outcome axis (МR5): the label key, and which of the two closed
     * vocabularies its values come from. `status="2xx"` for an exchange whose
     * outcome the protocol states as a number, `code="ok"` for a command whose
     * outcome is the four states an observation can end in. */
    const char *k_total;
    bool total_qcode; /* true: index by enum lk_qcode, print qcode_str */
    /* The octave grid of f_size (hist.h): which one is a property of what the
     * family measures — an HTTP response body, an S3 object and a Redis value
     * are three questions with three extents. 0 = the default (РH9) grid. */
    uint8_t size_min_log2, size_nbuckets;
    struct reg_family f_total, f_dur, f_rows, f_second, f_err, f_upload, f_bytes, f_size;
    struct reg_family f_internal, f_redirect, f_depth;
};

/* The tally array serves both axes, so the wider one has to be the storage. */
_Static_assert((int)LK_N_QCODES <= (int)LK_N_SCLASSES,
               "series.tally must hold either outcome axis");

/* The values of f_total's axis, and how many there are. */
static const char *sclass_str(uint32_t c);
static const char *qcode_str(uint32_t c);

static inline uint32_t total_axis_n(const struct reg_profile *pf)
{
    return pf->total_qcode ? LK_N_QCODES : LK_N_SCLASSES;
}

static inline const char *total_axis_str(const struct reg_profile *pf, uint32_t i)
{
    return pf->total_qcode ? qcode_str(i) : sclass_str(i);
}

static const struct reg_profile profiles[LK_N_PROFILES] = {
    [LK_PROF_QUERY] =
        {
            .families = RF_QTOTAL | RF_DURATION | RF_ROWS | RF_FIRST_ROW | RF_ERRORS |
                        RF_TRUNCATED | RF_OTHER | RF_TXN,
            .k_slot = "query",
            .k_op = NULL,
            .k_db = "db",
            .k_user = "user",
            .k_err = "sqlstate",
            .f_total = {"latkit_queries_total", "Query observations by kind and outcome."},
            .f_dur = {"latkit_query_duration_seconds", "Server-side query latency in seconds."},
            .f_rows = {"latkit_query_rows_total", "Rows returned/affected, from CommandComplete."},
            .f_second = {"latkit_query_first_row_seconds", "Time to first row in seconds."},
            .f_err = {"latkit_query_errors_total", "Errors by SQLSTATE (query-independent)."},
        },
    [LK_PROF_HTTP] =
        {
            .families =
                RF_TOTAL | RF_DURATION | RF_TTFB | RF_ERRORS | RF_UPLOAD | RF_BYTES | RF_SIZE,
            .k_slot = "route",
            .k_op = "method",
            .k_db = "host",
            .k_user = "user",
            .k_err = "code",
            .k_total = "status",
            .f_total = {"latkit_http_requests_total",
                        "HTTP exchanges observed, by route and status class."},
            .f_dur = {"latkit_http_request_duration_seconds",
                      "Server-side HTTP latency in seconds: last response byte minus last "
                      "request byte, so a slow upload is not a slow server (РH5)."},
            .f_second = {"latkit_http_ttfb_seconds",
                         "Time to the first response byte in seconds, from the end of the "
                         "request."},
            .f_err = {"latkit_http_errors_total",
                      "Responses with status >= 400, by exact code (route-independent)."},
            .f_upload = {"latkit_http_request_upload_seconds",
                         "Time spent receiving the request body in seconds."},
            .f_bytes = {"latkit_http_bytes_total", "HTTP body bytes observed, by direction."},
            .f_size = {"latkit_http_response_size_bytes", "Response body size in bytes."},
        },
    /* The S3 profile (РS7, PLAN-MINIO.md МS2). The same seven families as the
     * http one and the same engine underneath — an S3 exchange *is* an HTTP
     * exchange (РS1) — with four differences, and each of them is a difference
     * in what the number means rather than in how it is computed:
     *
     *   - the slot is the **operation**, a value from a closed table (РS2), so
     *     `op` needs no top-K reasoning to stay bounded and reads as a name
     *     rather than as a path;
     *   - the dim slot the http profile fills with the request's Host holds the
     *     **bucket** (РS3), and the user slot the **access key** (РS4);
     *   - the error label is the symbolic **S3 code** — `NoSuchKey` and
     *     `NoSuchBucket` are both `404` and are not the same page at 3 a.m.
     *     (РS5) — falling back to the status when no code was readable;
     *   - the size family measures the **object**, on the object grid and with
     *     the aws-chunked framing discounted (РS6), because a distribution that
     *     moves with the client's chunk size describes the client.
     *
     * `rows` and `txn` are off: an object store has neither. */
    [LK_PROF_S3] =
        {
            .families = RF_TOTAL | RF_DURATION | RF_TTFB | RF_ERRORS | RF_UPLOAD | RF_BYTES |
                        RF_SIZE | RF_INTERNAL,
            .k_slot = "op",
            .k_op = "method",
            .k_db = "bucket",
            .k_user = "user",
            .k_err = "s3code",
            .k_total = "status",
            .size_min_log2 = LK_OHIST_MIN_LOG2,
            .size_nbuckets = LK_OHIST_NBUCKETS,
            .f_total = {"latkit_s3_requests_total",
                        "S3 operations observed, by operation and status class."},
            .f_dur = {"latkit_s3_request_duration_seconds",
                      "Server-side S3 latency in seconds: last response byte minus last request "
                      "byte, so a slow upload is not a slow server (РH5)."},
            .f_second = {"latkit_s3_ttfb_seconds",
                         "Time to the first response byte in seconds, from the end of the "
                         "request."},
            .f_err = {"latkit_s3_errors_total",
                      "Failed S3 operations by error code — the `<Code>` of the error body, or "
                      "the HTTP status when none was readable (operation-independent)."},
            .f_upload = {"latkit_s3_request_upload_seconds",
                         "Time spent receiving the request body in seconds."},
            .f_bytes = {"latkit_s3_bytes_total", "S3 body bytes on the wire, by direction."},
            .f_size = {"latkit_s3_object_size_bytes",
                       "Size in bytes of the payload an operation moved, with the aws-chunked "
                       "framing discounted (РS6)."},
            .f_internal = {"latkit_s3_internal_requests_total",
                           "Requests to the server's own API (/minio/...): counted here and "
                           "reported in no other family (РS2)."},
        },
    /* The Redis profile (РR11, PLAN-REDIS.md МR5). A fourth row, and the engine
     * below it is again untouched — but this one is not the http shape under
     * different nouns, because a cache is not a request/response service with a
     * status line. What it does *not* have is as much of the design as what it
     * does: no `rows` (a reply is one value), no TTFB (a reply has no first row
     * to arrive early — reporting one would put a family on the dashboard that
     * always equals the duration), no upload (there is no request body separate
     * from the command), no status class (RESP has no statuses), and no `method`
     * beside the slot (the command *is* the identity; РR4's subcommand is part
     * of it, so `CONFIG|GET` is one slot and not `CONFIG` split by a verb).
     *
     * What it has instead is four decisions, each of them a number kept out of a
     * place where it would be plausible and wrong:
     *
     *   - **the total counter is keyed by outcome, and counts the untimed.** A
     *     `+QUEUED` inside a `MULTI` (РR9) and a `BLPOP` that waited out the
     *     client's own timeout (РR10) are commands and are counted as such; what
     *     they are not is latencies, and the duration histogram never sees them;
     *   - **the blocking wait has a family of its own** (РR10). It is measured —
     *     an application waiting 30 s on an empty list is a fact about that
     *     application — in a place where it cannot decide the p99 of a `GET`;
     *   - **the redirect has a family of its own** (РR7): `-MOVED` and `-ASK`
     *     are error replies that mean the cluster is working, and in
     *     `errors_total` they would paint a resharding cluster red for ever;
     *   - **the value size gets a third octave grid** (hist.h): half of what a
     *     Redis holds is smaller than the HTTP grid's first bucket.
     *
     * `txn` is off here and *on* in the query profile, which is where the
     * `MULTI`…`EXEC` interval is printed from: one family, one HELP block, keyed
     * by proto like every other (РR9 — the one place where a cache fits an
     * existing database family exactly). */
    [LK_PROF_REDIS] =
        {
            .families = RF_TOTAL | RF_DURATION | RF_ERRORS | RF_BYTES | RF_SIZE | RF_BLOCKING |
                        RF_REDIRECT | RF_DEPTH,
            .k_slot = "cmd",
            .k_op = NULL,
            .k_db = "db",
            .k_user = "user",
            .k_err = "error",
            .k_total = "code",
            .total_qcode = true,
            .size_min_log2 = LK_VHIST_MIN_LOG2,
            .size_nbuckets = LK_VHIST_NBUCKETS,
            .f_total = {"latkit_redis_commands_total",
                        "Redis commands observed, by command and outcome."},
            .f_dur = {"latkit_redis_command_duration_seconds",
                      "Command latency in seconds: last byte of the reply minus first byte of "
                      "the command. Excludes blocking commands and queued MULTI members, whose "
                      "duration is not the server's work (РR9/РR10)."},
            .f_second = {"latkit_redis_blocking_seconds",
                         "Time a blocking command (BLPOP, XREAD BLOCK, WAIT) waited — the "
                         "client's own timeout, not the server's service time."},
            .f_err = {"latkit_redis_errors_total",
                      "Failed commands by symbolic error (WRONGTYPE, NOSCRIPT, ...), "
                      "command-independent. MOVED/ASK are redirects and are not here."},
            .f_bytes = {"latkit_redis_bytes_total", "RESP bytes on the wire, by direction."},
            .f_size = {"latkit_redis_value_size_bytes", "Size in bytes of the reply value."},
            .f_redirect = {"latkit_redis_redirects_total",
                           "Cluster redirects (-MOVED / -ASK): ordinary cluster operation, "
                           "counted apart from the errors (РR7)."},
            .f_depth = {"latkit_redis_pipeline_depth",
                        "Commands that arrived in the same syscall as this one, sampled per "
                        "command: le=\"1\" is a client that does not pipeline."},
        },
};

static const struct reg_profile *profile_of(uint8_t id)
{
    return &profiles[id < LK_N_PROFILES ? id : LK_PROF_QUERY];
}

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

    struct {
        char name[8];        /* "pg" / "mysql" / "http" (lk_proto_ops.name) */
    } protos[LK_MAX_PROTOS]; /* interned; overflow -> proto index LK_MAX_PROTOS */
    uint32_t n_protos;
    /* The profile each interned proto reports under (РH10), including the spill
     * slot at index LK_MAX_PROTOS: the dump walks protocols, so it needs to know
     * which family names a proto id prints under. The spill takes the profile of
     * whoever overflowed first, which needs a ninth distinct protocol name to
     * even happen — the registry itself caps at LK_PROTO_MAX = 8. */
    uint8_t proto_prof[LK_MAX_PROTOS + 1];
    /* A profile prints nothing until it has seen an observation, so a PG-only
     * agent's exposition is exactly what it was before the http families
     * existed. LK_PROF_QUERY starts true: its blocks (with their zero counters)
     * have always been in the dump, and something scraping them must not have
     * them disappear on an idle agent. */
    bool used[LK_N_PROFILES];

    struct series **sbuckets;
    uint32_t sbuckets_n; /* power of two */
    uint32_t n_series;

    /* Bounded label-keyed families, flat over the interned dimensions. dim ids
     * run [0, max_dims] (max_dims = the (other,other) pseudo-pair), so each is
     * sized ndims = max_dims + 1; the orthogonal proto axis adds a factor of
     * nprotos = LK_MAX_PROTOS + 1 (the last index is the "other" proto). */
    uint64_t *q_total;   /* [ndims][nprotos][N_QKINDS][N_QCODES] latkit_queries_total */
    uint64_t *err_total; /* [MAX_ERR_CODES+1][ndims][nprotos] the profile's error counter */
    struct lk_hist *txn; /* [ndims][nprotos][2] latkit_txn_duration_seconds (ok|aborted) */
    /* Interned error codes, one namespace per profile: a SQLSTATE and an HTTP
     * status are different alphabets and must not compete for the same 64 slots.
     * err_total is still keyed by the code id alone, because the proto in its
     * key already determines the profile — hence which namespace to read the id
     * back through. */
    struct {
        /* A SQLSTATE is 5 bytes and an HTTP status 3; the S3 vocabulary of РS5
         * reaches 45 (`ServerSideEncryptionConfigurationNotFoundError`), which
         * is what sizes this. 9 KB of table for the three namespaces together. */
        char code[48];
    } err_codes[LK_N_PROFILES][LK_MAX_ERR_CODES];
    uint32_t n_err_codes[LK_N_PROFILES];

    /* The two families keyed by the protocol alone (РR7/РR3): neither belongs to
     * a command's series — a redirect is an answer about the *cluster* and a
     * batch depth is a property of a syscall — and both are bounded by the proto
     * axis, so they are flat arrays rather than anything the dictionary sees.
     * The depth histograms are allocated with the registry (nprotos * ~280 B =
     * 2.5 KB) rather than per use: an allocation on the hot path of the fastest
     * protocol the agent watches would be the wrong trade for two kilobytes.
     * Only their *grid* is set on first sight, since it belongs to the family
     * and a zeroed lk_bhist means the default one (hist.h). */
    uint64_t redirects[LK_N_REDIRECTS][LK_MAX_PROTOS + 1];
    struct lk_bhist *depth; /* [nprotos] */

    uint64_t truncated_obs[LK_N_PROFILES]; /* latkit_queries_truncated_total */
    uint64_t total_obs[LK_N_PROFILES];
    uint64_t other_obs[LK_N_PROFILES];
    uint64_t internal_obs[LK_N_PROFILES]; /* latkit_s3_internal_requests_total (РS2) */

    uint64_t created_ns; /* mono; registry construction -> start_time of the fixed families */
};

static inline uint32_t reg_ndims(const struct lk_registry *r)
{
    return r->max_dims + 1;
}

static inline uint32_t reg_nprotos(void)
{
    return LK_MAX_PROTOS + 1;
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

static uint64_t series_key(uint32_t qslot, uint32_t dim, uint32_t proto, uint8_t code)
{
    return ((uint64_t)qslot << 32) | ((uint64_t)dim << 8) | ((uint64_t)proto << 3) | code;
}

static struct series *series_get(struct lk_registry *r, uint32_t qslot, uint32_t dim,
                                 uint32_t proto, uint8_t code)
{
    uint64_t key = series_key(qslot, dim, proto, code);
    uint32_t b = (uint32_t)mix64(key) & (r->sbuckets_n - 1);
    struct series *s;

    for (s = r->sbuckets[b]; s; s = s->h_next)
        if (s->qslot == qslot && s->dim == dim && s->proto == proto && s->code == code)
            return s;

    s = calloc(1, sizeof(*s));
    if (!s)
        return NULL; /* out of memory: drop the observation, never crash */
    s->qslot = qslot;
    s->dim = dim;
    s->proto = proto;
    s->code = code;
    s->created_ns = reg_now_ns();
    s->h_next = r->sbuckets[b];
    r->sbuckets[b] = s;
    s->q_next = r->entries[qslot].series;
    r->entries[qslot].series = s;
    r->n_series++;
    return s;
}

static void series_unlink_hash(struct lk_registry *r, struct series *victim)
{
    uint64_t key = series_key(victim->qslot, victim->dim, victim->proto, victim->code);
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

/* Intern an error code for the profile's error counter (Р23): a linear scan
 * capped at LK_MAX_ERR_CODES, then the "other" pseudo-code at that index. The
 * namespace is per profile — SQLSTATEs on one side, HTTP statuses on the other
 * (РH9: the HTTP set is bounded by the protocol itself, ~60 codes). */
static uint32_t intern_err_code(struct lk_registry *r, uint8_t prof, const char *code)
{
    uint32_t *n = &r->n_err_codes[prof];

    for (uint32_t i = 0; i < *n; i++)
        if (!strcmp(r->err_codes[prof][i].code, code))
            return i;
    if (*n >= LK_MAX_ERR_CODES)
        return LK_MAX_ERR_CODES;

    uint32_t id = (*n)++;
    snprintf(r->err_codes[prof][id].code, sizeof(r->err_codes[prof][id].code), "%s", code);
    return id;
}

/* Intern the protocol name (РМ6): a tiny fixed set ("pg"/"mysql"/"http"), NULL
 * folds to "pg" (the protocol default, РМ2). Overflow past LK_MAX_PROTOS lands
 * on the "other" pseudo-proto at that index — unreachable while the protocol
 * registry itself is capped at the same number. */
static uint32_t intern_proto(struct lk_registry *r, const char *proto, uint8_t prof)
{
    const char *name = (proto && proto[0]) ? proto : "pg";

    for (uint32_t i = 0; i < r->n_protos; i++)
        if (!strcmp(r->protos[i].name, name))
            return i;
    if (r->n_protos >= LK_MAX_PROTOS) {
        r->proto_prof[LK_MAX_PROTOS] = prof;
        return LK_MAX_PROTOS;
    }

    uint32_t id = r->n_protos++;
    snprintf(r->protos[id].name, sizeof(r->protos[id].name), "%s", name);
    r->proto_prof[id] = prof;
    return id;
}

/* The profile a proto id reports under — what the dump walks by. */
static const struct reg_profile *proto_profile(const struct lk_registry *r, uint32_t proto)
{
    return profile_of(r->proto_prof[proto <= LK_MAX_PROTOS ? proto : LK_MAX_PROTOS]);
}

/* proto id -> label; the spill index prints proto="other". */
static const char *proto_str(const struct lk_registry *r, uint32_t proto)
{
    return proto < r->n_protos ? r->protos[proto].name : "other";
}

/* --- query dictionary: admit / evict / resolve ---------------------------- */

static int32_t admit(struct lk_registry *r, uint64_t fp, const char *label, const char *op)
{
    int32_t s = r->free_slots[--r->n_free];
    struct qentry *e = &r->entries[s];

    e->fp = fp;
    e->used = true;
    e->series = NULL;
    utf8_trunc(label ? label : "", e->label, r->label_len);
    snprintf(e->op, sizeof(e->op), "%s", op ? op : "");
    fp_insert(r, fp, s);
    lru_push_front(r, s);
    return s;
}

/* A series' lazily-allocated secondary histograms, created on first use (only
 * when the profile has the family). NULL on OOM: the caller drops that one
 * observation, never crashes. */
static struct lk_hist *series_first_row(struct series *s)
{
    if (!s->first_row)
        s->first_row = calloc(1, sizeof(*s->first_row));
    return s->first_row;
}

static struct lk_hist *series_upload(struct series *s)
{
    if (!s->upload)
        s->upload = calloc(1, sizeof(*s->upload));
    return s->upload;
}

/* The size histogram, on its profile's grid (hist.h): the two grids differ, so
 * the family it belongs to has to be known at the moment it is created. A NULL
 * profile means "whatever it turns out to be" — the eviction fold, where the
 * grid arrives with the histogram being merged in. */
static struct lk_bhist *series_size(struct series *s, const struct reg_profile *pf)
{
    if (!s->size) {
        s->size = calloc(1, sizeof(*s->size));
        if (s->size && pf && pf->size_nbuckets)
            lk_bhist_init(s->size, pf->size_min_log2, pf->size_nbuckets);
    }
    return s->size;
}

/* Fold the LRU slot's series into query="other" / route="other" (Р23) and free
 * the slot. Every accumulator a series can hold is merged, or the `other` row
 * would shrink for whichever family was forgotten — the one invariant this
 * function exists to keep. */
static void evict_lru(struct lk_registry *r)
{
    int32_t t = r->lru_tail;
    struct qentry *e = &r->entries[t];
    struct series *s = e->series, *next;

    for (; s; s = next) {
        struct series *dst = series_get(r, r->k, s->dim, s->proto, s->code);

        next = s->q_next;
        if (dst) {
            lk_hist_merge(&dst->dur, &s->dur);
            dst->rows += s->rows;
            dst->bytes_in += s->bytes_in;
            dst->bytes_out += s->bytes_out;
            for (uint32_t i = 0; i < LK_N_SCLASSES; i++)
                dst->tally[i] += s->tally[i];
            if (s->first_row) {
                struct lk_hist *dfr = series_first_row(dst);

                if (dfr)
                    lk_hist_merge(dfr, s->first_row);
            }
            if (s->upload) {
                struct lk_hist *du = series_upload(dst);

                if (du)
                    lk_hist_merge(du, s->upload);
            }
            if (s->size) {
                struct lk_bhist *ds = series_size(dst, NULL);

                if (ds)
                    lk_bhist_merge(ds, s->size);
            }
        }
        series_unlink_hash(r, s);
        free(s->first_row);
        free(s->upload);
        free(s->size);
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
static uint32_t resolve_query(struct lk_registry *r, uint64_t fp, const char *label, const char *op)
{
    int32_t s = fp_find(r, fp);

    if (s >= 0) {
        lru_touch(r, s);
        return (uint32_t)s;
    }
    if (r->n_free > 0) /* room: admit on first sight */
        return (uint32_t)admit(r, fp, label, op);

    /* Dictionary full: doorkeeper. Admit only on the second appearance. */
    uint64_t key = fp ? fp : 1; /* 0 doubles as the empty sentinel */
    uint32_t d = (uint32_t)(key ^ (key >> 17)) & (LK_DOORKEEPER_SLOTS - 1);

    if (r->door[d] == key) {
        r->door[d] = 0;
        evict_lru(r);
        return (uint32_t)admit(r, fp, label, op);
    }
    r->door[d] = key;
    return r->k; /* query="other" / route="other" */
}

/* --- public API ----------------------------------------------------------- */

void lk_reg_observe(struct lk_registry *r, const struct lk_reg_obs *o)
{
    uint8_t prof = o->profile < LK_N_PROFILES ? o->profile : LK_PROF_QUERY;
    const struct reg_profile *pf = &profiles[prof];
    uint32_t ndims = reg_ndims(r);
    uint32_t nprotos = reg_nprotos();
    uint8_t kind = o->kind < LK_N_QKINDS ? o->kind : LK_QK_SIMPLE;
    uint8_t qc = o->qcode < LK_N_QCODES ? o->qcode : LK_QCODE_OK;
    uint32_t dim, proto, qslot;
    struct series *s;

    r->used[prof] = true;
    /* Counted and nothing else (РS2): MinIO's own `/minio/…` surface is not an
     * S3 API, and on a distributed pool it is most of the traffic on the port —
     * so it may not touch a family that says "requests", or a latency, or a
     * byte count. It is not simply dropped either: a health-check flood and an
     * inter-node storm are things an operator needs to see, and this counter is
     * where they are visible. Ahead of the interning below, because such a
     * request has no bucket and no access key and must not spend a dimension
     * slot saying so. The observation ends here. */
    if (o->internal && (pf->families & RF_INTERNAL)) {
        r->internal_obs[prof]++;
        return;
    }
    dim = intern_dim(r, o->db ? o->db : "", o->user ? o->user : "");
    proto = intern_proto(r, o->proto, prof);
    /* latkit_queries_total{db,user,proto,kind,code} — every observation of a
     * profile that has the family. The http profile does not: its exchange
     * counter is keyed by route and lives on the series (RF_TOTAL below), and
     * an HTTP request in latkit_queries_total{kind="request"} was only ever a
     * placeholder for this milestone (РH9). */
    if (pf->families & RF_QTOTAL)
        r->q_total[((dim * nprotos + proto) * LK_N_QKINDS + kind) * LK_N_QCODES + qc]++;
    if (o->truncated && (pf->families & RF_TRUNCATED))
        r->truncated_obs[prof]++;
    if (o->err_code && (pf->families & RF_ERRORS))
        r->err_total[(intern_err_code(r, prof, o->err_code) * ndims + dim) * nprotos + proto]++;
    /* The answer that is an error in syntax and cluster routine in fact (РR7).
     * Keyed by the protocol alone: `-MOVED 3999 10.0.0.2:6379` is a statement
     * about the cluster's slot map, not about the key it was asked for, and the
     * node address in it is exactly the kind of thing that never becomes a
     * label. */
    if (o->redirect && (pf->families & RF_REDIRECT))
        r->redirects[o->redirect < LK_N_REDIRECTS ? o->redirect : LK_REDIR_NONE][proto]++;
    /* How deep the batch this observation arrived in was (РR3). Sampled per
     * command rather than per syscall, which is the weighting that answers the
     * question it is asked for: "did the median *command* wait behind others of
     * its own", not "how often does a client batch at all". */
    if (o->has_depth && (pf->families & RF_DEPTH) && r->depth) {
        struct lk_bhist *h = &r->depth[proto];

        if (!h->nbuckets)
            lk_bhist_init(h, LK_DHIST_MIN_LOG2, LK_DHIST_NBUCKETS);
        lk_bhist_observe(h, o->depth);
    }

    /* Slot-keyed families. A profile whose total counter is keyed by the slot
     * needs one for *every* observation and not only the timed ones (МR5): a
     * Redis command answered `+QUEUED`, or one whose reply never came, is a
     * command that happened, and a counter that skipped it would disagree with
     * the server's own `INFO commandstats` — which is what the МR8 accuracy
     * bench compares it against. Everything that is not a duration is recorded
     * before the early return below for the same reason: the bytes were on the
     * wire and the reply had a size whatever the clock says.
     *
     * Forced "other" (NO_TEXT / CANCEL, Р28; a request whose target never
     * arrived, РH7) skips the dictionary so ad-hoc text never churns the top-K;
     * otherwise resolve. */
    if (!o->has_duration && !(pf->families & RF_TOTAL))
        return; /* aborted / canceled: counters only (Р25) */
    qslot = (o->force_other || !o->label) ? r->k : resolve_query(r, o->fp, o->label, o->op);
    s = series_get(r, qslot, dim, proto, (uint8_t)o->dcode);
    if (!s)
        return;
    if (pf->families & RF_TOTAL) {
        uint32_t ax = pf->total_qcode ? qc : o->sclass;

        s->tally[ax < total_axis_n(pf) ? ax : 0]++;
    }
    if (pf->families & RF_BYTES) {
        s->bytes_in += o->bytes_in;
        s->bytes_out += o->bytes_out;
    }
    if (o->has_size && (pf->families & RF_SIZE)) {
        struct lk_bhist *sz = series_size(s, pf);

        if (sz)
            lk_bhist_observe(sz, o->size_bytes);
    }
    /* The wait that belongs to the client (РR10). Same storage as the second
     * histogram above, and deliberately the same *place* in the code as the
     * duration below: the two are alternatives, and a unit that lands here is
     * one the general distribution must never see. */
    if (o->has_block && (pf->families & RF_BLOCKING)) {
        struct lk_hist *bl = series_first_row(s);

        if (bl)
            lk_hist_observe(bl, o->block_seconds);
    }
    if (!o->has_duration)
        return;

    r->total_obs[prof]++;
    if (qslot == r->k)
        r->other_obs[prof]++;
    lk_hist_observe(&s->dur, o->dur_seconds);
    s->rows += o->rows;
    /* One storage field, two families: the query profile's first-row histogram
     * is opt-in (Р24 — most deployments never look at it), the http profile's
     * TTFB is not (РH9 — "how long until the client saw anything" is half of
     * what an HTTP dashboard is for). */
    if (o->has_first_row &&
        ((pf->families & RF_TTFB) || (r->first_row && (pf->families & RF_FIRST_ROW)))) {
        struct lk_hist *fr = series_first_row(s);

        if (fr)
            lk_hist_observe(fr, o->first_row_seconds);
    }
    if (o->has_upload && (pf->families & RF_UPLOAD)) {
        struct lk_hist *up = series_upload(s);

        if (up)
            lk_hist_observe(up, o->upload_seconds);
    }
}

void lk_reg_observe_txn(struct lk_registry *r, const char *db, const char *user, const char *proto,
                        uint8_t profile, bool aborted, double dur_seconds)
{
    uint32_t dim = intern_dim(r, db ? db : "", user ? user : "");
    uint32_t pr = intern_proto(r, proto, profile < LK_N_PROFILES ? profile : LK_PROF_QUERY);
    uint32_t nprotos = reg_nprotos();

    lk_hist_observe(&r->txn[(dim * nprotos + pr) * 2 + (aborted ? 1u : 0u)], dur_seconds);
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
    r->created_ns = reg_now_ns();

    r->fp_hcap = next_pow2((r->k + 1) * 2);
    r->sbuckets_n = next_pow2(r->k * 4);
    if (r->sbuckets_n < 1024)
        r->sbuckets_n = 1024;

    uint32_t ndims = reg_ndims(r);
    uint32_t nprotos = reg_nprotos();

    r->entries = calloc(r->k + 1, sizeof(*r->entries));
    r->fp_hash = malloc(r->fp_hcap * sizeof(*r->fp_hash));
    r->free_slots = malloc(r->k * sizeof(*r->free_slots));
    r->door = calloc(LK_DOORKEEPER_SLOTS, sizeof(*r->door));
    r->dims = calloc(ndims, sizeof(*r->dims));
    r->sbuckets = calloc(r->sbuckets_n, sizeof(*r->sbuckets));
    r->q_total = calloc((size_t)ndims * nprotos * LK_N_QKINDS * LK_N_QCODES, sizeof(*r->q_total));
    r->err_total = calloc((size_t)(LK_MAX_ERR_CODES + 1) * ndims * nprotos, sizeof(*r->err_total));
    r->txn = calloc((size_t)ndims * nprotos * 2, sizeof(*r->txn));
    r->depth = calloc(nprotos, sizeof(*r->depth));
    if (!r->entries || !r->fp_hash || !r->free_slots || !r->door || !r->dims || !r->sbuckets ||
        !r->q_total || !r->err_total || !r->txn || !r->depth) {
        lk_reg_free(r);
        return NULL;
    }
    for (uint32_t i = 0; i < r->fp_hcap; i++)
        r->fp_hash[i] = -1;
    for (uint32_t i = 0; i < r->k; i++) /* LIFO stack of every real slot */
        r->free_slots[i] = (int32_t)(r->k - 1 - i);
    r->n_free = r->k;
    r->used[LK_PROF_QUERY] = true; /* its blocks have always been in the dump */
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
                free(s->upload);
                free(s->size);
                free(s);
            }
        }
    free(r->depth);
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
/* Summed over the profiles: the invariant these serve ("nothing is ever lost
 * across an eviction") is a property of the dictionary, which is shared. */
uint64_t lk_reg_total_obs(const struct lk_registry *r)
{
    uint64_t n = 0;

    for (uint32_t i = 0; i < LK_N_PROFILES; i++)
        n += r->total_obs[i];
    return n;
}
uint64_t lk_reg_other_obs(const struct lk_registry *r)
{
    uint64_t n = 0;

    for (uint32_t i = 0; i < LK_N_PROFILES; i++)
        n += r->other_obs[i];
    return n;
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

#define LK_TXN_METRIC "latkit_txn_duration_seconds"

/* Escaped db/user pair: worst case each 64-byte label doubles under escaping. */
#define ESC64 (2 * 64)

/* One printed identity: the slot label, the optional operation, the two
 * dimension labels, the protocol and the key names between them, all escaped. */
#define LK_LABELSET_MAX (2 * LK_QUERY_LABEL_MAX + 2 * LK_REG_OP_MAX + 2 * ESC64 + 128)

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
    static const char *const s[LK_N_QKINDS] = {"simple",   "extended", "function", "copy_in",
                                               "copy_out", "cancel",   "request",  "command"};
    return k < LK_N_QKINDS ? s[k] : "?";
}

/* The `code` label of latkit_queries_total (Р23) and of the redis profile's
 * command counter (МR5): the four states an observation can end in. */
static const char *qcode_str(uint32_t c)
{
    static const char *const s[LK_N_QCODES] = {"ok", "error", "aborted", "canceled"};
    return c < LK_N_QCODES ? s[c] : "?";
}

/* The `status` label of latkit_http_requests_total (РH9): the class, five
 * values, plus the one a malformed status line can produce. */
static const char *sclass_str(uint32_t c)
{
    static const char *const s[LK_N_SCLASSES] = {"other", "1xx", "2xx", "3xx", "4xx", "5xx"};
    return c < LK_N_SCLASSES ? s[c] : "other";
}

/* The `kind` label of latkit_redis_redirects_total (РR7). */
static const char *redirect_str(uint32_t k)
{
    static const char *const s[LK_N_REDIRECTS] = {"none", "moved", "ask"};
    return k < LK_N_REDIRECTS ? s[k] : "none";
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

/* Order interned error codes lexically; the "other" pseudo-code prints last. */
static void order_err_codes(const struct lk_registry *r, uint8_t prof, uint32_t *ord)
{
    uint32_t n = r->n_err_codes[prof];

    for (uint32_t i = 0; i < n; i++)
        ord[i] = i;
    for (uint32_t i = 1; i < n; i++) {
        uint32_t v = ord[i], j = i;

        for (; j > 0 && strcmp(r->err_codes[prof][ord[j - 1]].code, r->err_codes[prof][v].code) > 0;
             j--)
            ord[j] = ord[j - 1];
        ord[j] = v;
    }
}

/* --- slot-keyed families (duration / rows / ttfb / bytes / size) ---------- */

struct dump_row {
    const struct series *s;
    const struct reg_profile *pf;
    uint8_t prof;
    const char *q, *op, *db, *user, *proto;
    int code;
};

static int row_cmp(const void *a, const void *b)
{
    const struct dump_row *x = a, *y = b;
    int c;

    /* Profile first: each profile's families print as one contiguous block, and
     * the query one comes first — which is what keeps a PG/MySQL exposition
     * byte-identical to the pre-М5 output (РH15). */
    if (x->prof != y->prof)
        return (int)x->prof - (int)y->prof;
    if ((c = strcmp(x->q, y->q)))
        return c;
    if ((c = strcmp(x->op, y->op)))
        return c;
    if ((c = strcmp(x->db, y->db)))
        return c;
    if ((c = strcmp(x->user, y->user)))
        return c;
    if ((c = strcmp(x->proto, y->proto)))
        return c;
    return x->code - y->code;
}

/* True when rows i and j share the (slot,op,db,user,proto) identity — they
 * differ only in `code`, which is the group boundary for every family that is
 * not the duration histogram. */
static bool same_qseries(const struct dump_row *a, const struct dump_row *b)
{
    return a->prof == b->prof && !strcmp(a->q, b->q) && !strcmp(a->op, b->op) &&
           !strcmp(a->db, b->db) && !strcmp(a->user, b->user) && !strcmp(a->proto, b->proto);
}

/* The escaped identity labelset of a row, without braces: the label keys are
 * the profile's (РH10), so one function prints
 * `query="…",db="…",user="…",proto="…"` and `route="…",method="…",host="…",
 * user="…",proto="…"` alike. */
static void row_labelset(const struct dump_row *rw, char *out, size_t cap)
{
    const struct reg_profile *pf = rw->pf;
    char qe[2 * LK_QUERY_LABEL_MAX], ope[2 * LK_REG_OP_MAX], dbe[ESC64], ue[ESC64];

    esc(rw->q, qe);
    esc(rw->op, ope);
    esc(rw->db, dbe);
    esc(rw->user, ue);
    if (pf->k_op)
        snprintf(out, cap, "%s=\"%s\",%s=\"%s\",%s=\"%s\",%s=\"%s\",proto=\"%s\"", pf->k_slot, qe,
                 pf->k_op, ope, pf->k_db, dbe, pf->k_user, ue, rw->proto);
    else
        snprintf(out, cap, "%s=\"%s\",%s=\"%s\",%s=\"%s\",proto=\"%s\"", pf->k_slot, qe, pf->k_db,
                 dbe, pf->k_user, ue, rw->proto);
}

/* Every family whose series identity is a dictionary slot. `rows` is the
 * profile's slice of the sorted row array. */
static void write_qkeyed(const struct lk_registry *r, FILE *f, const struct reg_profile *pf,
                         const struct dump_row *rows, uint32_t n)
{
    char base[LK_LABELSET_MAX], labelset[LK_LABELSET_MAX + 32];

    /* The slot-keyed total counter: one series per (identity, outcome), summed
     * over the duration code within the group. Keyed by route / command, unlike
     * the query profile's latkit_queries_total, because "requests per second by
     * route" — and "commands per second by command" — is the first panel
     * anybody opens (РH9/РR11). The outcome axis is the profile's own: a status
     * class where the protocol has statuses, the observation's own code where it
     * has none. */
    if (pf->families & RF_TOTAL) {
        uint32_t nax = total_axis_n(pf);

        fprintf(f, "# HELP %s %s\n", pf->f_total.name, pf->f_total.help);
        fprintf(f, "# TYPE %s counter\n", pf->f_total.name);
        for (uint32_t i = 0; i < n;) {
            uint64_t sum[LK_N_SCLASSES] = {0};
            uint32_t j = i;

            for (; j < n && same_qseries(&rows[i], &rows[j]); j++)
                for (uint32_t c = 0; c < nax; c++)
                    sum[c] += rows[j].s->tally[c];
            row_labelset(&rows[i], base, sizeof(base));
            for (uint32_t c = 0; c < nax; c++)
                if (sum[c])
                    fprintf(f, "%s{%s,%s=\"%s\"} %llu\n", pf->f_total.name, base, pf->k_total,
                            total_axis_str(pf, c), (unsigned long long)sum[c]);
            i = j;
        }
    }

    /* duration: one histogram per (identity, code). A series with no timed
     * observation prints nothing: for every profile but the redis one that
     * cannot happen (a series exists because something was timed into it), and
     * for that one it is the whole point — a command that was only ever answered
     * `+QUEUED`, or only ever blocked, is counted and has no latency (РR9/РR10),
     * and twenty empty buckets saying so would be twenty lies about a
     * distribution. */
    fprintf(f, "# HELP %s %s\n", pf->f_dur.name, pf->f_dur.help);
    fprintf(f, "# TYPE %s histogram\n", pf->f_dur.name);
    for (uint32_t i = 0; i < n; i++) {
        if (!rows[i].s->dur.count)
            continue;
        row_labelset(&rows[i], base, sizeof(base));
        snprintf(labelset, sizeof(labelset), "%s,code=\"%s\"", base,
                 rows[i].code == LK_CODE_ERROR ? "error" : "ok");
        lk_hist_write(&rows[i].s->dur, f, pf->f_dur.name, labelset);
    }

    /* rows_total: sum over code within each group. */
    if (pf->families & RF_ROWS) {
        fprintf(f, "# HELP %s %s\n", pf->f_rows.name, pf->f_rows.help);
        fprintf(f, "# TYPE %s counter\n", pf->f_rows.name);
        for (uint32_t i = 0; i < n;) {
            uint32_t j = i;
            uint64_t sum = 0;

            for (; j < n && same_qseries(&rows[i], &rows[j]); j++)
                sum += rows[j].s->rows;
            row_labelset(&rows[i], base, sizeof(base));
            fprintf(f, "%s{%s} %llu\n", pf->f_rows.name, base, (unsigned long long)sum);
            i = j;
        }
    }

    /* The second histogram — first row (opt-in), TTFB, or the blocking wait of
     * РR10 — merging the code series within each group. Three families, one
     * storage field: no protocol has two of them, because the question "what
     * else about this unit's time is worth a distribution" has exactly one
     * answer per protocol. */
    if ((pf->families & (RF_TTFB | RF_BLOCKING)) ||
        (r->first_row && (pf->families & RF_FIRST_ROW))) {
        fprintf(f, "# HELP %s %s\n", pf->f_second.name, pf->f_second.help);
        fprintf(f, "# TYPE %s histogram\n", pf->f_second.name);
        for (uint32_t i = 0; i < n;) {
            uint32_t j = i;
            struct lk_hist acc = {0};
            bool any = false;

            for (; j < n && same_qseries(&rows[i], &rows[j]); j++)
                if (rows[j].s->first_row) {
                    lk_hist_merge(&acc, rows[j].s->first_row);
                    any = true;
                }
            if (any) {
                row_labelset(&rows[i], base, sizeof(base));
                lk_hist_write(&acc, f, pf->f_second.name, base);
            }
            i = j;
        }
    }

    /* upload: the time the client spent sending the request body (РH5). */
    if (pf->families & RF_UPLOAD) {
        fprintf(f, "# HELP %s %s\n", pf->f_upload.name, pf->f_upload.help);
        fprintf(f, "# TYPE %s histogram\n", pf->f_upload.name);
        for (uint32_t i = 0; i < n;) {
            uint32_t j = i;
            struct lk_hist acc = {0};
            bool any = false;

            for (; j < n && same_qseries(&rows[i], &rows[j]); j++)
                if (rows[j].s->upload) {
                    lk_hist_merge(&acc, rows[j].s->upload);
                    any = true;
                }
            if (any) {
                row_labelset(&rows[i], base, sizeof(base));
                lk_hist_write(&acc, f, pf->f_upload.name, base);
            }
            i = j;
        }
    }
}

/* The two byte families, printed after the profile's error counter so the
 * latency material stays together at the top of the block. */
static void write_qkeyed_bytes(FILE *f, const struct reg_profile *pf, const struct dump_row *rows,
                               uint32_t n)
{
    char base[LK_LABELSET_MAX];

    if (pf->families & RF_BYTES) {
        fprintf(f, "# HELP %s %s\n", pf->f_bytes.name, pf->f_bytes.help);
        fprintf(f, "# TYPE %s counter\n", pf->f_bytes.name);
        for (uint32_t i = 0; i < n;) {
            uint32_t j = i;
            uint64_t in = 0, out = 0;

            for (; j < n && same_qseries(&rows[i], &rows[j]); j++) {
                in += rows[j].s->bytes_in;
                out += rows[j].s->bytes_out;
            }
            row_labelset(&rows[i], base, sizeof(base));
            fprintf(f, "%s{%s,direction=\"in\"} %llu\n", pf->f_bytes.name, base,
                    (unsigned long long)in);
            fprintf(f, "%s{%s,direction=\"out\"} %llu\n", pf->f_bytes.name, base,
                    (unsigned long long)out);
            i = j;
        }
    }

    if (pf->families & RF_SIZE) {
        fprintf(f, "# HELP %s %s\n", pf->f_size.name, pf->f_size.help);
        fprintf(f, "# TYPE %s histogram\n", pf->f_size.name);
        for (uint32_t i = 0; i < n;) {
            uint32_t j = i;
            /* The accumulator takes the family's grid from the series it
             * merges (hist.h); every series in this loop belongs to one
             * family, so they all agree. */
            struct lk_bhist acc = {0};
            bool any = false;

            for (; j < n && same_qseries(&rows[i], &rows[j]); j++)
                if (rows[j].s->size) {
                    lk_bhist_merge(&acc, rows[j].s->size);
                    any = true;
                }
            if (any) {
                row_labelset(&rows[i], base, sizeof(base));
                lk_bhist_write(&acc, f, pf->f_size.name, base);
            }
            i = j;
        }
    }
}

/* One profile's whole block: the dimension-keyed families, the slot-keyed ones
 * over its slice of the sorted rows, and its label-free counters. */
static void write_profile(const struct lk_registry *r, FILE *f, uint8_t prof,
                          const struct dump_row *rows, uint32_t n, const uint32_t *ord,
                          uint32_t ndims)
{
    const struct reg_profile *pf = &profiles[prof];
    uint32_t nprotos = reg_nprotos();

    /* --- latkit_queries_total{db,user,proto,kind,code} ------------------- */
    if (pf->families & RF_QTOTAL) {
        fprintf(f, "# HELP %s %s\n", pf->f_total.name, pf->f_total.help);
        fprintf(f, "# TYPE %s counter\n", pf->f_total.name);
        for (uint32_t oi = 0; oi < ndims; oi++) {
            uint32_t d = ord[oi];
            char dbe[ESC64], ue[ESC64];

            esc(r->dims[d].db, dbe);
            esc(r->dims[d].user, ue);
            for (uint32_t pr = 0; pr < nprotos; pr++) {
                if (proto_profile(r, pr) != pf)
                    continue;
                for (uint8_t k = 0; k < LK_N_QKINDS; k++)
                    for (uint8_t c = 0; c < LK_N_QCODES; c++) {
                        uint64_t v =
                            r->q_total[((d * nprotos + pr) * LK_N_QKINDS + k) * LK_N_QCODES + c];

                        if (v)
                            fprintf(f,
                                    "%s{%s=\"%s\",%s=\"%s\",proto=\"%s\",kind=\"%s\",code=\"%s\"} "
                                    "%llu\n",
                                    pf->f_total.name, pf->k_db, dbe, pf->k_user, ue,
                                    proto_str(r, pr), qkind_str(k), qcode_str(c),
                                    (unsigned long long)v);
                    }
            }
        }
    }

    /* --- slot-keyed families -------------------------------------------- */
    write_qkeyed(r, f, pf, rows, n);

    /* --- the error counter, without the slot label (Р23) ----------------- */
    if (pf->families & RF_ERRORS) {
        uint32_t sord[LK_MAX_ERR_CODES];
        uint32_t ncodes = r->n_err_codes[prof];

        fprintf(f, "# HELP %s %s\n", pf->f_err.name, pf->f_err.help);
        fprintf(f, "# TYPE %s counter\n", pf->f_err.name);
        order_err_codes(r, prof, sord);
        /* real codes in order, then the "other" pseudo-code last */
        for (uint32_t si = 0; si <= ncodes; si++) {
            uint32_t sq = si < ncodes ? sord[si] : LK_MAX_ERR_CODES;
            const char *code = si < ncodes ? r->err_codes[prof][sq].code : "other";

            for (uint32_t oi = 0; oi < ndims; oi++) {
                uint32_t d = ord[oi];
                char dbe[ESC64], ue[ESC64], ce[2 * sizeof(r->err_codes[0][0].code)];

                esc(code, ce);
                esc(r->dims[d].db, dbe);
                esc(r->dims[d].user, ue);
                for (uint32_t pr = 0; pr < nprotos; pr++) {
                    uint64_t v = r->err_total[(sq * ndims + d) * nprotos + pr];

                    if (!v || proto_profile(r, pr) != pf)
                        continue;
                    fprintf(f, "%s{%s=\"%s\",%s=\"%s\",%s=\"%s\",proto=\"%s\"} %llu\n",
                            pf->f_err.name, pf->k_err, ce, pf->k_db, dbe, pf->k_user, ue,
                            proto_str(r, pr), (unsigned long long)v);
                }
            }
        }
    }

    /* --- the two families keyed by the protocol alone (РR7/РR3) ---------- */
    if (pf->families & RF_REDIRECT) {
        fprintf(f, "# HELP %s %s\n", pf->f_redirect.name, pf->f_redirect.help);
        fprintf(f, "# TYPE %s counter\n", pf->f_redirect.name);
        for (uint32_t k = LK_REDIR_NONE + 1; k < LK_N_REDIRECTS; k++)
            for (uint32_t pr = 0; pr < nprotos; pr++) {
                uint64_t v = r->redirects[k][pr];

                if (!v || proto_profile(r, pr) != pf)
                    continue;
                fprintf(f, "%s{kind=\"%s\",proto=\"%s\"} %llu\n", pf->f_redirect.name,
                        redirect_str(k), proto_str(r, pr), (unsigned long long)v);
            }
    }
    if ((pf->families & RF_DEPTH) && r->depth) {
        fprintf(f, "# HELP %s %s\n", pf->f_depth.name, pf->f_depth.help);
        fprintf(f, "# TYPE %s histogram\n", pf->f_depth.name);
        for (uint32_t pr = 0; pr < nprotos; pr++) {
            char labelset[32];

            if (!r->depth[pr].count || proto_profile(r, pr) != pf)
                continue;
            snprintf(labelset, sizeof(labelset), "proto=\"%s\"", proto_str(r, pr));
            lk_bhist_write(&r->depth[pr], f, pf->f_depth.name, labelset);
        }
    }

    /* --- label-free counters -------------------------------------------- */
    if (pf->families & RF_TRUNCATED) {
        fprintf(f, "# HELP latkit_queries_truncated_total Observations with truncated SQL text.\n");
        fprintf(f, "# TYPE latkit_queries_truncated_total counter\n");
        fprintf(f, "latkit_queries_truncated_total %llu\n",
                (unsigned long long)r->truncated_obs[prof]);
    }
    if (pf->families & RF_OTHER) {
        fprintf(f, "# HELP latkit_queries_other_total Observations folded into query=\"other\".\n");
        fprintf(f, "# TYPE latkit_queries_other_total counter\n");
        fprintf(f, "latkit_queries_other_total %llu\n", (unsigned long long)r->other_obs[prof]);
    }
    if (pf->families & RF_INTERNAL) {
        fprintf(f, "# HELP %s %s\n", pf->f_internal.name, pf->f_internal.help);
        fprintf(f, "# TYPE %s counter\n", pf->f_internal.name);
        fprintf(f, "%s %llu\n", pf->f_internal.name, (unsigned long long)r->internal_obs[prof]);
    }

    /* --- latkit_txn_duration_seconds{db,user,proto,status} --------------
     * The one family two profiles feed (РR9): a `MULTI`…`EXEC` is a transaction
     * in the sense PG's is, and giving Redis a second name for the same measure
     * would be a worse answer than sharing this one. Printed by whichever
     * profile owns the family — the query one — for *every* protocol that has
     * recorded an interval, because a metric name may carry exactly one
     * HELP/TYPE block in an exposition, and two blocks is a scrape error rather
     * than a duplicate line. The `if (!h->count)` below is what keeps a
     * PG-only dump byte-identical: a protocol with no transactions prints
     * nothing whatever its profile. */
    if (pf->families & RF_TXN) {
        fprintf(f, "# HELP " LK_TXN_METRIC " Transaction duration in seconds.\n");
        fprintf(f, "# TYPE " LK_TXN_METRIC " histogram\n");
        for (uint32_t oi = 0; oi < ndims; oi++) {
            uint32_t d = ord[oi];
            char dbe[ESC64], ue[ESC64];

            esc(r->dims[d].db, dbe);
            esc(r->dims[d].user, ue);
            for (uint32_t pr = 0; pr < nprotos; pr++) {
                for (uint32_t st = 0; st < 2; st++) {
                    const struct lk_hist *h = &r->txn[(d * nprotos + pr) * 2 + st];
                    char labelset[3 * ESC64 + 64];

                    if (!h->count)
                        continue;
                    snprintf(labelset, sizeof(labelset),
                             "db=\"%s\",user=\"%s\",proto=\"%s\",status=\"%s\"", dbe, ue,
                             proto_str(r, pr), st ? "aborted" : "ok");
                    lk_hist_write(h, f, LK_TXN_METRIC, labelset);
                }
            }
        }
    }

    /* --- byte families --------------------------------------------------- */
    write_qkeyed_bytes(f, pf, rows, n);
}

/* Collect every live series as a sortable row. The `other` slot has no single
 * identity of its own, so it prints the folded values under the pseudo-labels
 * both profiles use for it. */
static uint32_t collect_rows(const struct lk_registry *r, struct dump_row *rows)
{
    uint32_t n = 0;

    for (uint32_t b = 0; b < r->sbuckets_n; b++)
        for (const struct series *s = r->sbuckets[b]; s; s = s->h_next) {
            const struct dim *d = &r->dims[s->dim];
            const struct reg_profile *pf = proto_profile(r, s->proto);
            bool other = s->qslot == r->k;

            rows[n].s = s;
            rows[n].pf = pf;
            rows[n].prof = (uint8_t)(pf - profiles);
            rows[n].q = other ? "other" : r->entries[s->qslot].label;
            rows[n].op = other ? "other" : r->entries[s->qslot].op;
            rows[n].db = d->db;
            rows[n].user = d->user;
            rows[n].proto = proto_str(r, s->proto);
            rows[n].code = s->code;
            n++;
        }
    if (n)
        qsort(rows, n, sizeof(*rows), row_cmp);
    return n;
}

int lk_reg_dump(const struct lk_registry *r, FILE *f)
{
    uint32_t ndims = reg_ndims(r);
    struct dump_row *rows = r->n_series ? malloc(r->n_series * sizeof(*rows)) : NULL;
    uint32_t *ord = malloc(ndims * sizeof(*ord));
    uint32_t n, lo = 0;

    if ((r->n_series && !rows) || !ord) {
        free(rows);
        free(ord);
        return -1;
    }
    order_dims(r, ord, ndims);
    n = collect_rows(r, rows);

    /* One block per profile, in profile order — the rows are sorted the same
     * way, so each block gets a contiguous slice. */
    for (uint8_t prof = 0; prof < LK_N_PROFILES; prof++) {
        uint32_t hi = lo;

        while (hi < n && rows[hi].prof == prof)
            hi++;
        if (r->used[prof])
            write_profile(r, f, prof, rows + lo, hi - lo, ord, ndims);
        lo = hi;
    }

    free(rows);
    free(ord);
    return 0;
}

/* --- structured iteration (Р31) ------------------------------------------- */

/* The identity labels of a row as views, in the same order the text dump prints
 * them; returns how many were written (4 or 5). */
static uint32_t row_label_views(const struct dump_row *rw, struct lk_label *lbl)
{
    const struct reg_profile *pf = rw->pf;
    uint32_t n = 0;

    lbl[n++] = (struct lk_label){pf->k_slot, rw->q};
    if (pf->k_op)
        lbl[n++] = (struct lk_label){pf->k_op, rw->op};
    lbl[n++] = (struct lk_label){pf->k_db, rw->db};
    lbl[n++] = (struct lk_label){pf->k_user, rw->user};
    lbl[n++] = (struct lk_label){"proto", rw->proto};
    return n;
}

/* The slot-keyed families as views, in exactly the grouping write_qkeyed uses
 * for the text dump. */
static void iter_qkeyed(const struct lk_registry *r, const struct reg_profile *pf,
                        lk_metrics_iter_fn fn, void *ctx, const struct dump_row *rows, uint32_t n)
{
    struct lk_label lbl[6];
    uint32_t nl;

    if (pf->families & RF_TOTAL)
        for (uint32_t i = 0; i < n;) {
            uint64_t sum[LK_N_SCLASSES] = {0};
            uint32_t nax = total_axis_n(pf);
            uint32_t j = i;

            for (; j < n && same_qseries(&rows[i], &rows[j]); j++)
                for (uint32_t c = 0; c < nax; c++)
                    sum[c] += rows[j].s->tally[c];
            nl = row_label_views(&rows[i], lbl);
            for (uint32_t c = 0; c < nax; c++) {
                struct lk_metric_view v = {
                    .name = pf->f_total.name,
                    .help = pf->f_total.help,
                    .type = LK_MT_COUNTER,
                    .labels = lbl,
                    .nlabels = nl + 1,
                    .created_ns = rows[i].s->created_ns,
                    .val = (double)sum[c],
                };

                if (!sum[c])
                    continue;
                lbl[nl] = (struct lk_label){pf->k_total, total_axis_str(pf, c)};
                fn(ctx, &v);
            }
            i = j;
        }

    /* duration: one histogram view per (identity, code), skipping the untimed
     * exactly as the text dump does. */
    for (uint32_t i = 0; i < n; i++) {
        struct lk_metric_view v = {
            .name = pf->f_dur.name,
            .help = pf->f_dur.help,
            .type = LK_MT_HIST,
            .labels = lbl,
            .created_ns = rows[i].s->created_ns,
            .hist = &rows[i].s->dur,
        };

        if (!rows[i].s->dur.count)
            continue;
        nl = row_label_views(&rows[i], lbl);
        lbl[nl] = (struct lk_label){"code", rows[i].code == LK_CODE_ERROR ? "error" : "ok"};
        v.nlabels = nl + 1;
        fn(ctx, &v);
    }

    /* rows_total: sum over code within each group. */
    if (pf->families & RF_ROWS)
        for (uint32_t i = 0; i < n;) {
            uint32_t j = i;
            uint64_t sum = 0;
            struct lk_metric_view v = {
                .name = pf->f_rows.name,
                .help = pf->f_rows.help,
                .type = LK_MT_COUNTER,
                .labels = lbl,
                .created_ns = rows[i].s->created_ns,
            };

            for (; j < n && same_qseries(&rows[i], &rows[j]); j++)
                sum += rows[j].s->rows;
            v.nlabels = row_label_views(&rows[i], lbl);
            v.val = (double)sum;
            fn(ctx, &v);
            i = j;
        }

    /* first row / TTFB / blocking wait: merge the code series' histograms
     * within each group (one storage field, three families — see write_qkeyed). */
    if ((pf->families & (RF_TTFB | RF_BLOCKING)) || (r->first_row && (pf->families & RF_FIRST_ROW)))
        for (uint32_t i = 0; i < n;) {
            uint32_t j = i;
            struct lk_hist acc = {0};
            bool any = false;

            for (; j < n && same_qseries(&rows[i], &rows[j]); j++)
                if (rows[j].s->first_row) {
                    lk_hist_merge(&acc, rows[j].s->first_row);
                    any = true;
                }
            if (any) {
                struct lk_metric_view v = {
                    .name = pf->f_second.name,
                    .help = pf->f_second.help,
                    .type = LK_MT_HIST,
                    .labels = lbl,
                    .nlabels = row_label_views(&rows[i], lbl),
                    .created_ns = rows[i].s->created_ns,
                    .hist = &acc,
                };

                fn(ctx, &v);
            }
            i = j;
        }

    if (pf->families & RF_UPLOAD)
        for (uint32_t i = 0; i < n;) {
            uint32_t j = i;
            struct lk_hist acc = {0};
            bool any = false;

            for (; j < n && same_qseries(&rows[i], &rows[j]); j++)
                if (rows[j].s->upload) {
                    lk_hist_merge(&acc, rows[j].s->upload);
                    any = true;
                }
            if (any) {
                struct lk_metric_view v = {
                    .name = pf->f_upload.name,
                    .help = pf->f_upload.help,
                    .type = LK_MT_HIST,
                    .labels = lbl,
                    .nlabels = row_label_views(&rows[i], lbl),
                    .created_ns = rows[i].s->created_ns,
                    .hist = &acc,
                };

                fn(ctx, &v);
            }
            i = j;
        }
}

static void iter_qkeyed_bytes(const struct reg_profile *pf, lk_metrics_iter_fn fn, void *ctx,
                              const struct dump_row *rows, uint32_t n)
{
    struct lk_label lbl[6];

    if (pf->families & RF_BYTES)
        for (uint32_t i = 0; i < n;) {
            uint32_t j = i;
            uint64_t bytes[2] = {0, 0};
            uint32_t nl;

            for (; j < n && same_qseries(&rows[i], &rows[j]); j++) {
                bytes[0] += rows[j].s->bytes_in;
                bytes[1] += rows[j].s->bytes_out;
            }
            nl = row_label_views(&rows[i], lbl);
            for (uint32_t d = 0; d < 2; d++) {
                struct lk_metric_view v = {
                    .name = pf->f_bytes.name,
                    .help = pf->f_bytes.help,
                    .type = LK_MT_COUNTER,
                    .labels = lbl,
                    .nlabels = nl + 1,
                    .created_ns = rows[i].s->created_ns,
                    .val = (double)bytes[d],
                };

                lbl[nl] = (struct lk_label){"direction", d ? "out" : "in"};
                fn(ctx, &v);
            }
            i = j;
        }

    if (pf->families & RF_SIZE)
        for (uint32_t i = 0; i < n;) {
            uint32_t j = i;
            struct lk_bhist acc = {0};
            bool any = false;

            for (; j < n && same_qseries(&rows[i], &rows[j]); j++)
                if (rows[j].s->size) {
                    lk_bhist_merge(&acc, rows[j].s->size);
                    any = true;
                }
            if (any) {
                struct lk_metric_view v = {
                    .name = pf->f_size.name,
                    .help = pf->f_size.help,
                    .type = LK_MT_HIST_BYTES,
                    .labels = lbl,
                    .nlabels = row_label_views(&rows[i], lbl),
                    .created_ns = rows[i].s->created_ns,
                    .bhist = &acc,
                };

                fn(ctx, &v);
            }
            i = j;
        }
}

/* One profile's families as views, in the dump's order. */
static void iter_profile(const struct lk_registry *r, uint8_t prof, lk_metrics_iter_fn fn,
                         void *ctx, const struct dump_row *rows, uint32_t n, const uint32_t *ord,
                         uint32_t ndims)
{
    const struct reg_profile *pf = &profiles[prof];
    uint32_t nprotos = reg_nprotos();

    if (pf->families & RF_QTOTAL)
        for (uint32_t oi = 0; oi < ndims; oi++) {
            uint32_t d = ord[oi];

            for (uint32_t pr = 0; pr < nprotos; pr++) {
                if (proto_profile(r, pr) != pf)
                    continue;
                for (uint8_t k = 0; k < LK_N_QKINDS; k++)
                    for (uint8_t c = 0; c < LK_N_QCODES; c++) {
                        uint64_t val =
                            r->q_total[((d * nprotos + pr) * LK_N_QKINDS + k) * LK_N_QCODES + c];
                        struct lk_label lbl[5] = {{pf->k_db, r->dims[d].db},
                                                  {pf->k_user, r->dims[d].user},
                                                  {"proto", proto_str(r, pr)},
                                                  {"kind", qkind_str(k)},
                                                  {"code", qcode_str(c)}};
                        struct lk_metric_view v = {
                            .name = pf->f_total.name,
                            .help = pf->f_total.help,
                            .type = LK_MT_COUNTER,
                            .labels = lbl,
                            .nlabels = 5,
                            .created_ns = r->created_ns,
                        };

                        if (!val)
                            continue;
                        v.val = (double)val;
                        fn(ctx, &v);
                    }
            }
        }

    iter_qkeyed(r, pf, fn, ctx, rows, n);

    if (pf->families & RF_ERRORS) {
        uint32_t sord[LK_MAX_ERR_CODES];
        uint32_t ncodes = r->n_err_codes[prof];

        order_err_codes(r, prof, sord);
        for (uint32_t si = 0; si <= ncodes; si++) {
            uint32_t sq = si < ncodes ? sord[si] : LK_MAX_ERR_CODES;
            const char *code = si < ncodes ? r->err_codes[prof][sq].code : "other";

            for (uint32_t oi = 0; oi < ndims; oi++) {
                uint32_t d = ord[oi];

                for (uint32_t pr = 0; pr < nprotos; pr++) {
                    uint64_t val = r->err_total[(sq * ndims + d) * nprotos + pr];
                    struct lk_label lbl[4] = {{pf->k_err, code},
                                              {pf->k_db, r->dims[d].db},
                                              {pf->k_user, r->dims[d].user},
                                              {"proto", proto_str(r, pr)}};
                    struct lk_metric_view v = {
                        .name = pf->f_err.name,
                        .help = pf->f_err.help,
                        .type = LK_MT_COUNTER,
                        .labels = lbl,
                        .nlabels = 4,
                        .created_ns = r->created_ns,
                    };

                    if (!val || proto_profile(r, pr) != pf)
                        continue;
                    v.val = (double)val;
                    fn(ctx, &v);
                }
            }
        }
    }

    /* The two proto-keyed families (РR7/РR3), in the dump's order. */
    if (pf->families & RF_REDIRECT)
        for (uint32_t k = LK_REDIR_NONE + 1; k < LK_N_REDIRECTS; k++)
            for (uint32_t pr = 0; pr < nprotos; pr++) {
                struct lk_label lbl[2] = {{"kind", redirect_str(k)}, {"proto", proto_str(r, pr)}};
                struct lk_metric_view v = {
                    .name = pf->f_redirect.name,
                    .help = pf->f_redirect.help,
                    .type = LK_MT_COUNTER,
                    .labels = lbl,
                    .nlabels = 2,
                    .created_ns = r->created_ns,
                    .val = (double)r->redirects[k][pr],
                };

                if (!r->redirects[k][pr] || proto_profile(r, pr) != pf)
                    continue;
                fn(ctx, &v);
            }
    if ((pf->families & RF_DEPTH) && r->depth)
        for (uint32_t pr = 0; pr < nprotos; pr++) {
            struct lk_label lbl[1] = {{"proto", proto_str(r, pr)}};
            struct lk_metric_view v = {
                .name = pf->f_depth.name,
                .help = pf->f_depth.help,
                .type = LK_MT_HIST_BYTES,
                .labels = lbl,
                .nlabels = 1,
                .created_ns = r->created_ns,
                .bhist = &r->depth[pr],
            };

            if (!r->depth[pr].count || proto_profile(r, pr) != pf)
                continue;
            fn(ctx, &v);
        }

    /* Label-free counters. */
    if (pf->families & RF_TRUNCATED) {
        struct lk_metric_view v = {
            .name = "latkit_queries_truncated_total",
            .help = "Observations with truncated SQL text.",
            .type = LK_MT_COUNTER,
            .created_ns = r->created_ns,
            .val = (double)r->truncated_obs[prof],
        };

        fn(ctx, &v);
    }
    if (pf->families & RF_OTHER) {
        struct lk_metric_view v = {
            .name = "latkit_queries_other_total",
            .help = "Observations folded into query=\"other\".",
            .type = LK_MT_COUNTER,
            .created_ns = r->created_ns,
            .val = (double)r->other_obs[prof],
        };

        fn(ctx, &v);
    }
    if (pf->families & RF_INTERNAL) {
        struct lk_metric_view v = {
            .name = pf->f_internal.name,
            .help = pf->f_internal.help,
            .type = LK_MT_COUNTER,
            .created_ns = r->created_ns,
            .val = (double)r->internal_obs[prof],
        };

        fn(ctx, &v);
    }

    /* latkit_txn_duration_seconds{db,user,proto,status} — one family, every
     * protocol that fed it (РR9), exactly as the text dump prints it. */
    if (pf->families & RF_TXN)
        for (uint32_t oi = 0; oi < ndims; oi++) {
            uint32_t d = ord[oi];

            for (uint32_t pr = 0; pr < nprotos; pr++) {
                for (uint32_t st = 0; st < 2; st++) {
                    const struct lk_hist *h = &r->txn[(d * nprotos + pr) * 2 + st];
                    struct lk_label lbl[4] = {{"db", r->dims[d].db},
                                              {"user", r->dims[d].user},
                                              {"proto", proto_str(r, pr)},
                                              {"status", st ? "aborted" : "ok"}};
                    struct lk_metric_view v = {
                        .name = LK_TXN_METRIC,
                        .help = "Transaction duration in seconds.",
                        .type = LK_MT_HIST,
                        .labels = lbl,
                        .nlabels = 4,
                        .created_ns = r->created_ns,
                        .hist = h,
                    };

                    if (!h->count)
                        continue;
                    fn(ctx, &v);
                }
            }
        }

    iter_qkeyed_bytes(pf, fn, ctx, rows, n);
}

void lk_reg_iter(const struct lk_registry *r, lk_metrics_iter_fn fn, void *ctx)
{
    uint32_t ndims = reg_ndims(r);
    struct dump_row *rows = r->n_series ? malloc(r->n_series * sizeof(*rows)) : NULL;
    uint32_t *ord = malloc(ndims * sizeof(*ord));
    uint32_t n, lo = 0;

    if (!ord || (r->n_series && !rows)) {
        free(rows);
        free(ord);
        return; /* best-effort: this export cycle skips the registry families */
    }
    order_dims(r, ord, ndims);
    n = collect_rows(r, rows);

    for (uint8_t prof = 0; prof < LK_N_PROFILES; prof++) {
        uint32_t hi = lo;

        while (hi < n && rows[hi].prof == prof)
            hi++;
        if (r->used[prof])
            iter_profile(r, prof, fn, ctx, rows + lo, hi - lo, ord, ndims);
        lo = hi;
    }

    free(rows);
    free(ord);
}
