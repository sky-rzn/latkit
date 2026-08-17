// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the series registry (task 4.2, Р23). Drives lk_reg_observe and
 * checks the three cardinality defences and their invariants:
 *
 *   - overflow past K routes a brand-new fingerprint to query="other";
 *   - a fingerprint that returns after eviction restarts its histogram from
 *     zero (an ordinary counter reset), while `other` keeps the old mass;
 *   - the doorkeeper drops one-shot fingerprints: a flood of single-appearance
 *     queries never evicts the working set;
 *   - nothing is ever lost: sum of every series' count == total observations,
 *     across arbitrary eviction (the monotonicity invariant);
 *   - the (db,user) dimension limit spills to (other,other);
 *   - the dump is valid text format with stable, escaped labels.
 *
 * Since М5 it also covers the observation profiles (РH10, РS7, РR11): the http,
 * s3 and redis families and their label keys, the fact that a PG-only registry
 * prints none of them, that the profiles share the dictionary and nothing else —
 * including the three size grids, which must not borrow each other's boundaries
 * — and that the structured (OTLP) walk emits the same families the text dump
 * does. The redis row adds the one case the engine had not seen before: an
 * observation that is counted and deliberately not timed (РR9/РR10). */
#include <stdio.h>
#include <string.h>

#include "registry.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static struct lk_registry *reg(uint32_t k, uint32_t dims)
{
    struct lk_metrics_cfg c;

    lk_metrics_cfg_defaults(&c);
    c.top_queries = k;
    c.max_session_dims = dims;
    return lk_reg_new(&c);
}

static void obs(struct lk_registry *r, uint64_t fp, const char *label, const char *db,
                const char *user, enum lk_code code)
{
    struct lk_reg_obs o = {
        .fp = fp,
        .label = label,
        .db = db,
        .user = user,
        .kind = LK_QK_SIMPLE,
        .qcode = code == LK_CODE_ERROR ? LK_QCODE_ERROR : LK_QCODE_OK,
        .has_duration = true,
        .dcode = code,
        .dur_seconds = 0.2,
    };

    lk_reg_observe(r, &o);
}

/* Capture a dump into buf; returns bytes read. */
static size_t dump(struct lk_registry *r, char *buf, size_t cap)
{
    FILE *f = tmpfile();
    size_t n;

    if (!f)
        return 0;
    lk_reg_dump(r, f);
    rewind(f);
    n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    return n;
}

static int contains(const char *hay, const char *needle)
{
    return strstr(hay, needle) != NULL;
}

/* A new fingerprint at a full dictionary lands in query="other". */
static int test_overflow_to_other(void)
{
    struct lk_registry *r = reg(4, 8);

    CHECK(r);
    for (uint64_t i = 1; i <= 4; i++)
        obs(r, i, "q", "db", "u", LK_CODE_OK);
    CHECK(lk_reg_n_queries(r) == 4);

    obs(r, 5, "q", "db", "u", LK_CODE_OK); /* dict full, first sight -> other */
    CHECK(!lk_reg_has_fp(r, 5));
    CHECK(lk_reg_n_queries(r) == 4);
    CHECK(lk_reg_other_obs(r) == 1);
    CHECK(lk_reg_total_obs(r) == 5);
    CHECK(lk_reg_series_count_sum(r) == 5);
    lk_reg_free(r);
    return 0;
}

/* An evicted fingerprint that comes back restarts from zero; `other` keeps the
 * mass folded out of it. */
static int test_evict_reset(void)
{
    struct lk_registry *r = reg(2, 8);

    CHECK(r);
    obs(r, 10, "A", "db", "u", LK_CODE_OK); /* admit A, count it 3x */
    obs(r, 10, "A", "db", "u", LK_CODE_OK);
    obs(r, 10, "A", "db", "u", LK_CODE_OK);
    obs(r, 20, "B", "db", "u", LK_CODE_OK); /* admit B; dict {A(LRU),B} full */
    CHECK(lk_reg_fp_count(r, 10) == 3);

    obs(r, 30, "C", "db", "u", LK_CODE_OK); /* C first sight -> other + doorkeeper */
    obs(r, 30, "C", "db", "u", LK_CODE_OK); /* C admitted, evicts A (folds 3 to other) */
    CHECK(!lk_reg_has_fp(r, 10));
    CHECK(lk_reg_has_fp(r, 30));

    obs(r, 10, "A", "db", "u", LK_CODE_OK); /* A back: first sight -> other + doorkeeper */
    obs(r, 10, "A", "db", "u", LK_CODE_OK); /* A re-admitted, evicts B */
    CHECK(lk_reg_has_fp(r, 10));
    CHECK(lk_reg_fp_count(r, 10) == 1); /* fresh: only the re-admitting observation */
    CHECK(!lk_reg_has_fp(r, 20));

    /* 8 observations total, none lost across the two evictions */
    CHECK(lk_reg_total_obs(r) == 8);
    CHECK(lk_reg_series_count_sum(r) == 8);
    lk_reg_free(r);
    return 0;
}

/* A flood of one-shot fingerprints cannot wash out the working set. */
static int test_doorkeeper(void)
{
    struct lk_registry *r = reg(2, 8);

    CHECK(r);
    obs(r, 10, "A", "db", "u", LK_CODE_OK);
    obs(r, 20, "B", "db", "u", LK_CODE_OK); /* working set {A,B}, full */

    for (uint64_t i = 0; i < 1000; i++)
        obs(r, 1000 + i, "adhoc", "db", "u", LK_CODE_OK); /* each seen once */

    CHECK(lk_reg_n_queries(r) == 2);
    CHECK(lk_reg_has_fp(r, 10));
    CHECK(lk_reg_has_fp(r, 20));
    CHECK(lk_reg_other_obs(r) == 1000);
    CHECK(lk_reg_total_obs(r) == 1002);
    CHECK(lk_reg_series_count_sum(r) == 1002); /* monotone: nothing dropped */
    lk_reg_free(r);
    return 0;
}

/* Unique fingerprints stress: rows stay bounded by K, memory does not grow. */
static int test_cardinality_ceiling(void)
{
    struct lk_registry *r = reg(64, 8);
    const uint64_t n = 100000;

    CHECK(r);
    for (uint64_t i = 1; i <= n; i++)
        obs(r, i, "q", "db", "u", LK_CODE_OK);

    CHECK(lk_reg_n_queries(r) == 64);    /* first 64 admitted, rest -> other */
    CHECK(lk_reg_n_series(r) == 64 + 1); /* one series each + the other row */
    CHECK(lk_reg_total_obs(r) == n);
    CHECK(lk_reg_series_count_sum(r) == n);
    lk_reg_free(r);
    return 0;
}

/* The (db,user) product is capped: extra pairs spill to (other,other). */
static int test_dim_limit(void)
{
    struct lk_registry *r = reg(8, 2);
    char buf[16384];

    CHECK(r);
    obs(r, 1, "q", "db1", "u1", LK_CODE_OK);
    obs(r, 1, "q", "db2", "u2", LK_CODE_OK);
    obs(r, 1, "q", "db3", "u3", LK_CODE_OK); /* third pair over the limit */
    CHECK(lk_reg_n_dims(r) == 2);

    dump(r, buf, sizeof(buf));
    CHECK(contains(buf, "db=\"db1\",user=\"u1\""));
    CHECK(contains(buf, "db=\"other\",user=\"other\""));
    CHECK(!contains(buf, "db=\"db3\""));
    lk_reg_free(r);
    return 0;
}

/* Dump shape: HELP/TYPE, per-series bucket/sum/count, escaped labels. */
static int test_dump_format(void)
{
    struct lk_registry *r = reg(8, 8);
    char buf[16384];

    CHECK(r);
    obs(r, 1, "select ?", "app", "alice", LK_CODE_OK);
    obs(r, 1, "select ?", "app", "alice", LK_CODE_OK);
    obs(r, 2, "upd\"ate", "app", "alice", LK_CODE_ERROR); /* label needs escaping */

    dump(r, buf, sizeof(buf));
    CHECK(contains(buf, "# HELP latkit_query_duration_seconds "));
    CHECK(contains(buf, "# TYPE latkit_query_duration_seconds histogram\n"));
    CHECK(contains(buf, "latkit_query_duration_seconds_count{query=\"select ?\",db=\"app\","
                        "user=\"alice\",proto=\"pg\",code=\"ok\"} 2\n"));
    CHECK(contains(buf, "code=\"error\""));
    CHECK(contains(buf, "query=\"upd\\\"ate\"")); /* the " is backslash-escaped */
    CHECK(contains(buf, "le=\"+Inf\""));
    lk_reg_free(r);
    return 0;
}

/* The proto label (РМ6) is an orthogonal axis: the same (db,user,query) under
 * two protocols yields two independent series, never a merged one. */
static int test_proto_split(void)
{
    struct lk_registry *r = reg(8, 8);
    char buf[16384];
    struct lk_reg_obs pg = {
        .fp = 1,
        .label = "select ?",
        .db = "app",
        .user = "alice",
        .proto = "pg",
        .kind = LK_QK_SIMPLE,
        .qcode = LK_QCODE_OK,
        .has_duration = true,
        .dcode = LK_CODE_OK,
        .dur_seconds = 0.2,
    };
    struct lk_reg_obs my = pg;

    CHECK(r);
    my.proto = "mysql";
    lk_reg_observe(r, &pg);
    lk_reg_observe(r, &pg);
    lk_reg_observe(r, &my); /* same fp/db/user, different protocol */

    dump(r, buf, sizeof(buf));
    /* Two separate duration series, each with its own count. */
    CHECK(contains(buf, "latkit_query_duration_seconds_count{query=\"select ?\",db=\"app\","
                        "user=\"alice\",proto=\"pg\",code=\"ok\"} 2\n"));
    CHECK(contains(buf, "latkit_query_duration_seconds_count{query=\"select ?\",db=\"app\","
                        "user=\"alice\",proto=\"mysql\",code=\"ok\"} 1\n"));
    /* queries_total keeps them apart too. */
    CHECK(contains(buf, "proto=\"pg\",kind=\"simple\",code=\"ok\"} 2\n"));
    CHECK(contains(buf, "proto=\"mysql\",kind=\"simple\",code=\"ok\"} 1\n"));
    /* A NULL proto folds to "pg" (the protocol default, РМ2). */
    my.proto = NULL;
    lk_reg_observe(r, &my);
    dump(r, buf, sizeof(buf));
    CHECK(contains(buf, "user=\"alice\",proto=\"pg\",code=\"ok\"} 3\n"));
    lk_reg_free(r);
    return 0;
}

/* --- the http profile (РH9/РH10, М5) -------------------------------------- */

static void http_obs(struct lk_registry *r, uint64_t fp, const char *route, const char *method,
                     const char *host, uint16_t status, uint64_t in, uint64_t out)
{
    char code[8];
    struct lk_reg_obs o = {
        .fp = fp,
        .label = route,
        .op = method,
        .db = host,
        .user = "-",
        .proto = "http",
        .profile = LK_PROF_HTTP,
        .kind = LK_QK_REQUEST,
        .sclass = (uint8_t)(LK_SCLASS_1XX + status / 100 - 1),
        .qcode = status >= 500 ? LK_QCODE_ERROR : LK_QCODE_OK,
        .has_duration = true,
        .dcode = status >= 500 ? LK_CODE_ERROR : LK_CODE_OK,
        .dur_seconds = 0.03,
        .has_first_row = true,
        .first_row_seconds = 0.01,
        .has_upload = in > 0,
        .upload_seconds = 0.5,
        .has_size = true,
        .size_bytes = out, /* the http profile histograms the response body */
        .bytes_in = in,
        .bytes_out = out,
    };

    if (status >= 400) {
        snprintf(code, sizeof(code), "%u", status);
        o.err_code = code;
    }
    lk_reg_observe(r, &o);
}

/* The profile decides the family names and the label keys, and nothing else:
 * one observation reaches every http family with the (route,method,host,user)
 * identity, and none of the query ones. */
static int test_http_profile(void)
{
    struct lk_registry *r = reg(8, 8);
    char buf[65536];

    CHECK(r);
    http_obs(r, 1, "/orders/{id}", "GET", "shop.example", 200, 0, 1500);
    http_obs(r, 1, "/orders/{id}", "GET", "shop.example", 200, 0, 1500);
    http_obs(r, 1, "/orders/{id}", "GET", "shop.example", 404, 0, 40);
    http_obs(r, 2, "/orders/{id}", "POST", "shop.example", 503, 900, 20);

    dump(r, buf, sizeof(buf));
    /* the identity, in every family, with the http label keys */
#define ID(m)                                                                                      \
    m "route=\"/orders/{id}\",method=\"GET\",host=\"shop.example\",user=\"-\",proto=\"http\""
    CHECK(contains(buf, ID("latkit_http_requests_total{") ",status=\"2xx\"} 2\n"));
    CHECK(contains(buf, ID("latkit_http_requests_total{") ",status=\"4xx\"} 1\n"));
    CHECK(contains(buf, ID("latkit_http_request_duration_seconds_count{") ",code=\"ok\"} 3\n"));
    CHECK(contains(buf, ID("latkit_http_ttfb_seconds_count{") "} 3\n"));
    CHECK(contains(buf, ID("latkit_http_bytes_total{") ",direction=\"out\"} 3040\n"));
    CHECK(contains(buf, ID("latkit_http_bytes_total{") ",direction=\"in\"} 0\n"));
    CHECK(contains(buf, ID("latkit_http_response_size_bytes_count{") "} 3\n"));
    CHECK(contains(buf, ID("latkit_http_response_size_bytes_bucket{") ",le=\"2048\"} 3\n"));
#undef ID
    /* the method is part of the identity (РH7): POST is its own slot, and its
     * 5xx is the one thing that reads as an error */
    CHECK(contains(buf, "method=\"POST\",host=\"shop.example\",user=\"-\",proto=\"http\",code="
                        "\"error\"} 1\n"));
    CHECK(contains(buf, "latkit_http_request_upload_seconds_count{route=\"/orders/{id}\",method="
                        "\"POST\""));
    /* the error counter is exact-code and route-free */
    CHECK(contains(buf, "latkit_http_errors_total{code=\"404\",host=\"shop.example\",user=\"-\","
                        "proto=\"http\"} 1\n"));
    CHECK(contains(buf, "latkit_http_errors_total{code=\"503\","));
    /* ... and no HTTP observation leaks into the database families */
    CHECK(!contains(buf, "proto=\"http\",kind="));
    CHECK(!contains(buf, "latkit_query_duration_seconds{query="));
    CHECK(!contains(buf, "latkit_http_request_duration_seconds_count{query="));
    lk_reg_free(r);
    return 0;
}

/* --- the s3 profile (РS7, PLAN-MINIO.md МS2) ------------------------------ */

static void s3_obs(struct lk_registry *r, uint64_t fp, const char *op, const char *method,
                   const char *bucket, uint16_t status, const char *s3code, uint64_t obj)
{
    char code[8];
    struct lk_reg_obs o = {
        .fp = fp,
        .label = op,
        .op = method,
        .db = bucket,
        .user = "AKIALK",
        .proto = "s3",
        .profile = LK_PROF_S3,
        .kind = LK_QK_REQUEST,
        .sclass = (uint8_t)(LK_SCLASS_1XX + status / 100 - 1),
        .qcode = status >= 500 ? LK_QCODE_ERROR : LK_QCODE_OK,
        .has_duration = true,
        .dcode = status >= 500 ? LK_CODE_ERROR : LK_CODE_OK,
        .dur_seconds = 0.03,
        .has_first_row = true,
        .first_row_seconds = 0.01,
        .has_size = obj > 0,
        .size_bytes = obj,
        .bytes_in = obj,
    };

    if (status >= 400) {
        snprintf(code, sizeof(code), "%u", status);
        o.err_code = s3code ? s3code : code;
    }
    lk_reg_observe(r, &o);
}

/* One profile row away from the http one, and the whole difference shows in the
 * dump: the S3 nouns on every family, the symbolic error code, the object grid
 * under the size histogram, and `internal` counted outside all of them. */
static int test_s3_profile(void)
{
    struct lk_registry *r = reg(8, 8);
    char buf[65536];

    CHECK(r);
    s3_obs(r, 1, "PutObject", "PUT", "photos", 200, NULL, 1048576);
    s3_obs(r, 1, "PutObject", "PUT", "photos", 200, NULL, 64ull << 20);
    s3_obs(r, 2, "GetObject", "GET", "photos", 404, "NoSuchKey", 0);
    s3_obs(r, 2, "GetObject", "GET", "photos", 404, "NoSuchBucket", 0);

#define ID(m) m "op=\"PutObject\",method=\"PUT\",bucket=\"photos\",user=\"AKIALK\",proto=\"s3\""
    dump(r, buf, sizeof(buf));
    CHECK(contains(buf, ID("latkit_s3_requests_total{") ",status=\"2xx\"} 2\n"));
    CHECK(contains(buf, ID("latkit_s3_request_duration_seconds_count{") ",code=\"ok\"} 2\n"));
    CHECK(contains(buf, ID("latkit_s3_ttfb_seconds_count{") "} 2\n"));
    CHECK(contains(buf, ID("latkit_s3_bytes_total{") ",direction=\"in\"} 68157440\n"));
    CHECK(contains(buf, ID("latkit_s3_object_size_bytes_count{") "} 2\n"));
    /* the object grid, not the response-size one: it starts at 1 KiB and holds
     * a 64 MiB part in a cell of its own (hist.h) */
    CHECK(contains(buf, ID("latkit_s3_object_size_bytes_bucket{") ",le=\"1024\"} 0\n"));
    CHECK(contains(buf, ID("latkit_s3_object_size_bytes_bucket{") ",le=\"1048576\"} 1\n"));
    CHECK(contains(buf, ID("latkit_s3_object_size_bytes_bucket{") ",le=\"67108864\"} 2\n"));
    CHECK(contains(buf, ID("latkit_s3_object_size_bytes_bucket{") ",le=\"1099511627776\"} 2\n"));
#undef ID
    /* two 404s, two different failures — the whole reason РS5 reads the body */
    CHECK(contains(buf, "latkit_s3_errors_total{s3code=\"NoSuchKey\",bucket=\"photos\","
                        "user=\"AKIALK\",proto=\"s3\"} 1\n"));
    CHECK(contains(buf, "latkit_s3_errors_total{s3code=\"NoSuchBucket\","));
    CHECK(contains(buf, "latkit_s3_requests_total{op=\"GetObject\",method=\"GET\",bucket="
                        "\"photos\",user=\"AKIALK\",proto=\"s3\",status=\"4xx\"} 2\n"));
    /* the two families an object store has no use for stay out of its block */
    CHECK(!contains(buf, "latkit_s3_rows"));
    CHECK(!contains(buf, "proto=\"s3\",kind="));
    CHECK(!contains(buf, "latkit_txn_duration_seconds{db=\"photos\""));
    /* the http families are not printed by an s3-only registry, and vice versa */
    CHECK(!contains(buf, "latkit_http_"));

    /* `/minio/…`: counted, and in no family that says "requests" (РS2) */
    CHECK(contains(buf, "latkit_s3_internal_requests_total 0\n"));
    struct lk_reg_obs internal = {
        .profile = LK_PROF_S3,
        .proto = "s3",
        .internal = true,
        .label = "internal",
        .op = "GET",
        .db = "-",
        .user = "-",
        .has_duration = true,
        .dur_seconds = 0.001,
    };

    lk_reg_observe(r, &internal);
    lk_reg_observe(r, &internal);
    dump(r, buf, sizeof(buf));
    CHECK(contains(buf, "latkit_s3_internal_requests_total 2\n"));
    CHECK(!contains(buf, "op=\"internal\""));
    CHECK(lk_reg_series_count_sum(r) == lk_reg_total_obs(r));
    lk_reg_free(r);
    return 0;
}

/* --- the redis profile (РR11, PLAN-REDIS.md МR5) --------------------------- */

static void redis_obs(struct lk_registry *r, uint64_t fp, const char *cmd, const char *db,
                      uint8_t qcode, const char *err, uint64_t out, uint32_t depth)
{
    struct lk_reg_obs o = {
        .fp = fp,
        .label = cmd,
        .db = db,
        .user = "default",
        .proto = "redis",
        .profile = LK_PROF_REDIS,
        .kind = LK_QK_COMMAND,
        .qcode = qcode,
        .has_duration = true,
        .dcode = qcode == LK_QCODE_ERROR ? LK_CODE_ERROR : LK_CODE_OK,
        .dur_seconds = 0.002,
        .has_size = out > 0,
        .size_bytes = out,
        .bytes_in = 24,
        .bytes_out = out,
        .err_code = err,
        .has_depth = depth > 0,
        .depth = depth,
    };

    lk_reg_observe(r, &o);
}

/* The fourth profile row, and the three families no other one has. Everything
 * the МR5 acceptance rests on is here in one dump: a command is counted whether
 * or not it was timed, its wait is timed where it cannot move a percentile, and
 * its redirect is counted where it cannot look like an outage. */
static int test_redis_profile(void)
{
    struct lk_registry *r = reg(8, 8);
    static char buf[1 << 17];

    CHECK(r);
    redis_obs(r, 1, "GET", "0", LK_QCODE_OK, NULL, 12, 1);
    redis_obs(r, 1, "GET", "0", LK_QCODE_OK, NULL, 4096, 8);
    redis_obs(r, 2, "HGETALL", "0", LK_QCODE_ERROR, "WRONGTYPE", 0, 1);

#define ID(m) m "cmd=\"GET\",db=\"0\",user=\"default\",proto=\"redis\""
    dump(r, buf, sizeof(buf));
    CHECK(contains(buf, ID("latkit_redis_commands_total{") ",code=\"ok\"} 2\n"));
    CHECK(contains(buf, ID("latkit_redis_command_duration_seconds_count{") ",code=\"ok\"} 2\n"));
    CHECK(contains(buf, ID("latkit_redis_bytes_total{") ",direction=\"out\"} 4108\n"));
    /* the value grid: 8 B … 8 MiB, so a 12-byte reply is in the second cell and
     * nothing lands where the http grid's 64 B floor would put it */
    CHECK(contains(buf, ID("latkit_redis_value_size_bytes_bucket{") ",le=\"8\"} 0\n"));
    CHECK(contains(buf, ID("latkit_redis_value_size_bytes_bucket{") ",le=\"16\"} 1\n"));
    CHECK(contains(buf, ID("latkit_redis_value_size_bytes_bucket{") ",le=\"4096\"} 2\n"));
    CHECK(contains(buf, ID("latkit_redis_value_size_bytes_bucket{") ",le=\"8388608\"} 2\n"));
#undef ID
    /* the depth histogram is keyed by the protocol alone, and per command */
    CHECK(contains(buf, "latkit_redis_pipeline_depth_bucket{proto=\"redis\",le=\"1\"} 2\n"));
    CHECK(contains(buf, "latkit_redis_pipeline_depth_bucket{proto=\"redis\",le=\"8\"} 3\n"));
    CHECK(contains(buf, "latkit_redis_pipeline_depth_count{proto=\"redis\"} 3\n"));
    /* the failure is symbolic and command-free (РR7) */
    CHECK(contains(buf, "latkit_redis_errors_total{error=\"WRONGTYPE\",db=\"0\",user=\"default\","
                        "proto=\"redis\"} 1\n"));
    /* the families a cache has no use for stay out of its block */
    CHECK(!contains(buf, "latkit_redis_rows"));
    CHECK(!contains(buf, "latkit_redis_ttfb"));
    CHECK(!contains(buf, "latkit_redis_request_upload"));
    CHECK(!contains(buf, "proto=\"redis\",kind="));
    CHECK(!contains(buf, "latkit_http_"));
    CHECK(!contains(buf, "latkit_s3_"));

    /* A `+QUEUED` and a `BLPOP`: counted, and neither of them timed here. The
     * duration family prints nothing at all for a command that only ever
     * queued, rather than an empty histogram claiming a distribution. */
    struct lk_reg_obs queued = {
        .fp = 3,
        .label = "SET",
        .db = "0",
        .user = "default",
        .proto = "redis",
        .profile = LK_PROF_REDIS,
        .kind = LK_QK_COMMAND,
        .qcode = LK_QCODE_OK,
        .bytes_in = 30,
        .bytes_out = 9,
    };
    struct lk_reg_obs blocked = {
        .fp = 4,
        .label = "BLPOP",
        .db = "0",
        .user = "default",
        .proto = "redis",
        .profile = LK_PROF_REDIS,
        .kind = LK_QK_COMMAND,
        .qcode = LK_QCODE_OK,
        .has_block = true,
        .block_seconds = 30.0,
        .has_size = true,
        .size_bytes = 40,
        .redirect = LK_REDIR_ASK,
    };

    lk_reg_observe(r, &queued);
    lk_reg_observe(r, &blocked);
    dump(r, buf, sizeof(buf));
    CHECK(contains(buf, "latkit_redis_commands_total{cmd=\"SET\",db=\"0\",user=\"default\","
                        "proto=\"redis\",code=\"ok\"} 1\n"));
    CHECK(contains(buf, "latkit_redis_bytes_total{cmd=\"SET\",db=\"0\",user=\"default\","
                        "proto=\"redis\",direction=\"in\"} 30\n"));
    CHECK(!contains(buf, "latkit_redis_command_duration_seconds_count{cmd=\"SET\""));
    CHECK(!contains(buf, "latkit_redis_command_duration_seconds_count{cmd=\"BLPOP\""));
    CHECK(contains(buf, "latkit_redis_blocking_seconds_sum{cmd=\"BLPOP\",db=\"0\",user=\"default\","
                        "proto=\"redis\"} 30\n"));
    CHECK(contains(buf, "latkit_redis_redirects_total{kind=\"ask\",proto=\"redis\"} 1\n"));
    CHECK(!contains(buf, "kind=\"none\""));
    /* the invariant the whole registry is checked by still holds: three timed
     * observations, three histogram samples, and the two untimed in neither */
    CHECK(lk_reg_series_count_sum(r) == lk_reg_total_obs(r));
    CHECK(lk_reg_total_obs(r) == 3);
    lk_reg_free(r);
    return 0;
}

/* The one family two profiles feed (РR9): a metric name may carry exactly one
 * HELP/TYPE block, so the transaction family is printed once for every protocol
 * that recorded an interval — not once per profile. */
static int test_txn_shared(void)
{
    struct lk_registry *r = reg(8, 8);
    char buf[65536];
    const char *p;
    int blocks = 0;

    CHECK(r);
    obs(r, 1, "select ?", "app", "alice", LK_CODE_OK);
    redis_obs(r, 2, "EXEC", "0", LK_QCODE_OK, NULL, 20, 1);
    lk_reg_observe_txn(r, "app", "alice", "pg", LK_PROF_QUERY, false, 0.4);
    lk_reg_observe_txn(r, "0", "default", "redis", LK_PROF_REDIS, true, 0.002);

    dump(r, buf, sizeof(buf));
    for (p = strstr(buf, "# TYPE latkit_txn_duration_seconds "); p;
         p = strstr(p + 1, "# TYPE latkit_txn_duration_seconds "))
        blocks++;
    CHECK(blocks == 1);
    CHECK(contains(buf, "latkit_txn_duration_seconds_count{db=\"app\",user=\"alice\",proto=\"pg\","
                        "status=\"ok\"} 1\n"));
    CHECK(contains(buf, "latkit_txn_duration_seconds_count{db=\"0\",user=\"default\","
                        "proto=\"redis\",status=\"aborted\"} 1\n"));
    /* ... and the transaction did not drag the protocol into the wrong profile:
     * `redis` is still printing latkit_redis_* families */
    CHECK(contains(buf, "latkit_redis_commands_total{cmd=\"EXEC\""));
    CHECK(!contains(buf, "proto=\"redis\",kind="));
    lk_reg_free(r);
    return 0;
}

/* The three profiles share one dictionary and one dimension table and nothing
 * else: an S3 operation and an HTTP route never land in each other's labels,
 * and the two size histograms keep their own grids in one dump. */
static int test_s3_http_split(void)
{
    struct lk_registry *r = reg(8, 8);
    static char buf[1 << 18]; /* three profiles' families in one dump */

    CHECK(r);
    http_obs(r, 1, "/orders/{id}", "GET", "shop.example", 200, 0, 1500);
    s3_obs(r, 2, "GetObject", "GET", "photos", 200, NULL, 4096);

    dump(r, buf, sizeof(buf));
    CHECK(contains(buf, "latkit_http_response_size_bytes_bucket{route=\"/orders/{id}\",method="
                        "\"GET\",host=\"shop.example\",user=\"-\",proto=\"http\",le=\"64\"} 0\n"));
    CHECK(contains(buf, "latkit_s3_object_size_bytes_bucket{op=\"GetObject\",method=\"GET\",bucket="
                        "\"photos\",user=\"AKIALK\",proto=\"s3\",le=\"4096\"} 1\n"));
    /* one grid per family, and neither borrowed the other's boundaries */
    CHECK(!contains(buf, "latkit_s3_object_size_bytes_bucket{op=\"GetObject\",method=\"GET\","
                         "bucket=\"photos\",user=\"AKIALK\",proto=\"s3\",le=\"64\"}"));
    CHECK(!contains(buf,
                    "latkit_http_response_size_bytes_bucket{route=\"/orders/{id}\",method="
                    "\"GET\",host=\"shop.example\",user=\"-\",proto=\"http\",le=\"1024\"} 0\n"
                    "latkit_http_response_size_bytes_bucket{route=\"/orders/{id}\",method="
                    "\"GET\",host=\"shop.example\",user=\"-\",proto=\"http\",le=\"2199023255552"
                    "\"}"));
    CHECK(!contains(buf, "op=\"/orders/{id}\""));
    CHECK(!contains(buf, "route=\"GetObject\""));
    lk_reg_free(r);
    return 0;
}

/* A PG-only registry emits no http blocks at all — the property that keeps an
 * existing exposition byte-identical (РH15). */
static int test_http_absent_without_traffic(void)
{
    struct lk_registry *r = reg(8, 8);
    char buf[16384];

    CHECK(r);
    obs(r, 1, "select ?", "app", "alice", LK_CODE_OK);
    dump(r, buf, sizeof(buf));
    CHECK(!contains(buf, "latkit_http_"));
    CHECK(!contains(buf, "latkit_s3_"));
    CHECK(contains(buf, "# TYPE latkit_queries_total counter\n"));
    lk_reg_free(r);
    return 0;
}

/* One registry, both profiles: the dictionary is shared (an HTTP route and a
 * SQL statement compete for the same K slots) but nothing else is — the two
 * label spaces never merge, and each profile's `other` counter is its own. */
static int test_profile_mix(void)
{
    struct lk_registry *r = reg(2, 8);
    char buf[65536];

    CHECK(r);
    obs(r, 10, "select ?", "app", "alice", LK_CODE_OK);
    http_obs(r, 20, "/health", "GET", "svc", 200, 0, 2);
    CHECK(lk_reg_n_queries(r) == 2); /* both took a slot */

    /* dictionary full: a third identity folds to the profile's own `other` */
    http_obs(r, 30, "/items/{id}", "GET", "svc", 200, 0, 2);
    dump(r, buf, sizeof(buf));
    CHECK(contains(buf, "latkit_queries_other_total 0\n")); /* not the http fold */
    CHECK(contains(buf, "route=\"other\",method=\"other\",host=\"svc\""));
    CHECK(contains(buf, "query=\"select ?\",db=\"app\",user=\"alice\",proto=\"pg\""));
    CHECK(lk_reg_other_obs(r) == 1); /* summed over profiles, for the invariant */
    CHECK(lk_reg_series_count_sum(r) == lk_reg_total_obs(r));
    lk_reg_free(r);
    return 0;
}

/* The structured walk (Р31, what OTLP exports) and the text dump are two
 * renderings of one registry, and they drift silently: a family added to the
 * dump and forgotten in the iterator disappears from OTLP without any test
 * going red. So: every view the iterator emits must be a family the dump also
 * prints, and every http family must be among them. */
struct iter_seen {
    const char *names[64];
    uint32_t n;
    uint32_t max_labels;
};

static void iter_cb(void *ctx, const struct lk_metric_view *v)
{
    struct iter_seen *s = ctx;

    if (v->nlabels > s->max_labels)
        s->max_labels = v->nlabels;
    for (uint32_t i = 0; i < s->n; i++)
        if (!strcmp(s->names[i], v->name))
            return;
    if (s->n < 64)
        s->names[s->n++] = v->name;
}

static int test_iter_matches_dump(void)
{
    struct lk_registry *r = reg(8, 8);
    struct iter_seen seen = {{0}, 0, 0};
    char buf[65536], want[128];
    static const char *const http_families[] = {
        "latkit_http_requests_total",
        "latkit_http_request_duration_seconds",
        "latkit_http_ttfb_seconds",
        "latkit_http_request_upload_seconds",
        "latkit_http_errors_total",
        "latkit_http_bytes_total",
        "latkit_http_response_size_bytes",
        "latkit_s3_requests_total",
        "latkit_s3_request_duration_seconds",
        "latkit_s3_ttfb_seconds",
        "latkit_s3_errors_total",
        "latkit_s3_bytes_total",
        "latkit_s3_object_size_bytes",
        "latkit_s3_internal_requests_total",
        "latkit_redis_commands_total",
        "latkit_redis_command_duration_seconds",
        "latkit_redis_blocking_seconds",
        "latkit_redis_errors_total",
        "latkit_redis_redirects_total",
        "latkit_redis_bytes_total",
        "latkit_redis_value_size_bytes",
        "latkit_redis_pipeline_depth",
    };

    CHECK(r);
    obs(r, 1, "select ?", "app", "alice", LK_CODE_OK);
    lk_reg_observe_txn(r, "app", "alice", "pg", LK_PROF_QUERY, false, 0.4);
    http_obs(r, 2, "/orders/{id}", "GET", "shop", 500, 10, 900);
    s3_obs(r, 3, "PutObject", "PUT", "photos", 403, "SignatureDoesNotMatch", 8192);
    redis_obs(r, 4, "GET", "0", LK_QCODE_OK, NULL, 64, 2);
    redis_obs(r, 5, "BLPOP", "0", LK_QCODE_ERROR, "WRONGTYPE", 12, 1);
    /* the blocking family has no observation of its own above: give it one, or
     * the "every family the dump prints is also a view" check cannot see it */
    struct lk_reg_obs blocked = {
        .fp = 6,
        .label = "BRPOP",
        .db = "0",
        .user = "default",
        .proto = "redis",
        .profile = LK_PROF_REDIS,
        .kind = LK_QK_COMMAND,
        .has_block = true,
        .block_seconds = 5.0,
        .redirect = LK_REDIR_MOVED,
    };

    lk_reg_observe(r, &blocked);

    lk_reg_iter(r, iter_cb, &seen);
    dump(r, buf, sizeof(buf));
    CHECK(seen.n > 0);
    for (uint32_t i = 0; i < seen.n; i++) {
        snprintf(want, sizeof(want), "# TYPE %s ", seen.names[i]);
        CHECK(contains(buf, want));
    }
    for (uint32_t i = 0; i < sizeof(http_families) / sizeof(*http_families); i++) {
        bool found = false;

        for (uint32_t j = 0; j < seen.n && !found; j++)
            found = !strcmp(seen.names[j], http_families[i]);
        CHECK(found);
    }
    /* route,method,host,user,proto + one of code/status/direction: the widest
     * label set any family has, and the bound the view's array must hold. */
    CHECK(seen.max_labels == 6);
    lk_reg_free(r);
    return 0;
}

int main(void)
{
    if (test_overflow_to_other() || test_evict_reset() || test_doorkeeper() ||
        test_cardinality_ceiling() || test_dim_limit() || test_dump_format() ||
        test_proto_split() || test_http_profile() || test_s3_profile() || test_redis_profile() ||
        test_txn_shared() || test_s3_http_split() || test_http_absent_without_traffic() ||
        test_profile_mix() || test_iter_matches_dump())
        return 1;
    printf("test_registry: all passed\n");
    return 0;
}
