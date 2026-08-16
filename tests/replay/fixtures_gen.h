/* SPDX-License-Identifier: GPL-2.0 */
/* Fixture builders (task 2.5): construct LKT1 traces (record.h) of synthetic
 * PostgreSQL sessions, in the exact record format a live `--record` produces,
 * together with the framer output each is expected to yield. One source of
 * truth for both gen_fixtures (writes the tests/fixtures .lkt files) and
 * (regenerates for a byte-for-byte reproducibility check, then replays the
 * committed file and asserts the expected messages). Building the trace and
 * its expectations in lockstep keeps them from drifting.
 *
 * These stand in for captures snapped off a live psql/pgbench with --record;
 * the record format and the replay path are identical, so a real capture
 * drops in as another fixture without code changes. */
#ifndef LATKIT_FIXTURES_GEN_H
#define LATKIT_FIXTURES_GEN_H

#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>

/* One expected framer message: dir/type/len plus the LK_MSG_* flags. */
struct fx_msg {
    __u8 dir;    /* enum lk_dir */
    char type;   /* 0 for startup / one-byte-reply messages */
    __u32 len;   /* protocol len field (0 for the one-byte SSL reply) */
    __u16 flags; /* expected LK_MSG_* */
};

/* An HTTP keep-alive fixture is 50 exchanges of five messages (PLAN-HTTP.md
 * М8), which is what sets this ceiling; the PG/MySQL fixtures use a handful. */
#define FX_MAX_MSGS 288

/* A built fixture: the trace bytes and everything test_replay asserts. */
struct fx {
    __u8 *buf; /* malloc'd LKT1 trace; caller frees */
    size_t len;

    struct fx_msg msgs[FX_MAX_MSGS];
    size_t nmsgs;
    bool clean;      /* expect zero bad_len/hdr_holes/off_anomalies */
    __u64 resyncs;   /* expected reasm resync count */
    __u64 tls_conns; /* expected reasm tls_conns count */

    /* Stage-3 parser expectations (task 3.2): the sessions the PG handler
     * emits and their labels; the observation count (task 3.3 makes it non-zero
     * for the simple-query fixtures). */
    __u64 sessions;        /* expected on_session count */
    __u64 queries;         /* expected on_query count */
    const char *sess_user; /* last session's user     (when sessions > 0) */
    const char *sess_db;   /* last session's database (when sessions > 0) */

    /* Last observation's fields (task 3.3), checked when queries > 0. */
    __u64 obs_rows;           /* expected lk_query_obs.rows */
    __u64 obs_bytes;          /* expected lk_query_obs.bytes (COPY) */
    __u16 obs_flags;          /* expected lk_query_obs.flags (LK_QO_*) */
    __u8 obs_kind;            /* expected lk_query_obs.kind */
    const char *obs_text;     /* expected SQL text; NULL = do not check */
    const char *obs_sqlstate; /* expected SQLSTATE; NULL = do not check */

    /* Parser counters (task 3.4), always checked against lk_proto_stats. */
    __u64 errors_sql; /* expected LK_QO_ERROR observations */

    /* --- HTTP expectations (PLAN-HTTP.md М8) -------------------------------
     * An HTTP observation's identity is a method, a templated route and a
     * status, not rows and a SQLSTATE, so the last-observation checks above
     * would pin nothing that matters. These are checked when queries > 0 and
     * the fixture sets them; obs_route = "" means "expect no route at all"
     * (the authority-form CONNECT), NULL means "do not check". */
    const char *obs_op;    /* lk_query_obs.op — the method */
    const char *obs_route; /* lk_query_obs.route — the template, never the path */
    __u16 obs_status;      /* lk_query_obs.err_code — set on every http obs */
    __u64 obs_bytes_in;    /* request body bytes */
    __u64 obs_bytes_out;   /* response body bytes */

    /* --- S3 expectations (PLAN-MINIO.md МS4) -------------------------------
     * The two fields an S3 observation has that no other HTTP one does, and
     * both are the point of a fixture rather than a detail of it: the failure's
     * name, which the status cannot express (РS5), and the object's size with
     * the aws-chunked framing discounted (РS6). Checked when queries > 0;
     * obs_err_name = "" means "expect no code at all", NULL means do not check.
     * obs_obj_bytes is always checked on an s3 fixture, because "the logical
     * size equals the wire size" is itself an assertion on every shape that is
     * not chunked. */
    const char *obs_err_name; /* lk_query_obs.err_name — NoSuchKey, ... */
    __u64 obs_obj_bytes;      /* lk_query_obs.obj_bytes */
    bool check_obj_bytes;     /* set by the s3 builders: 0 is a real expectation */

    /* Counters that are zero for every PG/MySQL fixture and are the point of
     * several HTTP ones; always checked, so a new blind zone or a new parse
     * error cannot appear anywhere in the set without a test saying so. */
    __u64 parse_errors; /* lk_proto_stats.parse_errors */
    __u64 blind_conns;  /* ... blind_conns (РH4: h2 / upgrade / CONNECT) */
};

struct fixture {
    const char *name; /* file stem: tests/fixtures/<name>.lkt */
    void (*build)(struct fx *x);
    const char *proto;     /* NULL = pg (the registry head); "mysql" for the
                              MySQL mirror set (MYSQL.md М7), "http" for the HTTP
                              one (PLAN-HTTP.md М8), "s3" for the S3 one
                              (PLAN-MINIO.md МS4) — selects both the framer and
                              the handler run over the fixture */
    const char *s3_domain; /* --s3-domain for this fixture (РS3): NULL = none,
                              and then every request is read path-style, which
                              is what MinIO itself does without MINIO_DOMAIN.
                              Only the virtual-host fixture sets it, exactly as
                              only a configured deployment gets that form */
};

extern const struct fixture lk_fixtures[];
extern const size_t lk_nfixtures;

#endif /* LATKIT_FIXTURES_GEN_H */
