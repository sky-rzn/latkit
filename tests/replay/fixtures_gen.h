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

#define FX_MAX_MSGS 32

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
    __u16 obs_flags;          /* expected lk_query_obs.flags (LK_QO_*) */
    __u8 obs_kind;            /* expected lk_query_obs.kind */
    const char *obs_text;     /* expected SQL text; NULL = do not check */
    const char *obs_sqlstate; /* expected SQLSTATE; NULL = do not check */
};

struct fixture {
    const char *name; /* file stem: tests/fixtures/<name>.lkt */
    void (*build)(struct fx *x);
};

extern const struct fixture lk_fixtures[];
extern const size_t lk_nfixtures;

#endif /* LATKIT_FIXTURES_GEN_H */
