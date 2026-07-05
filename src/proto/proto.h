/* SPDX-License-Identifier: GPL-2.0 */
/* Core <-> protocol-handler boundary (Р15, STAGE3.md). Exactly two contracts
 * live here, and this is the only header the core (events.c / the replay
 * harness) needs to speak to a protocol:
 *
 *   - down (core -> handler): the already-existing struct lk_msg_sink
 *     (reassembly.h) — whole messages, open/close, resync. A protocol handler
 *     *is* an lk_msg_sink implementation; the framer does not know who listens,
 *     so the --messages logger and the PG parser plug in the same way. Re-
 *     exported here so a consumer includes just proto.h.
 *   - up (handler -> consumer): the new struct lk_query_sink below —
 *     protocol-independent observations (lk_query_obs). Stage 3's consumer is
 *     the --queries logger; stage 4 swaps it for the aggregator without
 *     touching the parser.
 *
 * Per-connection parser state lives in lk_conn.proto_state (void *, owned by
 * the handler): allocated lazily on the connection's first message, freed in
 * on_conn_close. The connection table fires that close-hook on *every* removal
 * path (CONN_CLOSE, LRU eviction, idle sweep, table teardown) — see
 * lk_conn_table_on_destroy — so proto_state never leaks.
 *
 * Deliberate seam (Р15): the framer itself (reassembly.c) stays PG-aware —
 * type+len frames, startup framing and the 'Z' resync anchor are baked in.
 * Generalising the framer into per-protocol framer-ops waits for a second real
 * protocol; abstracting from a single instance is guessing. When that day
 * comes, the registry below grows a second entry and this file grows a vtable.
 *
 * Everything under src/proto/ is pure (no I/O, no libbpf), like decode /
 * conn_table / reassembly: unit tests feed synthetic lk_msg, replay tests feed
 * .lkt fixtures through the shared pipeline. */
#ifndef LATKIT_PROTO_H
#define LATKIT_PROTO_H

#include <linux/types.h>
#include <stdbool.h>

#include "conn_table.h" /* struct lk_conn, enum lk_dir */
#include "reassembly.h" /* struct lk_msg, struct lk_msg_sink (down contract) */

/* --- up contract: protocol-independent query observations ----------------- */

enum lk_query_kind {
    LK_Q_SIMPLE,   /* simple query (Q .. Z) */
    LK_Q_EXTENDED, /* extended: Bind/Execute */
    LK_Q_FUNCTION, /* FunctionCall */
    LK_Q_COPY_IN,  /* COPY FROM STDIN */
    LK_Q_COPY_OUT, /* COPY TO STDOUT */
    LK_Q_CANCEL,   /* CancelRequest */
};

/* lk_query_obs.flags */
#define LK_QO_ERROR      (1 << 0) /* closed by ErrorResponse; sqlstate valid */
#define LK_QO_TEXT_TRUNC (1 << 1) /* text is a prefix (capture budget) */
#define LK_QO_NO_TEXT    (1 << 2) /* no text (prepared not cached, F, ...) */
#define LK_QO_MULTI_STMT (1 << 3) /* simple Q with several statements */
#define LK_QO_EMPTY      (1 << 4) /* EmptyQueryResponse */
#define LK_QO_SUSPENDED  (1 << 5) /* PortalSuspended: Execute with a row limit */
#define LK_QO_ABORTED    (1 << 6) /* extended: killed by an earlier batch error */
#define LK_QO_PIPELINED  (1 << 7) /* more than one unit in the batch */

struct lk_session {
    char user[64], database[64], app[64]; /* truncated copies; "" = unknown */
    char server_version[16];
    bool complete; /* startup seen in full */
};

struct lk_query_obs {
    __u64 ts_start_ns;     /* first frontend message of the unit */
    __u64 ts_first_row_ns; /* first DataRow; 0 = none */
    __u64 ts_complete_ns;  /* backend message that closed the unit */
    __u64 ts_ready_ns;     /* nearest following Z; 0 = not yet (ABORTED/CANCEL) */
    const char *text;      /* raw SQL prefix, NOT normalised; NULL on NO_TEXT;
                              valid only for the duration of on_query */
    __u32 text_len;
    __u64 rows;       /* from the CommandComplete tag; summed on MULTI_STMT */
    __u64 bytes;      /* COPY: summed len of CopyData */
    char sqlstate[6]; /* on LK_QO_ERROR, C-string */
    __u8 kind;        /* enum lk_query_kind */
    char txn_status;  /* I/T/E from the closing Z; 0 = unknown */
    __u16 flags;      /* LK_QO_* */
};

struct lk_query_sink {
    void *ctx;
    void (*on_query)(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                     const struct lk_query_obs *o);
    void (*on_session)(void *ctx, const struct lk_conn *c,
                       const struct lk_session *s);    /* AuthenticationOk */
    void (*on_txn)(void *ctx, const struct lk_conn *c, /* T|E -> I on Z */
                   __u64 start_ns, __u64 end_ns, char final_status);
};

/* --- parser counters ------------------------------------------------------ */
/* Reported in the 10 s stats line; the field names are the stage-4 metric
 * stems. Stage 3.1 fills in only the message tallies (msgs / startup_msgs /
 * resyncs / conns / by_type); the query/error/loss counters wire up as the
 * parser grows (tasks 3.2-3.5). */
struct lk_proto_stats {
    __u64 msgs;                   /* messages dispatched */
    __u64 startup_msgs;           /* ... of them startup-framed */
    __u64 resyncs;                /* on_resync callbacks seen */
    __u64 conns;                  /* proto_state allocations (connections seen) */
    __u64 queries;                /* observations emitted */
    __u64 errors_sql;             /* LK_QO_ERROR observations */
    __u64 parse_errors;           /* corrupt field -> latkit_parse_errors_total */
    __u64 unknown_msgs;           /* unknown message type, skipped by len */
    __u64 units_dropped_resync;   /* in-flight units dropped on a resync */
    __u64 units_dropped_close;    /* ... on a CONN_CLOSE with a non-empty queue */
    __u64 units_dropped_overflow; /* ... over LK_PG_MAX_INFLIGHT */
    __u64 prep_evictions;         /* prepared-statement cache evictions */
    __u64 sessions;               /* on_session emitted */
    __u64 replication_conns;      /* CopyBoth -> IGNORE connections */
    __u64 by_type[2][256];        /* [enum lk_dir][type byte]; startup at [.][0] */
};

/* --- registry (Р15): one handler today, a vtable when a second arrives ---- */

/* Opaque protocol handler. Owns its per-connection state through
 * lk_conn.proto_state; is an lk_msg_sink downward and drives an lk_query_sink
 * upward. Assembled in exactly one place: events.c (live) / the replay harness
 * (offline). */
struct lk_proto;

/* PostgreSQL v3 handler. `out` (may have NULL callbacks) receives the
 * observations; it is borrowed, not copied deeply — keep it alive for the
 * handler's lifetime. */
struct lk_proto *lk_proto_pg_new(const struct lk_query_sink *out);

/* The down contract: install this as the framer's sink (or mirror into it). */
const struct lk_msg_sink *lk_proto_sink(struct lk_proto *p);

/* Cumulative counters for the stats line. */
const struct lk_proto_stats *lk_proto_stats(const struct lk_proto *p);

void lk_proto_free(struct lk_proto *p);

#endif /* LATKIT_PROTO_H */
