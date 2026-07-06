/* SPDX-License-Identifier: GPL-2.0 */
/* PostgreSQL v3 handler internals (STAGE3.md, structure §). Shared across the
 * pg_*.c translation units (pg.c dispatches; pg_session lands in task 3.2,
 * pg_query/pg_prep in 3.3-3.5). The public API is proto.h — nothing here
 * escapes the src/proto/pg/ directory.
 *
 * Task 3.2 adds startup/session/auth: pg.c dispatches, pg_session.c owns the
 * StartupMessage/AuthenticationOk/ParameterStatus/CancelRequest handling; the
 * query phase machine (Р16) still only uses its initial states. */
#ifndef LATKIT_PG_H
#define LATKIT_PG_H

#include "proto.h"

/* Connection phase (Р16). Startup connections walk STARTUP -> AUTH -> READY;
 * resynced / synthetic connections start in READY-degraded (tracked on the
 * conn state, task 3.5). The COPY, SKIP_TO_SYNC and IGNORE phases arrive with
 * later tasks. */
enum pg_phase {
    PG_PH_STARTUP = 0, /* awaiting StartupMessage */
    PG_PH_AUTH,        /* startup seen, awaiting AuthenticationOk */
    PG_PH_READY,       /* between/among queries */
    PG_PH_COPY_IN,
    PG_PH_COPY_OUT,
    PG_PH_SKIP_TO_SYNC, /* extended: error in batch, skip until Sync/Z */
    PG_PH_IGNORE,       /* replication etc.: no observations */
};

/* One in-flight query unit (Р16): opened by a frontend message (Q for a simple
 * query), driven by the backend replies, closed by the message that completes
 * it. Task 3.3 tracks a single simple unit at a time — simple queries never
 * pipeline, the client waits for ReadyForQuery — so one embedded unit suffices;
 * task 3.4 turns this into the LK_PG_MAX_INFLIGHT ring for the extended
 * protocol. The text is not stored here: it lives in the owning pg_conn's
 * reused buffer, since the Q body pointer is only valid during its on_msg. */
struct pg_unit {
    __u64 ts_start_ns;     /* first frontend message of the unit (Q) */
    __u64 ts_first_row_ns; /* first DataRow; 0 = none */
    __u64 ts_complete_ns;  /* backend message that completed it (C/E/I) */
    __u64 rows;            /* summed over the CommandComplete tags */
    __u32 ncomplete;       /* CommandComplete/EmptyQueryResponse count seen */
    __u8 kind;             /* enum lk_query_kind */
    __u16 flags;           /* accumulated LK_QO_* */
    char sqlstate[6];      /* from ErrorResponse 'C'; valid on LK_QO_ERROR */
};

/* Per-connection parser state — the owner of lk_conn.proto_state (Р15).
 * Allocated lazily on the connection's first message, freed in on_conn_close.
 * Grows into the in-flight queue + prepared-stmt cache over tasks 3.4-3.5;
 * task 3.2 adds the session labels, task 3.3 the simple-query unit + txn
 * tracking. */
struct pg_conn {
    enum pg_phase phase;
    struct lk_session session; /* startup params + server_version (Р16) */
    __u64 msgs;                /* messages dispatched on this connection */

    /* --- task 3.3: simple-query unit --------------------------------------- */
    struct pg_unit unit; /* the currently open unit (one at a time for simple) */
    bool unit_open;
    bool degraded;    /* READY-degraded (Р19): after a resync or on a synthetic
                         connection, no unit opens until the first clean Z */
    char *text;       /* owned copy of the open unit's SQL, lazily allocated and
                         reused across units, <= LK_MSG_BODY_MAX, freed on close */
    __u32 text_len;   /* length of the copy above (trailing NUL stripped) */
    __u32 text_cap;   /* allocated capacity of `text` */

    /* --- task 3.3: transaction tracking (Р16) ------------------------------ */
    char txn_status;    /* last ReadyForQuery status (I/T/E); 0 = unknown */
    __u64 txn_start_ns; /* Z timestamp of the I->T that opened the current txn */
};

/* The handler object, shared with the pg_*.c helpers so they can reach the
 * upward query sink and the counters. Assembled by lk_proto_pg_new (pg.c). */
struct lk_proto {
    struct lk_msg_sink msink; /* down: installed as the framer's sink */
    struct lk_query_sink out; /* up: borrowed from the assembler */
    struct lk_proto_stats st;
};

/* --- pg_session.c (task 3.2): startup, auth, session labels --------------- */

/* Frontend StartupMessage (LK_MSG_STARTUP): parse the wire code and, for a v3
 * StartupMessage, the parameter list into pc->session; CancelRequest emits a
 * CANCEL observation; SSL/GSSENC requests are left for the framer's reply
 * handling. Never reads a PasswordMessage — that is pg.c's default path. */
void pg_session_startup(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                        const struct lk_msg *m);

/* Backend Authentication ('R'): AuthenticationOk (code 0) advances to READY and
 * emits on_session; every other code keeps waiting in AUTH. */
void pg_session_auth(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                     const struct lk_msg *m);

/* Backend ParameterStatus ('S'): pick up server_version into the session
 * labels, ignore the rest. */
void pg_session_param_status(struct pg_conn *pc, const struct lk_msg *m);

/* --- pg_query.c (task 3.3): simple query, rows, errors, transactions ------ */

/* Frontend simple Query ('Q'): open a unit and copy its SQL text. A no-op while
 * READY-degraded (Р19) — the query is observed through a gap, never emitted. */
void pg_query_simple(struct pg_conn *pc, const struct lk_msg *m);

/* Backend replies that drive the open unit. DataRow ('D') stamps the first-row
 * time; CommandComplete ('C') and EmptyQueryResponse ('I') tally a statement's
 * rows; ErrorResponse ('E') attaches the SQLSTATE. None of these close the unit
 * — for a simple query the closing boundary is always the following Z. */
void pg_query_data_row(struct pg_conn *pc, const struct lk_msg *m);
void pg_query_complete(struct lk_proto *p, struct pg_conn *pc, const struct lk_msg *m);
void pg_query_empty(struct pg_conn *pc, const struct lk_msg *m);
void pg_query_error(struct pg_conn *pc, const struct lk_msg *m);

/* Backend ReadyForQuery ('Z'): close any open unit (emit on_query), advance the
 * transaction status and emit on_txn on a T|E -> I edge, and end READY-degraded
 * (a clean Z is the only guaranteed "between queries" boundary, Р19). */
void pg_query_ready(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                    const struct lk_msg *m);

/* Drop an open unit without emitting and bump *counter (resync/close, Р19):
 * an observation must never span a loss or a disconnect. NULL-safe on counter. */
void pg_query_drop(struct pg_conn *pc, __u64 *counter);

#endif /* LATKIT_PG_H */
