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

/* Per-connection parser state — the owner of lk_conn.proto_state (Р15).
 * Allocated lazily on the connection's first message, freed in on_conn_close.
 * Grows into the in-flight queue + prepared-stmt cache over tasks 3.3-3.5;
 * task 3.2 adds the session labels filled from startup + AuthenticationOk. */
struct pg_conn {
    enum pg_phase phase;
    struct lk_session session; /* startup params + server_version (Р16) */
    __u64 msgs;                /* messages dispatched on this connection */
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

#endif /* LATKIT_PG_H */
