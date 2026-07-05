/* SPDX-License-Identifier: GPL-2.0 */
/* PostgreSQL v3 handler internals (STAGE3.md, structure §). Shared across the
 * pg_*.c translation units (pg.c dispatches; pg_session/pg_query/pg_prep land
 * in tasks 3.2-3.5). The public API is proto.h — nothing here escapes the
 * src/proto/pg/ directory.
 *
 * Stage 3.1 is the skeleton: the phase machine (Р16) is declared but only its
 * initial states are used, messages are dispatched to per-direction stubs, and
 * the only real work is per-connection state ownership and message counting. */
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
 * Grows into the phase machine + in-flight queue + prepared-stmt cache over
 * tasks 3.2-3.5; here it holds just what the skeleton needs. */
struct pg_conn {
    enum pg_phase phase;
    __u64 msgs; /* messages dispatched on this connection */
};

#endif /* LATKIT_PG_H */
