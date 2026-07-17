/* SPDX-License-Identifier: GPL-2.0 */
/* PostgreSQL v3 handler internals (STAGE3.md, structure §). Shared across the
 * pg_*.c translation units: pg.c dispatches, pg_session.c owns startup/auth,
 * pg_query.c the phase machine (Р16), pg_prep.c the prepared-statement cache
 * (Р17). The public API is proto.h — nothing here escapes src/proto/pg/.
 *
 * Task 3.4 turns the single simple-query unit of task 3.3 into the in-flight
 * ring the extended protocol needs: Bind opens a unit, the backend replies
 * close units one by one, and up to LK_PG_MAX_INFLIGHT pipeline before a Sync.
 * Simple queries still work — they are one unit whose closing boundary is the
 * following Z (the client blocks on ReadyForQuery, so they never pipeline). */
#ifndef LATKIT_PG_H
#define LATKIT_PG_H

#include "proto.h"

/* In-flight queue depth (Р16): pipelining libpq/drivers really do reach dozens.
 * Beyond this the connection goes LOSSY until the next Z rather than risk
 * matching replies to the wrong request. */
#define LK_PG_MAX_INFLIGHT 64

/* Prepared-statement cache size per connection (Р17): drivers with server-side
 * prepared statements hold tens, not thousands. LRU-evicted past this. */
#define LK_PG_PREP_CACHE 256

/* Connection phase (Р16). Startup connections walk STARTUP -> AUTH -> READY;
 * resynced / synthetic connections start in READY-degraded. SKIP_TO_SYNC is the
 * extended error recovery (ignore until the batch's Sync/Z); COPY and IGNORE
 * arrive with later tasks / the session layer. */
enum pg_phase {
    PG_PH_STARTUP = 0, /* awaiting StartupMessage */
    PG_PH_AUTH,        /* startup seen, awaiting AuthenticationOk */
    PG_PH_READY,       /* between/among queries */
    PG_PH_COPY_IN,
    PG_PH_COPY_OUT,
    PG_PH_SKIP_TO_SYNC, /* extended: error in batch, skip until Sync/Z */
    PG_PH_IGNORE,       /* replication etc.: no observations */
};

/* One query unit (Р16): opened by a frontend message (Q for simple, Bind for
 * extended, FunctionCall for a legacy function), driven by backend replies,
 * closed by the message that completes it. Lives in the connection's in-flight
 * ring; slots are reused, so unit_reset (pg_query.c) preserves the owned text
 * buffer while clearing the semantics.
 *
 * Text (Р17). A unit does not copy the SQL unless it must: an extended unit
 * holds a *reference* into the prepared-statement cache (prep_idx + prep_gen),
 * resolved lazily at emit. own_text carries a copy only in two cases — a simple
 * query (whose text has no cache slot) and the rescue when the referenced cache
 * slot is evicted while the unit is still live (prep_idx is then reset to -1).
 * LK_QO_NO_TEXT means there is deliberately no text (Bind on an uncached name,
 * FunctionCall). */
struct pg_unit {
    __u64 ts_start_ns;     /* first frontend message of the unit (Q / Bind) */
    __u64 ts_first_row_ns; /* first DataRow; 0 = none */
    __u64 ts_complete_ns;  /* backend message that completed it (C/E/s/I) */
    __u64 rows;            /* summed over the CommandComplete tags */
    __u64 bytes;           /* COPY: summed len of CopyData messages (task 3.5) */
    __u32 ncomplete;       /* CommandComplete/EmptyQueryResponse count seen */
    __u8 kind;             /* enum lk_query_kind: the *opening* kind (SIMPLE /
                              EXTENDED / FUNCTION), which decides whether the unit
                              closes on its reply or waits for Z */
    __u8 copy_kind;        /* 0, or LK_Q_COPY_IN / LK_Q_COPY_OUT once a Copy*
                              Response arrives — reported as the observation kind
                              while `kind` keeps driving the Z-close logic */
    __u16 flags;           /* accumulated LK_QO_* */
    char sqlstate[6];      /* from ErrorResponse 'C'; valid on LK_QO_ERROR */

    int prep_idx;   /* prepared-cache slot referenced, or -1 (own_text / none) */
    __u32 prep_gen; /* generation of that slot at Bind, for a validity check */
    char *own_text; /* owned SQL copy (simple query / eviction rescue); reused
                       across the slot's units, freed on conn close */
    __u32 own_len;  /* length of own_text (0 = unused) */
    __u32 own_cap;  /* allocated capacity of own_text */
};

/* One prepared-statement cache entry (Р17): statement name -> SQL prefix. The
 * generation is bumped every time the slot is reused, so a stale unit reference
 * (one that missed its eviction rescue) is detected rather than followed. */
struct pg_prep {
    bool used;      /* slot occupied */
    bool trunc;     /* text is a truncated prefix (-> LK_QO_TEXT_TRUNC) */
    __u32 gen;      /* bumped on slot reuse; a unit stores the gen it saw */
    __u64 lru;      /* last-access stamp (pg_prep_cache.clock) for eviction */
    __u16 name_len; /* length of name (may be < the real name if truncated) */
    char name[64];  /* statement name; "" is the unnamed statement */
    char *text;     /* owned SQL prefix, <= LK_MSG_BODY_MAX; NULL if none */
    __u32 text_len; /* length of text */
    __u32 text_cap; /* allocated capacity of text (kept across reuse) */
};

/* Per-connection prepared-statement cache: a fixed LRU array, allocated lazily
 * on the first Parse (simple-only connections never pay for it). */
struct pg_prep_cache {
    struct pg_prep e[LK_PG_PREP_CACHE];
    __u64 clock; /* monotonic stamp source for LRU */
    __u32 count; /* occupied slots */
};

/* Per-connection parser state — the owner of lk_conn.proto_state (Р15).
 * Allocated lazily on the connection's first message, freed in on_conn_close. */
struct pg_conn {
    enum pg_phase phase;
    struct lk_session session; /* startup params + server_version (Р16) */
    __u64 msgs;                /* messages dispatched on this connection */

    /* --- in-flight query ring (Р16) ---------------------------------------
     * A batch of units accumulates here and is emitted together at the batch's Z
     * (the pipelined batch shares one ts_ready). head is the oldest unit; the
     * next backend reply closes ring[head + nclosed] (FIFO); Z emits the closed
     * units and drops the rest. */
    struct pg_unit ring[LK_PG_MAX_INFLIGHT];
    __u32 head;    /* index of the oldest unit in the batch */
    __u32 count;   /* units in the batch (open + closed, until Z) */
    __u32 nclosed; /* units from head already closed by a backend reply */
    bool lossy;    /* ring overflowed: emit nothing until the next Z */
    bool degraded; /* READY-degraded (Р19): no unit opens until a clean Z */

    /* --- prepared statements (Р17) ---------------------------------------- */
    struct pg_prep_cache *prep; /* lazily allocated on the first Parse */

    /* --- transaction tracking (Р16) --------------------------------------- */
    char txn_status;    /* last ReadyForQuery status (I/T/E); 0 = unknown */
    __u64 txn_start_ns; /* Z timestamp of the I->T that opened the current txn */
};

/* The handler object (struct lk_proto) is the protocol-independent base from
 * proto.h — the pg_*.c helpers reach the upward query sink and the counters
 * through it. Assembled by lk_proto_pg_new (pg.c). */

/* --- pg_session.c (task 3.2): startup, auth, session labels --------------- */

void pg_session_startup(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                        const struct lk_msg *m);
void pg_session_auth(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                     const struct lk_msg *m);
void pg_session_param_status(struct pg_conn *pc, const struct lk_msg *m);

/* --- pg_prep.c (task 3.4): prepared-statement cache (Р17) ----------------- */

/* Parse ('P'): cache {statement name -> SQL prefix}. The unnamed statement is
 * overwritten by each Parse; a named one replaces its previous text. Evicts the
 * LRU entry (bumping prep_evictions) when the cache is full; rescues live unit
 * references before reusing any slot. No-op (but counted upstream) on OOM. */
void pg_prep_parse(struct lk_proto *p, struct pg_conn *pc, const struct lk_msg *m);

/* Close ('C', frontend) of kind 'S': drop the named statement from the cache
 * (rescuing live references first). Kind 'P' (portal close) is not a cache op. */
void pg_prep_close(struct pg_conn *pc, const struct lk_msg *m);

/* Look up a statement name, refresh its LRU stamp, and hand back the slot index
 * (or -1) plus its generation and truncation flag — everything a Bind needs to
 * point a unit at the cached text. */
int pg_prep_lookup(struct pg_conn *pc, const char *name, __u32 name_len, __u32 *gen, bool *trunc);

/* Free the cache and its text buffers (conn close). */
void pg_prep_free(struct pg_conn *pc);

/* Copy a slot's text into every live unit that references it, then invalidate
 * the references — called from pg_prep.c before a slot is reused, and exposed
 * so the ring (pg_query.c) owns the copy target. Defined in pg_query.c. */
void pg_query_rescue_refs(struct pg_conn *pc, int slot);

/* --- pg_query.c (task 3.3/3.4): the phase machine ------------------------- */

/* Frontend simple Query ('Q'): open a SIMPLE unit and copy its SQL text. */
void pg_query_simple(struct lk_proto *p, struct pg_conn *pc, const struct lk_msg *m);

/* Frontend extended messages. Bind ('B') opens an EXTENDED unit (text from the
 * prepared cache, or LK_QO_NO_TEXT); Execute ('E') marks the head unit as
 * executing; Sync ('S') is a batch boundary (no-op here, the Z does the work);
 * FunctionCall ('F') opens a FUNCTION unit with no text. */
void pg_query_bind(struct lk_proto *p, struct pg_conn *pc, const struct lk_msg *m);
void pg_query_execute(struct pg_conn *pc, const struct lk_msg *m);
void pg_query_function(struct lk_proto *p, struct pg_conn *pc, const struct lk_msg *m);

/* Backend replies that close units in FIFO order without emitting — the batch is
 * emitted together at its Z (Р16). DataRow stamps the current unit's first-row
 * time; CommandComplete/EmptyQueryResponse/PortalSuspended close it (extended
 * units advance nclosed; a simple unit accumulates until Z); ErrorResponse
 * attaches the SQLSTATE and, in an extended batch, aborts the tail. */
void pg_query_data_row(struct pg_conn *pc, const struct lk_msg *m);
void pg_query_complete(struct lk_proto *p, struct pg_conn *pc, const struct lk_msg *m);
void pg_query_empty(struct pg_conn *pc, const struct lk_msg *m);
void pg_query_suspended(struct pg_conn *pc, const struct lk_msg *m);
void pg_query_error(struct pg_conn *pc, const struct lk_msg *m);
void pg_query_func_response(struct pg_conn *pc, const struct lk_msg *m);

/* COPY (Р20). CopyInResponse ('G') / CopyOutResponse ('H') turn the open unit
 * into a COPY_IN / COPY_OUT unit and move the connection into the matching COPY
 * phase; CopyData ('d', either direction) adds its len to the unit's byte
 * counter (bodies are never inspected); the closing CommandComplete ("COPY n")
 * supplies rows, and Z emits — a simple-protocol COPY like any simple query, an
 * extended one advancing nclosed. CopyBothResponse ('W') is walsender /
 * replication: the connection goes IGNORE, its queue is dropped, and
 * replication_conns is bumped (userspace flips it to HEADERS capture, Р21). */
void pg_query_copy_begin(struct pg_conn *pc, __u8 copy_kind);
void pg_query_copy_data(struct pg_conn *pc, const struct lk_msg *m);
void pg_query_copy_both(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc);

/* Backend ReadyForQuery ('Z'): emit the batch (every closed unit plus the open
 * simple/function unit, all sharing this Z as ts_ready), drop any leftovers, end
 * SKIP_TO_SYNC / READY-degraded / LOSSY, and track the transaction (emit on_txn
 * on a T|E -> I edge). */
void pg_query_ready(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                    const struct lk_msg *m);

/* Drop every in-flight unit without emitting and add the count to *counter
 * (resync/close, Р19): an observation must never span a loss or a disconnect.
 * NULL-safe on counter. */
void pg_query_drop_all(struct pg_conn *pc, __u64 *counter);

#endif /* LATKIT_PG_H */
