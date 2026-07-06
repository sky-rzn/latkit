// SPDX-License-Identifier: GPL-2.0
/* PostgreSQL v3 handler (STAGE3.md). Owns the per-connection parser state
 * through lk_conn.proto_state, mirrors the lk_msg_sink contract, tallies
 * messages by (direction, type), and dispatches each message by (direction,
 * phase, type). Task 3.2 wires the startup handshake (pg_session.c); the query
 * phases (simple/extended/COPY) fill in over tasks 3.3-3.5.
 *
 * No I/O, no libbpf: a pure state machine fed synthetic lk_msg by unit tests
 * and .lkt fixtures by the replay harness. */
#include "pg.h"

#include <stdlib.h>
#include <string.h>

#include "pg_wire.h"

/* struct lk_proto lives in pg.h so the pg_*.c helpers reach the sink/counters. */

/* Lazily attach per-connection state on the first message (Р15). Returns NULL
 * only on allocation failure — the caller degrades to counting, never crashes. */
static struct pg_conn *pg_conn_get(struct lk_proto *p, struct lk_conn *c)
{
    struct pg_conn *pc = c->proto_state;

    if (pc)
        return pc;
    pc = calloc(1, sizeof(*pc));
    if (!pc)
        return NULL;
    /* Startup is only ever seen on a fresh frontend stream; a synthetic or
     * mid-session entry joins in READY-degraded (Р19): no unit opens until the
     * first clean Z proves a "between queries" boundary. */
    if (c->flags & LK_CONN_SYNTHETIC) {
        pc->phase = PG_PH_READY;
        pc->degraded = true;
    } else {
        pc->phase = PG_PH_STARTUP;
    }
    c->proto_state = pc;
    p->st.conns++;
    return pc;
}

/* --- per-direction dispatch (grows in 3.3-3.5) ---------------------------- */

/* frontend -> backend (RECV on the server socket): startup, Q, P, B, E, S, X. */
static void pg_frontend_msg(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                            const struct lk_msg *m)
{
    if (m->flags & LK_MSG_STARTUP) {
        pg_session_startup(p, c, pc, m); /* StartupMessage / Cancel / SSL (3.2) */
        return;
    }
    switch (m->type) {
    case 'Q': /* simple Query: open a unit (3.3) */
        pg_query_simple(pc, m);
        break;
    case 'p':
        /* PasswordMessage / SASL: the body is the password. It is never read
         * or copied — a security invariant, not an optimisation (Р16). */
        break;
    default:
        /* P/B/E/S extended (3.4); d/c/f COPY (3.5). */
        break;
    }
}

/* backend -> frontend (SEND on the server socket): R, S, Z, T, D, C, E, ... */
static void pg_backend_msg(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                           const struct lk_msg *m)
{
    switch (m->type) {
    case 'R': /* Authentication: AuthenticationOk -> session (3.2) */
        pg_session_auth(p, c, pc, m);
        break;
    case 'S': /* ParameterStatus: server_version label (3.2). The one-byte
               * SSL 'S' reply also lands here with an empty body — parsed as an
               * empty ParameterStatus, i.e. harmlessly ignored. */
        pg_session_param_status(pc, m);
        break;
    case 'D': /* DataRow: first-row timing (3.3) */
        pg_query_data_row(pc, m);
        break;
    case 'C': /* CommandComplete: rows + statement count (3.3) */
        pg_query_complete(p, pc, m);
        break;
    case 'I': /* EmptyQueryResponse: an empty statement (3.3) */
        pg_query_empty(pc, m);
        break;
    case 'E': /* ErrorResponse: SQLSTATE onto the open unit (3.3) */
        pg_query_error(pc, m);
        break;
    case 'Z': /* ReadyForQuery: close the unit, track the transaction (3.3) */
        pg_query_ready(p, c, pc, m);
        break;
    default:
        /* RowDescription 'T' and the other noise types are counted and skipped
         * (Р18); COPY responses arrive with task 3.5. */
        break;
    }
}

/* --- lk_msg_sink implementation (down contract) --------------------------- */

static void pg_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct lk_proto *p = ctx;
    struct pg_conn *pc = pg_conn_get(p, c);

    p->st.msgs++;
    if (m->flags & LK_MSG_STARTUP)
        p->st.startup_msgs++;
    /* type is 0 for startup framing; index it at [dir][0] so the tally is
     * complete without a special case. */
    p->st.by_type[dir][(__u8)m->type]++;

    if (!pc)
        return; /* alloc failed: keep counting, skip semantics */
    pc->msgs++;
    if (dir == LK_DIR_RECV)
        pg_frontend_msg(p, c, pc, m);
    else
        pg_backend_msg(p, c, pc, m);
}

static void pg_on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    struct lk_proto *p = ctx;
    struct pg_conn *pc = pg_conn_get(p, c);

    (void)dir;
    p->st.resyncs++;
    if (!pc)
        return; /* alloc failed: keep counting, skip semantics */
    /* The stream broke here (Р19): drop an in-flight unit — an observation must
     * never span a gap — and go READY-degraded until the next clean Z. Fires
     * once per direction; the second call finds nothing to drop. The
     * transaction state is abandoned too (set unknown), so no on_txn is ever
     * emitted across the break; the next Z re-establishes it. */
    pg_query_drop(pc, &p->st.units_dropped_resync);
    pc->degraded = true;
    pc->txn_status = 0;
}

/* Fired by the connection table on *every* removal path (CONN_CLOSE, LRU
 * eviction, idle sweep, teardown), routed here through the framer sink — the
 * one place proto_state is released (Р15). Idempotent and NULL-safe. */
static void pg_on_conn_close(void *ctx, struct lk_conn *c)
{
    struct lk_proto *p = ctx;
    struct pg_conn *pc = c->proto_state;

    if (pc) {
        /* A query still in flight when the connection dies is dropped, never
         * emitted: a request cut off by a disconnect is not an observation
         * (Р19, a known blind spot of the model). */
        pg_query_drop(pc, &p->st.units_dropped_close);
        free(pc->text);
    }
    free(c->proto_state);
    c->proto_state = NULL;
}

/* --- registry entry points ------------------------------------------------ */

struct lk_proto *lk_proto_pg_new(const struct lk_query_sink *out)
{
    struct lk_proto *p = calloc(1, sizeof(*p));

    if (!p)
        return NULL;
    if (out)
        p->out = *out;
    p->msink.ctx = p;
    p->msink.on_msg = pg_on_msg;
    p->msink.on_conn_close = pg_on_conn_close;
    p->msink.on_resync = pg_on_resync;
    /* on_conn_open unused: proto_state is allocated lazily on the first
     * message, so there is nothing to do at open time (Р15). */
    return p;
}

const struct lk_msg_sink *lk_proto_sink(struct lk_proto *p)
{
    return &p->msink;
}

const struct lk_proto_stats *lk_proto_stats(const struct lk_proto *p)
{
    return &p->st;
}

void lk_proto_free(struct lk_proto *p)
{
    free(p);
}
