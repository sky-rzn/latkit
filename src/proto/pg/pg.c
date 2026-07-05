// SPDX-License-Identifier: GPL-2.0
/* PostgreSQL v3 handler (STAGE3.md). Task 3.1 is the skeleton: it owns the
 * per-connection parser state through lk_conn.proto_state, mirrors the
 * lk_msg_sink contract, tallies messages by (direction, type), and routes each
 * message to a per-direction stub. The stubs — and the observations they will
 * emit up through lk_query_sink — fill in over tasks 3.2-3.5.
 *
 * No I/O, no libbpf: a pure state machine fed synthetic lk_msg by unit tests
 * and .lkt fixtures by the replay harness. */
#include "pg.h"

#include <stdlib.h>
#include <string.h>

#include "pg_wire.h" /* task 3.1 deliverable; used from 3.2 on */

struct lk_proto {
    struct lk_msg_sink msink; /* down: installed as the framer's sink */
    struct lk_query_sink out; /* up: borrowed from the assembler */
    struct lk_proto_stats st;
};

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
     * mid-session entry joins in READY-degraded (Р19, refined in task 3.5). */
    pc->phase = (c->flags & LK_CONN_SYNTHETIC) ? PG_PH_READY : PG_PH_STARTUP;
    c->proto_state = pc;
    p->st.conns++;
    return pc;
}

/* --- per-direction dispatch stubs (grow in 3.2-3.5) ----------------------- */

/* frontend -> backend (RECV on the server socket): Q, P, B, E, S, X, ... */
static void pg_frontend_msg(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                            const struct lk_msg *m)
{
    (void)p;
    (void)c;
    (void)pc;
    (void)m;
    /* task 3.2: startup/session; 3.3: simple query; 3.4: extended. */
}

/* backend -> frontend (SEND on the server socket): R, Z, T, D, C, E, ... */
static void pg_backend_msg(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                           const struct lk_msg *m)
{
    (void)p;
    (void)c;
    (void)pc;
    (void)m;
    /* task 3.3: rows/CommandComplete/errors/txn; 3.5: COPY/replication. */
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

    (void)c;
    (void)dir;
    p->st.resyncs++;
    /* task 3.5: drop the in-flight queue, go READY-degraded (Р19). */
}

/* Fired by the connection table on *every* removal path (CONN_CLOSE, LRU
 * eviction, idle sweep, teardown), routed here through the framer sink — the
 * one place proto_state is released (Р15). Idempotent and NULL-safe. */
static void pg_on_conn_close(void *ctx, struct lk_conn *c)
{
    (void)ctx;
    /* task 3.5: drop a non-empty in-flight queue (units_dropped_close) before
     * freeing; the skeleton has no queue yet. */
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
