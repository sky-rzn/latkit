// SPDX-License-Identifier: GPL-2.0
/* MySQL classic-protocol handler (MYSQL.md М3, РМ8) — the real parser behind
 * lk_proto_my_new, replacing the М2 counting stub. Owns the per-connection
 * state through lk_conn.proto_state, tallies messages by (direction, type),
 * and dispatches by (direction, phase, command byte / reply state).
 *
 * The framer (my_frame.c) hands over glued logical packets: lk_msg.type is
 * the command byte for frontend packets that opened a command (wire seq 0),
 * 0 for everything else; body[0] is always the first payload byte. Server
 * packets carry no type — my_query.c classifies them by the reply state.
 *
 * No I/O, no libbpf: a pure state machine fed synthetic lk_msg by unit tests
 * and .lkt traces by the replay harness. */
#include "my.h"

#include <stdlib.h>

#include "reassembly.h" /* LK_MSG_* flags */

/* Lazily attach per-connection state on the first message (Р15). NULL only on
 * allocation failure — the caller degrades to counting, never crashes. */
static struct my_conn *my_conn_get(struct lk_proto *p, struct lk_conn *c)
{
    struct my_conn *pc = c->proto_state;

    if (pc)
        return pc;
    pc = calloc(1, sizeof(*pc));
    if (!pc)
        return NULL;
    pc->u.prep_idx = -1;
    /* A synthetic / mid-session entry never sees the handshake: no labels, no
     * caps (length heuristics classify terminators). Unlike PG there is no
     * READY-degraded stretch — the frontend resync anchor *is* a command
     * boundary (РМ4), so the first command opens an honest unit. */
    if (c->flags & LK_CONN_SYNTHETIC) {
        pc->phase = MY_PH_READY;
        pc->sess = MY_S_DONE;
    }
    c->proto_state = pc;
    p->st.conns++;
    return pc;
}

/* --- frontend: client -> server (RECV on the server socket) ---------------- */

static void my_frontend_msg(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                            const struct lk_msg *m)
{
    __u8 cmd;

    if (pc->phase == MY_PH_IGNORE)
        return; /* binlog / compressed: no observations, just the by_type tally */
    if (pc->phase == MY_PH_HANDSHAKE) {
        /* Untyped packets are the handshake / auth exchange itself. A typed
         * packet (a seq-0 command) while the handler still waits for the
         * exchange's tail means that tail fell into a hole and the framer
         * already forced the command phase — catch up (salvaging the session
         * if the HandshakeResponse was seen) and dispatch the command below. */
        if (m->type == 0) {
            my_session_frontend(p, c, pc, m);
            return;
        }
        my_session_promote(p, c, pc);
    }
    if (pc->phase == MY_PH_INFILE) {
        if (m->type == 0) {
            my_query_infile_data(pc, m); /* LOAD DATA LOCAL: raw data packets */
            return;
        }
        pc->phase = MY_PH_READY; /* a command: the final OK fell into a hole */
    }
    if (m->type == 0) {
        p->st.unknown_msgs++; /* a continuation-seq packet outside INFILE/auth */
        return;
    }

    cmd = (__u8)m->type;
    /* Commands with no server reply may be pipelined behind another exchange
     * (fire-and-forget statement close) — they say nothing about the pending
     * reply's health and skip the anchor discipline below. */
    switch (cmd) {
    case MY_COM_STMT_CLOSE: /* drop from the cache; NO server reply */
        my_prep_close(pc, m);
        return;
    case MY_COM_QUIT:                /* no reply, socket closes */
    case MY_COM_STMT_SEND_LONG_DATA: /* no reply */
        return;
    }

    /* Frontend-anchor discipline (РМ4): the protocol is strictly request ->
     * response, so a new command while a reply is still open means that
     * reply's tail fell into a capture hole — the open unit is dropped, never
     * emitted, and the pending-reply state resets. */
    if (pc->unit_open)
        my_query_drop_unit(pc, &p->st.units_dropped_resync);
    pc->reply = MY_R_NONE;
    pc->have_pending_db = false;
    pc->pending_prep = false;

    switch (cmd) {
    case MY_COM_QUERY: /* open a SIMPLE unit; text after the attribute header */
        my_query_simple(p, pc, m);
        break;
    case MY_COM_STMT_PREPARE: /* cache candidate: text now, stmt_id on OK */
        my_prep_prepare(p, pc, m);
        break;
    case MY_COM_STMT_EXECUTE: /* open an EXTENDED unit, text from the cache */
    case MY_COM_MARIADB_BULK: /* same header shape: stmt_id right after cmd */
        my_query_execute(p, pc, m);
        break;
    case MY_COM_STMT_FETCH: /* cursor continuation: rows arrive directly */
        my_query_fetch(p, pc, m);
        break;
    case MY_COM_INIT_DB: /* db label staged, committed on the OK */
        my_session_init_db(pc, m);
        pc->reply = MY_R_HEAD;
        break;
    case MY_COM_CHANGE_USER: /* re-enters an auth cycle (my_session.c) */
        my_session_change_user(p, pc, m);
        break;
    case MY_COM_BINLOG_DUMP: /* replication -> deliberate blind zone (РМ8) */
    case MY_COM_BINLOG_DUMP_GTID:
        my_query_drop_unit(pc, NULL);
        pc->phase = MY_PH_IGNORE;
        c->flags |= LK_CONN_IGNORE; /* framer discards; capture -> HEADERS */
        p->st.replication_conns++;
        break;
    case MY_COM_STATISTICS: /* replies one bare string packet — not OK/ERR */
        pc->reply = MY_R_STRING;
        break;
    case MY_COM_FIELD_LIST: /* deprecated: column defs until EOF */
        pc->reply = MY_R_FIELD_LIST;
        break;
    case MY_COM_RESET_CONNECTION: /* server forgets prepared statements */
        my_prep_drop_all(pc);
        pc->reply = MY_R_HEAD;
        break;
    case MY_COM_PING: /* service commands: consume the OK/ERR (or resultset,
                       * COM_PROCESS_INFO), observe nothing — by_type only */
    case MY_COM_DEBUG:
    case MY_COM_PROCESS_INFO:
    case MY_COM_SET_OPTION:
    case MY_COM_STMT_RESET:
    case MY_COM_REGISTER_SLAVE:
        pc->reply = MY_R_HEAD;
        break;
    default:
        /* Unknown command (Р18 analogue): count it and expect nothing — if a
         * reply does come it lands in MY_R_NONE and is ignored; the next
         * command resets cleanly either way. */
        p->st.unknown_msgs++;
        break;
    }
}

/* --- backend: server -> client (SEND on the server socket) ----------------- */

static void my_backend_msg(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                           const struct lk_msg *m)
{
    if (pc->phase == MY_PH_IGNORE)
        return;
    if (pc->phase == MY_PH_HANDSHAKE) {
        /* Greeting / auth exchange, and the COM_CHANGE_USER re-auth cycle
         * (unflagged — the handler's own state routes it). A lost handshake
         * tail resolves on the frontend side: the command that precedes any
         * reply promotes the phase, so by reply time READY is set. */
        my_session_backend(p, c, pc, m);
        return;
    }
    my_query_backend(p, c, pc, m);
}

/* --- lk_msg_sink implementation (down contract) ---------------------------- */

static void my_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct lk_proto *p = ctx;
    struct my_conn *pc = my_conn_get(p, c);

    p->st.msgs++;
    if (m->flags & LK_MSG_STARTUP)
        p->st.startup_msgs++;
    /* type is the command byte for seq-0 frontend packets, 0 otherwise —
     * indexed at [dir][0] so the tally is complete without a special case. */
    p->st.by_type[dir][(__u8)m->type]++;

    if (!pc)
        return; /* alloc failed: keep counting, skip semantics */
    if (dir == LK_DIR_RECV)
        my_frontend_msg(p, c, pc, m);
    else
        my_backend_msg(p, c, pc, m);
    pc->msgs++;
}

static void my_on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    struct lk_proto *p = ctx;
    struct my_conn *pc = my_conn_get(p, c);

    (void)dir;
    p->st.resyncs++;
    if (!pc)
        return;
    /* The stream broke (Р19): the in-flight unit is dropped — an observation
     * must never span a gap — and every sub-state of the broken exchange is
     * abandoned. The transaction state is unknown until the next terminator.
     * IGNORE survives (that connection never emits again); a handshake cut by
     * the break re-enters through the frontend command anchor (РМ4), which
     * promotes the phase on arrival. */
    my_query_drop_unit(pc, &p->st.units_dropped_resync);
    pc->reply = MY_R_NONE;
    pc->have_pending_db = false;
    pc->have_pending_user = false;
    pc->pending_prep = false;
    pc->txn_status = 0;
    if (pc->phase == MY_PH_INFILE)
        pc->phase = MY_PH_READY;
}

/* Fired by the connection table on *every* removal path (CONN_CLOSE, LRU
 * eviction, idle sweep, teardown) — the one place proto_state is released
 * (Р15). Idempotent and NULL-safe. */
static void my_on_conn_close(void *ctx, struct lk_conn *c)
{
    struct lk_proto *p = ctx;
    struct my_conn *pc = c->proto_state;

    if (pc) {
        /* A query still in flight when the connection dies is dropped, never
         * emitted (Р19): a request cut off by a disconnect is not an
         * observation. */
        my_query_drop_unit(pc, &p->st.units_dropped_close);
        free(pc->u.own_text);
        free(pc->pending_text);
        my_prep_free(pc);
    }
    free(c->proto_state);
    c->proto_state = NULL;
}

/* --- registry entry point -------------------------------------------------- */

struct lk_proto *lk_proto_my_new(const struct lk_query_sink *out)
{
    struct lk_proto *p = calloc(1, sizeof(*p));

    if (!p)
        return NULL;
    if (out)
        p->out = *out;
    p->msink.ctx = p;
    p->msink.on_msg = my_on_msg;
    p->msink.on_conn_close = my_on_conn_close;
    p->msink.on_resync = my_on_resync;
    /* on_conn_open unused: proto_state is allocated lazily (Р15). */
    return p;
}
