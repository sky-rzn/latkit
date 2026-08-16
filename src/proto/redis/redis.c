// SPDX-License-Identifier: GPL-2.0
/* Redis handler (PLAN-REDIS.md МR1) — the message consumer of the stream framer
 * in redis_frame.c, in the shape of pg.c / my.c / http.c: it owns the
 * per-connection state behind lk_conn.proto_state, tallies messages by
 * (direction, type), and turns the framer's '?' notes into the counters that
 * make a degradation visible.
 *
 * МR1 stops at the tally, exactly as PLAN-HTTP.md М1 did. The in-flight unit
 * queue, the pub/sub rule and the four timings (РR3, РR8) are МR2's; the command
 * table, the database and the ACL user (РR4–РR6) are МR3's; so this handler
 * emits no lk_query_obs at all. It exists to close the registry entry (every
 * protocol needs a proto_new), to make the per-protocol stats line real, to give
 * the МR1 acceptance criterion — parse_errors == 0 over the clean МR0 traces —
 * something to measure, and to pin the state lifecycle: proto_state is released
 * here on every removal path, exactly as Р15 requires, while the framer's
 * frame_state is released by the connection table (one flat allocation, see
 * conn_table.h).
 *
 * No I/O, no libbpf: a pure state machine, fed synthetic lk_msg by unit tests
 * and .lkt traces by the replay harness. */
#include <stdlib.h>

#include "redis.h"

/* Lazily attach per-connection state on the first message (Р15). NULL only on
 * allocation failure — the caller degrades to counting, never crashes. */
static struct redis_conn *redis_conn_get(struct lk_proto *p, struct lk_conn *c)
{
    struct redis_conn *rc = c->proto_state;

    if (rc)
        return rc;
    rc = calloc(1, sizeof(*rc));
    if (!rc)
        return NULL;
    /* A synthetic or lazily created entry joined an established connection: its
     * `SELECT` and its `AUTH` happened before we were watching, so its database
     * and user are unknowable (РR5 — `db="?"`, not `db="0"`) and no value on it
     * is a trustworthy unit boundary until the framer vouches for one. */
    rc->degraded = (c->flags & LK_CONN_SYNTHETIC) != 0;
    c->proto_state = rc;
    p->st.conns++;
    return rc;
}

/* The framer's notes (РR2): the only channel a stream framer has to report a
 * degradation, and it is the message stream itself. Split by what the note
 * says about *whose* fault it was — a corrupt length is the input's and belongs
 * in latkit_parse_errors_total, a capture hole is the budget's and does not. */
static void framer_note(struct lk_proto *p, const struct lk_msg *m)
{
    if (LK_REDIS_NOTE_IS_PARSE_ERR(m->len))
        p->st.parse_errors++;
}

static void redis_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct lk_proto *p = ctx;
    struct redis_conn *rc = redis_conn_get(p, c);

    p->st.msgs++;
    p->st.by_type[dir][(__u8)m->type]++;
    if (m->type == LK_REDIS_MSG_NOTE) {
        /* Counted whatever the state of the connection: a note is the framer's
         * own report about itself, and dropping it because an allocation failed
         * would hide the very failure it is reporting. */
        framer_note(p, m);
        return;
    }
    if (!rc)
        return; /* alloc failed: keep counting, skip semantics */
    rc->msgs++;
    /* МR2: open a unit on a frontend value, close the oldest on a backend one,
     * and recognise the pushes that close nothing (РR3, РR8). */
}

static void redis_on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    struct lk_proto *p = ctx;
    struct redis_conn *rc = redis_conn_get(p, c);

    (void)dir;
    p->st.resyncs++;
    if (!rc)
        return;
    /* The stream broke: whatever was in flight cannot be completed honestly.
     * МR2 drops the in-flight units into units_dropped_resync here; МR1 only
     * records that this connection is no longer at a known boundary. */
    rc->degraded = true;
}

/* Fired by the connection table on *every* removal path (CONN_CLOSE, LRU
 * eviction, idle sweep, teardown), routed here through the framer sink — the
 * one place proto_state is released (Р15). Idempotent and NULL-safe. */
static void redis_on_conn_close(void *ctx, struct lk_conn *c)
{
    (void)ctx;
    free(c->proto_state);
    c->proto_state = NULL;
}

/* --- registry entry point ------------------------------------------------- */

struct lk_proto *lk_proto_redis_new(const struct lk_query_sink *out)
{
    struct lk_proto *p = calloc(1, sizeof(*p));

    if (!p)
        return NULL;
    p->msink.ctx = p;
    p->msink.on_msg = redis_on_msg;
    p->msink.on_resync = redis_on_resync;
    p->msink.on_conn_close = redis_on_conn_close;
    if (out)
        p->out = *out;
    return p;
}
