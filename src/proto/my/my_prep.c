// SPDX-License-Identifier: GPL-2.0
/* MySQL prepared-statement cache (MYSQL.md М3): the pg_prep design (Р17)
 * transplanted to a u32 key — the server assigns the statement id, so the
 * text is remembered at COM_STMT_PREPARE and bound to its stmt_id only when
 * COM_STMT_PREPARE_OK answers (strict request -> response makes the pending
 * text unambiguous):
 *
 *   COM_STMT_PREPARE      stash the SQL text (pending), open no unit;
 *   COM_STMT_PREPARE_OK   bind pending -> stmt_id; num_params + num_columns
 *                         tell the reply machine how many metadata packets to
 *                         skip (my_query.c MY_R_PREP_META);
 *   COM_STMT_EXECUTE      looks the id up (my_query.c) — a hit points the
 *                         unit at the entry, a miss makes it NO_TEXT;
 *   COM_STMT_CLOSE        drops the id; NO server reply — waiting for one
 *                         would shift every following latency by an exchange;
 *   COM_RESET_CONNECTION / COM_CHANGE_USER  drop the whole cache (the server
 *                         forgets the statements).
 *
 * Slots carry generations, bumped on reuse; the live unit's reference is
 * rescued into its own copy before any slot changes (my_query_rescue_ref) —
 * the same rare-path economy as PG. Pure, no I/O; every field goes through
 * the bounded my_wire cursor (Р18). */
#include "my.h"

#include <stdlib.h>
#include <string.h>

#include "my_wire.h"
#include "reassembly.h" /* LK_MSG_BODY_MAX, LK_MSG_* flags */

static int find_by_id(struct my_prep_cache *pc, __u32 stmt_id)
{
    for (int i = 0; i < LK_MY_PREP_CACHE; i++)
        if (pc->e[i].used && pc->e[i].stmt_id == stmt_id)
            return i;
    return -1;
}

/* Pick a slot for a new entry: a free one, else evict the LRU. */
static int pick_slot(struct lk_proto *p, struct my_prep_cache *pc)
{
    int lru;

    for (int i = 0; i < LK_MY_PREP_CACHE; i++)
        if (!pc->e[i].used) {
            pc->count++;
            return i;
        }
    lru = 0;
    for (int i = 1; i < LK_MY_PREP_CACHE; i++)
        if (pc->e[i].lru < pc->e[lru].lru)
            lru = i;
    p->st.prep_evictions++;
    return lru; /* count unchanged: an occupied slot is replaced */
}

/* COM_STMT_PREPARE: the SQL text is the whole body past the command byte.
 * Stash it as pending — PREPARE-OK supplies the key. */
void my_prep_prepare(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m)
{
    __u32 n = m->body_cap > 1 ? m->body_cap - 1 : 0;

    (void)p;
    pc->reply = MY_R_PREPARE_OK;
    pc->pending_prep = true;
    pc->pending_trunc = (m->flags & LK_MSG_BODY_TRUNC) != 0;
    if (n > LK_MSG_BODY_MAX)
        n = LK_MSG_BODY_MAX;
    if (n > pc->pending_cap) {
        char *nb = realloc(pc->pending_text, n);

        if (!nb) {
            pc->pending_len = 0; /* OOM: the entry will be textless */
            return;
        }
        pc->pending_text = nb;
        pc->pending_cap = n;
    }
    if (n)
        memcpy(pc->pending_text, m->body + 1, n);
    pc->pending_len = n;
}

/* COM_STMT_PREPARE_OK (or the ERR of a failed prepare), routed here by the
 * reply machine: 0x00, stmt_id u32, num_columns u16, num_params u16. */
void my_prep_ok(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m)
{
    struct my_wire w;
    __u32 stmt_id;
    __u16 ncols, nparams;
    __u8 head;
    int slot;
    struct my_prep *e;

    pc->reply = MY_R_NONE;
    my_wire_init(&w, m->body, m->body_cap);
    if (!my_wire_get_u8(&w, &head))
        return;
    if (head != 0x00) {
        pc->pending_prep = false; /* ERR (or noise): the statement never got
                                   * an id — the pending text is discarded */
        return;
    }
    if (!my_wire_get_u32(&w, &stmt_id) || !my_wire_get_u16(&w, &ncols) ||
        !my_wire_get_u16(&w, &nparams)) {
        /* The fixed 9-byte header is cut: without the id the text cannot be
         * keyed, and without the counts the metadata cannot be skipped —
         * corrupt on a full body, capture loss otherwise. */
        if (!(m->flags & LK_MSG_BODY_TRUNC))
            p->st.parse_errors++;
        pc->pending_prep = false;
        return;
    }
    pc->meta_left = (__u32)ncols + nparams;
    if (pc->meta_left)
        pc->reply = MY_R_PREP_META;

    if (!pc->pending_prep)
        return; /* PREPARE not seen (resync): nothing to cache */
    pc->pending_prep = false;
    if (!pc->prep) {
        pc->prep = calloc(1, sizeof(*pc->prep));
        if (!pc->prep)
            return; /* OOM: EXECUTE on this id will be NO_TEXT */
    }
    /* The server reuses ids after CLOSE: a re-appearing id replaces its
     * slot's text (rescuing a live unit reference first). */
    slot = find_by_id(pc->prep, stmt_id);
    if (slot < 0)
        slot = pick_slot(p, pc->prep);
    my_query_rescue_ref(pc, slot);

    e = &pc->prep->e[slot];
    e->used = true;
    e->trunc = pc->pending_trunc;
    e->gen++;
    e->lru = ++pc->prep->clock;
    e->stmt_id = stmt_id;
    if (pc->pending_len > e->text_cap) {
        char *nb = realloc(e->text, pc->pending_len);

        if (!nb) {
            e->text_len = 0; /* OOM: the entry exists but is textless */
            return;
        }
        e->text = nb;
        e->text_cap = pc->pending_len;
    }
    if (pc->pending_len)
        memcpy(e->text, pc->pending_text, pc->pending_len);
    e->text_len = pc->pending_len;
}

/* COM_STMT_CLOSE: stmt_id u32 after the command byte; no server reply. */
void my_prep_close(struct my_conn *pc, const struct lk_msg *m)
{
    struct my_wire w;
    __u32 stmt_id;
    int slot;
    struct my_prep *e;

    my_wire_init(&w, m->body, m->body_cap);
    if (!my_wire_skip(&w, 1) || !my_wire_get_u32(&w, &stmt_id) || !pc->prep)
        return;
    slot = find_by_id(pc->prep, stmt_id);
    if (slot < 0)
        return;
    my_query_rescue_ref(pc, slot); /* keep the text of a unit still bound */
    e = &pc->prep->e[slot];
    e->used = false;
    e->gen++; /* invalidate references; the text buffer is kept for reuse */
    e->text_len = 0;
    pc->prep->count--;
}

int my_prep_lookup(struct my_conn *pc, __u32 stmt_id, __u32 *gen, bool *trunc)
{
    int slot;
    struct my_prep *e;

    if (!pc->prep)
        return -1;
    slot = find_by_id(pc->prep, stmt_id);
    if (slot < 0)
        return -1;
    e = &pc->prep->e[slot];
    e->lru = ++pc->prep->clock; /* touch: an EXECUTE is a use */
    *gen = e->gen;
    *trunc = e->trunc;
    return slot;
}

/* COM_RESET_CONNECTION / COM_CHANGE_USER: the server forgets every prepared
 * statement of the session. Rescue the live reference, empty the cache. */
void my_prep_drop_all(struct my_conn *pc)
{
    if (!pc->prep)
        return;
    for (int i = 0; i < LK_MY_PREP_CACHE; i++) {
        struct my_prep *e = &pc->prep->e[i];

        if (!e->used)
            continue;
        my_query_rescue_ref(pc, i);
        e->used = false;
        e->gen++;
        e->text_len = 0;
    }
    pc->prep->count = 0;
}

void my_prep_free(struct my_conn *pc)
{
    if (!pc->prep)
        return;
    for (int i = 0; i < LK_MY_PREP_CACHE; i++)
        free(pc->prep->e[i].text);
    free(pc->prep);
    pc->prep = NULL;
}
