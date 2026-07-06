// SPDX-License-Identifier: GPL-2.0
/* PostgreSQL prepared-statement cache (task 3.4, Р17). A per-connection LRU map
 * of {statement name -> SQL prefix} that gives extended-protocol Bind messages
 * their text without re-reading Parse each time:
 *
 *   Parse ('P')          caches name -> query; the unnamed statement ("") is
 *                        overwritten by every Parse, a named one replaces its
 *                        previous text;
 *   Bind  ('B')          looks the name up (pg_query.c) — a hit points the unit
 *                        at this cache entry, a miss makes it NO_TEXT;
 *   Close ('C','S')      drops a named statement.
 *
 * The cache is a fixed array of LK_PG_PREP_CACHE slots, allocated lazily on the
 * first Parse (simple-only connections never pay for it). When it is full the
 * least-recently-used slot is evicted (bumping prep_evictions). Every slot has a
 * generation counter, bumped on reuse; a unit stores the generation it saw at
 * Bind, so a reference that missed its rescue is *detected* rather than
 * followed. Before any slot is reused (eviction, Close, re-Parse of a name), the
 * ring's live references to it are rescued into the units' own copies
 * (pg_query_rescue_refs) — the rare path Р17 accepts to keep the common Bind a
 * cheap reference, not a copy.
 *
 * Pure, no I/O: every wire field goes through the bounded pg_wire cursor (Р18),
 * so a truncated Parse simply caches the captured prefix (flagged trunc) and a
 * corrupt one caches nothing. */
#include "pg.h"

#include <stdlib.h>
#include <string.h>

#include "pg_wire.h"    /* bounded cursor (Р18) */
#include "reassembly.h" /* LK_MSG_BODY_MAX, LK_MSG_* flags */

/* Find an occupied slot whose name matches, or -1. The unnamed statement ("",
 * name_len 0) is a normal match — there is only ever one of it. */
static int find_by_name(struct pg_prep_cache *pc, const char *name, __u32 nlen)
{
    for (int i = 0; i < LK_PG_PREP_CACHE; i++) {
        struct pg_prep *e = &pc->e[i];

        if (e->used && e->name_len == nlen && (nlen == 0 || memcmp(e->name, name, nlen) == 0))
            return i;
    }
    return -1;
}

/* Write name + text into a slot, bumping its generation so stale unit
 * references become detectable. The name is truncated to the inline buffer
 * (over-long statement names — practically never — then fail future lookups and
 * fall back to NO_TEXT, an accepted edge); the text is capped at the framer's
 * prefix ceiling and its buffer is grown and kept across reuse. */
static void fill_slot(struct pg_prep *e, const char *name, __u32 nlen, const char *text, __u32 tlen,
                      bool trunc, __u64 lru)
{
    __u32 n = nlen < sizeof(e->name) - 1 ? nlen : (__u32)(sizeof(e->name) - 1);
    __u32 t = tlen < LK_MSG_BODY_MAX ? tlen : LK_MSG_BODY_MAX;

    e->used = true;
    e->trunc = trunc;
    e->gen++;
    e->lru = lru;

    if (n)
        memcpy(e->name, name, n);
    e->name[n] = '\0';
    e->name_len = (__u16)n;

    if (t > e->text_cap) {
        char *nb = realloc(e->text, t);

        if (!nb) {
            e->text_len = 0; /* OOM: the entry exists but is textless (NO_TEXT) */
            return;
        }
        e->text = nb;
        e->text_cap = t;
    }
    if (t)
        memcpy(e->text, text, t);
    e->text_len = t;
}

/* Pick a slot for a new/overwritten entry: reuse a free one, else evict the LRU.
 * Returns the slot index (always valid for a non-empty cache). */
static int pick_slot(struct lk_proto *p, struct pg_prep_cache *pc)
{
    int lru;

    for (int i = 0; i < LK_PG_PREP_CACHE; i++)
        if (!pc->e[i].used) {
            pc->count++;
            return i;
        }
    lru = 0;
    for (int i = 1; i < LK_PG_PREP_CACHE; i++)
        if (pc->e[i].lru < pc->e[lru].lru)
            lru = i;
    p->st.prep_evictions++;
    return lru; /* count unchanged: an occupied slot is replaced */
}

void pg_prep_parse(struct lk_proto *p, struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_wire w;
    const char *name, *query;
    __u32 nlen, qlen;
    bool have_query, trunc;
    int slot;

    /* Parse body: statement name (cstring), query (cstring), then the parameter
     * type OIDs — only the name and query text are cached. */
    pg_wire_init(&w, m->body, m->body_cap);
    if (!pg_wire_cstring(&w, &name, &nlen))
        return; /* the name itself was cut: cannot key an entry, skip caching */
    have_query = pg_wire_cstring(&w, &query, &qlen);
    /* !have_query means the body was truncated mid-query — query/qlen still
     * describe the captured prefix, so cache that much and flag it truncated. */
    trunc = !have_query || (m->flags & LK_MSG_BODY_TRUNC);

    if (!pc->prep) {
        pc->prep = calloc(1, sizeof(*pc->prep));
        if (!pc->prep)
            return; /* OOM: no cache — Bind on this name will be NO_TEXT */
    }
    slot = find_by_name(pc->prep, name, nlen);
    if (slot < 0)
        slot = pick_slot(p, pc->prep);
    /* Whether overwriting a name, evicting the LRU, or claiming a free slot,
     * rescue any live unit references before the slot's text changes. */
    pg_query_rescue_refs(pc, slot);
    fill_slot(&pc->prep->e[slot], name, nlen, query, qlen, trunc, ++pc->prep->clock);
}

void pg_prep_close(struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_wire w;
    __u8 kind;
    const char *name;
    __u32 nlen;
    int slot;
    struct pg_prep *e;

    /* Close body: a kind byte ('S' statement / 'P' portal) then the name. Only a
     * statement close touches the cache; a portal close is not a cache op. */
    pg_wire_init(&w, m->body, m->body_cap);
    if (!pg_wire_get_u8(&w, &kind) || kind != 'S')
        return;
    if (!pg_wire_cstring(&w, &name, &nlen) || !pc->prep)
        return;
    slot = find_by_name(pc->prep, name, nlen);
    if (slot < 0)
        return;

    pg_query_rescue_refs(pc, slot); /* keep the text of any unit still bound */
    e = &pc->prep->e[slot];
    e->used = false;
    e->gen++; /* invalidate references; the text buffer is kept for reuse */
    e->name_len = 0;
    e->name[0] = '\0';
    e->text_len = 0;
    pc->prep->count--;
}

int pg_prep_lookup(struct pg_conn *pc, const char *name, __u32 name_len, __u32 *gen, bool *trunc)
{
    int slot;
    struct pg_prep *e;

    if (!pc->prep)
        return -1;
    slot = find_by_name(pc->prep, name, name_len);
    if (slot < 0)
        return -1;
    e = &pc->prep->e[slot];
    e->lru = ++pc->prep->clock; /* touch: a Bind is a use */
    *gen = e->gen;
    *trunc = e->trunc;
    return slot;
}

void pg_prep_free(struct pg_conn *pc)
{
    if (!pc->prep)
        return;
    for (int i = 0; i < LK_PG_PREP_CACHE; i++)
        free(pc->prep->e[i].text);
    free(pc->prep);
    pc->prep = NULL;
}
