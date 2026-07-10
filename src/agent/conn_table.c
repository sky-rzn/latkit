// SPDX-License-Identifier: GPL-2.0
#include "conn_table.h"

#include <stdlib.h>
#include <string.h>

struct lk_conn_table {
    struct lk_conn **bucket;
    __u32 nbuckets; /* power of two */
    __u32 max_conns;
    __u64 idle_timeout_ns;
    /* LRU list: head = most recently touched, tail = eviction candidate. */
    struct lk_conn *lru_head, *lru_tail;
    /* Fired for every entry removal, before the memory is freed (Р15): the
     * protocol handler frees lk_conn.proto_state here on all paths. */
    void (*on_destroy)(void *ctx, struct lk_conn *c);
    void *on_destroy_ctx;
    struct lk_conn_table_stats st;
};

static struct lk_conn **hash_bucket(struct lk_conn_table *t, __u64 cookie)
{
    /* Fibonacci hash: cookies are sequential, spread them. */
    return &t->bucket[(cookie * 0x9E3779B97F4A7C15ULL) >> 32 & (t->nbuckets - 1)];
}

static void lru_unlink(struct lk_conn_table *t, struct lk_conn *c)
{
    if (c->lru_prev)
        c->lru_prev->lru_next = c->lru_next;
    else
        t->lru_head = c->lru_next;
    if (c->lru_next)
        c->lru_next->lru_prev = c->lru_prev;
    else
        t->lru_tail = c->lru_prev;
    c->lru_prev = c->lru_next = NULL;
}

static void lru_push_front(struct lk_conn_table *t, struct lk_conn *c)
{
    c->lru_prev = NULL;
    c->lru_next = t->lru_head;
    if (t->lru_head)
        t->lru_head->lru_prev = c;
    t->lru_head = c;
    if (!t->lru_tail)
        t->lru_tail = c;
}

static struct lk_conn *lookup(struct lk_conn_table *t, __u64 cookie)
{
    struct lk_conn *c;

    for (c = *hash_bucket(t, cookie); c; c = c->hnext)
        if (c->cookie == cookie)
            return c;
    return NULL;
}

/* Unlink from the hash chain and the LRU list, free the framer buffers
 * (partial messages die with the entry) and the entry itself. */
static void destroy(struct lk_conn_table *t, struct lk_conn *c)
{
    struct lk_conn **slot;

    /* Release protocol state while the entry is still whole (Р15). This is the
     * single choke point for CONN_CLOSE, LRU eviction, the idle sweep and
     * teardown, so the hook covers all removal paths by construction. */
    if (t->on_destroy)
        t->on_destroy(t->on_destroy_ctx, c);
    for (slot = hash_bucket(t, c->cookie); *slot != c; slot = &(*slot)->hnext)
        ;
    *slot = c->hnext;
    lru_unlink(t, c);
    if (c->flags & LK_CONN_TLS)
        t->st.tls_active--; /* mirrors the ++ at the TLS flip (Р41) */
    free(c->frame[0].buf);
    free(c->frame[1].buf);
    free(c);
    t->st.active--;
}

static void mark_dirty(struct lk_conn *c)
{
    for (int i = 0; i < 2; i++) {
        c->frame[i].st = LK_FR_DIRTY;
        c->frame[i].resync_matched = 0; /* the resync scan starts fresh */
    }
}

/* Seq-hole check + activity bookkeeping, common to every event. */
static void touch(struct lk_conn_table *t, struct lk_conn *c, __u32 seq, __u64 ts_ns, __u32 *lost)
{
    if (seq > c->last_seq + 1) {
        *lost = seq - (c->last_seq + 1);
        c->dropped += *lost;
        t->st.seq_gaps++;
        t->st.lost_events += *lost;
        mark_dirty(c); /* seq is per-connection: both directions (Р9) */
    }
    if (seq > c->last_seq)
        c->last_seq = seq;
    c->last_activity_ns = ts_ns;
    lru_unlink(t, c);
    lru_push_front(t, c);
}

static struct lk_conn *create(struct lk_conn_table *t, __u64 cookie, __u32 seq, __u64 ts_ns)
{
    struct lk_conn **slot, *c;

    /* Ceiling: recycle the coldest entry. If it was still alive, its traffic
     * will lazily re-create it as dirty — data survives, metrics stay honest. */
    if (t->st.active >= t->max_conns && t->lru_tail) {
        destroy(t, t->lru_tail);
        t->st.evicted_lru++;
    }

    c = calloc(1, sizeof(*c));
    if (!c)
        return NULL; /* degrade to no tracking, not to exit */
    c->cookie = cookie;
    c->last_seq = seq;
    c->last_activity_ns = ts_ns;
    slot = hash_bucket(t, cookie);
    c->hnext = *slot;
    *slot = c;
    lru_push_front(t, c);
    t->st.created++;
    t->st.active++;
    return c;
}

struct lk_conn *lk_conn_table_open(struct lk_conn_table *t, __u64 cookie, __u32 seq, __u64 ts_ns,
                                   const struct lk_tuple *tuple, bool synthetic, __u32 *lost)
{
    struct lk_conn *c = lookup(t, cookie);

    *lost = 0;
    if (c) {
        /* Duplicate OPEN (should not happen; tolerate): just an activity. */
        touch(t, c, seq, ts_ns, lost);
        return c;
    }
    c = create(t, cookie, seq, ts_ns);
    if (!c)
        return NULL;
    c->tuple = *tuple;
    if (synthetic) {
        c->flags |= LK_CONN_SYNTHETIC;
        /* Startup was not seen: framing can only enter via resync (Р10). */
        mark_dirty(c);
    }
    return c;
}

struct lk_conn *lk_conn_table_data(struct lk_conn_table *t, __u64 cookie, __u32 seq, __u64 ts_ns,
                                   __u32 *lost)
{
    struct lk_conn *c = lookup(t, cookie);

    *lost = 0;
    if (c) {
        touch(t, c, seq, ts_ns, lost);
        return c;
    }
    /* Unknown cookie: the entry was evicted here (or its OPEN lost) and the
     * kernel will not resend a synthetic OPEN — re-create as dirty, no
     * tuple. No baseline for the seq check, so no loss reported. */
    c = create(t, cookie, seq, ts_ns);
    if (!c)
        return NULL;
    mark_dirty(c);
    return c;
}

/* Decrypted-channel twin of touch(): the seq-hole detector on tls_last_seq. The
 * first event seeds the baseline (no baseline, no loss — as for a lazily created
 * raw entry); a genuine gap dirties both framer directions, because the framed
 * stream on a TLS connection *is* the decrypted one (Р38). */
static void touch_tls(struct lk_conn_table *t, struct lk_conn *c, __u32 seq, __u64 ts_ns,
                      __u32 *lost)
{
    if (!c->tls_seq_seen) {
        c->tls_seq_seen = 1;
        c->tls_last_seq = seq;
    } else if (seq > c->tls_last_seq + 1) {
        *lost = seq - (c->tls_last_seq + 1);
        c->tls_dropped += *lost;
        t->st.seq_gaps++;
        t->st.lost_events += *lost;
        mark_dirty(c);
    }
    if (seq > c->tls_last_seq)
        c->tls_last_seq = seq;
    c->last_activity_ns = ts_ns;
    lru_unlink(t, c);
    lru_push_front(t, c);
}

struct lk_conn *lk_conn_table_peek(struct lk_conn_table *t, __u64 cookie)
{
    return lookup(t, cookie);
}

struct lk_conn *lk_conn_table_data_decrypted(struct lk_conn_table *t, __u64 cookie, __u32 seq,
                                             __u64 ts_ns, __u32 *lost)
{
    struct lk_conn *c = lookup(t, cookie);

    *lost = 0;
    if (c) {
        touch_tls(t, c, seq, ts_ns, lost);
        return c;
    }
    /* Unknown cookie on the decrypted channel: the socket entry was evicted or
     * its OPEN was lost. Re-create dirty (no tuple, no raw baseline) and seed
     * the decrypted seq space from this event — the same degrade-not-exit
     * contract as lk_conn_table_data. */
    c = create(t, cookie, seq, ts_ns);
    if (!c)
        return NULL;
    c->tls_seq_seen = 1;
    c->tls_last_seq = seq;
    mark_dirty(c);
    return c;
}

void lk_conn_table_note_tls_drop(struct lk_conn_table *t)
{
    t->st.tls_socket_dropped++;
}

void lk_conn_table_note_tls_open(struct lk_conn_table *t)
{
    t->st.tls_opened++;
    t->st.tls_active++;
}

void lk_conn_tls_reset_framing(struct lk_conn *c)
{
    for (int i = 0; i < 2; i++) {
        free(c->frame[i].buf);
        /* Zeroing yields the startup state: st == LK_FR_HEADER, startup_done ==
         * 0, no partial message — RECV re-enters startup framing for the real
         * StartupMessage, SEND stays in normal framing (Р36). */
        memset(&c->frame[i], 0, sizeof(c->frame[i]));
    }
}

void lk_conn_table_close(struct lk_conn_table *t, __u64 cookie, __u32 seq, __u64 ts_ns, __u32 *lost)
{
    struct lk_conn *c = lookup(t, cookie);

    *lost = 0;
    if (!c)
        return;                    /* whole life predates the agent or was lost */
    touch(t, c, seq, ts_ns, lost); /* the gap check runs on CLOSE itself */
    destroy(t, c);
    t->st.closed++;
}

unsigned int lk_conn_table_sweep(struct lk_conn_table *t, __u64 now_ns)
{
    unsigned int evicted = 0;

    while (t->lru_tail && t->lru_tail->last_activity_ns + t->idle_timeout_ns <= now_ns) {
        destroy(t, t->lru_tail);
        t->st.evicted_idle++;
        evicted++;
    }
    return evicted;
}

const struct lk_conn_table_stats *lk_conn_table_stats(const struct lk_conn_table *t)
{
    return &t->st;
}

struct lk_conn_table *lk_conn_table_new(__u32 max_conns, __u64 idle_timeout_ns)
{
    struct lk_conn_table *t = calloc(1, sizeof(*t));

    if (!t)
        return NULL;
    t->max_conns = max_conns ? max_conns : 1;
    t->idle_timeout_ns = idle_timeout_ns;
    /* Aim at chains of ~16 (the seqtrack ratio); clamp to a sane minimum. */
    t->nbuckets = 64;
    while (t->nbuckets < t->max_conns / 16)
        t->nbuckets <<= 1;
    t->bucket = calloc(t->nbuckets, sizeof(*t->bucket));
    if (!t->bucket) {
        free(t);
        return NULL;
    }
    return t;
}

void lk_conn_table_on_destroy(struct lk_conn_table *t, void (*fn)(void *ctx, struct lk_conn *c),
                              void *ctx)
{
    t->on_destroy = fn;
    t->on_destroy_ctx = ctx;
}

void lk_conn_table_free(struct lk_conn_table *t)
{
    if (!t)
        return;
    while (t->lru_head)
        destroy(t, t->lru_head);
    free(t->bucket);
    free(t);
}
