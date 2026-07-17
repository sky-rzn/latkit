// SPDX-License-Identifier: GPL-2.0
/* Generic framer mechanics (Р9-Р11); the protocol-shaped parts — header
 * size/parse, startup framing, special transitions, resync anchors — come
 * from the connection's lk_proto_ops (РМ1, proto.h). A connection without
 * assigned ops frames as PG: the default protocol (РМ2), and what keeps the
 * pre-vtable unit tests and fixtures running unchanged. */
#include "reassembly.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "proto.h"

/* Resolve (and pin) the connection's protocol. The live path assigns ops at
 * entry creation (conn_table, РМ2); the fallback covers lazily created
 * entries with no tuple and bare unit-test connections. */
static const struct lk_proto_ops *conn_ops(struct lk_conn *c)
{
    if (!c->ops)
        c->ops = &lk_proto_pg_ops;
    return c->ops;
}

void lk_reasm_init(struct lk_reasm *r, const struct lk_msg_sink *sink)
{
    memset(r, 0, sizeof(*r)); /* pool_n = 0: empty freelist */
    if (sink)
        r->sink = *sink;
}

void lk_reasm_free(struct lk_reasm *r)
{
    while (r->pool_n)
        free(r->pool[--r->pool_n]);
}

/* Freelist for the body-prefix slabs (Р11): every slab is LK_MSG_BODY_MAX, so
 * any prefix fits and slabs are interchangeable. buf_get pops the pool or
 * mallocs (NULL on OOM — the caller degrades, it does not abort); buf_put
 * recycles it or, past the cap, hands it back to the allocator. The loop is
 * single-threaded, so no lock. */
static __u8 *buf_get(struct lk_reasm *r)
{
    if (r->pool_n)
        return r->pool[--r->pool_n];
    return malloc(LK_MSG_BODY_MAX);
}

static void buf_put(struct lk_reasm *r, __u8 *buf)
{
    if (!buf)
        return;
    if (r->pool_n < LK_REASM_POOL_MAX)
        r->pool[r->pool_n++] = buf;
    else
        free(buf);
}

/* Back to HEADER at a message boundary; the body-prefix slab is recycled to
 * the freelist here (Р11), so steady-state heap churn is ~0. */
static void msg_reset(struct lk_reasm *r, struct lk_frame *f)
{
    buf_put(r, f->buf);
    f->buf = NULL;
    f->buf_len = 0;
    f->hdr_len = 0;
    f->body_len = 0;
    f->st = LK_FR_HEADER;
}

/* Sync lost on this direction: drop the partial message and wait for a
 * resync anchor. Each cause has its own counter. */
static void go_dirty(struct lk_reasm *r, struct lk_frame *f, __u64 *counter)
{
    (*counter)++;
    msg_reset(r, f);
    f->skip_left = 0;
    f->resync_matched = 0;
    f->st = LK_FR_DIRTY;
}

/* Anchor found (Р10): back to framing at the next byte. startup_done is
 * forced — a resync means mid-session entry, startup is long past (this is
 * also how synthetic connections, born dirty, join the stream). The next
 * emitted message tells the consumer the context before it is lost. */
static void do_resync(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct lk_frame *f)
{
    msg_reset(r, f); /* conn-table dirtying leaves partial-message state behind */
    f->skip_left = 0;
    f->resync_matched = 0;
    f->after_resync = 1;
    f->startup_done = 1;
    r->st.resyncs++;
    if (r->sink.on_resync)
        r->sink.on_resync(r->sink.ctx, c, dir);
}

static void emit(struct lk_reasm *r, const struct lk_proto_ops *ops, struct lk_conn *c,
                 enum lk_dir dir, struct lk_frame *f, const __u8 *body, __u32 body_cap)
{
    struct lk_msg m = {
        .ts_ns = f->msg_ts,
        .type = (char)f->msg_type,
        .len = f->msg_len,
        .body_cap = body_cap,
        .body = body,
    };

    /* Protocol flags and body-dependent framing transitions (startup code,
     * SSL/Cancel) live in the vtable (РМ1). */
    ops->pre_emit(c, dir, f, &m);
    if (f->after_resync) {
        m.flags |= LK_MSG_AFTER_RESYNC;
        f->after_resync = 0;
    }
    if (body_cap < f->body_len) {
        m.flags |= LK_MSG_BODY_TRUNC;
        r->st.msgs_trunc++;
    }
    r->st.msgs++;
    if (r->sink.on_msg)
        r->sink.on_msg(r->sink.ctx, c, dir, &m);
}

/* Body prefix actually captured per message (Р11). */
static __u32 body_target(const struct lk_frame *f)
{
    return f->body_len < LK_MSG_BODY_MAX ? f->body_len : LK_MSG_BODY_MAX;
}

void lk_frame_bytes(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, const __u8 *p, __u32 n,
                    __u64 ts_ns)
{
    const struct lk_proto_ops *ops = conn_ops(c);
    struct lk_frame *f = &c->frame[dir];

    /* Cross-direction special bytes before framing (PG: the one-byte SSL
     * reply). false = the rest of the chunk is ciphertext, drop it. */
    if (ops->intercept_bytes && n > 0 && !ops->intercept_bytes(r, c, dir, &p, &n, ts_ns))
        return;

    while (n > 0) {
        switch (f->st) {
        case LK_FR_HEADER: {
            __u32 hdr_size = ops->hdr_size(c, dir, f);
            __u32 take = hdr_size - f->hdr_len;

            if (f->hdr_len == 0)
                f->msg_ts = ts_ns; /* first byte of the header (Р13) */
            if (take > n)
                take = n;
            memcpy(f->hdr + f->hdr_len, p, take);
            f->hdr_len += take;
            p += take;
            n -= take;
            if (f->hdr_len < hdr_size)
                return;
            if (!ops->parse_hdr(c, dir, f)) {
                go_dirty(r, f, &r->st.bad_len);
                return;
            }
            if (f->body_len == 0) { /* empty body: whole message was the header */
                emit(r, ops, c, dir, f, NULL, 0);
                msg_reset(r, f);
            } else {
                f->st = LK_FR_BODY;
            }
            break;
        }
        case LK_FR_BODY: {
            __u32 target = body_target(f);
            __u32 rem = target - f->buf_len;

            if (n < rem) {
                /* Prefix incomplete: spill into the lazy slab (recycled from
                 * the freelist, LK_MSG_BODY_MAX so any target fits). On OOM
                 * degrade to emitting what this chunk holds and skipping the
                 * rest — capture quality drops, framing stays in sync. */
                if (!f->buf)
                    f->buf = buf_get(r);
                if (f->buf) {
                    memcpy(f->buf + f->buf_len, p, n);
                    f->buf_len += n;
                    return;
                }
                rem = n;
                target = f->buf_len + n; /* buf_len == 0 when buf is NULL */
            }
            const __u8 *body = f->buf ? f->buf : p;
            __u64 skip = (__u64)f->body_len - target;

            if (f->buf)
                memcpy(f->buf + f->buf_len, p, rem);
            emit(r, ops, c, dir, f, body, target);
            p += rem;
            n -= rem;
            msg_reset(r, f);
            if (skip) {
                f->st = LK_FR_SKIP;
                f->skip_left = skip;
            }
            break;
        }
        case LK_FR_SKIP: {
            __u64 take = f->skip_left < n ? f->skip_left : n;

            p += take;
            n -= take;
            f->skip_left -= take;
            if (!f->skip_left)
                f->st = LK_FR_HEADER;
            break;
        }
        case LK_FR_DIRTY: {
            /* Anchor scan in the captured bytes (Р10) — the pattern and the
             * direction policy are the protocol's (PG: backend 'Z' scan,
             * frontend bytes discarded; its anchor is a call boundary,
             * checked in lk_reasm_data). Framing resumes at the byte after
             * the anchor. */
            bool found = false;
            __u32 used = ops->resync_scan(c, dir, f, p, n, &found);

            p += used;
            n -= used;
            if (!found)
                return; /* no anchor in this chunk */
            do_resync(r, c, dir, f);
            break;
        }
        }
    }
}

void lk_frame_hole(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, __u64 n)
{
    const struct lk_proto_ops *ops = conn_ops(c);
    struct lk_frame *f = &c->frame[dir];

    if (n == 0)
        return;
    if (ops->intercept_hole && ops->intercept_hole(r, c, dir)) {
        /* A pending special reply fell into the hole (PG: the SSL byte —
         * whether the stream is now ciphertext is unknown): dirty and let
         * the resync sort it out. */
        go_dirty(r, f, &r->st.hdr_holes);
        return;
    }
    if (f->st == LK_FR_DIRTY) {
        f->resync_matched = 0; /* the anchor cannot span a hole */
        return;
    }
    r->st.holes++;
    r->st.hole_bytes += n;

    while (n > 0) {
        switch (f->st) {
        case LK_FR_HEADER:
            /* The next header is somewhere inside the hole — nothing to
             * learn its position from (Р9). */
            go_dirty(r, f, &r->st.hdr_holes);
            return;
        case LK_FR_BODY: {
            /* The header is known: emit the captured prefix now and advance
             * over the rest of the body arithmetically. */
            __u64 rem = (__u64)f->body_len - f->buf_len;
            __u64 take = rem < n ? rem : n;

            emit(r, ops, c, dir, f, f->buf, f->buf_len);
            n -= take;
            msg_reset(r, f);
            if (take < rem) {
                f->st = LK_FR_SKIP;
                f->skip_left = rem - take;
            }
            break;
        }
        case LK_FR_SKIP: {
            __u64 take = f->skip_left < n ? f->skip_left : n;

            n -= take;
            f->skip_left -= take;
            if (!f->skip_left)
                f->st = LK_FR_HEADER;
            break;
        }
        case LK_FR_DIRTY:
            return;
        }
    }
}

void lk_reasm_data(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                   const struct lk_ev_data *ev, __u32 cap_len)
{
    const struct lk_proto_ops *ops = conn_ops(c);
    struct lk_frame *f = &c->frame[dir];
    __u32 total = ev->total_len, off = ev->off;
    bool decrypted = ev->hdr.flags & LK_F_DECRYPTED;

    if (c->flags & LK_CONN_CANCEL)
        return; /* cancel: nothing else travels this connection, discard it all */
    if ((c->flags & LK_CONN_TLS) && !decrypted)
        return; /* ciphertext on a TLS connection: dropped (Р38). The router
                   already drops it before the seq detector; this guards the
                   direct callers — the plaintext source is the uprobe channel,
                   whose events carry LK_F_DECRYPTED and are framed below. */

    if (off == 0) {
        /* New call. The previous one ended under-captured (budget cut or
         * chunk-slot exhaustion — the latter comes without LK_F_TRUNC, which
         * is why the tail is detected here, lazily): its remainder is a hole
         * of known size, total_len is honest. */
        if (f->call_total > f->call_pos)
            lk_frame_hole(r, c, dir, f->call_total - f->call_pos);
        f->call_total = total;
        f->call_pos = 0;
    } else if (f->call_total == 0) {
        /* Mid-call chunk with no call in progress: the off==0 chunk was lost
         * to the ringbuf (the seq detector has already dirtied us) or the
         * entry was just re-created. Adopt the call; [0, off) becomes a hole
         * below. */
        f->call_total = total;
        f->call_pos = 0;
    }

    if (total != f->call_total || off < f->call_pos || (__u64)off + cap_len > total) {
        /* Chunk arithmetic diverged from reality (off backwards / past
         * total_len / total_len changed mid-call). On a clean direction this
         * is a real anomaly — dirty it, never corrupt silently; on a dirty
         * one it is expected post-loss debris. Either way re-adopt so the
         * call position stays coherent for the resync. */
        if (f->st != LK_FR_DIRTY)
            go_dirty(r, f, &r->st.off_anomalies);
        f->call_total = total;
        f->call_pos = off;
    } else if (off > f->call_pos) {
        /* Missing interval between chunks of one call: a known hole. */
        lk_frame_hole(r, c, dir, off - f->call_pos);
        f->call_pos = off;
    }

    /* Call-boundary resync anchor (Р10): where messages start at call
     * boundaries, a dirty direction may safely re-enter framing (PG:
     * frontend, valid type + plausible len). Checked after the hole/anomaly
     * bookkeeping, right before the bytes are fed. */
    if (f->st == LK_FR_DIRTY && ops->resync_boundary(c, dir, ev, cap_len))
        do_resync(r, c, dir, f);

    if (cap_len)
        lk_frame_bytes(r, c, dir, ev->payload, cap_len, ev->hdr.ts_ns);
    f->call_pos = off + cap_len;
    if (f->call_pos >= f->call_total)
        f->call_total = f->call_pos = 0; /* call fully accounted for */
}
