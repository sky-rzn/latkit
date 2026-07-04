// SPDX-License-Identifier: GPL-2.0
#include "reassembly.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* Message length sanity ceiling (Р10): larger values are corruption. */
#define LK_MSG_LEN_MAX (1u << 30)

void lk_reasm_init(struct lk_reasm *r, const struct lk_msg_sink *sink)
{
    memset(r, 0, sizeof(*r));
    if (sink)
        r->sink = *sink;
}

static __u32 be32(const __u8 *p)
{
    return (__u32)p[0] << 24 | (__u32)p[1] << 16 | (__u32)p[2] << 8 | p[3];
}

/* The port filter captures the server side, so RECV is the frontend->backend
 * stream: only it starts in startup framing (no type byte, Р10). */
static bool in_startup(const struct lk_frame *f, enum lk_dir dir)
{
    return dir == LK_DIR_RECV && !f->startup_done;
}

/* Back to HEADER at a message boundary; the body-prefix buffer is freed here,
 * not reused, so steady-state memory is ~0 (Р11). */
static void msg_reset(struct lk_frame *f)
{
    free(f->buf);
    f->buf = NULL;
    f->buf_len = 0;
    f->hdr_len = 0;
    f->st = LK_FR_HEADER;
}

/* Sync lost on this direction: drop the partial message and wait for the
 * task-2.4 resynchronisation. Each cause has its own counter. */
static void go_dirty(struct lk_frame *f, __u64 *counter)
{
    (*counter)++;
    msg_reset(f);
    f->skip_left = 0;
    f->st = LK_FR_DIRTY;
}

static void emit(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct lk_frame *f,
                 const __u8 *body, __u32 body_cap)
{
    struct lk_msg m = {
        .ts_ns = f->msg_ts,
        .type = (char)f->msg_type,
        .len = f->msg_len,
        .body_cap = body_cap,
        .body = body,
    };

    if (in_startup(f, dir)) {
        m.flags |= LK_MSG_STARTUP;
        /* StartupMessage flips the direction to normal framing; SSLRequest,
         * GSSENCRequest and CancelRequest keep it in startup framing (their
         * semantics — task 2.4). An unreadable code (body cut before byte 4)
         * leaves startup framing on; if it actually was a StartupMessage the
         * next header fails the len sanity check and the direction goes
         * dirty — no silent corruption. */
        if (body_cap >= 4 && be32(body) == LK_PG_PROTO_V3)
            f->startup_done = 1;
    }
    if (body_cap < f->msg_len - 4) {
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
    __u32 body_len = f->msg_len - 4;

    return body_len < LK_MSG_BODY_MAX ? body_len : LK_MSG_BODY_MAX;
}

/* Header complete: sanity-check len and move on. Returns false when the
 * direction went dirty. */
static bool parse_header(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                         struct lk_frame *f)
{
    bool startup = in_startup(f, dir);
    __u32 len = be32(f->hdr + (startup ? 0 : 1));

    /* len includes itself; a startup message must at least carry the 4-byte
     * code. Anything shorter, or absurdly long, is corruption (Р10). */
    if (len < (startup ? 8u : 4u) || len > LK_MSG_LEN_MAX) {
        go_dirty(f, &r->st.bad_len);
        return false;
    }
    f->msg_type = startup ? 0 : f->hdr[0];
    f->msg_len = len;
    if (len == 4) { /* empty body: whole message was the header */
        emit(r, c, dir, f, NULL, 0);
        msg_reset(f);
    } else {
        f->st = LK_FR_BODY;
    }
    return true;
}

void lk_frame_bytes(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, const __u8 *p, __u32 n,
                    __u64 ts_ns)
{
    struct lk_frame *f = &c->frame[dir];

    while (n > 0) {
        switch (f->st) {
        case LK_FR_HEADER: {
            __u32 hdr_size = in_startup(f, dir) ? 4 : 5;
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
            if (!parse_header(r, c, dir, f))
                return;
            break;
        }
        case LK_FR_BODY: {
            __u32 target = body_target(f);
            __u32 rem = target - f->buf_len;

            if (n < rem) {
                /* Prefix incomplete: spill into the lazy buffer. On OOM
                 * degrade to emitting what this chunk holds and skipping the
                 * rest — capture quality drops, framing stays in sync. */
                if (!f->buf)
                    f->buf = malloc(target);
                if (f->buf) {
                    memcpy(f->buf + f->buf_len, p, n);
                    f->buf_len += n;
                    return;
                }
                rem = n;
                target = f->buf_len + n; /* buf_len == 0 when buf is NULL */
            }
            const __u8 *body = f->buf ? f->buf : p;
            __u64 skip = (__u64)(f->msg_len - 4) - target;

            if (f->buf)
                memcpy(f->buf + f->buf_len, p, rem);
            emit(r, c, dir, f, body, target);
            p += rem;
            n -= rem;
            msg_reset(f);
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
        case LK_FR_DIRTY:
            return; /* discarded until the task-2.4 resync */
        }
    }
}

void lk_frame_hole(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, __u64 n)
{
    struct lk_frame *f = &c->frame[dir];

    if (n == 0 || f->st == LK_FR_DIRTY)
        return;
    r->st.holes++;
    r->st.hole_bytes += n;

    while (n > 0) {
        switch (f->st) {
        case LK_FR_HEADER:
            /* The next header is somewhere inside the hole — nothing to
             * learn its position from (Р9). */
            go_dirty(f, &r->st.hdr_holes);
            return;
        case LK_FR_BODY: {
            /* The header is known: emit the captured prefix now and advance
             * over the rest of the body arithmetically. */
            __u64 rem = (__u64)(f->msg_len - 4) - f->buf_len;
            __u64 take = rem < n ? rem : n;

            emit(r, c, dir, f, f->buf, f->buf_len);
            n -= take;
            msg_reset(f);
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
    struct lk_frame *f = &c->frame[dir];
    __u32 total = ev->total_len, off = ev->off;

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
         * call position stays coherent for the task-2.4 resync. */
        if (f->st != LK_FR_DIRTY)
            go_dirty(f, &r->st.off_anomalies);
        f->call_total = total;
        f->call_pos = off;
    } else if (off > f->call_pos) {
        /* Missing interval between chunks of one call: a known hole. */
        lk_frame_hole(r, c, dir, off - f->call_pos);
        f->call_pos = off;
    }

    if (cap_len)
        lk_frame_bytes(r, c, dir, ev->payload, cap_len, ev->hdr.ts_ns);
    f->call_pos = off + cap_len;
    if (f->call_pos >= f->call_total)
        f->call_total = f->call_pos = 0; /* call fully accounted for */
}
