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

/* Sync lost on this direction: drop the partial message and wait for a
 * resync anchor. Each cause has its own counter. */
static void go_dirty(struct lk_frame *f, __u64 *counter)
{
    (*counter)++;
    msg_reset(f);
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
    msg_reset(f); /* conn-table dirtying leaves partial-message state behind */
    f->skip_left = 0;
    f->resync_matched = 0;
    f->after_resync = 1;
    f->startup_done = 1;
    r->st.resyncs++;
    if (r->sink.on_resync)
        r->sink.on_resync(r->sink.ctx, c, dir);
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
        /* The code is all the semantics the framer needs (Р10). An
         * unreadable code (body cut before byte 4) leaves startup framing
         * on; if it actually was a StartupMessage the next header fails the
         * len sanity check and the direction goes dirty — no silent
         * corruption. */
        if (body_cap >= 4) {
            switch (be32(body)) {
            case LK_PG_PROTO_V3:
                f->startup_done = 1; /* normal framing from the next byte */
                break;
            case LK_PG_SSL_REQUEST:
            case LK_PG_GSSENC_REQUEST:
                /* The next backend byte is the one-byte reply; the request
                 * direction stays in startup framing (a StartupMessage
                 * follows after 'N'). */
                c->flags |= LK_CONN_SSL_REPLY;
                break;
            case LK_PG_CANCEL_REQUEST:
                /* Nothing else ever travels on a cancel connection: emit
                 * this message, then discard until CLOSE. */
                c->flags |= LK_CONN_CANCEL;
                break;
            }
        }
    }
    if (f->after_resync) {
        m.flags |= LK_MSG_AFTER_RESYNC;
        f->after_resync = 0;
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
static bool parse_header(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct lk_frame *f)
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

/* The one-byte backend reply to SSLRequest/GSSENCRequest — the only untyped
 * backend message (Р10). Emitted as an lk_msg with len == 0 (there is no
 * length field on the wire). Returns false when the connection went
 * encrypted and the rest of the stream must be dropped. An unexpected byte
 * (an ancient server answering with ErrorResponse) is treated as consumed
 * plaintext: framing derails on the next header and recovers via resync. */
static bool ssl_reply(struct lk_reasm *r, struct lk_conn *c, __u8 b, __u64 ts_ns)
{
    struct lk_msg m = {.ts_ns = ts_ns, .type = (char)b};

    c->flags &= ~LK_CONN_SSL_REPLY;
    r->st.msgs++;
    if (r->sink.on_msg)
        r->sink.on_msg(r->sink.ctx, c, LK_DIR_SEND, &m);
    if (b == 'S' || b == 'G') {
        /* TLS (or GSSAPI encryption) accepted: framing off, socket events
         * of this connection are discarded from now on — the plaintext
         * source becomes the stage-6 uprobe channel. */
        c->flags |= LK_CONN_TLS;
        r->st.tls_conns++;
        return false;
    }
    return true; /* 'N': plaintext continues */
}

/* Backend resync anchor: ReadyForQuery on the wire (Р10). Positions 0-4 are
 * fixed bytes, position 5 accepts the three status values. */
static const __u8 resync_pat[5] = {'Z', 0, 0, 0, 5};

void lk_frame_bytes(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, const __u8 *p, __u32 n,
                    __u64 ts_ns)
{
    struct lk_frame *f = &c->frame[dir];

    if (dir == LK_DIR_SEND && (c->flags & LK_CONN_SSL_REPLY) && n > 0) {
        if (!ssl_reply(r, c, p[0], ts_ns))
            return;
        p++;
        n--;
    }

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
            /* Backend resync scan (Р10): find 'Z' 00 00 00 05 [ITE] in the
             * captured bytes; resync_matched carries the partial match
             * across event boundaries. The pattern restarts only on 'Z' —
             * no other pattern byte equals 'Z', so this shortcut is exact.
             * The frontend anchor is a call boundary, checked in
             * lk_reasm_data; frontend bytes are discarded here. */
            if (dir != LK_DIR_SEND)
                return;
            while (n > 0) {
                __u8 b = *p++;

                n--;
                if (f->resync_matched < 5) {
                    f->resync_matched =
                        b == resync_pat[f->resync_matched] ? f->resync_matched + 1 : b == 'Z';
                } else if (b == 'I' || b == 'T' || b == 'E') {
                    /* Framing resumes at the byte after the anchor; the
                     * ReadyForQuery itself is not emitted — it is only a
                     * boundary marker (Р10). */
                    do_resync(r, c, dir, f);
                    break;
                } else {
                    f->resync_matched = b == 'Z';
                }
            }
            if (f->st == LK_FR_DIRTY)
                return; /* no anchor in this chunk */
            break;
        }
    }
}

void lk_frame_hole(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, __u64 n)
{
    struct lk_frame *f = &c->frame[dir];

    if (n == 0)
        return;
    if (dir == LK_DIR_SEND && (c->flags & LK_CONN_SSL_REPLY)) {
        /* The one-byte reply fell into the hole: 'S' or 'N' is unknown, so
         * whether the stream is now ciphertext is unknown too. Dirty and
         * let the resync sort it out — scanning ciphertext may cost a false
         * anchor or two (see the STAGE2.md risk table), never silence. */
        c->flags &= ~LK_CONN_SSL_REPLY;
        go_dirty(f, &r->st.hdr_holes);
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

/* Frontend message types acceptable as a resync anchor (Р10). */
static bool fe_type_ok(__u8 b)
{
    return b && strchr("QPBESXCDFHdcfp", b);
}

void lk_reasm_data(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                   const struct lk_ev_data *ev, __u32 cap_len)
{
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
            go_dirty(f, &r->st.off_anomalies);
        f->call_total = total;
        f->call_pos = off;
    } else if (off > f->call_pos) {
        /* Missing interval between chunks of one call: a known hole. */
        lk_frame_hole(r, c, dir, off - f->call_pos);
        f->call_pos = off;
    }

    /* Frontend resync anchor (Р10): a call boundary whose first captured
     * byte is a valid frontend type with a plausible len. Messages start at
     * call boundaries on the frontend (libpq flushes whole messages), so
     * this is where framing may safely re-enter; checked after the hole/
     * anomaly bookkeeping, right before the bytes are fed. */
    if (f->st == LK_FR_DIRTY && dir == LK_DIR_RECV && off == 0 && cap_len >= 5 &&
        fe_type_ok(ev->payload[0])) {
        __u32 len = be32(ev->payload + 1);

        if (len >= 4 && len <= LK_MSG_LEN_MAX)
            do_resync(r, c, dir, f);
    }

    if (cap_len)
        lk_frame_bytes(r, c, dir, ev->payload, cap_len, ev->hdr.ts_ns);
    f->call_pos = off + cap_len;
    if (f->call_pos >= f->call_total)
        f->call_total = f->call_pos = 0; /* call fully accounted for */
}
