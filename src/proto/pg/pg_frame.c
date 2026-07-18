// SPDX-License-Identifier: GPL-2.0
/* PG v3 framing knowledge behind the protocol vtable (РМ1, MYSQL.md М1) —
 * everything reassembly.c used to hard-code: type(1) + len(4, BE) frames, the
 * startup framing of the frontend prelude (len-only until StartupMessage), the
 * SSLRequest/GSSENCRequest one-byte-reply interception and the TLS/Cancel
 * connection transitions, and both resync anchors (Р10) — the backend
 * 'Z' 00 00 00 05 [ITE] byte scan and the frontend call-boundary check. The
 * generic mechanics (chunk arithmetic, holes, the body-prefix slab pool, the
 * dirty/skip state machine, counters) stayed behind in reassembly.c; the
 * behaviour of the pair is bit-for-bit the pre-vtable framer, pinned by
 * test_reassembly.c and the replay fixtures.
 *
 * The startup-message codes (LK_PG_PROTO_V3 & co) live in reassembly.h: they
 * predate the vtable and are shared by pg_session.c and a raft of test
 * builders — moving them would churn every include for no behaviour. */
#include <stdbool.h>
#include <string.h>

#include "proto.h"

/* Message length sanity ceiling (Р10): larger values are corruption. Shared
 * (via the resync-anchor plausibility check) with parse_hdr. */
#define LK_PG_MSG_LEN_MAX (1u << 30)

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

static __u32 pg_hdr_size(const struct lk_conn *c, enum lk_dir dir, const struct lk_frame *f)
{
    (void)c;
    return in_startup(f, dir) ? 4 : 5;
}

/* Header complete: sanity-check len, fill type/len/body_len. len includes
 * itself; a startup message must at least carry the 4-byte code. Anything
 * shorter, or absurdly long, is corruption (Р10) — the framer goes dirty. */
static bool pg_parse_hdr(struct lk_conn *c, enum lk_dir dir, struct lk_frame *f)
{
    bool startup = in_startup(f, dir);
    __u32 len = be32(f->hdr + (startup ? 0 : 1));

    (void)c;
    if (len < (startup ? 8u : 4u) || len > LK_PG_MSG_LEN_MAX)
        return false;
    f->msg_type = startup ? 0 : f->hdr[0];
    f->msg_len = len;
    f->body_len = len - 4;
    f->body_total = f->body_len; /* PG never glues fragments (РМ3 is MySQL's) */
    return true;
}

/* Startup-framed messages: flag them and read the code — all the semantics
 * the framer needs (Р10). An unreadable code (body cut before byte 4) leaves
 * startup framing on; if it actually was a StartupMessage the next header
 * fails the len sanity check and the direction goes dirty — no silent
 * corruption. */
static void pg_pre_emit(struct lk_conn *c, enum lk_dir dir, struct lk_frame *f, struct lk_msg *m)
{
    if (!in_startup(f, dir))
        return;
    m->flags |= LK_MSG_STARTUP;
    if (m->body_cap >= 4) {
        switch (be32(m->body)) {
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

/* The one-byte backend reply to SSLRequest/GSSENCRequest — the only untyped
 * backend message (Р10). Emitted as an lk_msg with len == 0 (there is no
 * length field on the wire). Returns false when the connection went
 * encrypted and the rest of the chunk must be dropped. An unexpected byte
 * (an ancient server answering with ErrorResponse) is treated as consumed
 * plaintext: framing derails on the next header and recovers via resync. */
static bool pg_intercept_bytes(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                               const __u8 **p, __u32 *n, __u64 ts_ns)
{
    if (dir != LK_DIR_SEND || !(c->flags & LK_CONN_SSL_REPLY) || *n == 0)
        return true;

    __u8 b = (*p)[0];
    struct lk_msg m = {.ts_ns = ts_ns, .type = (char)b};

    c->flags &= ~LK_CONN_SSL_REPLY;
    r->st.msgs++;
    if (r->sink.on_msg)
        r->sink.on_msg(r->sink.ctx, c, LK_DIR_SEND, &m);
    (*p)++;
    (*n)--;
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

/* The one-byte reply fell into a hole: 'S' or 'N' is unknown, so whether the
 * stream is now ciphertext is unknown too. Returning true has the framer
 * dirty the direction (hdr_holes) and let the resync sort it out — scanning
 * ciphertext may cost a false anchor or two (see the STAGE2.md risk table),
 * never silence. */
static bool pg_intercept_hole(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir)
{
    (void)r;
    if (dir != LK_DIR_SEND || !(c->flags & LK_CONN_SSL_REPLY))
        return false;
    c->flags &= ~LK_CONN_SSL_REPLY;
    return true;
}

/* Backend resync anchor: ReadyForQuery on the wire (Р10). Positions 0-4 are
 * fixed bytes, position 5 accepts the three status values. */
static const __u8 resync_pat[5] = {'Z', 0, 0, 0, 5};

/* Backend resync scan (Р10): find 'Z' 00 00 00 05 [ITE] in the captured
 * bytes; f->resync_matched carries the partial match across event boundaries.
 * The pattern restarts only on 'Z' — no other pattern byte equals 'Z', so
 * this shortcut is exact. The ReadyForQuery itself is not emitted — it is
 * only a boundary marker, framing resumes at the byte after it. The frontend
 * anchor is a call boundary (pg_resync_boundary); frontend bytes here are
 * discarded. */
static __u32 pg_resync_scan(struct lk_conn *c, enum lk_dir dir, struct lk_frame *f, const __u8 *p,
                            __u32 n, bool *found)
{
    __u32 used = 0;

    (void)c;
    if (dir != LK_DIR_SEND)
        return n;
    while (used < n) {
        __u8 b = p[used++];

        if (f->resync_matched < 5) {
            f->resync_matched =
                b == resync_pat[f->resync_matched] ? f->resync_matched + 1 : b == 'Z';
        } else if (b == 'I' || b == 'T' || b == 'E') {
            *found = true;
            return used;
        } else {
            f->resync_matched = b == 'Z';
        }
    }
    return used;
}

/* Frontend message types acceptable as a resync anchor (Р10). */
static bool fe_type_ok(__u8 b)
{
    return b && strchr("QPBESXCDFHdcfp", b);
}

/* Frontend resync anchor (Р10): a call boundary whose first captured byte is
 * a valid frontend type with a plausible len. Messages start at call
 * boundaries on the frontend (libpq flushes whole messages), so this is where
 * framing may safely re-enter. */
static bool pg_resync_boundary(const struct lk_conn *c, enum lk_dir dir,
                               const struct lk_ev_data *ev, __u32 cap_len)
{
    (void)c;
    if (dir != LK_DIR_RECV || ev->off != 0 || cap_len < 5 || !fe_type_ok(ev->payload[0]))
        return false;

    __u32 len = be32(ev->payload + 1);

    return len >= 4 && len <= LK_PG_MSG_LEN_MAX;
}

const struct lk_proto_ops lk_proto_pg_ops = {
    .name = "pg",
    .proto_new = lk_proto_pg_new,
    .hdr_size = pg_hdr_size,
    .parse_hdr = pg_parse_hdr,
    .pre_emit = pg_pre_emit,
    .intercept_bytes = pg_intercept_bytes,
    .intercept_hole = pg_intercept_hole,
    .resync_scan = pg_resync_scan,
    .resync_boundary = pg_resync_boundary,
};
