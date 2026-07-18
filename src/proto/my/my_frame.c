// SPDX-License-Identifier: GPL-2.0
/* MySQL classic-protocol framing behind the protocol vtable (РМ3/РМ4,
 * MYSQL.md М2) — the second lk_proto_ops entry, mirroring pg_frame.c.
 *
 * Wire format (notes-myproto.md): every packet is len(u24, LE) + seq(u8) +
 * payload; there is no type byte in the header. The framer therefore reports
 * lk_msg.type = first payload byte for frontend *commands* (packets starting
 * at wire seq 0 — commands reset the sequence, auth replies and LOAD DATA
 * chunks never do) and type = 0 for everything else; response classification
 * is the handler's job (first byte + phase, РМ3). lk_msg.body is the whole
 * payload — offset 0 is the command byte — and lk_msg.len is the *logical*
 * payload length: a payload of >= 16MB-1 travels as 0xFFFFFF-sized fragments
 * glued back into one lk_msg here (msg_cont / prefix_closed, the generic
 * framer's continuation contract), the sequence ending at the first fragment
 * with len < 0xFFFFFF (an exact multiple ends with an empty one). seq is
 * swallowed: handlers never see it, the framer uses it to pin continuations
 * (a continuation header whose seq breaks the chain is corruption) and as
 * resync material (РМ4).
 *
 * Connection phase (the server speaks first): the greeting and the whole auth
 * exchange are framed as ordinary packets, flagged LK_MSG_STARTUP until the
 * server's final OK; auth payloads are never parsed here (Р16 — they carry
 * scrambles and, on some paths, passwords). The framer reads exactly one
 * frontend packet deeply: the first one (HandshakeResponse41 or the short
 * SSLRequest), for the client capability flags —
 *   CLIENT_SSL       -> LK_CONN_TLS: the rest of the socket stream is
 *                       ciphertext (the generic framer drops the chunk tail);
 *                       the full HandshakeResponse repeats inside TLS on the
 *                       decrypted channel, where framing restarts (М5);
 *   CLIENT_COMPRESS / _ZSTD -> LK_CONN_COMPRESS_PENDING: compressed framing
 *                       starts right after the auth exchange, so the final OK
 *                       flips the connection to LK_CONN_IGNORE (РМ7 — a
 *                       recognised blind zone; session labels were already on
 *                       the wire in plaintext for М3 to read).
 *
 * Resync anchors (РМ4) — no 'Z'-like byte pattern exists, so resync_scan
 * never matches and both anchors are call boundaries:
 *   frontend (primary): off == 0 + seq == 0 + a known command byte + len >= 1
 *     — commands start their own syscall in every real client;
 *   backend (weak): off == 0 + seq == 1 + 1 <= len < 0xFFFFFF — a response
 *     head (replies to a seq-0 command start at seq 1). Mid-response call
 *     boundaries carry higher seqs and are rejected; the backend converges at
 *     the next request/response cycle, the accepted РМ4 cost. */
#include <stdbool.h>
#include <stdlib.h>

#include "proto.h"

/* Client capability bits the framer reads (notes-myproto.md; the handler
 * reads more in М3). */
#define MY_CLIENT_COMPRESS 0x00000020u
#define MY_CLIENT_SSL      0x00000800u
#define MY_CLIENT_ZSTD     0x04000000u /* CLIENT_ZSTD_COMPRESSION_ALGORITHM */

#define MY_PKT_MAX 0xFFFFFFu /* u24 ceiling: the continuation marker */

static __u32 le24(const __u8 *p)
{
    return (__u32)p[2] << 16 | (__u32)p[1] << 8 | p[0];
}

static __u32 le32(const __u8 *p)
{
    return (__u32)p[3] << 24 | (__u32)p[2] << 16 | (__u32)p[1] << 8 | p[0];
}

static __u32 my_hdr_size(const struct lk_conn *c, enum lk_dir dir, const struct lk_frame *f)
{
    (void)c;
    (void)dir;
    (void)f;
    return 4; /* len(3) + seq(1), both directions, all phases */
}

/* Any 4 bytes are a wire-legal header (len is unbounded by construction, seq
 * is free) — the only redundancy to check is the continuation chain: a
 * fragment header must carry the next seq, or the glue is torn (corruption /
 * misframing; the direction goes dirty via bad_len). */
static bool my_parse_hdr(struct lk_conn *c, enum lk_dir dir, struct lk_frame *f)
{
    __u32 len = le24(f->hdr);
    __u8 seq = f->hdr[3];

    (void)c;
    (void)dir;
    if (f->msg_cont) {
        if (seq != f->msg_seq)
            return false; /* not the continuation this must be */
        f->msg_seq = (__u8)(seq + 1);
        f->msg_cont = len == MY_PKT_MAX;
        f->body_len = len;
        /* Saturate rather than wrap: a corrupt stream can chain fragments
         * past 4GB (real servers cap payloads at max_allowed_packet, 1GB). */
        f->body_total = f->body_total + len < f->body_total ? ~0u : f->body_total + len;
        f->msg_len = f->body_total;
        return true;
    }
    f->msg_type = 0; /* frontend commands are typed in pre_emit, from body[0] */
    f->msg_seq0 = seq == 0;
    f->msg_seq = (__u8)(seq + 1);
    f->msg_cont = len == MY_PKT_MAX;
    f->body_len = len;
    f->body_total = len;
    f->msg_len = len;
    return true;
}

/* Phase bookkeeping over the assembled packet. startup_done semantics here:
 * RECV — the first frontend packet (HandshakeResponse/SSLRequest) was
 * consumed; SEND — the auth exchange ended (the server's final OK), i.e. the
 * connection is in the command phase. A resync forces startup_done on its
 * direction (generic do_resync), which reads correctly on both: mid-session
 * entry means the handshake is long past. */
static void my_pre_emit(struct lk_conn *c, enum lk_dir dir, struct lk_frame *f, struct lk_msg *m)
{
    struct lk_frame *be = &c->frame[LK_DIR_SEND];

    /* A frontend command implies the auth exchange completed — the backend
     * phase bit may lag when its direction entered dirty (synthetic conns)
     * or its OK fell into a hole. With compression negotiated a command-phase
     * packet is already compressed framing: this "command" is misframed
     * bytes, and the connection goes blind now (РМ7). */
    if (dir == LK_DIR_RECV && f->startup_done && f->msg_seq0) {
        be->startup_done = 1;
        if (c->flags & LK_CONN_COMPRESS_PENDING)
            c->flags |= LK_CONN_IGNORE;
    }
    if (!be->startup_done)
        m->flags |= LK_MSG_STARTUP;

    if (dir == LK_DIR_RECV) {
        if (!f->startup_done) {
            /* The one frontend packet the framer reads: client capability
             * flags sit at payload offset 0. A prefix cut before byte 4
             * (capture hole) leaves the flags unknown — assume plaintext,
             * uncompressed; if that was wrong the stream derails into DIRTY
             * and the resync anchors get no purchase on ciphertext, a
             * documented degradation (РМ4/РМ7). */
            if (m->body_cap >= 4) {
                __u32 caps = le32(m->body);

                if ((caps & MY_CLIENT_SSL) && !(c->flags & LK_CONN_TLS)) {
                    /* Short SSLRequest on the socket stream: everything after
                     * this packet is TLS. startup_done stays 0 — the real
                     * HandshakeResponse repeats inside TLS, where framing
                     * restarts and the connection is already LK_CONN_TLS, so
                     * the same CLIENT_SSL bit in the *full* response falls
                     * through to be read as the real thing (М5). */
                    c->flags |= LK_CONN_TLS;
                    return;
                }
                if (caps & (MY_CLIENT_COMPRESS | MY_CLIENT_ZSTD))
                    c->flags |= LK_CONN_COMPRESS_PENDING;
            }
            f->startup_done = 1;
            return;
        }
        if (f->msg_seq0 && m->body_cap)
            m->type = (char)m->body[0]; /* a command: type = command byte */
        return;
    }

    /* Backend, connection phase: watch for the exchange terminator. The
     * greeting (0x0a = protocol version 10), AuthSwitchRequest (0xfe) and
     * AuthMoreData (0x01) pass through; OK (0x00) ends the phase — and
     * activates compression when it was negotiated (РМ7). ERR (0xff) means
     * the server is about to close; nothing follows either way. */
    if (!f->startup_done && m->body_cap && m->body[0] == 0x00) {
        f->startup_done = 1;
        if (c->flags & LK_CONN_COMPRESS_PENDING)
            c->flags |= LK_CONN_IGNORE;
    }
}

/* No resynchronisation byte pattern exists (РМ4): captured bytes on a dirty
 * direction are discarded, both anchors are call boundaries checked in
 * my_resync_boundary. */
static __u32 my_resync_scan(struct lk_conn *c, enum lk_dir dir, struct lk_frame *f, const __u8 *p,
                            __u32 n, bool *found)
{
    (void)c;
    (void)dir;
    (void)f;
    (void)p;
    (void)found;
    return n;
}

/* Command bytes acceptable as a frontend resync anchor (РМ4): the known-set
 * from notes-myproto.md, including the recognised-but-tallied-only ones —
 * any of them restarts framing correctly. 0xfa is MariaDB
 * COM_STMT_BULK_EXECUTE. */
static bool my_cmd_ok(__u8 b)
{
    switch (b) {
    case 0x01: /* COM_QUIT */
    case 0x02: /* COM_INIT_DB */
    case 0x03: /* COM_QUERY */
    case 0x04: /* COM_FIELD_LIST */
    case 0x09: /* COM_STATISTICS */
    case 0x0a: /* COM_PROCESS_INFO */
    case 0x0d: /* COM_DEBUG */
    case 0x0e: /* COM_PING */
    case 0x11: /* COM_CHANGE_USER */
    case 0x12: /* COM_BINLOG_DUMP */
    case 0x15: /* COM_REGISTER_SLAVE */
    case 0x16: /* COM_STMT_PREPARE */
    case 0x17: /* COM_STMT_EXECUTE */
    case 0x18: /* COM_STMT_SEND_LONG_DATA */
    case 0x19: /* COM_STMT_CLOSE */
    case 0x1a: /* COM_STMT_RESET */
    case 0x1b: /* COM_SET_OPTION */
    case 0x1c: /* COM_STMT_FETCH */
    case 0x1e: /* COM_BINLOG_DUMP_GTID */
    case 0x1f: /* COM_RESET_CONNECTION */
    case 0xfa: /* MARIADB_COM_STMT_BULK_EXECUTE */
        return true;
    default:
        return false;
    }
}

/* Call-boundary anchors (РМ4). The frontend anchor is the primary one:
 * off == 0 + seq == 0 + a known command byte + len >= 1 (a command carries at
 * least its command byte; len == 0xFFFFFF is legal — a >=16MB query opens
 * with a continuation run). The backend anchor is weak by design: a response
 * head (seq == 1, sane len) at a call boundary. */
static bool my_resync_boundary(const struct lk_conn *c, enum lk_dir dir,
                               const struct lk_ev_data *ev, __u32 cap_len)
{
    __u32 len;

    (void)c;
    if (ev->off != 0 || cap_len < 4)
        return false;
    len = le24(ev->payload);
    if (dir == LK_DIR_RECV)
        return ev->payload[3] == 0 && len >= 1 && cap_len >= 5 && my_cmd_ok(ev->payload[4]);
    return ev->payload[3] == 1 && len >= 1 && len < MY_PKT_MAX;
}

/* --- М2 handler stub ------------------------------------------------------ */

/* Counting-only lk_msg_sink: the message tallies feed the stats line and the
 * М2 acceptance runs (--messages over the М0 corpus); no per-connection
 * state, no observations. М3 replaces this with the real parser
 * (src/proto/my/my.c) without touching the ops above. */
static void my_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct lk_proto *p = ctx;

    (void)c;
    p->st.msgs++;
    if (m->flags & LK_MSG_STARTUP)
        p->st.startup_msgs++;
    p->st.by_type[dir][(__u8)m->type]++;
}

static void my_on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    struct lk_proto *p = ctx;

    (void)c;
    (void)dir;
    p->st.resyncs++;
}

struct lk_proto *lk_proto_my_new(const struct lk_query_sink *out)
{
    struct lk_proto *p = calloc(1, sizeof(*p));

    if (!p)
        return NULL;
    if (out)
        p->out = *out;
    p->msink.ctx = p;
    p->msink.on_msg = my_on_msg;
    p->msink.on_resync = my_on_resync;
    /* on_conn_open/on_conn_close unused: the stub allocates no proto_state. */
    return p;
}

const struct lk_proto_ops lk_proto_my_ops = {
    .name = "mysql",
    .proto_new = lk_proto_my_new,
    .hdr_size = my_hdr_size,
    .parse_hdr = my_parse_hdr,
    .pre_emit = my_pre_emit,
    /* intercept_bytes/intercept_hole: none — MySQL has no untyped
     * cross-direction bytes; the TLS transition is a framed packet. */
    .resync_scan = my_resync_scan,
    .resync_boundary = my_resync_boundary,
};
