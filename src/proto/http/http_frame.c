// SPDX-License-Identifier: GPL-2.0
/* HTTP/1.x framing behind the protocol vtable — the third lk_proto_ops entry,
 * and the first one in *stream* mode (РH1, PLAN-HTTP.md М1).
 *
 * Why a second mode at all (docs/notes-httpproto.md, §"Framing"): PG and MySQL
 * put a fixed-size, length-carrying header in front of every message, which is
 * exactly what the generic machine in reassembly.c accumulates in the 8-byte
 * lk_frame.hdr. HTTP/1.x has no such thing — a message begins with a start
 * line, ends its header block at the first CRLFCRLF, and only then reveals the
 * body length (or hides it in chunk headers scattered through the body). The
 * hdr_size/parse_hdr contract cannot express that at any size of hdr[], so the
 * protocol takes the raw byte stream instead: lk_reasm_data still runs the
 * whole generic pipeline — chunk arithmetic, off-anomalies, the TLS/IGNORE
 * drop, the loss counters — and then hands what survives to stream_bytes /
 * stream_hole. Messages go back out through lk_reasm_emit, so --messages, the
 * replay harness, fuzz_pipe and the handlers see nothing new.
 *
 * М1 is the seam, not the protocol. This framer parses no HTTP whatsoever: it
 * emits one message per capture event, typed by direction, carrying that
 * event's bytes as the body. That is enough to prove the plumbing end to end —
 * state allocation and teardown, hole accounting, the resync path, the message
 * contract — over the М0 trace corpus, and it is what the М1 acceptance check
 * asserts (`--messages` prints one line per event). М2 replaces the body of
 * the two hooks with the real HEAD/BODY machine, the blind-spot detection and
 * the textual resync anchors; the ops table and the ownership rules here stay
 * as they are. */
#include <stdlib.h>

#include "http.h"

/* Framer state (РH1), lazily allocated: the connection table frees it on every
 * removal path. NULL on OOM — the framer degrades to emitting without the
 * bookkeeping, never to dropping the stream. */
static struct http_frame *http_frame_get(struct lk_conn *c)
{
    if (!c->frame_state)
        c->frame_state = calloc(1, sizeof(struct http_frame));
    return c->frame_state;
}

static void http_stream_bytes(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, const __u8 *p,
                              __u32 n, __u64 ts_ns)
{
    struct http_frame *hf = http_frame_get(c);
    struct lk_msg m = {
        .ts_ns = ts_ns,
        /* The capture is server-side (Р7/РH2), so RECV is the request stream
         * and SEND the response one — the direction alone gives the head
         * letter, no parsing needed. */
        .type = dir == LK_DIR_RECV ? LK_HTTP_MSG_REQ : LK_HTTP_MSG_RESP,
        .len = n,
        .body_cap = n < LK_MSG_BODY_MAX ? n : LK_MSG_BODY_MAX,
        .body = p,
    };

    /* Loss dirties both directions before the bytes ever reach us (the conn
     * table's seq detector; a lazily created or synthetic entry starts dirty
     * too). A framer that interprets nothing can resume at any byte, so М1
     * clears the state on the next bytes and counts the resync honestly. М2
     * resumes on a start-line / status-line anchor instead — the strongest
     * anchors of the three protocols (РH1, notes-httpproto.md). */
    if (c->frame[dir].st == LK_FR_DIRTY)
        lk_reasm_resync(r, c, dir);
    if (m.body_cap < m.len)
        m.flags |= LK_MSG_BODY_TRUNC;
    if (hf) {
        hf->off[dir] += n;
        hf->events[dir]++;
    }
    lk_reasm_emit(r, c, dir, &m);
}

/* A hole is bytes we will never see: an uncaptured call tail (the per-call
 * budget, РH14), a lost ringbuf event, a missing off-interval. For М1 it is
 * pure bookkeeping — the framer has no message in flight to damage. М2 turns
 * it into the four degradations of РH4: harmless inside a Content-Length body
 * (skipped arithmetically), fatal inside a chunked one (no chunk header
 * survives it) and sync-losing on a header block. */
static void http_stream_hole(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, __u64 n)
{
    struct http_frame *hf = http_frame_get(c);

    (void)r;
    if (hf) {
        hf->off[dir] += n;
        hf->holes[dir]++;
    }
}

const struct lk_proto_ops lk_proto_http_ops = {
    .name = "http",
    /* db_system stays NULL: HTTP is not a database, and otel_kind is what
     * tells the span builder so (РH11; М6 acts on it). */
    .otel_kind = LK_OTEL_KIND_HTTP,
    .role = LK_ROLE_SERVER, /* v1 observes servers only (РH2) */
    .flags = LK_PROTO_F_STREAM,
    .sql_dialect = LK_SQL_PG, /* unused: nothing here reaches the SQL normaliser */
    .proto_new = lk_proto_http_new,
    /* The message-framing hooks (hdr_size, parse_hdr, pre_emit, both
     * intercept_ and both resync_) stay NULL: in stream mode the two hooks
     * above are the machine. */
    .stream_bytes = http_stream_bytes,
    .stream_hole = http_stream_hole,
};
