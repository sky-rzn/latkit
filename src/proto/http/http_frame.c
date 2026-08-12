// SPDX-License-Identifier: GPL-2.0
/* HTTP/1.x framing behind the protocol vtable — the third lk_proto_ops entry,
 * and the only one in *stream* mode (РH1/РH3/РH4, PLAN-HTTP.md М2).
 *
 * Why a second mode at all (docs/notes-httpproto.md §"Framing"): PG and MySQL
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
 * The machine, per direction:
 *
 *   HEAD ──(empty line)──▶ decide the body length (RFC 9112 §6.3, in order)
 *     │                      ├─ nothing to read ─────────────▶ HEAD
 *     │                      ├─ Content-Length ──▶ BODY ──────▶ HEAD
 *     │                      ├─ chunked ─────────▶ CHUNK ─────▶ HEAD
 *     │                      └─ neither, response ▶ CLOSE ─────▶ (CONN_CLOSE)
 *     │
 *     └──(hole / malformed / oversized)──▶ SCAN ──(start line)──▶ HEAD
 *
 * Three properties are worth naming, because they are what the design bought:
 *
 *   - **the body is counted, never scanned.** Once the head names a length the
 *     body is arithmetic, so a 1 GB download costs the framer nothing per byte
 *     and a capture hole inside it is harmless — the plan's central claim about
 *     staying honest under loss (Р9) holds for the common case unchanged.
 *   - **chunked is the exception, and it is the main path.** The sizes live in
 *     the stream, so a hole in a chunked body cannot be skipped over: the
 *     direction resyncs and the unit is dropped, counted, and visible
 *     (LK_HTTP_NOTE_CHUNK_HOLE). М0 measured chunked at a third to two thirds
 *     of the responses from a modern backend, so this is a main-path
 *     degradation, not a corner.
 *   - **the two directions are not independent.** A response to `HEAD` carries
 *     a `Content-Length` describing a body that never arrives, and a `CONNECT`
 *     answered 2xx turns the socket into a tunnel — so the framer keeps the
 *     in-flight requests in a FIFO and the response direction reads it.
 *
 * Everything the framer rejects, it rejects loudly: a '!' note message carries
 * the reason into the same stream the heads travel in (РH3), so a degradation
 * is replayable, visible in --messages and countable by the handler without the
 * framer needing a stats object of its own. */
#include <stdlib.h>
#include <string.h>

#include "http.h"
#include "norm_redact.h"

/* Framer state (РH1), lazily allocated: the connection table frees it on every
 * removal path. NULL means we cannot frame this connection at all — say so and
 * make it a counted blind zone rather than guess at boundaries. */
static struct http_frame *http_frame_get(struct lk_conn *c)
{
    if (!c->frame_state)
        c->frame_state = calloc(1, sizeof(struct http_frame));
    return c->frame_state;
}

/* --- emitting ------------------------------------------------------------- */

static void emit(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, char type, __u32 len,
                 const __u8 *body, __u32 cap, __u16 flags, __u64 ts)
{
    struct lk_msg m = {
        .ts_ns = ts,
        .type = type,
        .flags = flags,
        .len = len,
        .body_cap = cap,
        .body = body,
    };

    lk_reasm_emit(r, c, dir, &m);
}

static void note(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, enum lk_http_note n,
                 __u64 ts)
{
    emit(r, c, dir, LK_HTTP_MSG_NOTE, (__u32)n, NULL, 0, 0, ts);
}

/* A recognised blind zone (РH4): the note names the reason, LK_CONN_IGNORE
 * stops the framer, the generic layer discards this connection's events from
 * here to CONN_CLOSE and userspace drops its capture to HEADERS. */
static void go_blind(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, enum lk_http_note n,
                     __u64 ts)
{
    note(r, c, dir, n, ts);
    c->flags |= LK_CONN_IGNORE;
}

/* Sync lost on this direction. HTTP_FR_SCAN and LK_FR_DIRTY are deliberately
 * the same state seen from two sides: the connection table dirties lk_frame on
 * a seq gap, the framer dirties it on its own losses, and either way the way
 * out is the anchor scan below plus lk_reasm_resync — one counter, one
 * on_resync callback, one LK_MSG_AFTER_RESYNC stamp for both causes. */
static void go_scan(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct http_dir *hd)
{
    struct lk_frame *f = &c->frame[dir];

    lk_reasm_buf_put(r, f->buf); /* the partial header block is worthless now */
    f->buf = NULL;
    f->buf_len = 0;
    f->st = LK_FR_DIRTY;
    hd->st = HTTP_FR_SCAN;
    hd->anchor_n = 0;
    hd->body_left = 0;
    hd->body_seen = 0;
    hd->chunk_left = 0;
    hd->chunk_val = 0;
    hd->chunk_dig = 0;
    hd->chunk_st = HTTP_CH_SIZE;
    hd->atline = 1;
}

/* Body bytes, captured or holed: 'D' carries the count and never the payload
 * (РH12). A hole reports here too — the bytes were on the wire and total_len
 * is honest (Р9), so the accounting is exact under any capture budget. */
static void body_add(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct http_dir *hd,
                     __u64 n, __u64 ts)
{
    if (!n)
        return;
    hd->body_seen += n;
    emit(r, c, dir, LK_HTTP_MSG_DATA, n > ~0u ? ~0u : (__u32)n, NULL, 0, 0, ts);
}

/* The message is over: 'E' closes it and the direction goes back to reading a
 * head. len saturates at u32 — 'D' already reported every byte, so this is the
 * convenience total, not the source of truth. */
static void body_end(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct http_dir *hd,
                     __u64 ts)
{
    emit(r, c, dir, LK_HTTP_MSG_END, hd->body_seen > ~0u ? ~0u : (__u32)hd->body_seen, NULL, 0, 0,
         ts);
    hd->body_seen = 0;
    hd->body_left = 0;
    hd->st = HTTP_FR_HEAD;
    hd->atline = 1;
}

/* --- in-flight request FIFO (РH6) ----------------------------------------- */

static void pend_push(struct lk_reasm *r, struct lk_conn *c, struct http_frame *hf, __u8 rq,
                      __u64 ts)
{
    if (hf->pend_n >= LK_HTTP_MAX_INFLIGHT) {
        /* Deeper pipelining than the ring holds. Rather than let responses
         * pair with the wrong requests, every response until the ring drains
         * frames from its own headers alone — which is right for everything
         * except a HEAD, the one case that needs the request. */
        hf->pend_skew = 1;
        note(r, c, LK_DIR_RECV, LK_HTTP_NOTE_PIPELINE_OVER, ts);
        return;
    }
    hf->pend[(hf->pend_head + hf->pend_n) % LK_HTTP_MAX_INFLIGHT] = rq;
    hf->pend_n++;
}

static __u8 pend_pop(struct http_frame *hf)
{
    __u8 v = 0;

    if (hf->pend_n) {
        v = hf->pend[hf->pend_head];
        hf->pend_head = (__u8)((hf->pend_head + 1) % LK_HTTP_MAX_INFLIGHT);
        hf->pend_n--;
        if (!hf->pend_n)
            hf->pend_skew = 0; /* drained: pairing is exact again */
    }
    return hf->pend_skew ? 0 : v;
}

/* --- header block assembly ------------------------------------------------ */

/* Consume bytes up to and including the LF that closes an *empty* line — the
 * end of a header block or of a chunked trailer section. *atline ("the next
 * byte starts a line") carries the machine across event boundaries, so every
 * byte is examined exactly once however the stream is cut up. Bare LF counts
 * as a line end: servers disagree about it and an observer that did not would
 * go blind where the server did not (notes-httpproto.md §"Header fields"). */
static __u32 scan_block(const __u8 *p, __u32 n, __u8 *atline, bool *end)
{
    __u32 i = 0;

    while (i < n) {
        __u8 b = p[i++];

        if (b == '\n') {
            if (*atline) {
                *end = true;
                return i;
            }
            *atline = 1;
        } else if (b != '\r') {
            *atline = 0;
        }
    }
    return n;
}

/* The framing fields, and only those: what is not read cannot leak (РH12).
 * Everything semantic — Host, User-Agent, traceparent — is М3's, read from the
 * very same head bytes this framer publishes in the 'R' / 'S' message. */
struct http_framing {
    __u64 clen;
    bool have_cl;    /* a usable Content-Length was read */
    bool bad_cl;     /* ... or one that must be rejected (RFC 9112 §6.3.4) */
    bool te_present; /* Transfer-Encoding at all */
    bool te_chunked; /* ... and its final encoding is chunked */
    __u8 rq;         /* HTTP_RQ_UP_* from the Upgrade field */
};

/* Two headers on the "of interest" list are deliberately *not* read here, and
 * their absence is a decision rather than an omission: `Connection: close`
 * changes nothing about where this message ends (rule 6 already runs the body
 * to the socket's end), and `Expect: 100-continue` only predicts an interim
 * response the framer recognises generically from its status code. Both are
 * one `http_list_has()` away for М3, which reads them for the session and the
 * span. */
static bool read_fields(struct http_head *h, struct http_framing *fr)
{
    struct http_span name, val;

    while (http_head_field(h, &name, &val)) {
        if (http_span_eq_ci(name, "content-length")) {
            __u64 v;

            if (!http_parse_content_length(val, &v) || (fr->have_cl && v != fr->clen))
                fr->bad_cl = true;
            else {
                fr->clen = v;
                fr->have_cl = true;
            }
        } else if (http_span_eq_ci(name, "transfer-encoding")) {
            /* Only the final encoding of the last field decides the framing
             * (RFC 9112 §6.1), hence assignment rather than accumulation. */
            fr->te_present = true;
            fr->te_chunked = http_span_eq_ci(http_list_last(val), "chunked");
        } else if (http_span_eq_ci(name, "upgrade")) {
            if (http_list_has(val, "websocket"))
                fr->rq |= HTTP_RQ_UP_WS;
            else if (http_list_has(val, "h2c"))
                fr->rq |= HTTP_RQ_UP_H2C;
            else if (val.n)
                fr->rq |= HTTP_RQ_UP_OTHER;
        }
    }
    return !(h->flags & HTTP_HEAD_BAD);
}

/* A head we refuse to frame from. Nothing is published: when two hops can
 * disagree about where this message ends, any length we pick is a guess, and a
 * dropped unit is honest where a guessed one is not (notes-httpproto.md
 * §"Body length"). The direction resyncs on the next start line. */
static void bad_head(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct http_dir *hd,
                     enum lk_http_note n, __u64 ts)
{
    note(r, c, dir, n, ts);
    go_scan(r, c, dir, hd);
}

/* A complete header block: decide what it means and what follows it. `head`
 * points either straight into the capture buffer (the head arrived in one
 * event — the common case, no copy) or into the direction's slab. */
static void head_complete(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                          struct http_frame *hf, const __u8 *head, __u32 len, __u64 ts)
{
    struct http_dir *hd = &hf->d[dir];
    struct http_framing fr = {0};
    struct http_head h;
    struct http_span line;
    __u8 minor = 0;

    http_head_init(&h, head, len);
    if (!http_head_line(&h, &line)) {
        bad_head(r, c, dir, hd, LK_HTTP_NOTE_BAD_HEAD, ts);
        return;
    }

    if (dir == LK_DIR_RECV) {
        struct http_span method = {0}, target = {0};
        enum http_method mid;
        __u8 rq;

        /* The HTTP/2 connection preface is a valid-looking HTTP/1.1 head, and
         * that is exactly why it is checked first: past it lies HPACK, which
         * this agent deliberately does not speak (§8 of the plan). Recognised,
         * named and counted — and with it goes gRPC. */
        if (len >= 14 && !memcmp(head, "PRI * HTTP/2.0", 14)) {
            go_blind(r, c, dir, LK_HTTP_NOTE_BLIND_H2, ts);
            return;
        }
        if (!http_parse_req_line(line, &method, &target, &minor)) {
            bad_head(r, c, dir, hd, LK_HTTP_NOTE_BAD_HEAD, ts);
            return;
        }
        if (!read_fields(&h, &fr)) {
            bad_head(r, c, dir, hd, LK_HTTP_NOTE_FIELD_BAD, ts);
            return;
        }
        if (fr.bad_cl) {
            bad_head(r, c, dir, hd, LK_HTTP_NOTE_CL_BAD, ts);
            return;
        }
        /* CL+TE is the desynchronisation primitive itself, and real servers do
         * not agree on it (М0: nginx/node/gunicorn answer 400, Go answers 200
         * and reads the chunked body). Reject. */
        if (fr.te_present && fr.have_cl) {
            bad_head(r, c, dir, hd, LK_HTTP_NOTE_CL_TE, ts);
            return;
        }
        if (fr.te_present && !fr.te_chunked) {
            bad_head(r, c, dir, hd, LK_HTTP_NOTE_TE_BAD, ts);
            return;
        }
        if ((h.flags & HTTP_HEAD_LF_ONLY) && !hf->lf_noted) {
            hf->lf_noted = 1;
            note(r, c, dir, LK_HTTP_NOTE_LF_ONLY, ts);
        }

        mid = http_method_id(method);
        rq = fr.rq;
        if (mid == HTTP_M_HEAD)
            rq |= HTTP_RQ_HEAD;
        else if (mid == HTTP_M_CONNECT)
            rq |= HTTP_RQ_CONNECT;
        (void)target; /* the route is М4's, off the very bytes emitted below */
        emit(r, c, dir, LK_HTTP_MSG_REQ, len, head, len, 0, hd->head_ts);
        pend_push(r, c, hf, rq, ts);

        if (fr.te_chunked) {
            hd->st = HTTP_FR_CHUNK;
            hd->chunk_st = HTTP_CH_SIZE;
            hd->chunk_val = 0;
            hd->chunk_dig = 0;
        } else if (fr.have_cl && fr.clen) {
            hd->st = HTTP_FR_BODY;
            hd->body_left = fr.clen;
        } else {
            /* Rule 5: a request with no framing header has no body — nothing
             * a server could read, so nothing to skip. */
            body_end(r, c, dir, hd, ts);
        }
        return;
    }

    /* --- response ---------------------------------------------------------- */
    __u16 code = 0;
    __u8 rq;

    if (!http_parse_status_line(line, &code, &minor)) {
        bad_head(r, c, dir, hd, LK_HTTP_NOTE_BAD_HEAD, ts);
        return;
    }
    if (!read_fields(&h, &fr)) {
        bad_head(r, c, dir, hd, LK_HTTP_NOTE_FIELD_BAD, ts);
        return;
    }
    if (fr.bad_cl) {
        bad_head(r, c, dir, hd, LK_HTTP_NOTE_CL_BAD, ts);
        return;
    }
    if (fr.te_present && fr.have_cl) {
        bad_head(r, c, dir, hd, LK_HTTP_NOTE_CL_TE, ts);
        return;
    }
    if ((h.flags & HTTP_HEAD_LF_ONLY) && !hf->lf_noted) {
        hf->lf_noted = 1;
        note(r, c, dir, LK_HTTP_NOTE_LF_ONLY, ts);
    }

    /* 101 is a 1xx that does not behave like one: it ends the unit and hands
     * the socket to another protocol. Which one we only know from the request
     * (websocket / h2c / something else), and the h2c case is why the request
     * alone must never be treated as a blind zone — measured, none of the four
     * М0 servers accepts the upgrade (README, item 4). */
    if (code == 101) {
        rq = pend_pop(hf);
        emit(r, c, dir, LK_HTTP_MSG_RESP, len, head, len, 0, hd->head_ts);
        body_end(r, c, dir, hd, ts);
        (void)rq;
        go_blind(r, c, dir, LK_HTTP_NOTE_BLIND_UPGRADE, ts);
        return;
    }
    if (code < 200) {
        /* Any other 1xx (100 Continue, 103 Early Hints): head only, never a
         * body, and it does not close the unit — the request it belongs to is
         * still in flight, so the FIFO is left alone. */
        emit(r, c, dir, LK_HTTP_MSG_INTER, len, head, len, 0, hd->head_ts);
        hd->atline = 1;
        return;
    }

    rq = pend_pop(hf);
    emit(r, c, dir, LK_HTTP_MSG_RESP, len, head, len, 0, hd->head_ts);

    if ((rq & HTTP_RQ_CONNECT) && code < 300) {
        body_end(r, c, dir, hd, ts);
        go_blind(r, c, dir, LK_HTTP_NOTE_BLIND_CONNECT, ts);
        return;
    }
    /* Rule 1: responses that cannot carry a body whatever their headers say.
     * Reading a HEAD response's Content-Length as a body length desynchronises
     * the connection for every request that follows — which is precisely why
     * the corpus has a `head` trace per server. */
    if ((rq & HTTP_RQ_HEAD) || code == 204 || code == 304) {
        body_end(r, c, dir, hd, ts);
        return;
    }
    if (fr.te_chunked) {
        hd->st = HTTP_FR_CHUNK;
        hd->chunk_st = HTTP_CH_SIZE;
        hd->chunk_val = 0;
        hd->chunk_dig = 0;
    } else if (fr.te_present) {
        hd->st = HTTP_FR_CLOSE; /* a non-chunked final encoding: length unknown */
    } else if (fr.have_cl) {
        if (fr.clen)
            hd->st = HTTP_FR_BODY, hd->body_left = fr.clen;
        else
            body_end(r, c, dir, hd, ts);
    } else {
        hd->st = HTTP_FR_CLOSE; /* rule 6: the body runs until the socket does */
    }
}

/* Feed bytes into the header block being assembled. Returns how many were
 * consumed; may leave the direction in any state. */
static __u32 head_feed(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                       struct http_frame *hf, const __u8 *p, __u32 n, __u64 ts)
{
    struct http_dir *hd = &hf->d[dir];
    struct lk_frame *f = &c->frame[dir];
    bool end = false;
    __u32 i = 0, k;

    if (f->buf_len == 0) {
        /* RFC 9112 §2.2: a recipient may ignore empty lines before a start
         * line, and clients do send them. Stripping them here also keeps the
         * empty-line scanner from reading the very first byte as a block end. */
        while (i < n && (p[i] == '\r' || p[i] == '\n'))
            i++;
        if (i == n)
            return n;
        hd->head_ts = ts; /* the event of the head's first byte (Р13) */
        hd->atline = 1;
    }
    k = scan_block(p + i, n - i, &hd->atline, &end);

    /* A header block over the message ceiling is corruption or an attack, not
     * a fat cookie jar: a real one is 63 B .. 1 KB (М0 measured), and 16 KB is
     * already four times what nginx will accept by default. */
    if ((__u64)f->buf_len + k > LK_MSG_BODY_MAX) {
        bad_head(r, c, dir, hd, LK_HTTP_NOTE_HEAD_TOO_BIG, ts);
        return i;
    }
    if (!end) {
        if (!f->buf) {
            f->buf = lk_reasm_buf_get(r);
            if (!f->buf) {
                bad_head(r, c, dir, hd, LK_HTTP_NOTE_NO_MEM, ts);
                return i;
            }
        }
        memcpy(f->buf + f->buf_len, p + i, k);
        f->buf_len += k;
        return i + k;
    }
    if (f->buf_len == 0) {
        /* The whole head arrived in one event: publish it straight out of the
         * capture buffer, no copy on the hot path. */
        head_complete(r, c, dir, hf, p + i, k, ts);
    } else {
        memcpy(f->buf + f->buf_len, p + i, k);
        f->buf_len += k;
        head_complete(r, c, dir, hf, f->buf, f->buf_len, ts);
        if (f->buf) { /* head_complete may have resynced and released it */
            lk_reasm_buf_put(r, f->buf);
            f->buf = NULL;
            f->buf_len = 0;
        }
    }
    return i + k;
}

/* --- chunked bodies ------------------------------------------------------- */

static void chunk_size_done(struct http_dir *hd)
{
    hd->chunk_dig = 0;
    if (hd->chunk_val == 0) {
        hd->chunk_st = HTTP_CH_TRAILER; /* last chunk: trailers, then the end */
        hd->atline = 1;
    } else {
        hd->chunk_left = hd->chunk_val;
        hd->chunk_st = HTTP_CH_DATA;
    }
    hd->chunk_val = 0;
}

static __u32 chunk_feed(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                        struct http_frame *hf, const __u8 *p, __u32 n, __u64 ts)
{
    struct http_dir *hd = &hf->d[dir];
    __u32 i = 0;

    while (i < n && hd->st == HTTP_FR_CHUNK) {
        char b = (char)p[i];

        switch (hd->chunk_st) {
        case HTTP_CH_SIZE: {
            int v = http_hex_val(b);

            if (v >= 0) {
                /* 16 hex digits is the u64 ceiling; more is not a big chunk,
                 * it is a stream we have lost the thread of. */
                if (hd->chunk_dig >= 16) {
                    bad_head(r, c, dir, hd, LK_HTTP_NOTE_CHUNK_BAD, ts);
                    return i;
                }
                hd->chunk_val = hd->chunk_val * 16 + (__u64)v;
                hd->chunk_dig++;
                i++;
            } else if (hd->chunk_dig && b == ';') {
                hd->chunk_st = HTTP_CH_EXT;
                i++;
            } else if (hd->chunk_dig && b == '\r') {
                hd->chunk_st = HTTP_CH_SIZE_LF;
                i++;
            } else if (hd->chunk_dig && b == '\n') {
                i++;
                chunk_size_done(hd);
            } else {
                bad_head(r, c, dir, hd, LK_HTTP_NOTE_CHUNK_BAD, ts);
                return i;
            }
            break;
        }
        case HTTP_CH_EXT: /* chunk-ext is never read, only skipped */
            if (b == '\r') {
                hd->chunk_st = HTTP_CH_SIZE_LF;
                i++;
            } else if (b == '\n') {
                i++;
                chunk_size_done(hd);
            } else {
                i++;
            }
            break;
        case HTTP_CH_SIZE_LF:
            if (b != '\n') {
                bad_head(r, c, dir, hd, LK_HTTP_NOTE_CHUNK_BAD, ts);
                return i;
            }
            i++;
            chunk_size_done(hd);
            break;
        case HTTP_CH_DATA: {
            __u64 avail = n - i;
            __u64 take = hd->chunk_left < avail ? hd->chunk_left : avail;

            /* 'D' reports *decoded* body bytes, not the chunk framing around
             * them, so a chunked body and a Content-Length one of the same
             * size report the same number of bytes. */
            body_add(r, c, dir, hd, take, ts);
            hd->chunk_left -= take;
            i += (__u32)take;
            if (!hd->chunk_left)
                hd->chunk_st = HTTP_CH_DATA_EOL;
            break;
        }
        case HTTP_CH_DATA_EOL:
            if (b == '\r') {
                i++;
            } else if (b == '\n') {
                i++;
                hd->chunk_st = HTTP_CH_SIZE;
                hd->chunk_val = 0;
                hd->chunk_dig = 0;
            } else {
                bad_head(r, c, dir, hd, LK_HTTP_NOTE_CHUNK_BAD, ts);
                return i;
            }
            break;
        case HTTP_CH_TRAILER: {
            bool end = false;

            /* Trailer fields are found, not read: their contents are as
             * private as any other header (РH12). */
            i += scan_block(p + i, n - i, &hd->atline, &end);
            if (end)
                body_end(r, c, dir, hd, ts);
            break;
        }
        default:
            bad_head(r, c, dir, hd, LK_HTTP_NOTE_CHUNK_BAD, ts);
            return i;
        }
    }
    return i;
}

/* --- resync (Р10 for HTTP: the strongest anchors of the three protocols) --- */

/* The request anchor alphabet: the known methods plus their separating space.
 * Deliberately the same short list as http_method_id — WebDAV verbs parse
 * fine, they are simply not anchors (notes-httpproto.md §"Start lines"). */
static const char *const http_req_anchors[] = {
    "GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH ",
};

/* Can these k bytes still become an anchor, and are they one already? The
 * response form is `HTTP/1.[01] SP [1-5][0-9][0-9]` — anchored at the line
 * start with constrained digits, which is what makes it stronger than anything
 * PG or MySQL offer. */
static bool anchor_ok(enum lk_dir dir, const __u8 *a, __u32 k, bool *full)
{
    *full = false;
    if (!k)
        return true;
    if (dir == LK_DIR_RECV) {
        bool any = false;

        for (unsigned i = 0; i < sizeof(http_req_anchors) / sizeof(http_req_anchors[0]); i++) {
            size_t l = strlen(http_req_anchors[i]);

            if (k <= l && !memcmp(a, http_req_anchors[i], k)) {
                any = true;
                if (k == l)
                    *full = true;
            }
        }
        return any;
    }
    for (__u32 i = 0; i < k; i++) {
        char b = (char)a[i];
        bool ok;

        if (i < 7)
            ok = b == "HTTP/1."[i];
        else if (i == 7)
            ok = b == '0' || b == '1';
        else if (i == 8)
            ok = b == ' ';
        else if (i == 9)
            ok = b >= '1' && b <= '5';
        else
            ok = http_is_digit(b);
        if (!ok)
            return false;
    }
    *full = k == LK_HTTP_ANCHOR_MAX;
    return true;
}

/* Sliding anchor search over a dirty direction. The match survives event
 * boundaries (like PG's 'Z' anchor) because the candidate bytes are kept, and
 * keeping them is also what lets framing resume *at the start line* rather than
 * after it: on a hit the matched bytes are fed straight back into the head
 * assembler, so the method and the target are not lost with the anchor.
 *
 * A false positive — "GET " inside a body, an HTML page quoting HTTP — costs
 * one wrongly-framed head, which then fails the start-line parse and returns
 * here. That is the documented, counted price of scanning text. */
static __u32 scan_feed(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                       struct http_frame *hf, const __u8 *p, __u32 n, __u64 ts)
{
    struct http_dir *hd = &hf->d[dir];
    __u32 i = 0;

    while (i < n) {
        bool full = false;

        hd->anchor[hd->anchor_n++] = p[i++];
        for (;;) {
            full = false;
            if (!hd->anchor_n || anchor_ok(dir, hd->anchor, hd->anchor_n, &full))
                break;
            hd->anchor_n--;
            memmove(hd->anchor, hd->anchor + 1, hd->anchor_n);
        }
        if (hd->anchor_n >= LK_HTTP_ANCHOR_MAX && !full) {
            hd->anchor_n = 0; /* unreachable by construction; never overrun */
            continue;
        }
        if (full) {
            __u8 anchor[LK_HTTP_ANCHOR_MAX];
            __u32 k = hd->anchor_n;

            memcpy(anchor, hd->anchor, k);
            hd->anchor_n = 0;
            hd->st = HTTP_FR_HEAD;
            lk_reasm_resync(r, c, dir); /* leaves LK_FR_DIRTY, stamps the next msg */
            head_feed(r, c, dir, hf, anchor, k, ts);
            return i;
        }
    }
    return i;
}

/* --- the two vtable hooks ------------------------------------------------- */

/* Framing is impossible without state: say so once, count it as a blind zone
 * and stop, rather than emit boundaries we cannot stand behind. */
static bool http_no_state(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, __u64 ts)
{
    if (c->frame_state)
        return false;
    go_blind(r, c, dir, LK_HTTP_NOTE_NO_MEM, ts);
    return true;
}

/* HTTPS: a TLS record where a start line should be (М7, РH13). Unlike PG and
 * MySQL, HTTP has no in-band negotiation to watch — TLS sits under it, so the
 * very first bytes of the socket are already a handshake record and the framer
 * would otherwise spend the connection scanning ciphertext for a method name.
 *
 * The test is deliberately narrow: only the first bytes of a direction, only a
 * handshake record (0x16) of a TLS 1.x version, and only the message type that
 * belongs on that side. A false positive would silence a real plaintext
 * connection; these five bytes cannot occur at the head of an HTTP/1.x message,
 * which must begin with a token or "HTTP/1.".
 *
 * Marking the connection LK_CONN_TLS is what puts it on the same footing as an
 * encrypted PG or MySQL session: ciphertext socket events are dropped rather
 * than framed, the plaintext channel (libssl or Go uprobes) feeds the framer
 * instead, and if no uprobes are attached the connection is honestly counted as
 * TLS-but-unread rather than parsed into garbage. */
static bool tls_record_head(enum lk_dir dir, const struct http_dir *hd, const __u8 *p, __u32 n)
{
    if (hd->events != 1 || hd->st != HTTP_FR_HEAD || n < 3)
        return false;
    if (p[0] != 0x16 || p[1] != 0x03 || p[2] > 0x04)
        return false; /* not a handshake record of SSL 3.0 / TLS 1.0..1.3 */
    if (n >= 6 && p[5] != (dir == LK_DIR_RECV ? 0x01 : 0x02))
        return false; /* handshake, but neither ClientHello nor ServerHello */
    return true;
}

static void http_stream_bytes(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, const __u8 *p,
                              __u32 n, __u64 ts_ns)
{
    struct http_frame *hf = http_frame_get(c);
    struct http_dir *hd;

    if (!hf) {
        http_no_state(r, c, dir, ts_ns);
        return;
    }
    hd = &hf->d[dir];
    hd->events++;
    hd->off += n;
    hd->last_ts = ts_ns;

    if (tls_record_head(dir, hd, p, n)) {
        note(r, c, dir, LK_HTTP_NOTE_TLS, ts_ns);
        c->flags |= LK_CONN_TLS;
        return; /* the rest of this chunk is ciphertext, and so is the stream */
    }

    /* Loss dirties both directions before the bytes ever reach us (the conn
     * table's seq detector; a lazily created or synthetic entry starts that
     * way). Whatever was being assembled cannot be finished honestly. */
    if (c->frame[dir].st == LK_FR_DIRTY && hd->st != HTTP_FR_SCAN)
        go_scan(r, c, dir, hd);

    /* РH4, the `sendfile` degradation: the head promised a body, not one byte
     * of it came through the socket, and here is the next status line. Since
     * ~6.5 the kernel routes splice through sendmsg and this never fires (М0
     * recon item 1) — before that conversion it was how every static file
     * looked, and 5.15 is in the support matrix. The unit closes here with the
     * bytes we saw, which is a lower bound, and says so. */
    if (dir == LK_DIR_SEND && hd->st == HTTP_FR_BODY && hd->body_seen == 0 && n >= 9 &&
        !memcmp(p, "HTTP/1.", 7) && (p[7] == '0' || p[7] == '1') && p[8] == ' ') {
        note(r, c, dir, LK_HTTP_NOTE_BODY_UNSEEN, ts_ns);
        body_end(r, c, dir, hd, ts_ns);
    }

    while (n) {
        __u8 st0 = hd->st;
        __u32 used;

        switch (hd->st) {
        case HTTP_FR_HEAD:
            used = head_feed(r, c, dir, hf, p, n, ts_ns);
            break;
        case HTTP_FR_BODY: {
            __u64 take = hd->body_left < n ? hd->body_left : n;

            body_add(r, c, dir, hd, take, ts_ns);
            hd->body_left -= take;
            used = (__u32)take;
            if (!hd->body_left)
                body_end(r, c, dir, hd, ts_ns);
            break;
        }
        case HTTP_FR_CHUNK:
            used = chunk_feed(r, c, dir, hf, p, n, ts_ns);
            break;
        case HTTP_FR_CLOSE:
            body_add(r, c, dir, hd, n, ts_ns);
            used = n;
            break;
        case HTTP_FR_SCAN:
            used = scan_feed(r, c, dir, hf, p, n, ts_ns);
            break;
        default:
            return;
        }
        if (c->flags & LK_CONN_IGNORE)
            return; /* a blind zone opened: the rest of this chunk is not ours */
        if (!used && hd->st == st0)
            return; /* defensive: a parked machine must not spin */
        p += used;
        n -= used;
    }
}

/* A hole is bytes we will never see: the uncaptured tail of a call (the
 * per-call budget, РH14), a lost ringbuf event, a missing off-interval. What it
 * costs depends entirely on where it lands — the four degradations of РH4. */
static void http_stream_hole(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, __u64 n)
{
    struct http_frame *hf = http_frame_get(c);
    struct lk_frame *f = &c->frame[dir];
    struct http_dir *hd;
    __u64 ts;

    if (!hf) {
        http_no_state(r, c, dir, 0);
        return;
    }
    if (!n)
        return;
    hd = &hf->d[dir];
    hd->holes++;
    hd->off += n;
    ts = hd->last_ts;

    if (f->st == LK_FR_DIRTY && hd->st != HTTP_FR_SCAN) {
        go_scan(r, c, dir, hd);
        return;
    }

    switch (hd->st) {
    case HTTP_FR_HEAD:
        /* The rest of this header block is gone, so the body boundary is
         * unknowable and the direction must resync. What did arrive is still
         * published, flagged as a prefix: the start line and the first fields
         * come first and carry the method, the route and the framing fields —
         * a head longer than the capture budget is a normal outcome, not an
         * error (РH14, and the `huge-head-cap2048` traces). */
        if (f->buf_len)
            emit(r, c, dir, dir == LK_DIR_RECV ? LK_HTTP_MSG_REQ : LK_HTTP_MSG_RESP, f->buf_len,
                 f->buf, f->buf_len, LK_MSG_BODY_TRUNC, hd->head_ts);
        note(r, c, dir, LK_HTTP_NOTE_HEAD_HOLE, ts);
        go_scan(r, c, dir, hd);
        break;
    case HTTP_FR_BODY: {
        /* The length is known, so the hole is skipped arithmetically and costs
         * nothing — the case the whole design is built around. */
        __u64 take = hd->body_left < n ? hd->body_left : n;

        body_add(r, c, dir, hd, take, ts);
        hd->body_left -= take;
        n -= take;
        if (!hd->body_left)
            body_end(r, c, dir, hd, ts);
        if (n) { /* ... unless it ran past the body into the next head */
            note(r, c, dir, LK_HTTP_NOTE_HEAD_HOLE, ts);
            go_scan(r, c, dir, hd);
        }
        break;
    }
    case HTTP_FR_CHUNK:
        /* The sizes live in the byte stream: one lost chunk header and every
         * byte after it is misread. The unit is dropped, not mis-attributed. */
        note(r, c, dir, LK_HTTP_NOTE_CHUNK_HOLE, ts);
        go_scan(r, c, dir, hd);
        break;
    case HTTP_FR_CLOSE:
        body_add(r, c, dir, hd, n, ts);
        break;
    case HTTP_FR_SCAN:
        hd->anchor_n = 0; /* an anchor cannot span a hole */
        break;
    default:
        break;
    }
}

/* --- masking the shown head (РH3/РH12, М6) --------------------------------- */

/* The four headers that carry a credential rather than a description of one.
 * `Cookie` is on the list for the same reason as `Authorization`: a session
 * cookie *is* the session, and anyone holding the bytes holds the account. */
static bool header_is_secret(struct http_span name)
{
    return http_span_eq_ci(name, "authorization") || http_span_eq_ci(name, "cookie") ||
           http_span_eq_ci(name, "set-cookie") || http_span_eq_ci(name, "proxy-authorization");
}

/* The offset of a span inside the caller's copy, or n when it is not in it —
 * which cannot happen, since every span here came out of this very buffer. */
static size_t span_off(const __u8 *base, __u32 n, struct http_span s)
{
    size_t off = (size_t)(s.p - (const char *)base);

    return (!s.p || off > n || s.n > n - off) ? n : off;
}

/* Blank a span of the caller's copy. Same length, so every offset in the
 * hexdump beside it still points where it did on the wire. */
static void blank(__u8 *base, __u32 n, struct http_span s)
{
    size_t off = span_off(base, n, s);

    if (off < n)
        memset(base + off, '*', s.n);
}

/* РH12's query redaction, applied to a span of the copy. */
static void blank_query(__u8 *base, __u32 n, struct http_span s)
{
    size_t off = span_off(base, n, s);

    if (off < n)
        lk_url_redact_inplace((char *)base + off, s.n);
}

/* Hide the two kinds of secret a head carries before it is *displayed*
 * (`--messages --hexdump`, lkt_messages): the credential headers, and the query
 * values РH12 redacts everywhere else. Only heads are touched — a 'D'/'E'/'!'
 * message has no bytes at all (РH3), bodies are never captured, and there is
 * nothing else in the dictionary.
 *
 * Deliberately *not* done at framing time. The framer publishes the head as it
 * arrived because the handler above it still has to read `Authorization` when
 * `--http-user basic` asks for the name half; masking there would make the flag
 * silently do nothing. So this runs on the viewer's own copy, at the point where
 * bytes turn into output, which is also the only place where the question "who
 * will read this" has an answer. */
static void http_mask_body(const struct lk_msg *m, __u8 *p, __u32 n)
{
    struct http_head h;
    struct http_span line, name, val;

    if (!p || !n)
        return;
    if (m->type != LK_HTTP_MSG_REQ && m->type != LK_HTTP_MSG_RESP && m->type != LK_HTTP_MSG_INTER)
        return;
    http_head_init(&h, p, n);
    if (!http_head_line(&h, &line))
        return;
    /* The start line of a request holds the target, and a target holds
     * `?token=…` as often as a header holds a bearer. Only the target span is
     * handed to the redactor, not the whole line: everything after it is
     * ` HTTP/1.1`, and a redactor told to treat that as the tail of a query
     * value would blank the version — a masked head that no longer shows its own
     * framing is a poor trade for hiding one more byte. */
    if (m->type == LK_HTTP_MSG_REQ) {
        struct http_span method, target;
        __u8 minor;

        if (http_parse_req_line(line, &method, &target, &minor) && target.n)
            blank_query(p, n, target);
    }
    while (http_head_field(&h, &name, &val))
        if (header_is_secret(name))
            blank(p, n, val);
}

const struct lk_proto_ops lk_proto_http_ops = {
    .name = "http",
    /* db_system stays NULL: HTTP is not a database, and otel_kind is what
     * tells the span builder so (РH11; М6 acts on it). */
    .otel_kind = LK_OTEL_KIND_HTTP,
    .profile = LK_PROTO_PROF_HTTP, /* latkit_http_* rather than latkit_query_* (РH10) */
    .role = LK_ROLE_SERVER,        /* v1 observes servers only (РH2) */
    .flags = LK_PROTO_F_STREAM,
    .sql_dialect = LK_SQL_PG, /* unused: nothing here reaches the SQL normaliser */
    /* The base flavour: heuristic route templating (РH7). The S3 entry
     * (PLAN-MINIO.md РS1) is this same framer and handler with another dialect
     * hanging here — that is the whole of what "a dialect, not a fork" means. */
    .dialect = &lk_http_dialect_base,
    /* РH14: heads are all this framer reads — the body is arithmetic — so an
     * HTTP port defaults to a quarter of the DB budget. `--port 8080=http:N`
     * overrides it; --capture-limit caps it. */
    .cap_limit = LK_HTTP_CAPTURE_LIMIT,
    .proto_new = lk_proto_http_new,
    /* The message-framing hooks (hdr_size, parse_hdr, pre_emit, both
     * intercept_ and both resync_) stay NULL: in stream mode the two hooks
     * above are the machine. */
    .stream_bytes = http_stream_bytes,
    .stream_hole = http_stream_hole,
    .mask_body = http_mask_body,
};
