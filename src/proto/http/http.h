/* SPDX-License-Identifier: GPL-2.0 */
/* Internals shared by the HTTP/1.x framer (http_frame.c) and handler (http.c),
 * the way pg.h / my.h serve their protocols. Not included by the core: the
 * outside world sees only lk_proto_http_ops and lk_proto_http_new (proto.h).
 *
 * PLAN-HTTP.md М2 fills in the framer the М1 seam left as a stub: the
 * direction machine (head → body → head), the body-length decision list of
 * РH4, the blind zones and the textual resync anchors. The handler is still
 * М3's — it tallies here and emits no observations.
 *
 * The split of state is the one М1 set up and the stages after this rely on:
 * *framing* state lives in lk_conn.frame_state (struct http_frame below, one
 * flat allocation freed by the connection table), *semantic* state in
 * lk_conn.proto_state (struct http_conn, freed by the handler). The bulk
 * scratch — the header block being assembled — is neither: it lives in
 * lk_frame.buf, drawn from the reassembly slab pool, so Р11's memory bound
 * covers it and the connection table frees it on every removal path. */
#ifndef LATKIT_HTTP_H
#define LATKIT_HTTP_H

#include "http_wire.h"
#include "proto.h"

/* --- the synthetic message dictionary (РH3) ------------------------------- */
/* HTTP has no messages in the PG/MySQL sense, so the framer invents five and
 * publishes them as ordinary lk_msg — that is what keeps --messages, the
 * replay harness, fuzz_pipe and the handler contract unchanged (РH1).
 *
 *   'R' request head    body = the whole header block, start line first, and
 *                       len == body_cap == its length. LK_MSG_BODY_TRUNC means
 *                       something different here than in the message mode:
 *                       there is no length field on the wire to compare
 *                       against, so it reads "the block never terminated — a
 *                       capture hole ate the rest, its real length is unknown
 *                       and larger" (РH14, the normal outcome for a head bigger
 *                       than the per-call budget)
 *   'S' response head   likewise, status line first
 *   'I' interim head    a 1xx response: head only, never a body, does NOT
 *                       close the unit (notes-httpproto.md §"Interim")
 *   'D' body data       len = body bytes accounted by this message, body = NULL:
 *                       payload is deliberately not carried (РH12 — bodies are
 *                       never read). Holes are reported here too: the bytes were
 *                       on the wire, we simply did not capture them, and
 *                       total_len is honest (Р9), so byte accounting stays exact
 *                       under any capture budget
 *   'E' body end        len = the message's total body size, saturated at u32;
 *                       every 'R'/'S' is followed by exactly one 'E' unless the
 *                       body runs until the connection closes (rule 6 of the
 *                       decision list), where CONN_CLOSE is the end and М3 owns it
 *   '!' framer note     len = enum lk_http_note; body = NULL. Degradations and
 *                       blind zones the framer recognises, in the message stream
 *                       rather than in a side channel: they are visible in
 *                       --messages, replayable, and the handler turns them into
 *                       counters without the framer needing a stats object */
#define LK_HTTP_MSG_REQ   'R'
#define LK_HTTP_MSG_RESP  'S'
#define LK_HTTP_MSG_INTER 'I'
#define LK_HTTP_MSG_DATA  'D'
#define LK_HTTP_MSG_END   'E'
#define LK_HTTP_MSG_NOTE  '!'

/* Note codes, carried in lk_msg.len of a '!' message. Everything up to
 * LK_HTTP_NOTE_BLIND_H2 is a degradation of one message or one direction;
 * from there on the whole connection becomes a blind zone (LK_CONN_IGNORE)
 * and nothing more is framed on it until CONN_CLOSE (РH4). */
enum lk_http_note {
    LK_HTTP_NOTE_BAD_HEAD = 1,  /* start line is not HTTP/1.x-shaped */
    LK_HTTP_NOTE_FIELD_BAD,     /* obs-fold / space before colon / no colon */
    LK_HTTP_NOTE_HEAD_TOO_BIG,  /* header block over LK_MSG_BODY_MAX */
    LK_HTTP_NOTE_HEAD_HOLE,     /* capture hole where a header block was */
    LK_HTTP_NOTE_CL_TE,         /* Content-Length *and* Transfer-Encoding */
    LK_HTTP_NOTE_CL_BAD,        /* unparsable or conflicting Content-Length */
    LK_HTTP_NOTE_TE_BAD,        /* request body framed by a non-chunked TE */
    LK_HTTP_NOTE_CHUNK_BAD,     /* malformed chunk-size line */
    LK_HTTP_NOTE_CHUNK_HOLE,    /* hole inside a chunked body (РH4) */
    LK_HTTP_NOTE_LF_ONLY,       /* bare-LF line endings (once per connection) */
    LK_HTTP_NOTE_PIPELINE_OVER, /* more in-flight requests than the ring holds */
    LK_HTTP_NOTE_BODY_UNSEEN,   /* body promised, none on the socket (РH4) */
    LK_HTTP_NOTE_NO_MEM,        /* framer state allocation failed */
    LK_HTTP_NOTE_BLIND_H2,      /* HTTP/2 preface: h2, hence gRPC, is out of scope */
    LK_HTTP_NOTE_BLIND_UPGRADE, /* 101 Switching Protocols: websocket, h2c, ... */
    LK_HTTP_NOTE_BLIND_CONNECT, /* CONNECT answered 2xx: the rest is a tunnel */
    LK_HTTP_NOTE_MAX
};

/* The three blind-zone codes are contiguous and last, so "did the connection
 * just go blind" is a range test rather than a switch anyone can forget to
 * extend. */
#define LK_HTTP_NOTE_IS_BLIND(n) ((n) >= LK_HTTP_NOTE_BLIND_H2 && (n) < LK_HTTP_NOTE_MAX)

/* Notes that mean "a field on the wire was rejected as corrupt" — the handler
 * routes exactly these to latkit_parse_errors_total, so the М2 acceptance
 * criterion (parse_errors == 0 over the clean М0 traces) measures what it
 * claims to. The rest are degradations of capture, not of the input. */
#define LK_HTTP_NOTE_IS_PARSE_ERR(n)                                                               \
    ((n) == LK_HTTP_NOTE_BAD_HEAD || (n) == LK_HTTP_NOTE_FIELD_BAD ||                              \
     (n) == LK_HTTP_NOTE_HEAD_TOO_BIG || (n) == LK_HTTP_NOTE_CL_TE ||                              \
     (n) == LK_HTTP_NOTE_CL_BAD || (n) == LK_HTTP_NOTE_TE_BAD || (n) == LK_HTTP_NOTE_CHUNK_BAD)

/* --- framing state (lk_conn.frame_state, РH1) ----------------------------- */

/* Per-direction machine. The three body states are the three framing shapes of
 * the decision list (notes-httpproto.md §"Body length"): a length known in
 * advance (the common case, skipped arithmetically and therefore immune to
 * capture holes), chunk sizes living in the byte stream (a hole is fatal), and
 * a body that ends only when the connection does. HTTP_FR_SCAN is the dirty
 * state; it is kept in lock-step with lk_frame.st == LK_FR_DIRTY so the
 * connection table's seq detector and the framer's own losses share one flag. */
enum http_fr_st {
    HTTP_FR_HEAD = 0, /* assembling a header block, up to the empty line */
    HTTP_FR_BODY,     /* Content-Length known: arithmetic skip of body_left */
    HTTP_FR_CHUNK,    /* Transfer-Encoding: chunked */
    HTTP_FR_CLOSE,    /* body until CONN_CLOSE (no length, no chunking) */
    HTTP_FR_SCAN,     /* sync lost: scanning for the next start line */
};

/* Sub-state inside a chunked body. The size line is parsed digit by digit
 * rather than buffered — chunk sizes are the one part of HTTP that repeats
 * every few kilobytes, and an accumulator per direction would cost memory on
 * every connection to parse a five-byte line. */
enum http_chunk_st {
    HTTP_CH_SIZE = 0, /* hex digits of chunk-size */
    HTTP_CH_EXT,      /* ";" chunk-ext, discarded up to the line end */
    HTTP_CH_SIZE_LF,  /* the LF closing the size line */
    HTTP_CH_DATA,     /* chunk-data: exactly chunk_left bytes */
    HTTP_CH_DATA_EOL, /* the CRLF closing chunk-data */
    HTTP_CH_TRAILER,  /* trailer section, ends at the empty line */
};

/* Longest resync anchor: "HTTP/1.1 200" (the response one). The request anchor
 * is a method token plus its space, all shorter than this. */
#define LK_HTTP_ANCHOR_MAX 12

struct http_dir {
    __u8 st;                         /* enum http_fr_st */
    __u8 chunk_st;                   /* enum http_chunk_st */
    __u8 chunk_dig;                  /* hex digits seen in the current size line */
    __u8 atline;                     /* block scanner: the next byte starts a line */
    __u8 anchor_n;                   /* bytes of a candidate resync anchor matched so far */
    __u8 anchor[LK_HTTP_ANCHOR_MAX]; /* ... and the bytes, re-injected on a hit */
    __u64 body_left;                 /* HTTP_FR_BODY: body bytes still unaccounted */
    __u64 body_seen;                 /* body bytes accounted for the current message */
    __u64 chunk_left;                /* HTTP_FR_CHUNK: data bytes left in this chunk */
    __u64 chunk_val;                 /* ... size being parsed */
    __u64 head_ts;                   /* event of the first byte of the head being assembled */
    __u64 last_ts;                   /* most recent event on this direction (holes borrow it) */
    __u64 off;                       /* bytes fed to the framer, captured or holed */
    __u64 events;                    /* capture events seen */
    __u64 holes;                     /* holes seen */
};

/* In-flight requests the response direction has to match against. HTTP/1.1
 * pipelining is ordered, so a FIFO is enough; the depth is generous next to
 * what real clients do (the М0 `pipelined` traces are four deep) because the
 * cost of overflowing it is a note and a degraded stretch, not a wrong answer. */
#define LK_HTTP_MAX_INFLIGHT 16

/* What the response direction needs to know about the request it answers
 * (notes-httpproto.md §"Body length", rules 1-2). */
#define HTTP_RQ_HEAD     (1 << 0) /* a HEAD: the response's Content-Length lies */
#define HTTP_RQ_CONNECT  (1 << 1) /* a CONNECT: a 2xx turns the rest into a tunnel */
#define HTTP_RQ_UP_WS    (1 << 2) /* Upgrade: websocket */
#define HTTP_RQ_UP_H2C   (1 << 3) /* Upgrade: h2c */
#define HTTP_RQ_UP_OTHER (1 << 4) /* Upgrade: anything else */
#define HTTP_RQ_UPGRADE  (HTTP_RQ_UP_WS | HTTP_RQ_UP_H2C | HTTP_RQ_UP_OTHER)

/* Stream-framer state — the owner of lk_conn.frame_state (РH1). One flat
 * allocation covering both directions, allocated lazily on the connection's
 * first captured bytes and freed by the connection table on every removal
 * path; nothing inside may own a pointer (see conn_table.h). Bulk scratch —
 * the header-block accumulator — goes into lk_frame.buf, drawn from the
 * reassembly slab pool so Р11's memory bound still holds.
 *
 * Its size is worth watching, because it is per connection and the table's
 * ceiling is 65536: 216 bytes next to lk_conn's own 296, allocated only for
 * connections that actually carry bytes. The worst case adds ~14 MB to a table
 * that already costs ~19 MB — proportionate, and bounded by the same max_conns
 * knob rather than by anything a client can inflate. */
struct http_frame {
    struct http_dir d[2]; /* index: enum lk_dir */
    __u8 pend[LK_HTTP_MAX_INFLIGHT];
    __u8 pend_head, pend_n;
    __u8 pend_skew; /* the ring overflowed: request/response pairing is off, so
                       every later response frames from its own headers only */
    __u8 lf_noted;  /* the bare-LF note has been emitted for this connection */
};

/* --- handler state (lk_conn.proto_state, Р15) ----------------------------- */

/* Per-connection handler state, allocated lazily on the first message and
 * freed in on_conn_close. М3 grows the unit ring and the four timings here. */
struct http_conn {
    __u64 msgs;    /* messages dispatched on this connection */
    bool degraded; /* joined mid-session (synthetic entry, or after a resync):
                      the next head is the first trustworthy boundary, so no
                      unit may open before it (М3 acts on this; М2 only
                      records it) */
};

#endif /* LATKIT_HTTP_H */
