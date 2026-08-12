/* SPDX-License-Identifier: GPL-2.0 */
/* Internals shared by the HTTP/1.x framer (http_frame.c) and handler (http.c),
 * the way pg.h / my.h serve their protocols. Not included by the core: the
 * outside world sees only lk_proto_http_ops and lk_proto_http_new (proto.h).
 *
 * PLAN-HTTP.md М2 filled in the framer the М1 seam left as a stub — the
 * direction machine (head → body → head), the body-length decision list of РH4,
 * the blind zones and the textual resync anchors — М3 the handler above it (the
 * in-flight ring, the four timings of РH5, the two head parsers), and М4 the one
 * step between a unit and a label: the dialect that turns a request into a route
 * (http_route.c, РH7/РH8).
 *
 * The split of state is the one М1 set up and the stages after this rely on:
 * *framing* state lives in lk_conn.frame_state (struct http_frame below, one
 * flat allocation freed by the connection table), *semantic* state in
 * lk_conn.proto_state (struct http_conn, freed by the handler). The bulk
 * scratch — the header block being assembled — is neither: it lives in
 * lk_frame.buf, drawn from the reassembly slab pool, so Р11's memory bound
 * covers it and the connection table frees it on every removal path.
 *
 * The two never share an understanding of a head. The framer reads a head to
 * decide where the body ends; the handler reads the same bytes again to decide
 * what to report about it. That is a deliberate second parse of a few hundred
 * bytes per exchange: a shared mutable view of the same head is how the two
 * would drift apart under a degradation, which is the one situation where the
 * framing must stay right whatever the labels do. */
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
    LK_HTTP_NOTE_TLS,           /* a TLS record where a request line belongs (М7) */
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

/* Bounds on what a unit copies out of a head. Everything here is a *label* or a
 * span attribute, so the ceilings are set by what a label may usefully be, not
 * by what HTTP permits: an identity longer than this is not an identity we
 * would put in a metric anyway. The two variable-length ones (the target and
 * tracestate) are owned buffers reused across the units of a ring slot, exactly
 * like pg_unit.own_text — a connection that never sees a trace context never
 * allocates for one. */
#define LK_HTTP_TARGET_MAX 2048 /* request-target: path + query, raw (М4 templates it) */
#define LK_HTTP_TSTATE_MAX 256  /* tracestate, carried through verbatim (РH11) */
#define LK_HTTP_METHOD_MAX 16   /* method token, incl. the NUL: unknown ones too */
#define LK_HTTP_HOST_MAX   64   /* == sizeof lk_session.database (РH10) */
#define LK_HTTP_USER_MAX   40   /* Authorization: Basic name half */
#define LK_HTTP_REQID_MAX  48   /* X-Request-Id / X-Amzn-Trace-Id (a UUID is 36) */
#define LK_HTTP_CTYPE_MAX  32   /* Content-Type, first token only */
#define LK_HTTP_ROUTE_MAX  96   /* --http-route-header value (РH7); "" = none */

/* W3C trace context lifted off the request (РH11). Kept in its compact binary
 * form — 25 bytes rather than the 55-character header — because it is small
 * enough to sit inline in every unit and М6 needs the ids, not the text. */
struct http_trace {
    __u8 trace_id[16];
    __u8 parent_id[8];
    __u8 flags; /* W3C trace-flags; bit 0 = sampled */
    bool valid; /* the header was present *and* well-formed */
};

/* One request/response exchange (РH6). Opened by a request head, closed by the
 * end of the response body, and emitted exactly once — as an observation if a
 * response was seen, into a units_dropped_* counter otherwise.
 *
 * The four timings of РH5 are the reason the unit exists at all; everything
 * else on it is a label or a size. ts_interim_ns is a fifth stamp with no
 * family of its own yet: the gap between the request head and a `100 Continue`
 * is the only server-side signal available before an upload starts, so it is
 * recorded now and spent in М6's span attributes. */
struct http_unit {
    __u64 ts_start_ns;     /* first byte of the request head */
    __u64 ts_req_done_ns;  /* last byte of the request body (РH5) */
    __u64 ts_first_row_ns; /* first byte of the response head — TTFB */
    __u64 ts_complete_ns;  /* last byte of the response body */
    __u64 ts_interim_ns;   /* first 1xx head; 0 = none */
    __u64 bytes_in;        /* request body bytes, captured or holed */
    __u64 bytes_out;       /* response body bytes */

    char *target; /* owned, reused across the slot's units; freed on conn close */
    __u32 target_len, target_cap;
    char *tracestate; /* owned likewise, allocated only when one arrives */
    __u32 tracestate_len, tracestate_cap;

    struct http_trace tp;
    char method[LK_HTTP_METHOD_MAX];   /* NUL-terminated; unknown methods verbatim */
    char host[LK_HTTP_HOST_MAX];       /* absolute-form authority, else Host */
    char user[LK_HTTP_USER_MAX];       /* --http-user basic only; "" otherwise */
    char req_id[LK_HTTP_REQID_MAX];    /* X-Request-Id / X-Amzn-Trace-Id */
    char ctype[LK_HTTP_CTYPE_MAX];     /* response Content-Type, first token */
    char route_hdr[LK_HTTP_ROUTE_MAX]; /* the route the app declared, read only
                                          when --http-route-header named a header
                                          (РH7); "" means "classify the target" */

    __u16 status;     /* final response status; 0 = no response head yet */
    __u16 flags;      /* accumulated LK_QO_* */
    __u8 method_id;   /* enum http_method */
    __u8 minor;       /* request HTTP/1.<minor> */
    __u8 resp_minor;  /* response HTTP/1.<minor> */
    bool used;        /* slot holds a live unit */
    bool req_done;    /* the request body ended */
    bool have_resp;   /* a *final* (non-1xx) response head arrived */
    bool expect_cont; /* the request carried `Expect: 100-continue`, so the
                         upload interval (ts_req_done − ts_start) contains a
                         server round trip and is not the client's alone —
                         М5's upload family excludes such units (РH5) */
    bool to_close;    /* rule 6: the response body ends only at CONN_CLOSE, so
                         the connection dying completes this unit instead of
                         truncating it (notes-httpproto.md §"Body length") */
};

/* Per-connection handler state, allocated lazily on the first message and freed
 * in on_conn_close.
 *
 * The in-flight units live in a ring addressed by a monotonic sequence rather
 * than by index: pipelining means a request body and a response body are being
 * accounted at the same time on two different units, and a stale reference to
 * an already-emitted unit (a request body still trickling in after the server
 * answered early with a 413) must be *detected*, not followed into whatever now
 * occupies the slot. Comparing seq against head_seq does that for free.
 *
 * Size, since this is per connection and the table's ceiling is 65536: 5.5 KB,
 * of which the 16-unit ring is 5.2 KB — the same order as the PG handler's
 * 64-deep ring (and smaller), and allocated only for connections that actually
 * carry a message. The two variable-length copies live outside it, in owned
 * buffers reused across a slot's units, so a connection that never meets a
 * trace context never allocates for one. */
struct http_conn {
    struct lk_session session; /* host -> db, UA -> app, user "-" unless basic (РH10) */
    __u64 msgs;                /* messages dispatched on this connection */

    struct http_unit ring[LK_HTTP_MAX_INFLIGHT];
    __u64 head_seq; /* oldest live unit; the one a response belongs to */
    __u64 open_seq; /* next seq to hand out; live units are [head_seq, open_seq) */
    __u64 req_seq;  /* unit currently receiving a request body; ~0 = none */

    /* Scratch for the redacted target (РH12, М6), owned and reused like the
     * unit's own buffers: `lk_query_obs.text` must stay valid for the callback,
     * and the redacted form is a different string from the one the unit holds —
     * the unit keeps the raw target because the route templater classifies that.
     * Allocated on the first request that actually carries a credential-shaped
     * query key, so a connection that never sees one never pays for it, which is
     * nearly all of them. */
    char *redacted;
    __u32 redacted_cap;

    __u32 owed;       /* responses still owed for requests the ring could not hold.
                         Responses arrive in request order, so the untracked ones
                         are the newest and their responses come last — which is
                         what makes a plain counter sufficient (РH6) */
    bool resp_orphan; /* skipping the body of one of those owed responses */
    bool session_emitted;
    bool degraded; /* joined mid-session (synthetic entry, or after a resync):
                      no unit may open before the next request head, which is
                      the first boundary the framer can vouch for */
};

/* The unit a sequence number refers to, or NULL when it has been emitted (or
 * never existed). Inline because every message dispatch calls it. */
static inline struct http_unit *http_unit_at(struct http_conn *hc, __u64 seq)
{
    if (seq < hc->head_seq || seq >= hc->open_seq)
        return NULL;
    return &hc->ring[seq % LK_HTTP_MAX_INFLIGHT];
}

/* The unit a response belongs to: the oldest live one (РH6 — the queue is a
 * FIFO because HTTP/1.1 responses come back in request order). */
static inline struct http_unit *http_unit_front(struct http_conn *hc)
{
    return http_unit_at(hc, hc->head_seq);
}

/* Copy a span into a fixed char[] as a C string, truncating rather than
 * failing: a clipped Host is a worse label than a full one and a better one
 * than none. Control bytes are dropped — every one of these values ends up in a
 * Prometheus label or an OTLP attribute, and both have opinions about those. */
static inline void http_copy_label(char *dst, __u32 cap, struct http_span s)
{
    __u32 n = 0;

    for (__u32 i = 0; i < s.n && n + 1 < cap; i++) {
        unsigned char b = (unsigned char)s.p[i];

        if (b < 0x20 || b == 0x7f)
            continue;
        dst[n++] = (char)b;
    }
    dst[n] = '\0';
}

/* Copy one C string into a fixed char[], truncating. The obvious snprintf("%s")
 * costs a few hundred nanoseconds of format machinery per call and this runs
 * twice on every observation — enough to show up next to the whole rest of the
 * handler in a microbenchmark, which is a silly thing to pay for a copy. */
static inline void http_copy_cstr(char *dst, __u32 cap, const char *src)
{
    __u32 n = 0;

    while (src[n] && n + 1 < cap) {
        dst[n] = src[n];
        n++;
    }
    dst[n] = '\0';
}

/* A framer message that found no live unit to attach itself to. On a connection
 * we know we joined mid-stream — a synthetic entry, or one that has just
 * resynced — this is the expected shape rather than an anomaly, and counting
 * every such message would swamp the tally exactly where it stops being able to
 * tell us anything. So `orphan_msgs` means "a message we had no business
 * losing", and hc->degraded is what separates the two; it clears on the next
 * request head, the first boundary the framer can vouch for. */
static inline void http_orphan(struct lk_proto *p, const struct http_conn *hc)
{
    if (!hc->degraded)
        p->st.orphan_msgs++;
}

/* --- http.c: the ring and the observation ---------------------------------- */

/* Open a unit for a request head. NULL when the ring is full — the caller emits
 * nothing and the connection remembers it owes a response (hc->owed). */
struct http_unit *http_unit_open(struct lk_proto *p, struct http_conn *hc, __u64 ts_ns);

/* --- http_req.c: the request head ------------------------------------------ */

/* Parse a request head ('R') into a fresh unit and update the session labels;
 * emits on_session the first time a connection produces one. The head bytes are
 * borrowed for the call only, so everything kept is copied. */
void http_req_head(struct lk_proto *p, struct lk_conn *c, struct http_conn *hc,
                   const struct lk_msg *m);

/* --- http_resp.c: the response head ---------------------------------------- */

/* Parse a response head into the unit it answers. `interim` marks a 1xx ('I'):
 * it records a timestamp and returns, because a 1xx closes nothing (РH6). */
void http_resp_head(struct lk_proto *p, struct http_conn *hc, const struct lk_msg *m, bool interim);

/* --- http_route.c: the dialect seam (РH8) ---------------------------------- */

/* The route this unit is reported under: the header the application declared if
 * `--http-route-header` asked for one, otherwise the connection's dialect
 * classifying the raw target (РH7). `out->text_len == 0` means "no route" — a
 * CONNECT, or a request head we never read — and the observation carries none
 * rather than a made-up one. */
void http_route_resolve(const struct lk_conn *c, const struct http_unit *u,
                        struct lk_route_out *out);

/* The active configuration (РH10/РH7), read by http_req.c and http_route.c. */
const struct lk_http_cfg *http_cfg(void);

#endif /* LATKIT_HTTP_H */
