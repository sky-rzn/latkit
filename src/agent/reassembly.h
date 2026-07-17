/* SPDX-License-Identifier: GPL-2.0 */
/* Streaming framer (Р9-Р11, STAGE2.md): turns the per-direction stream of
 * stage-1 data events into whole PG protocol messages. A direction is a
 * sequence of exactly two primitives, derived deterministically from
 * off/cap_len/total_len of the events (total_len is always honest, budgets
 * cut cap_len only — the stage-1 invariant this module is built on):
 *
 *   bytes(p, n) — captured payload;
 *   hole(n)     — a gap of known size: the uncaptured tail of a call and
 *                 missing off-intervals between chunks.
 *
 * A hole over a message *body* does not desynchronise framing — the header
 * carries len, so the tail is skipped arithmetically. A hole over a header
 * loses sync: the direction goes LK_FR_DIRTY and stays there until
 * resynchronisation (Р10). The resync anchors: backend — the ReadyForQuery
 * pattern 'Z' 00 00 00 05 [I|T|E] in the captured bytes (a sliding match
 * that survives the pattern torn across events; 'Z' semantics untouched,
 * it is only a boundary marker, framing resumes at the next byte);
 * frontend — a call boundary (off == 0) whose first byte is a valid
 * frontend type with a plausible len. The scan runs only in LK_FR_DIRTY,
 * so a false 'Z' pattern inside a clean message body costs nothing. The
 * first message after a resync carries LK_MSG_AFTER_RESYNC. Unknown holes
 * (lost ringbuf events) are the connection table's job: it dirties both
 * directions on a seq gap before events reach this module; synthetic
 * connections start dirty and enter the stream through the same resync.
 *
 * Framing knowledge is deliberately minimal (Р10) and, since РМ1 (MYSQL.md
 * М1), protocol-owned: header size/parse, startup framing, the SSL/Cancel
 * transitions and both resync anchors come from the connection's
 * lk_proto_ops vtable (proto.h) — PG's entry is src/proto/pg/pg_frame.c, and
 * a connection without assigned ops frames as PG (the default, РМ2). This
 * module keeps only the generic mechanics: chunk arithmetic, holes, the
 * header/body/skip/dirty state machine, the slab pool and the counters.
 * Message semantics are stage 3.
 *
 * Memory is bounded by construction (Р11): at most the body prefix of one
 * unfinished message is buffered per direction (<= LK_MSG_BODY_MAX, filled
 * lazily when a message spans chunks, released at the message boundary); the
 * body tail beyond the prefix is skipped by len. The buffer is a fixed
 * LK_MSG_BODY_MAX slab drawn from a small agent-wide freelist (not per-conn),
 * so the message boundary recycles it instead of malloc/free churning the
 * allocator on every torn message — the hot path (large Query/Bind, COPY, or
 * any body straddling a capture chunk) does zero heap ops in steady state.
 * The freelist is capped at LK_REASM_POOL_MAX slabs, so the recycled pool
 * ceiling is LK_REASM_POOL_MAX * LK_MSG_BODY_MAX regardless of connection
 * count; churn above the cap falls back to real free. RSS stays lazy: the
 * kernel backs only the pages a prefix actually writes, so a small torn
 * message costs a page, not 16 KiB (keeps Р11's small steady-state memory).
 * Single-threaded loop, so the freelist needs no lock.
 *
 * Pure state manipulation, no I/O: unit tests feed synthetic events, the
 * agent feeds decoded ringbuf records (events.c). */
#ifndef LATKIT_REASSEMBLY_H
#define LATKIT_REASSEMBLY_H

#include <linux/types.h>

#include "conn_table.h"
#include "latkit.h"

/* Body prefix kept per message (Р11): larger than the stage-4 fingerprint
 * needs and than the default per-call capture budget. Also the fixed size of
 * every freelist slab — any prefix fits, so slabs are interchangeable. */
#define LK_MSG_BODY_MAX (16 * 1024)

/* Body-slab freelist cap (Р11): the recycled pool holds at most this many
 * LK_MSG_BODY_MAX slabs, an agent-wide ceiling of 1 MiB independent of the
 * connection count. Frees past the cap go to the real allocator. */
#define LK_REASM_POOL_MAX 64

/* PG startup-message codes (Р10) — the first 4 body bytes of a startup-framed
 * message. The framer logic that reads them moved to src/proto/pg/pg_frame.c
 * (РМ1); the codes stay here because pg_session.c and a raft of test builders
 * include this header for them. */
#define LK_PG_PROTO_V3       0x00030000u /* StartupMessage */
#define LK_PG_CANCEL_REQUEST 80877102u   /* CancelRequest */
#define LK_PG_SSL_REQUEST    80877103u   /* SSLRequest */
#define LK_PG_GSSENC_REQUEST 80877104u   /* GSSENCRequest */

/* lk_msg.flags */
#define LK_MSG_BODY_TRUNC   (1 << 0) /* body_cap < len-4: prefix only */
#define LK_MSG_AFTER_RESYNC (1 << 1) /* first message after a resync */
#define LK_MSG_STARTUP      (1 << 2) /* startup framing: type=0, body has code */

struct lk_msg {
    __u64 ts_ns;      /* event of the first header byte (Р13) */
    char type;        /* 'Q','Z',...; 0 for startup messages */
    __u16 flags;      /* LK_MSG_* */
    __u32 len;        /* protocol len field (excludes the type byte);
                         0 only for the one-byte SSL/GSSENC reply */
    __u32 body_cap;   /* body bytes actually available (prefix) */
    const __u8 *body; /* valid only for the duration of on_msg */
};

/* Framer -> consumer contract (stage 2: the --messages logger; stage 3:
 * pgproto.c). on_msg and on_resync are called by the framer; the open/close
 * hooks are for the event router. Any callback may be NULL. */
struct lk_msg_sink {
    void *ctx;
    void (*on_msg)(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m);
    void (*on_conn_open)(void *ctx, struct lk_conn *c);
    void (*on_conn_close)(void *ctx, struct lk_conn *c);
    void (*on_resync)(void *ctx, struct lk_conn *c, enum lk_dir dir);
};

/* Cumulative framer counters, reported in the 10 s stats line. Each of
 * bad_len/hdr_holes/off_anomalies dirtied one direction when incremented. */
struct lk_reasm_stats {
    __u64 msgs;          /* messages emitted */
    __u64 msgs_trunc;    /* ... of them with LK_MSG_BODY_TRUNC */
    __u64 holes;         /* known holes generated */
    __u64 hole_bytes;    /* ... their total size */
    __u64 bad_len;       /* len sanity failure (< min or > 2^30) */
    __u64 hdr_holes;     /* hole landed on a message header */
    __u64 off_anomalies; /* off went backwards / past total_len */
    __u64 resyncs;       /* directions resynchronised out of DIRTY
                            (stage-4 metric name: latkit_resync_total) */
    __u64 tls_conns;     /* connections gone encrypted ('S'/'G' reply) */
};

struct lk_reasm {
    struct lk_msg_sink sink;
    struct lk_reasm_stats st;
    /* Recycled body-prefix slabs (Р11): a fixed-size freelist shared across
     * all connections. buf_get pops one or mallocs; the message boundary
     * pushes it back (or really frees past LK_REASM_POOL_MAX). */
    __u8 *pool[LK_REASM_POOL_MAX];
    unsigned pool_n;
};

void lk_reasm_init(struct lk_reasm *r, const struct lk_msg_sink *sink);

/* Release the recycled slab pool (the in-flight buffers are the conn table's;
 * it frees them on entry teardown). Call once when the framer is done — the
 * agent does it from lk_pipeline_fini. */
void lk_reasm_free(struct lk_reasm *r);

/* Chunk layer: derive bytes()/hole() from one decoded data event and feed
 * the framer. cap_len must be the decode-clamped value (lk_ev_view.cap_len),
 * not the raw field. Anomalous off (backwards, past total_len, total_len
 * changing mid-call) dirties the direction and bumps off_anomalies. Events
 * of LK_CONN_TLS / LK_CONN_CANCEL connections are silently discarded here;
 * the frontend resync anchor (a call boundary) is also checked here. */
void lk_reasm_data(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                   const struct lk_ev_data *ev, __u32 cap_len);

/* The two stream primitives (Р9), exposed for unit tests. */
void lk_frame_bytes(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, const __u8 *p, __u32 n,
                    __u64 ts_ns);
void lk_frame_hole(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, __u64 n);

#endif /* LATKIT_REASSEMBLY_H */
