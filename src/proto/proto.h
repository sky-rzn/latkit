/* SPDX-License-Identifier: GPL-2.0 */
/* Core <-> protocol-handler boundary (Р15, STAGE3.md). Exactly two contracts
 * live here, and this is the only header the core (events.c / the replay
 * harness) needs to speak to a protocol:
 *
 *   - down (core -> handler): the already-existing struct lk_msg_sink
 *     (reassembly.h) — whole messages, open/close, resync. A protocol handler
 *     *is* an lk_msg_sink implementation; the framer does not know who listens,
 *     so the --messages logger and the PG parser plug in the same way. Re-
 *     exported here so a consumer includes just proto.h.
 *   - up (handler -> consumer): the new struct lk_query_sink below —
 *     protocol-independent observations (lk_query_obs). Stage 3's consumer is
 *     the --queries logger; stage 4 swaps it for the aggregator without
 *     touching the parser.
 *
 * Per-connection parser state lives in lk_conn.proto_state (void *, owned by
 * the handler): allocated lazily on the connection's first message, freed in
 * on_conn_close. The connection table fires that close-hook on *every* removal
 * path (CONN_CLOSE, LRU eviction, idle sweep, table teardown) — see
 * lk_conn_table_on_destroy — so proto_state never leaks.
 *
 * The seam Р15 deliberately deferred is now real (РМ1, MYSQL.md М1): the
 * framer mechanics (bytes/hole, the body-prefix slab pool, off-anomalies,
 * counters) stay in reassembly.c, while everything protocol-shaped — header
 * size and parse, startup framing, SSL/Cancel transitions, resync anchors —
 * lives behind the lk_proto_ops vtable below. The PG entry is
 * src/proto/pg/pg_frame.c; a connection picks its ops from the port→protocol
 * map at creation (РМ2), NULL falling back to PG — the CLI default.
 *
 * Everything under src/proto/ is pure (no I/O, no libbpf), like decode /
 * conn_table / reassembly: unit tests feed synthetic lk_msg, replay tests feed
 * .lkt fixtures through the shared pipeline. */
#ifndef LATKIT_PROTO_H
#define LATKIT_PROTO_H

#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>

#include "conn_table.h" /* struct lk_conn, enum lk_dir */
#include "norm_sql.h"   /* enum lk_sql_dialect (lk_proto_ops.sql_dialect, РМ9/М6) */
#include "reassembly.h" /* struct lk_msg, struct lk_msg_sink (down contract) */

/* --- up contract: protocol-independent query observations ----------------- */

enum lk_query_kind {
    LK_Q_SIMPLE,   /* simple query (Q .. Z) */
    LK_Q_EXTENDED, /* extended: Bind/Execute */
    LK_Q_FUNCTION, /* FunctionCall */
    LK_Q_COPY_IN,  /* COPY FROM STDIN */
    LK_Q_COPY_OUT, /* COPY TO STDOUT */
    LK_Q_CANCEL,   /* CancelRequest */
};

/* lk_query_obs.flags */
#define LK_QO_ERROR      (1 << 0) /* closed by ErrorResponse; sqlstate valid */
#define LK_QO_TEXT_TRUNC (1 << 1) /* text is a prefix (capture budget) */
#define LK_QO_NO_TEXT    (1 << 2) /* no text (prepared not cached, F, ...) */
#define LK_QO_MULTI_STMT (1 << 3) /* simple Q with several statements */
#define LK_QO_EMPTY      (1 << 4) /* EmptyQueryResponse */
#define LK_QO_SUSPENDED  (1 << 5) /* PortalSuspended: Execute with a row limit */
#define LK_QO_ABORTED    (1 << 6) /* extended: killed by an earlier batch error */
#define LK_QO_PIPELINED  (1 << 7) /* more than one unit in the batch */

struct lk_session {
    char user[64], database[64], app[64]; /* truncated copies; "" = unknown */
    char server_version[16];
    bool complete; /* startup seen in full */
};

struct lk_query_obs {
    __u64 ts_start_ns;     /* first frontend message of the unit */
    __u64 ts_first_row_ns; /* first DataRow; 0 = none */
    __u64 ts_complete_ns;  /* backend message that closed the unit */
    __u64 ts_ready_ns;     /* nearest following Z; 0 = not yet (ABORTED/CANCEL) */
    const char *text;      /* raw SQL prefix, NOT normalised; NULL on NO_TEXT;
                              valid only for the duration of on_query */
    __u32 text_len;
    __u64 rows;       /* from the CommandComplete tag; summed on MULTI_STMT */
    __u64 bytes;      /* COPY: summed len of CopyData */
    char sqlstate[6]; /* on LK_QO_ERROR, C-string */
    __u16 err_code;   /* vendor error code (MySQL errno) on LK_QO_ERROR; 0 =
                         none/unknown (PG has no numeric code) — М6 span attr */
    __u8 kind;        /* enum lk_query_kind */
    char txn_status;  /* I/T/E from the closing Z; 0 = unknown */
    __u16 flags;      /* LK_QO_* */
};

struct lk_query_sink {
    void *ctx;
    void (*on_query)(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                     const struct lk_query_obs *o);
    void (*on_session)(void *ctx, const struct lk_conn *c,
                       const struct lk_session *s);    /* AuthenticationOk */
    void (*on_txn)(void *ctx, const struct lk_conn *c, /* T|E -> I on Z */
                   __u64 start_ns, __u64 end_ns, char final_status);
};

/* --- parser counters ------------------------------------------------------ */
/* Reported in the 10 s stats line; the field names are the stage-4 metric
 * stems. Stage 3.1 fills in only the message tallies (msgs / startup_msgs /
 * resyncs / conns / by_type); the query/error/loss counters wire up as the
 * parser grows (tasks 3.2-3.5). */
struct lk_proto_stats {
    __u64 msgs;                   /* messages dispatched */
    __u64 startup_msgs;           /* ... of them startup-framed */
    __u64 resyncs;                /* on_resync callbacks seen */
    __u64 conns;                  /* proto_state allocations (connections seen) */
    __u64 queries;                /* observations emitted */
    __u64 errors_sql;             /* LK_QO_ERROR observations */
    __u64 parse_errors;           /* corrupt field -> latkit_parse_errors_total */
    __u64 unknown_msgs;           /* unknown message type, skipped by len */
    __u64 units_dropped_resync;   /* in-flight units dropped on a resync */
    __u64 units_dropped_close;    /* ... on a CONN_CLOSE with a non-empty queue */
    __u64 units_dropped_overflow; /* ... over LK_PG_MAX_INFLIGHT */
    __u64 prep_evictions;         /* prepared-statement cache evictions */
    __u64 sessions;               /* on_session emitted */
    __u64 replication_conns;      /* CopyBoth / binlog dump -> IGNORE connections */
    __u64 compressed_conns;       /* CLIENT_COMPRESS/_ZSTD -> IGNORE connections (РМ7) */
    __u64 by_type[2][256];        /* [enum lk_dir][type byte]; startup at [.][0] */
};

/* --- protocol handler (down: lk_msg_sink, up: lk_query_sink) -------------- */

/* Protocol handler object. Owns its per-connection state through
 * lk_conn.proto_state; is an lk_msg_sink downward and drives an lk_query_sink
 * upward. Assembled in exactly one place: events.c (live) / the replay harness
 * (offline). The base is protocol-independent — a handler's own state lives
 * entirely in proto_state — so the accessors below are shared (registry.c). */
struct lk_proto {
    struct lk_msg_sink msink; /* down: installed as the framer's sink */
    struct lk_query_sink out; /* up: borrowed from the assembler */
    struct lk_proto_stats st;
};

/* PostgreSQL v3 handler. `out` (may have NULL callbacks) receives the
 * observations; it is borrowed, not copied deeply — keep it alive for the
 * handler's lifetime. */
struct lk_proto *lk_proto_pg_new(const struct lk_query_sink *out);

/* The down contract: install this as the framer's sink (or mirror into it). */
const struct lk_msg_sink *lk_proto_sink(struct lk_proto *p);

/* Cumulative counters for the stats line. */
const struct lk_proto_stats *lk_proto_stats(const struct lk_proto *p);

void lk_proto_free(struct lk_proto *p);

/* --- protocol vtable + registry (РМ1) ------------------------------------- */

struct lk_reasm; /* reassembly.h (included above); for the hook signatures */
struct lk_ev_data;

/* One wire protocol: its name (the `--port N=<name>` selector), its handler
 * constructor, and the framer knowledge reassembly.c calls out for. The framer
 * hooks are pure state manipulation over lk_frame / lk_conn flags — no I/O, no
 * allocation. All hooks except the two intercept_* are mandatory.
 *
 * Contract notes:
 *  - hdr_size returns how many header bytes to accumulate in f->hdr before
 *    parse_hdr can run (<= sizeof f->hdr); it may depend on the direction's
 *    framing state (PG: 4 in startup framing, 5 normal).
 *  - parse_hdr reads f->hdr and fills f->msg_type, f->msg_len (the lk_msg.len
 *    value, protocol semantics), f->body_len (wire bytes following the
 *    header) and f->body_total (logical body size, what BODY_TRUNC is judged
 *    against — equal to body_len unless the message glues wire fragments).
 *    false = corrupt header: the framer dirties the direction and bumps
 *    bad_len. A protocol whose logical message spans several wire fragments
 *    (MySQL 16MB continuations, РМ3) sets f->msg_cont: the fragment's body
 *    then ends in reading the next header instead of emitting, the prefix in
 *    f->buf is pinned across fragments (prefix_closed), and parse_hdr sees
 *    the continuation header with msg_cont still set. Clearing msg_cont on
 *    the last fragment releases the single glued emit.
 *  - pre_emit runs on every assembled message right before the sink: set
 *    protocol flags on *m (LK_MSG_STARTUP) and drive framing-state transitions
 *    that depend on the body (PG: startup code -> startup_done /
 *    LK_CONN_SSL_REPLY / LK_CONN_CANCEL).
 *  - intercept_bytes consumes cross-direction special bytes before framing
 *    (PG: the one-byte SSL/GSSENC reply); it advances *p and *n, returning false
 *    discards the rest of the chunk (the connection went encrypted).
 *    intercept_hole is its hole twin: true = the pending special reply fell
 *    into the hole, and the framer dirties the direction (hdr_holes).
 *  - resync_scan runs in LK_FR_DIRTY over captured bytes: return how many were
 *    consumed and set *found when framing may resume at the next byte
 *    (f->resync_matched is the protocol's scratch, zeroed on holes).
 *  - resync_boundary is the call-boundary anchor, checked by lk_reasm_data on
 *    a dirty direction before the bytes are fed (PG: frontend off==0 + valid
 *    type + plausible len). */
struct lk_proto_ops {
    const char *name;                /* the `--port N=<name>` selector AND the `proto`
                                        metric label value (РМ6): "pg" / "mysql" */
    const char *db_system;           /* OTel semconv db.system.name for the spans (М6):
                                        "postgresql" / "mysql" */
    enum lk_sql_dialect sql_dialect; /* normaliser dialect for this protocol's
                                        SQL (РМ9; М6 threads it to the sinks) */

    struct lk_proto *(*proto_new)(const struct lk_query_sink *out);

    __u32 (*hdr_size)(const struct lk_conn *c, enum lk_dir dir, const struct lk_frame *f);
    bool (*parse_hdr)(struct lk_conn *c, enum lk_dir dir, struct lk_frame *f);
    void (*pre_emit)(struct lk_conn *c, enum lk_dir dir, struct lk_frame *f, struct lk_msg *m);
    bool (*intercept_bytes)(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, const __u8 **p,
                            __u32 *n, __u64 ts_ns);
    bool (*intercept_hole)(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir);
    __u32 (*resync_scan)(struct lk_conn *c, enum lk_dir dir, struct lk_frame *f, const __u8 *p,
                         __u32 n, bool *found);
    bool (*resync_boundary)(const struct lk_conn *c, enum lk_dir dir, const struct lk_ev_data *ev,
                            __u32 cap_len);
};

/* PG v3 framing behind the vtable (src/proto/pg/pg_frame.c). Also the
 * default: a bare `--port N` and a connection without an assigned protocol
 * (lazily created entry, bare unit-test lk_conn) frame as PG (РМ2). */
extern const struct lk_proto_ops lk_proto_pg_ops;

/* A connection's effective protocol: NULL ops (no port map / lazily created
 * entry / bare unit-test lk_conn) means the PG default, mirroring the framer's
 * fallback in reassembly.c (РМ2). The observation sinks (metrics.c / spans.c)
 * read the dialect, the `proto` label and db.system.name through this — never
 * by guessing from the port (М6). */
static inline const struct lk_proto_ops *lk_conn_proto(const struct lk_conn *c)
{
    return c->ops ? c->ops : &lk_proto_pg_ops;
}

/* MySQL classic protocol: framing in src/proto/my/my_frame.c (РМ3/РМ4), the
 * handler in src/proto/my/my.c + my_session/my_query/my_prep (М3, РМ8) —
 * `--port 3306=mysql`. */
extern const struct lk_proto_ops lk_proto_my_ops;
struct lk_proto *lk_proto_my_new(const struct lk_query_sink *out);

/* The registry: one entry per supported protocol, PG first (the default).
 * LK_PROTO_MAX caps it so consumers can size parallel arrays statically. */
#define LK_PROTO_MAX 4
extern const struct lk_proto_ops *const lk_proto_registry[];
extern const unsigned lk_proto_nregistry;

/* Name lookup for the CLI (`--port 3306=mysql`); NULL when unknown. */
const struct lk_proto_ops *lk_proto_find(const char *name, size_t name_len);

#endif /* LATKIT_PROTO_H */
