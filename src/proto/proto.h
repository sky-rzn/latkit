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
 * The vtable has two framing modes since РH1 (PLAN-HTTP.md М1). PG and MySQL
 * are *message-framed*: a fixed-size header the generic machine accumulates in
 * lk_frame.hdr[8], then a body of known length. HTTP/1.x has neither — its
 * header block is CRLF-delimited and kilobytes long — so LK_PROTO_F_STREAM
 * hands the protocol the raw byte/hole stream (stream_bytes/stream_hole) after
 * the generic mechanics and lets it assemble messages itself, publishing them
 * through lk_reasm_emit. Both modes emit lk_msg, so everything downstream —
 * --messages, the replay harness, fuzz_pipe, the handlers — is unaware.
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
#include "norm_route.h" /* struct lk_route_cfg / lk_route_out (РH7/РH8, М4) */
#include "norm_s3.h"    /* struct lk_s3_cfg (РS3/РS4, PLAN-MINIO.md МS1) */
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
    LK_Q_REQUEST,  /* one HTTP request/response exchange (РH6, PLAN-HTTP.md М3):
                      opened by a request head, closed by the end of the response
                      body. Kept in the same enum rather than given a parallel one
                      because every consumer downstream already switches on it —
                      enum lk_qkind in metrics.h mirrors it value for value. */
    LK_Q_COMMAND,  /* one Redis command and the value that answered it (РR3/РR11,
                      PLAN-REDIS.md МR5). A command is neither a statement nor an
                      exchange: it has no text, no rows and no status, and the
                      profile it reports under says so by leaving those families
                      out. Mirrored as LK_QK_COMMAND. */
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
/* HTTP (РH10): a 4xx is an error too, but it is the *client's*, and mixing it
 * into LK_QO_ERROR would make every 404-heavy service look broken. The two are
 * separate flags rather than one status field so the DB protocols keep the
 * single "did this fail" bit they have always had. */
#define LK_QO_CLIENT_ERR (1 << 8) /* HTTP status 4xx: counted apart from ERROR */
/* РH5: the interval `ts_start … ts_req_done` contains a server round trip (the
 * client asked `Expect: 100-continue` and waited for the answer before sending
 * the body), so it is not the client's upload time and the upload family skips
 * the unit. Duration and TTFB are unaffected — they start at ts_req_done. */
#define LK_QO_EXPECT_CONT (1 << 10)
/* S3 (РS2): the request went to the server's own API (`/minio/…`), which is not
 * an S3 operation and on a distributed pool is most of the traffic on the port.
 * The observation exists — it is real traffic and `--queries` shows it — but the
 * metrics facade counts it and reports it in no family that says "requests"
 * (МS2). Set by the dialect, which is the only component that knows the
 * server's own surface when it sees one. */
#define LK_QO_INTERNAL (1 << 11)
/* Redis (РR9): the command was answered `+QUEUED` — it is inside a `MULTI` and
 * the server did nothing but write it down, in microseconds. The observation is
 * real (the command was sent, and `commands_total` counts it) and its *duration*
 * is not: it measures how fast the server can say "noted", and in a histogram
 * beside real work it drags every percentile down. The work happens at `EXEC`,
 * and the interval that means something is the transaction's, which goes to
 * latkit_txn_duration_seconds. */
#define LK_QO_QUEUED (1 << 12)
/* Redis (РR10): a blocking command — `BLPOP key 30`, `XREAD BLOCK`, `WAIT`. Its
 * latency is the wait the *client* asked for, not the server's service time, so
 * it is measured (in a family of its own, МR5) and kept out of the general
 * duration histogram: with a 30-second `BLPOP` in the same series as `GET`, the
 * p99 of a Redis is whatever its longest poll happened to be. */
#define LK_QO_BLOCKING (1 << 13)
#define LK_QO_BODY_UNSEEN                                                                          \
    (1 << 9) /* РH4: the response body was promised and did not                                   \
                arrive in full — an old-kernel sendfile that                                     \
                bypassed the socket, or a connection that died                                     \
                mid-transfer. The head timings are honest and                                      \
                bytes_out is a lower bound; the unit was closed                                    \
                by something other than its own last byte */

struct lk_session {
    char user[64], database[64], app[64]; /* truncated copies; "" = unknown */
    char server_version[16];
    bool complete; /* startup seen in full */
};

/* What an HTTP exchange carries that a database query has no equivalent of
 * (РH11, PLAN-HTTP.md М6): the W3C trace context it arrived under, and the
 * handful of head fields that are span attributes rather than labels. Hung off
 * lk_query_obs by pointer and NULL for PG/MySQL, so the database path keeps the
 * struct — and the cache lines — it had.
 *
 * All of it is *borrowed for the duration of the callback*, like `text`: the
 * pointers reach into the handler's per-connection state, which is reused by the
 * next unit on that connection. A sink that keeps any of it copies it (spans.c
 * does).
 *
 * Not here on purpose: the host, the user agent and the user, which are session
 * labels and already travel in lk_session (РH10), and the status, which reuses
 * err_code because *every* HTTP observation has one. */
struct lk_http_obs {
    const __u8 *trace_id;  /* 16 bytes; NULL = no usable `traceparent` */
    const __u8 *parent_id; /* 8 bytes, valid with trace_id */
    const char *tracestate;
    __u32 tracestate_len;    /* verbatim, unparsed, may be 0 */
    const char *req_id;      /* X-Request-Id / X-Amzn-Trace-Id; NULL = none. The S3
                                dialect fills it from the response's
                                `X-Amz-Request-Id` instead (РS4), which is the join
                                key `mc admin trace` reports and therefore the one
                                the МS4 accuracy bench matches on */
    const char *obj_version; /* the version of the object this exchange touched
                                (S3: `x-amz-version-id`); NULL for a dialect that
                                has no such thing, which is every one but S3 */
    const char *ctype;       /* response Content-Type, first token; NULL = none */
    __u64 ts_interim_ns;     /* first 1xx head (100-continue / early hints); 0 = none */
    __u8 trace_flags;        /* W3C trace-flags; bit 0 = the caller sampled this trace */
    __u8 version;            /* HTTP/1.<version> of the response, else of the request */
};

/* What a Redis command carries that neither a query nor an HTTP exchange has an
 * equivalent of (РR3/РR11, PLAN-REDIS.md МR2). Hung off lk_query_obs by pointer
 * and NULL for every other protocol, exactly as lk_http_obs is, so the database
 * path keeps the struct it had.
 *
 * The first field is the one RESP makes a first-class fact: **how many commands
 * arrived in the same syscall as this one**. On PG a pipelined batch is unusual
 * enough to be a flag; on Redis batching is what every client library does by
 * default, the depth spans 1…100 in the МR0 corpus, and it is the difference
 * between "the server was slow" and "this command waited behind ninety-nine of
 * its own". МR5 makes it latkit_redis_pipeline_depth and МR6 the
 * `redis.pipeline.depth` span attribute; the measurement is here because only
 * the handler sees the call boundaries the framer marks for it.
 *
 * The second is the answer that is an error in syntax and routine cluster
 * operation in fact (РR7): it travels beside `err_name` rather than inside it
 * because a `-MOVED` must be counted *somewhere* — an operator wants to see a
 * resharding cluster — and that somewhere may not be the error rate, or every
 * healthy cluster reports as broken. Hence its own family with its own label,
 * and no entry in latkit_redis_errors_total.
 *
 * The last two are МR6's, and both exist so that a span can say something a
 * label may not. `argc` is **how many arguments there were and nothing about
 * what they were**: it is the whole of what `db.query.text` is built from
 * (`GET ?`, `SET ? ? ? ?`), which is the only shape of a Redis command that is
 * safe to export — an argument is a key or a value, and neither leaves the
 * handler at any setting (РR11). `txn_size` is the same idea one level up: an
 * `EXEC` runs the commands a `MULTI` collected, and how many that was is the
 * one number that makes a five-millisecond transaction readable. */
struct lk_redis_obs {
    __u32 pipeline_depth; /* commands in this one's batch, >= 1 */
    __u32 txn_size;       /* `EXEC` only: commands the transaction queued, from the
                             `+QUEUED` replies actually seen; 0 = not an `EXEC`, or
                             a transaction whose `MULTI` we never watched */
    __u16 argc;           /* elements after the identity, saturated: a count, never
                             a byte of one. The verb (and, for a container command,
                             its subcommand) is not in it — that part is the
                             identity and travels in `route` */
    __u8 redirect;        /* enum lk_redis_redirect (norm_redis.h), mirrored by
                             enum lk_redirect in metrics.h; 0 = not a redirect */
};

/* One completed unit of work, whatever the protocol calls it: a query, a COPY,
 * or an HTTP request/response exchange. The four timestamps are the reason the
 * struct exists — everything else is labels.
 *
 * The HTTP track (РH5) needs one stamp the database protocols never did. There,
 * `ts_start … ts_complete` covers the client's upload of the request body,
 * which is time the server did not spend and cannot control, so a POST of a
 * gigabyte would report a "slow server". ts_req_done_ns splits the interval:
 *
 *   ts_start ──request head+body──▶ ts_req_done ──server──▶ ts_first_row ──▶ ts_complete
 *   duration = ts_complete − ts_req_done   ttfb = ts_first_row − ts_req_done
 *   upload   = ts_req_done − ts_start      (its own family, РH9)
 *
 * For PG and MySQL ts_req_done_ns is simply 0 and every consumer keeps reading
 * ts_start as it always has. */
struct lk_query_obs {
    __u64 ts_start_ns;     /* first frontend message of the unit / request head */
    __u64 ts_req_done_ns;  /* HTTP: last byte of the request body (РH5); 0 = n/a */
    __u64 ts_first_row_ns; /* first DataRow / response head (TTFB); 0 = none */
    __u64 ts_complete_ns;  /* backend message that closed the unit / last body byte */
    __u64 ts_ready_ns;     /* nearest following Z; 0 = not yet (ABORTED/CANCEL).
                              HTTP has no separate ready point: == ts_complete */
    const char *text;      /* raw SQL prefix / the request target (path+query),
                              NOT normalised; NULL on NO_TEXT; valid only for the
                              duration of on_query. The one thing done to it is
                              РH12's redaction: with `--http-redact` (the default)
                              the values of credential-shaped query keys arrive
                              already replaced by `***`, at the handler rather
                              than in each sink, so no consumer can leak one by
                              forgetting to ask */
    __u32 text_len;
    __u64 rows;        /* from the CommandComplete tag; summed on MULTI_STMT */
    __u64 bytes;       /* COPY: summed len of CopyData */
    __u64 bytes_in;    /* HTTP: request body bytes, captured or holed (РH9) */
    __u64 bytes_out;   /* HTTP: response body bytes */
    __u64 obj_bytes;   /* S3 (РS6): the *logical* size of the payload this
                          exchange moved, with the transfer framing discounted —
                          `x-amz-decoded-content-length` when the upload was
                          `aws-chunked`, the body size on the wire otherwise. It
                          is a separate number from bytes_in/bytes_out because a
                          signed chunk costs ~87 bytes of framing, which is 17 %
                          at 1 KB chunks: a size histogram built on the wire
                          count would move with the client's buffer size. 0 =
                          the dialect has no logical size to report */
    const char *op;    /* protocol operation name, borrowed for the callback: the
                          HTTP method ("GET"), for every dialect including S3 —
                          РS7's `method` label is exactly this. What an S3
                          request *is* (`PutObject`) is its identity, not its
                          verb, and travels in `route` */
    const char *route; /* HTTP (РH7, М4): the *templated* request identity —
                          `/orders/{id}` for the base dialect, an operation
                          name for a dialect that has one (РH8, and РS2 where
                          the name comes from a closed table rather than a
                          heuristic). Borrowed for the callback like `text`, and
                          never the raw path: `text` keeps that for the span,
                          this is what may become a label. NULL for the DB
                          protocols, and for an HTTP unit whose target never
                          arrived */
    __u32 route_len;
    __u64 route_fp;                   /* XXH3-64 of `method NUL route`: the identity the М5
                                         top-K keys on. The method is in it because two
                                         methods on one path are two routes (РH7) */
    const char *err_name;             /* symbolic error name, borrowed for the callback: the
                                         S3 dialect's `<Code>` (РS5), folded to `other`
                                         outside the known vocabulary. NULL for the base
                                         HTTP dialect and the DB protocols, whose error
                                         identity is err_code / sqlstate */
    const struct lk_http_obs *http;   /* HTTP span material (РH11, М6), borrowed for
                                         the callback; NULL for the DB protocols */
    const struct lk_redis_obs *redis; /* Redis batch material (РR3, МR2), borrowed
                                         for the callback; NULL everywhere else */
    char sqlstate[6];                 /* on LK_QO_ERROR, C-string */
    __u16 err_code;                   /* vendor error code (MySQL errno) on LK_QO_ERROR; 0 =
                                         none/unknown (PG has no numeric code) — М6 span attr.
                                         HTTP reuses it for the status code, which is set on
                                         *every* observation, not only failing ones (РH10) */
    __u8 kind;                        /* enum lk_query_kind */
    char txn_status;                  /* I/T/E from the closing Z; 0 = unknown (HTTP: none) */
    __u16 flags;                      /* LK_QO_* */
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
    __u64 orphan_msgs;            /* a framer message with no live unit to attach it
                                     to (РH6): a response on a connection joined
                                     mid-stream, or one arriving after its unit was
                                     emitted. Not a parse error — the input was
                                     fine, we simply never saw its request */
    __u64 redirects;              /* `-MOVED` / `-ASK` replies (РR7): errors in syntax
                                     and ordinary cluster operation in fact. Counted
                                     here and *not* in errors_sql, because a resharding
                                     cluster produces them continuously and an agent
                                     that called them failures would report every
                                     healthy cluster as broken */
    __u64 pushes;                 /* the deliberate twin of orphan_msgs: server values
                                     that closed no unit *by construction* (РR8) — a
                                     pub/sub delivery, a client-side-caching
                                     invalidation, or the second and later
                                     confirmations of one multi-channel SUBSCRIBE.
                                     Nothing was lost; a queue that let them close
                                     units would mis-time every later command on the
                                     connection */
    __u64 prep_evictions;         /* prepared-statement cache evictions */
    __u64 sessions;               /* on_session emitted */
    __u64 replication_conns;      /* CopyBoth / binlog dump / PSYNC -> IGNORE conns */
    __u64 monitor_conns;          /* MONITOR -> IGNORE connections (РR14). Its own
                                     reason rather than replication's: the connection
                                     turns into a feed of *other clients'* commands,
                                     which is a different fact about a deployment and
                                     a different conversation with its operator */
    __u64 compressed_conns;       /* CLIENT_COMPRESS/_ZSTD -> IGNORE connections (РМ7) */
    __u64 blind_conns;            /* protocol switched away from what we parse ->
                                     IGNORE connections (РH4: the HTTP/2 preface,
                                     a 101 upgrade, a CONNECT tunnel). The total;
                                     the three below split it by reason, because
                                     "we cannot see h2" and "somebody opened a
                                     websocket" are different facts about a
                                     deployment and only one of them is a
                                     surprise (М5). */
    __u64 blind_h2;               /* ... an HTTP/2 preface: h2, hence gRPC */
    __u64 blind_upgrade;          /* ... a 101: websocket, h2c, anything else */
    __u64 blind_connect;          /* ... a CONNECT tunnel */
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

/* lk_proto_ops.flags
 *
 * LK_PROTO_F_STREAM (РH1) — stream framing: the protocol assembles messages
 * itself out of the raw bytes and holes it receives through stream_bytes /
 * stream_hole and publishes them with lk_reasm_emit; the generic
 * HEADER/BODY/SKIP/DIRTY machine and the hdr_size/parse_hdr/pre_emit/resync_*
 * hooks are not used. For protocols whose header block carries no length
 * prefix and has no bound that fits lk_frame.hdr[8] — HTTP/1.x ends its one
 * at the first CRLFCRLF, kilobytes in. */
#define LK_PROTO_F_STREAM (1 << 0)

/* Which side of the conversation the port filter puts us on (РH2). v1 captures
 * by *local* port, so every protocol is observed server-side: RECV is the
 * request stream, SEND the response one. The field is the seam for the client
 * mode (`--peer-port 80=http`, filtering by skc_dport) — it exists so the
 * assumption is named rather than implied by the direction constants. */
enum lk_proto_role {
    LK_ROLE_SERVER = 0, /* the capture filter matched our local port */
    LK_ROLE_CLIENT,     /* (not in v1) the filter matched the remote port */
};

/* Span shape a protocol's observations produce (РH11, wired in М6). Not every
 * protocol is a database: the field replaces the unconditional db_system, which
 * silently assumed one. db.* attributes and db_system are read only for
 * LK_OTEL_KIND_DB; LK_OTEL_KIND_HTTP takes the HTTP semconv path. */
enum lk_otel_kind {
    LK_OTEL_KIND_DB = 0, /* db.system.name / db.query.text / db.namespace */
    LK_OTEL_KIND_HTTP,   /* http.request.method / http.route / http.response.* */
};

/* Which metric families a protocol's observations are reported in (РH10, М5).
 * Mirrors enum lk_profile (metrics.h) value for value — the metrics library
 * stays free of the protocol headers, exactly as lk_qkind mirrors
 * lk_query_kind. Kept apart from otel_kind on purpose: the S3 dialect
 * (PLAN-MINIO.md) is an HTTP span with a metric profile of its own, so the two
 * questions have two answers even though today they agree. */
enum lk_proto_profile {
    LK_PROTO_PROF_QUERY = 0, /* latkit_query_*{query,db,user} */
    LK_PROTO_PROF_HTTP,      /* latkit_http_*{route,method,host,user} */
    LK_PROTO_PROF_S3,        /* latkit_s3_*{op,method,bucket,user} (РS7, МS2) */
    LK_PROTO_PROF_REDIS,     /* latkit_redis_*{cmd,db,user} (РR11, МR5) */
};

/* --- the HTTP dialect seam (РH8) ------------------------------------------ */

/* One flavour of HTTP. The framer, the unit lifecycle and the four timings are
 * the protocol and are shared; what an exchange is *called* — and which handful
 * of headers say it — is the dialect, and that is the whole difference between
 * `--port 8080=http` (a templated route, РH7) and `--port 9000=s3` (an operation
 * out of a closed table, РS1). Two registry entries, one implementation: the
 * alternative was forking the handler, and a fork is where the second copy stops
 * getting the bug fixes.
 *
 * Declared here and *defined* in src/proto/http/http.h, because its hooks speak
 * in the handler's own types (the unit, the header spans) and the core has no
 * business knowing those. A pointer to an incomplete type is all lk_proto_ops
 * needs, so events.c and the sinks include proto.h and learn nothing. */
struct lk_http_dialect;

/* One wire protocol: its name (the `--port N=<name>` selector), its handler
 * constructor, and the framer knowledge reassembly.c calls out for. The framer
 * hooks are pure state manipulation over lk_frame / lk_conn flags — no I/O, no
 * allocation. Which hooks are mandatory depends on the framing mode:
 *
 *   - message framing (flags == 0, PG/MySQL): everything but the two
 *     intercept_* hooks, and stream_bytes/stream_hole are unused;
 *   - stream framing (LK_PROTO_F_STREAM, HTTP): stream_bytes/stream_hole only —
 *     the whole hdr_size/parse_hdr/pre_emit/resync_* set is unused, because
 *     the protocol owns its own state machine (see below).
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
 *    type + plausible len).
 *  - stream_bytes/stream_hole (LK_PROTO_F_STREAM only, РH1) receive the
 *    direction's byte stream after *all* the generic mechanics have run —
 *    chunk arithmetic, off-anomalies, the TLS/IGNORE drop, the hole and
 *    loss counters — but before any framing interpretation: there is no
 *    header accumulator, no arithmetic body skip and no LK_FR_* transition
 *    behind them. The protocol keeps its state in lk_conn.frame_state,
 *    reads lk_frame.st == LK_FR_DIRTY as "the connection table saw loss"
 *    (the seq detector still dirties both directions), leaves that state
 *    through lk_reasm_resync and publishes assembled messages with
 *    lk_reasm_emit — so consumers still see nothing but lk_msg. */
struct lk_proto_ops {
    const char *name;                      /* the `--port N=<name>` selector AND the `proto`
                                              metric label value (РМ6): "pg" / "mysql" / "http" */
    const char *db_system;                 /* OTel semconv db.system.name for the spans (М6):
                                              "postgresql" / "mysql". Read only when
                                              otel_kind == LK_OTEL_KIND_DB. */
    enum lk_otel_kind otel_kind;           /* span shape the observations produce (РH11) */
    enum lk_proto_profile profile;         /* metric families they are reported in (РH10) */
    enum lk_proto_role role;               /* which side the port filter puts us on (РH2) */
    __u16 flags;                           /* LK_PROTO_F_* */
    enum lk_sql_dialect sql_dialect;       /* normaliser dialect for this protocol's
                                              SQL (РМ9; М6 threads it to the sinks) */
    const struct lk_http_dialect *dialect; /* HTTP flavour (РH8); NULL for the
                                              database protocols, which have no
                                              classification step at all */
    __u32 cap_limit;                       /* default per-call capture budget of a port
                                              speaking this protocol, bytes (РH14, М7);
                                              0 = follow --capture-limit, which is what
                                              the database protocols want. HTTP asks for
                                              less: it needs heads, and a gigabyte of
                                              response body copied into the ringbuf buys
                                              nothing. An explicit `--port N=http:BYTES`
                                              overrides it. */

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
    void (*stream_bytes)(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, const __u8 *p,
                         __u32 n, __u64 ts_ns);
    void (*stream_hole)(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, __u64 n);
    /* Redact a message body that is about to be *shown* — `--messages --hexdump`
     * and the lkt_messages harness (РH3, М6). It runs on the viewer's own copy,
     * in place, and never on the framer's buffer: the handler downstream must
     * still see the head as it arrived, because `--http-user basic` reads the
     * very header this hides. NULL means "nothing here needs hiding", which is
     * the honest answer for PG and MySQL — their credentials travel in an
     * authentication exchange the framer never republishes. */
    void (*mask_body)(const struct lk_msg *m, __u8 *p, __u32 n);
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

/* HTTP/1.x: stream framing (РH1) in src/proto/http/http_frame.c, the handler in
 * src/proto/http/http.c + http_req.c / http_resp.c — `--port 8080=http`. */
extern const struct lk_proto_ops lk_proto_http_ops;
struct lk_proto *lk_proto_http_new(const struct lk_query_sink *out);

/* S3, which is HTTP/1.1 with a particular reading of the path, the query and six
 * headers (РS1, PLAN-MINIO.md МS1) — `--port 9000=s3`. The same framer, the same
 * handler and the same constructor as the entry above; everything that differs
 * hangs off `.dialect`, in src/proto/s3/s3_dialect.c. */
extern const struct lk_proto_ops lk_proto_s3_ops;

/* Redis (RESP2/RESP3): stream framing (РR2) in src/proto/redis/redis_frame.c,
 * the handler in src/proto/redis/redis.c — `--port 6379=redis`. A new protocol
 * rather than a dialect (РR1): RESP has no heads, no statuses and no routes, so
 * the `.dialect` seam above does not apply to it and stays NULL. Valkey, KeyDB,
 * Dragonfly and Sentinel are the same wire and the same entry. */
extern const struct lk_proto_ops lk_proto_redis_ops;
struct lk_proto *lk_proto_redis_new(const struct lk_query_sink *out);

/* Handler-wide Redis settings (РR6), the lk_http_cfg twin and process-wide for
 * the same reason: one handler per agent, values fixed at startup. Call before
 * the first event; NULL restores the defaults, and the default — a zeroed
 * struct — is `--redis-user acl`.
 *
 * One knob, where HTTP has six, because Redis needs no route heuristic and no
 * query redactor: its identities come from a closed table and its arguments are
 * never read at all. The one decision an operator still has is whether the ACL
 * user becomes a label, and unlike `--http-user` it defaults to *on* — the name
 * is its own array element, so reading it costs nothing and touches no
 * credential, while `Authorization: Basic` hid the name inside the same base64
 * blob as the password (РH12 vs РR6). */
struct lk_redis_cfg {
    bool no_user; /* `--redis-user off`: never derive a user label from `AUTH` */
};
void lk_proto_redis_configure(const struct lk_redis_cfg *cfg);

/* Handler-wide HTTP settings (РH10/РH7). Process-wide rather than per-handler
 * because there is exactly one http handler instance per agent and the values
 * are fixed at startup from the CLI; the *dialect* is per port and travels on
 * lk_proto_ops instead, which is the split РH8 asked for — what an exchange is
 * called depends on the port, how much of it we are allowed to read does not.
 * Call before the first event; NULL restores the defaults.
 *
 * Everything the route config points at is borrowed and must outlive the agent's
 * event loop: in main.c that is argv and the map parsed at startup. */
struct lk_http_cfg {
    /* --http-redact (РH12), and the one setting here whose default is *on*: the
     * values of credential-shaped query keys are replaced by `***` before the
     * target leaves the handler, so no export path can carry one. Off restores
     * the byte-exact target — a debugging choice, and one an operator has to
     * make deliberately. A zeroed lk_http_cfg therefore means "redact", which is
     * why the field is spelled as an opt-out. */
    bool no_redact;
    bool user_basic;           /* --http-user basic: take the `user` label from the name
                                  half of `Authorization: Basic`. Off by default — it is
                                  an identity, and the plan's rule is that nothing leaves
                                  the wire unless it was asked for (РH12). The password
                                  half is never decoded past the colon, ever. */
    struct lk_route_cfg route; /* --http-routes / --http-route-depth /
                                  --http-query-keys (РH7) */
    char route_header[32];     /* --http-route-header X-Route: trust this header
                                  as the route when present. "" = off, and off is
                                  the default — the value arrives from the network
                                  like every other header, so the only thing
                                  protecting cardinality here is the top-K
                                  dictionary downstream (РH7) */
    struct lk_s3_cfg s3;       /* --s3-domain / --s3-user (РS3/РS4): read only by
                                  the S3 dialect, and inert for every port that is
                                  not one. Here rather than on lk_proto_ops for the
                                  same reason as the rest of this struct — it is a
                                  startup decision of the operator's, not a
                                  property of the wire protocol */
};
void lk_proto_http_configure(const struct lk_http_cfg *cfg);

/* The registry: one entry per supported protocol, PG first (the default).
 * LK_PROTO_MAX caps it so consumers can size parallel arrays statically.
 * Raised to 8 for the HTTP track (РH9): pg + mysql + http + the s3 dialect
 * (PLAN-MINIO.md) already fill the old ceiling of 4, and a protocol that does
 * not fit the registry would silently disappear from the `proto` label. */
#define LK_PROTO_MAX 8
extern const struct lk_proto_ops *const lk_proto_registry[];
extern const unsigned lk_proto_nregistry;

/* Name lookup for the CLI (`--port 3306=mysql`); NULL when unknown. */
const struct lk_proto_ops *lk_proto_find(const char *name, size_t name_len);

/* Copy a message body for *display* — `--messages --hexdump` and lkt_messages —
 * through the protocol's mask_body hook (РH3/РH12, М6). Returns the number of
 * bytes written to out (min(m->body_cap, outcap)).
 *
 * A copy rather than a mask in place, and that is the whole point: the framer's
 * buffer belongs to the parser, which still has to read the header this hides
 * (`--http-user basic`). One helper rather than the same six lines in every
 * viewer, so a new consumer of lk_msg cannot print a credential by not knowing
 * it had to ask. */
__u32 lk_msg_body_for_display(const struct lk_proto_ops *ops, const struct lk_msg *m, __u8 *out,
                              __u32 outcap);

#endif /* LATKIT_PROTO_H */
