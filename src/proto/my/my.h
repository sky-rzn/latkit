/* SPDX-License-Identifier: GPL-2.0 */
/* MySQL classic-protocol handler internals (MYSQL.md М3, РМ8). Shared across
 * the my_*.c translation units, mirroring the pg.h split: my.c dispatches,
 * my_session.c owns the connection phase (greeting / HandshakeResponse / auth
 * cycle / live label updates), my_query.c the reply state machine (units,
 * resultsets, LOAD DATA, transactions), my_prep.c the prepared-statement
 * cache (stmt_id -> SQL, the pg_prep design with a u32 key). The public API
 * is proto.h — nothing here escapes src/proto/my/.
 *
 * The central difference from PG: the classic protocol is strictly
 * request -> response, so the in-flight ring degenerates to a single unit
 * (unit_open), and a server packet has no self-describing type — the reply
 * state (enum my_reply) plus the first payload byte classify it (РМ3,
 * notes-myproto.md "Response classification"). */
#ifndef LATKIT_MY_H
#define LATKIT_MY_H

#include "proto.h"

/* Prepared-statement cache size per connection: same sizing rationale as
 * LK_PG_PREP_CACHE — drivers hold tens of statements, not thousands. */
#define LK_MY_PREP_CACHE 256

/* --- client capability flags (the connection's truth is what the client sent
 * in its HandshakeResponse — the intersection with the server's offer). */
#define MY_CAP_MYSQL                                                                               \
    0x00000001u /* CLIENT_LONG_PASSWORD; MariaDB: clear                                            \
                 * = the filler u32 is extended caps */
#define MY_CAP_CONNECT_WITH_DB    0x00000008u
#define MY_CAP_PROTOCOL_41        0x00000200u
#define MY_CAP_TRANSACTIONS       0x00002000u
#define MY_CAP_MULTI_STATEMENTS   0x00010000u
#define MY_CAP_PLUGIN_AUTH        0x00080000u
#define MY_CAP_CONNECT_ATTRS      0x00100000u
#define MY_CAP_PLUGIN_AUTH_LENENC 0x00200000u
#define MY_CAP_SESSION_TRACK      0x00800000u
#define MY_CAP_DEPRECATE_EOF      0x01000000u
#define MY_CAP_OPT_METADATA       0x02000000u /* CLIENT_OPTIONAL_RESULTSET_METADATA */
#define MY_CAP_QUERY_ATTRIBUTES   0x08000000u
/* CLIENT_SSL / CLIENT_COMPRESS / CLIENT_ZSTD are the framer's business
 * (my_frame.c); the handler never re-reads them. */

/* MariaDB extended capabilities (the u32 in the HandshakeResponse filler,
 * meaningful when MY_CAP_MYSQL is clear). */
#define MY_MCAP_PROGRESS       0x00000001u /* ERR errno 0xFFFF = progress, not error */
#define MY_MCAP_CACHE_METADATA 0x00000010u /* resultset may omit column definitions */

/* --- server status flags (OK / EOF payloads) ------------------------------ */
#define MY_ST_IN_TRANS      0x0001
#define MY_ST_MORE_RESULTS  0x0008 /* SERVER_MORE_RESULTS_EXISTS: unit stays open */
#define MY_ST_CURSOR_EXISTS 0x0040
#define MY_ST_LAST_ROW_SENT 0x0080
#define MY_ST_STATE_CHANGED 0x4000 /* SERVER_SESSION_STATE_CHANGED: track info follows */

/* --- command bytes (РМ8 table in notes-myproto.md) ------------------------ */
#define MY_COM_QUIT                0x01
#define MY_COM_INIT_DB             0x02
#define MY_COM_QUERY               0x03
#define MY_COM_FIELD_LIST          0x04
#define MY_COM_STATISTICS          0x09
#define MY_COM_PROCESS_INFO        0x0a
#define MY_COM_DEBUG               0x0d
#define MY_COM_PING                0x0e
#define MY_COM_CHANGE_USER         0x11
#define MY_COM_BINLOG_DUMP         0x12
#define MY_COM_REGISTER_SLAVE      0x15
#define MY_COM_STMT_PREPARE        0x16
#define MY_COM_STMT_EXECUTE        0x17
#define MY_COM_STMT_SEND_LONG_DATA 0x18
#define MY_COM_STMT_CLOSE          0x19
#define MY_COM_STMT_RESET          0x1a
#define MY_COM_SET_OPTION          0x1b
#define MY_COM_STMT_FETCH          0x1c
#define MY_COM_BINLOG_DUMP_GTID    0x1e
#define MY_COM_RESET_CONNECTION    0x1f
#define MY_COM_MARIADB_BULK        0xfa /* MARIADB_COM_STMT_BULK_EXECUTE */

/* Connection phase. The handshake is owned by my_session.c (sub-state below);
 * INFILE is the LOAD DATA LOCAL client-data stretch (the COPY_IN analogue);
 * IGNORE is the deliberate blind zone (binlog dump, compressed framing). */
enum my_phase {
    MY_PH_HANDSHAKE = 0,
    MY_PH_READY,
    MY_PH_INFILE,
    MY_PH_IGNORE,
};

/* Handshake sub-state (my_session.c). A COM_CHANGE_USER re-enters MY_S_AUTH
 * from the command phase (its auth cycle has the connection-phase shape but
 * no LK_MSG_STARTUP flag — the handler's own state routes it). */
enum my_sess {
    MY_S_GREETING = 0, /* awaiting the server greeting */
    MY_S_RESPONSE,     /* awaiting HandshakeResponse41 (repeats inside TLS) */
    MY_S_AUTH,         /* response consumed, awaiting the final OK / ERR */
    MY_S_DONE,
};

/* What the backend stream is currently answering (РМ3): the protocol is
 * strictly request -> response, so this single state plus the first payload
 * byte classifies every server packet. */
enum my_reply {
    MY_R_NONE = 0,   /* no reply pending; stray backend packets are ignored */
    MY_R_HEAD,       /* result head: OK / ERR / 0xFB infile / column count */
    MY_R_COLS,       /* skipping column definitions (cols_left) */
    MY_R_ROWS,       /* row packets until the terminator */
    MY_R_PREPARE_OK, /* COM_STMT_PREPARE_OK / ERR */
    MY_R_PREP_META,  /* skipping prepare param/column definitions (meta_left) */
    MY_R_STRING,     /* COM_STATISTICS: one bare string packet */
    MY_R_FIELD_LIST, /* COM_FIELD_LIST: column defs until EOF / ERR */
};

/* The single in-flight query unit (depth-1 pg_unit): opened by a command,
 * driven by the reply machine, closed by the terminator (OK / ERR / final
 * EOF). ts_ready == ts_complete — MySQL has no separate ReadyForQuery. */
struct my_unit {
    __u64 ts_start_ns;     /* the command packet */
    __u64 ts_first_row_ns; /* first row packet; 0 = none */
    __u64 ts_complete_ns;  /* the terminator */
    __u64 rows;            /* row packets seen (SELECT, lower bound under holes,
                              РМ5) + affected_rows from OK terminators (DML) */
    __u64 bytes;           /* LOAD DATA LOCAL: summed len of the data packets */
    __u32 ncomplete;       /* terminators consumed (>1 -> LK_QO_MULTI_STMT) */
    __u8 kind;             /* LK_Q_SIMPLE / LK_Q_EXTENDED */
    __u8 copy_kind;        /* 0, or LK_Q_COPY_IN once the 0xFB infile request
                              arrives — the reported observation kind */
    __u16 flags;           /* accumulated LK_QO_* */
    char sqlstate[6];      /* from ERR; valid on LK_QO_ERROR */
    __u16 err_code;        /* MySQL errno from ERR; 0 = unknown (М6 span attr) */

    int prep_idx;   /* prep-cache slot referenced, or -1 (own_text / none) */
    __u32 prep_gen; /* generation of that slot at EXECUTE, validity check */
    char *own_text; /* owned SQL copy (COM_QUERY / eviction rescue); kept
                       across units, freed on conn close */
    __u32 own_len;
    __u32 own_cap;
};

/* One prepared-statement cache entry: stmt_id -> SQL prefix, with the pg_prep
 * generation/rescue machinery intact (Р17 transplanted to a u32 key). */
struct my_prep {
    bool used;
    bool trunc;    /* text is a truncated prefix (-> LK_QO_TEXT_TRUNC) */
    __u32 gen;     /* bumped on slot reuse; stale references are detected */
    __u64 lru;     /* last-access stamp for eviction */
    __u32 stmt_id; /* server-assigned key (COM_STMT_PREPARE_OK) */
    char *text;    /* owned SQL prefix, <= LK_MSG_BODY_MAX; NULL if none */
    __u32 text_len;
    __u32 text_cap;
};

struct my_prep_cache {
    struct my_prep e[LK_MY_PREP_CACHE];
    __u64 clock;
    __u32 count;
};

/* Per-connection parser state — the owner of lk_conn.proto_state (Р15). */
struct my_conn {
    enum my_phase phase;
    enum my_sess sess;
    enum my_reply reply;
    struct lk_session session;
    __u64 msgs;

    __u32 caps;           /* client capability flags (HandshakeResponse) */
    __u32 mcaps;          /* MariaDB extended caps (filler u32, MY_CAP_MYSQL clear) */
    bool caps_known;      /* false on synthetic / resynced-past-handshake entry:
                             terminator classification falls back to length
                             heuristics, COM_QUERY attribute sniffing */
    bool session_emitted; /* on_session fired (once per connection) */

    struct my_unit u;
    bool unit_open;

    __u32 cols_left; /* MY_R_COLS / MY_R_PREP_META countdowns */
    __u32 meta_left;

    /* Pending side effects committed by the reply's OK (strict request ->
     * response makes "the current reply" unambiguous). */
    char pending_db[64];   /* COM_INIT_DB / COM_CHANGE_USER */
    char pending_user[64]; /* COM_CHANGE_USER */
    bool have_pending_db, have_pending_user;

    /* Pending COM_STMT_PREPARE text, bound to a stmt_id by PREPARE-OK. */
    char *pending_text;
    __u32 pending_len, pending_cap;
    bool pending_prep, pending_trunc;

    struct my_prep_cache *prep; /* lazily allocated on the first PREPARE */

    /* Transaction tracking: SERVER_STATUS_IN_TRANS edges on terminators. */
    char txn_status; /* 'T' in transaction / 'I' idle; 0 = unknown */
    __u64 txn_start_ns;
};

/* Parsed OK / EOF terminator payload (my_query.c owns the parser; the session
 * layer reuses it for the final auth OK's session-track info). */
struct my_ok {
    __u64 affected, insert_id; /* OK-shaped only; 0 on EOF */
    __u16 status, warnings;
    bool have_status;
};

/* --- my_session.c: connection phase, labels ------------------------------- */

void my_session_frontend(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                         const struct lk_msg *m);
void my_session_backend(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                        const struct lk_msg *m);

/* Handshake never completed in view but the command phase provably started
 * (framer-forced startup_done): salvage the session if the response was seen,
 * then enter READY. */
void my_session_promote(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc);

/* COM_INIT_DB / COM_CHANGE_USER: stage label updates (committed on OK). */
void my_session_init_db(struct my_conn *pc, const struct lk_msg *m);
void my_session_change_user(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m);

/* Commit staged labels / session-track schema changes from an OK terminator. */
void my_session_ok_effects(struct my_conn *pc, const struct my_ok *ok);

/* --- my_prep.c: stmt_id -> SQL cache -------------------------------------- */

void my_prep_prepare(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m);
void my_prep_ok(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m);
void my_prep_close(struct my_conn *pc, const struct lk_msg *m);
int my_prep_lookup(struct my_conn *pc, __u32 stmt_id, __u32 *gen, bool *trunc);
void my_prep_drop_all(struct my_conn *pc); /* COM_RESET_CONNECTION / CHANGE_USER */
void my_prep_free(struct my_conn *pc);

/* Copy a slot's text into the live unit that references it, then detach the
 * reference — called before a slot is reused. Defined in my_query.c (it owns
 * the copy target), like pg_query_rescue_refs. */
void my_query_rescue_ref(struct my_conn *pc, int slot);

/* --- my_query.c: the reply state machine ---------------------------------- */

void my_query_simple(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m);
void my_query_execute(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m);
void my_query_fetch(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m);
void my_query_infile_data(struct my_conn *pc, const struct lk_msg *m);
void my_query_backend(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                      const struct lk_msg *m);

/* Parse an OK (0x00 / terminating 0xFE) or EOF payload into *ok. eof_shape
 * selects the 5-byte EOF layout (warnings + status) over the OK layout. */
void my_query_parse_ok(struct my_conn *pc, const struct lk_msg *m, bool eof_shape,
                       struct my_ok *ok);

/* Drop the in-flight unit (if any) without emitting, adding it to *counter
 * (resync / close / frontend-anchor discipline, Р19). NULL-safe on counter. */
void my_query_drop_unit(struct my_conn *pc, __u64 *counter);

#endif /* LATKIT_MY_H */
