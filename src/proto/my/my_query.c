// SPDX-License-Identifier: GPL-2.0
/* MySQL query phase machine (MYSQL.md М3, РМ5/РМ8). Turns the strict
 * request -> response exchanges into one lk_query_obs per query unit:
 *
 *   COM_QUERY          opens a SIMPLE unit, copies the SQL text (offset past
 *                      the CLIENT_QUERY_ATTRIBUTES header — plan risk 4);
 *   COM_STMT_EXECUTE   opens an EXTENDED unit, text from the stmt_id cache;
 *   COM_STMT_FETCH     opens an EXTENDED cursor unit (rows arrive directly,
 *                      the PortalSuspended analogue);
 *   row packets        counted (SELECT rows are a lower bound under capture
 *                      holes, РМ5) and stamp ts_first_row;
 *   OK / ERR / EOF     terminate: rows += affected_rows (DML), SQLSTATE from
 *                      ERR, SERVER_MORE_RESULTS_EXISTS chains resultsets into
 *                      one MULTI_STMT unit, IN_TRANS edges drive on_txn;
 *   0xFB               LOAD DATA LOCAL: the unit becomes COPY_IN, client data
 *                      packets add bytes, the final OK supplies rows.
 *
 * A server packet has no self-describing type: enum my_reply (what the
 * backend is answering) plus the first payload byte classify it. The
 * 0xFE disambiguation is the protocol's own: an EOF is shorter than 9 bytes;
 * with CLIENT_DEPRECATE_EOF the terminator is an OK with a 0xFE header and
 * any length below the 16 MB continuation ceiling. When the capabilities are
 * unknown (synthetic / resynced entry) the length alone decides — the same
 * rule, degraded honestly.
 *
 * ts_ready == ts_complete everywhere: MySQL has no separate ReadyForQuery,
 * the done-point is single (notes-myproto).
 *
 * Honesty invariants (Р19): a unit open when the stream breaks, the
 * connection closes, or a new command arrives (the РМ4 frontend-anchor
 * discipline) is dropped, never emitted. Pure, no I/O: every field goes
 * through the bounded my_wire cursor (Р18); a corrupt field on a *full* body
 * bumps parse_errors and drops the unit. */
#include "my.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strncasecmp for the ROLLBACK verb probe */

#include "my_wire.h"
#include "reassembly.h" /* LK_MSG_* flags, LK_MSG_BODY_MAX */

#define MY_PKT_MAX 0xFFFFFFu /* the u24 continuation ceiling (my_frame.c) */

/* Column-count sanity ceiling: the server caps result width at 4096 columns;
 * anything larger is a misclassified packet, not a resultset head. */
#define MY_MAX_COLUMNS 4096

static bool deprecate_eof(const struct my_conn *pc)
{
    return pc->caps_known && (pc->caps & MY_CAP_DEPRECATE_EOF);
}

/* Is this 0xFE-headed packet a terminator, and which shape (РМ3)? With the
 * caps unknown both questions fall back to the length rule alone. */
static bool fe_terminator(const struct my_conn *pc, const struct lk_msg *m, bool *eof_shape)
{
    if (pc->caps_known && !(pc->caps & MY_CAP_DEPRECATE_EOF)) {
        *eof_shape = true;
        return m->len < 9;
    }
    *eof_shape = !pc->caps_known && m->len < 9;
    return m->len < MY_PKT_MAX;
}

/* --- unit lifecycle -------------------------------------------------------- */

/* Reset-and-open the single in-flight unit, keeping the owned text buffer
 * across occupants (freed only on conn close, the pg_unit pattern). */
static struct my_unit *unit_open(struct my_conn *pc, __u8 kind, __u64 ts)
{
    struct my_unit *u = &pc->u;
    char *buf = u->own_text;
    __u32 cap = u->own_cap;

    memset(u, 0, sizeof(*u));
    u->own_text = buf;
    u->own_cap = cap;
    u->prep_idx = -1;
    u->kind = kind;
    u->ts_start_ns = ts;
    pc->unit_open = true;
    return u;
}

void my_query_drop_unit(struct my_conn *pc, __u64 *counter)
{
    if (!pc->unit_open)
        return;
    if (counter)
        (*counter)++;
    pc->unit_open = false;
}

/* A structured field overran a *full* body (Р18): corrupt content on valid
 * framing. Count it, drop the unit, expect nothing more from this reply. */
static void corrupt(struct lk_proto *p, struct my_conn *pc)
{
    p->st.parse_errors++;
    my_query_drop_unit(pc, NULL);
    pc->reply = MY_R_NONE;
}

/* --- text ------------------------------------------------------------------ */

/* Grow the unit's owned buffer to n bytes; false (and NO_TEXT) on OOM. */
static bool own_grow(struct my_unit *u, __u32 n)
{
    if (n > u->own_cap) {
        char *nb = realloc(u->own_text, n);

        if (!nb) {
            u->own_len = 0;
            u->flags |= LK_QO_NO_TEXT;
            return false;
        }
        u->own_text = nb;
        u->own_cap = n;
    }
    return true;
}

void my_query_rescue_ref(struct my_conn *pc, int slot)
{
    struct my_unit *u = &pc->u;
    const struct my_prep *e = &pc->prep->e[slot];

    if (!pc->unit_open || u->prep_idx != slot || u->prep_gen != e->gen)
        return;
    if (e->text_len && own_grow(u, e->text_len)) {
        memcpy(u->own_text, e->text, e->text_len);
        u->own_len = e->text_len;
    } else {
        u->own_len = 0; /* empty text, or OOM (own_grow flagged NO_TEXT) */
    }
    u->prep_idx = -1;
}

/* Resolve the unit's borrowed SQL text: prepared statements read from the stmt
 * cache, COM_QUERY from the owned buffer. *text stays NULL / *len 0 when the
 * text is unknown (NO_TEXT, stale prepared reference, empty). */
static void unit_text(const struct my_conn *pc, const struct my_unit *u, const char **text,
                      __u32 *len)
{
    *text = NULL;
    *len = 0;
    if (u->flags & LK_QO_NO_TEXT)
        return;
    if (u->prep_idx >= 0 && pc->prep) {
        const struct my_prep *e = &pc->prep->e[u->prep_idx];

        if (e->used && e->gen == u->prep_gen && e->text_len) {
            *text = e->text;
            *len = e->text_len;
        }
        /* else: a stale reference the rescue missed — no text, defensive */
    } else if (u->own_len) {
        *text = u->own_text;
        *len = u->own_len;
    }
}

/* Resolve the unit's text into the observation (borrowed for on_query). */
static void fill_text(struct my_conn *pc, const struct my_unit *u, struct lk_query_obs *o)
{
    unit_text(pc, u, &o->text, &o->text_len);
}

/* Did the statement that closed the transaction close it with an explicit
 * ROLLBACK? MySQL answers a ROLLBACK with a plain OK — no error, and its status
 * flags are indistinguishable from a COMMIT — so the statement verb is the only
 * signal that maps a MySQL transaction to the 'aborted' half of
 * latkit_txn_duration_seconds. ROLLBACK TO SAVEPOINT keeps SERVER_STATUS_IN_TRANS
 * set and so never reaches the T->I edge this runs on, making a leading-token
 * match unambiguous. */
static bool unit_is_rollback(const struct my_conn *pc, const struct my_unit *u)
{
    const char *t;
    __u32 n, i = 0;

    unit_text(pc, u, &t, &n);
    if (!t)
        return false;
    while (i < n && (t[i] == ' ' || t[i] == '\t' || t[i] == '\n' || t[i] == '\r'))
        i++;
    if (n - i < 8 || strncasecmp(t + i, "ROLLBACK", 8) != 0)
        return false;
    i += 8; /* word boundary: reject ROLLBACKS / ROLLBACK_x identifiers */
    if (i == n)
        return true;
    return !((t[i] >= 'A' && t[i] <= 'Z') || (t[i] >= 'a' && t[i] <= 'z') ||
             (t[i] >= '0' && t[i] <= '9') || t[i] == '_');
}

/* Skip one binary-protocol parameter value by its type (the value part of a
 * COM_QUERY attribute header). Everything not fixed-width or length-prefixed
 * is a lenenc string — strings, blobs, decimals, json, bit. */
static bool skip_binary_value(struct my_wire *w, __u8 type)
{
    const char *s;
    __u32 sl;
    __u8 l;

    switch (type) {
    case 0x01: /* TINY */
        return my_wire_skip(w, 1);
    case 0x02: /* SHORT */
    case 0x0d: /* YEAR */
        return my_wire_skip(w, 2);
    case 0x03: /* LONG */
    case 0x04: /* FLOAT */
    case 0x09: /* INT24 */
        return my_wire_skip(w, 4);
    case 0x05: /* DOUBLE */
    case 0x08: /* LONGLONG */
        return my_wire_skip(w, 8);
    case 0x06: /* NULL */
        return true;
    case 0x07: /* TIMESTAMP */
    case 0x0a: /* DATE */
    case 0x0b: /* TIME */
    case 0x0c: /* DATETIME */
        return my_wire_get_u8(w, &l) && my_wire_skip(w, l);
    default:
        return my_wire_get_lenenc_str(w, &s, &sl);
    }
}

/* The CLIENT_QUERY_ATTRIBUTES ceiling we bother skipping past: attributes are
 * a handful in practice; a bigger count is garbage (or not worth the walk). */
#define MY_ATTR_MAX 64

/* Locate the SQL text inside a COM_QUERY body: offset 1 without query
 * attributes; with them, past the two lenenc counts and — when parameters are
 * present — the null bitmap, types+names and values (plan risk 4: reading the
 * text at a fixed offset is the classic corruption bug). Unknown caps sniff
 * the header: SQL never starts with a NUL byte, so 0x00 0x01 right after the
 * command byte can only be the {param_count=0, set_count=1} pair every 8.x
 * client emits. Returns false when the text cannot be located (the unit goes
 * NO_TEXT rather than carrying garbage). */
static bool query_text_off(const struct my_conn *pc, const struct lk_msg *m, __u32 *off)
{
    struct my_wire w;
    __u64 pcount, scount;
    const __u8 *bitmap;
    __u8 types[MY_ATTR_MAX];
    __u8 bound;

    *off = 1;
    if (pc->caps_known) {
        if (!(pc->caps & MY_CAP_QUERY_ATTRIBUTES))
            return true;
    } else if (!(m->body_cap >= 3 && m->body[1] == 0x00 && m->body[2] == 0x01)) {
        return true;
    }

    my_wire_init(&w, m->body, m->body_cap);
    if (!my_wire_skip(&w, 1) || !my_wire_get_lenenc(&w, &pcount) ||
        !my_wire_get_lenenc(&w, &scount))
        return false;
    if (pcount > MY_ATTR_MAX)
        return false;
    if (pcount) {
        __u32 nb = ((__u32)pcount + 7) / 8;

        bitmap = w.p; /* validated by the skip below before it is read */
        if (!my_wire_skip(&w, nb) || !my_wire_get_u8(&w, &bound))
            return false;
        if (!bound)
            return false; /* types absent: value sizes unknowable */
        for (__u32 i = 0; i < pcount; i++) {
            const char *nm;
            __u32 nl;

            if (!my_wire_get_u8(&w, &types[i]) || !my_wire_skip(&w, 1) ||
                !my_wire_get_lenenc_str(&w, &nm, &nl))
                return false;
        }
        for (__u32 i = 0; i < pcount; i++) {
            if (bitmap[i / 8] & (1 << (i % 8)))
                continue; /* NULL: no value bytes */
            if (!skip_binary_value(&w, types[i]))
                return false;
        }
    }
    *off = (__u32)(w.p - m->body);
    return true;
}

/* --- frontend: unit-opening commands --------------------------------------- */

void my_query_simple(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m)
{
    struct my_unit *u = unit_open(pc, LK_Q_SIMPLE, m->ts_ns);
    __u32 off, n;

    (void)p;
    pc->reply = MY_R_HEAD;
    if (!query_text_off(pc, m, &off) || off >= m->body_cap) {
        /* Attributes unreadable, or the text fell entirely past the captured
         * prefix: latency is honest, the text is unknown. */
        u->flags |=
            (m->flags & LK_MSG_BODY_TRUNC) ? LK_QO_NO_TEXT | LK_QO_TEXT_TRUNC : LK_QO_NO_TEXT;
        return;
    }
    n = m->body_cap - off;
    if (n > LK_MSG_BODY_MAX)
        n = LK_MSG_BODY_MAX;
    if (!own_grow(u, n))
        return;
    memcpy(u->own_text, m->body + off, n);
    u->own_len = n;
    if (m->flags & LK_MSG_BODY_TRUNC)
        u->flags |= LK_QO_TEXT_TRUNC;
}

/* Shared by COM_STMT_EXECUTE / FETCH / MariaDB bulk: the stmt_id sits right
 * after the command byte; the parameter tail is never parsed (only the cache
 * reference matters). */
static struct my_unit *open_stmt_unit(struct my_conn *pc, const struct lk_msg *m)
{
    struct my_unit *u = unit_open(pc, LK_Q_EXTENDED, m->ts_ns);
    struct my_wire w;
    __u32 stmt_id, gen;
    bool trunc;
    int idx;

    my_wire_init(&w, m->body, m->body_cap);
    if (!my_wire_skip(&w, 1) || !my_wire_get_u32(&w, &stmt_id)) {
        u->flags |= LK_QO_NO_TEXT; /* stmt_id cut by the capture budget */
        return u;
    }
    idx = my_prep_lookup(pc, stmt_id, &gen, &trunc);
    if (idx < 0) {
        /* Execute on an id not in the cache (agent started after the PREPARE,
         * eviction, synthetic entry): honest latency, unknown text. */
        u->flags |= LK_QO_NO_TEXT;
    } else {
        u->prep_idx = idx;
        u->prep_gen = gen;
        if (trunc)
            u->flags |= LK_QO_TEXT_TRUNC;
    }
    return u;
}

void my_query_execute(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m)
{
    (void)p;
    open_stmt_unit(pc, m);
    pc->reply = MY_R_HEAD;
}

/* COM_STMT_FETCH: a cursor batch — rows arrive with no resultset head, closed
 * by an EOF/OK carrying CURSOR_EXISTS (more to fetch -> SUSPENDED, the
 * PortalSuspended analogue) or LAST_ROW_SENT (drained). */
void my_query_fetch(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m)
{
    (void)p;
    open_stmt_unit(pc, m);
    pc->reply = MY_R_ROWS;
}

/* LOAD DATA LOCAL client stream: raw data packets (bytes counted, bodies
 * never read), the empty packet marks EOF — the server's final OK follows. */
void my_query_infile_data(struct my_conn *pc, const struct lk_msg *m)
{
    if (m->len == 0)
        return; /* EOF marker; MY_R_HEAD is already armed for the final OK */
    if (pc->unit_open)
        pc->u.bytes += m->len;
}

/* --- OK / EOF / ERR parsing ------------------------------------------------ */

/* Session-state info trailing an OK (CLIENT_SESSION_TRACK): entries of
 * {type u8, data lenenc-str}; SESSION_TRACK_SCHEMA (1) carries the new
 * default schema as a nested lenenc string — the live `db` label for a plain
 * `USE db` that COM_INIT_DB alone would miss (notes-myproto). */
static void parse_session_track(struct my_conn *pc, struct my_wire *w)
{
    const char *info, *data;
    __u32 ilen, dlen;
    __u64 total;

    if (!my_wire_get_lenenc_str(w, &info, &ilen)) /* human-readable info */
        return;
    if (!my_wire_get_lenenc(w, &total))
        return;
    while (my_wire_remaining(w)) {
        __u8 type;

        if (!my_wire_get_u8(w, &type) || !my_wire_get_lenenc_str(w, &data, &dlen))
            return;
        if (type == 1) { /* SESSION_TRACK_SCHEMA */
            struct my_wire iw;
            const char *schema;
            __u32 slen;

            my_wire_init(&iw, (const __u8 *)data, dlen);
            if (my_wire_get_lenenc_str(&iw, &schema, &slen) && slen) {
                __u32 n = slen < sizeof(pc->session.database) - 1
                              ? slen
                              : (__u32)(sizeof(pc->session.database) - 1);

                memcpy(pc->session.database, schema, n);
                pc->session.database[n] = '\0';
            }
        }
    }
}

void my_query_parse_ok(struct my_conn *pc, const struct lk_msg *m, bool eof_shape, struct my_ok *ok)
{
    struct my_wire w;

    memset(ok, 0, sizeof(*ok));
    my_wire_init(&w, m->body, m->body_cap);
    if (!my_wire_skip(&w, 1)) /* the 0x00 / 0xFE header byte */
        return;
    if (eof_shape) {
        /* EOF: warnings u16, status u16 — nothing else. */
        ok->have_status = my_wire_get_u16(&w, &ok->warnings) && my_wire_get_u16(&w, &ok->status);
        return;
    }
    if (!my_wire_get_lenenc(&w, &ok->affected) || !my_wire_get_lenenc(&w, &ok->insert_id))
        return; /* cut by the capture budget: counts unknown, not corrupt */
    ok->have_status = my_wire_get_u16(&w, &ok->status) && my_wire_get_u16(&w, &ok->warnings);
    if (ok->have_status && pc->caps_known && (pc->caps & MY_CAP_SESSION_TRACK) &&
        (ok->status & MY_ST_STATE_CHANGED))
        parse_session_track(pc, &w);
}

/* ERR payload: errno u16, then '#' + 5-byte SQLSTATE (PROTOCOL_41). Returns
 * false for a MariaDB progress packet (errno 0xFFFF under MARIADB_CLIENT_
 * PROGRESS) — an event, not an error, and not a terminator either. */
static bool parse_err(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m,
                      char sqlstate[6], __u16 *err_code)
{
    struct my_wire w;
    __u16 eno;
    __u8 mark;

    sqlstate[0] = '\0';
    *err_code = 0;
    my_wire_init(&w, m->body, m->body_cap);
    if (!my_wire_skip(&w, 1) || !my_wire_get_u16(&w, &eno)) {
        if (!(m->flags & LK_MSG_BODY_TRUNC))
            p->st.parse_errors++; /* a full ERR body always carries errno */
        return true;              /* still an error terminator, code unknown */
    }
    if (eno == 0xffff && (pc->mcaps & MY_MCAP_PROGRESS))
        return false; /* progress report: swallow */
    *err_code = eno;
    if (my_wire_get_u8(&w, &mark) && mark == '#') {
        const __u8 *s = w.p;

        if (my_wire_skip(&w, 5)) {
            memcpy(sqlstate, s, 5);
            sqlstate[5] = '\0';
        }
    }
    return true;
}

/* --- terminators ----------------------------------------------------------- */

/* Track SERVER_STATUS_IN_TRANS edges across terminators: material for
 * latkit_txn_duration_seconds, same contract as the PG 'Z' tracking. */
static void txn_track(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                      const struct my_ok *ok, __u64 ts_ns)
{
    char status;

    if (!ok->have_status)
        return;
    status = (ok->status & MY_ST_IN_TRANS) ? 'T' : 'I';
    if (status == 'T' && pc->txn_status != 'T')
        pc->txn_start_ns = ts_ns;
    else if (status == 'I' && pc->txn_status == 'T' && p->out.on_txn) {
        /* 'E' (aborted) when the closing statement was an explicit ROLLBACK,
         * else 'T' (committed) — the sink maps 'E' to status="aborted". Only a
         * live unit carries a trustworthy verb; a status-bearing service OK
         * reuses a stale text buffer, so treat it as committed. */
        char final = (pc->unit_open && unit_is_rollback(pc, &pc->u)) ? 'E' : 'T';

        p->out.on_txn(p->out.ctx, c, pc->txn_start_ns, ts_ns, final);
    }
    pc->txn_status = status;
}

static void emit_unit(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc)
{
    struct my_unit *u = &pc->u;
    struct lk_query_obs o = {
        .ts_start_ns = u->ts_start_ns,
        .ts_first_row_ns = u->ts_first_row_ns,
        .ts_complete_ns = u->ts_complete_ns,
        .ts_ready_ns = u->ts_complete_ns, /* the single done-point */
        .rows = u->rows,
        .bytes = u->bytes,
        .kind = u->copy_kind ? u->copy_kind : u->kind,
        .flags = u->flags,
        .txn_status = pc->txn_status,
    };

    fill_text(pc, u, &o);
    if (u->flags & LK_QO_ERROR) {
        memcpy(o.sqlstate, u->sqlstate, sizeof(o.sqlstate));
        o.err_code = u->err_code;
    }
    p->st.queries++;
    if (u->flags & LK_QO_ERROR)
        p->st.errors_sql++;
    pc->unit_open = false;
    if (p->out.on_query)
        p->out.on_query(p->out.ctx, c, &pc->session, &o);
}

/* An OK-family terminator (OK, terminating 0xFE-OK, or EOF). Closes the unit
 * unless SERVER_MORE_RESULTS_EXISTS chains another resultset onto it. */
static void terminator_ok(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                          const struct lk_msg *m, bool eof_shape)
{
    struct my_ok ok;
    bool more;

    my_query_parse_ok(pc, m, eof_shape, &ok);
    my_session_ok_effects(pc, &ok); /* staged COM_INIT_DB / CHANGE_USER db */
    txn_track(p, c, pc, &ok, m->ts_ns);
    if (pc->phase == MY_PH_INFILE)
        pc->phase = MY_PH_READY; /* the final OK of a LOAD DATA LOCAL */

    more = ok.have_status && (ok.status & MY_ST_MORE_RESULTS);
    if (!pc->unit_open) {
        pc->reply = more ? MY_R_HEAD : MY_R_NONE; /* service-command reply */
        return;
    }
    pc->u.ts_complete_ns = m->ts_ns;
    pc->u.rows += ok.affected; /* DML row count; 0 on EOF / SELECT OKs */
    if (++pc->u.ncomplete > 1)
        pc->u.flags |= LK_QO_MULTI_STMT;
    if (more) {
        pc->reply = MY_R_HEAD; /* next resultset, same unit (multi-statement /
                                * multi-resultset / stored procedure) */
        return;
    }
    if (ok.have_status && (ok.status & MY_ST_CURSOR_EXISTS) && !(ok.status & MY_ST_LAST_ROW_SENT))
        pc->u.flags |= LK_QO_SUSPENDED; /* cursor not drained: FETCH continues */
    pc->reply = MY_R_NONE;
    emit_unit(p, c, pc);
}

/* An ERR terminator: attach the SQLSTATE, close and emit the unit. Aborted
 * multi-statement tails never arrive — the server stops at the first error —
 * so unlike PG there is no ABORTED chain to unwind. */
static void terminator_err(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                           const struct lk_msg *m)
{
    char sqlstate[6];
    __u16 err_code;

    if (!parse_err(p, pc, m, sqlstate, &err_code))
        return; /* MariaDB progress packet: not a terminator */
    if (pc->phase == MY_PH_INFILE)
        pc->phase = MY_PH_READY;
    pc->reply = MY_R_NONE;
    pc->have_pending_db = false; /* a refused COM_INIT_DB commits nothing */
    if (!pc->unit_open)
        return; /* auth/service errors carry no unit */
    pc->u.flags |= LK_QO_ERROR;
    memcpy(pc->u.sqlstate, sqlstate, sizeof(pc->u.sqlstate));
    pc->u.err_code = err_code;
    pc->u.ts_complete_ns = m->ts_ns;
    if (pc->u.ncomplete == 0)
        pc->u.ncomplete = 1; /* the error is this statement's completion */
    emit_unit(p, c, pc);
}

/* --- the reply state machine ----------------------------------------------- */

/* Result head: OK (DML), ERR, the 0xFB LOCAL INFILE request, or a lenenc
 * column count opening a resultset. */
static void reply_head(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                       const struct lk_msg *m)
{
    struct my_wire w;
    __u64 count;
    __u8 head = m->body[0];
    bool eof_shape;

    switch (head) {
    case 0x00:
        terminator_ok(p, c, pc, m, false);
        return;
    case 0xff:
        terminator_err(p, c, pc, m);
        return;
    case 0xfb:
        /* LOAD DATA LOCAL request (the filename is not an observable): the
         * unit becomes COPY_IN, the client streams data packets next. */
        if (pc->unit_open)
            pc->u.copy_kind = LK_Q_COPY_IN;
        pc->phase = MY_PH_INFILE;
        return; /* reply stays MY_R_HEAD for the final OK / ERR */
    case 0xfe:
        if (fe_terminator(pc, m, &eof_shape)) {
            terminator_ok(p, c, pc, m, eof_shape);
            return;
        }
        break; /* a 0xFE lenenc head: falls to the column count below, where
                * the sanity ceiling rejects it as corruption */
    default:
        break;
    }

    my_wire_init(&w, m->body, m->body_cap);
    if (pc->caps_known && (pc->caps & MY_CAP_OPT_METADATA)) {
        __u8 mf;

        /* CLIENT_OPTIONAL_RESULTSET_METADATA: a metadata-follows byte
         * precedes the count. (A resultset with the byte 0 collides with the
         * OK header above — no mainstream client enables this cap; the
         * metadata-present shape is the one handled.) */
        if (!my_wire_get_u8(&w, &mf) || !my_wire_get_lenenc(&w, &count))
            goto bad;
        pc->cols_left = mf ? (__u32)count : 0;
    } else {
        if (!my_wire_get_lenenc(&w, &count))
            goto bad;
        pc->cols_left = (__u32)count;
        if (pc->mcaps & MY_MCAP_CACHE_METADATA) {
            __u8 mf;

            /* MariaDB cached metadata: a send-metadata byte follows the
             * count; 0 = the column definitions (and their EOF) are omitted. */
            if (!my_wire_get_u8(&w, &mf))
                goto bad;
            if (!mf)
                pc->cols_left = 0;
        }
    }
    if (count == 0 || count > MY_MAX_COLUMNS)
        goto bad;
    /* Column definitions (or none, when cached metadata omits them), then —
     * without DEPRECATE_EOF — the metadata EOF, then rows. */
    pc->reply = pc->cols_left ? MY_R_COLS : MY_R_ROWS;
    if (!pc->cols_left && pc->caps_known && !(pc->caps & MY_CAP_DEPRECATE_EOF) &&
        !(pc->mcaps & MY_MCAP_CACHE_METADATA))
        pc->reply = MY_R_COLS; /* zero defs but an EOF still due: wait in COLS */
    return;

bad:
    if (!(m->flags & LK_MSG_BODY_TRUNC)) {
        corrupt(p, pc);
        return;
    }
    /* The head fell victim to the capture budget: classification impossible,
     * the unit cannot be finished honestly. */
    my_query_drop_unit(pc, &p->st.units_dropped_resync);
    pc->reply = MY_R_NONE;
}

/* Column definitions: skipped by count; the post-metadata EOF (pre-DEPRECATE
 * servers) moves to rows — unless it carries CURSOR_EXISTS, in which case it
 * *is* the terminator of a cursor-opening COM_STMT_EXECUTE. */
static void reply_cols(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                       const struct lk_msg *m)
{
    /* A definition packet whose body fell into a capture hole (body_cap == 0)
     * still counts as one skipped definition — the dispatcher lets a blind
     * packet through in MY_R_COLS for exactly that reason (my_query_backend).
     * head == 0 is neither 0xFF nor an EOF, so it falls to the decrement
     * below; reading body[0] unguarded would deref NULL (reply_rows /
     * reply_prep_meta guard the same way). */
    __u8 head = m->body_cap ? m->body[0] : 0;

    if (head == 0xff) {
        terminator_err(p, c, pc, m);
        return;
    }
    if (head == 0xfe && m->len < 9) {
        struct my_ok ok;

        /* The metadata EOF. (A column definition starts with the lenenc
         * catalog string "def" — never 0xFE.) */
        my_query_parse_ok(pc, m, true, &ok);
        if (ok.have_status && (ok.status & MY_ST_CURSOR_EXISTS)) {
            /* Cursor execute: metadata + EOF, no rows — the terminator. */
            txn_track(p, c, pc, &ok, m->ts_ns);
            if (pc->unit_open) {
                pc->u.ts_complete_ns = m->ts_ns;
                pc->u.ncomplete++;
                if (!(ok.status & MY_ST_LAST_ROW_SENT))
                    pc->u.flags |= LK_QO_SUSPENDED;
                pc->reply = MY_R_NONE;
                emit_unit(p, c, pc);
                return;
            }
            pc->reply = MY_R_NONE;
            return;
        }
        pc->cols_left = 0;
        pc->reply = MY_R_ROWS;
        return;
    }
    if (pc->cols_left)
        pc->cols_left--;
    if (!pc->cols_left && deprecate_eof(pc))
        pc->reply = MY_R_ROWS; /* no metadata EOF follows */
}

/* Row packets: counted, never parsed (Р18/РМ5); the terminator closes. */
static void reply_rows(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                       const struct lk_msg *m)
{
    __u8 head = m->body_cap ? m->body[0] : 0;
    bool eof_shape;

    if (m->body_cap) {
        if (head == 0xff) {
            terminator_err(p, c, pc, m);
            return;
        }
        if (head == 0xfe && fe_terminator(pc, m, &eof_shape)) {
            terminator_ok(p, c, pc, m, eof_shape);
            return;
        }
    }
    /* A row (including a body swallowed whole by a capture hole — in a row
     * stretch that is overwhelmingly a row packet). */
    if (pc->unit_open) {
        pc->u.rows++;
        if (pc->u.ts_first_row_ns == 0)
            pc->u.ts_first_row_ns = m->ts_ns;
    }
}

/* COM_STMT_PREPARE metadata: parameter + column definitions, interleaved
 * with EOFs on pre-DEPRECATE servers (never decremented — the counts cover
 * definitions only). */
static void reply_prep_meta(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m)
{
    __u8 head = m->body_cap ? m->body[0] : 0;

    (void)p;
    if (head == 0xfe && m->len < 9)
        return; /* an interleaved EOF */
    if (pc->meta_left)
        pc->meta_left--;
    if (!pc->meta_left)
        pc->reply = MY_R_NONE; /* a trailing EOF, if any, lands in NONE */
}

void my_query_backend(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                      const struct lk_msg *m)
{
    if (pc->reply != MY_R_NONE && m->body_cap == 0 && pc->reply != MY_R_ROWS &&
        pc->reply != MY_R_COLS && pc->reply != MY_R_PREP_META) {
        /* A classifying packet whose whole body fell into a capture hole:
         * the reply cannot be followed honestly. (Rows / definition skips
         * survive a blind packet — it is a countable packet either way.) */
        my_query_drop_unit(pc, &p->st.units_dropped_resync);
        pc->reply = MY_R_NONE;
        pc->pending_prep = false;
        return;
    }

    switch (pc->reply) {
    case MY_R_NONE:
        /* Stray backend packet: a reply to a command we did not observe or
         * chose not to track (e.g. an unknown command). Ignored — the next
         * frontend command re-anchors the exchange. */
        break;
    case MY_R_HEAD:
        reply_head(p, c, pc, m);
        break;
    case MY_R_COLS:
        reply_cols(p, c, pc, m);
        break;
    case MY_R_ROWS:
        reply_rows(p, c, pc, m);
        break;
    case MY_R_PREPARE_OK:
        my_prep_ok(p, pc, m);
        break;
    case MY_R_PREP_META:
        reply_prep_meta(p, pc, m);
        break;
    case MY_R_STRING:
        pc->reply = MY_R_NONE; /* COM_STATISTICS: one bare string packet */
        break;
    case MY_R_FIELD_LIST:
        /* COM_FIELD_LIST: column definitions until an EOF / ERR. */
        if (m->body_cap && (m->body[0] == 0xff || (m->body[0] == 0xfe && m->len < 9)))
            pc->reply = MY_R_NONE;
        break;
    }
}
