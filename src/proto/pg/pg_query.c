// SPDX-License-Identifier: GPL-2.0
/* PostgreSQL simple-query state machine (task 3.3, Р16). Turns the frontend
 * Query / backend reply stream into one lk_query_obs per query:
 *
 *   Q                     opens a unit (kind=SIMPLE), copies the SQL text;
 *   D (DataRow)           stamps ts_first_row on the first row;
 *   C (CommandComplete)   adds a statement's row count (>1 -> MULTI_STMT);
 *   I (EmptyQueryResponse) an empty statement (LK_QO_EMPTY);
 *   E (ErrorResponse)     attaches the SQLSTATE and LK_QO_ERROR;
 *   Z (ReadyForQuery)     closes the unit (emit), tracks the transaction.
 *
 * The unit boundary is always Z: for a simple query the client blocks on
 * ReadyForQuery, so C/E/I only accumulate and Z is what emits — a "select 1;
 * select 2" is one unit with two CommandCompletes, not two observations.
 *
 * Honesty invariants (Р19): while READY-degraded (after a resync, on a
 * synthetic connection) no unit opens, and a unit that is open when the stream
 * breaks or the connection closes is dropped, never emitted — an observation
 * must never span a gap.
 *
 * Pure, no I/O: every wire field goes through the bounded pg_wire cursor (Р18),
 * so a truncated or corrupt body can never read past the captured prefix; a
 * corrupt field on a *full* body bumps parse_errors and drops the unit. */
#include "pg.h"

#include <stdlib.h>
#include <string.h>

#include "pg_wire.h"    /* bounded cursor (Р18) */
#include "reassembly.h" /* LK_MSG_* flags, LK_MSG_BODY_MAX */

/* --- text buffer ----------------------------------------------------------- */

/* Copy the Q body (the query text, a single NUL-terminated wire string) into
 * the connection's reused buffer; the body pointer dies with this on_msg but
 * the unit lives until Z. Grows the buffer as needed, capped at the framer's
 * prefix ceiling. On OOM the unit keeps its text empty (NO_TEXT), not stale. */
static void set_text(struct pg_conn *pc, const struct lk_msg *m)
{
    __u32 n = m->body_cap < LK_MSG_BODY_MAX ? m->body_cap : LK_MSG_BODY_MAX;

    if (n > pc->text_cap) {
        char *nb = realloc(pc->text, n);

        if (!nb) {
            pc->text_len = 0;
            pc->unit.flags |= LK_QO_NO_TEXT;
            return;
        }
        pc->text = nb;
        pc->text_cap = n;
    }
    if (n)
        memcpy(pc->text, m->body, n);
    /* Drop the trailing NUL of the wire cstring so the text is the SQL alone;
     * a budget-truncated body has no terminator and keeps every captured byte. */
    if (n && pc->text[n - 1] == '\0')
        n--;
    pc->text_len = n;
}

/* --- CommandComplete tag --------------------------------------------------- */

/* Row count from a CommandComplete tag (Р16). Only the commands that report one
 * do — the number is the tag's last space-separated token ("INSERT 0 5" -> 5,
 * "SELECT 42" -> 42); everything else (BEGIN, SET, CREATE TABLE, ...) is 0. The
 * command whitelist guards against a future tag that merely ends in a digit. */
static __u64 tag_rows(const char *tag, __u32 len)
{
    static const char *const counted[] = {"SELECT", "INSERT", "UPDATE", "DELETE",
                                           "MERGE",  "FETCH",  "MOVE",   "COPY"};
    __u32 cmd = 0, s, e;
    __u64 rows = 0;
    bool ok = false, any = false;

    while (cmd < len && tag[cmd] != ' ')
        cmd++; /* length of the first token (the command verb) */
    for (size_t i = 0; i < sizeof(counted) / sizeof(counted[0]); i++)
        if (cmd == strlen(counted[i]) && memcmp(tag, counted[i], cmd) == 0) {
            ok = true;
            break;
        }
    if (!ok)
        return 0;

    e = len; /* the last token: [s, e) after trimming a trailing space */
    while (e > 0 && tag[e - 1] == ' ')
        e--;
    s = e;
    while (s > 0 && tag[s - 1] != ' ')
        s--;
    for (__u32 k = s; k < e; k++) {
        if (tag[k] < '0' || tag[k] > '9')
            return 0; /* not a pure number: report nothing rather than guess */
        rows = rows * 10 + (__u64)(tag[k] - '0');
        any = true;
    }
    return any ? rows : 0;
}

/* --- corruption ------------------------------------------------------------ */

/* A structured field overran a *full* body (Р18): the content is corrupt though
 * the framing was valid. Count it, drop the unit, and skip to the next clean Z
 * — the same degraded state a resync leaves behind. */
static void corrupt(struct lk_proto *p, struct pg_conn *pc)
{
    p->st.parse_errors++;
    pc->unit_open = false;
    pc->degraded = true;
}

/* --- emit ------------------------------------------------------------------ */

static void emit_unit(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc, char txn_status,
                      __u64 ready_ns)
{
    const struct pg_unit *u = &pc->unit;
    struct lk_query_obs o = {
        .ts_start_ns = u->ts_start_ns,
        .ts_first_row_ns = u->ts_first_row_ns,
        .ts_complete_ns = u->ts_complete_ns,
        .ts_ready_ns = ready_ns,
        .rows = u->rows,
        .kind = u->kind,
        .flags = u->flags,
        .txn_status = txn_status,
    };

    if (!(u->flags & LK_QO_NO_TEXT) && pc->text_len) {
        o.text = pc->text;
        o.text_len = pc->text_len;
    }
    if (u->flags & LK_QO_ERROR)
        memcpy(o.sqlstate, u->sqlstate, sizeof(o.sqlstate));

    p->st.queries++;
    if (u->flags & LK_QO_ERROR)
        p->st.errors_sql++;
    if (p->out.on_query)
        p->out.on_query(p->out.ctx, c, &pc->session, &o);
}

/* --- frontend -------------------------------------------------------------- */

void pg_query_simple(struct pg_conn *pc, const struct lk_msg *m)
{
    if (pc->phase != PG_PH_READY)
        return; /* a Q before AuthenticationOk or mid-COPY is anomalous: ignore */
    if (pc->degraded)
        return; /* observed through a gap: no unit until the next clean Z (Р19) */

    /* Open a fresh unit. A still-open one here means the previous Z was lost;
     * drop it silently rather than emit a unit with no closing boundary. */
    memset(&pc->unit, 0, sizeof(pc->unit));
    pc->unit.kind = LK_Q_SIMPLE;
    pc->unit.ts_start_ns = m->ts_ns;
    set_text(pc, m);
    if (m->flags & LK_MSG_BODY_TRUNC)
        pc->unit.flags |= LK_QO_TEXT_TRUNC;
    pc->unit_open = true;
}

/* --- backend replies ------------------------------------------------------- */

void pg_query_data_row(struct pg_conn *pc, const struct lk_msg *m)
{
    /* Bodies are never parsed (Р18/Р20) — the only thing a DataRow contributes
     * is the time the first row of the unit reached the client. */
    if (pc->unit_open && pc->unit.ts_first_row_ns == 0)
        pc->unit.ts_first_row_ns = m->ts_ns;
}

void pg_query_complete(struct lk_proto *p, struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_wire w;
    const char *tag;
    __u32 tlen;

    if (!pc->unit_open)
        return; /* CommandComplete with no unit (post-resync noise): ignore */

    pg_wire_init(&w, m->body, m->body_cap);
    if (pg_wire_cstring(&w, &tag, &tlen)) {
        pc->unit.rows += tag_rows(tag, tlen);
    } else if (!(m->flags & LK_MSG_BODY_TRUNC)) {
        corrupt(p, pc); /* no terminator in a full body: content is corrupt */
        return;
    }
    /* A truncated tag leaves the count unknown for this statement, but it still
     * completed — count it so a MULTI_STMT is not undercounted. */
    pc->unit.ts_complete_ns = m->ts_ns;
    if (++pc->unit.ncomplete > 1)
        pc->unit.flags |= LK_QO_MULTI_STMT;
}

void pg_query_empty(struct pg_conn *pc, const struct lk_msg *m)
{
    if (!pc->unit_open)
        return;
    pc->unit.flags |= LK_QO_EMPTY;
    pc->unit.ts_complete_ns = m->ts_ns;
    pc->unit.ncomplete++;
}

void pg_query_error(struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_wire w;

    if (!pc->unit_open)
        return; /* error outside a unit (e.g. a startup-phase error): nothing
                 * to attach it to; the session layer stays in charge */

    /* ErrorResponse is a list of (field-type byte, value cstring) pairs ended by
     * a zero field type. Only 'C' (SQLSTATE) has a home in the observation; the
     * rest (message, severity, ...) are skipped. A truncated body may cut the
     * list short — whatever prefix carried 'C' is still salvaged. */
    pg_wire_init(&w, m->body, m->body_cap);
    for (;;) {
        __u8 field;
        const char *val;
        __u32 vlen;

        if (!pg_wire_get_u8(&w, &field) || field == 0)
            break;
        if (!pg_wire_cstring(&w, &val, &vlen))
            break; /* value ran into the captured-prefix end */
        if (field == 'C') {
            /* SQLSTATE is exactly 5 chars; copy into the [6] slot, NUL-terminate. */
            __u32 n = vlen < 5 ? vlen : 5;

            if (n)
                memcpy(pc->unit.sqlstate, val, n);
            pc->unit.sqlstate[n] = '\0';
        }
    }
    pc->unit.flags |= LK_QO_ERROR;
    pc->unit.ts_complete_ns = m->ts_ns;
    if (pc->unit.ncomplete == 0)
        pc->unit.ncomplete = 1; /* the error is this statement's completion */
}

void pg_query_ready(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                    const struct lk_msg *m)
{
    struct pg_wire w;
    __u8 sb;
    char status = 0;

    pg_wire_init(&w, m->body, m->body_cap);
    if (pg_wire_get_u8(&w, &sb))
        status = (char)sb; /* I / T / E; 0 (unknown) if the body was cut */

    if (pc->unit_open) {
        emit_unit(p, c, pc, status, m->ts_ns);
        pc->unit_open = false;
    }
    /* A clean Z is the guaranteed boundary between queries: it is what ends
     * READY-degraded and lets the next Q open a unit again (Р19). */
    pc->degraded = false;

    /* Transaction span (Р16): remember the I->T that opens one, emit on_txn on
     * the T|E -> I that closes it. Material for latkit_txn_duration_seconds. */
    if (status) {
        char prev = pc->txn_status;

        if (status == 'T' && prev != 'T' && prev != 'E')
            pc->txn_start_ns = m->ts_ns;
        else if (status == 'I' && (prev == 'T' || prev == 'E') && p->out.on_txn)
            p->out.on_txn(p->out.ctx, c, pc->txn_start_ns, m->ts_ns, prev);
        pc->txn_status = status;
    }
}

void pg_query_drop(struct pg_conn *pc, __u64 *counter)
{
    if (pc->unit_open) {
        pc->unit_open = false;
        if (counter)
            (*counter)++;
    }
}
