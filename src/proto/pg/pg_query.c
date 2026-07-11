// SPDX-License-Identifier: GPL-2.0
/* PostgreSQL query phase machine (tasks 3.3/3.4, Р16). Turns the frontend
 * request / backend reply streams into one lk_query_obs per query, tracking the
 * in-flight units in a FIFO ring:
 *
 *   simple (Q .. Z):
 *     Q                     opens a SIMPLE unit, copies the SQL text;
 *     D (DataRow)           stamps ts_first_row on the first row;
 *     C (CommandComplete)   adds a statement's row count (>1 -> MULTI_STMT);
 *     I (EmptyQueryResponse) an empty statement (LK_QO_EMPTY);
 *     E (ErrorResponse)     attaches the SQLSTATE and LK_QO_ERROR;
 *     Z (ReadyForQuery)     closes the unit (emit), tracks the transaction.
 *   The client blocks on ReadyForQuery, so a simple query never pipelines: the
 *   single unit accumulates C/D/I/E and only Z emits it ("select 1; select 2"
 *   is one MULTI_STMT observation, not two).
 *
 *   extended (Parse/Bind/Execute .. Sync):
 *     P (Parse)             caches {name -> SQL} (pg_prep.c); opens no unit;
 *     B (Bind)              opens an EXTENDED unit, text from the cache;
 *     E (Execute)           marks execution start (no extra timestamp to record);
 *     C/E/s/I               close the *head* unit one by one (emit immediately);
 *     S (Sync) + Z          end the batch.
 *   Bind..Bind before the replies pipeline: whenever two units coexist in the
 *   ring they are flagged LK_QO_PIPELINED. An ErrorResponse aborts the rest of
 *   the batch (LK_QO_ABORTED, no execution timings) and skips to the Sync/Z.
 *
 * Honesty invariants (Р19): while READY-degraded (after a resync, on a synthetic
 * connection) no unit opens; a unit open when the stream breaks or the
 * connection closes is dropped, never emitted; and an overflowing ring makes the
 * connection LOSSY until the next Z, emitting nothing (a mis-matched reply is
 * worse than a missing observation).
 *
 * Pure, no I/O: every wire field goes through the bounded pg_wire cursor (Р18),
 * so a truncated or corrupt body can never read past the captured prefix; a
 * corrupt field on a *full* body bumps parse_errors and resets to the next Z. */
#include "pg.h"

#include <stdlib.h>
#include <string.h>

#include "pg_wire.h"    /* bounded cursor (Р18) */
#include "reassembly.h" /* LK_MSG_* flags, LK_MSG_BODY_MAX */

/* --- ring -----------------------------------------------------------------
 * A FIFO of units: head is the oldest unclosed (the next a backend reply
 * closes), (head + count) mod N is where the next Q/Bind enqueues. Slots are
 * reused, so unit_reset clears a unit's semantics but keeps its owned text
 * buffer for the next occupant (freed only on conn close). */

static void unit_reset(struct pg_unit *u)
{
    char *buf = u->own_text;
    __u32 cap = u->own_cap;

    memset(u, 0, sizeof(*u));
    u->own_text = buf;
    u->own_cap = cap;
    u->prep_idx = -1; /* no cache reference until Bind sets one */
}

/* Enqueue a fresh unit, or NULL if the ring is full / already LOSSY. Overflow
 * marks the connection LOSSY (Р16): from here to the next Z no observation is
 * emitted, so a reply is never matched to the wrong request. Two coexisting
 * units mean pipelining — flag every in-flight unit LK_QO_PIPELINED. */
static struct pg_unit *ring_push(struct lk_proto *p, struct pg_conn *pc)
{
    struct pg_unit *u;

    /* Full ring, or already LOSSY from an earlier overflow: this unit cannot be
     * opened. Stay LOSSY until the next Z and count every dropped unit (like the
     * other units_dropped_* counters). */
    if (pc->lossy || pc->count >= LK_PG_MAX_INFLIGHT) {
        pc->lossy = true;
        p->st.units_dropped_overflow++;
        return NULL;
    }
    u = &pc->ring[(pc->head + pc->count) % LK_PG_MAX_INFLIGHT];
    pc->count++;
    unit_reset(u);
    if (pc->count > 1)
        for (__u32 i = 0; i < pc->count; i++)
            pc->ring[(pc->head + i) % LK_PG_MAX_INFLIGHT].flags |= LK_QO_PIPELINED;
    return u;
}

void pg_query_drop_all(struct pg_conn *pc, __u64 *counter)
{
    if (counter)
        *counter += pc->count;
    pc->head = 0;
    pc->count = 0;
    pc->nclosed = 0;
    pc->lossy = false;
}

/* --- text -----------------------------------------------------------------
 * A unit resolves its text three ways (Р17): a live reference into the prepared
 * cache (extended), an owned copy (simple query, or the rescue when the cached
 * slot is evicted while the unit is live), or none (LK_QO_NO_TEXT). */

/* Grow a unit's owned buffer and copy in n bytes; caller sets own_len. Returns
 * false (and flags NO_TEXT) on OOM. */
static bool own_grow(struct pg_unit *u, __u32 n)
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

/* Copy a simple Query body (the SQL text, one NUL-terminated wire string) into
 * the unit's owned buffer. The body pointer dies with this on_msg, so the copy
 * is what the unit carries to Z. */
static void set_simple_text(struct pg_unit *u, const struct lk_msg *m)
{
    __u32 n = m->body_cap < LK_MSG_BODY_MAX ? m->body_cap : LK_MSG_BODY_MAX;

    if (!own_grow(u, n))
        return;
    if (n)
        memcpy(u->own_text, m->body, n);
    /* Drop the trailing NUL of the wire cstring; a budget-truncated body has no
     * terminator and keeps every captured byte. */
    if (n && u->own_text[n - 1] == '\0')
        n--;
    u->own_len = n;
}

/* Copy a cache slot's text into every live unit that still references it, then
 * detach the references (prep_idx = -1) so they read their own copy. Called
 * before the slot is reused (pg_prep.c) — the rare path Р17 pays for keeping
 * unit text as a reference in the common case. */
void pg_query_rescue_refs(struct pg_conn *pc, int slot)
{
    const struct pg_prep *e = &pc->prep->e[slot];

    for (__u32 i = 0; i < pc->count; i++) {
        struct pg_unit *u = &pc->ring[(pc->head + i) % LK_PG_MAX_INFLIGHT];

        if (u->prep_idx != slot || u->prep_gen != e->gen)
            continue;
        if (e->text_len && own_grow(u, e->text_len)) {
            memcpy(u->own_text, e->text, e->text_len);
            u->own_len = e->text_len;
        } else {
            u->own_len = 0; /* empty text, or OOM (own_grow flagged NO_TEXT) */
        }
        u->prep_idx = -1;
    }
}

/* Resolve a unit's text into the observation (borrowed for the on_query call). */
static void fill_text(struct pg_conn *pc, const struct pg_unit *u, struct lk_query_obs *o)
{
    if (u->flags & LK_QO_NO_TEXT)
        return;
    if (u->prep_idx >= 0 && pc->prep) {
        const struct pg_prep *e = &pc->prep->e[u->prep_idx];

        if (e->used && e->gen == u->prep_gen && e->text_len) {
            o->text = e->text;
            o->text_len = e->text_len;
        }
        /* else: a stale reference the rescue somehow missed — no text, defensive */
    } else if (u->own_len) {
        o->text = u->own_text;
        o->text_len = u->own_len;
    }
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
 * the framing was valid. Count it, drop the whole in-flight batch (matching any
 * further reply to a request is no longer safe), and skip to the next clean Z —
 * the same degraded state a resync leaves behind. */
static void corrupt(struct lk_proto *p, struct pg_conn *pc)
{
    p->st.parse_errors++;
    pg_query_drop_all(pc, NULL);
    pc->degraded = true;
}

/* --- emit ------------------------------------------------------------------ */

/* Emit one unit up through the query sink. ready_ns is the batch's Z (0 for an
 * ABORTED unit, which never reached its Z honestly, or CANCEL). Does not pop —
 * the whole batch is cleared together after the Z loop. */
static void emit_unit(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                      const struct pg_unit *u, __u64 ready_ns, char txn_status)
{
    struct lk_query_obs o = {
        .ts_start_ns = u->ts_start_ns,
        .ts_first_row_ns = u->ts_first_row_ns,
        .ts_complete_ns = u->ts_complete_ns,
        .ts_ready_ns = ready_ns,
        .rows = u->rows,
        .bytes = u->bytes,
        /* copy_kind (once a Copy*Response arrived) is what the consumer sees;
         * the opening `kind` only drove the internal close semantics (Р20). */
        .kind = u->copy_kind ? u->copy_kind : u->kind,
        .flags = u->flags,
        .txn_status = txn_status,
    };

    fill_text(pc, u, &o);
    if (u->flags & LK_QO_ERROR)
        memcpy(o.sqlstate, u->sqlstate, sizeof(o.sqlstate));
    p->st.queries++;
    if (u->flags & LK_QO_ERROR)
        p->st.errors_sql++;
    if (p->out.on_query)
        p->out.on_query(p->out.ctx, c, &pc->session, &o);
}

/* Simple and FunctionCall units have no per-reply completion — they accumulate
 * (simple) or wait (function) and are closed by the following Z, not by
 * advancing nclosed. Extended units are closed one CommandComplete/Error/etc at
 * a time. */
static bool unit_z_closed(const struct pg_unit *u)
{
    return u->kind == LK_Q_SIMPLE || u->kind == LK_Q_FUNCTION;
}

/* The unit a backend reply currently addresses: the oldest one not yet closed
 * (ring[head + nclosed]), or NULL if every unit is already closed. For a simple
 * query nclosed stays 0, so this is the single open unit. */
static struct pg_unit *current_unit(struct pg_conn *pc)
{
    if (pc->nclosed >= pc->count)
        return NULL;
    return &pc->ring[(pc->head + pc->nclosed) % LK_PG_MAX_INFLIGHT];
}

/* --- frontend -------------------------------------------------------------- */

void pg_query_simple(struct lk_proto *p, struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_unit *u;

    if (pc->phase != PG_PH_READY)
        return; /* a Q before AuthenticationOk or mid-COPY is anomalous: ignore */
    if (pc->degraded)
        return; /* observed through a gap: no unit until the next clean Z (Р19) */

    u = ring_push(p, pc);
    if (!u)
        return; /* ring full: LOSSY until the next Z */
    u->kind = LK_Q_SIMPLE;
    u->ts_start_ns = m->ts_ns;
    set_simple_text(u, m);
    if (m->flags & LK_MSG_BODY_TRUNC)
        u->flags |= LK_QO_TEXT_TRUNC;
}

void pg_query_bind(struct lk_proto *p, struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_wire w;
    const char *portal, *stmt;
    __u32 plen, slen, gen;
    bool have_stmt, trunc;
    struct pg_unit *u;
    int idx;

    if (pc->phase != PG_PH_READY)
        return; /* Bind while skipping to Sync, or mid-COPY: ignore */
    if (pc->degraded)
        return; /* Р19 */

    /* Bind body: portal name, statement name, then parameter formats/values —
     * only the statement name matters (it keys the prepared-statement cache). */
    pg_wire_init(&w, m->body, m->body_cap);
    pg_wire_cstring(&w, &portal, &plen); /* portal name: skipped */
    have_stmt = pg_wire_cstring(&w, &stmt, &slen);
    (void)portal;
    (void)plen;

    u = ring_push(p, pc);
    if (!u)
        return;
    u->kind = LK_Q_EXTENDED;
    u->ts_start_ns = m->ts_ns;
    if (!have_stmt) {
        u->flags |= LK_QO_NO_TEXT; /* couldn't read the name (truncated): no text */
        return;
    }
    idx = pg_prep_lookup(pc, stmt, slen, &gen, &trunc);
    if (idx < 0) {
        /* Bind on a name not in the cache (agent started after Parse, eviction,
         * synthetic connection): the latency is honest, the text is unknown. */
        u->flags |= LK_QO_NO_TEXT;
    } else {
        u->prep_idx = idx;
        u->prep_gen = gen;
        if (trunc)
            u->flags |= LK_QO_TEXT_TRUNC;
    }
}

void pg_query_function(struct lk_proto *p, struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_unit *u;

    if (pc->phase != PG_PH_READY || pc->degraded)
        return;
    /* FunctionCall bodies (the function OID + argument values) are not parsed
     * (Р17): the unit carries no text. It is closed by the following Z, like a
     * simple query — the backend answers FunctionCallResponse then ReadyForQuery,
     * with no CommandComplete. */
    u = ring_push(p, pc);
    if (!u)
        return;
    u->kind = LK_Q_FUNCTION;
    u->ts_start_ns = m->ts_ns;
    u->flags |= LK_QO_NO_TEXT;
}

/* --- backend replies ------------------------------------------------------- */

void pg_query_data_row(struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_unit *u = current_unit(pc);

    /* Bodies are never parsed (Р18/Р20) — a DataRow only contributes the time
     * the first row of the unit reached the client. */
    if (u && u->ts_first_row_ns == 0)
        u->ts_first_row_ns = m->ts_ns;
}

void pg_query_complete(struct lk_proto *p, struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_unit *u = current_unit(pc);
    struct pg_wire w;
    const char *tag;
    __u32 tlen;

    if (!u)
        return; /* CommandComplete with no open unit (post-resync noise): ignore */

    pg_wire_init(&w, m->body, m->body_cap);
    if (pg_wire_cstring(&w, &tag, &tlen)) {
        u->rows += tag_rows(tag, tlen);
    } else if (!(m->flags & LK_MSG_BODY_TRUNC)) {
        corrupt(p, pc); /* no terminator in a full body: content is corrupt */
        return;
    }
    /* A truncated tag leaves the count unknown for this statement, but it still
     * completed — count it so a MULTI_STMT is not undercounted. */
    u->ts_complete_ns = m->ts_ns;
    if (++u->ncomplete > 1)
        u->flags |= LK_QO_MULTI_STMT;
    if (!unit_z_closed(u))
        pc->nclosed++; /* extended: this reply closes the unit; Z will emit it */
}

void pg_query_empty(struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_unit *u = current_unit(pc);

    if (!u)
        return;
    u->flags |= LK_QO_EMPTY;
    u->ts_complete_ns = m->ts_ns;
    u->ncomplete++;
    if (!unit_z_closed(u))
        pc->nclosed++;
}

void pg_query_suspended(struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_unit *u = current_unit(pc);

    if (!u)
        return;
    /* PortalSuspended: an Execute hit its row limit. The unit is closed with
     * LK_QO_SUSPENDED; a following Execute of the same portal would (per Р16's
     * documented simplification) be observed as a fresh unit — which, since we
     * do not track portal->text bindings, simply gets NO_TEXT if it is not
     * re-Bound. PortalSuspended is extended-only. */
    u->flags |= LK_QO_SUSPENDED;
    u->ts_complete_ns = m->ts_ns;
    u->ncomplete++;
    pc->nclosed++;
}

void pg_query_error(struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_unit *u = current_unit(pc);
    struct pg_wire w;

    if (!u)
        return; /* error outside a unit (e.g. a startup-phase error): the session
                 * layer stays in charge; nothing to attach it to */

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
            __u32 n = vlen < 5 ? vlen : 5; /* SQLSTATE is exactly 5 chars */

            if (n)
                memcpy(u->sqlstate, val, n);
            u->sqlstate[n] = '\0';
        }
    }
    u->flags |= LK_QO_ERROR;
    u->ts_complete_ns = m->ts_ns;
    if (u->ncomplete == 0)
        u->ncomplete = 1; /* the error is this statement's completion */

    if (unit_z_closed(u))
        return; /* simple: wait for Z to emit (it carries txn status + ts_ready) */

    /* Extended: the error closes this unit and aborts the rest of the batch
     * (Р16). The backend ignores everything until Sync, so the remaining units
     * are marked LK_QO_ABORTED with no execution timings, and the phase skips to
     * the Sync's Z — which then emits "one ERROR + a tail of ABORTED." */
    pc->nclosed++;
    while (pc->nclosed < pc->count) {
        struct pg_unit *r = &pc->ring[(pc->head + pc->nclosed) % LK_PG_MAX_INFLIGHT];

        r->flags |= LK_QO_ABORTED;
        r->ts_complete_ns = 0;
        r->ts_first_row_ns = 0;
        pc->nclosed++;
    }
    pc->phase = PG_PH_SKIP_TO_SYNC;
}

void pg_query_func_response(struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_unit *u = current_unit(pc);

    /* FunctionCallResponse: the value body is not parsed. The FUNCTION unit is
     * closed by the following Z, so this only stamps the completion time. */
    if (u) {
        u->ts_complete_ns = m->ts_ns;
        u->ncomplete++;
    }
}

/* --- COPY (Р20) ------------------------------------------------------------ */

void pg_query_copy_begin(struct pg_conn *pc, __u8 copy_kind)
{
    struct pg_unit *u = current_unit(pc);

    /* The response bodies (overall + per-column format codes) carry no latency
     * signal, so they are not parsed. Enter the matching COPY phase so a stray
     * Q/Bind is refused until the copy finishes; the opening unit becomes the
     * COPY observation. A CopyInResponse with no open unit (post-resync noise)
     * still switches phase — the next Z clears it. */
    pc->phase = (copy_kind == LK_Q_COPY_IN) ? PG_PH_COPY_IN : PG_PH_COPY_OUT;
    if (u)
        u->copy_kind = copy_kind;
}

void pg_query_copy_data(struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_unit *u = current_unit(pc);

    /* Bytes in flight, not content (Р20): sum the honest protocol len (which
     * stays exact even when the capture budget truncated the body). */
    if (u)
        u->bytes += m->len;
}

void pg_query_copy_both(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc)
{
    /* CopyBothResponse: this is a walsender / logical-replication stream. No
     * per-query observations will ever come from it — drop the queue, count the
     * connection, and go IGNORE. Mark the connection so userspace flips it to
     * HEADERS capture (Р21): gigabytes of WAL should not travel the ringbuf. The
     * flag lives on lk_conn (owned by the core, but a public contract field), so
     * the pure parser stays libbpf-free — the core reads it after this call. */
    pg_query_drop_all(pc, NULL);
    pc->phase = PG_PH_IGNORE;
    c->flags |= LK_CONN_REPLICATION;
    p->st.replication_conns++;
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

    if (!pc->lossy) {
        /* Emit the whole batch, oldest first: every closed unit plus the open
         * simple/function unit, all sharing this Z as ts_ready (Р16). An
         * extended unit still open here got no reply (bound-but-never-executed,
         * or a lost reply) and is dropped — no honest observation. */
        for (__u32 i = 0; i < pc->count; i++) {
            struct pg_unit *u = &pc->ring[(pc->head + i) % LK_PG_MAX_INFLIGHT];
            bool closed = i < pc->nclosed || unit_z_closed(u);

            if (!closed)
                continue;
            if (unit_z_closed(u) && u->ts_complete_ns == 0)
                u->ts_complete_ns = m->ts_ns; /* function with no explicit tag */
            /* An ABORTED unit never reached its own Z honestly — leave its
             * ts_ready at 0 (the contract's ABORTED case). */
            emit_unit(p, c, pc, u, (u->flags & LK_QO_ABORTED) ? 0 : m->ts_ns, status);
        }
    }
    /* The batch is done: whether emitted, dropped as leftovers, or discarded
     * because LOSSY, the ring resets and Z is the clean boundary. */
    pc->head = 0;
    pc->count = 0;
    pc->nclosed = 0;
    pc->lossy = false;
    /* A clean Z is the guaranteed boundary between queries: it ends READY-
     * degraded, the extended skip-to-Sync state (Р19) and a finished COPY. An
     * IGNORE'd replication connection never reaches here (no Z on a CopyBoth
     * stream), so it stays IGNORE. */
    pc->degraded = false;
    if (pc->phase == PG_PH_SKIP_TO_SYNC || pc->phase == PG_PH_COPY_IN ||
        pc->phase == PG_PH_COPY_OUT)
        pc->phase = PG_PH_READY;

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
