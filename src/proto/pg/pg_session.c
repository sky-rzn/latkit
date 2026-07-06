// SPDX-License-Identifier: GPL-2.0
/* PostgreSQL startup / auth / session labels (task 3.2, Р16). Turns the
 * connection's opening handshake into a struct lk_session (user / database /
 * application_name / server_version) and, on AuthenticationOk, emits it up
 * through the query sink. Also handles the two startup-framed oddities that
 * carry no query: CancelRequest (a CANCEL observation) and SSL/GSSENC requests
 * (left to the framer, which has already armed the one-byte reply).
 *
 * Security invariant (Р16): the PasswordMessage / SASL body ('p') is never
 * read here — it never reaches this file. That path stays in pg.c's default
 * arm, which touches nothing.
 *
 * Pure, no I/O: every field read goes through the bounded pg_wire cursor (Р18),
 * so a truncated or corrupt body can never walk past the captured prefix. */
#include "pg.h"

#include <string.h>

#include "pg_wire.h"    /* bounded cursor (Р18) */
#include "reassembly.h" /* LK_PG_* startup codes, LK_MSG_* flags */

/* Copy a wire string (not NUL-terminated, length known) into a fixed session
 * field, truncating to fit and always NUL-terminating. */
static void copy_field(char *dst, size_t dstsz, const char *src, __u32 srclen)
{
    __u32 n = srclen < dstsz - 1 ? srclen : (__u32)(dstsz - 1);

    if (n)
        memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Wire string == C literal? Compares by length, so an embedded NUL cannot
 * shorten the match. */
static bool key_is(const char *key, __u32 klen, const char *lit)
{
    return klen == strlen(lit) && memcmp(key, lit, klen) == 0;
}

/* StartupMessage parameter list: key\0value\0...\0 pairs terminated by an empty
 * key (the trailing double-NUL). Unknown keys are skipped; the three we label
 * with are copied. A truncated body (LK_MSG_BODY_TRUNC) can cut the list mid-
 * pair — the cursor reports overrun, we salvage whatever prefix we have and
 * stop; completeness is recorded by the caller. */
static void parse_params(struct pg_conn *pc, struct pg_wire *w)
{
    for (;;) {
        const char *key, *val;
        __u32 klen, vlen;

        if (!pg_wire_cstring(w, &key, &klen))
            return; /* no terminator before the captured prefix ended */
        if (klen == 0)
            return; /* empty key: end of the parameter list */

        bool val_ok = pg_wire_cstring(w, &val, &vlen);

        if (key_is(key, klen, "user"))
            copy_field(pc->session.user, sizeof(pc->session.user), val, vlen);
        else if (key_is(key, klen, "database"))
            copy_field(pc->session.database, sizeof(pc->session.database), val, vlen);
        else if (key_is(key, klen, "application_name"))
            copy_field(pc->session.app, sizeof(pc->session.app), val, vlen);

        if (!val_ok)
            return; /* value ran into the truncated tail: prefix salvaged above */
    }
}

/* CancelRequest: no query text, no timings — just a CANCEL observation so the
 * consumer can count them. The connection carries nothing else (the framer set
 * LK_CONN_CANCEL and discards the rest), so move to IGNORE. */
static void emit_cancel(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc)
{
    struct lk_query_obs o = {.kind = LK_Q_CANCEL};

    pc->phase = PG_PH_IGNORE;
    p->st.queries++;
    if (p->out.on_query)
        p->out.on_query(p->out.ctx, c, &pc->session, &o);
}

void pg_session_startup(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                        const struct lk_msg *m)
{
    struct pg_wire w;
    __u32 code;

    pg_wire_init(&w, m->body, m->body_cap);
    if (!pg_wire_get_u32(&w, &code))
        return; /* body cut before the 4-byte code: nothing to learn (never
                 * happens in practice — startup fits the capture budget) */

    switch (code) {
    case LK_PG_PROTO_V3:
        parse_params(pc, &w);
        /* "complete" means the whole startup packet was captured; a budget
         * truncation leaves some parameters unknown but the session is still
         * usable (partial labels, honest flag). */
        pc->session.complete = !(m->flags & LK_MSG_BODY_TRUNC);
        pc->phase = PG_PH_AUTH;
        break;
    case LK_PG_CANCEL_REQUEST:
        emit_cancel(p, c, pc);
        break;
    case LK_PG_SSL_REQUEST:
    case LK_PG_GSSENC_REQUEST:
    default:
        /* SSL/GSSENC negotiation (the framer handles the one-byte reply; a real
         * StartupMessage follows after 'N') or an unknown startup code: stay in
         * STARTUP and wait for the v3 packet. */
        break;
    }
}

void pg_session_auth(struct lk_proto *p, struct lk_conn *c, struct pg_conn *pc,
                     const struct lk_msg *m)
{
    struct pg_wire w;
    __u32 code;

    if (pc->phase != PG_PH_AUTH)
        return; /* stray 'R' outside the handshake (resync/synthetic): ignore */

    pg_wire_init(&w, m->body, m->body_cap);
    if (!pg_wire_get_u32(&w, &code))
        return; /* truncated auth body: keep waiting */
    if (code != 0)
        return; /* MD5 / SASL / ...: not done yet, stay in AUTH */

    /* AuthenticationOk: the session is now established. server_version may
     * still arrive later (ParameterStatus) and refine the labels; on_query
     * carries the live session, so late fields are not lost. */
    pc->phase = PG_PH_READY;
    p->st.sessions++;
    if (p->out.on_session)
        p->out.on_session(p->out.ctx, c, &pc->session);
}

void pg_session_param_status(struct pg_conn *pc, const struct lk_msg *m)
{
    struct pg_wire w;
    const char *key, *val;
    __u32 klen, vlen;

    pg_wire_init(&w, m->body, m->body_cap);
    if (!pg_wire_cstring(&w, &key, &klen) || !pg_wire_cstring(&w, &val, &vlen))
        return; /* truncated/corrupt: the label is optional, drop it */
    if (key_is(key, klen, "server_version"))
        copy_field(pc->session.server_version, sizeof(pc->session.server_version), val, vlen);
}
