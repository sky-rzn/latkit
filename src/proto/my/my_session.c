// SPDX-License-Identifier: GPL-2.0
/* MySQL connection phase: greeting / HandshakeResponse41 / auth cycle /
 * session labels (MYSQL.md М3, notes-myproto.md "Connection phase"). Turns
 * the handshake into a struct lk_session (user / database / app /
 * server_version) and emits it on the server's final OK — the session
 * boundary the plan pins on_session to; auth timing is deliberately not
 * measured.
 *
 * Security invariant (Р16, verbatim from PG): auth payloads are never read.
 * The client's auth response inside the HandshakeResponse is length-skipped,
 * the AuthSwitch/AuthMoreData round-trip bodies are not parsed at all — they
 * carry scrambles and, on the clear-password paths, actual passwords.
 *
 * Live labels: COM_INIT_DB and COM_CHANGE_USER stage updates committed on
 * their OK; an OK carrying SESSION_TRACK_SCHEMA (a plain `USE db` under
 * CLIENT_SESSION_TRACK) updates the db label from the tracker info — both
 * feed through my_session_ok_effects, called by the terminator parser.
 *
 * Pure, no I/O: every field goes through the bounded my_wire cursor (Р18). */
#include "my.h"

#include <string.h>

#include "my_wire.h"
#include "reassembly.h" /* LK_MSG_* flags */

/* Copy a wire string (length known, not NUL-terminated) into a fixed session
 * field, truncating to fit and always NUL-terminating. */
static void copy_field(char *dst, size_t dstsz, const char *src, __u32 srclen)
{
    __u32 n = srclen < dstsz - 1 ? srclen : (__u32)(dstsz - 1);

    if (n)
        memcpy(dst, src, n);
    dst[n] = '\0';
}

static bool key_is(const char *key, __u32 klen, const char *lit)
{
    return klen == strlen(lit) && memcmp(key, lit, klen) == 0;
}

/* --- greeting (server speaks first) ---------------------------------------- */

/* Initial Handshake, protocol version 10: all the session needs is
 * server_version — MariaDB prefixes `5.5.5-` for replication compatibility
 * and the label strips it (notes-myproto). The server's capability flags are
 * only an offer; the connection's truth is what the client sends back. */
static void greeting(struct my_conn *pc, const struct lk_msg *m)
{
    struct my_wire w;
    const char *ver;
    __u32 vlen;
    __u8 proto;

    my_wire_init(&w, m->body, m->body_cap);
    if (!my_wire_get_u8(&w, &proto))
        return;
    if (proto == 0xff)
        return; /* ERR instead of a greeting (too many connections): the
                 * server closes; nothing to learn, stay in GREETING */
    pc->sess = MY_S_RESPONSE;
    if (proto != 10)
        return; /* protocol 9 or garbage: no field layout we know */
    if (!my_wire_cstring(&w, &ver, &vlen))
        return; /* version cut by the capture budget: label stays unknown */
    if (vlen > 6 && memcmp(ver, "5.5.5-", 6) == 0) {
        ver += 6; /* MariaDB replication-compat prefix */
        vlen -= 6;
    }
    copy_field(pc->session.server_version, sizeof(pc->session.server_version), ver, vlen);
}

/* --- HandshakeResponse41 (and the short SSLRequest) ------------------------ */

/* Connection attributes: lenenc total length, then lenenc key/value pairs.
 * `program_name` labels the session's app; `_client_name` (the driver name)
 * is the fallback when the application did not set one. */
static void parse_attrs(struct my_conn *pc, struct my_wire *w)
{
    __u64 total;
    const char *key, *val;
    __u32 klen, vlen;
    bool have_program = false;

    if (!my_wire_get_lenenc(w, &total))
        return;
    while (my_wire_remaining(w)) {
        if (!my_wire_get_lenenc_str(w, &key, &klen))
            return; /* truncated tail: whatever was salvaged above stands */
        if (!my_wire_get_lenenc_str(w, &val, &vlen))
            return;
        if (key_is(key, klen, "program_name")) {
            copy_field(pc->session.app, sizeof(pc->session.app), val, vlen);
            have_program = true;
        } else if (key_is(key, klen, "_client_name") && !have_program &&
                   pc->session.app[0] == '\0') {
            copy_field(pc->session.app, sizeof(pc->session.app), val, vlen);
        }
    }
}

/* HandshakeResponse41: client caps u32, max_packet u32, charset u8, 23 bytes
 * filler (MariaDB clients put extended caps in the last 4), then the labels.
 * The short SSLRequest is this very packet ending right after the filler —
 * the cursor runs dry before the username, and the state stays MY_S_RESPONSE:
 * the full response repeats inside TLS on the decrypted channel (М5). */
static void handshake_response(struct my_conn *pc, const struct lk_msg *m)
{
    struct my_wire w;
    const char *user, *db;
    __u32 ulen, dlen, dummy;
    __u8 charset;
    __u64 alen;
    bool cut = (m->flags & LK_MSG_BODY_TRUNC) != 0;

    my_wire_init(&w, m->body, m->body_cap);
    if (!my_wire_get_u32(&w, &pc->caps))
        return; /* caps cut by a hole: assume nothing, wait for more */
    pc->caps_known = true;
    if (!my_wire_get_u32(&w, &dummy) || !my_wire_get_u8(&w, &charset) || !my_wire_skip(&w, 19) ||
        !my_wire_get_u32(&w, &pc->mcaps)) {
        /* Cut inside the fixed 32-byte header: a truncated real response —
         * the auth cycle is still coming, the labels are lost. */
        if (cut)
            pc->sess = MY_S_AUTH;
        return;
    }
    (void)charset;
    if (pc->caps & MY_CAP_MYSQL)
        pc->mcaps = 0; /* a mysql-dialect client: the u32 is plain filler */

    if (!my_wire_remaining(&w)) {
        /* A full 32-byte packet is the short SSLRequest: stay in RESPONSE
         * (the real response repeats inside TLS). A packet *cut* at 32 is a
         * truncated response — move on to the auth cycle. */
        if (cut)
            pc->sess = MY_S_AUTH;
        return;
    }

    pc->sess = MY_S_AUTH;
    pc->session.complete = !cut;
    if (!my_wire_cstring(&w, &user, &ulen)) {
        copy_field(pc->session.user, sizeof(pc->session.user), user, ulen);
        return; /* username cut: salvage the prefix, rest unknown */
    }
    copy_field(pc->session.user, sizeof(pc->session.user), user, ulen);

    /* Auth response: length-skipped, never read (Р16). */
    if (pc->caps & MY_CAP_PLUGIN_AUTH_LENENC) {
        if (!my_wire_get_lenenc(&w, &alen) || !my_wire_skip(&w, (__u32)alen))
            return;
    } else {
        __u8 al;

        if (!my_wire_get_u8(&w, &al) || !my_wire_skip(&w, al))
            return;
    }
    if (pc->caps & MY_CAP_CONNECT_WITH_DB) {
        if (!my_wire_cstring(&w, &db, &dlen)) {
            copy_field(pc->session.database, sizeof(pc->session.database), db, dlen);
            return;
        }
        copy_field(pc->session.database, sizeof(pc->session.database), db, dlen);
    }
    if (pc->caps & MY_CAP_PLUGIN_AUTH) {
        const char *plugin;
        __u32 plen;

        if (!my_wire_cstring(&w, &plugin, &plen))
            return; /* plugin name: skipped either way */
    }
    if (pc->caps & MY_CAP_CONNECT_ATTRS)
        parse_attrs(pc, &w);
}

/* --- the session boundary --------------------------------------------------- */

/* The server's final OK: the session is established. Fires once; the
 * CHANGE_USER cycle re-enters here only to commit its staged labels. */
static void session_ok(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                       const struct lk_msg *m)
{
    struct my_ok ok;

    if (pc->have_pending_user) {
        copy_field(pc->session.user, sizeof(pc->session.user), pc->pending_user,
                   (__u32)strlen(pc->pending_user));
        pc->have_pending_user = false;
    }
    my_query_parse_ok(pc, m, false, &ok);
    my_session_ok_effects(pc, &ok); /* pending db + session-track schema */

    pc->sess = MY_S_DONE;
    /* Compression negotiated (РМ7): the framer flipped the connection to
     * LK_CONN_IGNORE on this very OK — the labels above are the whole point
     * of parsing a compressed connection's handshake (a named blind spot).
     * Counted per reason (М6): latkit_ignored_conns_total{reason="compressed"}. */
    if (c->flags & LK_CONN_IGNORE) {
        pc->phase = MY_PH_IGNORE;
        p->st.compressed_conns++;
    } else {
        pc->phase = MY_PH_READY;
    }
    if (!pc->session_emitted) {
        pc->session_emitted = true;
        p->st.sessions++;
        if (p->out.on_session)
            p->out.on_session(p->out.ctx, c, &pc->session);
    }
}

void my_session_backend(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                        const struct lk_msg *m)
{
    __u8 head = m->body_cap ? m->body[0] : 0;

    switch (pc->sess) {
    case MY_S_GREETING:
        greeting(pc, m);
        break;
    case MY_S_RESPONSE:
        /* The server does not normally speak between the greeting and the
         * response; an ERR here (handshake timeout, host blocked) means it is
         * about to close. Everything else is noise. */
        if (head == 0xff)
            pc->sess = MY_S_DONE;
        break;
    case MY_S_AUTH:
        /* AuthSwitchRequest (0xFE) and AuthMoreData (0x01) keep the cycle
         * going — their bodies are never parsed (Р16). OK ends the phase,
         * ERR means the server closes (no session). */
        if (head == 0x00) {
            session_ok(p, c, pc, m);
        } else if (head == 0xff) {
            pc->sess = MY_S_DONE;
            pc->phase = MY_PH_READY; /* moot — the close event follows */
            pc->have_pending_user = false;
            pc->have_pending_db = false;
        }
        break;
    case MY_S_DONE:
        break; /* stray connection-phase packet: tallied upstream, ignored */
    }
}

void my_session_frontend(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc,
                         const struct lk_msg *m)
{
    (void)p;
    (void)c;
    switch (pc->sess) {
    case MY_S_GREETING: /* response before the greeting was seen (greeting in a
                         * hole): still parseable — fall through */
    case MY_S_RESPONSE:
        handshake_response(pc, m);
        break;
    case MY_S_AUTH:
    case MY_S_DONE:
        break; /* auth round-trip replies: consumed, never parsed (Р16) */
    }
}

/* The framer proved the command phase started (a seq-0 command / its reply)
 * while the handler still waited for the exchange's tail — the final OK fell
 * into a hole. Salvage what the response gave us: the labels are known, only
 * the boundary packet is missing, so the session is still worth emitting. */
void my_session_promote(struct lk_proto *p, struct lk_conn *c, struct my_conn *pc)
{
    if (pc->sess == MY_S_AUTH && !pc->session_emitted) {
        pc->session_emitted = true;
        pc->session.complete = false; /* the exchange was not seen in full */
        p->st.sessions++;
        if (p->out.on_session)
            p->out.on_session(p->out.ctx, c, &pc->session);
    }
    pc->sess = MY_S_DONE;
    pc->phase = MY_PH_READY;
    pc->have_pending_user = false;
    pc->have_pending_db = false;
}

/* --- live label updates (command phase) ------------------------------------ */

/* COM_INIT_DB: the body after the command byte is the bare schema name. The
 * label changes only if the server says OK — staged here, committed by
 * my_session_ok_effects from the terminator. */
void my_session_init_db(struct my_conn *pc, const struct lk_msg *m)
{
    __u32 n = m->body_cap > 1 ? m->body_cap - 1 : 0;

    copy_field(pc->pending_db, sizeof(pc->pending_db), (const char *)m->body + 1, n);
    pc->have_pending_db = true;
}

/* COM_CHANGE_USER: user NUL-string, u8-length-prefixed auth response
 * (skipped, Р16), database NUL-string — staged, committed on the final OK of
 * the auth cycle this command re-enters. The server also discards the
 * connection's prepared statements. */
void my_session_change_user(struct lk_proto *p, struct my_conn *pc, const struct lk_msg *m)
{
    struct my_wire w;
    const char *user, *db;
    __u32 ulen, dlen;
    __u8 alen;

    (void)p;
    my_prep_drop_all(pc);
    pc->phase = MY_PH_HANDSHAKE;
    pc->sess = MY_S_AUTH;

    my_wire_init(&w, m->body, m->body_cap);
    if (!my_wire_skip(&w, 1)) /* the command byte */
        return;
    if (!my_wire_cstring(&w, &user, &ulen)) {
        copy_field(pc->pending_user, sizeof(pc->pending_user), user, ulen);
        pc->have_pending_user = ulen > 0;
        return;
    }
    copy_field(pc->pending_user, sizeof(pc->pending_user), user, ulen);
    pc->have_pending_user = true;
    if (!my_wire_get_u8(&w, &alen) || !my_wire_skip(&w, alen))
        return;
    if (!my_wire_cstring(&w, &db, &dlen))
        return;
    copy_field(pc->pending_db, sizeof(pc->pending_db), db, dlen);
    pc->have_pending_db = true;
}

/* OK-side effects on the session labels. Called by the terminator parser for
 * every OK-shaped packet: commits a staged COM_INIT_DB / CHANGE_USER db and
 * applies a SESSION_TRACK_SCHEMA change parsed by my_query_parse_ok (which
 * stashes it in ok->status handling — see there). The staged db is dropped
 * unapplied when the reply was an ERR (the caller never gets here). */
void my_session_ok_effects(struct my_conn *pc, const struct my_ok *ok)
{
    (void)ok;
    if (pc->have_pending_db) {
        copy_field(pc->session.database, sizeof(pc->session.database), pc->pending_db,
                   (__u32)strlen(pc->pending_db));
        pc->have_pending_db = false;
    }
}
