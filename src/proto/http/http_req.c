// SPDX-License-Identifier: GPL-2.0
/* The request head (PLAN-HTTP.md М3, РH5/РH10/РH11) — everything the handler
 * lifts off an 'R' message, in the shape of pg_session.c: one direction, one
 * message type, no state machine of its own.
 *
 * The framer has already decided where this message ends and refused to publish
 * anything it could not frame, so a parse here cannot desynchronise a
 * connection; what it *can* do is read too much. That is the only real design
 * pressure on this file. The list of headers it looks at is closed and short
 * (notes-httpproto.md §"Headers of interest"); what is not on the list is
 * skipped without being copied anywhere. `Cookie` travels past this code
 * untouched, and so does `Authorization` unless `--http-user basic` explicitly
 * asked for the name half — what is not read cannot leak (РH12).
 *
 * The head bytes are borrowed for the duration of the callback, so everything
 * kept is copied under a bounded ceiling (LK_HTTP_*_MAX). The target is the one
 * variable-length copy on the common path, and it is kept **raw**: М4's route
 * templating is a pure function of the method, path and query, and feeding it a
 * value this file already normalised would move the templating rules somewhere
 * nobody can test them. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"

/* Copy into an owned, reused buffer — the pg_unit.own_text pattern (Р17): the
 * ring slot allocates once and keeps the allocation for every later unit that
 * lands on it, so a keep-alive connection serving 50 requests does one malloc,
 * not 50. Returns false on OOM, which costs the field and nothing else. */
static bool copy_owned(char **buf, __u32 *len, __u32 *cap, struct http_span s, __u32 max)
{
    __u32 n = s.n > max ? max : s.n;

    *len = 0;
    if (*cap < n) {
        char *nb = realloc(*buf, n);

        if (!nb)
            return false;
        *buf = nb;
        *cap = n;
    }
    if (n)
        memcpy(*buf, s.p, n);
    *len = n;
    return true;
}

/* Session labels (РH10): the host in the db slot, the User-Agent in the app
 * slot, and the user slot left empty unless --http-user basic filled it. The
 * registry prints an empty slot as "-", which is the honest answer for a
 * protocol that usually carries no identity at all.
 *
 * Emitted once per connection, off the first request head: HTTP has no
 * handshake to hang a session on, and the first request is the nearest thing to
 * one. Later requests on the same socket may disagree — name-based virtual
 * hosts are exactly this shape — which is why an *observation* reports its own
 * unit's host rather than this one. The session is the connection's opening
 * statement, not a summary of it. */
static void session_emit(struct lk_proto *p, struct lk_conn *c, struct http_conn *hc,
                         const struct http_unit *u, struct http_span ua)
{
    if (hc->session_emitted)
        return;
    http_copy_cstr(hc->session.database, sizeof(hc->session.database), u->host);
    http_copy_cstr(hc->session.user, sizeof(hc->session.user), u->user);
    http_copy_label(hc->session.app, sizeof(hc->session.app), ua);
    snprintf(hc->session.server_version, sizeof(hc->session.server_version), "HTTP/1.%u",
             (unsigned)(u->minor & 1));
    /* "complete" means the labels are as good as they are going to get, and for
     * HTTP they are: there is no second act like PG's ParameterStatus. */
    hc->session.complete = true;
    hc->session_emitted = true;
    p->st.sessions++;
    if (p->out.on_session)
        p->out.on_session(p->out.ctx, c, &hc->session);
}

void http_req_head(struct lk_proto *p, struct lk_conn *c, struct http_conn *hc,
                   const struct lk_msg *m)
{
    const struct lk_http_cfg *cfg = http_cfg();
    struct http_span line, name, val, ua = http_span(NULL, 0);
    struct http_span method = {0}, target = {0}, path, query, authority;
    struct http_span host = http_span(NULL, 0), tstate = http_span(NULL, 0);
    struct http_head h;
    struct http_unit *u;
    __u8 minor = 0;

    http_head_init(&h, m->body, m->body_cap);
    if (!http_head_line(&h, &line) || !http_parse_req_line(line, &method, &target, &minor)) {
        /* The framer parsed this very line before publishing the message, so
         * the only way here is the head it publishes *without* having parsed
         * one: a block a capture hole cut short (LK_MSG_BODY_TRUNC, РH14),
         * which can end mid-start-line. No unit opens — without a method and a
         * target there is nothing to observe, and half a start line is not a
         * guess worth making. */
        http_orphan(p, hc);
        return;
    }

    u = http_unit_open(p, hc, m->ts_ns);
    if (!u) {
        /* The ring is full. The response to this request will arrive after the
         * responses to every unit still in it (HTTP/1.1 answers in order), so a
         * plain counter is enough to recognise and skip it later (РH6). */
        hc->owed++;
        return;
    }
    hc->degraded = false;
    hc->req_seq = hc->open_seq - 1;

    /* Methods are case-sensitive tokens, so the known ones are already spelled
     * canonically on the wire and an unknown one is reported by its own bytes —
     * never mapped onto a method it merely resembles. */
    http_copy_label(u->method, sizeof(u->method), method);
    u->method_id = (__u8)http_method_id(method);
    u->minor = minor;
    if (m->flags & LK_MSG_BODY_TRUNC)
        u->flags |= LK_QO_TEXT_TRUNC;

    /* The target: path and query rejoined, because that is what the route
     * templater takes (РH7) and what a sampled span's `url.path` needs. An
     * absolute-form authority is not part of it — that is the host label. */
    http_target_split(target, &path, &query, &authority);
    if (path.n) {
        struct http_span raw = http_span(path.p, path.n + (query.n ? query.n + 1 : 0));

        if (!copy_owned(&u->target, &u->target_len, &u->target_cap, raw, LK_HTTP_TARGET_MAX))
            u->flags |= LK_QO_NO_TEXT;
        else if (raw.n > LK_HTTP_TARGET_MAX)
            u->flags |= LK_QO_TEXT_TRUNC;
    } else {
        u->flags |= LK_QO_NO_TEXT; /* authority-form (CONNECT): there is no path */
    }

    /* `Content-Length` is deliberately *not* read here, and its absence is a
     * decision rather than an omission. The header says what the client
     * promised; `bytes_in` is what the server actually received, summed from the
     * framer's own 'D' accounting — captured bytes and holed ones alike (Р9).
     * On a torn upload the two disagree (corpus `torn-body`: 100 bytes arrived
     * against a declared 4096), and the number worth reporting is the one that
     * describes what happened. The framer already read the header to decide
     * where the body ends; reading it again to report a different truth is how
     * the two halves of a unit drift apart. */
    while (http_head_field(&h, &name, &val)) {
        if (http_span_eq_ci(name, "host")) {
            host = val;
        } else if (http_span_eq_ci(name, "user-agent")) {
            ua = val;
        } else if (http_span_eq_ci(name, "expect")) {
            u->expect_cont = http_list_has(val, "100-continue");
        } else if (http_span_eq_ci(name, "traceparent")) {
            u->tp.valid =
                http_parse_traceparent(val, u->tp.trace_id, u->tp.parent_id, &u->tp.flags);
        } else if (http_span_eq_ci(name, "tracestate")) {
            tstate = val;
        } else if (http_span_eq_ci(name, "x-request-id") ||
                   http_span_eq_ci(name, "x-amzn-trace-id")) {
            if (!u->req_id[0]) /* first one wins: a proxy chain may add a second */
                http_copy_label(u->req_id, sizeof(u->req_id), val);
        } else if (cfg->user_basic && http_span_eq_ci(name, "authorization")) {
            /* Read only because it was asked for, and only ever the name half:
             * the base64 decode stops at the colon (РH10, http_basic_user). */
            if (!http_basic_user(val, u->user, sizeof(u->user)))
                u->user[0] = '\0';
        }
    }

    /* An absolute-form authority beats `Host`: a proxy-style request names its
     * real destination there while `Host` may name the proxy (RFC 9112 §3.2.2,
     * corpus `absolute-form`). An HTTP/1.0 request may carry neither, and then
     * the host label is legitimately empty — "-" once the registry prints it. */
    http_copy_label(u->host, sizeof(u->host), authority.n ? authority : host);
    /* tracestate is carried through verbatim and unparsed (РH11): it is a
     * vendor's opaque state and reading into it would be someone else's schema.
     * Failure to allocate loses the field and nothing else. */
    if (tstate.n)
        copy_owned(&u->tracestate, &u->tracestate_len, &u->tracestate_cap, tstate,
                   LK_HTTP_TSTATE_MAX);

    p->st.by_type[LK_DIR_RECV][(__u8)http_method_tag((enum http_method)u->method_id)]++;
    session_emit(p, c, hc, u, ua);
}
