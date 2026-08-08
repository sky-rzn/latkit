// SPDX-License-Identifier: GPL-2.0
/* HTTP/1.x handler (PLAN-HTTP.md М3, РH5/РH6/РH10) — the message consumer of
 * the stream framer in http_frame.c, in the shape of pg.c / my.c: it owns the
 * per-connection state behind lk_conn.proto_state, dispatches the framer's
 * synthetic messages by (direction, type), and turns each request/response
 * exchange into one lk_query_obs.
 *
 * What a unit is (РH6): opened by a request head, closed by the last byte of
 * the response body, emitted exactly once — as an observation when a response
 * was seen, into a units_dropped_* counter otherwise. In flight they sit in a
 * FIFO, because HTTP/1.1 answers in request order and pipelining makes that
 * queue deeper than one.
 *
 * Where this handler differs from the two database ones, and why:
 *
 *   - **four timestamps, not two** (РH5). `ts_start … ts_complete` contains the
 *     client's upload of the request body, which is time the server neither
 *     spent nor controls; ts_req_done_ns splits it off so a 1 GB POST does not
 *     read as a slow server. For a GET the extra stamp is free — the request
 *     head and its (empty) body arrive in one event, so all three models agree,
 *     which is exactly why the difference is invisible until it matters.
 *   - **the connection's end can *complete* a unit.** A response with no length
 *     and no chunked framing runs until the socket closes (rule 6 of the
 *     body-length list), so CONN_CLOSE finishes it rather than truncating it.
 *     Every other in-flight unit is still dropped there, as in PG: a request cut
 *     off by a disconnect is not an observation.
 *   - **there is no transaction and no row count.** on_txn is never called,
 *     `rows` stays zero, and a unit's identity is the method plus the *route*
 *     — the template the target came from (РH7), resolved through the
 *     connection's dialect (РH8) as the unit is emitted. The raw target travels
 *     beside it untouched, because a span needs the path and a label must not
 *     have it.
 *
 * The framer's '!' note messages (РH3) are the only channel a stream framer has
 * for reporting a degradation, so this is also where they become counters:
 * corrupt input into latkit_parse_errors_total, a protocol switch into the
 * blind-zone tally, and the sendfile case into a flag on the unit it degraded.
 * Capture holes are deliberately not parse errors — nothing was wrong with the
 * input, we just did not see all of it.
 *
 * No I/O, no libbpf: a pure state machine, fed synthetic lk_msg by unit tests
 * and .lkt traces by the replay harness. */
#include <stdlib.h>
#include <string.h>

#include "http.h"

/* --- handler-wide configuration (РH10) ------------------------------------ */

static struct lk_http_cfg http_cfg_cur;

void lk_proto_http_configure(const struct lk_http_cfg *cfg)
{
    static const struct lk_http_cfg defaults = {0};

    http_cfg_cur = cfg ? *cfg : defaults;
    /* The route header is folded to lower case once, here, rather than at every
     * comparison: field names are case-insensitive and http_span_eq_ci wants its
     * literal lowercase, so a caller that spelled `X-Route` would otherwise
     * configure a header that can never match — a silent misconfiguration, and
     * the worst kind (РH7). */
    for (unsigned i = 0; i < sizeof(http_cfg_cur.route_header); i++) {
        char c = http_cfg_cur.route_header[i];

        if (c >= 'A' && c <= 'Z')
            http_cfg_cur.route_header[i] = (char)(c - 'A' + 'a');
    }
}

const struct lk_http_cfg *http_cfg(void)
{
    return &http_cfg_cur;
}

/* --- per-connection state -------------------------------------------------- */

/* Lazily attach per-connection state on the first message (Р15). NULL only on
 * allocation failure — the caller degrades to counting, never crashes. */
static struct http_conn *http_conn_get(struct lk_proto *p, struct lk_conn *c)
{
    struct http_conn *hc = c->proto_state;

    if (hc)
        return hc;
    hc = calloc(1, sizeof(*hc));
    if (!hc)
        return NULL;
    hc->req_seq = ~0ull;
    /* A synthetic or lazily created entry joined an established connection: the
     * first bytes may be the middle of a body, so nothing before the next
     * request head is a trustworthy unit boundary. */
    hc->degraded = (c->flags & LK_CONN_SYNTHETIC) != 0;
    c->proto_state = hc;
    p->st.conns++;
    return hc;
}

/* --- the in-flight ring ---------------------------------------------------- */

/* Wipe a slot for reuse while keeping its owned buffers: the allocation is the
 * expensive part and a keep-alive connection recycles the same few slots
 * thousands of times (the pg_unit reset pattern, Р17). */
static void unit_reset(struct http_unit *u)
{
    char *target = u->target, *tracestate = u->tracestate;
    __u32 tcap = u->target_cap, scap = u->tracestate_cap;

    memset(u, 0, sizeof(*u));
    u->target = target;
    u->target_cap = tcap;
    u->tracestate = tracestate;
    u->tracestate_cap = scap;
}

struct http_unit *http_unit_open(struct lk_proto *p, struct http_conn *hc, __u64 ts_ns)
{
    struct http_unit *u;

    if (hc->open_seq - hc->head_seq >= LK_HTTP_MAX_INFLIGHT) {
        /* Deeper pipelining than the ring holds. Dropping the *newest* request
         * rather than the oldest is what keeps the queue a FIFO: the responses
         * still in it pair correctly, and the ones we will not be able to place
         * are the last to arrive (http_resp.c reads hc->owed for them). */
        p->st.units_dropped_overflow++;
        return NULL;
    }
    u = &hc->ring[hc->open_seq % LK_HTTP_MAX_INFLIGHT];
    unit_reset(u);
    u->used = true;
    u->ts_start_ns = ts_ns;
    hc->open_seq++;
    /* Pipelining is "a second request went out before the first was answered",
     * and both units carry the mark: the first one's duration is honest, but the
     * second's start time reflects a client that was not waiting, so neither is
     * comparable with a standalone unit (РH6, LK_QO_PIPELINED as in PG). */
    if (hc->open_seq - hc->head_seq > 1) {
        for (__u64 s = hc->head_seq; s < hc->open_seq; s++)
            hc->ring[s % LK_HTTP_MAX_INFLIGHT].flags |= LK_QO_PIPELINED;
    }
    return u;
}

/* --- emitting -------------------------------------------------------------- */

static void unit_emit(struct lk_proto *p, struct lk_conn *c, struct http_conn *hc,
                      struct http_unit *u)
{
    struct lk_route_out route;
    struct lk_query_obs o = {
        .ts_start_ns = u->ts_start_ns,
        .ts_req_done_ns = u->ts_req_done_ns ? u->ts_req_done_ns : u->ts_start_ns,
        .ts_first_row_ns = u->ts_first_row_ns,
        .ts_complete_ns = u->ts_complete_ns,
        .ts_ready_ns = u->ts_complete_ns, /* HTTP has no separate ready point */
        .bytes_in = u->bytes_in,
        .bytes_out = u->bytes_out,
        .op = u->method[0] ? u->method : NULL,
        .err_code = u->status,
        .kind = LK_Q_REQUEST,
        .flags = u->flags,
    };

    /* ts_req_done is clamped to ts_start above rather than left at zero: a
     * server that answers before the upload finishes (413 mid-POST, or a 400 on
     * a head it disliked) never produces the request-body end, and an
     * observation whose duration is "since the epoch" is worse than one whose
     * upload interval reads as zero. The upload family loses that unit; the
     * duration and TTFB stay right. */
    if (!(u->flags & LK_QO_NO_TEXT) && u->target_len) {
        o.text = u->target;
        o.text_len = u->target_len;
    } else {
        o.flags |= LK_QO_NO_TEXT;
    }
    /* The two identities of an HTTP observation travel side by side and neither
     * replaces the other (РH7): `text` is the raw target, for the span that М6
     * will redact and sample, and `route` is the template, the only one of the
     * two that may become a metric label. Computing it here rather than in each
     * sink means the dialect (РH8) is consulted once per observation, by the one
     * component that knows which connection — hence which dialect — this is. */
    http_route_resolve(c, u, &route);
    if (route.text_len) {
        o.route = route.text;
        o.route_len = route.text_len;
        o.route_fp = route.fp;
    }
    /* РH10: the host of *this* request, not of the connection — one keep-alive
     * socket can serve several virtual hosts, and the session only remembers
     * the first. */
    http_copy_cstr(hc->session.database, sizeof(hc->session.database), u->host);
    http_copy_cstr(hc->session.user, sizeof(hc->session.user), u->user);

    p->st.queries++;
    if (o.flags & LK_QO_ERROR)
        p->st.errors_sql++;
    u->used = false;
    if (p->out.on_query)
        p->out.on_query(p->out.ctx, c, &hc->session, &o);
}

/* Retire the front unit: emit it if a response ever arrived, drop it into
 * *dropped otherwise. Advancing head_seq is what invalidates every reference to
 * it — a request body still trickling in for an already-answered unit finds
 * http_unit_at returning NULL rather than the next unit's slot. */
static void unit_retire(struct lk_proto *p, struct lk_conn *c, struct http_conn *hc, __u64 *dropped)
{
    struct http_unit *u = http_unit_front(hc);

    if (!u)
        return;
    if (u->have_resp)
        unit_emit(p, c, hc, u);
    else if (dropped)
        (*dropped)++;
    u->used = false;
    hc->head_seq++;
}

/* Drop every in-flight unit without emitting (Р19: an observation must never
 * span a loss or a disconnect) and add the count to *counter. */
static void units_drop_all(struct http_conn *hc, __u64 *counter)
{
    while (hc->head_seq < hc->open_seq) {
        hc->ring[hc->head_seq % LK_HTTP_MAX_INFLIGHT].used = false;
        hc->head_seq++;
        if (counter)
            (*counter)++;
    }
    hc->req_seq = ~0ull;
    hc->owed = 0;
    hc->resp_orphan = false;
}

/* --- body accounting ------------------------------------------------------- */

/* 'D' carries a count and never a payload (РH12), and counts holed bytes as
 * well as captured ones (Р9) — which is what makes bytes_in/bytes_out exact
 * under any capture budget rather than "exact when nothing was lost". */
static void body_data(struct lk_proto *p, struct http_conn *hc, enum lk_dir dir,
                      const struct lk_msg *m)
{
    struct http_unit *u;

    if (dir == LK_DIR_RECV) {
        u = http_unit_at(hc, hc->req_seq);
        if (!u) {
            http_orphan(p, hc);
            return;
        }
        u->bytes_in += m->len;
        return;
    }
    /* Checked before the ring, not after it: these bytes belong to a response we
     * knew we could not place (the ring overflowed), and a request that opened a
     * unit in the meantime must not be charged for them. Reading the front unit
     * first would do exactly that, and the resulting observation would look
     * perfectly plausible. */
    if (hc->resp_orphan)
        return;
    u = http_unit_front(hc);
    if (!u) {
        http_orphan(p, hc);
        return;
    }
    u->bytes_out += m->len;
}

static void body_end(struct lk_proto *p, struct lk_conn *c, struct http_conn *hc, enum lk_dir dir,
                     const struct lk_msg *m)
{
    struct http_unit *u;

    if (dir == LK_DIR_RECV) {
        u = http_unit_at(hc, hc->req_seq);
        hc->req_seq = ~0ull;
        if (!u) {
            http_orphan(p, hc);
            return;
        }
        u->req_done = true;
        u->ts_req_done_ns = m->ts_ns; /* РH5: the server's clock starts here */
        return;
    }
    if (hc->resp_orphan) {
        hc->resp_orphan = false; /* an owed response finished; nothing to report */
        return;
    }
    u = http_unit_front(hc);
    if (!u) {
        http_orphan(p, hc);
        return;
    }
    /* A body end with no response head behind it means the head itself was
     * unreadable — a capture hole cut the status line, so the framer published a
     * truncated 'S' that http_resp.c refused. There is no status to report, so
     * the unit is dropped rather than emitted with a made-up one. */
    if (!u->have_resp) {
        http_orphan(p, hc);
        u->used = false;
        hc->head_seq++;
        return;
    }
    u->ts_complete_ns = m->ts_ns;
    unit_retire(p, c, hc, NULL);
}

/* --- framer notes (РH3) ---------------------------------------------------- */

static void framer_note(struct lk_proto *p, struct http_conn *hc, const struct lk_msg *m)
{
    /* A field on the wire the framer refused to trust — a malformed start line,
     * CL+TE, a conflicting Content-Length — is a parse error in the same sense
     * as PG's and MySQL's. A capture hole is not: nothing was wrong with the
     * input, we simply did not see all of it, and the generic framer already
     * counts it as a hole. */
    if (LK_HTTP_NOTE_IS_PARSE_ERR(m->len))
        p->st.parse_errors++;
    if (LK_HTTP_NOTE_IS_BLIND(m->len))
        p->st.blind_conns++;
    if (m->len == LK_HTTP_NOTE_BODY_UNSEEN && hc) {
        /* РH4: the head promised a body, not one byte of it came through the
         * socket, and the next response head closed the unit. The timings are
         * honest, bytes_out is a lower bound, and the observation says so
         * instead of quietly under-reporting. */
        struct http_unit *u = http_unit_front(hc);

        if (u)
            u->flags |= LK_QO_BODY_UNSEEN;
    }
}

/* --- lk_msg_sink implementation (down contract) ---------------------------- */

static void http_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct lk_proto *p = ctx;
    struct http_conn *hc = http_conn_get(p, c);

    p->st.msgs++;
    if (m->type == LK_HTTP_MSG_NOTE) {
        /* Counted before the state check: a note is the framer's own report and
         * stays true whether or not we could allocate somewhere to put it. The
         * '!' tally is per direction, like every other type. */
        p->st.by_type[dir][(__u8)'!']++;
        framer_note(p, hc, m);
        return;
    }
    if (!hc)
        return; /* alloc failed: keep counting, skip semantics */
    hc->msgs++;

    switch (m->type) {
    case LK_HTTP_MSG_REQ:
        if (dir == LK_DIR_RECV)
            http_req_head(p, c, hc, m);
        break;
    case LK_HTTP_MSG_RESP:
    case LK_HTTP_MSG_INTER:
        if (dir == LK_DIR_SEND)
            http_resp_head(p, hc, m, m->type == LK_HTTP_MSG_INTER);
        break;
    case LK_HTTP_MSG_DATA:
        body_data(p, hc, dir, m);
        break;
    case LK_HTTP_MSG_END:
        body_end(p, c, hc, dir, m);
        break;
    default:
        p->st.unknown_msgs++;
        break;
    }
}

static void http_on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    struct lk_proto *p = ctx;
    struct http_conn *hc = http_conn_get(p, c);

    p->st.resyncs++;
    if (!hc)
        return;
    /* Which units a loss ruins depends on which direction lost the thread, and
     * the distinction is worth making because a resync is *reported late*: the
     * framer only knows it is back in sync when it finds an anchor, which on the
     * response side is the next status line — by which time the next request has
     * long since opened its unit. Dropping everything here would therefore throw
     * away the exchange the resync just recovered, on every connection the agent
     * joins mid-stream.
     *
     *   - **request side**: a request may have gone by unseen, so the queue no
     *     longer lines up with the responses still to come. Every pairing from
     *     here on would be a guess. Drop the lot (Р19).
     *   - **response side**: what was lost is a response, so the unit being
     *     answered is ruined — but a unit that has not been answered yet still
     *     has its own honest request head, and the FIFO still puts its response
     *     next. Drop the ones with a response in progress and keep the rest. */
    if (dir == LK_DIR_RECV) {
        units_drop_all(hc, &p->st.units_dropped_resync);
    } else {
        struct http_unit *u;

        while ((u = http_unit_front(hc)) && u->have_resp) {
            u->used = false;
            hc->head_seq++;
            p->st.units_dropped_resync++;
        }
        hc->resp_orphan = false;
    }
    hc->degraded = true;
}

/* Fired by the connection table on *every* removal path (CONN_CLOSE, LRU
 * eviction, idle sweep, teardown), routed here through the framer sink — the
 * one place proto_state is released (Р15). Idempotent and NULL-safe. */
static void http_on_conn_close(void *ctx, struct lk_conn *c)
{
    struct lk_proto *p = ctx;
    struct http_conn *hc = c->proto_state;
    struct http_unit *u;

    if (!hc)
        return;
    /* The front unit is the only one a close can say anything about, and what it
     * says depends on why its body had not ended yet:
     *
     *   - **rule 6**: the response declared no length at all, so the socket
     *     closing *is* the end of the body (RFC 9112 §6.3). The unit completes
     *     normally — the ordinary shape for HTTP/1.0 and for `Connection: close`,
     *     and the reason a plain `curl http://…` produces an observation.
     *   - **a declared length that never finished**: a body that went out by
     *     sendfile with an iterator the probe cannot copy from, a capture whose
     *     last call was cut short (Р9's lazy tail never learns those bytes
     *     existed), or a client that hung up mid-download. The status, the route
     *     and the head timings are all honest and worth reporting; only the byte
     *     count is short, so the unit is emitted with LK_QO_BODY_UNSEEN rather
     *     than thrown away (РH4). Dropping it would make `nginx/get.lkt` — one
     *     request, one 200, one 17-byte body — produce nothing at all.
     *
     * A unit that never saw a response head is a different thing entirely and is
     * still dropped: a request cut off by a disconnect is not an observation
     * (Р19, a documented blind spot of the model). */
    u = http_unit_front(hc);
    if (u && u->have_resp) {
        u->ts_complete_ns = c->last_activity_ns;
        if (!u->to_close)
            u->flags |= LK_QO_BODY_UNSEEN;
        unit_retire(p, c, hc, NULL);
    }
    units_drop_all(hc, &p->st.units_dropped_close);
    for (int i = 0; i < LK_HTTP_MAX_INFLIGHT; i++) {
        free(hc->ring[i].target);
        free(hc->ring[i].tracestate);
    }
    free(hc);
    c->proto_state = NULL;
}

/* --- registry entry point ------------------------------------------------- */

struct lk_proto *lk_proto_http_new(const struct lk_query_sink *out)
{
    struct lk_proto *p = calloc(1, sizeof(*p));

    if (!p)
        return NULL;
    if (out)
        p->out = *out;
    p->msink.ctx = p;
    p->msink.on_msg = http_on_msg;
    p->msink.on_conn_close = http_on_conn_close;
    p->msink.on_resync = http_on_resync;
    /* on_conn_open unused: proto_state is allocated lazily (Р15). */
    return p;
}
