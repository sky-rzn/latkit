// SPDX-License-Identifier: GPL-2.0
/* HTTP/1.x handler (PLAN-HTTP.md М1/М2) — the message consumer of the stream
 * framer in http_frame.c, in the shape of pg.c / my.c: it owns the
 * per-connection state behind lk_conn.proto_state, tallies messages by
 * (direction, type), and would dispatch them by phase.
 *
 * М2 stops at the tally, with one addition: the framer's '!' note messages
 * (РH3) are the only channel a stream framer has for reporting a degradation,
 * so this is where they turn into counters — corrupt input into
 * latkit_parse_errors_total, a protocol switch into the blind-zone tally. That
 * split is what makes the М2 acceptance criterion measurable: parse_errors
 * counts fields the wire got wrong, never bytes the capture budget lost.
 *
 * The unit lifecycle and the four timings (РH5/РH6) are М3's, so this handler
 * emits no lk_query_obs at all — it exists to close the registry entry (every
 * protocol needs a proto_new), to make the per-protocol stats line real, and to
 * pin the state lifecycle: proto_state is released here on every removal path,
 * exactly as Р15 requires, while the framer's frame_state is released by the
 * connection table (one flat allocation, see conn_table.h).
 *
 * No I/O, no libbpf: a pure state machine, fed synthetic lk_msg by unit tests
 * and .lkt traces by the replay harness. */
#include <stdlib.h>

#include "http.h"

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
    /* A synthetic or lazily created entry joined an established connection:
     * the first bytes may be the middle of a body, so nothing before the next
     * request head is a trustworthy unit boundary (М3 acts on this). */
    hc->degraded = (c->flags & LK_CONN_SYNTHETIC) != 0;
    c->proto_state = hc;
    p->st.conns++;
    return hc;
}

static void http_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct lk_proto *p = ctx;
    struct http_conn *hc = http_conn_get(p, c);

    p->st.msgs++;
    p->st.by_type[dir][(__u8)m->type]++;
    if (m->type == LK_HTTP_MSG_NOTE) {
        /* A field on the wire the framer refused to trust — a malformed start
         * line, CL+TE, a conflicting Content-Length — is a parse error in the
         * same sense as PG's and MySQL's. A capture hole is not: nothing was
         * wrong with the input, we simply did not see all of it, and it is
         * already counted as a hole by the generic framer. */
        if (LK_HTTP_NOTE_IS_PARSE_ERR(m->len))
            p->st.parse_errors++;
        if (LK_HTTP_NOTE_IS_BLIND(m->len))
            p->st.blind_conns++;
    }
    if (!hc)
        return; /* alloc failed: keep counting, skip semantics */
    hc->msgs++;
    /* М3: dispatch to http_req.c / http_resp.c and drive the unit queue. */
}

static void http_on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    struct lk_proto *p = ctx;
    struct http_conn *hc = http_conn_get(p, c);

    (void)dir;
    p->st.resyncs++;
    if (!hc)
        return;
    /* The stream broke: whatever was in flight cannot be completed honestly.
     * М3 drops the in-flight units into units_dropped_resync here; М2 only
     * records that this connection is no longer at a known boundary. */
    hc->degraded = true;
}

/* Fired by the connection table on *every* removal path (CONN_CLOSE, LRU
 * eviction, idle sweep, teardown), routed here through the framer sink — the
 * one place proto_state is released (Р15). Idempotent and NULL-safe. */
static void http_on_conn_close(void *ctx, struct lk_conn *c)
{
    (void)ctx;
    free(c->proto_state);
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
