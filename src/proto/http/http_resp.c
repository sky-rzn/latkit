// SPDX-License-Identifier: GPL-2.0
/* The response head (PLAN-HTTP.md М3, РH4/РH5/РH10) — the other half of what a
 * unit is made of, and a much shorter file than http_req.c, because a response
 * carries almost nothing worth keeping: a status, a size, and a content type
 * for the span. Everything identifying about an exchange came from the request.
 *
 * Two decisions live here rather than anywhere else:
 *
 *   - **the status splits three ways, not two.** 5xx is the server failing and
 *     becomes LK_QO_ERROR; 4xx is the *client* failing and gets its own flag
 *     (РH10). Folding them together is the single easiest way to make a
 *     404-heavy service look broken, and once folded there is no way back —
 *     the metric is already aggregated.
 *   - **rule 6 is recognised here, not at the connection's end.** A response
 *     with no Content-Length, no chunked encoding and no status that forbids a
 *     body runs until the socket closes (RFC 9112 §6.3), so its unit is
 *     *completed* by CONN_CLOSE rather than truncated by it. The head is the
 *     only place that distinction is visible, so http.c is told now and reads
 *     the flag later. */
#include <string.h>

#include "http.h"

/* Everything the framing rules need out of a response head, read in one pass so
 * the head is walked once. Deliberately a copy of the framer's own reading: the
 * framer decides where the body ends, the handler decides what to report about
 * it, and giving them a shared mutable understanding of the same head is how
 * the two drift apart under a degradation. */
struct resp_fields {
    __u64 clen;
    bool have_cl;
    bool te_chunked;
    bool te_present;
    struct http_span ctype;
};

static void read_fields(struct http_head *h, struct resp_fields *rf)
{
    struct http_span name, val;

    while (http_head_field(h, &name, &val)) {
        if (http_span_eq_ci(name, "content-length")) {
            if (http_parse_content_length(val, &rf->clen))
                rf->have_cl = true;
        } else if (http_span_eq_ci(name, "transfer-encoding")) {
            rf->te_present = true;
            rf->te_chunked = http_span_eq_ci(http_list_last(val), "chunked");
        } else if (http_span_eq_ci(name, "content-type")) {
            rf->ctype = http_first_token(val);
        }
    }
}

void http_resp_head(struct lk_proto *p, struct http_conn *hc, const struct lk_msg *m, bool interim)
{
    struct http_unit *u = http_unit_front(hc);
    struct resp_fields rf = {0};
    struct http_head h;
    struct http_span line;
    __u16 code = 0;
    __u8 minor = 0;

    http_head_init(&h, m->body, m->body_cap);
    if (!http_head_line(&h, &line) || !http_parse_status_line(line, &code, &minor)) {
        /* As in http_req.c: only a head cut short by a capture hole reaches
         * this, since the framer parses the status line before publishing. */
        http_orphan(p, hc);
        return;
    }
    /* The status class is the tally the stats line wants — one digit rather
     * than sixty codes, and it is counted whether or not a unit is waiting for
     * it, so the number matches what went over the wire. */
    p->st.by_type[LK_DIR_SEND][(__u8)('0' + code / 100)]++;

    if (!u) {
        /* No unit to answer. Either the ring overflowed and this is one of the
         * responses we knew we would not be able to place (hc->owed), or the
         * connection was joined mid-stream / has just resynced. Both are
         * expected shapes, neither is a parse error: the bytes were fine, we
         * simply never saw the request they belong to. */
        if (!interim && hc->owed) {
            hc->owed--;
            hc->resp_orphan = true; /* its body follows and belongs to nobody */
        }
        http_orphan(p, hc);
        return;
    }

    if (interim) {
        /* A 1xx closes nothing (РH6). Its timestamp is the only server-side
         * signal available before an upload starts, so it is kept; the first
         * one wins, because `103 Early Hints` may repeat. */
        if (!u->ts_interim_ns)
            u->ts_interim_ns = m->ts_ns;
        return;
    }

    read_fields(&h, &rf);
    u->status = code;
    u->resp_minor = minor;
    u->have_resp = true;
    u->ts_first_row_ns = m->ts_ns; /* TTFB: the first byte of the response head */
    if (m->flags & LK_MSG_BODY_TRUNC)
        u->flags |= LK_QO_TEXT_TRUNC;
    if (rf.ctype.n)
        http_copy_label(u->ctype, sizeof(u->ctype), rf.ctype);

    if (code >= 500)
        u->flags |= LK_QO_ERROR;
    else if (code >= 400)
        u->flags |= LK_QO_CLIENT_ERR;

    /* Rule 6 of the body-length list: neither a length nor a chunked encoding,
     * and a status that may carry a body — so the body is however many bytes
     * arrive before the socket closes. CONN_CLOSE then *completes* this unit
     * instead of dropping it (http.c). A response to HEAD is the mirror case: a
     * Content-Length describing a body that will never come, which is why the
     * request's method decides here and not the header. */
    u->to_close =
        !rf.have_cl && !rf.te_present && code != 204 && code != 304 && u->method_id != HTTP_M_HEAD;
}
