// SPDX-License-Identifier: GPL-2.0
#include "pipeline.h"

#include <string.h>

#include "latkit.h"

int lk_pipeline_init(struct lk_pipeline *p, __u32 max_conns, __u64 idle_timeout_ns,
                     const struct lk_msg_sink *sink)
{
    memset(p, 0, sizeof(*p));
    lk_reasm_init(&p->reasm, sink);
    p->conns = lk_conn_table_new(max_conns, idle_timeout_ns);
    return p->conns ? 0 : -1;
}

void lk_pipeline_fini(struct lk_pipeline *p)
{
    if (!p)
        return;
    lk_conn_table_free(p->conns);
    p->conns = NULL;
}

void lk_pipeline_feed(struct lk_pipeline *p, const void *data, size_t size,
                      struct lk_pipeline_ev *out)
{
    struct lk_ev_view *v = &out->view;
    __u32 lost = 0;

    memset(out, 0, sizeof(*out));
    out->status = lk_ev_decode(data, size, v);

    switch (out->status) {
    case LK_DEC_CONN:
        if (v->hdr->type == LK_EV_CONN_CLOSE) {
            lk_conn_table_close(p->conns, v->hdr->conn_id, v->hdr->seq, v->hdr->ts_ns, &lost);
        } else {
            out->conn = lk_conn_table_open(p->conns, v->hdr->conn_id, v->hdr->seq, v->hdr->ts_ns,
                                           &v->conn->tuple, v->hdr->flags & LK_F_SYNTHETIC, &lost);
        }
        break;
    case LK_DEC_DATA: {
        struct lk_conn *c =
            lk_conn_table_data(p->conns, v->hdr->conn_id, v->hdr->seq, v->hdr->ts_ns, &lost);

        out->conn = c;
        if (c) { /* NULL only on alloc failure: degrade to no framing */
            bool was_tls = c->flags & LK_CONN_TLS;

            lk_reasm_data(&p->reasm, c, v->hdr->dir, v->data, v->cap_len);
            out->tls_now = !was_tls && (c->flags & LK_CONN_TLS);
        }
        break;
    }
    case LK_DEC_UNKNOWN:
    case LK_DEC_SHORT:
    default:
        break;
    }
    out->lost = lost;
}
