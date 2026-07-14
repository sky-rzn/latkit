// SPDX-License-Identifier: GPL-2.0
#include "pipeline.h"

#include <string.h>

#include "latkit.h"

/* Bridge the connection table's removal hook to the framer sink's close
 * callback, so the protocol handler frees lk_conn.proto_state on every path an
 * entry can leave the table — CONN_CLOSE, LRU eviction, idle sweep, teardown
 * (Р15). The sink is the framer's own copy, valid for the pipeline's life. */
static void pipeline_on_destroy(void *ctx, struct lk_conn *c)
{
    struct lk_pipeline *p = ctx;

    if (p->reasm.sink.on_conn_close)
        p->reasm.sink.on_conn_close(p->reasm.sink.ctx, c);
}

int lk_pipeline_init(struct lk_pipeline *p, __u32 max_conns, __u64 idle_timeout_ns,
                     const struct lk_msg_sink *sink)
{
    memset(p, 0, sizeof(*p));
    lk_reasm_init(&p->reasm, sink);
    p->conns = lk_conn_table_new(max_conns, idle_timeout_ns);
    if (!p->conns)
        return -1;
    lk_conn_table_on_destroy(p->conns, pipeline_on_destroy, p);
    return 0;
}

void lk_pipeline_fini(struct lk_pipeline *p)
{
    if (!p)
        return;
    lk_conn_table_free(p->conns); /* frees in-flight body buffers on teardown */
    p->conns = NULL;
    lk_reasm_free(&p->reasm); /* drain the recycled body-slab pool */
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
        bool decrypted = v->hdr->flags & LK_F_DECRYPTED;
        struct lk_conn *c = lk_conn_table_peek(p->conns, v->hdr->conn_id);

        /* Ciphertext socket event of a TLS connection: drop it before the seq
         * detector runs (Р38), so a ciphertext gap never dirties the decrypted
         * framer through the shared seq bookkeeping. The uprobe channel is the
         * sole data source from the moment the connection went TLS. */
        if (c && (c->flags & LK_CONN_TLS) && !decrypted) {
            out->conn = c;
            out->tls_socket_dropped = true;
            lk_conn_table_note_tls_drop(p->conns, c, v->hdr->seq, v->hdr->ts_ns);
            break;
        }

        if (decrypted) {
            /* Plaintext from an SSL_* uprobe: its own seq space (Р38), framed
             * into the entry the socket path already opened by cookie. */
            c = lk_conn_table_data_decrypted(p->conns, v->hdr->conn_id, v->hdr->seq, v->hdr->ts_ns,
                                             &lost);
            out->conn = c;
            if (c) {
                /* Р38 order has 'S' happen-before any decrypted byte; a
                 * decrypted event on a still-plaintext conn means that broke. */
                out->decrypted_early = !(c->flags & LK_CONN_TLS);
                lk_reasm_data(&p->reasm, c, v->hdr->dir, v->data, v->cap_len);
            }
            break;
        }

        /* Plaintext socket event of a non-TLS connection: the normal path. The
         * 'S' reply flows through here (the conn is not yet TLS) and flips it,
         * whereupon the framer is reset to startup for the decrypted stream. */
        c = lk_conn_table_data(p->conns, v->hdr->conn_id, v->hdr->seq, v->hdr->ts_ns, &lost);
        out->conn = c;
        if (c) { /* NULL only on alloc failure: degrade to no framing */
            bool was_tls = c->flags & LK_CONN_TLS;

            lk_reasm_data(&p->reasm, c, v->hdr->dir, v->data, v->cap_len);
            out->tls_now = !was_tls && (c->flags & LK_CONN_TLS);
            if (out->tls_now) {
                lk_conn_tls_reset_framing(c);
                lk_conn_table_note_tls_open(p->conns);
            }
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
