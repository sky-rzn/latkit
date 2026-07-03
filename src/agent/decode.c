// SPDX-License-Identifier: GPL-2.0
#include "decode.h"

enum lk_decode_status lk_ev_decode(const void *buf, size_t size, struct lk_ev_view *v)
{
    const struct lk_ev_hdr *hdr = buf;

    *v = (struct lk_ev_view){0};
    if (size < sizeof(*hdr))
        return LK_DEC_SHORT;
    v->hdr = hdr;

    switch (hdr->type) {
    case LK_EV_CONN_OPEN:
    case LK_EV_CONN_CLOSE:
        if (size < sizeof(struct lk_ev_conn))
            return LK_DEC_SHORT;
        v->conn = buf;
        return LK_DEC_CONN;
    case LK_EV_DATA: {
        const struct lk_ev_data *d = buf;

        if (size < sizeof(*d))
            return LK_DEC_SHORT;
        v->data = d;
        v->cap_len = d->cap_len;
        /* Trust the record boundary over the kernel-written length. */
        if (v->cap_len > size - sizeof(*d))
            v->cap_len = size - sizeof(*d);
        return LK_DEC_DATA;
    }
    default:
        return LK_DEC_UNKNOWN;
    }
}
