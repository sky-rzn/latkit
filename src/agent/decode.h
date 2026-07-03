/* SPDX-License-Identifier: GPL-2.0 */
/* Ringbuf record decoder: classify a raw record by lk_ev_hdr.type and the
 * size-class layout of format v1 (STAGE1.md). Pure — no I/O, no state — so
 * the same code is unit-tested against crafted records in tests/unit. */
#ifndef LATKIT_DECODE_H
#define LATKIT_DECODE_H

#include <linux/types.h>
#include <stddef.h>

#include "latkit.h"

enum lk_decode_status {
    LK_DEC_CONN = 0, /* view.conn valid; OPEN or CLOSE per hdr.type */
    LK_DEC_DATA,     /* view.data valid; view.cap_len clamped to the record */
    LK_DEC_SHORT,    /* record smaller than its type demands; drop */
    LK_DEC_UNKNOWN,  /* hdr.type not recognised; drop */
};

struct lk_ev_view {
    const struct lk_ev_hdr *hdr; /* set whenever the record fits a header */
    const struct lk_ev_conn *conn;
    const struct lk_ev_data *data;
    __u32 cap_len; /* payload bytes safe to read from data->payload */
};

enum lk_decode_status lk_ev_decode(const void *buf, size_t size, struct lk_ev_view *v);

#endif /* LATKIT_DECODE_H */
