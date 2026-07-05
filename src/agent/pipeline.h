/* SPDX-License-Identifier: GPL-2.0 */
/* Framing-relevant core of the event path (Р14, STAGE2.md): decode one raw
 * ringbuf record and route it through the connection table and the streaming
 * framer. This is the code the live agent (events.c) and the offline replay
 * harness (tests/replay) share, so both drive the *same* logic over live and
 * recorded traces. It is libbpf-free and I/O-free; the caller layers its own
 * presentation (--events/--messages) and BPF side effects (set_cap_headers on
 * TLS detect) around the per-record outcome returned in lk_pipeline_ev. */
#ifndef LATKIT_PIPELINE_H
#define LATKIT_PIPELINE_H

#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>

#include "conn_table.h"
#include "decode.h"
#include "reassembly.h"

struct lk_pipeline {
    struct lk_conn_table *conns;
    struct lk_reasm reasm;
};

/* Per-record outcome, for the caller's logging and side effects. */
struct lk_pipeline_ev {
    enum lk_decode_status status; /* how the record decoded */
    struct lk_ev_view view;       /* decoded view (valid unless SHORT/UNKNOWN) */
    struct lk_conn *conn;         /* entry touched by a data/open event, else NULL */
    __u32 lost;                   /* events lost in a seq gap before this one */
    bool tls_now;                 /* this data event flipped the conn to TLS */
};

/* Build the table (max_conns / idle timeout as in conn_table) and init the
 * framer with `sink`. Returns -1 on allocation failure. */
int lk_pipeline_init(struct lk_pipeline *p, __u32 max_conns, __u64 idle_timeout_ns,
                     const struct lk_msg_sink *sink);
void lk_pipeline_fini(struct lk_pipeline *p);

/* Decode and route one record, filling *out. Safe on malformed records: the
 * status reports SHORT/UNKNOWN and nothing is routed. */
void lk_pipeline_feed(struct lk_pipeline *p, const void *data, size_t size,
                      struct lk_pipeline_ev *out);

#endif /* LATKIT_PIPELINE_H */
