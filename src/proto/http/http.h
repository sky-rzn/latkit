/* SPDX-License-Identifier: GPL-2.0 */
/* Internals shared by the HTTP/1.x framer (http_frame.c) and handler (http.c),
 * the way pg.h / my.h serve their protocols. Not included by the core: the
 * outside world sees only lk_proto_http_ops and lk_proto_http_new (proto.h).
 *
 * PLAN-HTTP.md М1 builds the seam, not the protocol: the framer is a stream
 * framer (РH1) that emits one synthetic message per capture event, and the
 * handler counts messages and emits no observations. М2 replaces the framer
 * body with the real HEAD/BODY machine, М3 the handler with the unit
 * lifecycle. The two structures below are already split the way those stages
 * need them — framing state in lk_conn.frame_state, semantic state in
 * lk_conn.proto_state — so the ownership rules are exercised from day one. */
#ifndef LATKIT_HTTP_H
#define LATKIT_HTTP_H

#include "proto.h"

/* Synthetic message types (РH3). М1 emits only the two head letters, one per
 * capture event and per direction; М2 adds 'I' (interim 1xx), 'D' (a body
 * chunk: length only, no bytes) and 'E' (end of body). */
#define LK_HTTP_MSG_REQ  'R' /* request head: start line + header block */
#define LK_HTTP_MSG_RESP 'S' /* response head: status line + header block */

/* Stream-framer state — the owner of lk_conn.frame_state (РH1). One flat
 * allocation covering both directions, allocated lazily on the connection's
 * first captured bytes and freed by the connection table on every removal
 * path; nothing inside may own a pointer (see conn_table.h). Bulk scratch —
 * М2's header-block accumulator — goes into lk_frame.buf, drawn from the
 * reassembly slab pool so Р11's memory bound still holds. */
struct http_frame {
    __u64 off[2];    /* bytes fed to the framer so far, per direction: the
                        stream position М2 anchors its resync against */
    __u64 events[2]; /* capture events seen, per direction */
    __u64 holes[2];  /* holes (lost or uncaptured bytes) seen, per direction */
};

/* Per-connection handler state — the owner of lk_conn.proto_state (Р15),
 * allocated lazily on the first message and freed in on_conn_close. */
struct http_conn {
    __u64 msgs;    /* messages dispatched on this connection */
    bool degraded; /* joined mid-session (synthetic entry, or after a resync):
                      the next head is the first trustworthy boundary, so no
                      unit may open before it (М3 acts on this; М1 only
                      records it) */
};

#endif /* LATKIT_HTTP_H */
