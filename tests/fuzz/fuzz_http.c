// SPDX-License-Identifier: GPL-2.0
/* HTTP/1.x framer libFuzzer target (PLAN-HTTP.md М2 acceptance; the fuzz_pg /
 * fuzz_my harness transplanted to the third protocol). The framer's input is
 * the most untrusted the agent handles: unlike a database wire format, an HTTP
 * request is written by whoever can open a socket, and the shapes that matter
 * here — CL together with TE, duplicate Content-Length, bare LF, an oversized
 * head, a chunk size that overflows — are the same ones that desynchronise
 * real proxies. So this target drives the exact production path those bytes
 * take: bytes -> framer (http_frame.c) -> lk_msg -> handler (http.c), through
 * one function, lk_http_fuzz_one().
 *
 * The connection is forced to the http vtable (lk_conn_table_set_protos):
 * without it the framer would fall back to PG. One input feeds both directions
 * of one connection — the RECV pass drives request heads and their bodies, the
 * SEND pass drives status lines, chunked framing and the blind zones — with a
 * hole injected between them so the header-hole and chunked-hole degradations
 * and the anchor scan are on the fuzzed path rather than only in unit tests.
 * The connection then closes, so the destroy hook frees per-connection state
 * on the live agent's path (Р15) and a leak or use-after-free surfaces under
 * ASAN. Every emitted message goes through the Р51 invariant asserts
 * (fuzz_invariants.h) and every emitted byte is read, so an out-of-bounds
 * pointer is caught at emit time.
 *
 * Built only in the -DLATKIT_FUZZ=ON profile (clang; fuzzer,address,undefined).
 * The committed corpus lives in tests/fuzz/corpus/http/; CI replays it (plus
 * the М0 .lkt traces, whose raw bytes are also valid framer input) with
 * -runs=0 as a regression test. */
#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "conn_table.h"
#include "fuzz_invariants.h"
#include "http.h"
#include "proto.h"
#include "reassembly.h"

/* Input larger than this is clamped: the framer takes a __u32 length, and a
 * multi-megabyte single feed exercises nothing the low kilobytes do not. */
#define LK_FUZZ_MAX_INPUT (1u << 20)

/* --- framer -> handler tee (identical in shape to fuzz_pg / fuzz_my) ------ */
struct fz_tee {
    const struct lk_msg_sink *psink; /* = lk_proto_sink(proto) */
    __u64 body[2];                   /* 'D' bytes seen since the last 'E' */
};

static void tee_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct fz_tee *t = ctx;
    const struct lk_msg_sink *ps = t->psink;

    fz_check_http_msg(m);
    /* The framer's own accounting invariant, and the one a mis-framed body
     * breaks first: every byte of a body is reported exactly once by a 'D',
     * and the closing 'E' is their sum. Checked here rather than in
     * fz_check_http_msg because it is a property of the *sequence*. */
    if (m->type == LK_HTTP_MSG_DATA) {
        t->body[dir] += m->len;
    } else if (m->type == LK_HTTP_MSG_END) {
        FZ_ASSERT(m->len == (t->body[dir] > ~0u ? ~0u : (__u32)t->body[dir]));
        t->body[dir] = 0;
    } else if (m->type == LK_HTTP_MSG_REQ || m->type == LK_HTTP_MSG_RESP) {
        t->body[dir] = 0; /* a head with no 'E' before it: the unit was dropped */
    }
    if (ps->on_msg)
        ps->on_msg(ps->ctx, c, dir, m);
}

static void tee_on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    const struct lk_msg_sink *ps = ((struct fz_tee *)ctx)->psink;

    if (ps->on_resync)
        ps->on_resync(ps->ctx, c, dir);
}

static void fz_on_destroy(void *ctx, struct lk_conn *c)
{
    const struct lk_msg_sink *ps = ((struct fz_tee *)ctx)->psink;

    if (ps->on_conn_close)
        ps->on_conn_close(ps->ctx, c);
}

/* One fuzz iteration: bytes -> lk_msg -> HTTP handler, set up and torn down
 * from scratch so state never leaks between inputs. */
int lk_http_fuzz_one(const uint8_t *data, size_t n)
{
    const struct lk_proto_ops *ops = lk_proto_find("http", 4);
    struct lk_proto *proto;
    struct fz_tee tee = {0};
    struct lk_reasm reasm;
    struct lk_conn_table *tbl;
    struct lk_conn *c;
    struct lk_tuple tuple = {0};
    __u32 lost = 0;
    __u32 len = n > LK_FUZZ_MAX_INPUT ? LK_FUZZ_MAX_INPUT : (__u32)n;

    if (!ops)
        return 0;
    proto = ops->proto_new(NULL); /* М2 emits no observations; М3 wires a sink */
    if (!proto)
        return 0;
    tee.psink = lk_proto_sink(proto);
    lk_reasm_init(&reasm, &(struct lk_msg_sink){.ctx = &tee,
                                                .on_msg = tee_on_msg,
                                                .on_resync = tee_on_resync,
                                                .on_conn_close = fz_on_destroy});

    tbl = lk_conn_table_new(LK_MAX_CONNS_DEFAULT, 600ULL * 1000000000ULL);
    if (!tbl) {
        lk_proto_free(proto);
        return 0;
    }
    /* Force the http framer/handler on every entry (else the PG default). */
    lk_conn_table_set_protos(tbl, NULL, 0, ops);
    lk_conn_table_on_destroy(tbl, fz_on_destroy, &tee);

    c = lk_conn_table_open(tbl, 0x1234, 0, 1000, &tuple, false, &lost);
    if (c) {
        /* Request pass, then a hole, then the response pass over the same
         * bytes: whatever head or body the first pass left open meets a hole,
         * and the second pass has to find its way back on a start-line anchor.
         * The split feed also lets one input drive a head across events. */
        lk_frame_bytes(&reasm, c, LK_DIR_RECV, data, len / 2, 2000);
        lk_frame_bytes(&reasm, c, LK_DIR_RECV, data + len / 2, len - len / 2, 2001);
        lk_frame_hole(&reasm, c, LK_DIR_RECV, 5);
        lk_frame_bytes(&reasm, c, LK_DIR_SEND, data, len, 3000);
        lk_frame_hole(&reasm, c, LK_DIR_SEND, 7);
        lk_frame_bytes(&reasm, c, LK_DIR_RECV, data, len, 4000);
    }
    lk_conn_table_close(tbl, 0x1234, 1, 5000, &lost);

    lk_conn_table_free(tbl);
    lk_reasm_free(&reasm);
    lk_proto_free(proto);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return lk_http_fuzz_one(data, size);
}
