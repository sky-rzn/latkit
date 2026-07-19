// SPDX-License-Identifier: GPL-2.0
/* MySQL classic-protocol parser libFuzzer target (MYSQL.md М7; the fuzz_pg
 * harness transplanted to the second protocol). Same contract as fuzz_pg: the
 * parser input is untrusted — packet bodies come off the wire and may be
 * truncated (capture budget) or corrupt — so this target drives the exact
 * production path an attacker-controlled byte stream takes: bytes -> framer
 * (my_frame.c) -> lk_msg -> MySQL handler (src/proto/my), through one function,
 * lk_my_fuzz_one(), so a single input covers both the framer's u24-length /
 * seq / 16MB-continuation gating and every field read in the handler
 * (my_wire.h bounds, lenenc parsing, the reply state machine).
 *
 * The connection is forced to the mysql vtable (lk_conn_table_set_protos):
 * without it the framer would fall back to PG. The same input feeds both
 * directions of one connection — the RECV pass drives frontend commands
 * (COM_QUERY / STMT_* / the handshake response) that open units, the SEND pass
 * drives the replies (OK / ERR / EOF / resultsets) that close them — then the
 * connection closes so the destroy hook frees per-connection state on the live
 * agent's path (Р15): a leak or use-after-free shows up under ASAN. Every
 * emitted message and observation goes through the Р51 invariant asserts
 * (fuzz_invariants.h), and every emitted field is read, so an out-of-bounds
 * pointer is caught at emit time.
 *
 * Built only in the -DLATKIT_FUZZ=ON profile (clang; fuzzer,address,undefined).
 * The committed corpus lives in tests/fuzz/corpus/my/; CI replays it (plus the
 * MySQL .lkt traces) with -runs=0 as a regression test. */
#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "conn_table.h"
#include "fuzz_invariants.h"
#include "proto.h"
#include "reassembly.h"

/* Input larger than this is clamped: the framer takes a __u32 length, and a
 * multi-megabyte single feed exercises nothing the low kilobytes do not. */
#define LK_FUZZ_MAX_INPUT (1u << 20)

static void fz_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                        const struct lk_query_obs *o)
{
    (void)ctx;
    (void)c;
    fz_check_obs(o);
    if (s)
        fz_read_bytes(s->user, strnlen(s->user, sizeof(s->user)));
}

static void fz_on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    (void)ctx;
    (void)c;
    fz_read_bytes(s->user, strnlen(s->user, sizeof(s->user)));
    fz_read_bytes(s->database, strnlen(s->database, sizeof(s->database)));
    fz_read_bytes(s->app, strnlen(s->app, sizeof(s->app)));
    fz_read_bytes(s->server_version, strnlen(s->server_version, sizeof(s->server_version)));
    fz_byte_sink += s->complete;
}

static void fz_on_txn(void *ctx, const struct lk_conn *c, __u64 start_ns, __u64 end_ns,
                      char final_status)
{
    (void)ctx;
    (void)c;
    fz_byte_sink += start_ns ^ end_ns ^ (unsigned char)final_status;
}

/* --- framer -> parser tee (identical to fuzz_pg) -------------------------- */
struct fz_tee {
    const struct lk_msg_sink *psink; /* = lk_proto_sink(proto) */
};

static void tee_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    const struct lk_msg_sink *ps = ((struct fz_tee *)ctx)->psink;

    fz_check_msg(m, true);
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

/* One fuzz iteration: bytes -> lk_msg -> MySQL parser, set up and torn down
 * from scratch so state never leaks between inputs. */
int lk_my_fuzz_one(const uint8_t *data, size_t n)
{
    struct lk_query_sink qsink = {
        .on_query = fz_on_query,
        .on_session = fz_on_session,
        .on_txn = fz_on_txn,
    };
    const struct lk_proto_ops *ops = lk_proto_find("mysql", 5);
    struct lk_proto *proto;
    struct fz_tee tee;
    struct lk_reasm reasm;
    struct lk_conn_table *tbl;
    struct lk_conn *c;
    struct lk_tuple tuple = {0};
    __u32 lost = 0;
    __u32 len = n > LK_FUZZ_MAX_INPUT ? LK_FUZZ_MAX_INPUT : (__u32)n;

    if (!ops)
        return 0;
    proto = ops->proto_new(&qsink);
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
    /* Force the mysql framer/handler on every entry (else the PG default). */
    lk_conn_table_set_protos(tbl, NULL, 0, ops);
    lk_conn_table_on_destroy(tbl, fz_on_destroy, &tee);

    c = lk_conn_table_open(tbl, 0x1234, 0, 1000, &tuple, false, &lost);
    if (c) {
        /* Frontend then backend over the same bytes: the request pass opens
         * units, the reply pass closes them. A header hole between the two
         * dirties the frontend so the parser's resync/degraded path is walked
         * whenever the backend bytes carry a response-head anchor. */
        lk_frame_bytes(&reasm, c, LK_DIR_RECV, data, len, 2000);
        lk_frame_hole(&reasm, c, LK_DIR_RECV, 5);
        lk_frame_bytes(&reasm, c, LK_DIR_SEND, data, len, 3000);
    }
    lk_conn_table_close(tbl, 0x1234, 1, 4000, &lost);

    lk_conn_table_free(tbl);
    lk_reasm_free(&reasm);
    lk_proto_free(proto);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return lk_my_fuzz_one(data, size);
}
