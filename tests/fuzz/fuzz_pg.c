// SPDX-License-Identifier: GPL-2.0
/* PostgreSQL parser libFuzzer target (task 8.3, Р51; harness laid down in 3.6).
 *
 * The whole point of Р18 is that the parser input is untrusted: bodies come
 * off the wire and may be truncated (capture budget) or outright corrupt. This
 * target drives the exact production path an attacker-controlled byte stream
 * would take — bytes -> framer -> lk_msg -> PG parser — through one function,
 * lk_pg_fuzz_one(), so a single input covers both the framer's length/type
 * gating and every field read in src/proto/pg.
 *
 * The framer (reassembly.c) turns a per-direction byte stream into whole
 * messages; the PG handler (latkit_proto) consumes them. lk_pg_fuzz_one feeds
 * the same input to both directions of one connection, so frontend passes open
 * units (Q/Parse/Bind/...) and backend passes drive the replies that close them
 * (C/E/Z/COPY/...), then closes the connection so the destroy hook frees the
 * per-connection parser state on the same path the live agent uses (Р15) — a
 * leak or a use-after-free shows up under ASAN. On top of the memory checks,
 * every emitted message and observation goes through the Р51 invariant asserts
 * (fuzz_invariants.h): in-bounds body prefixes, trunc consistent with the
 * prefix, well-formed observations — and every emitted field is read, so an
 * out-of-bounds pointer is caught at emit time, not just at parse time.
 *
 * Built only in the -DLATKIT_FUZZ=ON profile (clang; fuzzer,address,undefined
 * baked in — see tests/fuzz/CMakeLists.txt). The committed corpus lives in
 * tests/fuzz/corpus/pg/; CI replays it (plus the .lkt fixtures) with -runs=0
 * as a regression test. */
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

/* --- framer -> parser tee -------------------------------------------------
 * The framer's sink checks the Р51 message invariants, then tees every message
 * / resync into the PG handler, exactly as events.c and the replay harness
 * wire it. */
struct fz_tee {
    const struct lk_msg_sink *psink; /* = lk_proto_sink(proto) */
};

static void tee_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    const struct lk_msg_sink *ps = ((struct fz_tee *)ctx)->psink;

    fz_check_msg(m);
    if (ps->on_msg)
        ps->on_msg(ps->ctx, c, dir, m);
}

static void tee_on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    const struct lk_msg_sink *ps = ((struct fz_tee *)ctx)->psink;

    if (ps->on_resync)
        ps->on_resync(ps->ctx, c, dir);
}

/* The connection table fires this on every removal path; route it to the parser
 * so proto_state is freed (Р15). */
static void fz_on_destroy(void *ctx, struct lk_conn *c)
{
    const struct lk_msg_sink *ps = ((struct fz_tee *)ctx)->psink;

    if (ps->on_conn_close)
        ps->on_conn_close(ps->ctx, c);
}

/* One fuzz iteration: bytes -> lk_msg -> PG parser, set up and torn down from
 * scratch so state never leaks between inputs. Returns 0 always (a crash or an
 * invariant abort is the only failure a fuzzer cares about). */
int lk_pg_fuzz_one(const uint8_t *data, size_t n)
{
    struct lk_query_sink qsink = {
        .on_query = fz_on_query,
        .on_session = fz_on_session,
        .on_txn = fz_on_txn,
    };
    struct lk_proto *proto;
    struct fz_tee tee;
    struct lk_reasm reasm;
    struct lk_conn_table *tbl;
    struct lk_conn *c;
    struct lk_tuple tuple = {0};
    __u32 lost = 0;
    __u32 len = n > LK_FUZZ_MAX_INPUT ? LK_FUZZ_MAX_INPUT : (__u32)n;

    proto = lk_proto_pg_new(&qsink);
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
    /* The destroy hook (CONN_CLOSE / eviction / teardown) frees proto_state. */
    lk_conn_table_on_destroy(tbl, fz_on_destroy, &tee);

    c = lk_conn_table_open(tbl, 0x1234, 0, 1000, &tuple, false, &lost);
    if (c) {
        /* Frontend then backend over the same bytes: the request pass opens
         * units, the reply pass closes them. A header hole between the two
         * dirties the frontend so the parser's resync/degraded path is walked
         * whenever the backend bytes carry a 'Z' anchor. */
        lk_frame_bytes(&reasm, c, LK_DIR_RECV, data, len, 2000);
        lk_frame_hole(&reasm, c, LK_DIR_RECV, 5);
        lk_frame_bytes(&reasm, c, LK_DIR_SEND, data, len, 3000);
    }
    /* CLOSE fires the destroy hook -> parser frees proto_state (Р15). */
    lk_conn_table_close(tbl, 0x1234, 1, 4000, &lost);

    lk_conn_table_free(tbl);
    lk_reasm_free(&reasm); /* drain the recycled body-prefix slab pool (Р11) */
    lk_proto_free(proto);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return lk_pg_fuzz_one(data, size);
}
