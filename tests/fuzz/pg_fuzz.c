// SPDX-License-Identifier: GPL-2.0
/* PostgreSQL parser fuzz harness (task 3.6, groundwork for stage 8).
 *
 * The whole point of Р18 is that the parser input is untrusted: bodies come
 * off the wire and may be truncated (capture budget) or outright corrupt. This
 * harness drives the exact production path an attacker-controlled byte stream
 * would take — bytes -> framer -> lk_msg -> PG parser — through one function,
 * lk_pg_fuzz_one(), so a single fuzzer (or the offline corpus run below) covers
 * both the framer's length/type gating and every field read in src/proto/pg.
 *
 * The framer (reassembly.c) turns a per-direction byte stream into whole
 * messages; the PG handler (latkit_proto) consumes them. lk_pg_fuzz_one feeds
 * the same input to both directions of one connection, so frontend passes open
 * units (Q/Parse/Bind/...) and backend passes drive the replies that close them
 * (C/E/Z/COPY/...), then closes the connection so the destroy hook frees the
 * per-connection parser state on the same path the live agent uses (Р15) — a
 * leak or a use-after-free shows up under ASAN. The observation sink is not a
 * no-op: it reads every emitted field, including the whole SQL-text prefix, so
 * an out-of-bounds text pointer is caught at emit time, not just at parse time.
 *
 * Two entry points share lk_pg_fuzz_one:
 *   - default: a `main` that treats each argv as a corpus file and runs it
 *     through the harness (what CI does, built with -fsanitize=address,undefined
 *     over the committed fixtures — no privileges, no BPF);
 *   - -DLK_FUZZ_LIBFUZZER: LLVMFuzzerTestOneInput, the real libFuzzer target
 *     (stage 8 wires a persistent corpus and coverage feedback).
 *
 * Build is behind the LATKIT_FUZZ CMake option — a normal build never compiles
 * it. */
#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conn_table.h"
#include "proto.h"
#include "reassembly.h"

/* Input larger than this is clamped: the framer takes a __u32 length, and a
 * multi-megabyte single feed exercises nothing the low kilobytes do not. */
#define LK_FUZZ_MAX_INPUT (1u << 20)

/* --- observation sink: touch every field so OOB reads surface --------------
 * A checksum the compiler cannot elide keeps the reads live (and, under a
 * sanitizer, bounds-checked). We deliberately walk the entire text prefix. */
static volatile uint64_t g_sink;

static void fz_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                        const struct lk_query_obs *o)
{
    uint64_t acc = 0;

    (void)ctx;
    (void)c;
    acc += o->ts_start_ns ^ o->ts_first_row_ns ^ o->ts_complete_ns ^ o->ts_ready_ns;
    acc += o->rows + o->bytes + o->kind + o->flags + (unsigned char)o->txn_status;
    for (size_t i = 0; i < sizeof(o->sqlstate); i++)
        acc += (unsigned char)o->sqlstate[i];
    for (__u32 i = 0; i < o->text_len && o->text; i++)
        acc += (unsigned char)o->text[i]; /* read the whole captured prefix */
    if (s)
        acc += (unsigned char)s->user[0] + (unsigned char)s->database[0];
    g_sink += acc;
}

static void fz_on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    (void)ctx;
    (void)c;
    g_sink += (unsigned char)s->user[0] + (unsigned char)s->database[0] + (unsigned char)s->app[0] +
              (unsigned char)s->server_version[0] + s->complete;
}

static void fz_on_txn(void *ctx, const struct lk_conn *c, __u64 start_ns, __u64 end_ns,
                      char final_status)
{
    (void)ctx;
    (void)c;
    g_sink += start_ns ^ end_ns ^ (unsigned char)final_status;
}

/* --- framer -> parser tee -------------------------------------------------
 * The framer's sink both would-be logs the message stream (dropped here) and
 * tees every message / resync into the PG handler, exactly as events.c and the
 * replay harness wire it. */
struct fz_tee {
    const struct lk_msg_sink *psink; /* = lk_proto_sink(proto) */
};

static void tee_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    const struct lk_msg_sink *ps = ((struct fz_tee *)ctx)->psink;

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
 * scratch so state never leaks between inputs. Returns 0 always (a crash is the
 * only failure a fuzzer cares about). */
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
    lk_proto_free(proto);
    return 0;
}

#ifdef LK_FUZZ_LIBFUZZER

/* Real libFuzzer entry (stage 8 builds this with -fsanitize=fuzzer). */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return lk_pg_fuzz_one(data, size);
}

#else

/* Offline corpus runner: each argv is a file fed through lk_pg_fuzz_one. CI runs
 * it over the committed fixtures under ASAN/UBSAN. Reports the byte totals so a
 * zero-coverage run (e.g. missing corpus) is visible. */
static int run_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    long sz;
    uint8_t *buf;
    size_t got;

    if (!f) {
        fprintf(stderr, "fuzz: cannot open %s\n", path);
        return 1;
    }
    if (fseek(f, 0, SEEK_END) || (sz = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
        fclose(f);
        fprintf(stderr, "fuzz: cannot size %s\n", path);
        return 1;
    }
    buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return 1;
    }
    got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    lk_pg_fuzz_one(buf, got);
    free(buf);
    printf("ok fuzz %s (%zu bytes)\n", path, got);
    return 0;
}

int main(int argc, char **argv)
{
    /* No corpus given: still exercise the empty and single-byte edges so the
     * harness itself is smoke-tested even without fixtures. */
    if (argc < 2) {
        static const uint8_t one[1] = {'Q'};

        lk_pg_fuzz_one(NULL, 0);
        lk_pg_fuzz_one(one, sizeof(one));
        printf("ok fuzz (built-in smoke inputs; pass corpus files as arguments)\n");
        return 0;
    }
    for (int i = 1; i < argc; i++)
        if (run_file(argv[i]))
            return 1;
    printf("ok\n");
    return 0;
}

#endif /* LK_FUZZ_LIBFUZZER */
