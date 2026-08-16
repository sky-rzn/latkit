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
 * Since М3 the handler also emits observations, so the target carries a query
 * sink whose callbacks re-read every borrowed string and assert the shared
 * lk_query_obs invariants (fz_check_obs): a unit's target and method outlive
 * the head buffer they were copied out of only if the copy really happened, and
 * a fuzzer that never looked at them would not notice.
 *
 * Since МS4 the same target also drives the **S3 dialect** (РS1), selected by a
 * leading 0xFD — a byte that cannot begin an HTTP start line, so the whole
 * pre-existing corpus keeps exercising the base dialect unshifted and the
 * fuzzer switches flavours by mutating one byte (the idiom fuzz_norm uses for
 * its three input languages). The dialect is where an S3 port's attack surface
 * actually is: it reads four things the base one does not — a `Credential=` out
 * of a signature, a bucket out of a Host or a path, `<Code>` out of a *body*
 * prefix, and the operation out of a closed table — and every one of them is
 * parsed from bytes an unauthenticated client chose. The S3 branch therefore
 * carries one invariant of its own beside the shared ones (fz_check_s3_obs):
 * whatever the input, the operation label is a bare identifier, never a slice
 * of the path. That is what "the cardinality of `op` is bounded by
 * construction" (РS2) means, checked against a mutator rather than a table.
 *
 * The connection is forced to the selected vtable (lk_conn_table_set_protos):
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

/* Whether this run drives the S3 dialect, so the query sink knows which
 * contract to hold the observation to. A file-scope flag rather than a sink
 * context because the sink is installed once, before the input is read. */
static bool fz_is_s3;

/* РS2, from the outside: an S3 observation's `op` is a pointer into a static
 * table, so no input — however much of it looks like a path — may produce a
 * label with a path's alphabet in it. Checked here rather than only in
 * test_s3_op because the classifier is reached through the framer and the
 * header parser, and it is those two that decide what it is *given*.
 *
 * The two labels either side of it have *different* contracts, and the
 * difference is worth stating because the first version of this check got it
 * wrong and the fuzzer said so within the hour:
 *
 *   - the **bucket** is validated against the S3 naming rules before it may be
 *     a label (РS3), so its alphabet is closed: lower-case, digits, `.` and
 *     `-`. A name that fails becomes `other`, never the bytes that failed.
 *   - the **access key** is not validated, because it cannot be: it is whatever
 *     the deployment issued, and refusing an unfamiliar shape would lose the
 *     label on exactly the servers whose keys are not AWS-shaped. What РS4
 *     promises is that it is *bounded* (40 bytes, refused rather than clipped),
 *     *printable* (a control byte rejects the whole value), and never the
 *     signature or a path — the extractors stop at the `/` that begins the
 *     credential scope, so the one byte an object key could not survive
 *     without is the one byte that cannot appear. A `%` can: a client is free
 *     to percent-encode its own key, and a fuzzer will.
 */
static void fz_check_s3_obs(const struct lk_session *s, const struct lk_query_obs *o)
{
    if (o->route) {
        /* The longest name in the table is `DeleteBucketLifecycleConfiguration`
         * at 34; a slice of a target would have no such ceiling. */
        FZ_ASSERT(o->route_len > 0 && o->route_len <= 34);
        for (__u32 i = 0; i < o->route_len; i++) {
            char ch = o->route[i];

            FZ_ASSERT((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                      (ch >= '0' && ch <= '9'));
        }
    }
    if (!s)
        return;
    for (const char *p = s->database; *p; p++)
        FZ_ASSERT((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '.' || *p == '-');
    FZ_ASSERT(strlen(s->user) <= LK_S3_AK_MAX);
    for (const char *p = s->user; *p; p++)
        FZ_ASSERT((unsigned char)*p > 0x20 && (unsigned char)*p < 0x7f && *p != '/');
}

static void fz_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                        const struct lk_query_obs *o)
{
    (void)ctx;
    (void)c;
    fz_check_obs(o);
    FZ_ASSERT(o->kind == LK_Q_REQUEST); /* every http observation is one exchange */
    if (fz_is_s3)
        fz_check_s3_obs(s, o);
    if (s) {
        fz_read_bytes(s->database, strnlen(s->database, sizeof(s->database)));
        fz_read_bytes(s->user, strnlen(s->user, sizeof(s->user)));
    }
}

static void fz_on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    (void)ctx;
    (void)c;
    fz_read_bytes(s->database, strnlen(s->database, sizeof(s->database)));
    fz_read_bytes(s->user, strnlen(s->user, sizeof(s->user)));
    fz_read_bytes(s->app, strnlen(s->app, sizeof(s->app)));
    fz_read_bytes(s->server_version, strnlen(s->server_version, sizeof(s->server_version)));
    fz_byte_sink += s->complete;
}

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
    const struct lk_proto_ops *ops;
    struct lk_http_cfg cfg = {0};
    struct lk_proto *proto;
    struct fz_tee tee = {0};
    struct lk_reasm reasm;
    struct lk_conn_table *tbl;
    struct lk_conn *c;
    struct lk_tuple tuple = {0};
    __u32 lost = 0;
    __u32 len;

    /* The dialect selector (МS4): 0xFD cannot begin an HTTP start line, so a
     * corpus entry that does not carry it is an http input exactly as it was
     * before this branch existed, and one mutated byte turns any of them into
     * an S3 one. */
    fz_is_s3 = n && data[0] == 0xFD;
    if (fz_is_s3) {
        data++;
        n--;
    }
    len = n > LK_FUZZ_MAX_INPUT ? LK_FUZZ_MAX_INPUT : (__u32)n;
    ops = fz_is_s3 ? lk_proto_find("s3", 2) : lk_proto_find("http", 4);
    if (!ops)
        return 0;
    /* Alternate the one configurable read of a credential header (РH10) so the
     * base64 decoder is on the fuzzed path rather than only in unit tests. The
     * switch is derived from the input so a crash reproduces from the file. */
    cfg.user_basic = (n & 1) != 0;
    /* The same for the S3 knobs (РS3/РS4). A configured domain is what puts the
     * virtual-host branch on the fuzzed path — without it every request is read
     * path-style and the Host is never split — and `--s3-user off` is the
     * configuration in which the signature parser must not run at all. */
    if (fz_is_s3) {
        cfg.s3.domains[cfg.s3.ndomains++] = "s3.lktest";
        cfg.s3.domains[cfg.s3.ndomains++] = "minio.lktest";
        cfg.s3.no_user = (n & 2) != 0;
    }
    lk_proto_http_configure(&cfg);
    proto = ops->proto_new(&(struct lk_query_sink){
        .on_query = fz_on_query, .on_session = fz_on_session}); /* М3: observations */
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
    /* Force the selected framer/handler on every entry (else the PG default). */
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
