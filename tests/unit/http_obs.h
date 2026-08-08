/* SPDX-License-Identifier: GPL-2.0 */
/* Shared harness for the three HTTP handler test binaries (PLAN-HTTP.md М3):
 * test_http_req.c, test_http_resp.c and test_http_unit.c. It wires the real
 * production chain — bytes → stream framer (http_frame.c) → lk_msg → handler
 * (http.c/http_req.c/http_resp.c) → lk_query_obs — and captures what comes out
 * the top, so a test asserts on *observations*, which is what М3 delivers, not
 * on the framer's message stream, which test_http_frame.c already covers.
 *
 * Every test therefore feeds bytes exactly as a capture event would deliver
 * them, holes included: a handler bug that only shows up when a head arrives in
 * two pieces is a bug the corpus will find, so the harness must be able to
 * reproduce it here first. */
#ifndef LATKIT_TEST_HTTP_OBS_H
#define LATKIT_TEST_HTTP_OBS_H

#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"
#include "reassembly.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

#define H_MAX_OBS 64

/* One captured observation. Everything is copied: lk_query_obs borrows its
 * strings for the duration of the callback, and a test that peeked at them
 * afterwards would be testing the allocator. */
struct h_obs {
    __u64 ts_start, ts_req_done, ts_first_row, ts_complete, ts_ready;
    __u64 bytes_in, bytes_out;
    __u16 status, flags;
    __u8 kind;
    char method[16];
    char target[512];
    __u32 target_len;
    char host[64], user[64], app[64], ver[16];
};

struct h_sess {
    char host[64], user[64], app[64], ver[16];
    bool complete;
};

static struct h_obs h_obs[H_MAX_OBS];
static struct h_sess h_sess[H_MAX_OBS];
static int h_nobs, h_nsess;

static struct lk_reasm h_reasm;
static struct lk_conn h_conn;
static struct lk_proto *h_proto;

static inline void h_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                              const struct lk_query_obs *o)
{
    struct h_obs *r = &h_obs[h_nobs % H_MAX_OBS];
    __u32 n = o->text_len < sizeof(r->target) - 1 ? o->text_len : (__u32)sizeof(r->target) - 1;

    (void)ctx;
    (void)c;
    h_nobs++;
    memset(r, 0, sizeof(*r));
    r->ts_start = o->ts_start_ns;
    r->ts_req_done = o->ts_req_done_ns;
    r->ts_first_row = o->ts_first_row_ns;
    r->ts_complete = o->ts_complete_ns;
    r->ts_ready = o->ts_ready_ns;
    r->bytes_in = o->bytes_in;
    r->bytes_out = o->bytes_out;
    r->status = o->err_code;
    r->flags = o->flags;
    r->kind = o->kind;
    snprintf(r->method, sizeof(r->method), "%s", o->op ? o->op : "");
    if (o->text && n)
        memcpy(r->target, o->text, n);
    r->target_len = o->text_len;
    snprintf(r->host, sizeof(r->host), "%s", s->database);
    snprintf(r->user, sizeof(r->user), "%s", s->user);
    snprintf(r->app, sizeof(r->app), "%s", s->app);
    snprintf(r->ver, sizeof(r->ver), "%s", s->server_version);
}

static inline void h_on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    struct h_sess *r = &h_sess[h_nsess % H_MAX_OBS];

    (void)ctx;
    (void)c;
    h_nsess++;
    memset(r, 0, sizeof(*r));
    snprintf(r->host, sizeof(r->host), "%s", s->database);
    snprintf(r->user, sizeof(r->user), "%s", s->user);
    snprintf(r->app, sizeof(r->app), "%s", s->app);
    snprintf(r->ver, sizeof(r->ver), "%s", s->server_version);
    r->complete = s->complete;
}

static inline void h_free(void)
{
    const struct lk_msg_sink *sink;

    if (h_proto) {
        /* The live path fires this from the connection table on every removal
         * path; here the test drives it, so proto_state is released down the
         * same code the agent runs (Р15). */
        sink = lk_proto_sink(h_proto);
        if (sink->on_conn_close)
            sink->on_conn_close(sink->ctx, &h_conn);
        lk_proto_free(h_proto);
        h_proto = NULL;
    }
    free(h_conn.frame[0].buf);
    free(h_conn.frame[1].buf);
    free(h_conn.frame_state); /* the conn table does this in the live path */
    lk_reasm_free(&h_reasm);
}

/* Start a fresh connection. `flags` seeds lk_conn.flags — LK_CONN_SYNTHETIC is
 * how a test says "we joined this connection mid-stream". */
static inline void h_reset_flags(__u16 flags)
{
    static const struct lk_query_sink qsink = {.on_query = h_on_query, .on_session = h_on_session};

    h_free();
    memset(&h_conn, 0, sizeof(h_conn));
    h_conn.ops = &lk_proto_http_ops;
    h_conn.flags = flags;
    h_conn.cookie = 0x1234;
    if (flags & LK_CONN_SYNTHETIC) {
        /* What the connection table does for a synthetic entry: startup was not
         * seen, so framing can only enter through a resync (Р10). Reproduced
         * here so "joined mid-stream" means the same thing in a test as it does
         * on the live path. */
        h_conn.frame[0].st = LK_FR_DIRTY;
        h_conn.frame[1].st = LK_FR_DIRTY;
    }
    h_proto = lk_proto_http_new(&qsink);
    lk_reasm_init(&h_reasm, lk_proto_sink(h_proto));
    h_nobs = 0;
    h_nsess = 0;
}

static inline void h_reset(void)
{
    h_reset_flags(0);
}

/* One data event, modelled by off/total exactly as the agent's capture does, so
 * an under-captured call leaves the same lazy tail here as in production. */
static inline void h_feed(enum lk_dir dir, __u32 total, __u32 off, const void *p, __u32 cap,
                          __u64 ts)
{
    static union {
        struct lk_ev_data d;
        __u8 raw[sizeof(struct lk_ev_data) + 65536];
    } u;

    memset(&u.d, 0, sizeof(u.d));
    u.d.hdr.ts_ns = ts;
    u.d.hdr.dir = dir;
    u.d.total_len = total;
    u.d.off = off;
    u.d.cap_len = cap;
    if (cap)
        memcpy(u.d.payload, p, cap);
    lk_reasm_data(&h_reasm, &h_conn, dir, &u.d, cap);
}

/* A whole syscall's worth of bytes, fully captured — the common shape. */
static inline void h_call(enum lk_dir dir, const char *s, __u64 ts)
{
    h_feed(dir, (__u32)strlen(s), 0, s, (__u32)strlen(s), ts);
}

static inline void h_bytes(enum lk_dir dir, const void *p, __u32 n, __u64 ts)
{
    h_feed(dir, n, 0, p, n, ts);
}

/* Bytes we will never see. */
static inline void h_hole(enum lk_dir dir, __u64 n)
{
    lk_frame_hole(&h_reasm, &h_conn, dir, n);
}

/* The connection ends. Drives the handler's close hook the way the connection
 * table does, with last_activity_ns as the close timestamp — which is what a
 * rule-6 body's ts_complete becomes. */
static inline void h_close(__u64 ts)
{
    const struct lk_msg_sink *sink = lk_proto_sink(h_proto);

    h_conn.last_activity_ns = ts;
    if (sink->on_conn_close)
        sink->on_conn_close(sink->ctx, &h_conn);
}

static inline const struct lk_proto_stats *h_stats(void)
{
    return lk_proto_stats(h_proto);
}

/* Send a request head and, right after it, a response — the shape most tests
 * only need as a backdrop for the one thing they are actually checking. */
static inline int h_target_is(int i, const char *want)
{
    if (i >= h_nobs) {
        fprintf(stderr, "FAIL: no observation #%d (have %d)\n", i, h_nobs);
        return 0;
    }
    if (h_obs[i].target_len != strlen(want) || memcmp(h_obs[i].target, want, strlen(want))) {
        fprintf(stderr, "FAIL: obs #%d target is '%.*s', want '%s'\n", i, (int)h_obs[i].target_len,
                h_obs[i].target, want);
        return 0;
    }
    return 1;
}

#endif /* LATKIT_TEST_HTTP_OBS_H */
