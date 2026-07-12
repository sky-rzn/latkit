/* SPDX-License-Identifier: GPL-2.0 */
/* Shared by pgstream and tlspipe (task 8.4, Р52): turns the fixture traces of
 * tests/replay/fixtures_gen.c into per-connection byte scripts that replay
 * over a REAL socket. The fixtures already are the single source of truth for
 * PG wire bytes and their expected parse results; here each trace is reduced
 * to its ordered {dir, len} ops plus a flat payload buffer, and the trace-level
 * expectations (sessions/queries/errors) are summed so the smoke test can
 * assert exact counts against the agent's metrics.
 *
 * A fixture is replayable only when its trace is a CLEAN capture: fixtures
 * that model capture pathology — seq holes (session_gap), a synthetic
 * mid-session join, decrypted uprobe events (ssl_tls), truncation — describe
 * how events were lost or sourced, not what travelled the wire, and cannot be
 * reproduced by writing bytes into a healthy socket. They are filtered out
 * here by inspecting the trace itself (flags/resyncs), not by name, so a new
 * fixture is picked up automatically iff it is clean.
 *
 * Header-only (static functions): two small test tools, no library worth it. */
#ifndef LATKIT_KERNEL_FIXTURE_STREAM_H
#define LATKIT_KERNEL_FIXTURE_STREAM_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../replay/fixtures_gen.h"
#include "latkit.h"
#include "reassembly.h" /* LK_PG_SSL_REQUEST */
#include "record.h"

#define KS_MAX_OPS     64
#define KS_MAX_STREAMS 16

struct ks_op {
    __u8 dir;   /* enum lk_dir: RECV = client writes, SEND = server writes */
    __u32 len;  /* payload bytes of this send/recv call */
    size_t off; /* offset into ks_stream.bytes */
};

struct ks_stream {
    const char *name; /* fixture name, for logging */
    __u8 *bytes;      /* all op payloads concatenated in trace order (malloc) */
    size_t nbytes;
    struct ks_op ops[KS_MAX_OPS];
    size_t nops;
    /* Expectations of this one connection, from the fixture builder. */
    __u64 sessions, queries, errors;
};

/* lk_replay_mem callback state: collect ops, veto on any pathology marker. */
struct ks_extract {
    struct ks_stream *s;
    bool reject;
    bool starts_sslreq; /* first client bytes are an SSLRequest */
};

static int ks_on_record(void *ctx, const void *data, __u32 size)
{
    struct ks_extract *e = ctx;
    const struct lk_ev_hdr *h = data;
    const struct lk_ev_data *d = data;

    if (size < sizeof(*h))
        return (e->reject = true), 1;

    switch (h->type) {
    case LK_EV_CONN_OPEN:
        if (h->flags & LK_F_SYNTHETIC)
            return (e->reject = true), 1;
        return 0;
    case LK_EV_CONN_CLOSE:
        return 0;
    case LK_EV_DATA:
        break;
    default:
        return (e->reject = true), 1;
    }

    /* Decrypted events come from uprobes, gaps/truncation from losses and
     * budgets — none of them is producible by writing into a live socket. */
    if (h->flags & (LK_F_DECRYPTED | LK_F_GAP | LK_F_TRUNC))
        return (e->reject = true), 1;
    if (size < sizeof(*d) || d->cap_len != d->total_len || d->cap_len == 0)
        return (e->reject = true), 1;

    if (e->s->nops == KS_MAX_OPS)
        return (e->reject = true), 1;

    if (e->s->nops == 0 && d->hdr.dir == LK_DIR_RECV && d->cap_len >= 8) {
        const __u8 *p = d->payload;
        __u32 code = (__u32)p[4] << 24 | (__u32)p[5] << 16 | (__u32)p[6] << 8 | p[7];

        e->starts_sslreq = code == LK_PG_SSL_REQUEST;
    }

    e->s->bytes = realloc(e->s->bytes, e->s->nbytes + d->cap_len);
    if (!e->s->bytes)
        return (e->reject = true), 1;
    memcpy(e->s->bytes + e->s->nbytes, d->payload, d->cap_len);
    e->s->ops[e->s->nops++] = (struct ks_op){
        .dir = d->hdr.dir,
        .len = d->cap_len,
        .off = e->s->nbytes,
    };
    e->s->nbytes += d->cap_len;
    return 0;
}

/* Extract every replayable fixture into out[]; returns the count. With
 * `tls_mode` the SSLRequest-opening fixtures are also skipped: tlspipe issues
 * its own SSLRequest/'S' prelude before the handshake, so the replayed stream
 * must start at the (in-TLS) StartupMessage, like a real libpq session. */
static size_t ks_extract_all(bool tls_mode, struct ks_stream *out, size_t max)
{
    size_t n = 0;

    for (size_t i = 0; i < lk_nfixtures && n < max; i++) {
        struct fx x = {0};
        struct ks_stream *s = &out[n];
        struct ks_extract e = {.s = s};

        memset(s, 0, sizeof(*s));
        s->name = lk_fixtures[i].name;
        lk_fixtures[i].build(&x);

        if (x.resyncs || x.tls_conns || !x.clean)
            e.reject = true;
        else
            lk_replay_mem(x.buf, x.len, ks_on_record, &e);
        if (tls_mode && e.starts_sslreq)
            e.reject = true;

        free(x.buf);
        if (e.reject || s->nops == 0) {
            free(s->bytes);
            memset(s, 0, sizeof(*s));
            continue;
        }
        s->sessions = x.sessions;
        s->queries = x.queries;
        s->errors = x.errors_sql;
        n++;
    }
    return n;
}

/* One summary line both tools print; tests/kernel/smoke.sh parses it and
 * asserts the agent's metrics against these exact numbers. */
static void ks_print_summary(const char *tool, size_t conns, const struct ks_stream *ss, size_t n,
                             int repeat)
{
    __u64 q = 0, sess = 0, err = 0;

    for (size_t i = 0; i < n; i++) {
        q += ss[i].queries;
        sess += ss[i].sessions;
        err += ss[i].errors;
    }
    printf("%s: done conns=%zu queries=%llu sessions=%llu errors=%llu\n", tool, conns,
           (unsigned long long)(q * repeat), (unsigned long long)(sess * repeat),
           (unsigned long long)(err * repeat));
}

#endif /* LATKIT_KERNEL_FIXTURE_STREAM_H */
