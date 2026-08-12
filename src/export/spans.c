// SPDX-License-Identifier: GPL-2.0
/* See spans.h. Sampling predicates + a bounded FIFO ring of copied spans. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* getrandom via sys/random */
#endif
#include "spans.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "norm_sql.h"
#include "proto.h" /* lk_query_sink, lk_query_obs, lk_conn, lk_session */

struct lk_spans {
    struct lk_spans_cfg cfg;
    struct lk_query_sink sink;

    uint64_t ratio_threshold; /* ratio * 2^64; UINT64_MAX means "always" */
    bool ratio_always;        /* ratio >= 1.0 */
    uint32_t text_max;
    uint64_t seed;     /* mixed into the sampling hash */
    uint64_t id_state; /* splitmix64 stream for trace/span ids */

    /* One contiguous text-store slab: slot i owns [i*text_max, (i+1)*text_max).
     * Allocated once, so the hot path never touches the allocator; RSS stays
     * lazy — only pages actually written by a span become resident. */
    char *text_arena;
    /* The HTTP attribute arena (РH11, М6), allocated on the first HTTP span and
     * never freed until teardown: an agent watching a web port keeps it, one
     * watching only databases never allocates it at all, and neither pays for
     * the other. Slot i belongs to ring slot i, exactly like the text arena. */
    struct lk_span_http *http_arena;
    struct lk_span ring[LK_SPAN_BUF];
    unsigned head, count; /* FIFO: pop at head, push at (head + count) % BUF */
    bool wm_fired;        /* 3/4 watermark fired since the last drain */

    uint64_t sampled_total, dropped_total;
};

/* splitmix64: a good-enough non-cryptographic mixer. Used both as a one-shot
 * hash (sampling) and as a counter-based PRNG stream (ids). */
static uint64_t splitmix64(uint64_t *x)
{
    uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);

    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static uint64_t mix64(uint64_t x)
{
    uint64_t s = x;

    return splitmix64(&s);
}

/* Fill n bytes from the id PRNG stream. */
static void id_fill(struct lk_spans *s, uint8_t *dst, size_t n)
{
    while (n) {
        uint64_t v = splitmix64(&s->id_state);
        size_t k = n < sizeof(v) ? n : sizeof(v);

        memcpy(dst, &v, k);
        dst += k;
        n -= k;
    }
}

/* Sampling decision (Р32, and РH11 for the trace context): probabilistic OR
 * slow, with an inherited decision overriding both. A query with no measurable
 * duration (missing completion — cancel/aborted) is never sampleable.
 *
 * The order matters and encodes the plan's rule. When the request arrived with a
 * valid `traceparent`, the caller has already decided whether this trace is
 * being recorded, and a server span that second-guesses that decision produces
 * the worst possible artefact: a trace with a hole in the middle where the
 * downstream hop should be. So a sampled trace is sampled here too — parent-
 * based sampling, as every OTel SDK does it — and an unsampled one is kept out
 * of the ratio draw entirely.
 *
 * The asymmetry: the *slow* predicate still fires on an unsampled trace. Its
 * whole purpose is "never lose the pathological ones", and an upstream sampler
 * that threw dice before the request was served could not have known this one
 * would take four seconds. Such a span joins a trace whose other spans were
 * dropped — a real cost, documented rather than papered over (РH11,
 * docs/notes-export.md).
 *
 * The consequence worth naming: once spans are enabled at all, a caller
 * sampling at 100 % makes this agent export a span per request whatever ratio
 * `--otlp-spans` set. That is what respecting the caller means; the ring bound
 * and its drop counter are what keep it from costing anything but visibility.
 * (Enabled "at all" is the operator's switch and is not overridden here: with
 * neither predicate configured the collector is never built, so no traceparent
 * can turn spans on.) */
static bool should_sample(struct lk_spans *s, const struct lk_conn *c, const struct lk_query_obs *o)
{
    const struct lk_http_obs *h = o->http;
    uint64_t dur, from = o->ts_start_ns;

    if (o->ts_complete_ns <= o->ts_start_ns)
        return false;
    /* РH5: for HTTP the *server's* interval starts where the request body ends,
     * so a gigabyte upload over a slow link is not a slow request. The span
     * still covers the whole exchange — only the predicate narrows. */
    if (h && o->ts_req_done_ns > from && o->ts_req_done_ns < o->ts_complete_ns)
        from = o->ts_req_done_ns;
    dur = o->ts_complete_ns - from;

    if (s->cfg.slow_ns && dur >= s->cfg.slow_ns)
        return true;
    if (h && h->trace_id)
        return (h->trace_flags & 0x01) != 0;
    if (s->ratio_always)
        return true;
    if (s->ratio_threshold) {
        uint64_t h2 = mix64(o->ts_start_ns * 0x9e3779b97f4a7c15ULL + c->cookie + s->seed);

        return h2 < s->ratio_threshold;
    }
    return false;
}

/* Copy the one variable-length value a span carries into its slot of the text
 * arena, bounded by text_max: db.query.text for a database span, url.path for an
 * HTTP one. NULL stays NULL on an empty copy — the encoder gates on it. */
static void store_text(struct lk_spans *s, struct lk_span *sp, const char *src, uint32_t slen)
{
    uint32_t n = slen > s->text_max ? s->text_max : slen;

    if (!src || !n)
        return;
    {
        char *dst = s->text_arena + (size_t)(sp - s->ring) * s->text_max;

        memcpy(dst, src, n);
        sp->text = dst;
        sp->text_len = n;
    }
}

/* db.system.name value plus enum kind pass-through are the encoder's job; here we
 * only capture what dangles after the callback. name = normalised prefix; text =
 * raw (or, masked, normalised) SQL bounded by text_max. */
static void fill_text_and_name(struct lk_spans *s, struct lk_span *sp, const struct lk_query_obs *o,
                               enum lk_sql_dialect dialect)
{
    struct lk_norm_out norm;

    sp->text = NULL;
    sp->text_len = 0;
    sp->name[0] = '\0';
    if (!o->text || (o->flags & LK_QO_NO_TEXT) || o->text_len == 0)
        return;

    lk_norm_sql(o->text, o->text_len, dialect, &norm);
    {
        uint32_t nn = norm.text_len < sizeof(sp->name) - 1 ? norm.text_len : sizeof(sp->name) - 1;

        memcpy(sp->name, norm.text, nn);
        sp->name[nn] = '\0';
    }

    store_text(s, sp, s->cfg.masked ? norm.text : o->text,
               s->cfg.masked ? norm.text_len : o->text_len);
}

/* Copy a bounded, non-NUL-terminated span into a fixed char[] as a C string. */
static void copy_n(char *dst, size_t cap, const char *src, uint32_t n)
{
    size_t k = n < cap - 1 ? n : cap - 1;

    if (src && k)
        memcpy(dst, src, k);
    else
        k = 0;
    dst[k] = '\0';
}

/* The HTTP half of a span (РH11). Returns false only when the arena cannot be
 * allocated, in which case the caller drops the span rather than exporting one
 * that claims HTTP semantics and carries none.
 *
 * Nothing here is read off the wire a second time: every value arrived on the
 * observation or the session, and the target already passed the РH12 redactor in
 * the handler — this function's whole job is to *copy* before the pointers
 * dangle. */
static bool fill_http(struct lk_spans *s, struct lk_span *sp, const struct lk_conn *c,
                      const struct lk_session *sess, const struct lk_query_obs *o)
{
    const struct lk_http_obs *h = o->http;
    struct lk_span_http *hs;

    if (!s->http_arena) {
        s->http_arena = malloc((size_t)LK_SPAN_BUF * sizeof(*s->http_arena));
        if (!s->http_arena)
            return false;
    }
    hs = &s->http_arena[sp - s->ring];
    memset(hs, 0, sizeof(*hs));
    sp->http = hs;
    sp->otel_kind = LK_OTEL_KIND_HTTP;

    if (o->op)
        snprintf(hs->method, sizeof(hs->method), "%s", o->op);
    copy_n(hs->route, sizeof(hs->route), o->route, o->route_len);
    snprintf(hs->host, sizeof(hs->host), "%s", sess->database);
    snprintf(hs->ua, sizeof(hs->ua), "%s", sess->app);
    /* `user.name` rather than `db.user`, and empty unless `--http-user basic`
     * asked for an identity — HTTP usually carries none, and РH12's rule is that
     * nothing leaves the wire unless it was requested. */
    snprintf(sp->user, sizeof(sp->user), "%s", sess->user);
    if (h->req_id)
        snprintf(hs->req_id, sizeof(hs->req_id), "%s", h->req_id);
    if (h->ctype)
        snprintf(hs->ctype, sizeof(hs->ctype), "%s", h->ctype);
    /* Carried whole or not at all (РH11): the handler already dropped an
     * oversized one, and clipping a list here would undo that decision. */
    if (h->tracestate && h->tracestate_len && h->tracestate_len < sizeof(hs->tstate))
        copy_n(hs->tstate, sizeof(hs->tstate), h->tracestate, h->tracestate_len);

    hs->status = o->err_code;
    hs->client_error = (o->flags & LK_QO_CLIENT_ERR) != 0;
    hs->bytes_in = o->bytes_in;
    hs->bytes_out = o->bytes_out;
    hs->req_done_ns = o->ts_req_done_ns;
    hs->first_byte_ns = o->ts_first_row_ns;
    hs->version = h->version;
    hs->tls = (c->flags & LK_CONN_TLS) != 0;
    /* The capture is server-side (РH2), so the *peer* of the connection is the
     * client. A lazily created entry has no tuple at all — then there is no
     * address to report and the attribute is simply absent. */
    if (c->tuple.family) {
        if (!inet_ntop(c->tuple.family, c->tuple.daddr, hs->client, sizeof(hs->client)))
            hs->client[0] = '\0';
        hs->client_port = c->tuple.dport;
        hs->server_port = c->tuple.sport;
    }

    /* The OTel name for a server span is `{method} {route}` — low-cardinality by
     * construction, since the route already is. No route (a CONNECT, or a head
     * we never read) leaves the method alone rather than inventing a path. */
    {
        size_t n = strlen(hs->method);

        if (n > sizeof(sp->name) - 1)
            n = sizeof(sp->name) - 1;
        memcpy(sp->name, hs->method, n);
        if (hs->route[0] && n + 1 < sizeof(sp->name)) {
            sp->name[n++] = ' ';
            copy_n(sp->name + n, sizeof(sp->name) - n, hs->route, (uint32_t)strlen(hs->route));
        } else {
            sp->name[n] = '\0';
        }
    }

    /* url.path is the specimen a person opens when a route looks slow, and the
     * one place a whole target leaves the agent. Two gates, both РH12: the
     * redactor has already replaced credential-shaped query values, and
     * `--otlp-span-masked` drops the path entirely — for HTTP "masked" can only
     * mean "the template and nothing else", since a URL has no literals to
     * collapse the way SQL does. */
    if (!s->cfg.masked && o->text && !(o->flags & LK_QO_NO_TEXT))
        store_text(s, sp, o->text, o->text_len);
    return true;
}

static void spans_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *sess,
                           const struct lk_query_obs *o)
{
    struct lk_spans *s = ctx;
    const struct lk_proto_ops *ops = lk_conn_proto(c);
    struct lk_span *sp;
    unsigned slot;

    if (!should_sample(s, c, o))
        return;

    s->sampled_total++;
    if (s->count >= LK_SPAN_BUF) {
        s->dropped_total++; /* ring full: drop the newest (Р32) */
        return;
    }
    slot = (s->head + s->count) % LK_SPAN_BUF;
    sp = &s->ring[slot];
    memset(sp, 0, sizeof(*sp));

    /* Ids (РH11). A request that arrived inside somebody else's trace keeps that
     * trace's id and points at the caller's span as its parent; the span id is
     * always ours, because this span is ours. Without a trace context — every
     * database observation, and any request whose `traceparent` was missing or
     * malformed — both ids are minted here, as they always were. */
    if (o->http && o->http->trace_id) {
        memcpy(sp->trace_id, o->http->trace_id, sizeof(sp->trace_id));
        memcpy(sp->parent_id, o->http->parent_id, sizeof(sp->parent_id));
        sp->have_parent = true;
    } else {
        id_fill(s, sp->trace_id, sizeof(sp->trace_id));
    }
    id_fill(s, sp->span_id, sizeof(sp->span_id));
    sp->start_ns = o->ts_start_ns;
    sp->end_ns = o->ts_complete_ns;
    sp->kind = o->kind;
    if (o->flags & LK_QO_ERROR) {
        sp->error = true;
        sp->err_code = o->err_code;
    }

    /* db.* attributes describe a database, and since РH11 not every protocol is
     * one. `otel_kind` is the switch: the HTTP path takes the semconv of a server
     * span and none of the db.* fields, and a PG or MySQL span reads exactly as
     * it did before М6 — the branch below is the whole difference. */
    if (ops->otel_kind == LK_OTEL_KIND_HTTP && o->http) {
        if (!fill_http(s, sp, c, sess, o)) {
            s->dropped_total++; /* no arena: an HTTP span with no attributes is
                                   not worth exporting */
            return;
        }
    } else {
        if (o->rows || !(o->flags & (LK_QO_ERROR | LK_QO_EMPTY))) {
            sp->rows = o->rows;
            sp->have_rows = true;
        }
        if (o->flags & LK_QO_ERROR)
            snprintf(sp->sqlstate, sizeof(sp->sqlstate), "%s", o->sqlstate);
        sp->db_system = ops->otel_kind == LK_OTEL_KIND_DB ? ops->db_system : NULL;
        snprintf(sp->db, sizeof(sp->db), "%s", sess->database);
        snprintf(sp->user, sizeof(sp->user), "%s", sess->user);
        fill_text_and_name(s, sp, o, ops->sql_dialect);
    }

    s->count++;
    if (!s->wm_fired && s->count >= (LK_SPAN_BUF * 3) / 4) {
        s->wm_fired = true;
        if (s->cfg.on_watermark)
            s->cfg.on_watermark(s->cfg.watermark_ctx);
    }
}

struct lk_spans *lk_spans_new(const struct lk_spans_cfg *cfg)
{
    struct lk_spans *s = calloc(1, sizeof(*s));

    if (!s)
        return NULL;
    s->cfg = *cfg;
    s->text_max = cfg->text_max ? cfg->text_max : LK_SPAN_TEXT_MAX_DEF;

    /* One slab for all slots. Virtual size is LK_SPAN_BUF * text_max, but the
     * kernel backs only the pages a span actually writes, so RSS tracks real
     * query sizes, not the cap (Р11 spirit: small steady-state memory). */
    s->text_arena = malloc((size_t)LK_SPAN_BUF * s->text_max);
    if (!s->text_arena) {
        free(s);
        return NULL;
    }

    if (cfg->sample_ratio >= 1.0) {
        s->ratio_always = true;
    } else if (cfg->sample_ratio > 0.0) {
        /* ratio * 2^64, kept in the uint64 domain the hash compares against. */
        s->ratio_threshold = (uint64_t)(cfg->sample_ratio * 18446744073709551616.0);
    }

    s->seed = cfg->seed;
    s->id_state = cfg->seed;
    if (!cfg->seed) {
        uint64_t r[2] = {0, 0};

        /* Best effort: a failed getrandom leaves the seed weakly time-derived,
         * still fine for non-cryptographic ids. */
        if (getrandom(r, sizeof(r), 0) != (ssize_t)sizeof(r))
            r[0] = (uint64_t)(uintptr_t)s ^ 0x243f6a8885a308d3ULL;
        s->seed = r[0];
        s->id_state = r[1] ? r[1] : (r[0] ^ 0x9e3779b97f4a7c15ULL);
    }

    s->sink = (struct lk_query_sink){.ctx = s, .on_query = spans_on_query};
    return s;
}

void lk_spans_free(struct lk_spans *s)
{
    if (!s)
        return;
    free(s->text_arena);
    free(s->http_arena);
    free(s);
}

const struct lk_query_sink *lk_spans_sink(struct lk_spans *s)
{
    return &s->sink;
}

void lk_spans_drain(struct lk_spans *s, void (*emit)(void *ctx, const struct lk_span *sp),
                    void *ctx)
{
    while (s->count) {
        struct lk_span *sp = &s->ring[s->head];

        if (emit)
            emit(ctx, sp);
        sp->text = NULL; /* text lives in the arena; refill memsets the slot */
        s->head = (s->head + 1) % LK_SPAN_BUF;
        s->count--;
    }
    s->head = 0;
    s->wm_fired = false;
}

uint64_t lk_spans_sampled_total(const struct lk_spans *s)
{
    return s->sampled_total;
}

uint64_t lk_spans_dropped_total(const struct lk_spans *s)
{
    return s->dropped_total;
}

unsigned lk_spans_queued(const struct lk_spans *s)
{
    return s->count;
}
