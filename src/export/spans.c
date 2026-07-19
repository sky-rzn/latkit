// SPDX-License-Identifier: GPL-2.0
/* See spans.h. Sampling predicates + a bounded FIFO ring of copied spans. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* getrandom via sys/random */
#endif
#include "spans.h"

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

/* Sampling decision (Р32): probabilistic OR slow. A query with no measurable
 * duration (missing completion — cancel/aborted) is never sampleable. */
static bool should_sample(struct lk_spans *s, const struct lk_conn *c, const struct lk_query_obs *o)
{
    uint64_t dur;

    if (o->ts_complete_ns <= o->ts_start_ns)
        return false;
    dur = o->ts_complete_ns - o->ts_start_ns;

    if (s->cfg.slow_ns && dur >= s->cfg.slow_ns)
        return true;
    if (s->ratio_always)
        return true;
    if (s->ratio_threshold) {
        uint64_t h = mix64(o->ts_start_ns * 0x9e3779b97f4a7c15ULL + c->cookie + s->seed);

        return h < s->ratio_threshold;
    }
    return false;
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

    {
        const char *src = s->cfg.masked ? norm.text : o->text;
        uint32_t slen = s->cfg.masked ? norm.text_len : o->text_len;
        uint32_t n = slen > s->text_max ? s->text_max : slen;

        if (n) {
            char *dst = s->text_arena + (size_t)(sp - s->ring) * s->text_max;

            memcpy(dst, src, n);
            sp->text = dst; /* NULL stays NULL on n==0: the encoder gates on it */
            sp->text_len = n;
        }
    }
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

    id_fill(s, sp->trace_id, sizeof(sp->trace_id));
    id_fill(s, sp->span_id, sizeof(sp->span_id));
    sp->start_ns = o->ts_start_ns;
    sp->end_ns = o->ts_complete_ns;
    sp->kind = o->kind;
    if (o->rows || !(o->flags & (LK_QO_ERROR | LK_QO_EMPTY))) {
        sp->rows = o->rows;
        sp->have_rows = true;
    }
    if (o->flags & LK_QO_ERROR) {
        sp->error = true;
        snprintf(sp->sqlstate, sizeof(sp->sqlstate), "%s", o->sqlstate);
        sp->err_code = o->err_code;
    }
    sp->db_system = ops->db_system;
    snprintf(sp->db, sizeof(sp->db), "%s", sess->database);
    snprintf(sp->user, sizeof(sp->user), "%s", sess->user);
    fill_text_and_name(s, sp, o, ops->sql_dialect);

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
