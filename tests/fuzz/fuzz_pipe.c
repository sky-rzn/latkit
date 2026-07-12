// SPDX-License-Identifier: GPL-2.0
/* Structural whole-pipeline libFuzzer target (task 8.3, Р51).
 *
 * fuzz_pg drives bytes through one clean connection; this target drives the
 * *event* dimension the ringbuf really has: multiple connections, lost events
 * (seq gaps), capture holes, synthetic and lazily-created entries, the TLS
 * flip and the decrypted channel, LRU/idle eviction, and raw corrupt records
 * into decode. The input is interpreted as a scenario (fuzz_pipe_ops.h) and
 * replayed through the exact production stack — lk_pipeline_feed (decode +
 * conn_table + framer) into the PG handler, the same wiring events.c and the
 * replay harness use — because the historically fragile bugs live between the
 * modules (resync after holes Р10/Р19, startup phase, Р38 routing), not
 * inside them.
 *
 * Invariants (Р51) checked on every callback, not just "no crash":
 *   - every message satisfies the framer contract (fuzz_invariants.h);
 *   - Р19 end-to-end: after a detected loss on a connection, the next message
 *     a direction emits MUST carry LK_MSG_AFTER_RESYNC — the framer never
 *     emits through a hole. The harness tracks per-slot "loss pending" marks
 *     from lk_pipeline_ev outcomes (lost counts, lazy dirty creation,
 *     synthetic opens) and clears them on the TLS flip, which legitimately
 *     resets framing to a fresh startup (Р36). The check is one-sided: a
 *     dirtying the harness cannot see (off-anomaly inside the framer) simply
 *     yields an unasserted AFTER_RESYNC.
 *   - every observation is well-formed, and its text normalises stably
 *     (fingerprint is a pure function of the bytes) — the same lk_norm_sql
 *     call the aggregator makes on this text.
 *
 * The connection table is deliberately tiny (16 entries) so the fuzzer reaches
 * the LRU-ceiling recycling path (Р12) with a few fresh-cookie opens.
 *
 * Built only in the -DLATKIT_FUZZ=ON profile; corpus in tests/fuzz/corpus/pipe/
 * (seeds written by gen_seeds, minimised by the campaign). */
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "conn_table.h"
#include "decode.h"
#include "fuzz_invariants.h"
#include "fuzz_pipe_ops.h"
#include "latkit.h"
#include "pipeline.h"
#include "proto.h"

#define PIPE_MAX_CONNS   16 /* small on purpose: the LRU ceiling is reachable */
#define PIPE_IDLE_NS     (600ull * 1000000000ull)
#define PIPE_COOKIE_BASE 0xC0000000ull
#define PIPE_COOKIE_STEP 0x01000000ull /* per slot; generations bump by 0x100 */

struct pipe_slot {
    __u64 cookie;
    __u32 seq;     /* socket-path seq space (kernel counter mirror) */
    __u32 tls_seq; /* decrypted-channel seq space (Р38) */
    bool mark[2];  /* per dir: loss seen — next message must be AFTER_RESYNC */
};

struct pipe_ctx {
    struct lk_pipeline pipe;
    struct lk_proto *proto;
    const struct lk_msg_sink *psink; /* = lk_proto_sink(proto) */
    struct pipe_slot slot[PIPE_SLOTS];
    __u64 now;
};

static struct pipe_slot *slot_of(struct pipe_ctx *px, __u64 cookie)
{
    for (int i = 0; i < PIPE_SLOTS; i++)
        if (px->slot[i].cookie == cookie)
            return &px->slot[i];
    return NULL; /* RAW-conjured cookie or a dead generation: not tracked */
}

/* --- sinks: Р51 invariants + tee into the PG handler ---------------------- */

static void pipe_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct pipe_ctx *px = ctx;
    struct pipe_slot *s = slot_of(px, c->cookie);

    fz_check_msg(m);
    /* Р19: nothing is emitted across a loss — the first message after it must
     * announce the resync. The len==0 one-byte SSL reply bypasses framing
     * (cross-direction flag, Р10) and is exempt. */
    if (s && m->len > 0) {
        if (s->mark[dir])
            FZ_ASSERT(m->flags & LK_MSG_AFTER_RESYNC);
        s->mark[dir] = false;
    }
    if (px->psink->on_msg)
        px->psink->on_msg(px->psink->ctx, c, dir, m);
}

static void pipe_on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    struct pipe_ctx *px = ctx;

    if (px->psink->on_resync)
        px->psink->on_resync(px->psink->ctx, c, dir);
}

/* Fired by the pipeline for every removal path (CLOSE, LRU, sweep, teardown):
 * forward so the parser frees proto_state (Р15). */
static void pipe_on_conn_close(void *ctx, struct lk_conn *c)
{
    struct pipe_ctx *px = ctx;

    if (px->psink->on_conn_close)
        px->psink->on_conn_close(px->psink->ctx, c);
}

static void pipe_on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                          const struct lk_query_obs *o)
{
    (void)ctx;
    (void)c;
    fz_check_obs(o);
    /* The aggregator's next step over live traffic: normalise the text. The
     * stability check makes the fingerprint contract part of this target. */
    if (o->text)
        fz_check_norm_stable(o->text, o->text_len);
    if (s)
        fz_read_bytes(s->user, strnlen(s->user, sizeof(s->user)));
}

static void pipe_on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    (void)ctx;
    (void)c;
    fz_read_bytes(s->user, strnlen(s->user, sizeof(s->user)));
    fz_read_bytes(s->database, strnlen(s->database, sizeof(s->database)));
    fz_read_bytes(s->app, strnlen(s->app, sizeof(s->app)));
}

static void pipe_on_txn(void *ctx, const struct lk_conn *c, __u64 start_ns, __u64 end_ns,
                        char final_status)
{
    (void)ctx;
    (void)c;
    fz_byte_sink += start_ns ^ end_ns ^ (unsigned char)final_status;
}

/* --- scenario reader (saturating: missing bytes read as 0) ----------------- */

struct rd {
    const uint8_t *p, *end;
};

static uint32_t rd_u8(struct rd *r)
{
    return r->p < r->end ? *r->p++ : 0;
}

static uint32_t rd_take(struct rd *r, const uint8_t **out, uint32_t want)
{
    uint32_t avail = (uint32_t)(r->end - r->p);
    uint32_t n = want < avail ? want : avail;

    *out = r->p;
    r->p += n;
    return n;
}

/* --- event feeding + loss bookkeeping -------------------------------------- */

/* Loss-mark bookkeeping. The framer emits messages DURING lk_pipeline_feed —
 * a dirty direction can resync and emit its flagged message inside the very
 * feed that caused the loss — so anything a DATA event can dirty must be
 * marked BEFORE the feed (a post-feed mark would blame the next, legitimately
 * clean message: the campaign found exactly that harness race). Marking
 * pre-feed means predicting what the table will decide, mirroring touch()/
 * touch_tls()/lazy-create from conn_table.c:
 *   - unknown cookie: the entry is lazily created dirty (Р12);
 *   - decrypted event: gap check in the tls seq space, once seeded (Р38);
 *   - plaintext event on a non-TLS conn: gap check in the raw seq space;
 *   - plaintext event on a TLS conn: dropped before the detector — no mark.
 * Under-marking is safe (the check just does not fire); over-marking is a
 * false positive. */
static void mark_data_pre(struct pipe_ctx *px, struct pipe_slot *s, const struct lk_ev_view *v)
{
    const struct lk_conn *c = lk_conn_table_peek(px->pipe.conns, s->cookie);
    __u32 seq = v->hdr->seq;
    bool gap;

    if (!c) {
        s->mark[0] = s->mark[1] = true; /* lazily created: born dirty */
        return;
    }
    if (v->hdr->flags & LK_F_DECRYPTED)
        gap = c->tls_seq_seen && seq > c->tls_last_seq + 1;
    else if (!(c->flags & LK_CONN_TLS))
        gap = seq > c->last_seq + 1;
    else
        gap = false; /* ciphertext on a TLS conn: dropped, never dirties */
    if (gap)
        s->mark[0] = s->mark[1] = true;
}

/* CONN events emit no messages during their feed, so their effects are safely
 * accounted after it; the TLS flip clears the marks — framing was reset to a
 * fresh startup (Р36). */
static void account_post(struct pipe_slot *s, const struct lk_pipeline_ev *out, bool existed)
{
    if (!s)
        return;
    if (out->status == LK_DEC_CONN) {
        if (out->lost)
            s->mark[0] = s->mark[1] = true;
        if (out->view.hdr->type == LK_EV_CONN_OPEN && !existed)
            s->mark[0] = s->mark[1] = (out->view.hdr->flags & LK_F_SYNTHETIC) != 0;
        if (out->view.hdr->type == LK_EV_CONN_CLOSE)
            s->mark[0] = s->mark[1] = false; /* entry gone; recreation re-marks */
    }
    if (out->tls_now)
        s->mark[0] = s->mark[1] = false;
}

static void feed(struct pipe_ctx *px, const void *rec, size_t sz)
{
    struct lk_ev_view v;
    struct lk_pipeline_ev out;
    struct pipe_slot *s = NULL;
    bool existed = false;
    enum lk_decode_status st;

    /* Pre-decode to learn the cookie and event type (RAW records carry
     * arbitrary ones): DATA effects must be marked before the feed. */
    st = lk_ev_decode(rec, sz, &v);
    if (st != LK_DEC_SHORT && v.hdr) {
        s = slot_of(px, v.hdr->conn_id);
        if (s) {
            existed = lk_conn_table_peek(px->pipe.conns, s->cookie) != NULL;
            if (st == LK_DEC_DATA)
                mark_data_pre(px, s, &v);
        }
    }
    lk_pipeline_feed(&px->pipe, rec, sz, &out);
    account_post(s, &out, existed);
}

/* Aligned scratch for building records; raw[] covers the largest DATA event. */
union rec_buf {
    struct lk_ev_conn conn;
    struct lk_ev_hdr hdr;
    __u8 raw[sizeof(struct lk_ev_data) + PIPE_DATA_MAX];
};

static void op_conn(struct pipe_ctx *px, int sloti, uint32_t arg, bool open)
{
    struct pipe_slot *s = &px->slot[sloti];
    union rec_buf rb;
    struct lk_ev_conn *ev = &rb.conn;
    bool gap = open ? (arg & PIPE_OPEN_GAP) : (arg & PIPE_CLOSE_GAP);

    if (open && (arg & PIPE_OPEN_FRESH)) {
        /* New generation: the previous entry (if any) is left behind for the
         * LRU ceiling or the idle sweep to collect — the leak-insurance paths. */
        s->cookie += 0x100;
        s->seq = 0;
        s->tls_seq = 0;
        s->mark[0] = s->mark[1] = false;
    }
    s->seq += gap ? 3 : 1;
    px->now += 1000;

    memset(ev, 0, sizeof(*ev));
    ev->hdr.conn_id = s->cookie;
    ev->hdr.ts_ns = px->now;
    ev->hdr.seq = s->seq;
    ev->hdr.type = open ? LK_EV_CONN_OPEN : LK_EV_CONN_CLOSE;
    if (open && (arg & PIPE_OPEN_SYNTHETIC))
        ev->hdr.flags |= LK_F_SYNTHETIC;
    ev->tuple.family = 2 /* AF_INET */;
    ev->tuple.dport = 5432;
    ev->tuple.sport = (__u16)(40000 + sloti);
    feed(px, ev, sizeof(*ev));
}

static void op_data(struct pipe_ctx *px, int sloti, uint32_t arg, enum lk_dir dir, struct rd *r)
{
    static const __u32 tail_bytes[4] = {0, 1, 64, 4096};
    struct pipe_slot *s = &px->slot[sloti];
    union rec_buf rb;
    struct lk_ev_data *ev = (struct lk_ev_data *)rb.raw;
    uint32_t meta = rd_u8(r);
    uint32_t want = ((arg & 7) << 8) | rd_u8(r);
    const uint8_t *payload;
    __u32 cap = rd_take(r, &payload, want);
    __u32 tail = tail_bytes[(meta >> 2) & 3];
    __u32 off = 0, total = cap + tail;
    bool decrypted = meta & PIPE_DATA_DECRYPTED;
    struct lk_conn *c = lk_conn_table_peek(px->pipe.conns, s->cookie);
    __u32 call_pos = c ? c->frame[dir].call_pos : 0;
    __u32 call_total = c ? c->frame[dir].call_total : 0;

    switch ((meta >> 4) & 3) {
    case PIPE_SHAPE_NEW_TAIL:
        break; /* off=0, total = cap+tail */
    case PIPE_SHAPE_CONT:
        /* Continue the call in progress (message torn across events) or fall
         * back to a clean exact call. */
        if (call_total > call_pos) {
            off = call_pos;
            total = call_total;
            if (cap > call_total - off)
                cap = call_total - off;
        } else {
            total = cap;
        }
        break;
    case PIPE_SHAPE_CONT_HOLE:
        /* Continuation that skips `tail` bytes: an intra-call hole (Р9). */
        if (call_total > call_pos + tail) {
            off = call_pos + tail;
            total = call_total;
            if (cap > call_total - off)
                cap = call_total - off;
        }
        break;
    case PIPE_SHAPE_ANOMALY:
        /* Deliberately incoherent off: backwards / past total_len debris. */
        off = (want << 3) | 1;
        total = cap;
        break;
    }

    if (decrypted)
        s->tls_seq += (meta & PIPE_DATA_GAP) ? 3 : 1;
    else
        s->seq += (meta & PIPE_DATA_GAP) ? 3 : 1;
    px->now += 1000;

    memset(ev, 0, sizeof(*ev));
    ev->hdr.conn_id = s->cookie;
    ev->hdr.ts_ns = px->now;
    ev->hdr.seq = decrypted ? s->tls_seq : s->seq;
    ev->hdr.type = LK_EV_DATA;
    ev->hdr.dir = (__u8)dir;
    if (decrypted)
        ev->hdr.flags |= LK_F_DECRYPTED;
    if (tail)
        ev->hdr.flags |= LK_F_TRUNC;
    ev->total_len = total;
    ev->off = off;
    ev->cap_len = cap;
    memcpy(ev->payload, payload, cap);
    feed(px, ev, sizeof(*ev) + cap);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct pipe_ctx px;
    struct rd r = {data, data + size};
    struct lk_query_sink qsink = {
        .ctx = &px,
        .on_query = pipe_on_query,
        .on_session = pipe_on_session,
        .on_txn = pipe_on_txn,
    };

    memset(&px, 0, sizeof(px));
    px.now = 1000000;
    for (int i = 0; i < PIPE_SLOTS; i++)
        px.slot[i].cookie = PIPE_COOKIE_BASE + (__u64)i * PIPE_COOKIE_STEP;

    px.proto = lk_proto_pg_new(&qsink);
    if (!px.proto)
        return 0;
    px.psink = lk_proto_sink(px.proto);
    if (lk_pipeline_init(&px.pipe, PIPE_MAX_CONNS, PIPE_IDLE_NS,
                         &(struct lk_msg_sink){.ctx = &px,
                                               .on_msg = pipe_on_msg,
                                               .on_resync = pipe_on_resync,
                                               .on_conn_close = pipe_on_conn_close})) {
        lk_proto_free(px.proto);
        return 0;
    }

    while (r.p < r.end) {
        uint32_t op = rd_u8(&r);
        int sloti = op & 3;
        uint32_t arg = (op >> 5) & 7;

        switch ((op >> 2) & 7) {
        case PIPE_OP_OPEN:
            op_conn(&px, sloti, arg, true);
            break;
        case PIPE_OP_CLOSE:
            op_conn(&px, sloti, arg, false);
            break;
        case PIPE_OP_RECV:
            op_data(&px, sloti, arg, LK_DIR_RECV, &r);
            break;
        case PIPE_OP_SEND:
            op_data(&px, sloti, arg, LK_DIR_SEND, &r);
            break;
        case PIPE_OP_SWEEP:
            px.now += (arg + 1) * 100ull * 1000000000ull;
            lk_conn_table_sweep(px.pipe.conns, px.now);
            break;
        case PIPE_OP_RAW: {
            /* Feed through the aligned scratch: lk_ev_decode dereferences the
             * record as a struct, and every real caller guarantees 8-byte
             * alignment (the ringbuf natively, replay via a bounce buffer). */
            union rec_buf rb;
            const uint8_t *bytes;
            uint32_t n = rd_take(&r, &bytes, rd_u8(&r));

            memcpy(rb.raw, bytes, n);
            px.now += 1000;
            feed(&px, rb.raw, n);
            break;
        }
        default: /* TICK */
            px.now += (arg + 1) * 1000;
            break;
        }
    }

    /* Cheap cross-checks over the cumulative counters before teardown. */
    FZ_ASSERT(px.pipe.reasm.st.msgs_trunc <= px.pipe.reasm.st.msgs);
    {
        const struct lk_conn_table_stats *cs = lk_conn_table_stats(px.pipe.conns);

        FZ_ASSERT(cs->active <= PIPE_MAX_CONNS);
        FZ_ASSERT(cs->created >= cs->closed + cs->evicted_lru + cs->evicted_idle);
    }

    /* Table teardown fires the destroy hooks (parser must still be alive),
     * then the handler goes — the replay harness ordering (Р15). */
    lk_pipeline_fini(&px.pipe);
    lk_proto_free(px.proto);
    return 0;
}
