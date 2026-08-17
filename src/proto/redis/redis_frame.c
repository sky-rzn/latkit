// SPDX-License-Identifier: GPL-2.0
/* RESP2/RESP3 framing behind the protocol vtable — the fifth lk_proto_ops entry
 * and the second in *stream* mode (РR1/РR2, PLAN-REDIS.md МR1).
 *
 * Why stream mode (docs/notes-redisproto.md §"Framing: values, not packets"):
 * PG and MySQL put a fixed-size, length-carrying header in front of every
 * message, which is what the generic machine in reassembly.c accumulates in the
 * 8-byte lk_frame.hdr. RESP has no header at all. A value begins with a type
 * byte, continues to a CRLF, and only then says whether anything follows it —
 * and if that something is an aggregate, it says how many *values* follow, not
 * how many bytes. The hdr_size/parse_hdr contract cannot express that at any
 * size of hdr[], so the protocol takes the raw byte stream instead: lk_reasm_data
 * still runs the whole generic pipeline — chunk arithmetic, off-anomalies, the
 * TLS/IGNORE drop, the loss counters — and hands what survives to
 * redis_stream_bytes / redis_stream_hole. Messages go back out through
 * lk_reasm_emit, so --messages, the replay harness, the fuzz harness and the
 * handler see nothing new.
 *
 * The machine, per direction. One state per shape a value can take, and the
 * stack is what makes it a machine rather than a recursion (РR2 — a recursive
 * descent over a stream that arrives in fragments would have to keep its
 * continuation somewhere, and that somewhere is this stack):
 *
 *   VALUE ─(type byte)─▶ LINE ─(CRLF)─┬─ scalar ────────────────────▶ done
 *     │                               ├─ bulk ──▶ BULK ──▶ BULK_EOL ─▶ done
 *     │                               └─ aggregate ─(push N)────────▶ VALUE
 *     ├─(a byte that is not a type byte, frontend)─▶ INLINE ─(LF)───▶ done
 *     └─(hole in a header / aggregate, corruption)─▶ SCAN
 *                                                    │
 *                       (call boundary + anchor) ────┘──▶ VALUE
 *
 *   done: pop the stack while the level owes nothing more; at depth 0 the
 *         top-level value is complete and one lk_msg carries it.
 *
 * Three properties are worth naming, because they are what the design bought:
 *
 *   - **a bulk payload is counted, never scanned.** The length is on the wire,
 *     so a 1 MB value costs the framer nothing per byte and a capture hole
 *     inside it is harmless — which is the entire argument for the 512-byte
 *     per-port budget of РR13: at that budget holes land in payloads, and
 *     payloads are exactly what arithmetic can skip.
 *   - **an aggregate cannot be skipped at all.** `*3` says three values, not
 *     three hundred bytes, so the only way past one is through its elements and
 *     a hole inside one is unrecoverable by construction (risk 1 of the plan).
 *     The direction resyncs, and the units the handler had in flight are
 *     dropped and counted rather than mis-attributed.
 *   - **an inline command is a command.** `PING\r\n` from a healthcheck is what
 *     half the connections in a deployment carry, and a framer that treated a
 *     missing type byte as corruption would go blind exactly there.
 *
 * Everything the framer rejects, it rejects loudly: a '?' note message carries
 * the reason into the same stream the values travel in, so a degradation is
 * replayable, visible in --messages and countable by the handler without the
 * framer needing a stats object of its own.
 *
 * Two things joined the framer after МR1, and both are here because they are
 * questions about *bytes* rather than about traffic: redis_read_argv, which
 * unwraps the leading elements of a value for the command table of МR3, and
 * redis_mask_body, which blanks the password of an `AUTH` before a viewer prints
 * it (РR6). The unit queue, the pub/sub rule and the session state machine live
 * in redis.c, where the connection does. */
#include <stdlib.h>
#include <string.h>

#include "redis.h"

/* Framer state (РH1), lazily allocated: the connection table frees it on every
 * removal path. NULL means we cannot frame this connection at all — say so and
 * make it a counted blind zone rather than guess at value boundaries. */
static struct redis_frame *redis_frame_get(struct lk_conn *c)
{
    if (!c->frame_state)
        c->frame_state = calloc(1, sizeof(struct redis_frame));
    return c->frame_state;
}

/* --- emitting ------------------------------------------------------------- */

static void emit(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, char type, __u32 len,
                 const __u8 *body, __u32 cap, __u16 flags, __u64 ts)
{
    struct lk_msg m = {
        .ts_ns = ts,
        .type = type,
        .flags = flags,
        .len = len,
        .body_cap = cap,
        .body = body,
    };

    lk_reasm_emit(r, c, dir, &m);
}

/* Р19 applies to a note as much as to a value: a message that follows a hole
 * has to say so. A note emitted while the direction is already dirty has no
 * pending resync stamp to inherit — nothing was recovered — so it carries the
 * flag itself, exactly as the HTTP framer does. */
static void note(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, enum lk_redis_note n,
                 __u64 ts)
{
    __u16 flags = c->frame[dir].st == LK_FR_DIRTY ? LK_MSG_AFTER_RESYNC : 0;

    emit(r, c, dir, LK_REDIS_MSG_NOTE, (__u32)n, NULL, 0, flags, ts);
}

/* Sync lost on this direction. REDIS_FR_SCAN and LK_FR_DIRTY are deliberately
 * the same state seen from two sides: the connection table dirties lk_frame on
 * a seq gap, the framer dirties it on its own losses, and either way the way out
 * is a call boundary plus an anchor, plus lk_reasm_resync — one counter, one
 * on_resync callback (which is where the handler drops its in-flight units), one
 * LK_MSG_AFTER_RESYNC stamp for both causes. */
static void go_scan(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct redis_dir *rd)
{
    struct lk_frame *f = &c->frame[dir];

    lk_reasm_buf_put(r, f->buf); /* the prefix of a value we can no longer frame */
    f->buf = NULL;
    f->buf_len = 0;
    f->st = LK_FR_DIRTY;
    rd->st = REDIS_FR_SCAN;
    rd->depth = 0;
    rd->bulk_left = 0;
    rd->eol_left = 0;
    rd->line_n = 0;
    rd->num_n = 0;
    rd->num_bad = 0;
    rd->saw_cr = 0;
    rd->lost_prefix = 0;
}

/* A length the wire cannot mean: `$abc`, `$536870913` (past
 * `proto-max-bulk-len`), `*2147483648`. The server answers `-ERR Protocol
 * error: …` and closes the connection, so this is not a value we could pick up
 * after — it is the end of the conversation, and the honest reading is that
 * everything after it is unknown. Counted twice on purpose, from the two sides
 * that ask different questions: lk_reasm_stats.bad_len is the framer's ("a
 * length field failed its sanity check, and the direction was dirtied for it" —
 * the same meaning it has for PG and MySQL), the note becomes the handler's
 * latkit_parse_errors_total. */
static void bad_len(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct redis_dir *rd,
                    __u64 ts)
{
    r->st.bad_len++;
    note(r, c, dir, LK_REDIS_NOTE_BAD_LEN, ts);
    go_scan(r, c, dir, rd);
}

/* --- the body prefix ------------------------------------------------------
 * A value is published with a prefix of its own wire bytes, which is what the
 * МR3 handler reads its command and subcommand out of. The common case costs
 * nothing: a value that begins and ends inside one capture event is published
 * straight out of the capture buffer. Only a value that spans events is copied,
 * and then at most LK_MSG_BODY_MAX of it, into a slab borrowed from the
 * reassembly pool (Р11's ceiling therefore still covers it).
 *
 * `rd->cur` is the offset in the chunk being fed at which the not-yet-copied
 * bytes of the open value begin; stashing catches the slab up to `end`. */
static void stash(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct redis_dir *rd,
                  const __u8 *p, __u32 end)
{
    struct lk_frame *f = &c->frame[dir];
    __u32 k;

    if (end <= rd->cur)
        return;
    if (rd->lost_prefix || f->buf_len >= LK_MSG_BODY_MAX) {
        rd->cur = end; /* nothing more of this value will be kept */
        return;
    }
    if (!f->buf) {
        f->buf = lk_reasm_buf_get(r);
        if (!f->buf) {
            /* Out of scratch. The framing is unaffected — every length in
             * flight is already in rd — so the value is still framed and
             * published, with no body rather than with a body missing an
             * unknown middle. */
            rd->lost_prefix = 1;
            rd->cur = end;
            note(r, c, dir, LK_REDIS_NOTE_NO_MEM, rd->last_ts);
            return;
        }
        f->buf_len = 0;
    }
    k = LK_MSG_BODY_MAX - f->buf_len;
    if (k > end - rd->cur)
        k = end - rd->cur;
    memcpy(f->buf + f->buf_len, p + rd->cur, k);
    f->buf_len += k;
    rd->cur = end;
}

/* Give the slab back and forget the value being assembled — used where a value
 * ends without becoming a message (a blank inline line) and after every emit. */
static void prefix_release(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                           struct redis_dir *rd, __u32 end)
{
    struct lk_frame *f = &c->frame[dir];

    lk_reasm_buf_put(r, f->buf);
    f->buf = NULL;
    f->buf_len = 0;
    rd->lost_prefix = 0;
    rd->cur = end;
}

/* One top-level value, complete. `p` is the chunk being fed and `end` the
 * offset just past the value's last byte in it; `p == NULL` means the value was
 * completed by a *hole* (its bulk payload and the CRLF after it both fell into
 * one), in which case everything publishable is already in the slab.
 *
 * `len` is the value's whole size on the wire, holes included, which is what
 * makes it the number МR5's byte and size families want; `body_cap` is what of
 * it we actually hold. The two differ on this protocol far more often than on
 * any other — at a 512-byte budget every reply over half a kilobyte is a
 * prefix — so LK_MSG_BODY_TRUNC here reads "normal", not "anomaly". */
static void value_emit(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct redis_dir *rd,
                       const __u8 *p, __u32 end, __u64 end_pos)
{
    struct lk_frame *f = &c->frame[dir];
    __u64 len = end_pos - rd->v_pos;
    const __u8 *body = NULL;
    __u32 cap = 0;
    __u16 flags = 0;

    if (f->buf_len || rd->lost_prefix) {
        if (p)
            stash(r, c, dir, rd, p, end);
        body = f->buf;
        cap = f->buf_len;
    } else if (p) {
        body = p + rd->cur;
        cap = end - rd->cur;
        if (cap > LK_MSG_BODY_MAX)
            cap = LK_MSG_BODY_MAX;
    }
    if (len > cap)
        flags |= LK_MSG_BODY_TRUNC;
    emit(r, c, dir, (char)rd->vtype, len > ~0u ? ~0u : (__u32)len, body, cap, flags, rd->v_ts);
    prefix_release(r, c, dir, rd, end);
}

/* A value ended — an element, an aggregate, or the top-level one. Pop the stack
 * while each level's last element has just arrived; at depth 0 the whole
 * top-level value is over and becomes the message. */
static void value_done(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct redis_dir *rd,
                       const __u8 *p, __u32 end, __u64 end_pos)
{
    while (rd->depth) {
        if (--rd->stack[rd->depth - 1])
            break; /* this level still owes elements */
        rd->depth--;
    }
    rd->st = REDIS_FR_VALUE;
    if (!rd->depth)
        value_emit(r, c, dir, rd, p, end, end_pos);
}

/* --- the states ----------------------------------------------------------- */

/* At the start of a value. The type byte is the whole classification (RESP has
 * no phase context), and the three ways it can fail to be one are all decided
 * here. */
static __u32 value_start(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                         struct redis_dir *rd, const __u8 *p, __u32 i, __u64 ts)
{
    __u8 b = p[i];
    enum redis_vshape sh;

    if (!rd->depth) {
        /* Between top-level values, a stray CR or LF is not corruption and not
         * a message. Two real things produce them: an empty inline line, which
         * the server answers with nothing at all, and the bare `\n` keepalives a
         * master sends its replica while it forks (notes-redisproto.md
         * §"What is on the port but is not RESP"). */
        if (b == '\r' || b == '\n') {
            rd->cur = i + 1;
            return i + 1;
        }
        rd->v_pos = rd->cbase + i;
        rd->v_ts = ts;
        rd->vtype = b;
        rd->cur = i;
        /* This value is the first one to *start* since a syscall boundary, so on
         * the frontend it opens a batch (РR3, МR2 reads it through
         * redis_frame). A value torn across two calls belongs to the call it
         * started in, which is why the mark is taken here and not at the emit. */
        rd->v_call = rd->call_new;
        rd->call_new = 0;
    }

    sh = redis_vshape(b);
    if (sh == REDIS_V_BAD) {
        /* A line that does not begin with a type byte is an inline command —
         * on the frontend, where a client is speaking. On the backend it is a
         * reply that is not a reply, and there is nothing to do but say so. */
        if (dir == LK_DIR_RECV && !rd->depth) {
            rd->st = REDIS_FR_INLINE;
            rd->vtype = LK_REDIS_MSG_INLINE;
            rd->line_n = 0;
            rd->inline_arg = 0;
            return i; /* the byte belongs to the line */
        }
        note(r, c, dir, LK_REDIS_NOTE_BAD_TYPE, ts);
        go_scan(r, c, dir, rd);
        return i + 1;
    }

    rd->shape = (__u8)sh;
    rd->st = REDIS_FR_LINE;
    rd->line_n = 0;
    rd->num_n = 0;
    rd->num_bad = 0;
    rd->saw_cr = 0;
    return i + 1;
}

/* A CRLF-terminated line is complete: what it meant depends on the type byte
 * that opened it. */
static void line_complete(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                          struct redis_dir *rd, const __u8 *p, __u32 end, __u64 ts)
{
    __s64 v;

    if (rd->shape == REDIS_V_LINE) {
        value_done(r, c, dir, rd, p, end, rd->cbase + end);
        return;
    }
    if (rd->num_bad || !redis_parse_i64(rd->num, rd->num_n, &v)) {
        bad_len(r, c, dir, rd, ts);
        return;
    }
    if (rd->shape == REDIS_V_BULK) {
        __u64 payload;
        bool null;

        if (!redis_bulk_len(v, &payload, &null)) {
            bad_len(r, c, dir, rd, ts);
            return;
        }
        if (null) { /* `$-1`: the RESP2 null, complete where it stands */
            value_done(r, c, dir, rd, p, end, rd->cbase + end);
            return;
        }
        rd->bulk_left = payload;
        rd->eol_left = 2;
        rd->st = REDIS_FR_BULK;
        return;
    }

    __u32 elems;

    if (!redis_agg_count(v, rd->shape == REDIS_V_AGGPAIR, &elems)) {
        bad_len(r, c, dir, rd, ts);
        return;
    }
    if (!elems) {
        /* `*0` and `*-1` are the same thing to a framer: a value that is over.
         * They are *not* the same thing to the unit queue — a frontend `*0`
         * gets no reply at all — but that is МR2's to know, and it can, because
         * the count is in the body it receives. */
        value_done(r, c, dir, rd, p, end, rd->cbase + end);
        return;
    }
    if (rd->depth >= LK_REDIS_MAX_DEPTH) {
        note(r, c, dir, LK_REDIS_NOTE_DEPTH, ts);
        go_scan(r, c, dir, rd);
        return;
    }
    rd->stack[rd->depth++] = elems;
    rd->st = REDIS_FR_VALUE;
}

/* Feed bytes into the line being assembled. A line ends at CRLF and at nothing
 * else: the server's own parser looks for the CR and takes the byte after it,
 * so a bare LF inside a typed value is an ordinary byte here too — and a
 * multibulk command with LF-only terminators does not parse for the server
 * either (measured, `redis/inline-cmds.lkt`). Only the digits of a length line
 * are kept; the text of a `+`/`-`/`,` line is in the published body and is
 * nobody's business here. */
static __u32 line_feed(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct redis_dir *rd,
                       const __u8 *p, __u32 n, __u32 i, __u64 ts)
{
    while (i < n) {
        __u8 b = p[i++];

        if (rd->saw_cr && b == '\n') {
            line_complete(r, c, dir, rd, p, i, ts);
            return i;
        }
        if (rd->saw_cr)
            rd->num_bad = 1; /* a CR that was content: not a number, whatever else */
        rd->saw_cr = b == '\r';
        if (!rd->saw_cr) {
            if (rd->num_n < sizeof(rd->num))
                rd->num[rd->num_n++] = (char)b;
            else
                rd->num_bad = 1;
        }
        if (++rd->line_n > LK_REDIS_LINE_MAX) {
            note(r, c, dir, LK_REDIS_NOTE_LINE_TOO_BIG, ts);
            go_scan(r, c, dir, rd);
            return i;
        }
    }
    return i;
}

/* The CRLF that closes a bulk payload. Checked rather than skipped: if it is
 * not there, the declared length did not describe the wire, and every byte
 * after it would be read as something it is not. Redis's own client parsers
 * take the two bytes on faith; an observer that did so would misframe silently
 * where it could instead resync loudly. */
static __u32 eol_feed(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, struct redis_dir *rd,
                      const __u8 *p, __u32 n, __u32 i, __u64 ts)
{
    while (i < n && rd->eol_left) {
        __u8 want = rd->eol_left == 2 ? '\r' : '\n';

        rd->eol_left--;
        if (p[i++] != want) {
            note(r, c, dir, LK_REDIS_NOTE_BULK_EOL, ts);
            go_scan(r, c, dir, rd);
            return i;
        }
    }
    if (!rd->eol_left)
        value_done(r, c, dir, rd, p, i, rd->cbase + i);
    return i;
}

/* An inline command, terminated by LF with an optional CR before it — the
 * server splits on `\n` and strips a trailing `\r`, so an LF-only client works
 * and is measured working. A line with no non-blank byte is not a command: the
 * server answers nothing, so it must not become a message either, or the unit
 * queue МR2 builds on it would wait for a reply that is never coming. */
static __u32 inline_feed(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir,
                         struct redis_dir *rd, const __u8 *p, __u32 n, __u32 i, __u64 ts)
{
    while (i < n) {
        __u8 b = p[i++];

        if (b == '\n') {
            if (rd->inline_arg)
                value_emit(r, c, dir, rd, p, i, rd->cbase + i);
            else
                prefix_release(r, c, dir, rd, i);
            rd->st = REDIS_FR_VALUE;
            return i;
        }
        if (b != '\r' && b != ' ' && b != '\t')
            rd->inline_arg = 1;
        if (++rd->line_n > LK_REDIS_INLINE_MAX) {
            /* The server's own ceiling, and it answers `-ERR Protocol error:
             * too big inline request` and hangs up when it is crossed. */
            note(r, c, dir, LK_REDIS_NOTE_INLINE_TOO_BIG, ts);
            go_scan(r, c, dir, rd);
            return i;
        }
    }
    return i;
}

/* --- reading a value's elements (МR3) --------------------------------------
 * Everything above turns bytes into values; this turns a value into the first
 * few of its elements, which is the form src/norm/norm_redis.c classifies. It
 * belongs here rather than in the handler because it is RESP knowledge, and it
 * exists exactly once because two consumers have to agree byte for byte about
 * where element 2 begins: the handler, which reads a verb and an ACL user, and
 * the mask below, which hides a password. Two readers would eventually disagree
 * and the disagreement would be a leak.
 *
 * The reader stops at the caller's element bound and refuses to descend into a
 * nested one. A key, a value, a score and a script body are all *past* the point
 * where anything is read (РR4), so walking further would buy nothing and would
 * mean holding a pointer to a secret we have no use for. */

struct redis_rd {
    const __u8 *p;
    __u32 n, i;
};

/* The CRLF-terminated line at the cursor: content only, cursor left past the
 * terminator. false = no terminator inside the prefix, which is the honest
 * answer for a truncated body. */
static bool rd_line(struct redis_rd *rd, const char **start, __u32 *len)
{
    for (__u32 i = rd->i; i + 1 < rd->n; i++) {
        if (rd->p[i] == '\r' && rd->p[i + 1] == '\n') {
            *start = (const char *)rd->p + rd->i;
            *len = i - rd->i;
            rd->i = i + 2;
            return true;
        }
    }
    return false;
}

/* The next element, as a text token. Only the two shapes an element we ever
 * look at can take produce one — a bulk (`$3\r\nGET`, which is what a command's
 * verb, its subcommand and a push's kind word are on the wire) and a
 * line-shaped scalar. Anything else — a nested aggregate, an integer — ends the
 * walk: none of the questions asked here has an answer in it, and stepping over
 * a nested value correctly is the machine's job above, not a reader's. */
static bool rd_elem(struct redis_rd *rd, struct lk_redis_arg *t)
{
    const char *line;
    __u32 len;

    if (rd->i >= rd->n)
        return false;
    switch (redis_vshape(rd->p[rd->i])) {
    case REDIS_V_BULK: {
        __s64 v;
        __u64 payload;
        bool null;

        rd->i++;
        if (!rd_line(rd, &line, &len) || !redis_parse_i64(line, len, &v))
            return false;
        if (!redis_bulk_len(v, &payload, &null) || null)
            return false;
        if (payload > rd->n - rd->i)
            return false; /* the prefix ends inside the payload */
        t->p = (const char *)rd->p + rd->i;
        t->n = (__u32)payload;
        rd->i += (__u32)payload;
        if (rd->n - rd->i < 2)
            rd->i = rd->n; /* no room for the CRLF: this is the last token */
        else
            rd->i += 2;
        return true;
    }
    case REDIS_V_LINE:
        rd->i++;
        if (!rd_line(rd, &line, &len))
            return false;
        t->p = line;
        t->n = len;
        return true;
    default:
        return false;
    }
}

/* An inline command is not RESP and has no elements: the server splits it on
 * blanks itself, so the reader does too. `PING\r\n` from a healthcheck is the
 * common case and `SELECT 3` from a `nc` session the other one. Quoting
 * (`SET "a b" "c d"`, which the server does honour) is *not* interpreted: it
 * would matter only for reading an argument, and the one argument this reader
 * exists to find — a password, so that it can be blanked — is safer over-blanked
 * than parsed cleverly. */
static void read_inline(const __u8 *body, __u32 cap, __u32 max, struct lk_redis_argv *v)
{
    const char *p = (const char *)body;
    __u32 i = 0;

    while (v->n < max) {
        __u32 start;

        while (i < cap && (p[i] == ' ' || p[i] == '\t'))
            i++;
        start = i;
        while (i < cap && p[i] != ' ' && p[i] != '\t' && p[i] != '\r' && p[i] != '\n')
            i++;
        if (i == start)
            return;
        v->a[v->n].p = p + start;
        v->a[v->n].n = i - start;
        v->n++;
    }
}

void redis_read_argv(const struct lk_msg *m, const __u8 *body, __u32 cap, __u32 max,
                     struct lk_redis_argv *v, __s64 *nelem)
{
    struct redis_rd rd = {.p = body, .n = cap};
    enum redis_vshape sh;
    const char *line;
    __u32 len, elems;
    __s64 count;

    memset(v, 0, sizeof(*v));
    if (max > LK_REDIS_ARGV_MAX)
        max = LK_REDIS_ARGV_MAX;
    if (nelem)
        *nelem = -1;
    if (!body || !cap)
        return; /* the prefix was lost (no slab): nothing is known, and nothing
                   is guessed — the caller treats the value as an ordinary one */
    if (m->type == LK_REDIS_MSG_INLINE) {
        read_inline(body, cap, max, v);
        return;
    }
    sh = redis_vshape((__u8)m->type);
    if (sh != REDIS_V_AGG && sh != REDIS_V_AGGPAIR)
        return;
    rd.i = 1;
    if (!rd_line(&rd, &line, &len) || !redis_parse_i64(line, len, &count))
        return;
    if (!redis_agg_count(count, sh == REDIS_V_AGGPAIR, &elems))
        return;
    if (nelem)
        *nelem = elems;
    while (v->n < max && v->n < elems && rd_elem(&rd, &v->a[v->n]))
        v->n++;
}

struct lk_redis_arg redis_read_word(const struct lk_msg *m, const __u8 *body, __u32 cap)
{
    struct lk_redis_arg t = {0};
    struct redis_rd rd = {.p = body, .n = cap};
    const char *line;
    __u32 len, i;

    if (!body || !cap)
        return t;
    rd.i = 1; /* past the type byte */
    switch (redis_vshape((__u8)m->type)) {
    case REDIS_V_LINE:
        break; /* `-WRONGTYPE …`, `+QUEUED`: the line *is* the text */
    case REDIS_V_BULK:
        /* `!21\r\nWRONGPASS …`: the length line first, and the declared length
         * is not read at all — the prefix is the bound here, as everywhere in
         * this file, because the capture budget may have ended the value long
         * before its length says it does. */
        if (!rd_line(&rd, &line, &len))
            return t;
        break;
    default:
        return t; /* an aggregate has no text of its own; its elements are
                     redis_read_argv's business */
    }
    for (i = rd.i; i < cap; i++)
        if (body[i] == ' ' || body[i] == '\r' || body[i] == '\n')
            break;
    /* A token is whole only if something *ended* it inside the prefix. A
     * `-NOPERM …` cut by the budget at the fourth byte yields nothing rather
     * than `NOPE`, which would be a symbol the vocabulary happens not to have
     * and would fold to `other` — the same answer, arrived at by luck. */
    if (i == cap || i == rd.i)
        return t;
    t.p = (const char *)body + rd.i;
    t.n = i - rd.i;
    return t;
}

/* --- masking a credential (РR6) -------------------------------------------- */

/* Blank a span of the copy, keeping its length: the bulk header in front of it
 * says how many bytes follow, so a mask that shortened the payload would produce
 * a dump that no longer frames — and a `--messages` view whose framing is a
 * fiction is worse than one with a hidden field. */
static void blank(__u8 *base, __u32 n, struct lk_redis_arg s)
{
    size_t off = (size_t)((const __u8 *)s.p - base);

    if (s.p && off < n && s.n <= n - off)
        memset(base + off, '*', s.n);
}

void redis_mask_body(const struct lk_msg *m, __u8 *p, __u32 n)
{
    struct lk_redis_argv v;
    uint32_t mask;
    uint16_t id;

    if (!p || !n)
        return;
    if (m->type != REDIS_T_ARRAY && m->type != LK_REDIS_MSG_INLINE)
        return; /* a command is an array or an inline line; a *reply* carries no
                   credential, and `AUTH`'s is `+OK` either way */
    redis_read_argv(m, p, n, LK_REDIS_ARGV_MAX, &v, NULL);
    id = lk_redis_cmd(&v);
    mask = lk_redis_secret_mask(id, &v);
    for (uint32_t i = 0; i < v.n; i++)
        if (mask & (1u << i))
            blank(p, n, v.a[i]);
}

/* --- the two vtable hooks ------------------------------------------------- */

/* Framing is impossible without state: say so once, count it as a blind zone
 * and stop, rather than emit value boundaries we cannot stand behind. */
static bool redis_no_state(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, __u64 ts)
{
    if (c->frame_state)
        return false;
    note(r, c, dir, LK_REDIS_NOTE_NO_MEM, ts);
    c->flags |= LK_CONN_IGNORE;
    return true;
}

void redis_stream_bytes(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, const __u8 *p,
                        __u32 n, __u64 ts_ns)
{
    struct redis_frame *rf = redis_frame_get(c);
    /* Р10 for RESP: an anchor is only an anchor at a syscall boundary, because
     * that is where a client starts a batch. The generic layer has already put
     * this chunk's offset within its call into lk_frame.call_pos, so the
     * boundary is a comparison rather than a new contract. */
    bool at_call = c->frame[dir].call_pos == 0;
    struct redis_dir *rd;
    __u32 i = 0;

    if (!rf) {
        redis_no_state(r, c, dir, ts_ns);
        return;
    }
    rd = &rf->d[dir];
    rd->events++;
    rd->cbase = rd->off;
    rd->off += n;
    rd->last_ts = ts_ns;
    rd->cur = 0;
    if (at_call)
        rd->call_new = 1; /* the next value to start opens a batch (РR3) */

    /* Loss dirties both directions before the bytes ever reach us (the conn
     * table's seq detector; a lazily created or synthetic entry starts that
     * way). Whatever was being assembled cannot be finished honestly. */
    if (c->frame[dir].st == LK_FR_DIRTY && rd->st != REDIS_FR_SCAN)
        go_scan(r, c, dir, rd);

    while (i < n) {
        __u8 st0 = rd->st;
        __u32 i0 = i;

        switch (rd->st) {
        case REDIS_FR_VALUE:
            i = value_start(r, c, dir, rd, p, i, ts_ns);
            break;
        case REDIS_FR_LINE:
            i = line_feed(r, c, dir, rd, p, n, i, ts_ns);
            break;
        case REDIS_FR_BULK: {
            __u64 take = rd->bulk_left < n - i ? rd->bulk_left : n - i;

            rd->bulk_left -= take;
            i += (__u32)take;
            if (!rd->bulk_left)
                rd->st = REDIS_FR_BULK_EOL;
            break;
        }
        case REDIS_FR_BULK_EOL:
            i = eol_feed(r, c, dir, rd, p, n, i, ts_ns);
            break;
        case REDIS_FR_INLINE:
            i = inline_feed(r, c, dir, rd, p, n, i, ts_ns);
            break;
        case REDIS_FR_SCAN:
            /* The anchors of notes-redisproto.md §"Resync anchors": a call
             * boundary plus, on the frontend, an array header whose first
             * element is a plausible bulk — four conditions that have to agree
             * — and on the backend a valid type byte, which is all a stream of
             * arbitrary payload bytes will ever allow. Anything else: this
             * chunk is not ours, and neither is any byte in it. */
            if (i == 0 && at_call &&
                (dir == LK_DIR_RECV ? redis_anchor_fe(p, n) : redis_anchor_be(p, n))) {
                lk_reasm_resync(r, c, dir); /* leaves LK_FR_DIRTY, stamps the next msg */
                rd->st = REDIS_FR_VALUE;
                break;
            }
            return;
        default:
            return;
        }
        if (c->flags & LK_CONN_IGNORE)
            return; /* a blind zone opened: the rest of this chunk is not ours */
        if (i == i0 && rd->st == st0)
            return; /* defensive: a parked machine must not spin */
    }

    /* A value that outlives this chunk keeps its prefix — one copy per value
     * that spans events, none for a value that does not. */
    if (redis_value_open(rd))
        stash(r, c, dir, rd, p, n);
}

/* A hole is bytes we will never see: the uncaptured tail of a call (the
 * per-port budget, РR13), a lost ringbuf event, a missing off-interval. What it
 * costs depends entirely on where it lands, and on this protocol there is
 * exactly one place where it costs nothing — inside a bulk payload, whose
 * length is on the wire. That is not a coincidence but the reason the budget is
 * 512 bytes: at that size the holes fall in payloads (measured — 31 of 32
 * commands and 29 of 32 replies fit whole under it) and not in the headers,
 * which have no length to be skipped by. */
void redis_stream_hole(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, __u64 n)
{
    struct redis_frame *rf = redis_frame_get(c);
    struct lk_frame *f = &c->frame[dir];
    struct redis_dir *rd;
    __u64 ts;

    if (!rf) {
        redis_no_state(r, c, dir, 0);
        return;
    }
    if (!n)
        return;
    rd = &rf->d[dir];
    rd->holes++;
    rd->off += n;
    ts = rd->last_ts;

    if (f->st == LK_FR_DIRTY && rd->st != REDIS_FR_SCAN) {
        go_scan(r, c, dir, rd);
        return;
    }
    if (rd->st == REDIS_FR_SCAN)
        return;

    if (rd->st == REDIS_FR_BULK) {
        __u64 take = rd->bulk_left < n ? rd->bulk_left : n;

        rd->bulk_left -= take;
        n -= take;
        if (!rd->bulk_left)
            rd->st = REDIS_FR_BULK_EOL;
    }
    if (rd->st == REDIS_FR_BULK_EOL && n) {
        __u64 take = rd->eol_left < n ? rd->eol_left : n;

        rd->eol_left -= (__u8)take;
        n -= take;
        if (!rd->eol_left) /* payload *and* its CRLF fell into the hole */
            value_done(r, c, dir, rd, NULL, 0, rd->off - n);
    }
    if (!n)
        return; /* the hole ended where a length said it would */

    /* Anywhere else: a header line, an aggregate, or the gap between two
     * top-level values, none of which can be stepped over. Risk 1 of the plan,
     * and it is stated rather than papered over. */
    note(r, c, dir, LK_REDIS_NOTE_VALUE_HOLE, ts);
    r->st.hdr_holes++;
    go_scan(r, c, dir, rd);
}

const struct lk_proto_ops lk_proto_redis_ops = {
    .name = "redis",
    /* Redis *is* a database as far as the span semconv is concerned, and its
     * db.system.name is `redis` for Valkey and KeyDB too: on the wire they are
     * RESP and indistinguishable, and where they differ (their own admin
     * commands) МR3 folds them into cmd="other" (РR1). */
    .db_system = "redis",
    .otel_kind = LK_OTEL_KIND_DB,
    /* .profile stays at LK_PROTO_PROF_QUERY, the zero value, and is *not* the
     * final answer: РR11 gives Redis a profile of its own (latkit_redis_*) in
     * МR5. Nothing reads it before then — this handler emits no observation at
     * all — so the enum grows where its families do, and not one milestone
     * earlier. */
    .role = LK_ROLE_SERVER, /* v1 observes servers only (РH2) */
    .flags = LK_PROTO_F_STREAM,
    .sql_dialect = LK_SQL_PG, /* unused: nothing here reaches the SQL normaliser */
    /* No dialect: РH8's seam is HTTP's, and RESP has neither heads nor statuses
     * nor routes for it to hang off (see the header of redis.h). */
    /* РR13: the smallest budget of any protocol in the registry. A command is a
     * verb, a key and sometimes a megabyte of value; a reply is a few bytes,
     * except when it is an entire object. Everything the agent reads — the type
     * byte, the error symbol, the declared length, the command and its
     * subcommand — is in the first few dozen bytes of each, and the rate is an
     * order of magnitude above anything else the agent watches, so copying the
     * rest into the ringbuf buys nothing and costs the most. `--port
     * 6379=redis:BYTES` overrides it; --capture-limit caps it. */
    .cap_limit = LK_REDIS_CAPTURE_LIMIT,
    .proto_new = lk_proto_redis_new,
    /* The message-framing hooks (hdr_size, parse_hdr, pre_emit, both
     * intercept_ and both resync_) stay NULL: in stream mode the two hooks
     * above are the machine. */
    .stream_bytes = redis_stream_bytes,
    .stream_hole = redis_stream_hole,
    /* The first non-NULL mask_body outside the HTTP family (РR6): a Redis
     * password is an ordinary element of an ordinary command, so unlike PG's and
     * MySQL's — which travel in an authentication exchange the framer never
     * republishes — it is in a body a viewer would otherwise print. */
    .mask_body = redis_mask_body,
};
