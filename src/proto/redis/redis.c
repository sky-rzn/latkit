// SPDX-License-Identifier: GPL-2.0
/* Redis handler (PLAN-REDIS.md МR2, РR3/РR8/РR14) — the message consumer of the
 * stream framer in redis_frame.c, in the shape of pg.c / my.c / http.c: it owns
 * the per-connection state behind lk_conn.proto_state, keeps the in-flight
 * command queue, and turns each command/reply pair into one lk_query_obs.
 *
 * What a unit is (РR3): opened by a top-level value from the client, closed by
 * the **oldest unanswered** top-level value from the server. That is the whole
 * correspondence RESP offers — there is no request id, no sequence number and
 * nothing in a reply that names the command it answers — so two things follow,
 * and they are the two things this file is about:
 *
 *   - **the queue is mandatory, not an optimisation.** Every client library
 *     measured in МR0 pipelines by default at depth 1 and on request at depth
 *     100, and a batch can be split across syscalls (go-redis writes 18 + 82).
 *     A handler that assumed one outstanding command would mis-time every
 *     command on every pooled connection in a deployment.
 *   - **anything unsolicited has to be recognised.** A pub/sub delivery and an
 *     invalidation are values the server sends because somebody *else* did
 *     something. Let one of them close a unit and the queue is permanently one
 *     behind: every later latency on that connection is the wrong command's,
 *     and every one of them looks perfectly plausible (РR8). Recognising them
 *     is a correctness condition, which is why it lands in the same milestone
 *     as the queue rather than after it.
 *
 * Three shapes of traffic on a Redis port are not a request/response stream at
 * all, and pretending otherwise corrupts everything after them, so they become
 * deliberate blind zones (РR14): the replication handshake (`PSYNC`, and the RDB
 * and propagation streams behind it), and `MONITOR`, whose connection turns into
 * a feed of *other clients'* commands.
 *
 * What is *not* here, because it is МR3's and МR4's: the command table, so an
 * observation carries no identity yet (`cmd` becomes a label in МR3); the
 * database and the ACL user, so the session is empty; the symbolic error, the
 * redirects, `MULTI`/`EXEC` and the blocking family. The verb is read here all
 * the same, but only for the four questions this milestone has to answer —
 * is this a subscription, a replication handshake, a `MONITOR` or a `RESET` —
 * and never as an identity.
 *
 * No I/O, no libbpf: a pure state machine, fed synthetic lk_msg by unit tests
 * and .lkt traces by the replay harness. */
#include <stdlib.h>
#include <string.h>

#include "redis.h"

/* --- reading the first two elements of a value ----------------------------
 * The handler's questions are all about *words*: the verb of a command, and the
 * kind word that opens a pub/sub value. Both live in the first element, both are
 * bounded, and neither is ever a key — a Redis key is an identifier and becomes
 * no label at any setting (РR4), which is why this reader stops at two elements
 * and refuses to walk further.
 *
 * Everything is read out of the *published prefix*, which under the 512-byte
 * per-port budget of РR13 is all of a command's head and none of a large
 * value's tail. A prefix that ends mid-token yields no token rather than a
 * short one: half a verb is not a verb. */

struct redis_tok {
    const char *p;
    __u32 n;
};

struct redis_view {
    struct redis_tok a[2]; /* argv[0], argv[1] — as far as anything here looks */
    __u32 nargs;           /* tokens actually read (0..2) */
    __s64 nelem;           /* declared elements of the top-level aggregate;
                              -1 = the value is not an aggregate at all */
};

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

/* The next element, as a text token. Only the two shapes an element that we
 * ever look at can take produce one — a bulk (`$9\r\nsubscribe`, which is what
 * a command's verb and a push's kind word are on the wire) and a line-shaped
 * scalar. Anything else — a nested aggregate, an integer — ends the walk: the
 * questions above have no answer in it, and stepping over a nested value
 * correctly is the framer's job, not a reader's. */
static bool rd_elem(struct redis_rd *rd, struct redis_tok *t)
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
 * common case and `SELECT 3` from a `nc` session the other one. */
static void view_inline(const struct lk_msg *m, struct redis_view *v)
{
    const char *p = (const char *)m->body;
    __u32 i = 0, n = m->body_cap;

    while (v->nargs < 2) {
        __u32 start;

        while (i < n && (p[i] == ' ' || p[i] == '\t'))
            i++;
        start = i;
        while (i < n && p[i] != ' ' && p[i] != '\t' && p[i] != '\r' && p[i] != '\n')
            i++;
        if (i == start)
            return;
        v->a[v->nargs].p = p + start;
        v->a[v->nargs].n = i - start;
        v->nargs++;
    }
}

static void redis_view(const struct lk_msg *m, struct redis_view *v)
{
    struct redis_rd rd = {.p = m->body, .n = m->body_cap};
    enum redis_vshape sh;
    const char *line;
    __u32 len, elems;
    __s64 count;

    memset(v, 0, sizeof(*v));
    v->nelem = -1;
    if (!m->body || !m->body_cap)
        return; /* the prefix was lost (no slab): nothing is known, nothing is
                   guessed — the caller treats the value as an ordinary one */
    if (m->type == LK_REDIS_MSG_INLINE) {
        view_inline(m, v);
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
    v->nelem = elems;
    while (v->nargs < 2 && v->nargs < elems && rd_elem(&rd, &v->a[v->nargs]))
        v->nargs++;
}

/* Command names are case-insensitive on the wire (go-redis sends them in lower
 * case, measured), and the kind words of a push arrive in lower case from the
 * server. One case-folding comparison serves both. */
static bool tok_is(struct redis_tok t, const char *lit)
{
    __u32 i = 0;

    for (; i < t.n && lit[i]; i++) {
        char a = t.p[i];

        if (a >= 'A' && a <= 'Z')
            a = (char)(a - 'A' + 'a');
        if (a != lit[i])
            return false;
    }
    return i == t.n && !lit[i];
}

/* --- the pub/sub vocabulary (РR8) ------------------------------------------
 * The correction МR0 made to the plan, in two functions. РR8 proposed "a push
 * never closes a unit" plus a counting rule for RESP2; measured, the truth is
 * one rule for both versions and it is not counting — **the first element
 * carries the kind**, the two sets do not overlap, and in RESP3 the subscribe
 * confirmation is itself a push, so the naive rule would leave every SUBSCRIBE
 * unit open for ever (notes-redisproto.md §"Subscriptions"). */

/* A confirmation: the server acknowledging a subscribe-family command. One per
 * channel named in the command. */
static bool kind_is_confirm(struct redis_tok t)
{
    return tok_is(t, "subscribe") || tok_is(t, "unsubscribe") || tok_is(t, "psubscribe") ||
           tok_is(t, "punsubscribe") || tok_is(t, "ssubscribe") || tok_is(t, "sunsubscribe");
}

/* A delivery: somebody else published, or the server is invalidating a key this
 * client cached. Answers no command and must close no unit. */
static bool kind_is_delivery(struct redis_tok t)
{
    return tok_is(t, "message") || tok_is(t, "pmessage") || tok_is(t, "smessage") ||
           tok_is(t, "invalidate");
}

static bool verb_is_sub_family(struct redis_tok t)
{
    return tok_is(t, "subscribe") || tok_is(t, "psubscribe") || tok_is(t, "ssubscribe") ||
           tok_is(t, "unsubscribe") || tok_is(t, "punsubscribe") || tok_is(t, "sunsubscribe");
}

/* --- per-connection state -------------------------------------------------- */

/* Lazily attach per-connection state on the first message (Р15). NULL only on
 * allocation failure — the caller degrades to counting, never crashes. */
static struct redis_conn *redis_conn_get(struct lk_proto *p, struct lk_conn *c)
{
    struct redis_conn *rc = c->proto_state;

    if (rc)
        return rc;
    rc = calloc(1, sizeof(*rc));
    if (!rc)
        return NULL;
    /* A synthetic or lazily created entry joined an established connection: its
     * `SELECT` and its `AUTH` happened before we were watching, so its database
     * and user are unknowable (РR5 — `db="?"`, not `db="0"`) and no value on it
     * is a trustworthy unit boundary until the framer vouches for one. */
    rc->degraded = (c->flags & LK_CONN_SYNTHETIC) != 0;
    c->proto_state = rc;
    p->st.conns++;
    return rc;
}

/* A value that found no unit to belong to. On a connection we know we joined
 * mid-stream — a synthetic entry, or one that has just resynced — that is the
 * expected shape rather than an anomaly, and counting every such value would
 * swamp the tally exactly where it stops being able to tell us anything. So
 * `orphan_msgs` means "a reply we had no business losing", and rc->degraded is
 * what separates the two (the HTTP rule, РH6); it clears on the next command,
 * the first boundary the frontend anchor can vouch for. */
static void redis_orphan(struct lk_proto *p, const struct redis_conn *rc)
{
    if (!rc->degraded)
        p->st.orphan_msgs++;
}

/* --- the in-flight ring ---------------------------------------------------- */

static struct redis_unit *unit_front(struct redis_conn *rc)
{
    return rc->head_seq < rc->open_seq ? &rc->ring[rc->head_seq % LK_REDIS_MAX_INFLIGHT] : NULL;
}

/* Drop every in-flight unit without emitting (Р19: an observation must never
 * span a loss or a disconnect) and add the count to *counter. */
static void units_drop_all(struct redis_conn *rc, __u64 *counter)
{
    while (rc->head_seq < rc->open_seq) {
        rc->head_seq++;
        if (counter)
            (*counter)++;
    }
    rc->owed = 0;
    rc->early_n = 0;
    rc->batch_seq0 = rc->open_seq;
    rc->batch_n = 0;
}

/* A new batch begins: freeze the depth of the one that just ended into the units
 * still queued from it, since from here on batch_n counts somebody else.
 *
 * The loop runs once per syscall over at most the units of one batch, so the
 * cost is one pass per batch and not one per command — and on the shape that
 * actually dominates a Redis port, a single command per call, it runs over
 * nothing at all. */
static void batch_new(struct redis_conn *rc)
{
    __u64 s = rc->batch_seq0 > rc->head_seq ? rc->batch_seq0 : rc->head_seq;
    __u16 d = rc->batch_n > 0xffff ? 0xffff : (__u16)rc->batch_n;

    for (; s < rc->open_seq; s++)
        rc->ring[s % LK_REDIS_MAX_INFLIGHT].depth = d;
    rc->batch_seq0 = rc->open_seq;
    rc->batch_n = 0;
}

/* Open a unit for a command. NULL when the ring is full — the caller records
 * that a reply is owed and will skip it (РR3). Dropping the *newest* command
 * rather than the oldest is what keeps the queue a FIFO: the commands still in
 * it pair with their replies correctly, and the ones we cannot place are the
 * last to be answered. */
static struct redis_unit *unit_open(struct lk_proto *p, struct redis_conn *rc, __u64 ts_ns)
{
    struct redis_unit *u;

    if (rc->open_seq - rc->head_seq >= LK_REDIS_MAX_INFLIGHT) {
        p->st.units_dropped_overflow++;
        return NULL;
    }
    u = &rc->ring[rc->open_seq % LK_REDIS_MAX_INFLIGHT];
    memset(u, 0, sizeof(*u));
    u->ts_start_ns = ts_ns;
    rc->open_seq++;
    /* Pipelining is "a command went out before the previous one was answered",
     * and every unit in flight carries the mark: the first one's duration is
     * honest, the later ones' start times reflect a client that was not waiting,
     * so none of them is comparable with a standalone command (РR3, and the same
     * LK_QO_PIPELINED as PG and HTTP).
     *
     * Two slots, not a sweep of the queue: every unit but the one below the new
     * arrival was marked when *it* arrived, so marking the pair is enough and the
     * cost stays constant. On a protocol whose stated headline risk is event rate
     * (риск 2), a batch of 100 is not the place to run a hundred loops of a
     * hundred. */
    if (rc->open_seq - rc->head_seq > 1) {
        u->flags |= LK_QO_PIPELINED;
        rc->ring[(rc->open_seq - 2) % LK_REDIS_MAX_INFLIGHT].flags |= LK_QO_PIPELINED;
    }
    return u;
}

/* Risk 4's backstop: a queue that has been waiting longer than any legal
 * blocking command can be waiting for is not waiting, it is wrong. Checked at
 * the front only — the units behind it are younger by construction — and only
 * when a *command* arrives: a reply is evidence that the queue is still being
 * served, and a connection that has gone quiet altogether loses its units to the
 * close hook anyway. */
static void units_expire(struct lk_proto *p, struct redis_conn *rc, __u64 now)
{
    struct redis_unit *u = unit_front(rc);

    if (u && now > u->ts_start_ns && now - u->ts_start_ns > LK_REDIS_UNIT_TIMEOUT_NS)
        units_drop_all(rc, &p->st.units_dropped_close);
}

/* --- emitting -------------------------------------------------------------- */

static void unit_emit(struct lk_proto *p, struct lk_conn *c, struct redis_conn *rc,
                      const struct redis_unit *u, __u64 seq, __u32 reply_bytes, __u64 end_ns)
{
    /* The batch this command arrived in is normally still open when its reply
     * comes back — the whole batch is read out of one syscall before the server
     * answers any of it — so the live count is the answer, and the frozen one
     * only for a unit whose batch has since been superseded (РR3). */
    struct lk_redis_obs rr = {
        .pipeline_depth = seq >= rc->batch_seq0 ? rc->batch_n : u->depth,
    };
    struct lk_query_obs o = {
        .ts_start_ns = u->ts_start_ns,
        /* ts_req_done and ts_first_row stay 0 deliberately: RESP has neither.
         * There is no request body to finish separately from the command, and no
         * first row to arrive before the rest — a reply is one value, so its
         * first byte and its completion are the same event as often as not.
         * Reporting an invented TTFB here would put a family on the dashboard
         * that always equals the duration (РR11 switches it off for that
         * reason). */
        .ts_complete_ns = end_ns,
        .ts_ready_ns = end_ns, /* no separate ready point, as in HTTP */
        .bytes_in = u->bytes,
        .bytes_out = reply_bytes,
        .redis = &rr,
        /* МR5 gives Redis LK_Q_COMMAND and a profile of its own (РR11). Until
         * then a command is the closest thing the enum already has — one
         * statement, one round trip, no prepare and no cursor — and the value is
         * mirrored into metrics.h, so inventing one here would have to be
         * mirrored too, one milestone before the families that read it exist. */
        .kind = LK_Q_SIMPLE,
        /* No identity yet: the command table is МR3's (РR4), and an observation
         * that carried the raw command instead would be carrying the key with
         * it. `other` is the honest label until the table lands. */
        .flags = (__u16)(u->flags | LK_QO_NO_TEXT),
    };

    p->st.queries++;
    if (p->out.on_query)
        p->out.on_query(p->out.ctx, c, &rc->session, &o);
}

/* A reply for the oldest unit: emit it, or account for its absence. */
static void unit_close(struct lk_proto *p, struct lk_conn *c, struct redis_conn *rc,
                       const struct lk_msg *m, __u64 end_ns)
{
    struct redis_unit *u = unit_front(rc);
    const struct redis_dir *fe;

    if (!u) {
        /* The ring overflowed and this is one of the replies we knew we would
         * not be able to place. */
        if (rc->owed) {
            rc->owed--;
            return;
        }
        /* The command this answers is *still being assembled* — it was bigger
         * than the capture budget, so its uncaptured tail (and with it the
         * value's publication) waits for the next call on the frontend, which
         * has not happened yet. The reply is held rather than orphaned, and the
         * command it belongs to claims it the moment it arrives. */
        fe = redis_dir_of(c, LK_DIR_RECV);
        if (fe && redis_value_open(fe) && rc->early_n < LK_REDIS_MAX_EARLY) {
            rc->early[rc->early_n].end_ns = end_ns;
            rc->early[rc->early_n].bytes = m->len;
            rc->early_n++;
            return;
        }
        /* Otherwise: a connection joined mid-stream, or a reply arriving after
         * its unit was dropped. Not a parse error — the bytes were fine, we
         * simply never saw the command they answer. */
        redis_orphan(p, rc);
        return;
    }
    unit_emit(p, c, rc, u, rc->head_seq, m->len, end_ns);
    rc->head_seq++;
}

/* The command a held reply was waiting for has arrived (see unit_close). It is
 * the front of the queue by construction — nothing was queued when the reply was
 * held — and the guard is there so that "by construction" cannot quietly become
 * "usually". */
static void early_claim(struct lk_proto *p, struct lk_conn *c, struct redis_conn *rc)
{
    struct redis_early e = rc->early[0];

    if (rc->head_seq + 1 != rc->open_seq) {
        rc->early_n = 0;
        redis_orphan(p, rc);
        return;
    }
    memmove(rc->early, rc->early + 1, sizeof(rc->early[0]) * (__u32)(rc->early_n - 1));
    rc->early_n--;
    unit_emit(p, c, rc, unit_front(rc), rc->head_seq, e.bytes, e.end_ns);
    rc->head_seq++;
}

/* --- the frontend: a command ----------------------------------------------- */

/* A connection that stopped being a request/response stream (РR14). Everything
 * queued on it is dropped rather than emitted — the replies we would have to
 * match are not coming — and the framer discards its events from here on. */
static void ignore_conn(struct lk_proto *p, struct lk_conn *c, struct redis_conn *rc,
                        __u64 *counter)
{
    units_drop_all(rc, &p->st.units_dropped_close);
    c->flags |= LK_CONN_IGNORE;
    (*counter)++;
}

static void redis_command(struct lk_proto *p, struct lk_conn *c, struct redis_conn *rc,
                          const struct lk_msg *m, bool batch_first)
{
    struct redis_view v;
    struct redis_unit *u;

    if (batch_first)
        batch_new(rc);
    redis_view(m, &v);
    /* `*0\r\n` and `*-1\r\n` are complete values that the server answers with
     * *nothing at all*. They must not open a unit: the queue would then be one
     * ahead for the rest of the connection, which is the same corruption a
     * missed push causes, from the other side. */
    if (!v.nelem)
        return;

    if (v.nargs) {
        /* The replication handshake (РR14). After it the connection carries an
         * RDB image and then a stream of write commands *from the server*, none
         * of which answers anything — parsing that as replies is not a
         * degradation, it is guaranteed nonsense (notes-redisproto.md §"What is
         * on the port but is not RESP").
         *
         * **Any** `REPLCONF`, not just the `listening-port` of РR14. Only a
         * replica sends the command at all, and the broader rule is what catches
         * the case the corpus actually contains: a replication link joined after
         * its `PSYNC` — the handshake happened before the agent attached, so the
         * only mark left on the wire is the periodic `REPLCONF ACK <offset>`.
         * `libs/java-pipeline.lkt` and `libs/memtier-pipe100.lkt` each carry one
         * beside the traffic they were recorded for, and without this rule the
         * propagated writes on them read as a hundred unanswerable replies. */
        if (tok_is(v.a[0], "psync") || tok_is(v.a[0], "sync") || tok_is(v.a[0], "replconf")) {
            ignore_conn(p, c, rc, &p->st.replication_conns);
            return;
        }
        /* `MONITOR`: `+OK`, and then one simple string per command executed by
         * every *other* client on the server. Its own reason, because "somebody
         * is running a replica" and "somebody left a MONITOR open" are different
         * facts about a deployment — and the second is also a performance
         * problem worth seeing on the dashboard (МR5). */
        if (tok_is(v.a[0], "monitor")) {
            ignore_conn(p, c, rc, &p->st.monitor_conns);
            return;
        }
        /* `RESET` returns the connection to a virgin state — out of subscribe
         * mode, out of the transaction, back to RESP2, database 0, user
         * `default`. МR3 and МR4 take the rest of that list; the subscribe bit
         * is the part this milestone owns. */
        if (tok_is(v.a[0], "reset"))
            rc->sub = false;
        else if (tok_is(v.a[0], "subscribe") || tok_is(v.a[0], "psubscribe") ||
                 tok_is(v.a[0], "ssubscribe"))
            rc->sub = true;
    }

    rc->batch_n++;
    u = unit_open(p, rc, m->ts_ns);
    if (!u) {
        rc->owed++;
        return;
    }
    rc->degraded = false;
    u->bytes = m->len;
    if (v.nargs && verb_is_sub_family(v.a[0]))
        u->uflags |= REDIS_U_SUB;
    if (rc->early_n)
        early_claim(p, c, rc);
}

/* --- the backend: a reply, a confirmation, a push or a prefix -------------- */

enum redis_rkind {
    REDIS_R_REPLY = 0, /* an ordinary reply: it closes the oldest unit */
    REDIS_R_CONFIRM,   /* a subscribe-family confirmation (РR8) */
    REDIS_R_PUSH,      /* a delivery or an invalidation: closes nothing */
    REDIS_R_ATTR,      /* an attribute: a *prefix* to the value that follows */
};

static enum redis_rkind reply_kind(const struct redis_conn *rc, const struct lk_msg *m)
{
    struct redis_view v;

    /* An attribute is not a reply and never closes a unit — it decorates the
     * value that comes after it. Closing one would answer this command with the
     * decoration and the next command with this command's reply, for ever
     * (measured, `redis/types3.lkt`). */
    if (m->type == REDIS_T_ATTR)
        return REDIS_R_ATTR;
    if (m->type == REDIS_T_PUSH) {
        redis_view(m, &v);
        /* RESP3: the confirmation of a SUBSCRIBE *is* a push, so the type byte
         * alone cannot decide. The kind word can, and it decides for RESP2 too. */
        return (v.nargs && kind_is_confirm(v.a[0])) ? REDIS_R_CONFIRM : REDIS_R_PUSH;
    }
    if (m->type == REDIS_T_ARRAY && rc->sub) {
        /* RESP2: a delivery and an ordinary array are the same type byte, so the
         * kind word is read *only* on a connection known to have subscribed —
         * otherwise a `LRANGE` returning the word "message" would be swallowed
         * as somebody's publication. */
        redis_view(m, &v);
        if (v.nargs && kind_is_delivery(v.a[0]))
            return REDIS_R_PUSH;
        if (v.nargs && kind_is_confirm(v.a[0]))
            return REDIS_R_CONFIRM;
    }
    return REDIS_R_REPLY;
}

static void redis_reply(struct lk_proto *p, struct lk_conn *c, struct redis_conn *rc,
                        const struct lk_msg *m, __u64 end_ns)
{
    switch (reply_kind(rc, m)) {
    case REDIS_R_ATTR:
        return;
    case REDIS_R_PUSH:
        p->st.pushes++;
        return;
    case REDIS_R_CONFIRM: {
        struct redis_unit *u = unit_front(rc);

        /* A push-shaped confirmation proves the connection subscribes even if we
         * never saw the command that made it so — which is how a connection
         * joined mid-stream learns it is a subscriber. */
        rc->sub = true;
        /* One `SUBSCRIBE a b` is one command and **two** confirmations, one per
         * channel (measured, `redis/pubsub.lkt`) — and a bare `UNSUBSCRIBE`
         * produces one per channel the connection happened to hold, a number
         * nobody watching from outside can know. So a confirmation closes a unit
         * only when the unit it would close is itself a subscribe-family
         * command; the second and later ones answer nothing that is still
         * queued. Letting them close the units behind it would credit the next
         * command with a latency it never had, and *counting* them as orphans
         * would report a loss where nothing was lost. They go with the pushes,
         * which is exactly what they are to the queue: a server value that
         * closes nothing. */
        if (!u || !(u->uflags & REDIS_U_SUB)) {
            p->st.pushes++;
            return;
        }
        break;
    }
    case REDIS_R_REPLY:
        break;
    }
    unit_close(p, c, rc, m, end_ns);
}

/* --- framer notes (РR2) ---------------------------------------------------- */

/* The framer's notes: the only channel a stream framer has to report a
 * degradation, and it is the message stream itself. Split by what the note says
 * about *whose* fault it was — a corrupt length is the input's and belongs in
 * latkit_parse_errors_total, a capture hole is the budget's and does not. */
static void framer_note(struct lk_proto *p, const struct lk_msg *m)
{
    if (LK_REDIS_NOTE_IS_PARSE_ERR(m->len))
        p->st.parse_errors++;
}

/* --- lk_msg_sink implementation (down contract) ---------------------------- */

static void redis_on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct lk_proto *p = ctx;
    struct redis_conn *rc = redis_conn_get(p, c);
    const struct redis_dir *rd;
    __u64 end_ns = m->ts_ns;
    bool batch_first = false;

    p->st.msgs++;
    p->st.by_type[dir][(__u8)m->type]++;
    if (m->type == LK_REDIS_MSG_NOTE) {
        /* Counted whatever the state of the connection: a note is the framer's
         * own report about itself, and dropping it because an allocation failed
         * would hide the very failure it is reporting. */
        framer_note(p, m);
        return;
    }
    if (!rc)
        return; /* alloc failed: keep counting, skip semantics */
    rc->msgs++;

    /* The two facts about the capture rather than about the bytes (see redis.h):
     * when this value's last byte arrived, and whether it opened a batch. */
    rd = redis_dir_of(c, dir);
    if (rd) {
        if (rd->last_ts > end_ns)
            end_ns = rd->last_ts;
        batch_first = rd->v_call != 0;
    }

    if (dir == LK_DIR_RECV) {
        units_expire(p, rc, m->ts_ns);
        redis_command(p, c, rc, m, batch_first);
    } else {
        redis_reply(p, c, rc, m, end_ns);
    }
}

static void redis_on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    struct lk_proto *p = ctx;
    struct redis_conn *rc = redis_conn_get(p, c);

    (void)dir;
    p->st.resyncs++;
    if (!rc)
        return;
    /* Every in-flight unit goes, whichever direction lost the thread, and RESP
     * is the reason the HTTP handler's finer rule does not carry over here. A
     * value has no length that a later value confirms: after a hole we cannot
     * say how many replies went past unseen, so the queue's alignment is not
     * "degraded", it is unknown. Emitting from it would produce observations
     * that look right and pair a command with somebody else's answer (Р19,
     * risk 1 of the plan). */
    units_drop_all(rc, &p->st.units_dropped_resync);
    rc->degraded = true;
}

/* Fired by the connection table on *every* removal path (CONN_CLOSE, LRU
 * eviction, idle sweep, teardown), routed here through the framer sink — the
 * one place proto_state is released (Р15). Idempotent and NULL-safe.
 *
 * A command still waiting for its reply when the socket dies is not an
 * observation: unlike HTTP, where a bodiless response can be *completed* by the
 * close (rule 6), RESP has no reply whose end is the connection's end. */
static void redis_on_conn_close(void *ctx, struct lk_conn *c)
{
    struct lk_proto *p = ctx;
    struct redis_conn *rc = c->proto_state;

    if (!rc)
        return;
    units_drop_all(rc, &p->st.units_dropped_close);
    free(rc);
    c->proto_state = NULL;
}

/* --- registry entry point ------------------------------------------------- */

struct lk_proto *lk_proto_redis_new(const struct lk_query_sink *out)
{
    struct lk_proto *p = calloc(1, sizeof(*p));

    if (!p)
        return NULL;
    p->msink.ctx = p;
    p->msink.on_msg = redis_on_msg;
    p->msink.on_resync = redis_on_resync;
    p->msink.on_conn_close = redis_on_conn_close;
    if (out)
        p->out = *out;
    return p;
}
