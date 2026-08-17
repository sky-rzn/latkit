// SPDX-License-Identifier: GPL-2.0
/* Redis handler (PLAN-REDIS.md МR2/МR3, РR3–РR8/РR14) — the message consumer of the
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
 * МR3 adds what an observation is *about*: the identity (РR4) and the two
 * session labels (РR5, РR6). All three come out of the closed table in
 * src/norm/norm_redis.c — this file decides *when* they move, which for both
 * labels is a question RESP answers only in the reply, and never in the command
 * that asked. That split is the whole of the session machine below.
 *
 * МR4 adds what an observation's *outcome* is, and all three of its rules exist
 * to keep a number out of a place where it would be plausible and wrong:
 *
 *   - **the error is symbolic, and two errors are not failures** (РR7). The
 *     first token of `-WRONGTYPE Operation against…` is the label; the sentence
 *     after it is written for a human and holds a key. `-MOVED` and `-ASK` are
 *     how a cluster routes, so they get a counter of their own and
 *     LK_QO_CLIENT_ERR — in `errors_total` they would paint a healthy resharding
 *     cluster red for ever.
 *   - **`+QUEUED` is not a latency** (РR9). Inside a `MULTI` the server writes a
 *     command down in microseconds and runs it at `EXEC`; the interval that
 *     means something is `MULTI` → the reply to `EXEC`, and it goes to the
 *     transaction family every database protocol here already feeds.
 *   - **a blocking command measures the client's own patience** (РR10). `BLPOP
 *     key 30` is a thirty-second observation about nothing, and one of them in
 *     the general histogram decides its p99.
 *
 * No I/O, no libbpf: a pure state machine, fed synthetic lk_msg by unit tests
 * and .lkt traces by the replay harness. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "redis.h"

/* --- the handler's two readers ---------------------------------------------
 * A command's elements are unwrapped by redis_read_argv (redis_frame.c: RESP
 * knowledge, and one reader so that the handler and the mask cannot disagree
 * about where an element begins) and classified by src/norm/norm_redis.c. What
 * is left here is the one word the *server* sends that has to be read: the kind
 * word of a pub/sub value, which is not a command and is in no table.
 *
 * Everything is read out of the *published prefix*, which under the 512-byte
 * per-port budget of РR13 is all of a command's head and none of a large
 * value's tail. A prefix that ends mid-token yields no token rather than a
 * short one: half a verb is not a verb. */

/* Command names are case-insensitive on the wire (go-redis sends them in lower
 * case, measured), and the kind words of a push arrive in lower case from the
 * server. One case-folding comparison serves both. */
static bool tok_is(struct lk_redis_arg t, const char *lit)
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
 * channel named in the command.
 *
 * Spelled out rather than looked up in the command table, though the six words
 * are the six names of LK_REDIS_C_SUBFAM: this is the *server* talking, and a
 * kind word is not a command. `SUBSCRIBE` in a reply's first element is the
 * server saying "you are now subscribed"; matching it through the table that
 * classifies what a client sends would make the two facts one, and they are not
 * one — a future kind word need not be a command name, and a future command
 * name need not be a kind word. */
static bool kind_is_confirm(struct lk_redis_arg t)
{
    return tok_is(t, "subscribe") || tok_is(t, "unsubscribe") || tok_is(t, "psubscribe") ||
           tok_is(t, "punsubscribe") || tok_is(t, "ssubscribe") || tok_is(t, "sunsubscribe");
}

/* A delivery: somebody else published, or the server is invalidating a key this
 * client cached. Answers no command and must close no unit. */
static bool kind_is_delivery(struct lk_redis_arg t)
{
    return tok_is(t, "message") || tok_is(t, "pmessage") || tok_is(t, "smessage") ||
           tok_is(t, "invalidate");
}

/* --- the session labels (РR5, РR6) -----------------------------------------
 * Two dim slots, the same two PG fills out of its startup packet — and that is
 * where the resemblance ends. In RESP both are *connection state that moves*:
 * `SELECT 3` puts everything after it in database 3, `AUTH lkreader …` puts
 * everything after it under another ACL user, and a connection pool recycles
 * both several times a second. So the labels are the output of a state machine,
 * and the machine has one rule that matters: **it moves on the reply, never on
 * the command.** `SELECT 16` is `-ERR DB index is out of range` and the
 * connection stays where it was; `AUTH lkuser wrongpass` is `-WRONGPASS` and the
 * user does not change (both measured, `redis/select-db.lkt` and
 * `redis/auth-forms.lkt`). A machine that moved on the request would be wrong
 * about every command that followed, for as long as the connection lived. */

/* Handler-wide settings (РR6), in the shape lk_proto_http_configure set: there
 * is exactly one redis handler per agent and the value is fixed at startup from
 * the CLI, so a static is what a per-handler pointer would be with more steps.
 * A zeroed config is the default — `--redis-user acl`, on. */
static struct lk_redis_cfg redis_cfg;

void lk_proto_redis_configure(const struct lk_redis_cfg *cfg)
{
    if (cfg)
        redis_cfg = *cfg;
    else
        memset(&redis_cfg, 0, sizeof(redis_cfg));
}

/* What a connection whose beginning we watched starts as: database 0, user
 * `default`. Both are facts about the protocol rather than guesses — a new
 * connection *is* in database 0 and *is* the `default` user until it says
 * otherwise.
 *
 * With `--redis-user off` the user slot stays empty everywhere and the registry
 * reports `user="-"`: what is not read cannot leak and cannot multiply series,
 * which is the РH12 rule applied to the one identity a Redis connection carries
 * (РR6). */
static void session_init(struct redis_conn *rc, bool synthetic)
{
    if (redis_cfg.no_user)
        rc->session.user[0] = '\0';
    if (synthetic) {
        /* A connection joined mid-stream: its `SELECT` and its `AUTH` happened
         * before we were watching, so both labels are unknowable and say so
         * (РR5 — `db="?"`, never `db="0"`, because a wrong `0` is indis-
         * tinguishable from a right one on a dashboard). `redis/midstream.lkt`
         * is recorded by starting the client first, precisely so that this path
         * is exercised by real traffic and not only by a test. */
        memcpy(rc->session.database, "?", 2);
        if (!redis_cfg.no_user)
            memcpy(rc->session.user, "?", 2);
        return;
    }
    memcpy(rc->session.database, "0", 2);
    if (!redis_cfg.no_user)
        memcpy(rc->session.user, "default", 8);
}

static void session_set_db(struct redis_conn *rc, __u16 db)
{
    if (db == LK_REDIS_DB_UNKNOWN)
        memcpy(rc->session.database, "?", 2);
    else
        snprintf(rc->session.database, sizeof(rc->session.database), "%u", db);
}

/* The ACL user, folded to `other` when the name is not one a label may carry.
 * A user name is chosen by an operator and always passes; what does not is a
 * client putting arbitrary bytes where a series name goes, and the S3 rule
 * applies unchanged (РS3) — refuse it, keep the fact that *someone*
 * authenticated, and do not let the wire name a series. */
static void session_set_user(struct redis_conn *rc, const char *p, __u32 n)
{
    if (redis_cfg.no_user)
        return;
    if (!n) {
        /* `AUTH <password>` names nobody: it authenticates as `default`, which
         * is a real answer and not an absence (РR6). */
        memcpy(rc->session.user, "default", 8);
        return;
    }
    if (!lk_redis_user_valid(p, n)) {
        memcpy(rc->session.user, "other", 6);
        return;
    }
    memcpy(rc->session.user, p, n);
    rc->session.user[n] = '\0';
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
    session_init(rc, rc->degraded);
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
 * span a loss or a disconnect) and add the count to *counter.
 *
 * A dropped unit takes its label with it. If a `SELECT` was in flight when the
 * stream was lost, the connection is now in a database we cannot name, and the
 * only two answers are "?" and a number that has a good chance of being wrong —
 * on a dashboard those are indistinguishable, which is precisely why the first
 * one is the right one (РR5, and the same reasoning as `db="?"` for a connection
 * joined mid-stream). */
static void units_drop_all(struct redis_conn *rc, __u64 *counter)
{
    while (rc->head_seq < rc->open_seq) {
        const struct redis_unit *u = &rc->ring[rc->head_seq % LK_REDIS_MAX_INFLIGHT];

        if (u->uflags & (REDIS_U_SELECT | REDIS_U_RESET))
            session_set_db(rc, LK_REDIS_DB_UNKNOWN);
        if ((u->uflags & (REDIS_U_AUTH | REDIS_U_RESET)) && !redis_cfg.no_user)
            memcpy(rc->session.user, "?", 2);
        rc->head_seq++;
        if (counter)
            (*counter)++;
    }
    /* An open transaction goes with them (РR9). Its interval would span the loss
     * — the `EXEC` that ends it may already have gone past unseen — and Р19 is
     * the same rule for a transaction as for a unit: an observation that survived
     * a gap is a plausible number about an unknown stretch of time. */
    rc->txn_start_ns = 0;
    rc->txn_n = 0;
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
    /* Zero is a valid table id (the first command alphabetically), so the
     * identity is set to `other` explicitly rather than left to memset: an
     * observation that lost its classification must say "unknown", not name
     * whichever command happens to sort first. */
    u->cmd = lk_redis_cmd_other();
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
                      const struct redis_unit *u, __u64 seq, const struct redis_reply *r)
{
    __u32 cmd_len;
    const char *cmd = lk_redis_cmd_name(u->cmd, &cmd_len);
    /* The identity of a container command is spelled `CONFIG|GET`, and the `|` is
     * the record that it ate the second element (РR4). So the argument count the
     * unit carries — everything after the verb — loses one here, and loses it in
     * the one place that knows: the classifier may or may not have found a
     * subcommand, and only the name it returned says which (МR6). */
    __u16 argc = memchr(cmd, '|', cmd_len) && u->argc ? (__u16)(u->argc - 1) : u->argc;
    /* The batch this command arrived in is normally still open when its reply
     * comes back — the whole batch is read out of one syscall before the server
     * answers any of it — so the live count is the answer, and the frozen one
     * only for a unit whose batch has since been superseded (РR3). */
    struct lk_redis_obs rr = {
        .pipeline_depth = seq >= rc->batch_seq0 ? rc->batch_n : u->depth,
        /* The size of the transaction this `EXEC` is about to run (МR6), read
         * here because txn_apply clears it immediately after — and read for an
         * `EXEC` alone, since on any other command the number belongs to
         * somebody else's work. */
        .txn_size = (u->uflags & REDIS_U_EXEC) ? rc->txn_n : 0,
        .argc = argc,
        /* The redirect travels to the facade as well as to the stats line
         * (МR5): it has a family of its own, and the whole of РR7 is that it is
         * counted *somewhere* and nowhere near the error rate. */
        .redirect = r->redirect,
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
        .ts_complete_ns = r->end_ns,
        .ts_ready_ns = r->end_ns, /* no separate ready point, as in HTTP */
        .bytes_in = u->bytes,
        .bytes_out = r->bytes,
        .redis = &rr,
        /* A command is its own kind of work (РR11, МR5): not a statement, not
         * an exchange. The value is mirrored into metrics.h as LK_QK_COMMAND,
         * and the redis profile has no `kind` axis to print it on — RESP has
         * one shape of work and the label would be a constant. What reads it is
         * every consumer that switches on the observation's shape. */
        .kind = LK_Q_COMMAND,
        /* The identity (РR4), in the slot S3 puts an operation name in: a value
         * from a closed table, so the `cmd` label's cardinality is a
         * compile-time constant and the top-K dictionary downstream never has to
         * do any bounding at all (риск 7). `route_fp` keys that dictionary, as
         * it does for every protocol with a name rather than a statement.
         *
         * `text` stays absent, and the flag says so. A Redis command's text is
         * its verb *and its arguments*, and the arguments are keys and values —
         * the one thing that never leaves this handler at any setting. МR6 gives
         * the span a `db.query.text` built out of the identity and a `?` per
         * argument, which is the only shape of it that is safe to export. */
        .route = cmd,
        .route_len = cmd_len,
        .route_fp = lk_redis_cmd_fp(u->cmd),
        /* The failure's name (РR7), in the slot the S3 dialect puts an
         * `<Code>` in: a pointer into the static vocabulary of norm_redis.c, so
         * the `error` label is as bounded as the `cmd` one and no part of the
         * server's sentence — which names the key, the slot or the node — can
         * reach a series. NULL when nothing failed. */
        .err_name = r->err_name,
        .flags = (__u16)(u->flags | r->flags | LK_QO_NO_TEXT),
    };

    p->st.queries++;
    if (o.flags & LK_QO_ERROR)
        p->st.errors_sql++;
    if (r->redirect)
        p->st.redirects++;
    if (p->out.on_query)
        p->out.on_query(p->out.ctx, c, &rc->session, &o);
}

/* The transaction interval (РR9). Called with the same reply that closed the
 * unit, straight after the observation, and it is one rule in three lines: a
 * `MULTI` the server accepted opens the interval at the command's first byte,
 * an `EXEC` or a `DISCARD` closes it at the reply's last one.
 *
 * The interval is `MULTI` … the answer to `EXEC` rather than `EXEC` alone
 * because that is the transaction — what the application waited for, and what
 * `latkit_txn_duration_seconds` means for PG and MySQL, where it is likewise the
 * span from the statement that opened one to the status that closed it. That
 * this fits an existing family exactly is the pleasant surprise of the track: a
 * cache with transactions is still a database here.
 *
 * The three endings that are *not* a commit are the reason a bit of the reply is
 * read at all: `-EXECABORT` (a command failed at queue time), `DISCARD`, and a
 * null `EXEC` — a broken `WATCH`, which is a null and not an error, and would
 * otherwise be counted as the one thing it is not (notes-redisproto.md
 * §"Transactions", `redis/watch-abort.lkt`). */
static void txn_apply(struct lk_proto *p, struct lk_conn *c, struct redis_conn *rc,
                      const struct redis_unit *u, const struct redis_reply *r)
{
    bool aborted;

    if (u->uflags & REDIS_U_MULTI) {
        /* Only on success, which is what makes a nested `MULTI` harmless: the
         * server answers `-ERR MULTI calls can not be nested` and the first
         * transaction goes on — so the stamp must not move, or the interval
         * would start at the wrong command (measured, `redis/multi.lkt`). */
        if (!r->err && !rc->txn_start_ns) {
            rc->txn_start_ns = u->ts_start_ns;
            rc->txn_n = 0;
        }
        return;
    }
    /* How big the transaction is, for the `EXEC`'s span (МR6). `+QUEUED` is the
     * server saying "written down", so counting those replies counts what the
     * `EXEC` will actually run — one command per reply, whatever the client
     * pipelined. A command refused at queue time answers an error instead and is
     * rightly not in the tally: it is the reason the `EXEC` will be
     * `-EXECABORT`, not part of the work it does. */
    if ((r->flags & LK_QO_QUEUED) && rc->txn_start_ns) {
        rc->txn_n++;
        return;
    }
    /* `RESET` closes one too, and closes it as thrown away: it returns the
     * connection to a virgin state, transaction included (РR5's twin rule, and
     * the same `+RESET` the session machine waits for). */
    if (!(u->uflags & (REDIS_U_EXEC | REDIS_U_DISCARD | REDIS_U_RESET)))
        return;
    /* `EXEC` with no transaction open is `-ERR EXEC without MULTI`, and a
     * `DISCARD` outside one the same: a real observation, and no interval to
     * report. Also the shape a connection joined mid-stream has, where the
     * `MULTI` happened before we were watching and the honest answer is one
     * transaction missing rather than one measured from an invented start. */
    if (!rc->txn_start_ns || (r->err && !(u->uflags & REDIS_U_EXEC)))
        return;
    aborted = !(u->uflags & REDIS_U_EXEC) || r->err || r->null;
    if (p->out.on_txn)
        p->out.on_txn(p->out.ctx, c, rc->txn_start_ns, r->end_ns, aborted ? 'E' : 'I');
    rc->txn_start_ns = 0;
    rc->txn_n = 0;
}

/* The server has ruled on a command that would move a label (РR5/РR6). Called
 * *after* the observation is emitted, which is the deliberate half of the rule:
 * the `SELECT 3` itself is an observation in the database it was issued from,
 * and only what comes after it is in database 3. Anything else would report a
 * command as belonging to a place it had not reached yet.
 *
 * `err` is the whole of what the reply has to say. Redis answers `+OK`, `+RESET`
 * or a `HELLO` map on success and an error on failure, with nothing in between,
 * so one bit of the reply decides — and taking it from the reply rather than
 * from the command is what makes `SELECT 16` and `-WRONGPASS` behave (measured,
 * `redis/select-db.lkt`, `redis/auth-forms.lkt`). */
static void session_apply(struct redis_conn *rc, const struct redis_unit *u, __u64 seq, bool err)
{
    if (!(u->uflags & (REDIS_U_SELECT | REDIS_U_AUTH | REDIS_U_RESET)) || err)
        return;
    if (u->uflags & REDIS_U_RESET) {
        /* `RESET` puts the connection back to database 0 and user `default` —
         * and out of subscribe mode (redis_command), out of the transaction
         * (txn_apply) and back to RESP2, which needs no state of ours. */
        session_set_db(rc, 0);
        session_set_user(rc, NULL, 0);
        return;
    }
    if (u->uflags & REDIS_U_SELECT)
        session_set_db(rc, u->db);
    if (u->uflags & REDIS_U_AUTH) {
        /* The name was parked on the connection rather than in the unit (see
         * redis.h). If a later `AUTH` superseded it before this one was
         * answered, we know a login succeeded and cannot say whose — which is
         * `user="?"`, the same answer as for a connection joined mid-stream. */
        if (seq == rc->auth_seq)
            session_set_user(rc, rc->auth_user, (__u32)strlen(rc->auth_user));
        else if (!redis_cfg.no_user)
            memcpy(rc->session.user, "?", 2);
    }
}

/* --- what a reply says (РR7, РR9) ------------------------------------------
 * Everything the observation and the two state machines take from a server
 * value, read once, at the moment it arrives. One function because the three
 * questions share the same three bytes of it — the type and the first word —
 * and because a reply that overtook its own command is kept in exactly this
 * shape until the command arrives (see early_claim). */
static struct redis_reply reply_verdict(const struct lk_msg *m, __u64 end_ns)
{
    struct redis_reply r = {.end_ns = end_ns, .bytes = m->len};
    struct lk_redis_arg w;
    struct lk_redis_err e;

    switch (m->type) {
    case REDIS_T_ERROR:
    case REDIS_T_BLOBERR:
        /* RESP2's `-ERR …` and RESP3's blob error are the two shapes a refusal
         * takes; the symbol is in the same place in both. */
        r.err = true;
        w = redis_read_word(m, m->body, m->body_cap);
        e = lk_redis_err(w.p, w.n);
        r.err_name = e.name;
        r.redirect = e.redirect;
        /* A redirect is a *routing* answer, and the flag it carries is the one
         * HTTP gives a 4xx: the request was refused, the server is healthy, and
         * the two facts belong in different counters (РR7). */
        r.flags |= r.redirect ? LK_QO_CLIENT_ERR : LK_QO_ERROR;
        break;
    case REDIS_T_SIMPLE:
        /* `+QUEUED`, and nothing else on the wire looks like it: no command
         * outside a transaction is answered with that word. Read from the reply
         * rather than deduced from a `MULTI` we may not have seen, which is what
         * makes it right on a connection joined mid-stream — and what keeps a
         * queue-time error (`-ERR unknown command`, answered *instead* of
         * `+QUEUED`) an honest error with an honest duration (РR9). */
        w = redis_read_word(m, m->body, m->body_cap);
        if (w.n == 6 && !memcmp(w.p, "QUEUED", 6))
            r.flags |= LK_QO_QUEUED;
        break;
    case REDIS_T_NULL:
        r.null = true;
        break;
    case REDIS_T_ARRAY:
        /* RESP2 spells null `*-1`, and to the framer that is simply an array of
         * no elements — the same thing `*0` is, and rightly so: both are values
         * complete where they stand. Here the difference is the whole answer,
         * because `*-1` from an `EXEC` is a transaction a broken `WATCH` refused
         * and `*0` is one that ran no commands and committed (`redis/multi.lkt`
         * has both). The sign is the only place the two differ, so the sign is
         * what is read. */
        r.null = m->body && m->body_cap > 1 && m->body[1] == '-';
        break;
    default:
        break;
    }
    return r;
}

/* A reply for the oldest unit: emit it, or account for its absence. */
static void unit_close(struct lk_proto *p, struct lk_conn *c, struct redis_conn *rc,
                       const struct lk_msg *m, __u64 end_ns)
{
    struct redis_reply r = reply_verdict(m, end_ns);
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
            rc->early[rc->early_n++] = r;
            return;
        }
        /* Otherwise: a connection joined mid-stream, or a reply arriving after
         * its unit was dropped. Not a parse error — the bytes were fine, we
         * simply never saw the command they answer. */
        redis_orphan(p, rc);
        return;
    }
    unit_emit(p, c, rc, u, rc->head_seq, &r);
    session_apply(rc, u, rc->head_seq, r.err);
    txn_apply(p, c, rc, u, &r);
    rc->head_seq++;
}

/* The command a held reply was waiting for has arrived (see unit_close). It is
 * the front of the queue by construction — nothing was queued when the reply was
 * held — and the guard is there so that "by construction" cannot quietly become
 * "usually". */
static void early_claim(struct lk_proto *p, struct lk_conn *c, struct redis_conn *rc)
{
    struct redis_reply r = rc->early[0];

    if (rc->head_seq + 1 != rc->open_seq) {
        rc->early_n = 0;
        redis_orphan(p, rc);
        return;
    }
    memmove(rc->early, rc->early + 1, sizeof(rc->early[0]) * (__u32)(rc->early_n - 1));
    rc->early_n--;
    unit_emit(p, c, rc, unit_front(rc), rc->head_seq, &r);
    /* The held reply's verdict travels with it, whole: an `AUTH` whose password
     * is long enough to overflow the capture budget is exactly the shape that
     * gets its reply published first, so the session machine has to hear about it
     * here or a password-sized login would move a label it should not — and the
     * same goes for a transaction whose `EXEC` outran a large queued command. */
    session_apply(rc, unit_front(rc), rc->head_seq, r.err);
    txn_apply(p, c, rc, unit_front(rc), &r);
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

/* Park the name a pending `AUTH` would install (see redis.h for why it lives on
 * the connection and not in the unit). Nothing but this function ever copies an
 * identity out of a command, and it copies exactly one element — the *first*
 * argument of the two-argument form, or the name inside `HELLO … AUTH`. The
 * element after it is the password and is not read here, in norm_redis.c, or
 * anywhere else in the tree. */
static void auth_park(struct redis_conn *rc, __u64 seq, struct lk_redis_arg user)
{
    __u32 n = user.n < LK_REDIS_USER_MAX - 1 ? user.n : LK_REDIS_USER_MAX - 1;

    if (user.p)
        memcpy(rc->auth_user, user.p, n);
    else
        n = 0; /* `AUTH <password>`: nobody is named, and `default` is who it is */
    rc->auth_user[n] = '\0';
    rc->auth_seq = seq;
}

static void redis_command(struct lk_proto *p, struct lk_conn *c, struct redis_conn *rc,
                          const struct lk_msg *m, bool batch_first)
{
    struct lk_redis_argv v;
    struct lk_redis_arg user;
    struct redis_unit *u;
    __u32 cflags;
    __u16 id, db;
    __s64 nelem;

    if (batch_first)
        batch_new(rc);
    redis_read_argv(m, m->body, m->body_cap, LK_REDIS_ARGV_LABELS, &v, &nelem);
    /* `*0\r\n` and `*-1\r\n` are complete values that the server answers with
     * *nothing at all*. They must not open a unit: the queue would then be one
     * ahead for the rest of the connection, which is the same corruption a
     * missed push causes, from the other side. */
    if (!nelem)
        return;

    /* The identity (РR4): a lookup in the closed table of norm_redis.c, over the
     * verb and — for the fifteen container commands and nowhere else — the
     * second element. Everything else the command carries is a key, a field, a
     * value or a password, and the classifier is not shown any of it. */
    id = lk_redis_cmd(&v);
    cflags = lk_redis_cmd_flags(id);

    /* The replication handshake (РR14). After it the connection carries an RDB
     * image and then a stream of write commands *from the server*, none of which
     * answers anything — parsing that as replies is not a degradation, it is
     * guaranteed nonsense (notes-redisproto.md §"What is on the port but is not
     * RESP").
     *
     * **Any** `REPLCONF`, not just the `listening-port` of РR14. Only a replica
     * sends the command at all, and the broader rule is what catches the case the
     * corpus actually contains: a replication link joined after its `PSYNC` — the
     * handshake happened before the agent attached, so the only mark left on the
     * wire is the periodic `REPLCONF ACK <offset>`. `libs/java-pipeline.lkt` and
     * `libs/memtier-pipe100.lkt` each carry one beside the traffic they were
     * recorded for, and without this rule the propagated writes on them read as a
     * hundred unanswerable replies. */
    if (cflags & LK_REDIS_C_REPL) {
        ignore_conn(p, c, rc, &p->st.replication_conns);
        return;
    }
    /* `MONITOR`: `+OK`, and then one simple string per command executed by every
     * *other* client on the server. Its own reason, because "somebody is running
     * a replica" and "somebody left a MONITOR open" are different facts about a
     * deployment — and the second is also a performance problem worth seeing on
     * the dashboard (МR5). */
    if (cflags & LK_REDIS_C_MONITOR) {
        ignore_conn(p, c, rc, &p->st.monitor_conns);
        return;
    }
    /* `RESET` returns the connection to a virgin state — out of subscribe mode,
     * out of the transaction, back to RESP2, database 0, user `default`. The
     * subscribe bit goes now because a subscribe-mode misreading corrupts the
     * *queue*; the two labels and the transaction wait for the `+RESET`
     * (session_apply, txn_apply), because a label that moved before the server
     * agreed would be a lie for as long as this connection lives. */
    if (cflags & LK_REDIS_C_RESET)
        rc->sub = false;
    else if (cflags & LK_REDIS_C_SUBON)
        rc->sub = true;

    rc->batch_n++;
    u = unit_open(p, rc, m->ts_ns);
    if (!u) {
        rc->owed++;
        return;
    }
    rc->degraded = false;
    u->bytes = m->len;
    u->cmd = id;
    /* How many elements followed the verb, which is everything МR6 exports about
     * them (РR11): `db.query.text` is the identity with one `?` per argument, and
     * a count is the only thing about a key or a value that a span may carry.
     *
     * The count comes from the *declared* element count in the value's header, so
     * a command whose tail the capture budget cut off still reports its real
     * arity — the header is the one part of a 1 KB `SET` that is always in the
     * prefix. An inline command has no header, and there the answer is the words
     * on the line — which is its arity for `PING` and `INFO server`, the shapes
     * inline traffic actually has, and only approximately so for the two
     * curiosities the corpus keeps: past LK_REDIS_ARGV_LABELS words it stops
     * counting, and `SET "a b" "c d"` counts four because the reader does not
     * interpret quotes (deliberately — redis_frame.c). A blank-separated word
     * count is what it is, and the alternative is a parser for a shape only a
     * human at a terminal produces. The subcommand of a container is not an
     * argument but half the identity, and is taken off at the emit, where the
     * identity is already expanded and says whether it swallowed one. */
    {
        __s64 args = (nelem >= 0 ? nelem : (__s64)v.n) - 1;

        u->argc = args <= 0 ? 0 : (args > 0xffff ? 0xffff : (__u16)args);
    }
    if (cflags & LK_REDIS_C_SUBFAM)
        u->uflags |= REDIS_U_SUB;
    /* The transaction (РR9). Recorded on the unit for the same reason the labels
     * are: whether a `MULTI` opened anything is the server's answer, not the
     * client's request — a nested one is refused and the transaction already
     * running is untouched. */
    if (cflags & LK_REDIS_C_MULTI)
        u->uflags |= REDIS_U_MULTI;
    else if (cflags & LK_REDIS_C_EXEC)
        u->uflags |= REDIS_U_EXEC;
    else if (cflags & LK_REDIS_C_DISCARD)
        u->uflags |= REDIS_U_DISCARD;

    /* Blocking (РR10), decided from the command because that is where the answer
     * is: `BLPOP key 30` is a thirty-second observation the moment it is sent,
     * whatever it returns. `XREAD`/`XREADGROUP` are the two the server's own flag
     * gets wrong — they block only with a `BLOCK` keyword — and the deeper read
     * is done for them alone, since the keyword sits behind `GROUP g c` and an
     * optional `COUNT n`. That read is the *only* place in the tree an argument
     * past the identity is looked at, it looks for a keyword and never at a
     * value, and it stops at `STREAMS` so that a stream named `BLOCK` stays a
     * key. */
    if (cflags & LK_REDIS_C_BLOCKING) {
        struct lk_redis_argv deep;

        if (cflags & LK_REDIS_C_ARGBLOCK)
            redis_read_argv(m, m->body, m->body_cap, LK_REDIS_ARGV_MAX, &deep, NULL);
        if (lk_redis_cmd_blocking(id, (cflags & LK_REDIS_C_ARGBLOCK) ? &deep : &v))
            u->flags |= LK_QO_BLOCKING;
    }

    /* What this command would do to the labels, if the server accepts it
     * (РR5/РR6). The candidate is recorded on the unit and applied when the
     * reply arrives — never here. */
    switch (lk_redis_session(id, &v, &db, &user)) {
    case LK_REDIS_SESS_DB:
        u->uflags |= REDIS_U_SELECT;
        u->db = db;
        break;
    case LK_REDIS_SESS_USER:
        u->uflags |= REDIS_U_AUTH;
        auth_park(rc, rc->open_seq - 1, user);
        break;
    case LK_REDIS_SESS_RESET:
        u->uflags |= REDIS_U_RESET;
        break;
    case LK_REDIS_SESS_NONE:
        break;
    }

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
    struct lk_redis_argv v;

    /* An attribute is not a reply and never closes a unit — it decorates the
     * value that comes after it. Closing one would answer this command with the
     * decoration and the next command with this command's reply, for ever
     * (measured, `redis/types3.lkt`). */
    if (m->type == REDIS_T_ATTR)
        return REDIS_R_ATTR;
    if (m->type == REDIS_T_PUSH) {
        redis_read_argv(m, m->body, m->body_cap, 1, &v, NULL);
        /* RESP3: the confirmation of a SUBSCRIBE *is* a push, so the type byte
         * alone cannot decide. The kind word can, and it decides for RESP2 too. */
        return (v.n && kind_is_confirm(v.a[0])) ? REDIS_R_CONFIRM : REDIS_R_PUSH;
    }
    if (m->type == REDIS_T_ARRAY && rc->sub) {
        /* RESP2: a delivery and an ordinary array are the same type byte, so the
         * kind word is read *only* on a connection known to have subscribed —
         * otherwise a `LRANGE` returning the word "message" would be swallowed
         * as somebody's publication. */
        redis_read_argv(m, m->body, m->body_cap, 1, &v, NULL);
        if (v.n && kind_is_delivery(v.a[0]))
            return REDIS_R_PUSH;
        if (v.n && kind_is_confirm(v.a[0]))
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
