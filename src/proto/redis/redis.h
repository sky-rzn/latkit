/* SPDX-License-Identifier: GPL-2.0 */
/* Internals shared by the RESP framer (redis_frame.c) and the handler
 * (redis.c), the way pg.h / my.h / http.h serve their protocols. Not included
 * by the core: the outside world sees only lk_proto_redis_ops and
 * lk_proto_redis_new (proto.h).
 *
 * PLAN-REDIS.md МR1 filled in the framer — the value machine of РR2, the
 * synthetic message dictionary below, the two resync anchors. МR2 added the
 * other half: the in-flight unit queue, the four timings, the pub/sub rule and
 * the service connections that are not a request/response stream at all (РR3,
 * РR8, РR14). МR3 gives an observation its identity and its labels — the
 * command table of РR4, the database of РR5 and the ACL user of РR6, all three
 * out of src/norm/norm_redis.c, plus the `mask_body` hook that keeps a password
 * out of every viewer. МR4 adds what an observation's *outcome* is: the symbolic
 * error and the redirect that is not one (РR7), the transaction interval (РR9),
 * and the commands whose latency is the client's own choice (РR10). МR6 adds the
 * two numbers a *span* needs and a label may not have: how many arguments a
 * command had (never what they were — that is `db.query.text` as `GET ?`) and
 * how many commands an `EXEC` committed.
 *
 * **Redis is a new protocol, not a dialect.** RESP has no heads, no statuses
 * and no routes, so the `struct lk_http_dialect` seam (РH8) does not apply and
 * is not reused. What *is* reused is everything else the two tracks before it
 * built: the stream mode of the protocol vtable (РH1), the reassembly slab pool
 * for bulk scratch (Р11), lk_reasm_emit / lk_reasm_resync and their counters,
 * and — from МR2 on — the in-flight unit queue and the metric-profile
 * machinery.
 *
 * The split of state is the one РH1 set up: *framing* state lives in
 * lk_conn.frame_state (struct redis_frame below, one flat allocation freed by
 * the connection table on every removal path), *semantic* state in
 * lk_conn.proto_state (struct redis_conn, freed by the handler). The bulk
 * scratch — the prefix of a value that spans capture events — is neither: it
 * lives in lk_frame.buf, drawn from the reassembly slab pool, so Р11's memory
 * bound covers it. */
#ifndef LATKIT_REDIS_H
#define LATKIT_REDIS_H

#include "norm_redis.h" /* the identity table and the session rules (РR4–РR6) */
#include "proto.h"
#include "redis_wire.h"

/* --- the message dictionary (РR2) ------------------------------------------
 * One lk_msg per **top-level RESP value**, whatever it nests: `*3\r\n$3\r\nSET
 * …` is one message and so is `+OK\r\n`. That is the unit the protocol
 * actually has — a command is one value and its answer is one value — and
 * publishing anything smaller would push the aggregate arithmetic into every
 * consumer.
 *
 *   <type byte>  a RESP value. `type` is its first byte verbatim, so the
 *                fourteen of redis_wire.h are the dictionary and nothing has to
 *                be invented for them; `len` is the value's **whole size on the
 *                wire** in bytes, terminators and nested elements included,
 *                saturated at u32; `body` is a prefix of those very bytes,
 *                bounded by LK_MSG_BODY_MAX and by what the capture budget let
 *                through (РR13 asks for 512 bytes a call, so a large reply is
 *                normally a prefix). LK_MSG_BODY_TRUNC says body_cap < len,
 *                which on this protocol is the common case rather than an
 *                anomaly. The payload of a bulk is *skipped arithmetically* and
 *                is in the body only because it happened to be inside the
 *                prefix — nothing reads it (РR4)
 *   'i'          an inline command: `PING\r\n` from telnet, a healthcheck
 *                script or a load balancer's TCP probe. Not RESP at all, so it
 *                cannot carry a RESP type byte, and a synthetic one keeps it a
 *                message like any other: `len` and `body` are the raw line
 *                including its terminator. An empty line is *not* a command
 *                (the server answers nothing) and produces no message at all
 *   '?'          a framer note: `len` is an enum lk_redis_note, `body` is NULL.
 *                Degradations in the message stream rather than in a side
 *                channel — visible in --messages, replayable, and turned into
 *                counters by the handler without the framer needing a stats
 *                object of its own (the РH3 pattern; '!' cannot be borrowed for
 *                it here, being RESP3's blob error)
 *
 * Two consequences worth naming, because МR2 depends on both. An `|` attribute
 * arrives as its own message and must not close a unit — it is a prefix to the
 * value that follows (measured, `redis/types3.lkt`). And a frontend `*0\r\n` or
 * `*-1\r\n` is a complete value that the server answers with *nothing*, so it
 * must not open one. */
#define LK_REDIS_MSG_INLINE 'i'
#define LK_REDIS_MSG_NOTE   '?'

/* Note codes, carried in lk_msg.len of a '?' message. */
enum lk_redis_note {
    LK_REDIS_NOTE_BAD_TYPE = 1,   /* a byte that is not a type byte where a value
                                     must start (backend only: on the frontend the
                                     same byte is an inline command) */
    LK_REDIS_NOTE_BAD_LEN,        /* bulk length / element count unparsable or out
                                     of range — `$abc`, `$536870913`, `*2147483648`,
                                     each of which the server itself answers with a
                                     protocol error and a hang-up */
    LK_REDIS_NOTE_BULK_EOL,       /* a bulk payload was not followed by CRLF: the
                                     declared length did not match the wire, so
                                     everything after it would be misread */
    LK_REDIS_NOTE_LINE_TOO_BIG,   /* a line past LK_REDIS_LINE_MAX with no CRLF */
    LK_REDIS_NOTE_INLINE_TOO_BIG, /* an inline request past the server's own 64 KB
                                     limit, where it answers and closes */
    LK_REDIS_NOTE_DEPTH,          /* aggregates nested past LK_REDIS_MAX_DEPTH.
                                     A degradation, never a verdict: `COMMAND DOCS`
                                     measures 13 deep and a Lua script can return
                                     any depth at all (МR0 recon item 6) */
    LK_REDIS_NOTE_VALUE_HOLE,     /* a capture hole landed somewhere a length could
                                     not skip it: a header line, or inside an
                                     aggregate, which has no length to skip by.
                                     Risk 1 of the plan, in the message stream */
    LK_REDIS_NOTE_NO_MEM,         /* framer state allocation failed */
    LK_REDIS_NOTE_MAX
};

/* Notes that mean "a field on the wire was rejected as corrupt" — the handler
 * routes exactly these to latkit_parse_errors_total, so the МR1 acceptance
 * criterion (parse_errors == 0 over the clean МR0 traces) measures what it
 * claims to. The rest are degradations of *capture* or of our own bounds, not
 * of the input: a hole is the budget, a depth overflow is our stack, and
 * neither says the server got anything wrong. */
#define LK_REDIS_NOTE_IS_PARSE_ERR(n)                                                              \
    ((n) == LK_REDIS_NOTE_BAD_TYPE || (n) == LK_REDIS_NOTE_BAD_LEN ||                              \
     (n) == LK_REDIS_NOTE_BULK_EOL || (n) == LK_REDIS_NOTE_LINE_TOO_BIG ||                         \
     (n) == LK_REDIS_NOTE_INLINE_TOO_BIG)

/* --- framing state (lk_conn.frame_state, РH1) ----------------------------- */

/* Aggregate nesting the framer will follow. РR2 proposed 8 on the reasoning
 * that real replies never nest deeper than 4; МR0 measured `COMMAND DOCS` at
 * **13** — and it is the first command an interactive `redis-cli` sends, before
 * the prompt appears — `COMMAND` at 9 and `XINFO STREAM FULL` at 8. A Lua
 * script can return any depth at all, so no bound is universal and the right
 * answer is a generous one plus a graceful degradation: past the bound the
 * framer stops descending, says so ('?' + LK_REDIS_NOTE_DEPTH) and
 * resynchronises on the next call boundary. Treating depth as evidence of
 * corruption would declare a human opening redis-cli to be a corrupt stream. */
#define LK_REDIS_MAX_DEPTH 32

/* Per-direction machine. Four of the five states are the four shapes a value
 * can take (redis_wire.h); REDIS_FR_SCAN is the dirty state, kept in lock-step
 * with lk_frame.st == LK_FR_DIRTY so that the connection table's seq detector
 * and the framer's own losses share one flag, one counter and one
 * LK_MSG_AFTER_RESYNC stamp. */
enum redis_fr_st {
    REDIS_FR_VALUE = 0, /* at the start of a value, at any depth */
    REDIS_FR_LINE,      /* accumulating a line up to CRLF */
    REDIS_FR_BULK,      /* skipping bulk_left payload bytes arithmetically */
    REDIS_FR_BULK_EOL,  /* the CRLF that closes a bulk payload */
    REDIS_FR_INLINE,    /* accumulating an inline command line up to LF */
    REDIS_FR_SCAN,      /* sync lost: waiting for a call boundary + an anchor */
};

struct redis_dir {
    __u8 st;                    /* enum redis_fr_st */
    __u8 shape;                 /* enum redis_vshape of the value whose line is being read */
    __u8 depth;                 /* aggregates open above the current value */
    __u8 call_new;              /* a syscall boundary has passed and no value has started
                                   since: the next one to start opens a batch (РR3) */
    __u8 v_call;                /* ... and that is what the open value did. Read by the
                                   handler at the emit — see the note on the side channel
                                   below */
    __u8 saw_cr;                /* LINE: the previous byte was CR */
    __u8 num_n;                 /* digits kept in num[] */
    __u8 num_bad;               /* ... and the line is known not to be a number anyway */
    __u8 vtype;                 /* type byte of the top-level value being assembled */
    __u8 eol_left;              /* BULK_EOL: bytes of the trailing CRLF still owed */
    __u8 lost_prefix;           /* the slab could not be borrowed: this value is framed
                                   correctly and published without a body, rather than
                                   with a body missing an unknown middle */
    __u8 inline_arg;            /* INLINE: the line holds at least one non-blank byte, so
                                   it is a command and not the whitespace the server
                                   answers nothing to */
    char num[LK_REDIS_NUM_MAX]; /* the length line's digits, for the parse */
    __u32 line_n;               /* bytes of the current line so far (bound check) */
    __u32 cur;                  /* offset in the chunk being fed at which the open
                                   value's not-yet-stashed bytes begin */
    __u64 bulk_left;            /* BULK: payload bytes still to skip */
    __u64 v_pos;                /* stream position of the open value's first byte */
    __u64 v_ts;                 /* event of that byte (Р13) */
    __u64 cbase;                /* stream position of the chunk being fed */
    __u64 last_ts;              /* most recent event here (holes borrow it) */
    __u64 off;                  /* bytes fed to the framer, captured or holed */
    __u64 events, holes;
    __u32 stack[LK_REDIS_MAX_DEPTH]; /* elements still owed at each open level */
};

/* Stream-framer state — the owner of lk_conn.frame_state (РH1). One flat
 * allocation covering both directions, taken lazily on the connection's first
 * captured bytes and freed by the connection table on every removal path;
 * nothing inside may own a pointer (conn_table.h).
 *
 * Its size is worth watching, because it is per connection and the table's
 * ceiling is 65536: 480 bytes, of which the two 32-deep stacks are 256. That is
 * twice the HTTP framer's 216 and the depth is where it goes — the price of
 * following `COMMAND DOCS` instead of declaring it corrupt. At the ceiling it
 * is ~31 MB, allocated only for connections that actually carry bytes, and
 * bounded by the same max_conns knob rather than by anything a client can
 * inflate. */
struct redis_frame {
    struct redis_dir d[2]; /* index: enum lk_dir */
};

/* --- handler state (lk_conn.proto_state, Р15) ----------------------------- */

/* In-flight commands the reply direction matches against (РR3). RESP has no
 * request id and no sequence number: **order is the only correspondence the
 * protocol offers**, so a FIFO is not an optimisation here, it is the entire
 * mechanism — and everything unsolicited on the wire has to be recognised as
 * such or the queue slides by one and every latency after it is a plausible
 * lie (РR8).
 *
 * 256 because МR0 measured what clients really do: an application with a
 * connection pool pipelines at depth 1, a batching one at exactly the depth it
 * asked for, and the deepest measured batch is memtier's 100
 * (notes-redisproto.md §"Pipelining is the normal mode"). Past the ring the
 * newest command is dropped into units_dropped_overflow and its reply is
 * skipped by count, exactly as in HTTP — the units still queued keep pairing
 * correctly, which is what makes an overflow a degraded stretch rather than a
 * wrong answer. */
#define LK_REDIS_MAX_INFLIGHT 256

/* Risk 4 of the plan, second line of defence. Pub/Sub and RESP3 pushes are
 * recognised, but Redis has other ways to put a value on the wire that answers
 * nothing (`-UNBLOCKED`, a keyspace notification, an admin's `CLIENT KILL`), and
 * one unrecognised one would leave the queue permanently one behind. A queue
 * that has been non-empty for longer than any sane blocking command is therefore
 * flushed rather than trusted: `BLPOP key 0` blocks for ever and is legal, so
 * the answer is to drop the units, not the connection (notes-redisproto.md
 * §"Timeouts"). */
#define LK_REDIS_UNIT_TIMEOUT_NS (30ull * 1000000000ull)

/* redis_unit.uflags — what the *handler* knows about a command, as opposed to
 * what the observation carries. Kept apart from the LK_QO_* word so that neither
 * space has to leave room for the other.
 *
 * The three session bits are the mechanism behind РR5/РR6's one rule: **a label
 * moves on the reply, never on the command.** `SELECT 16` is an error and stays
 * in the previous database, `AUTH lkuser wrongpass` is `-WRONGPASS` and leaves
 * the user alone (measured, `redis/select-db.lkt` and `redis/auth-forms.lkt`),
 * so what the command carries is a *candidate* and the unit is what holds it
 * until the server rules on it. */
/*   SUB     a (P|S)(UN)SUBSCRIBE: its reply is a confirmation, and only such a
 *           unit may be closed by one (РR8)
 *   SELECT  a `SELECT`: on `+OK`, unit.db becomes the label
 *   AUTH    an `AUTH` / `HELLO … AUTH`: on success, the name parked in
 *           redis_conn.auth_user becomes the label
 *   RESET   a `RESET`: on `+RESET`, database 0 and user `default`, whatever
 *           they were
 *
 * The three transaction bits are the same shape of rule for РR9's interval: a
 * `MULTI` opens one only if the server says `+OK` (a nested `MULTI` is
 * `-ERR MULTI calls can not be nested` and the first transaction survives
 * untouched), and an `EXEC` closes one whatever it answers — the array it
 * committed, an `-EXECABORT`, or the null that says a `WATCH` was broken.
 *
 *   MULTI   opens the interval at this command's first byte
 *   EXEC    closes it at this reply's last byte
 *   DISCARD ... and so does this, as `aborted` */
#define REDIS_U_SUB     (1 << 0)
#define REDIS_U_SELECT  (1 << 1)
#define REDIS_U_AUTH    (1 << 2)
#define REDIS_U_RESET   (1 << 3)
#define REDIS_U_MULTI   (1 << 4)
#define REDIS_U_EXEC    (1 << 5)
#define REDIS_U_DISCARD (1 << 6)

/* What a reply says about the command it closes — everything the observation and
 * the two state machines need out of it, read once at the moment the value
 * arrives (МR4). One struct rather than five out-parameters because a reply is
 * sometimes read long before it is used: a value that overtook its own command
 * (see below) is held in exactly this shape until the command shows up.
 *
 * `err_name` is a pointer into the static vocabulary of norm_redis.c and never
 * into the wire, which is what makes "an error message never becomes a label" a
 * property of the type rather than a promise: the sentence after the symbol
 * holds the key that had the wrong type and the node a `MOVED` points at, and
 * there is nowhere for it to be copied to. */
struct redis_reply {
    const char *err_name; /* the symbolic error (РR7); NULL = not a refusal */
    __u64 end_ns;         /* the reply's last byte (Р13, and not its first: a
                             17 MB `KEYS *` takes 212 events) */
    __u32 bytes;          /* its whole size on the wire */
    __u16 flags;          /* LK_QO_ERROR / LK_QO_CLIENT_ERR / LK_QO_QUEUED */
    __u8 redirect;        /* enum lk_redis_redirect (РR7) */
    bool err;             /* a refusal, which is what the session machine of МR3
                             needs: `-WRONGPASS` moves no label */
    bool null;            /* a null value — the one thing an `EXEC` says with no
                             error at all: a broken `WATCH` answers `*-1` (RESP2)
                             or `_` (RESP3), and that is an aborted transaction
                             rather than a failed command (РR9) */
};

/* Replies that arrived before the command they answer, which sounds impossible
 * and is not: a command larger than the per-call capture budget (РR13 makes that
 * 512 bytes, so a `SET` of a one-kilobyte value qualifies) has an uncaptured
 * tail, and Р9's chunk layer only learns that tail existed when the *next* call
 * on that direction starts. The value is therefore published late — after the
 * reply to it has already gone by. Without a memo the pairing would slip by one
 * and stay slipped for the life of the connection, which is the one failure mode
 * this whole file exists to prevent: every later observation would be a
 * plausible number belonging to the wrong command.
 *
 * Four slots because only the *last* value of a call can be left open, so one
 * is the realistic depth and four is the room for a pipeline of them; past that
 * the reply is an orphan and says so. */
#define LK_REDIS_MAX_EARLY 4

/* One command in flight. Deliberately small — the ring is 256 slots on every
 * connection that carries a command, and at the table's ceiling of 65536 that
 * is the difference between 6 MB and 400 MB of steady state. Everything that
 * would grow it is either already known when the unit closes (the reply's size,
 * its type) or belongs to the observation and not to the queue.
 *
 * МR3's identity fits in the two bytes of `cmd` for exactly that reason: the
 * table is closed, so a command is an *index* into it and not a pointer and a
 * length. The name, the fingerprint and the bits are expanded from the index
 * when the unit closes — the whole struct stays at 24 bytes, which is what it
 * was before that milestone, and МR6's `argc` fits in the padding that was
 * already there rather than costing the ring a byte. */
struct redis_unit {
    __u64 ts_start_ns; /* first byte of the command (Р13) */
    __u32 bytes;       /* the command's whole size on the wire */
    __u16 flags;       /* accumulated LK_QO_* */
    __u16 depth;       /* commands in this one's batch, frozen when the batch
                          ended; while the batch is still open the live count in
                          redis_conn.batch_n is the answer (РR3) */
    __u16 cmd;         /* the identity: an id in the norm_redis table (РR4) */
    __u16 db;          /* REDIS_U_SELECT: the database this command would move the
                          connection to, applied only if the server accepts it */
    __u16 argc;        /* elements after the identity, saturated at 0xffff: what
                          МR6's `db.query.text` renders one `?` each of. A count
                          and not a copy — the elements themselves are read by
                          nothing past the identity (РR4/РR11) */
    __u8 uflags;       /* REDIS_U_* */
};

/* Per-connection handler state, allocated lazily on the first message and freed
 * in on_conn_close (Р15).
 *
 * The ring is addressed by a monotonic sequence rather than by index, as in the
 * HTTP handler: "is this unit still the one I saw" then costs a comparison
 * instead of a generation counter, and a stale reference cannot be followed into
 * whatever now occupies the slot.
 *
 * Size, since this is per connection: 6.4 KB, of which the 256-slot ring is 6 KB
 * — the same order as the HTTP handler's 5.5 KB, and allocated only for
 * connections that actually carry a message. МR3's labels cost 72 bytes of it
 * and the ring not a byte, because an identity is a table index and not a name
 * (see struct redis_unit). Nothing in it is owned by pointer, so the close hook
 * is one free(). */
struct redis_conn {
    struct lk_session session; /* the database in `database`, the ACL user in `user`
                                  (РR5/РR6) — the same two dim slots PG fills from
                                  its startup packet, filled here by a state machine
                                  because in RESP both are connection state that
                                  moves mid-stream */
    __u64 msgs;                /* messages dispatched on this connection */

    /* The name a pending `AUTH` would install, parked here rather than in the
     * unit: a 64-byte label copy in every one of 256 ring slots would cost 16 KB
     * per connection to hold a value that at most one command in flight can
     * have. `auth_seq` says which unit owns it, so a second `AUTH` issued before
     * the first was answered simply supersedes it — pipelining two logins is not
     * a thing any client does, and the honest failure if one did is that the
     * older answer moves no label. */
    char auth_user[LK_REDIS_USER_MAX];
    __u64 auth_seq;

    struct redis_unit ring[LK_REDIS_MAX_INFLIGHT];
    __u64 head_seq;   /* oldest live unit: the one the next reply answers */
    __u64 open_seq;   /* next seq to hand out; live units are [head_seq, open_seq) */
    __u64 batch_seq0; /* first unit of the batch being filled; units from it read
                         their depth live out of batch_n, older ones out of the
                         value frozen into them when their batch ended */
    __u32 batch_n;    /* commands seen so far in the batch being filled */
    __u32 owed;       /* replies still owed for commands the ring could not hold.
                         Replies arrive in command order, so the untracked commands
                         are the newest and their replies come last — which is what
                         makes a plain counter sufficient (РR3) */

    struct redis_reply early[LK_REDIS_MAX_EARLY]; /* replies that overtook their
                                                     own command's publication */
    __u8 early_n;

    /* The open transaction's first byte — the `MULTI`, not the first command
     * inside it — or 0 for no transaction (РR9). What `latkit_txn_duration_
     * seconds` measures on a Redis is `MULTI` … the reply to `EXEC`, which is
     * the interval the application waited and the one a database's transaction
     * family already means everywhere else in the agent.
     *
     * One stamp and no queue: `MULTI` inside `MULTI` is refused by the server, so
     * a connection has at most one transaction open, and the commands in between
     * are ordinary units that happen to be answered `+QUEUED`. */
    __u64 txn_start_ns;

    /* ... and how many of those there have been (МR6). Counted from the
     * `+QUEUED` replies rather than from the commands sent, for the same reason
     * the interval is: what the transaction will run is what the server wrote
     * down, and a command refused at queue time (`-ERR unknown command`) is not
     * in it. Read by the `EXEC`'s observation, which is emitted before the
     * transaction machine clears the pair. */
    __u32 txn_n;

    bool sub;      /* the connection has subscribed, so an array whose first element
                      is a pub/sub kind word is a delivery or a confirmation rather
                      than an ordinary reply (РR8). In RESP3 the `>` type says it
                      without state; in RESP2 nothing does, and reading kind words
                      out of *every* array would misread a `LRANGE` that happens to
                      hold the word "message" */
    bool degraded; /* joined mid-session (synthetic entry, or after a resync):
                      nothing here is a trustworthy boundary until the framer
                      vouches for one again */
};

/* --- redis_frame.c: the framer -------------------------------------------- */

void redis_stream_bytes(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, const __u8 *p,
                        __u32 n, __u64 ts_ns);
void redis_stream_hole(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, __u64 n);

/* Unwrap the leading elements of a published value into the (pointer, length)
 * pairs src/norm/norm_redis.c classifies (РR4). RESP knowledge, so it lives with
 * the framer, and it is deliberately the *only* thing in the tree that turns a
 * value's bytes into elements — the handler reading a verb and the viewer hiding
 * a password have to agree byte for byte about where element 2 begins, and one
 * reader is how that is guaranteed rather than hoped for.
 *
 * `max` is how many elements the caller has a use for, and the two callers want
 * different numbers: the handler needs LK_REDIS_ARGV_LABELS on every command it
 * sees, the display mask needs LK_REDIS_ARGV_MAX on the rare message somebody
 * prints. Bounding the walk at the call site is what keeps the hot path paying
 * only for what it reads.
 *
 * `body`/`cap` are passed in rather than taken from `m` so that the mask can run
 * over the viewer's own copy and get spans into *it* (proto.h's
 * lk_msg_body_for_display never touches the framer's buffer). `nelem` receives
 * the declared element count of the top-level aggregate, or -1 when the value is
 * not one — the empty command `*0\r\n`, which is complete, answered with nothing
 * and must open no unit, is `nelem == 0`.
 *
 * Reads only what is inside the prefix: under the 512-byte per-port budget of
 * РR13 that is all of a command's head and none of a large value's tail, and an
 * element the prefix cuts in half yields no element at all rather than a short
 * one. Half a verb is not a verb. */
void redis_read_argv(const struct lk_msg *m, const __u8 *body, __u32 cap, __u32 max,
                     struct lk_redis_argv *v, __s64 *nelem);

/* The first blank-delimited word of a *scalar* value's text (МR4). Two questions
 * in one reader, because on the wire they are one shape:
 *
 *   - the **symbol** of an error, which is its identity (РR7): `-WRONGTYPE
 *     Operation against…` and RESP3's `!21\r\nWRONGPASS invalid…` both yield the
 *     first word and nothing after it. What follows is a sentence for a human
 *     and holds a key, a slot, a node address — none of which may become a label.
 *   - the **word** of a status, which is how a `+QUEUED` is told from an `+OK`
 *     (РR9): a command inside a transaction is answered in microseconds and its
 *     duration means nothing, and that answer is the only place on the wire that
 *     says so.
 *
 * An empty token when the value is not scalar or the prefix does not hold a
 * complete one — half a symbol is not a symbol, exactly as half a verb is not a
 * verb in redis_read_argv. */
struct lk_redis_arg redis_read_word(const struct lk_msg *m, const __u8 *body, __u32 cap);

/* The `mask_body` hook of lk_proto_ops (РH3/РR6): blank the password in an
 * `AUTH` or a `HELLO … AUTH` before a viewer prints the body. Runs on the
 * viewer's copy — the handler downstream still has to read the very element this
 * hides, which is why masking at framing time would make `--redis-user acl`
 * silently do nothing. Redis's own `MONITOR` feed sets the precedent, printing
 * `"AUTH" "(redacted)" "(redacted)"`.
 *
 * This is the first protocol in the tree that needs the hook at all: PG and
 * MySQL authenticate in an exchange the framer never republishes, and HTTP's
 * credentials are headers. Here the password is an ordinary array element in an
 * ordinary command, indistinguishable in shape from a key. */
void redis_mask_body(const struct lk_msg *m, __u8 *p, __u32 n);

/* --- the framer -> handler side channel (МR2) ------------------------------
 * Two facts a unit needs are properties of the *capture* rather than of the byte
 * stream, and neither may travel in lk_msg:
 *
 *   - **where the syscall boundaries were.** The batch depth of РR3 is by
 *     definition "how many commands came out of one recvmsg", so a flag on the
 *     message would make the message stream depend on where the stream was cut —
 *     and "the same bytes cut anywhere produce the same messages" is the
 *     invariant МR1 was accepted on (test_redis_stream.c). The framer keeps the
 *     mark in its own state, where being call-shaped is the point.
 *   - **when the value's last byte arrived.** lk_msg.ts_ns is the event of the
 *     *first* byte (Р13, and every protocol before this one wants it that way),
 *     but a unit closes when the server has finished writing — a 17 MB `KEYS *`
 *     reply takes 212 events (`redis/keys-1m.lkt`), and timing it to its first
 *     one would report the server as faster than it was.
 *
 * Both are read straight off redis_dir during the on_msg call, which is
 * synchronous inside the framer's own emit — the fields are current exactly
 * then and nowhere else. */
static inline const struct redis_dir *redis_dir_of(const struct lk_conn *c, enum lk_dir dir)
{
    const struct redis_frame *rf = c->frame_state;

    return rf ? &rf->d[dir] : NULL;
}

/* Is a value being assembled on this direction right now? The framer needs it to
 * decide whether the tail of a chunk has to be kept; the handler needs it to
 * recognise a reply that overtook its own command (see redis.c, "the early
 * reply"). */
static inline bool redis_value_open(const struct redis_dir *rd)
{
    switch (rd->st) {
    case REDIS_FR_LINE:
    case REDIS_FR_BULK:
    case REDIS_FR_BULK_EOL:
    case REDIS_FR_INLINE:
        return true;
    case REDIS_FR_VALUE:
        return rd->depth != 0;
    default:
        return false;
    }
}

#endif /* LATKIT_REDIS_H */
