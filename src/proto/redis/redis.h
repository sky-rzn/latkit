/* SPDX-License-Identifier: GPL-2.0 */
/* Internals shared by the RESP framer (redis_frame.c) and the handler
 * (redis.c), the way pg.h / my.h / http.h serve their protocols. Not included
 * by the core: the outside world sees only lk_proto_redis_ops and
 * lk_proto_redis_new (proto.h).
 *
 * PLAN-REDIS.md МR1 fills in the framer — the value machine of РR2, the
 * synthetic message dictionary below, the two resync anchors — and leaves the
 * handler at a tally, exactly as PLAN-HTTP.md М1 did: the unit queue, the
 * pub/sub rule (РR3, РR8) are МR2's, the command table and the session labels
 * (РR4–РR6) МR3's.
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

/* МR1 keeps a tally and the one bit МR2 needs from the start: whether this
 * connection was joined mid-stream, in which case no boundary before the next
 * resync can be vouched for. The unit ring, the pub/sub mode, the database and
 * the ACL user land here in МR2/МR3. */
struct redis_conn {
    struct lk_session session; /* db -> database, ACL user -> user (МR3, РR5/РR6) */
    __u64 msgs;                /* messages dispatched on this connection */
    bool degraded;             /* joined mid-session (synthetic entry, or after a
                                  resync): nothing here is a trustworthy boundary
                                  until the framer vouches for one again */
};

/* --- redis_frame.c: the framer -------------------------------------------- */

void redis_stream_bytes(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, const __u8 *p,
                        __u32 n, __u64 ts_ns);
void redis_stream_hole(struct lk_reasm *r, struct lk_conn *c, enum lk_dir dir, __u64 n);

#endif /* LATKIT_REDIS_H */
