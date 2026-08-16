// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the RESP framer (PLAN-REDIS.md МR1, src/proto/redis/) — the
 * test_reassembly.c / test_my_frame.c / test_http_frame.c matrix rerun over
 * lk_proto_redis_ops, the second protocol in stream mode, plus the cases only a
 * protocol framed by *values* has.
 *
 * The matrix, in the order МR1 lists it: nesting and the element stack,
 * overflowing that stack, inline commands, a huge bulk crossing a capture hole,
 * torn values, the null forms of both versions, corrupt lengths, and the two
 * resync anchors.
 *
 * Three properties are asserted throughout rather than in one test, because
 * they are what the framer exists to guarantee:
 *
 *   - **one message per top-level value, whatever it nests.** A `*3` command
 *     with three bulks inside it is one message; so is a 13-deep `COMMAND DOCS`
 *     reply. lk_msg.len is the value's whole size on the wire, holes included,
 *     so the byte accounting stays exact under any capture budget.
 *   - **a bulk payload is skipped by arithmetic**, so a hole inside one costs
 *     nothing at all — the single property the 512-byte per-port budget of РR13
 *     is chosen to exploit. A hole anywhere else is unrecoverable and says so.
 *   - **a degradation never silently mis-frames**: it emits its '?' note and
 *     drops the direction into the anchor wait, and the wait comes back at a
 *     call boundary and not one byte earlier. */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reassembly.h"
#include "redis.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* --- captured sink output ------------------------------------------------- */

#define MAXREC 256

struct rec {
    __u64 ts;
    __u8 dir;
    char type;
    __u16 flags;
    __u32 len, cap;
    char body[64]; /* prefix copy: lk_msg.body is valid only in the callback */
};

static struct rec recs[MAXREC];
static int nrecs, nresyncs;

static void on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct rec *r = &recs[nrecs % MAXREC];
    __u32 nbody = m->body_cap < sizeof(r->body) - 1 ? m->body_cap : (__u32)sizeof(r->body) - 1;

    (void)ctx;
    (void)c;
    nrecs++;
    memset(r, 0, sizeof(*r));
    r->ts = m->ts_ns;
    r->dir = dir;
    r->type = m->type;
    r->flags = m->flags;
    r->len = m->len;
    r->cap = m->body_cap;
    if (nbody)
        memcpy(r->body, m->body, nbody);
}

static void on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    (void)ctx;
    (void)c;
    (void)dir;
    nresyncs++;
}

static struct lk_reasm reasm;
static struct lk_conn conn;

static void reset(void)
{
    static const struct lk_msg_sink sink = {.on_msg = on_msg, .on_resync = on_resync};

    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    free(conn.frame_state); /* the conn table does this in the live path */
    lk_reasm_free(&reasm);  /* drain the recycled slab pool before re-init */
    memset(&conn, 0, sizeof(conn));
    conn.ops = &lk_proto_redis_ops;
    lk_reasm_init(&reasm, &sink);
    nrecs = 0;
    nresyncs = 0;
}

/* One data event: a chunk of a call, modelled by off/total like the agent's. */
static void feed(enum lk_dir dir, __u32 total, __u32 off, const void *p, __u32 cap, __u64 ts)
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
    lk_reasm_data(&reasm, &conn, dir, &u.d, cap);
}

/* A whole syscall's worth of bytes, fully captured — the common shape. */
static void call(enum lk_dir dir, const char *s, __u64 ts)
{
    feed(dir, (__u32)strlen(s), 0, s, (__u32)strlen(s), ts);
}

static void nbytes(enum lk_dir dir, const void *p, __u32 n, __u64 ts)
{
    feed(dir, n, 0, p, n, ts);
}

/* --- assertions ----------------------------------------------------------- */

static int msg_is(int i, enum lk_dir dir, char type, __u32 len, const char *body)
{
    struct rec *r = &recs[i];

    if (i >= nrecs) {
        fprintf(stderr, "FAIL: expected message %d, only %d arrived\n", i, nrecs);
        return 1;
    }
    if (r->dir != dir || r->type != type || r->len != len ||
        (body && strncmp(r->body, body, strlen(body)))) {
        fprintf(stderr,
                "FAIL: msg %d = %s '%c' len=%u body=\"%s\", expected %s '%c' len=%u \"%s\"\n", i,
                r->dir == LK_DIR_RECV ? "fe>" : "<be", r->type, r->len, r->body,
                dir == LK_DIR_RECV ? "fe>" : "<be", type, len, body ? body : "");
        return 1;
    }
    return 0;
}

#define MSG(i, dir, type, len, body)                                                               \
    do {                                                                                           \
        if (msg_is(i, dir, type, len, body))                                                       \
            return 1;                                                                              \
    } while (0)

#define NOTE(i, dir, code) MSG(i, dir, LK_REDIS_MSG_NOTE, (__u32)(code), NULL)

/* --- the ordinary shapes --------------------------------------------------- */

/* An exchange, annotated in notes-redisproto.md and framed here: a command is
 * one array, its reply is one value, and the message carries the type byte and
 * the whole wire size. The key is inside the published body because the body is
 * the value's own bytes — and it goes no further than that: nothing in the
 * framer reads it, and МR3's table reads the verb only. */
static int test_command_and_reply(void)
{
    reset();
    call(LK_DIR_RECV, "*3\r\n$3\r\nSET\r\n$4\r\nlk:k\r\n$5\r\nhello\r\n", 100);
    call(LK_DIR_SEND, "+OK\r\n", 200);
    call(LK_DIR_RECV, "*2\r\n$3\r\nGET\r\n$4\r\nlk:k\r\n", 300);
    call(LK_DIR_SEND, "$5\r\nhello\r\n", 400);

    CHECK(nrecs == 4);
    MSG(0, LK_DIR_RECV, '*', 34, "*3\r\n$3\r\nSET\r\n");
    MSG(1, LK_DIR_SEND, '+', 5, "+OK\r\n");
    MSG(2, LK_DIR_RECV, '*', 23, "*2\r\n$3\r\nGET\r\n");
    MSG(3, LK_DIR_SEND, '$', 11, "$5\r\nhello\r\n");
    CHECK(recs[0].ts == 100 && recs[3].ts == 400);
    CHECK(recs[0].cap == 34 && !(recs[0].flags & LK_MSG_BODY_TRUNC));
    CHECK(reasm.st.msgs == 4 && reasm.st.resyncs == 0 && reasm.st.bad_len == 0);
    /* The message machine never ran: this is stream mode. */
    CHECK(conn.frame[LK_DIR_RECV].hdr_len == 0 && conn.frame[LK_DIR_RECV].buf == NULL);
    return 0;
}

/* Pipelining is the normal mode, not an exception (measured: every client
 * library batches, memtier at depth 100). Three commands in one write are three
 * messages, and the depth of the batch is left for МR2 to count. */
static int test_pipeline_one_write(void)
{
    reset();
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nPING\r\n*1\r\n$4\r\nPING\r\n", 10);
    call(LK_DIR_SEND, "+PONG\r\n+PONG\r\n+PONG\r\n", 20);

    CHECK(nrecs == 6);
    for (int i = 0; i < 3; i++)
        MSG(i, LK_DIR_RECV, '*', 14, "*1\r\n$4\r\nPING\r\n");
    for (int i = 3; i < 6; i++)
        MSG(i, LK_DIR_SEND, '+', 7, "+PONG\r\n");
    return 0;
}

/* Aggregates inside aggregates, and the map whose count is pairs. One message
 * covers the lot: the framer's stack is what turns nesting into arithmetic. */
static int test_nesting(void)
{
    reset();
    /* *2 [ *2 [ :1, :2 ], $3 abc ] */
    call(LK_DIR_SEND, "*2\r\n*2\r\n:1\r\n:2\r\n$3\r\nabc\r\n", 10);
    CHECK(nrecs == 1);
    MSG(0, LK_DIR_SEND, '*', 25, "*2\r\n*2\r\n:1\r\n");

    /* %2 is *four* values, not two — the off-by-two that eats the next reply. */
    reset();
    call(LK_DIR_SEND, "%2\r\n$1\r\na\r\n:1\r\n$1\r\nb\r\n:2\r\n+next\r\n", 10);
    CHECK(nrecs == 2);
    MSG(0, LK_DIR_SEND, '%', 26, "%2\r\n");
    MSG(1, LK_DIR_SEND, '+', 7, "+next\r\n");

    /* An attribute is a prefix: two top-level values arrive and only the second
     * answers the command. The framer publishes both and says which is which by
     * its type byte; not closing a unit on the '|' is МR2's rule. */
    reset();
    call(LK_DIR_SEND, "|1\r\n$3\r\nttl\r\n:90\r\n$2\r\nhi\r\n", 10);
    CHECK(nrecs == 2);
    MSG(0, LK_DIR_SEND, '|', 18, "|1\r\n$3\r\nttl\r\n:90\r\n");
    MSG(1, LK_DIR_SEND, '$', 8, "$2\r\nhi\r\n");

    /* A push is an ordinary aggregate to the framer. What it *means* — a
     * subscribe confirmation closes a unit, a publication closes nothing — is
     * read off the first element by МR2 (РR8). */
    reset();
    call(LK_DIR_SEND, ">3\r\n$7\r\nmessage\r\n$2\r\nch\r\n$2\r\nhi\r\n", 10);
    CHECK(nrecs == 1);
    MSG(0, LK_DIR_SEND, '>', 33, ">3\r\n$7\r\nmessage\r\n");
    return 0;
}

/* Every RESP3 scalar, one per `DEBUG PROTOCOL`, framed by its type byte alone —
 * there is no phase context to consult, which is the property that makes the
 * machine small. */
static int test_resp3_scalars(void)
{
    reset();
    call(LK_DIR_SEND,
         "_\r\n#t\r\n#f\r\n,3.141\r\n,inf\r\n(1234567890123456789012345\r\n"
         "=9\r\ntxt:hello\r\n!5\r\nOOPS!\r\n",
         10);
    CHECK(nrecs == 8);
    MSG(0, LK_DIR_SEND, '_', 3, "_\r\n");
    MSG(1, LK_DIR_SEND, '#', 4, "#t\r\n");
    MSG(2, LK_DIR_SEND, '#', 4, "#f\r\n");
    MSG(3, LK_DIR_SEND, ',', 8, ",3.141\r\n");
    MSG(4, LK_DIR_SEND, ',', 6, ",inf\r\n");
    MSG(5, LK_DIR_SEND, '(', 28, "(1234567890123456789012345\r\n");
    MSG(6, LK_DIR_SEND, '=', 15, "=9\r\ntxt:hello\r\n");
    MSG(7, LK_DIR_SEND, '!', 11, "!5\r\nOOPS!\r\n");
    CHECK(reasm.st.bad_len == 0);
    return 0;
}

/* The null forms of both versions, and the empty array. All three are a value
 * that is over where it stands — and `*0`/`*-1` from a client get no reply at
 * all, which is why they must not silently become "a command in flight". */
static int test_null_forms(void)
{
    reset();
    call(LK_DIR_SEND, "$-1\r\n*-1\r\n*0\r\n_\r\n", 10);
    CHECK(nrecs == 4);
    MSG(0, LK_DIR_SEND, '$', 5, "$-1\r\n");
    MSG(1, LK_DIR_SEND, '*', 5, "*-1\r\n");
    MSG(2, LK_DIR_SEND, '*', 4, "*0\r\n");
    MSG(3, LK_DIR_SEND, '_', 3, "_\r\n");

    /* An empty bulk is not a null one: zero payload bytes and then the CRLF. */
    reset();
    call(LK_DIR_SEND, "$0\r\n\r\n+OK\r\n", 10);
    CHECK(nrecs == 2);
    MSG(0, LK_DIR_SEND, '$', 6, "$0\r\n\r\n");
    MSG(1, LK_DIR_SEND, '+', 5, "+OK\r\n");
    return 0;
}

/* --- inline commands ------------------------------------------------------ */

/* What telnet, a healthcheck script and a load balancer's probe send. Three
 * measured properties: an empty line is not a command, a bare LF terminates,
 * and an inline line and a RESP command can share one write. */
static int test_inline(void)
{
    reset();
    call(LK_DIR_RECV, "PING\r\n", 10);
    call(LK_DIR_SEND, "+PONG\r\n", 20);
    CHECK(nrecs == 2);
    MSG(0, LK_DIR_RECV, LK_REDIS_MSG_INLINE, 6, "PING\r\n");
    MSG(1, LK_DIR_SEND, '+', 7, "+PONG\r\n");

    /* A bare LF is a terminator here — the server splits on `\n` and strips a
     * trailing `\r`, so an LF-only client works and is measured working. */
    reset();
    call(LK_DIR_RECV, "PING\n", 10);
    CHECK(nrecs == 1);
    MSG(0, LK_DIR_RECV, LK_REDIS_MSG_INLINE, 5, "PING\n");

    /* Empty and blank lines produce no reply from the server, so they must
     * produce no message here: a unit opened on one would wait for ever. */
    reset();
    call(LK_DIR_RECV, "\r\n\n   \r\nECHO hi\r\n", 10);
    CHECK(nrecs == 1);
    MSG(0, LK_DIR_RECV, LK_REDIS_MSG_INLINE, 9, "ECHO hi\r\n");

    /* Quotes and repeated spaces are the server's to split, not ours: the line
     * is published verbatim and МR3 reads the verb off it. */
    reset();
    call(LK_DIR_RECV, "SET  \"a b\"  \"c d\"\r\n", 10);
    CHECK(nrecs == 1);
    MSG(0, LK_DIR_RECV, LK_REDIS_MSG_INLINE, 19, "SET  \"a b\"  \"c d\"\r\n");

    /* Both in one write (measured, `redis/inline-cmds.lkt`). */
    reset();
    call(LK_DIR_RECV, "INFO server\r\n*1\r\n$4\r\nPING\r\n", 10);
    CHECK(nrecs == 2);
    MSG(0, LK_DIR_RECV, LK_REDIS_MSG_INLINE, 13, "INFO server\r\n");
    MSG(1, LK_DIR_RECV, '*', 14, "*1\r\n$4\r\nPING\r\n");

    /* A reply is not an inline command: on the backend a byte that is not a
     * type byte is the stream being lost, and it is named as such. */
    reset();
    call(LK_DIR_SEND, "PONG\r\n", 10);
    CHECK(nrecs == 1);
    NOTE(0, LK_DIR_SEND, LK_REDIS_NOTE_BAD_TYPE);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    return 0;
}

/* A master sends its replica bare `\n` bytes while it forks (measured,
 * `redis/replica.lkt`). Between two top-level values they are neither a command
 * nor a reply, and the framer stays quiet rather than calling them corruption —
 * and, crucially, they do not become part of the next value's body. */
static int test_keepalive_bytes(void)
{
    reset();
    call(LK_DIR_SEND, "\n\n\n+OK\r\n", 10);
    CHECK(nrecs == 1);
    MSG(0, LK_DIR_SEND, '+', 5, "+OK\r\n");
    CHECK(recs[0].cap == 5);
    CHECK(reasm.st.bad_len == 0 && nresyncs == 0);
    return 0;
}

/* --- torn values and the body prefix -------------------------------------- */

/* A value cut into pieces by the socket, down to one byte per syscall (the
 * `slow-client` scenario). The published body is reassembled whole, and it costs
 * one slab from the reassembly pool — borrowed at the first cut and handed back
 * at the value boundary, so Р11's ceiling still bounds it. */
static int test_torn_value(void)
{
    static const char cmd[] = "*3\r\n$3\r\nSET\r\n$4\r\nlk:k\r\n$5\r\nhello\r\n";

    reset();
    for (unsigned i = 0; i + 1 < sizeof(cmd); i++)
        feed(LK_DIR_RECV, 1, 0, cmd + i, 1, 100 + i);

    CHECK(nrecs == 1);
    MSG(0, LK_DIR_RECV, '*', 34, "*3\r\n$3\r\nSET\r\n");
    CHECK(recs[0].cap == 34 && !(recs[0].flags & LK_MSG_BODY_TRUNC));
    CHECK(recs[0].ts == 100); /* the event of the value's *first* byte (Р13) */
    CHECK(conn.frame[LK_DIR_RECV].buf == NULL && reasm.pool_n == 1);
    return 0;
}

/* A value larger than the prefix ceiling: framed exactly, published truncated.
 * At the 512-byte budget РR13 asks for, this is the normal outcome for a reply
 * and not an anomaly — which is why lk_msg.len is the wire size and body_cap is
 * only what we hold. */
static int test_prefix_ceiling(void)
{
    static char big[40000];
    __u32 n;

    reset();
    n = (__u32)snprintf(big, sizeof(big), "$%u\r\n", 30000);
    memset(big + n, 'y', 30000);
    memcpy(big + n + 30000, "\r\n", 2);
    n += 30002;

    nbytes(LK_DIR_SEND, big, n, 10);
    CHECK(nrecs == 1);
    CHECK(recs[0].type == '$' && recs[0].len == n);
    CHECK(recs[0].cap == LK_MSG_BODY_MAX);
    CHECK(recs[0].flags & LK_MSG_BODY_TRUNC);
    return 0;
}

/* --- holes ---------------------------------------------------------------- */

/* The case the whole design is built around (РR13): the capture budget cuts a
 * 1 MB value, the hole lands in the bulk *payload*, the length on the wire steps
 * over it, and the framer never loses sync. The message is honest about both
 * numbers — len is every byte that was on the wire, body_cap is what we saw. */
static int test_hole_in_bulk_payload(void)
{
    static char head[64];
    __u32 hn;

    reset();
    hn = (__u32)snprintf(head, sizeof(head), "*3\r\n$3\r\nSET\r\n$4\r\nlk:k\r\n$%u\r\n", 1048576);

    /* One call of 1048576 + hn + 2 bytes, of which only the first 512 are
     * captured — the РR13 budget, exactly as the kernel would deliver it. */
    feed(LK_DIR_RECV, hn + 1048576 + 2, 0, head, 512, 10);
    /* The uncaptured tail is recognised lazily at the next call. */
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 20);

    CHECK(reasm.st.holes == 1);
    CHECK(nrecs == 2);
    MSG(0, LK_DIR_RECV, '*', hn + 1048576 + 2, "*3\r\n$3\r\nSET\r\n");
    CHECK(recs[0].cap == 512 && (recs[0].flags & LK_MSG_BODY_TRUNC));
    MSG(1, LK_DIR_RECV, '*', 14, "*1\r\n$4\r\nPING\r\n");
    /* No resync, no note, no parse error: a hole in a payload is free. */
    CHECK(nresyncs == 0 && reasm.st.hdr_holes == 0);
    CHECK(conn.frame[LK_DIR_RECV].st != LK_FR_DIRTY);
    return 0;
}

/* And the case that cannot be saved (risk 1 of the plan): an aggregate says how
 * many *values* follow, not how many bytes, so a hole inside one has no length
 * to be stepped over. The direction dirties, says why, and comes back at the
 * next anchor — the units in flight are dropped by the handler on the resync
 * rather than mis-attributed. */
static int test_hole_in_aggregate(void)
{
    reset();
    /* A reply of 100 small bulks, cut after the third. */
    feed(LK_DIR_SEND, 4000, 0, "*100\r\n$1\r\na\r\n$1\r\nb\r\n$1\r\nc\r\n", 27, 10);
    call(LK_DIR_SEND, "+OK\r\n", 20); /* a new call: the tail becomes a hole first */

    CHECK(reasm.st.holes == 1 && reasm.st.hdr_holes == 1);
    NOTE(0, LK_DIR_SEND, LK_REDIS_NOTE_VALUE_HOLE);
    /* `+OK` is at a call boundary and starts with a valid type byte, so the
     * weak backend anchor takes it — and the message says it followed a break. */
    CHECK(nresyncs == 1);
    MSG(1, LK_DIR_SEND, '+', 5, "+OK\r\n");
    CHECK(recs[1].flags & LK_MSG_AFTER_RESYNC);
    return 0;
}

/* A hole that swallows a payload *and* its trailing CRLF still lands on a value
 * boundary, and the framer notices rather than resyncing out of habit. */
static int test_hole_ends_value(void)
{
    reset();
    /* The other shape a hole comes in: a gap *between two chunks of one call*,
     * rather than the uncaptured tail of one. [6, 108) is exactly the payload
     * and its CRLF, so the value ends inside the hole and the bytes after it
     * are framed without an anchor — the direction never went dirty. */
    feed(LK_DIR_SEND, 200, 0, "$100\r\n", 6, 10);
    feed(LK_DIR_SEND, 200, 108, "+OK\r\n", 5, 20);

    CHECK(reasm.st.holes == 1 && reasm.st.hole_bytes == 102);
    CHECK(nrecs == 2);
    MSG(0, LK_DIR_SEND, '$', 108, "$100\r\n");
    CHECK(recs[0].flags & LK_MSG_BODY_TRUNC);
    MSG(1, LK_DIR_SEND, '+', 5, "+OK\r\n");
    CHECK(nresyncs == 0 && reasm.st.hdr_holes == 0);
    return 0;
}

/* --- corrupt input -------------------------------------------------------- */

/* The three lengths the server itself answers `-ERR Protocol error:` to and
 * then hangs up. Counted in two places on purpose: bad_len is the framer's own
 * "a length field failed its sanity check", the note becomes the handler's
 * parse_errors. */
static int test_bad_lengths(void)
{
    static const char *const bad[] = {
        "$abc\r\n",         /* not a number */
        "$536870913\r\n",   /* past proto-max-bulk-len */
        "*2147483648\r\n",  /* past INT_MAX */
        "$EOF:0011\r\n",    /* diskless replication's delimiter form */
        "%99999999999\r\n", /* a pair count that cannot be doubled */
    };

    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        reset();
        call(LK_DIR_SEND, bad[i], 10);
        CHECK(nrecs == 1);
        NOTE(0, LK_DIR_SEND, LK_REDIS_NOTE_BAD_LEN);
        CHECK(reasm.st.bad_len == 1);
        CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    }
    return 0;
}

/* A declared length that does not match the wire. Redis's own client parsers
 * take the two bytes after a payload on faith; an observer that did so would
 * misframe every value after this one in silence. (Measured: the corpus's
 * `torn-bulk` scenario declares `$8` for a seven-byte key, and the server
 * answers the same complaint at the same byte.) */
static int test_bulk_eol_mismatch(void)
{
    reset();
    call(LK_DIR_RECV, "*2\r\n$3\r\nGET\r\n$8\r\nlk:torn\r\n", 10);
    CHECK(nrecs == 1);
    NOTE(0, LK_DIR_RECV, LK_REDIS_NOTE_BULK_EOL);
    CHECK(conn.frame[LK_DIR_RECV].st == LK_FR_DIRTY);
    return 0;
}

/* Nesting past the stack. МR0 measured `COMMAND DOCS` at 13 deep and it is the
 * first thing an interactive redis-cli sends, so 32 is generous — but a Lua
 * script can return any depth at all, and past the bound the answer is a
 * degradation and a resync, never a verdict of corruption. */
static int test_depth(void)
{
    char deep[4 * (LK_REDIS_MAX_DEPTH + 4)];
    __u32 n = 0;

    /* Exactly at the bound: framed, one message, no complaint. */
    reset();
    for (unsigned i = 0; i < LK_REDIS_MAX_DEPTH - 1; i++)
        n += (__u32)snprintf(deep + n, sizeof(deep) - n, "*1\r\n");
    n += (__u32)snprintf(deep + n, sizeof(deep) - n, "*0\r\n");
    nbytes(LK_DIR_SEND, deep, n, 10);
    CHECK(nrecs == 1);
    MSG(0, LK_DIR_SEND, '*', n, "*1\r\n*1\r\n");

    /* One deeper: the framer stops descending and says so. */
    reset();
    n = 0;
    for (unsigned i = 0; i < LK_REDIS_MAX_DEPTH + 1; i++)
        n += (__u32)snprintf(deep + n, sizeof(deep) - n, "*1\r\n");
    nbytes(LK_DIR_SEND, deep, n, 10);
    CHECK(nrecs == 1);
    NOTE(0, LK_DIR_SEND, LK_REDIS_NOTE_DEPTH);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY);
    CHECK(reasm.st.bad_len == 0); /* deep is not corrupt */
    return 0;
}

/* A line that never ends. The bound is the server's own inline ceiling, and
 * past it the server answers once and closes; nothing legitimate comes near it
 * (the longest reply line in the corpus is a 60-byte `+FULLRESYNC`). */
static int test_line_too_big(void)
{
    static char huge[LK_REDIS_LINE_MAX + 16];

    reset();
    memset(huge, 'x', sizeof(huge));
    huge[0] = '+';
    nbytes(LK_DIR_SEND, huge, sizeof(huge), 10);
    CHECK(nrecs == 1);
    NOTE(0, LK_DIR_SEND, LK_REDIS_NOTE_LINE_TOO_BIG);

    reset();
    memset(huge, 'x', sizeof(huge));
    nbytes(LK_DIR_RECV, huge, sizeof(huge), 10);
    CHECK(nrecs == 1);
    NOTE(0, LK_DIR_RECV, LK_REDIS_NOTE_INLINE_TOO_BIG);
    return 0;
}

/* --- resync --------------------------------------------------------------- */

/* Both anchors are checked at a call boundary and nowhere else, because that is
 * where the strength comes from: a client starts a batch on a write boundary.
 * A chunk that is not one, or that does not match, is discarded whole rather
 * than scanned for a pattern that would be a coincidence. */
static int test_resync_anchors(void)
{
    reset();
    conn.flags |= LK_CONN_SYNTHETIC;
    conn.frame[LK_DIR_RECV].st = LK_FR_DIRTY;
    conn.frame[LK_DIR_SEND].st = LK_FR_DIRTY;

    /* Mid-value debris at a call boundary: not an anchor, nothing published. */
    call(LK_DIR_RECV, "lue\r\n$5\r\nhello\r\n", 10);
    CHECK(nrecs == 0 && nresyncs == 0);

    /* An inline command is deliberately *not* a frontend anchor: after a hole
     * it cannot be told from the text inside somebody's value. */
    call(LK_DIR_RECV, "PING\r\n", 20);
    CHECK(nrecs == 0 && nresyncs == 0);

    /* The four conditions agree: back in. */
    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 30);
    CHECK(nresyncs == 1 && nrecs == 1);
    MSG(0, LK_DIR_RECV, '*', 14, "*1\r\n$4\r\nPING\r\n");
    CHECK(recs[0].flags & LK_MSG_AFTER_RESYNC);
    CHECK(conn.frame[LK_DIR_SEND].st == LK_FR_DIRTY); /* the other direction waits */

    /* The backend takes any valid type byte, which is all it can honestly ask
     * for — a payload may contain a perfectly formed reply. */
    call(LK_DIR_SEND, "+PONG\r\n", 40);
    CHECK(nresyncs == 2 && nrecs == 2);
    MSG(1, LK_DIR_SEND, '+', 7, "+PONG\r\n");
    return 0;
}

/* A chunk that is not the start of a syscall cannot resynchronise on, however
 * well it matches: the anchor's whole strength is the boundary. */
static int test_resync_needs_call_boundary(void)
{
    reset();
    conn.frame[LK_DIR_RECV].st = LK_FR_DIRTY;

    /* A 30-byte call whose first 10 bytes were lost: the anchor pattern sits at
     * offset 10, inside the call, and is not taken. */
    feed(LK_DIR_RECV, 30, 10, "*1\r\n$4\r\nPING\r\n", 14, 10);
    CHECK(nrecs == 0 && nresyncs == 0);

    feed(LK_DIR_RECV, 14, 0, "*1\r\n$4\r\nPING\r\n", 14, 20);
    CHECK(nresyncs == 1 && nrecs == 1);
    return 0;
}

/* --- the seam ------------------------------------------------------------- */

/* Framing state follows the connection and nothing inside it owns a pointer:
 * the table frees frame_state on every removal path, and the prefix slab lives
 * in lk_frame.buf so it is freed and recycled with it. */
static int test_state_lifetime(void)
{
    reset();
    call(LK_DIR_RECV, "*3\r\n$3\r\nSET\r\n", 10); /* half a value: the slab is taken */
    CHECK(nrecs == 0);
    CHECK(conn.frame_state != NULL);
    CHECK(conn.frame[LK_DIR_RECV].buf != NULL && conn.frame[LK_DIR_RECV].buf_len == 13);
    CHECK(reasm.pool_n == 0);

    call(LK_DIR_RECV, "$4\r\nlk:k\r\n$5\r\nhello\r\n", 20);
    CHECK(nrecs == 1);
    MSG(0, LK_DIR_RECV, '*', 34, "*3\r\n$3\r\nSET\r\n$4\r\nlk:k\r\n");
    CHECK(conn.frame[LK_DIR_RECV].buf == NULL); /* ... and given back */
    CHECK(reasm.pool_n == 1);
    return 0;
}

/* РH15's invariant, restated for the fifth registry entry: a PG connection
 * frames exactly as it did while a Redis one shares the framer. The two use
 * disjoint state and meet only in the counters. */
static int test_pg_unaffected_alongside(void)
{
    static struct lk_conn pgconn;
    __u8 wire[64];

    reset();
    memset(&pgconn, 0, sizeof(pgconn));
    pgconn.ops = &lk_proto_pg_ops;
    pgconn.frame[LK_DIR_RECV].startup_done = 1;

    wire[0] = 'Q'; /* 'Q' + len(4+9) + "select 1" */
    wire[1] = wire[2] = wire[3] = 0;
    wire[4] = 13;
    memcpy(wire + 5, "select 1", 9);

    call(LK_DIR_RECV, "*1\r\n$4\r\nPING\r\n", 10);
    lk_frame_bytes(&reasm, &pgconn, LK_DIR_RECV, wire, 14, 20);
    call(LK_DIR_SEND, "+PONG\r\n", 30);

    CHECK(nrecs == 3);
    MSG(1, LK_DIR_RECV, 'Q', 13, "select 1");
    CHECK(pgconn.frame[LK_DIR_RECV].st == LK_FR_HEADER && pgconn.frame_state == NULL);
    CHECK(conn.frame_state != NULL);
    return 0;
}

int main(void)
{
    if (test_command_and_reply() || test_pipeline_one_write() || test_nesting() ||
        test_resp3_scalars() || test_null_forms() || test_inline() || test_keepalive_bytes() ||
        test_torn_value() || test_prefix_ceiling() || test_hole_in_bulk_payload() ||
        test_hole_in_aggregate() || test_hole_ends_value() || test_bad_lengths() ||
        test_bulk_eol_mismatch() || test_depth() || test_line_too_big() || test_resync_anchors() ||
        test_resync_needs_call_boundary() || test_state_lifetime() ||
        test_pg_unaffected_alongside())
        return 1;
    free(conn.frame[0].buf);
    free(conn.frame[1].buf);
    free(conn.frame_state);
    lk_reasm_free(&reasm);
    printf("ok\n");
    return 0;
}
