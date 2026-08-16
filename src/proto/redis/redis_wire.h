/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded cursor over RESP2/RESP3 values (РR2, PLAN-REDIS.md МR1) — the
 * pg_wire.h / my_wire.h / http_wire.h of this protocol. The input is untrusted:
 * it comes off the wire, it may be truncated by the capture budget (512 bytes
 * on a redis port, РR13) and it may be shaped to desynchronise us, so every
 * accessor takes an explicit (pointer, length) pair and none of them ever reads
 * past the range it was handed. Direct pointer walking over lk_msg.body is a
 * review reject here exactly as in the three protocols before it.
 *
 * What RESP is, in one paragraph (docs/notes-redisproto.md §"Framing"): a value
 * starts with a type byte, and that byte is the whole classification — no phase
 * context as in MySQL, no fixed header as in PG. What follows the type byte is a
 * CRLF-terminated line, and what the line means depends on the type: it *is* the
 * value (`+OK`, `:12`, `,3.141`), or it carries a **byte** length and a payload
 * follows (`$5\r\nhello`), or it carries an **element** count and that many
 * values follow (`*3\r\n…`). The asymmetry between the last two is the whole
 * difficulty of the track: a bulk can be skipped arithmetically through a
 * capture hole, an aggregate cannot be skipped at all.
 *
 * Deliberately not here: anything that reads a *value*. The framer needs the
 * type, the lengths and the terminators; the payload of a bulk is skipped by
 * arithmetic and never inspected (РR4 — a Redis key is an identifier and never
 * becomes a label). The one place an argument is ever looked at is МR3's
 * command table, over the message body this framer publishes, and even there it
 * is a lookup of the verb and never of the key.
 *
 * Header-only and dependency-light so the unit tests and the МR8 fuzz harness
 * include it directly. */
#ifndef LATKIT_REDIS_WIRE_H
#define LATKIT_REDIS_WIRE_H

#include <linux/types.h>
#include <stdbool.h>

/* --- the fourteen type bytes (notes-redisproto.md §"The type bytes") ------- */

#define REDIS_T_SIMPLE '+' /* simple string:  +OK\r\n                        */
#define REDIS_T_ERROR  '-' /* error:          -WRONGTYPE Operation…\r\n      */
#define REDIS_T_INT    ':' /* integer:        :12345\r\n                     */
#define REDIS_T_BULK   '$' /* bulk string:    $5\r\nhello\r\n, null $-1\r\n  */
#define REDIS_T_ARRAY  '*' /* array:          *3\r\n…, null *-1\r\n          */
/* RESP3 only, all of them measured against a live 7.4 (`DEBUG PROTOCOL`). */
#define REDIS_T_NULL     '_' /* _\r\n                                          */
#define REDIS_T_BOOL     '#' /* #t\r\n / #f\r\n                                */
#define REDIS_T_DOUBLE   ',' /* ,3.141\r\n, also inf / -inf / nan              */
#define REDIS_T_BIGNUM   '(' /* (123456789012345678901234567890\r\n            */
#define REDIS_T_BLOBERR  '!' /* !21\r\nSYNTAX invalid syntax\r\n               */
#define REDIS_T_VERBATIM '=' /* =15\r\ntxt:Some string\r\n                     */
#define REDIS_T_MAP      '%' /* %1\r\n…  — the count is *pairs*                */
#define REDIS_T_SET      '~' /* ~3\r\n…                                        */
#define REDIS_T_PUSH     '>' /* >3\r\n…  — see below                            */
#define REDIS_T_ATTR     '|' /* |1\r\n…  — see below                            */

/* The last two are the ones that are not simply "a reply", and both corrections
 * МR0 made to the plan are about them:
 *
 *   - a **push** is either somebody else's publication or the reply to
 *     `SUBSCRIBE` itself, and which it is can only be read off the kind word in
 *     its first element — in RESP3 the subscribe confirmation *is* a push, so
 *     "a push never closes a unit" would leave every SUBSCRIBE open for ever
 *     (РR8, МR2's to act on);
 *   - an **attribute** is a *prefix* to the value that follows and never a
 *     reply of its own. If it closed a unit, every later reply on that
 *     connection would answer the previous command and the latencies would stay
 *     plausible while being wrong (РR3). */

/* How the framer must read a value, once it has the type byte. Four shapes
 * cover all fourteen types, which is why the state machine in redis_frame.c is
 * small enough to state its invariants. */
enum redis_vshape {
    REDIS_V_BAD = 0, /* not a type byte at all */
    REDIS_V_LINE,    /* the line *is* the value: + - : _ # , ( */
    REDIS_V_BULK,    /* the line carries a byte length, a payload + CRLF follow:
                        $ = !  — skippable arithmetically, hence hole-proof */
    REDIS_V_AGG,     /* the line carries an element count: * ~ > */
    REDIS_V_AGGPAIR, /* ... a *pair* count, so 2n values follow: % |
                        (off-by-two here silently eats the next reply) */
};

static inline enum redis_vshape redis_vshape(__u8 t)
{
    switch (t) {
    case REDIS_T_SIMPLE:
    case REDIS_T_ERROR:
    case REDIS_T_INT:
    case REDIS_T_NULL:
    case REDIS_T_BOOL:
    case REDIS_T_DOUBLE:
    case REDIS_T_BIGNUM:
        return REDIS_V_LINE;
    case REDIS_T_BULK:
    case REDIS_T_VERBATIM:
    case REDIS_T_BLOBERR:
        return REDIS_V_BULK;
    case REDIS_T_ARRAY:
    case REDIS_T_SET:
    case REDIS_T_PUSH:
        return REDIS_V_AGG;
    case REDIS_T_MAP:
    case REDIS_T_ATTR:
        return REDIS_V_AGGPAIR;
    default:
        return REDIS_V_BAD;
    }
}

/* A type byte that exists only in RESP3, so seeing one *proves* the connection
 * negotiated `HELLO 3` — which is how a connection joined mid-stream learns its
 * protocol version without having seen the handshake (notes-redisproto.md
 * §"`HELLO` and the protocol version"). Nothing in МR1 acts on it; the field is
 * here because it is a property of the type byte and belongs beside its twin. */
static inline bool redis_type_is_resp3(__u8 t)
{
    switch (t) {
    case REDIS_T_NULL:
    case REDIS_T_BOOL:
    case REDIS_T_DOUBLE:
    case REDIS_T_BIGNUM:
    case REDIS_T_BLOBERR:
    case REDIS_T_VERBATIM:
    case REDIS_T_MAP:
    case REDIS_T_SET:
    case REDIS_T_PUSH:
    case REDIS_T_ATTR:
        return true;
    default:
        return false;
    }
}

/* --- the bounds the wire is validated against ----------------------------- */

/* `proto-max-bulk-len`, the server's own ceiling on a bulk (512 MB by default).
 * It is *configured* rather than fixed, so it is read here as a validation rule
 * and not as a constant of the protocol: a length beyond it is corruption —
 * the server itself answers `-ERR Protocol error: invalid bulk length` and
 * closes the connection — while a length under it is honoured however
 * enormous. */
#define LK_REDIS_MAX_BULK (512u * 1024u * 1024u)

/* The server rejects a multibulk count over INT_MAX outright ("invalid
 * multibulk length"), and there is no smaller bound worth asserting: `KEYS *`
 * over a million keys really does answer `*1000000`. A pair count is halved so
 * that count × 2 still fits the element counter of the framer's stack. */
#define LK_REDIS_MAX_ELEMS 2147483647u

/* Longest line the framer will assemble before declaring the stream lost. The
 * server's own inline-request limit is 64 KB (`-ERR Protocol error: too big
 * inline request`, then it hangs up), and no reply line it generates comes near
 * it — a `-` error is a sentence, a `+FULLRESYNC` is 60 bytes. */
#define LK_REDIS_LINE_MAX (64u * 1024u)

/* The server's own `PROTO_INLINE_MAX_SIZE`: past it an inline request is
 * `-ERR Protocol error: too big inline request` and the connection is closed
 * (measured, `redis/garbage.lkt`). The same number as the line bound above and
 * kept separate from it on purpose — this one is the *server's* rule, quoted,
 * and would follow the server if it ever changed. */
#define LK_REDIS_INLINE_MAX (64u * 1024u)

/* Digits of a length line kept for the numeric parse. A signed 64-bit number is
 * at most 20 characters; anything longer cannot be one, which is exactly the
 * answer the framer needs and the reason the scratch can be this small. */
#define LK_REDIS_NUM_MAX 24

/* --- numbers -------------------------------------------------------------- */

/* Strict signed decimal over an explicit range: the whole span must be digits
 * (with one optional leading `-`), at least one of them, and the value must fit
 * an __s64 without wrapping. Deliberately not strtoll: it accepts leading
 * whitespace, a `+`, and a partial parse, and every one of those would turn a
 * corrupt length into a plausible one.
 *
 * `+3\r\n` is not a length and `3 \r\n` is not a length; the server agrees on
 * both (`$abc` and `$ 3` are `invalid bulk length`, and the connection dies). */
static inline bool redis_parse_i64(const char *p, __u32 n, __s64 *out)
{
    bool neg = false;
    __u64 v = 0;
    __u32 i = 0;

    if (!n || n > LK_REDIS_NUM_MAX)
        return false;
    if (p[0] == '-') {
        neg = true;
        i = 1;
        if (n == 1)
            return false;
    }
    for (; i < n; i++) {
        if (p[i] < '0' || p[i] > '9')
            return false;
        /* Refuse *before* the multiply, so the accumulator cannot wrap: past
         * this the value is rejected outright, which is right because the
         * ceiling is eighteen digits — nine orders of magnitude above the
         * largest length RESP can legally carry. The caller then checks its own
         * limit (512 MB for a bulk, INT_MAX for a count) against a number that
         * is certainly a number. */
        if (v > (((__u64)1 << 62) - 9) / 10)
            return false;
        v = v * 10 + (__u64)(p[i] - '0');
    }
    *out = neg ? -(__s64)v : (__s64)v;
    return true;
}

/* --- the two length rules -------------------------------------------------- */

/* A bulk header (`$`, `=`, `!`). Returns false for a length that is corruption;
 * on true, *payload is the number of payload bytes to skip and *null says the
 * value has no payload at all (`$-1`, the RESP2 null).
 *
 * Every negative length is read as null rather than only -1: that is what every
 * client library does, the server emits nothing else, and treating `$-2` as
 * corruption would buy a distinction nobody can act on. */
static inline bool redis_bulk_len(__s64 v, __u64 *payload, bool *null)
{
    if (v < 0) {
        *null = true;
        *payload = 0;
        return true;
    }
    if ((__u64)v > LK_REDIS_MAX_BULK)
        return false;
    *null = false;
    *payload = (__u64)v;
    return true;
}

/* An aggregate header (`*`, `~`, `>`, and with pairs `%`, `|`). Returns false
 * for a count that is corruption; on true, *elems is how many values follow —
 * zero for both the empty aggregate (`*0`) and the null one (`*-1`), which the
 * framer treats identically because they are the same thing to it: a value that
 * is complete where it stands. */
static inline bool redis_agg_count(__s64 v, bool pairs, __u32 *elems)
{
    __u64 lim = pairs ? LK_REDIS_MAX_ELEMS / 2 : LK_REDIS_MAX_ELEMS;

    if (v < 0) {
        *elems = 0;
        return true;
    }
    if ((__u64)v > lim)
        return false;
    *elems = (__u32)v * (pairs ? 2u : 1u);
    return true;
}

/* --- resync anchors (Р10 for RESP, notes-redisproto.md §"Resync anchors") ---
 *
 * Both anchors are checked *at a syscall boundary only*, which is where the
 * strength comes from: a client starts a batch on a write boundary, so the
 * first byte of a call is the first byte of a command far more reliably than
 * any byte pattern could be. The helpers below are the pattern half; the
 * boundary half is the framer's, which is the only side that knows it. */

/* Element counts a *command* plausibly has. A command is a verb, a key and a
 * handful of arguments; `MSET` of a thousand pairs is the outlier and 1024 is
 * already generous for it. Nothing but the anchor uses this bound — a real
 * `*100000` inside a healthy stream is framed without complaint. */
#define LK_REDIS_ANCHOR_ELEMS 1024

/* Bytes the frontend anchor may need: `*1024\r\n$536870912\r\n` is 20. */
#define LK_REDIS_ANCHOR_MAX 24

/* A CRLF-terminated line starting at `off`, bounded by `max` content bytes.
 * *content is its length without the terminator, *next the offset just past it. */
static inline bool redis_line_at(const __u8 *p, __u32 n, __u32 off, __u32 max, __u32 *content,
                                 __u32 *next)
{
    for (__u32 i = off; i + 1 < n && i - off <= max; i++) {
        if (p[i] == '\r' && p[i + 1] == '\n') {
            *content = i - off;
            *next = i + 2;
            return true;
        }
    }
    return false;
}

/* The frontend anchor (strong): `*<1..1024>\r\n$<0..proto-max-bulk-len>\r\n`.
 * Four independent conditions have to agree — the array marker, a plausible
 * count, a `$` where the first element's type belongs, and a plausible bulk
 * length — which is what makes a false positive on captured payload bytes
 * unlikely enough to re-enter framing on. It is the direct analogue of PG's
 * frontend anchor and stronger than MySQL's. */
static inline bool redis_anchor_fe(const __u8 *p, __u32 n)
{
    __u32 content, next, digits;
    __s64 v;
    __u64 payload;
    bool null;

    if (!n || p[0] != REDIS_T_ARRAY)
        return false;
    if (!redis_line_at(p, n, 1, LK_REDIS_NUM_MAX, &content, &next))
        return false;
    if (!redis_parse_i64((const char *)p + 1, content, &v) || v < 1 || v > LK_REDIS_ANCHOR_ELEMS)
        return false;
    if (next >= n || p[next] != REDIS_T_BULK)
        return false;
    digits = next + 1;
    if (!redis_line_at(p, n, digits, LK_REDIS_NUM_MAX, &content, &next))
        return false;
    if (!redis_parse_i64((const char *)p + digits, content, &v))
        return false;
    return redis_bulk_len(v, &payload, &null) && !null;
}

/* The backend anchor (weak): a valid type byte at a call boundary, and nothing
 * more can honestly be asked of it. A bulk's payload may contain anything,
 * including a perfectly formed reply, so no pattern on this side is evidence;
 * the discipline comes from the frontend, and a wrong guess here costs one
 * misframed value and another resync. */
static inline bool redis_anchor_be(const __u8 *p, __u32 n)
{
    return n && redis_vshape(p[0]) != REDIS_V_BAD;
}

#endif /* LATKIT_REDIS_WIRE_H */
