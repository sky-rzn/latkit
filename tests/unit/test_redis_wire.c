// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the RESP wire helpers (PLAN-REDIS.md МR1, redis_wire.h) — the
 * pg_wire / my_wire / http_wire twin of this protocol: the pure predicates the
 * framer decides everything by, tested apart from the framer that uses them.
 *
 * Four groups, and each of them is a claim from docs/notes-redisproto.md:
 * the type byte is the whole classification and it says which of four shapes a
 * value has; a length is a *strict* decimal or it is corruption (the server
 * closes the connection over it, so a lenient parse here would be a lie); the
 * null forms of both versions collapse to "a value that is over"; and the two
 * resync anchors are as strong as the direction allows — four agreeing
 * conditions on the frontend, a single type byte on the backend, which is all a
 * stream that may contain arbitrary payload bytes can honestly offer. */
#include <stdio.h>
#include <string.h>

#include "redis_wire.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* --- the type bytes ------------------------------------------------------- */

/* All fourteen, in the shape the framer reads them as. The RESP2 five and the
 * RESP3 nine are one table because the wire does not separate them: a
 * connection that said `HELLO 3` simply starts producing more of them. */
static int test_shapes(void)
{
    CHECK(redis_vshape(REDIS_T_SIMPLE) == REDIS_V_LINE);
    CHECK(redis_vshape(REDIS_T_ERROR) == REDIS_V_LINE);
    CHECK(redis_vshape(REDIS_T_INT) == REDIS_V_LINE);
    CHECK(redis_vshape(REDIS_T_NULL) == REDIS_V_LINE);
    CHECK(redis_vshape(REDIS_T_BOOL) == REDIS_V_LINE);
    CHECK(redis_vshape(REDIS_T_DOUBLE) == REDIS_V_LINE);
    CHECK(redis_vshape(REDIS_T_BIGNUM) == REDIS_V_LINE);

    CHECK(redis_vshape(REDIS_T_BULK) == REDIS_V_BULK);
    CHECK(redis_vshape(REDIS_T_VERBATIM) == REDIS_V_BULK);
    CHECK(redis_vshape(REDIS_T_BLOBERR) == REDIS_V_BULK);

    CHECK(redis_vshape(REDIS_T_ARRAY) == REDIS_V_AGG);
    CHECK(redis_vshape(REDIS_T_SET) == REDIS_V_AGG);
    CHECK(redis_vshape(REDIS_T_PUSH) == REDIS_V_AGG);

    /* The two whose count is *pairs*: off by two here and the next reply is
     * silently eaten. */
    CHECK(redis_vshape(REDIS_T_MAP) == REDIS_V_AGGPAIR);
    CHECK(redis_vshape(REDIS_T_ATTR) == REDIS_V_AGGPAIR);

    /* Everything else is not a value — which on the frontend means an inline
     * command and on the backend means the stream is lost. */
    CHECK(redis_vshape('P') == REDIS_V_BAD); /* an inline PING */
    CHECK(redis_vshape('\r') == REDIS_V_BAD);
    CHECK(redis_vshape('\n') == REDIS_V_BAD); /* a replication keepalive */
    CHECK(redis_vshape(0) == REDIS_V_BAD);
    CHECK(redis_vshape(0xff) == REDIS_V_BAD);
    CHECK(redis_vshape('&') == REDIS_V_BAD); /* not in RESP3 either */
    return 0;
}

/* Seeing one of these proves the connection negotiated RESP3, which is how a
 * connection joined mid-stream learns its version. The RESP2 five prove
 * nothing: both versions send them. */
static int test_resp3_marker(void)
{
    CHECK(!redis_type_is_resp3(REDIS_T_SIMPLE));
    CHECK(!redis_type_is_resp3(REDIS_T_ERROR));
    CHECK(!redis_type_is_resp3(REDIS_T_INT));
    CHECK(!redis_type_is_resp3(REDIS_T_BULK));
    CHECK(!redis_type_is_resp3(REDIS_T_ARRAY));

    CHECK(redis_type_is_resp3(REDIS_T_NULL));
    CHECK(redis_type_is_resp3(REDIS_T_BOOL));
    CHECK(redis_type_is_resp3(REDIS_T_DOUBLE));
    CHECK(redis_type_is_resp3(REDIS_T_BIGNUM));
    CHECK(redis_type_is_resp3(REDIS_T_BLOBERR));
    CHECK(redis_type_is_resp3(REDIS_T_VERBATIM));
    CHECK(redis_type_is_resp3(REDIS_T_MAP));
    CHECK(redis_type_is_resp3(REDIS_T_SET));
    CHECK(redis_type_is_resp3(REDIS_T_PUSH));
    CHECK(redis_type_is_resp3(REDIS_T_ATTR));
    return 0;
}

/* --- numbers -------------------------------------------------------------- */

static bool i64(const char *s, __s64 *v)
{
    return redis_parse_i64(s, (__u32)strlen(s), v);
}

/* Strict, because the server is: `$abc`, `$ 3` and `$+3` are all
 * `-ERR Protocol error: invalid bulk length` and the connection is closed.
 * Anything this function accepts that the server would not is a length we would
 * then frame by, and every byte after it would be wrong. */
static int test_parse_i64(void)
{
    __s64 v = 999;

    CHECK(i64("0", &v) && v == 0);
    CHECK(i64("3", &v) && v == 3);
    CHECK(i64("1048576", &v) && v == 1048576);
    CHECK(i64("-1", &v) && v == -1);
    CHECK(i64("-5", &v) && v == -5);
    CHECK(i64("9223372036854775807", &v) == false); /* over the safety ceiling */
    CHECK(i64("1234567890123456", &v) && v == 1234567890123456LL);

    CHECK(!i64("", &v));
    CHECK(!i64("-", &v));
    CHECK(!i64("+3", &v));
    CHECK(!i64("3 ", &v));
    CHECK(!i64(" 3", &v));
    CHECK(!i64("abc", &v));
    CHECK(!i64("3a", &v));
    CHECK(!i64("3.5", &v));
    CHECK(!i64("--1", &v));
    CHECK(!i64("EOF:0123456789abcdef", &v)); /* diskless replication's `$EOF:` */
    CHECK(!redis_parse_i64("1", 0, &v));
    /* Longer than any 64-bit number: rejected on length before a digit is
     * looked at, which is also why the framer's scratch can be 24 bytes. */
    CHECK(!i64("111111111111111111111111111111", &v));
    return 0;
}

/* --- the two length rules -------------------------------------------------- */

static int test_bulk_len(void)
{
    __u64 payload = 12345;
    bool null = false;

    CHECK(redis_bulk_len(0, &payload, &null) && !null && payload == 0);
    CHECK(redis_bulk_len(5, &payload, &null) && !null && payload == 5);
    CHECK(redis_bulk_len(LK_REDIS_MAX_BULK, &payload, &null) && !null &&
          payload == LK_REDIS_MAX_BULK);

    /* `$-1` is RESP2's null bulk. Every negative is read as one: the server
     * emits nothing else, every client library does the same, and a
     * distinction nobody can act on is not worth a corruption verdict. */
    CHECK(redis_bulk_len(-1, &payload, &null) && null && payload == 0);
    CHECK(redis_bulk_len(-5, &payload, &null) && null && payload == 0);

    /* Past `proto-max-bulk-len`: the server answers a protocol error and hangs
     * up, so this is the end of the conversation and not a large value. */
    CHECK(!redis_bulk_len(LK_REDIS_MAX_BULK + 1, &payload, &null));
    CHECK(!redis_bulk_len(1LL << 40, &payload, &null));
    return 0;
}

static int test_agg_count(void)
{
    __u32 e = 12345;

    CHECK(redis_agg_count(3, false, &e) && e == 3);
    CHECK(redis_agg_count(1000000, false, &e) && e == 1000000); /* KEYS * on 1M keys */
    CHECK(redis_agg_count(LK_REDIS_MAX_ELEMS, false, &e) && e == LK_REDIS_MAX_ELEMS);

    /* `*0` and `*-1` are the same thing to the framer: a value that is over
     * where it stands. (They are *not* the same to the unit queue — neither
     * gets a reply from the server — but that is МR2's to know.) */
    CHECK(redis_agg_count(0, false, &e) && e == 0);
    CHECK(redis_agg_count(-1, false, &e) && e == 0);
    CHECK(redis_agg_count(-5, false, &e) && e == 0);

    /* A map and an attribute count *pairs*, so twice as many values follow. */
    CHECK(redis_agg_count(3, true, &e) && e == 6);
    CHECK(redis_agg_count(1, true, &e) && e == 2);
    CHECK(redis_agg_count(0, true, &e) && e == 0);

    /* Over INT_MAX the server itself says `invalid multibulk length`; the pair
     * ceiling is half of that so that count × 2 still fits the counter. */
    CHECK(!redis_agg_count((__s64)LK_REDIS_MAX_ELEMS + 1, false, &e));
    CHECK(!redis_agg_count(LK_REDIS_MAX_ELEMS / 2 + 1, true, &e));
    CHECK(redis_agg_count(LK_REDIS_MAX_ELEMS / 2, true, &e) && e == LK_REDIS_MAX_ELEMS - 1);
    return 0;
}

/* --- lines ---------------------------------------------------------------- */

/* A typed value's line ends at CRLF and at nothing else. A bare LF is an
 * ordinary byte there — the server's own parser looks for the CR and takes what
 * follows it, and a multibulk command with LF-only terminators does not parse
 * for the server either (measured). The bare-LF rule of the *inline* path is a
 * different rule and lives in the framer, where the inline path is. */
static int test_line_at(void)
{
    static const char s[] = "$5\r\nhello\r\n";
    __u32 content = 999, next = 999;

    CHECK(redis_line_at((const __u8 *)s, sizeof(s) - 1, 1, LK_REDIS_NUM_MAX, &content, &next));
    CHECK(content == 1 && next == 4);
    CHECK(redis_line_at((const __u8 *)s, sizeof(s) - 1, 4, LK_REDIS_NUM_MAX, &content, &next));
    CHECK(content == 5 && next == 11);

    /* No terminator in range: not a line yet, whatever else it may become. */
    CHECK(!redis_line_at((const __u8 *)"$5\r", 3, 1, LK_REDIS_NUM_MAX, &content, &next));
    CHECK(!redis_line_at((const __u8 *)"$5\n", 3, 1, LK_REDIS_NUM_MAX, &content, &next));
    CHECK(!redis_line_at((const __u8 *)"", 0, 0, LK_REDIS_NUM_MAX, &content, &next));
    /* The bound is on the content, so a long line is not searched for ever. */
    CHECK(!redis_line_at((const __u8 *)"$00000000\r\n", 11, 1, 4, &content, &next));
    return 0;
}

/* --- resync anchors -------------------------------------------------------- */

static bool afe(const char *s)
{
    return redis_anchor_fe((const __u8 *)s, (__u32)strlen(s));
}

/* The frontend anchor, where four conditions have to agree: the array marker,
 * a plausible element count, a `$` where the first element's type belongs, and
 * a bulk length the server would accept. A client starts a batch on a write
 * boundary, so this pattern at the first byte of a syscall is as close to a
 * frame boundary as this protocol offers. */
static int test_anchor_fe(void)
{
    CHECK(afe("*1\r\n$4\r\nPING\r\n"));
    CHECK(afe("*3\r\n$3\r\nSET\r\n$1\r\na\r\n$1\r\nb\r\n"));
    CHECK(afe("*2\r\n$0\r\n\r\n$1\r\na\r\n")); /* an empty first argument is legal */
    CHECK(afe("*1024\r\n$1\r\na\r\n"));

    CHECK(!afe(""));
    CHECK(!afe("*"));
    CHECK(!afe("*1\r\n"));                /* the first element has not arrived */
    CHECK(!afe("*1\r\n$4\r"));            /* ... nor has its length */
    CHECK(!afe("+OK\r\n"));               /* a reply is not a command */
    CHECK(!afe("*0\r\n$4\r\nPING\r\n"));  /* no elements: not a command either */
    CHECK(!afe("*-1\r\n$4\r\nPING\r\n")); /* the null array, likewise */
    CHECK(!afe("*1025\r\n$1\r\na\r\n"));  /* past what a command plausibly is */
    CHECK(!afe("*1\r\n+PING\r\n"));       /* elements of a command are bulks */
    CHECK(!afe("*1\r\n$abc\r\n"));
    CHECK(!afe("*1\r\n$536870913\r\n")); /* past proto-max-bulk-len */
    CHECK(!afe("*1\r\n$-1\r\n"));        /* a null argument is not a command */
    CHECK(!afe("PING\r\n"));             /* an inline command is not an anchor: after
                                            a hole it is indistinguishable from text */
    return 0;
}

/* The backend anchor is weak on purpose and cannot be otherwise: a bulk's
 * payload may hold a perfectly formed reply, so no pattern is evidence. The
 * discipline comes from the call boundary the framer adds to it. */
static int test_anchor_be(void)
{
    CHECK(redis_anchor_be((const __u8 *)"+OK\r\n", 5));
    CHECK(redis_anchor_be((const __u8 *)"-WRONGTYPE x", 12));
    CHECK(redis_anchor_be((const __u8 *)"*3\r\n", 4));
    CHECK(redis_anchor_be((const __u8 *)">2\r\n", 4)); /* a push is a reply too */
    CHECK(redis_anchor_be((const __u8 *)"_\r\n", 3));

    CHECK(!redis_anchor_be((const __u8 *)"", 0));
    CHECK(!redis_anchor_be((const __u8 *)"OK\r\n", 4));
    CHECK(!redis_anchor_be((const __u8 *)"\n", 1)); /* a replication keepalive */
    return 0;
}

int main(void)
{
    if (test_shapes() || test_resp3_marker() || test_parse_i64() || test_bulk_len() ||
        test_agg_count() || test_line_at() || test_anchor_fe() || test_anchor_be())
        return 1;
    printf("ok\n");
    return 0;
}
