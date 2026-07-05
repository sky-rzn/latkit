// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the bounded read cursor (Р18, task 3.1). The parser's only
 * door to an untrusted body: every read stays in bounds, big-endian decodes
 * are correct, a missing cstring terminator is an overrun (not an OOB read),
 * and — the distinction the whole design hinges on — running out of bytes is
 * reported uniformly as `overrun`, leaving the caller to read it as truncation
 * (budget) or corruption (full body) using the message's TRUNC flag. */
#include <linux/types.h>
#include <stdio.h>
#include <string.h>

#include "pg_wire.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* Every accessor decodes correctly and advances by exactly its width; the
 * cursor lands precisely at end with nothing left over. */
static int test_reads_in_bounds(void)
{
    /* u8=0x41, u16=0x4243 (BE), u32=0x44454647 (BE), cstring "hi", u8=0x7a */
    const __u8 body[] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 'h', 'i', 0x00, 0x7a};
    struct pg_wire w;
    __u8 u8;
    __u16 u16;
    __u32 u32;
    const char *s;
    __u32 slen;

    pg_wire_init(&w, body, sizeof(body));
    CHECK(pg_wire_remaining(&w) == sizeof(body));

    CHECK(pg_wire_get_u8(&w, &u8) && u8 == 0x41);
    CHECK(pg_wire_get_u16(&w, &u16) && u16 == 0x4243);      /* big-endian */
    CHECK(pg_wire_get_u32(&w, &u32) && u32 == 0x44454647u); /* big-endian */
    CHECK(pg_wire_cstring(&w, &s, &slen) && slen == 2 && memcmp(s, "hi", 2) == 0);
    CHECK(pg_wire_get_u8(&w, &u8) && u8 == 0x7a);

    CHECK(pg_wire_ok(&w));
    CHECK(pg_wire_remaining(&w) == 0);
    return 0;
}

/* A read wider than what remains fails without touching memory past end, zeroes
 * the out-param, does not advance past end, and latches overrun so every later
 * read fails too (no wraparound). */
static int test_out_of_bounds(void)
{
    const __u8 body[] = {0x01, 0x02, 0x03};
    struct pg_wire w;
    __u8 u8;
    __u16 u16;
    __u32 u32;

    /* u32 needs 4, only 3 available: overrun, out zeroed, cursor pinned. */
    pg_wire_init(&w, body, sizeof(body));
    CHECK(!pg_wire_get_u32(&w, &u32) && u32 == 0);
    CHECK(!pg_wire_ok(&w));
    CHECK(pg_wire_remaining(&w) == 0);
    CHECK(!pg_wire_get_u8(&w, &u8) && u8 == 0); /* still failing, not wrapped */

    /* u16 straddling the end: consumes nothing, fails cleanly. */
    pg_wire_init(&w, body, sizeof(body));
    CHECK(pg_wire_get_u16(&w, &u16) && u16 == 0x0102);
    CHECK(!pg_wire_get_u16(&w, &u16) && u16 == 0); /* 1 byte left, need 2 */
    CHECK(!pg_wire_ok(&w));

    /* skip past the end fails and pins the cursor. */
    pg_wire_init(&w, body, sizeof(body));
    CHECK(!pg_wire_skip(&w, 4));
    CHECK(!pg_wire_ok(&w) && pg_wire_remaining(&w) == 0);

    /* skip of exactly what remains is fine. */
    pg_wire_init(&w, body, sizeof(body));
    CHECK(pg_wire_skip(&w, 3) && pg_wire_ok(&w) && pg_wire_remaining(&w) == 0);
    return 0;
}

/* A cstring with no NUL before end: overrun, but the available prefix is still
 * handed back (out non-NULL, len = bytes seen) so a truncated body can salvage
 * it while a full body treats it as corruption. An empty buffer yields a valid
 * empty range. */
static int test_cstring_no_terminator(void)
{
    const __u8 body[] = {'a', 'b', 'c'}; /* no NUL */
    struct pg_wire w;
    const char *s;
    __u32 slen;

    pg_wire_init(&w, body, sizeof(body));
    CHECK(!pg_wire_cstring(&w, &s, &slen));
    CHECK(!pg_wire_ok(&w));
    CHECK(s == (const char *)body && slen == 3); /* prefix salvaged */
    CHECK(pg_wire_remaining(&w) == 0);

    /* Terminator as the very last byte: valid empty tail, cursor at end. */
    pg_wire_init(&w, (const __u8 *)"x\0", 2);
    CHECK(pg_wire_cstring(&w, &s, &slen) && slen == 1 && s[0] == 'x');
    CHECK(pg_wire_ok(&w) && pg_wire_remaining(&w) == 0);

    /* Empty buffer: cstring overruns, out is a valid empty range, not NULL. */
    pg_wire_init(&w, body, 0);
    CHECK(!pg_wire_cstring(&w, &s, &slen) && s != NULL && slen == 0);
    return 0;
}

/* Truncated (budget) vs corrupt (full body): pg_wire reports the same overrun;
 * the meaning is the caller's, driven by the TRUNC flag. This models that
 * decision so the contract is pinned. */
static int test_truncated_vs_corrupt(void)
{
    /* A message claims a u32 field but the captured prefix is only 2 bytes. */
    const __u8 prefix[] = {0x00, 0x01};
    struct pg_wire w;
    __u32 u32;

    /* Budget-truncated body (LK_MSG_BODY_TRUNC would be set): overrun means
     * "field unknown", the parser keeps the connection. */
    pg_wire_init(&w, prefix, sizeof(prefix));
    CHECK(!pg_wire_get_u32(&w, &u32));
    bool truncated_flag = true; /* stand-in for m->flags & LK_MSG_BODY_TRUNC */
    CHECK(!pg_wire_ok(&w) && truncated_flag /* => not an error, field unknown */);

    /* Same overrun on a full body (flag clear): the caller reads it as
     * corruption and bumps parse_errors. Identical cursor state, opposite
     * verdict — exactly the split Р18 draws. */
    pg_wire_init(&w, prefix, sizeof(prefix));
    CHECK(!pg_wire_get_u32(&w, &u32));
    bool truncated_flag2 = false;
    CHECK(!pg_wire_ok(&w) && !truncated_flag2 /* => corruption, parse_errors++ */);
    return 0;
}

int main(void)
{
    if (test_reads_in_bounds() || test_out_of_bounds() || test_cstring_no_terminator() ||
        test_truncated_vs_corrupt())
        return 1;
    printf("ok\n");
    return 0;
}
