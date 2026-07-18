// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the bounded MySQL wire cursor (МYSQL.md М2, my_wire.h) —
 * the pg_wire test matrix in little-endian plus the protocol's own scalars:
 * lenenc integers (all four widths, the 0xfb/0xff non-lenenc heads, truncated
 * tails), lenenc strings (salvage on truncation), NUL strings, and the
 * overrun latch (a failed read parks the cursor at end; nothing ever reads
 * past the bound — the fuzz invariant). */
#include <linux/types.h>
#include <stdio.h>
#include <string.h>

#include "my_wire.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* Fixed-width getters read little-endian and advance; exhaustion latches. */
static int test_scalars(void)
{
    static const __u8 buf[] = {0x2a, 0x34, 0x12, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34,
                               0x12, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01};
    struct my_wire w;
    __u8 v8;
    __u16 v16;
    __u32 v32;
    __u64 v64;

    my_wire_init(&w, buf, sizeof(buf));
    CHECK(my_wire_get_u8(&w, &v8) && v8 == 0x2a);
    CHECK(my_wire_get_u16(&w, &v16) && v16 == 0x1234);
    CHECK(my_wire_get_u24(&w, &v32) && v32 == 0x123456);
    CHECK(my_wire_get_u32(&w, &v32) && v32 == 0x12345678);
    CHECK(my_wire_get_u64(&w, &v64) && v64 == 0x0123456789abcdefull);
    CHECK(my_wire_remaining(&w) == 0 && my_wire_ok(&w));

    CHECK(!my_wire_get_u8(&w, &v8) && v8 == 0); /* dry: overrun, zeroed out */
    CHECK(!my_wire_ok(&w));
    CHECK(!my_wire_get_u32(&w, &v32) && v32 == 0); /* latched: still failing */

    /* A read wider than what remains must not consume the tail. */
    my_wire_init(&w, buf, 3);
    CHECK(!my_wire_get_u32(&w, &v32) && !my_wire_ok(&w));
    CHECK(my_wire_remaining(&w) == 0); /* parked at end, no wrap */
    return 0;
}

static int test_skip(void)
{
    static const __u8 buf[] = {1, 2, 3, 4, 5};
    struct my_wire w;
    __u8 v;

    my_wire_init(&w, buf, sizeof(buf));
    CHECK(my_wire_skip(&w, 3));
    CHECK(my_wire_get_u8(&w, &v) && v == 4);
    CHECK(!my_wire_skip(&w, 2) && !my_wire_ok(&w)); /* only 1 left */

    my_wire_init(&w, buf, sizeof(buf));
    CHECK(my_wire_skip(&w, 5) && my_wire_remaining(&w) == 0 && my_wire_ok(&w));
    return 0;
}

/* Lenenc integers: literal, +u16, +u24, +u64; 0xfb/0xff are not lenenc and
 * leave the cursor untouched with no overrun; a cut tail is an overrun. */
static int test_lenenc(void)
{
    static const __u8 buf[] = {
        0xfa,                                           /* literal 250 */
        0xfc, 0xcd, 0xab,                               /* 0xabcd */
        0xfd, 0x56, 0x34, 0x12,                         /* 0x123456 */
        0xfe, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, /* 8-byte ... */
        0x11,                                           /* ... 0x1122334455667788 */
        0xfb,                                           /* row NULL marker */
    };
    struct my_wire w;
    __u64 v;
    __u8 b;

    my_wire_init(&w, buf, sizeof(buf));
    CHECK(my_wire_get_lenenc(&w, &v) && v == 250);
    CHECK(my_wire_get_lenenc(&w, &v) && v == 0xabcd);
    CHECK(my_wire_get_lenenc(&w, &v) && v == 0x123456);
    CHECK(my_wire_get_lenenc(&w, &v) && v == 0x1122334455667788ull);

    /* 0xfb: refused, cursor parked ON the byte, no overrun — the caller's
     * phase context reads it itself. */
    CHECK(!my_wire_get_lenenc(&w, &v) && my_wire_ok(&w));
    CHECK(my_wire_get_u8(&w, &b) && b == 0xfb);
    CHECK(my_wire_remaining(&w) == 0);

    static const __u8 err_head[] = {0xff, 0x12};

    my_wire_init(&w, err_head, sizeof(err_head));
    CHECK(!my_wire_get_lenenc(&w, &v) && my_wire_ok(&w));
    CHECK(my_wire_remaining(&w) == 2); /* untouched */

    /* Truncated wide forms: overrun, not garbage. */
    static const __u8 cut16[] = {0xfc, 0x01};

    my_wire_init(&w, cut16, sizeof(cut16));
    CHECK(!my_wire_get_lenenc(&w, &v) && !my_wire_ok(&w) && v == 0);

    my_wire_init(&w, NULL, 0); /* empty body: plain overrun */
    CHECK(!my_wire_get_lenenc(&w, &v) && !my_wire_ok(&w));
    return 0;
}

/* Lenenc strings: in-buffer pointer on success; truncation salvages the
 * available prefix and latches overrun (the pg_wire_cstring pattern). */
static int test_lenenc_str(void)
{
    static const __u8 buf[] = {5, 'h', 'e', 'l', 'l', 'o', 3, 'x', 'y', 'z'};
    struct my_wire w;
    const char *s;
    __u32 len;

    my_wire_init(&w, buf, sizeof(buf));
    CHECK(my_wire_get_lenenc_str(&w, &s, &len));
    CHECK(len == 5 && memcmp(s, "hello", 5) == 0);
    CHECK(my_wire_get_lenenc_str(&w, &s, &len));
    CHECK(len == 3 && memcmp(s, "xyz", 3) == 0);
    CHECK(my_wire_remaining(&w) == 0 && my_wire_ok(&w));

    /* Length runs past the bound: salvage what is there. */
    static const __u8 cut[] = {9, 'p', 'r', 'e'};

    my_wire_init(&w, cut, sizeof(cut));
    CHECK(!my_wire_get_lenenc_str(&w, &s, &len));
    CHECK(!my_wire_ok(&w));
    CHECK(len == 3 && memcmp(s, "pre", 3) == 0);
    CHECK(my_wire_remaining(&w) == 0);

    /* A 0xfb head is not a string either: cursor untouched, no overrun. */
    static const __u8 nul_mark[] = {0xfb, 'a'};

    my_wire_init(&w, nul_mark, sizeof(nul_mark));
    CHECK(!my_wire_get_lenenc_str(&w, &s, &len) && my_wire_ok(&w));
    CHECK(my_wire_remaining(&w) == 2);
    return 0;
}

/* NUL-terminated strings: same salvage semantics as pg_wire_cstring. */
static int test_cstring(void)
{
    static const __u8 buf[] = {'8', '.', '4', '.', '1', '0', 0, 'q'};
    struct my_wire w;
    const char *s;
    __u32 len;
    __u8 b;

    my_wire_init(&w, buf, sizeof(buf));
    CHECK(my_wire_cstring(&w, &s, &len));
    CHECK(len == 6 && memcmp(s, "8.4.10", 6) == 0);
    CHECK(my_wire_get_u8(&w, &b) && b == 'q');

    static const __u8 cut[] = {'a', 'b', 'c'}; /* no terminator */

    my_wire_init(&w, cut, sizeof(cut));
    CHECK(!my_wire_cstring(&w, &s, &len) && !my_wire_ok(&w));
    CHECK(len == 3 && memcmp(s, "abc", 3) == 0);

    my_wire_init(&w, NULL, 0);
    CHECK(!my_wire_cstring(&w, &s, &len) && !my_wire_ok(&w));
    CHECK(s != NULL && len == 0); /* never a NULL out: an empty string */
    return 0;
}

int main(void)
{
    if (test_scalars() || test_skip() || test_lenenc() || test_lenenc_str() || test_cstring())
        return 1;
    printf("ok\n");
    return 0;
}
