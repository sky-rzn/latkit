// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the Go function-table reader (PLAN-HTTP.md М7, РH13.3,
 * src/agent/go_pclntab.c).
 *
 * The table is built here rather than taken from a fixture: shipping a Go
 * binary in the repository to test a parser is a poor trade, and a synthetic
 * table exercises the parts that matter — the header validation, the name
 * lookup, the entry/size arithmetic and every refusal — without a Go toolchain
 * in the loop. The *real* binaries are checked where they belong: the e2e stand
 * builds a server both ways (with and without `-ldflags "-s -w"`), and the
 * agent resolving the stripped one through this code is the assertion.
 *
 * One property is worth naming because it caught a real bug: the header's
 * `textStart` is **zero in the file image** of every Go binary examined (the
 * runtime fills it in at load time), so the caller's `.text` address has to
 * stand in. Read literally, the field would place every probe at an address
 * about 4 MB too low — inside a live server. The last test pins the rule.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "go_pclntab.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* Layout of the table this file builds, mirroring a real one:
 *
 *   [0, 72)     pcHeader
 *   [72, ...)   funcnametab: the two names, NUL-terminated
 *   FUNCTAB     nfunc+1 pairs of u32 {entryOff, funcOff}
 *   FUNCS       the _func structs the pairs point at
 */
#define TAB_SIZE     512
#define FUNCNAME_OFF 72
#define FUNCTAB_OFF  200
#define FUNCS_OFF    300

static uint8_t tab[TAB_SIZE];

static void put32(size_t off, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        tab[off + i] = (uint8_t)(v >> (8 * i));
}

static void put64(size_t off, uint64_t v)
{
    put32(off, (uint32_t)v);
    put32(off + 4, (uint32_t)(v >> 32));
}

/* Two functions at text-relative 0x100 (size 0x80) and 0x200 (size 0x40), plus
 * the sentinel that gives the second one its size. */
static void build(uint32_t magic, uint64_t text_start)
{
    size_t n0 = FUNCNAME_OFF, n1;

    memset(tab, 0, sizeof(tab));
    put32(0, magic);
    tab[6] = 1;   /* minLC */
    tab[7] = 8;   /* ptrSize */
    put64(8, 2);  /* nfunc */
    put64(16, 1); /* nfiles */
    put64(24, text_start);
    put64(32, FUNCNAME_OFF);
    put64(64, FUNCTAB_OFF);

    strcpy((char *)tab + n0, "crypto/tls.(*Conn).Write");
    n1 = n0 + strlen("crypto/tls.(*Conn).Write") + 1;
    strcpy((char *)tab + n1, "main.main");

    /* functab: {entryOff, funcOff}, sorted, with the trailing sentinel. */
    put32(FUNCTAB_OFF + 0, 0x100);
    put32(FUNCTAB_OFF + 4, FUNCS_OFF - FUNCTAB_OFF);
    put32(FUNCTAB_OFF + 8, 0x200);
    put32(FUNCTAB_OFF + 12, (FUNCS_OFF + 16) - FUNCTAB_OFF);
    put32(FUNCTAB_OFF + 16, 0x240); /* sentinel: end of text */

    /* _func: entryOff, then nameOff into funcnametab. */
    put32(FUNCS_OFF + 0, 0x100);
    put32(FUNCS_OFF + 4, (uint32_t)(n0 - FUNCNAME_OFF));
    put32(FUNCS_OFF + 16, 0x200);
    put32(FUNCS_OFF + 20, (uint32_t)(n1 - FUNCNAME_OFF));
}

static int test_lookup(void)
{
    uint64_t va = 0, sz = 0;

    build(0xfffffff1u, 0); /* Go 1.20+ */
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x401000, "crypto/tls.(*Conn).Write", &va, &sz) ==
          0);
    CHECK(va == 0x401100 && sz == 0x100);
    /* The last function's size comes from the sentinel, which is the only
     * reason the table can size it at all. */
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x401000, "main.main", &va, &sz) == 0);
    CHECK(va == 0x401200 && sz == 0x40);
    /* A name that is a prefix of a present one must not match: the comparison
     * is against the whole NUL-terminated string. */
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x401000, "main.ma", &va, &sz) == -1);
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x401000, "crypto/tls.(*Conn).Read", &va, &sz) ==
          -1);

    /* Go 1.18/1.19 spell the magic differently and are otherwise the same. */
    build(0xfffffff0u, 0);
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x401000, "main.main", &va, &sz) == 0);
    CHECK(va == 0x401200);
    return 0;
}

/* The textStart rule, and why it is a rule. */
static int test_text_base(void)
{
    uint64_t va = 0, sz = 0;

    /* Zero in the file (what every real binary looks like): the caller's .text
     * address is the base. */
    build(0xfffffff1u, 0);
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x400000, "main.main", &va, &sz) == 0);
    CHECK(va == 0x400200);

    /* Non-zero: the file said so, and the file wins. */
    build(0xfffffff1u, 0x800000);
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x400000, "main.main", &va, &sz) == 0);
    CHECK(va == 0x800200);
    return 0;
}

/* Everything unrecognised is a refusal, and the two kinds of failure stay
 * distinguishable: -1 "not in this binary", -2 "not a table we understand". */
static int test_refusals(void)
{
    uint64_t va = 0, sz = 0;

    build(0xfffffffbu, 0); /* Go 1.2 .. 1.17 magics */
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x401000, "main.main", &va, &sz) == -2);

    build(0xfffffff1u, 0);
    tab[4] = 1; /* the pad bytes must be zero */
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x401000, "main.main", &va, &sz) == -2);

    build(0xfffffff1u, 0);
    tab[7] = 4; /* 32-bit pointers: a different layout, not a smaller one */
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x401000, "main.main", &va, &sz) == -2);

    build(0xfffffff1u, 0);
    put64(8, 1u << 30); /* nfunc that cannot fit the buffer */
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x401000, "main.main", &va, &sz) == -2);

    build(0xfffffff1u, 0);
    put64(64, TAB_SIZE + 8); /* functab outside the table */
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x401000, "main.main", &va, &sz) == -2);

    build(0xfffffff1u, 0);
    put32(FUNCTAB_OFF + 8, 0x080); /* entries out of order: sizes are meaningless */
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x401000, "crypto/tls.(*Conn).Write", &va, &sz) ==
          -2);

    build(0xfffffff1u, 0);
    CHECK(lk_go_pclntab_find(tab, 8, 0x401000, "main.main", &va, &sz) == -2); /* truncated */
    CHECK(lk_go_pclntab_find(NULL, sizeof(tab), 0x401000, "main.main", &va, &sz) == -2);
    CHECK(lk_go_pclntab_find(tab, sizeof(tab), 0x401000, NULL, &va, &sz) == -2);
    return 0;
}

int main(void)
{
    if (test_lookup() || test_text_base() || test_refusals())
        return 1;
    printf("ok\n");
    return 0;
}
