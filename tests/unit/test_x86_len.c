// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the x86-64 length decoder and the return-site search
 * (PLAN-HTTP.md М7, РH13.3, src/agent/x86_len.c).
 *
 * This is the module whose failure mode is the worst in the whole agent: a
 * wrong length means a uprobe on a byte that is not an instruction boundary,
 * which corrupts the *observed* process — the one thing an observability tool
 * must never do. So the tests come in three groups, and the third is as
 * important as the first two:
 *
 *   1. lengths — every instruction shape a Go function body actually contains,
 *      with the encodings taken from a real assembler rather than from memory;
 *   2. the search — that `ret` is found where it is an opcode and *not* found
 *      where the same byte is an operand, which is the entire reason a decoder
 *      exists here instead of a memchr;
 *   3. refusals — truncation, unknown opcodes, AVX, a body that ends mid
 *      instruction, more exits than the caller can hold. Each must come back as
 *      a failure, because the caller's answer to a failure is to leave the
 *      function unhooked, and that is always the safe answer.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "x86_len.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

struct len_case {
    const char *asm_text;
    int len; /* expected, -1 = must be refused */
    uint8_t bytes[16];
};

/* Encodings produced by GNU as for the listed mnemonics — the instruction mix
 * of a Go method: prologue and stack frame, the fs-relative goroutine access,
 * RIP-relative addressing, immediates of every size, SSE moves, an atomic, and
 * the two forms of return. */
static const struct len_case len_cases[] = {
    {"ret", 1, {0xc3}},
    {"push %rbp", 1, {0x55}},
    {"mov %rsp,%rbp", 3, {0x48, 0x89, 0xe5}},
    {"mov 0x8(%rsp),%rax", 5, {0x48, 0x8b, 0x44, 0x24, 0x08}},                    /* SIB + disp8 */
    {"lea 0x78563412(%rip),%rax", 7, {0x48, 0x8d, 0x05, 0x12, 0x34, 0x56, 0x78}}, /* RIP-rel */
    {"call rel32", 5, {0xe8, 0x00, 0x00, 0x00, 0x00}},
    {"je rel8", 2, {0x74, 0xe8}},
    {"je rel32", 6, {0x0f, 0x84, 0x00, 0x00, 0x00, 0x00}},
    {"mov $0x1,%rax", 7, {0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00}},
    {"movabs $0x1122334455667788,%rax",
     10,
     {0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}},
    {"nopw (%rax,%rax,1)", 5, {0x66, 0x0f, 0x1f, 0x04, 0x00}},
    {"endbr64", 4, {0xf3, 0x0f, 0x1e, 0xfa}},
    {"sub $0x20,%rsp", 4, {0x48, 0x83, 0xec, 0x20}},
    {"neg %eax", 2, {0xf7, 0xd8}},                               /* F7 /3: no immediate */
    {"test $0x1,%ecx", 6, {0xf7, 0xc1, 0x01, 0x00, 0x00, 0x00}}, /* F7 /0: immediate */
    {"test $0x1,%eax", 5, {0xa9, 0x01, 0x00, 0x00, 0x00}},
    /* The goroutine pointer: a segment override, REX, SIB with no base. */
    {"mov %fs:-8,%rcx", 9, {0x64, 0x48, 0x8b, 0x0c, 0x25, 0xf8, 0xff, 0xff, 0xff}},
    {"syscall", 2, {0x0f, 0x05}},
    {"mov %rbx,0x10(%rsp)", 5, {0x48, 0x89, 0x5c, 0x24, 0x10}},
    {"int3", 1, {0xcc}},
    {"ud2", 2, {0x0f, 0x0b}},
    {"lret $0x10", 3, {0xca, 0x10, 0x00}},
    {"movq %xmm0,%rax", 5, {0x66, 0x48, 0x0f, 0x7e, 0xc0}},
    {"cmpxchg %rbx,(%rax)", 4, {0x48, 0x0f, 0xb1, 0x18}},
    {"movsd (%rax),%xmm1", 4, {0xf2, 0x0f, 0x10, 0x08}},
    {"ret $0x10", 3, {0xc2, 0x10, 0x00}},
    {"xchg %ax,%ax", 2, {0x66, 0x90}},
    {"mov $0xc3c3c3c3,%esi", 5, {0xbe, 0xc3, 0xc3, 0xc3, 0xc3}},
    /* Refused on purpose: AVX is not in the subset, and a compiler emits none
     * of it in the functions this module is pointed at. */
    {"vxorps %xmm0,%xmm0,%xmm0 (VEX2)", -1, {0xc5, 0xf8, 0x57, 0xc0}},
    {"VEX3 prefix", -1, {0xc4, 0xe2, 0x71, 0xf7, 0xc0}},
    {"EVEX prefix", -1, {0x62, 0xf1, 0x7c, 0x48, 0x28, 0xc0}},
    /* Invalid in 64-bit mode (the 32-bit `push %es` and friends). */
    {"push %es (invalid in long mode)", -1, {0x06}},
};

static int test_lengths(void)
{
    for (size_t i = 0; i < sizeof(len_cases) / sizeof(len_cases[0]); i++) {
        const struct len_case *c = &len_cases[i];
        /* The full 16 bytes are always readable, so a wrong answer here is a
         * decode error and never a truncation. */
        int got = lk_x86_insn_len(c->bytes, sizeof(c->bytes));

        if (got != c->len) {
            fprintf(stderr, "FAIL %s: length %d, want %d\n", c->asm_text, got, c->len);
            return 1;
        }
    }
    return 0;
}

/* A decode that would need one more byte than it has must fail rather than
 * report the length it hopes for: the caller uses the answer to place a probe. */
static int test_truncated(void)
{
    static const uint8_t mov_rsp[] = {0x48, 0x8b, 0x44, 0x24, 0x08};

    for (size_t n = 0; n < sizeof(mov_rsp); n++)
        CHECK(lk_x86_insn_len(mov_rsp, n) == -1);
    CHECK(lk_x86_insn_len(mov_rsp, sizeof(mov_rsp)) == 5);
    /* Prefixes with nothing after them are not an instruction either. */
    CHECK(lk_x86_insn_len((const uint8_t *)"\x66\x48", 2) == -1);
    return 0;
}

/* The point of the module. This body (GNU as output) carries eight 0xC3 bytes
 * inside a `movabs` immediate and four more inside a `mov $imm32`, and exactly
 * two real returns: `ret` at 0x10 and `ret $0x10` at 0x1b. A byte search would
 * report fourteen return sites, twelve of them in the middle of an
 * instruction. */
static const uint8_t body[] = {
    0xf7, 0xc1, 0x01, 0x00, 0x00, 0x00,                         /* test $1,%ecx */
    0x48, 0xbb, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, /* movabs ... */
    0xc3,                                                       /* ret         */
    0xbe, 0xc3, 0xc3, 0xc3, 0xc3,                               /* mov $imm,%esi */
    0x48, 0x39, 0xc3,                                           /* cmp %rax,%rbx */
    0x75, 0xe5,                                                 /* jne          */
    0xc2, 0x10, 0x00,                                           /* ret $0x10    */
};

static int test_find_rets(void)
{
    uint32_t rets[8];
    int n = lk_x86_find_rets(body, sizeof(body), rets, 8);

    CHECK(n == 2);
    CHECK(rets[0] == 0x10);
    CHECK(rets[1] == 0x1b);

    /* A byte scan is the wrong answer, and here is the number that says so. */
    int naive = 0;

    for (size_t i = 0; i < sizeof(body); i++)
        naive += body[i] == 0xc3;
    CHECK(naive == 14);
    return 0;
}

static int test_refusals(void)
{
    uint32_t rets[8];
    /* A body that ends in the middle of its last instruction: the walk was
     * lost somewhere behind, so nothing it produced can be trusted. */
    CHECK(lk_x86_find_rets(body, sizeof(body) - 1, rets, 8) == -1);
    /* An unsupported instruction anywhere in the body kills the whole body,
     * not just the tail after it. */
    static const uint8_t with_avx[] = {0xc5, 0xf8, 0x57, 0xc0, 0xc3};

    CHECK(lk_x86_find_rets(with_avx, sizeof(with_avx), rets, 8) == -1);
    /* More exits than the caller can hook: hooking a prefix of them would look
     * like lost plaintext instead of a refusal. */
    static const uint8_t many_rets[] = {0xc3, 0xc3, 0xc3, 0xc3};

    CHECK(lk_x86_find_rets(many_rets, sizeof(many_rets), rets, 4) == 4);
    CHECK(lk_x86_find_rets(many_rets, sizeof(many_rets), rets, 3) == -1);
    /* A function that never returns (a tail jump, or a body of padding) is not
     * an error, it simply has nothing to hook — and the caller says so. */
    static const uint8_t no_ret[] = {0x55, 0x48, 0x89, 0xe5, 0xeb, 0xfe};

    CHECK(lk_x86_find_rets(no_ret, sizeof(no_ret), rets, 8) == 0);
    /* Degenerate inputs. */
    CHECK(lk_x86_find_rets(body, 0, rets, 8) == -1);
    CHECK(lk_x86_find_rets(NULL, 4, rets, 8) == -1);
    CHECK(lk_x86_find_rets(body, sizeof(body), rets, 0) == -1);
    return 0;
}

/* Every byte of the corpus above, decoded from every possible start, must
 * either produce a length that stays inside the buffer or refuse. Nothing here
 * asserts a *correct* disassembly of a mid-instruction start — that is
 * meaningless — only that the decoder never claims a length it cannot back,
 * which is what keeps the walk from running off a function body. */
static int test_no_overrun(void)
{
    for (size_t start = 0; start < sizeof(body); start++) {
        for (size_t avail = 1; avail <= sizeof(body) - start; avail++) {
            int l = lk_x86_insn_len(body + start, avail);

            CHECK(l == -1 || (l > 0 && (size_t)l <= avail));
        }
    }
    return 0;
}

int main(void)
{
    if (test_lengths() || test_truncated() || test_find_rets() || test_refusals() ||
        test_no_overrun())
        return 1;
    printf("ok\n");
    return 0;
}
