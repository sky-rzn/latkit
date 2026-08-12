// SPDX-License-Identifier: GPL-2.0
/* See x86_len.h. A length decoder, not a disassembler: it answers "how long is
 * this instruction" and "is that byte an opcode or an operand", which is all
 * the RET search needs.
 *
 * Shape of the decode, in the order the bytes come:
 *
 *   [legacy prefixes]* [REX] opcode [ModRM [SIB]] [displacement] [immediate]
 *
 * Two tables carry the per-opcode knowledge — one for the one-byte map, one for
 * the 0x0F map — and each entry says only what changes the length: does it take
 * a ModRM byte, and how many immediate bytes follow. OP_BAD marks everything
 * outside the supported subset, and the AVX prefixes (VEX C4/C5, EVEX 62) are
 * deliberately in it: a Go compiler emits none of them in the functions we
 * hook, so the honest reaction to seeing one is to stop rather than to grow a
 * second decoder no test would ever exercise. */
#include "x86_len.h"

#include <stdbool.h>

/* Per-opcode length attributes. OP_IMM_Z is the operand-size-dependent
 * immediate (4 bytes, 2 under a 0x66 prefix); OP_IMM_V is the same but 8 bytes
 * under REX.W (the B8+r `movabs` form, the only 64-bit immediate in the ISA);
 * OP_IMM_A is the address-size-dependent one used by the A0..A3 moffs forms. */
#define OP_MODRM (1u << 0)
#define OP_IMM8  (1u << 1)
#define OP_IMM16 (1u << 2)
#define OP_IMM_Z (1u << 3)
#define OP_IMM_V (1u << 4)
#define OP_IMM_A (1u << 5)
#define OP_BAD   (1u << 6) /* not in the supported subset: refuse */
#define OP_GRP1  (1u << 7) /* F6/F7: immediate only when ModRM.reg is 0 or 1 */

#define B OP_BAD
#define M OP_MODRM
#define I OP_IMM8
#define W OP_IMM16
#define Z OP_IMM_Z
#define V OP_IMM_V
#define A OP_IMM_A
#define G OP_GRP1
#define _ 0u

/* One-byte opcode map. Prefixes (26/2E/36/3E/64/65/66/67/F0/F2/F3), the REX
 * range 40..4F and the 0F escape are consumed before the lookup, so those
 * entries are never read; they are left zero rather than marked bad so the
 * table stays a faithful picture of the map. */
/* The two maps are laid out sixteen opcodes to a row, the way every x86 opcode
 * table in every manual is, so a row's index is its high nibble and an entry can
 * be checked against the reference by eye — hence the formatter is held off for
 * them; reflowed they become three hundred unreadable lines. */
/* clang-format off */
static const unsigned char op1[256] = {
    /* 00 */ M, M, M, M, I, Z, B, B, M, M, M, M, I, Z, B, _,
    /* 10 */ M, M, M, M, I, Z, B, B, M, M, M, M, I, Z, B, B,
    /* 20 */ M, M, M, M, I, Z, _, B, M, M, M, M, I, Z, _, B,
    /* 30 */ M, M, M, M, I, Z, _, B, M, M, M, M, I, Z, _, B,
    /* 40 */ _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _,
    /* 50 */ _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _,
    /* 60 */ B, B, B, M, _, _, _, _, Z, M|Z, I, M|I, _, _, _, _,
    /* 70 */ I, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I,
    /* 80 */ M|I, M|Z, B, M|I, M, M, M, M, M, M, M, M, M, M, M, M,
    /* 90 */ _, _, _, _, _, _, _, _, _, _, B, _, _, _, _, _,
    /* A0 */ A, A, A, A, _, _, _, _, I, Z, _, _, _, _, _, _,
    /* B0 */ I, I, I, I, I, I, I, I, V, V, V, V, V, V, V, V,
    /* C0 */ M|I, M|I, W, _, B, B, M|I, M|Z, W|I, _, W, _, _, I, B, _,
    /* D0 */ M, M, M, M, B, B, B, _, M, M, M, M, M, M, M, M,
    /* E0 */ I, I, I, I, I, I, I, I, Z, Z, B, I, _, _, _, _,
    /* F0 */ _, _, _, _, _, _, M|G, M|G, _, _, _, _, _, _, M, M,
};

/* 0x0F map. The two three-byte escapes (0F 38, 0F 3A) are handled in the
 * decoder rather than here, since they consume a further opcode byte. */
static const unsigned char op2[256] = {
    /* 00 */ M, M, M, M, B, _, _, _, _, _, B, _, B, M, _, B,
    /* 10 */ M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    /* 20 */ M, M, M, M, B, B, B, B, M, M, M, M, M, M, M, M,
    /* 30 */ _, _, _, _, _, _, B, _, _, B, _, B, B, B, B, B,
    /* 40 */ M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    /* 50 */ M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    /* 60 */ M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    /* 70 */ M|I, M|I, M|I, M|I, M, M, M, _, M, M, B, B, M, M, M, M,
    /* 80 */ Z, Z, Z, Z, Z, Z, Z, Z, Z, Z, Z, Z, Z, Z, Z, Z,
    /* 90 */ M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    /* A0 */ _, _, _, M, M|I, M, B, B, _, _, _, M, M|I, M, M, M,
    /* B0 */ M, M, M, M, M, M, M, M, M, M, M|I, M, M, M, M, M,
    /* C0 */ M, M, M|I, M, M|I, M|I, M|I, M, _, _, _, _, _, _, _, _,
    /* D0 */ M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    /* E0 */ M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
    /* F0 */ M, M, M, M, M, M, M, M, M, M, M, M, M, M, M, M,
};
/* clang-format on */

#undef B
#undef M
#undef I
#undef W
#undef Z
#undef V
#undef A
#undef G
#undef _

/* Longest legal x86-64 instruction; a decode that grows past it is lost. */
#define X86_MAX_INSN 15

/* The decoder proper. On success returns the length and, through *op_off, the
 * index of the opcode byte within the instruction — which is what makes "is
 * this a ret" a question about an opcode rather than about a byte value. */
static int insn_len(const uint8_t *p, size_t n, size_t *op_off)
{
    bool opsz = false, addrsz = false, rex_w = false;
    unsigned flags;
    size_t i = 0;
    uint8_t op;

    if (!p)
        return -1;
    /* Legacy prefixes, any order and any number (up to the length limit). Only
     * the two size overrides change a length; the rest are noted and skipped. */
    for (;;) {
        if (i >= n || i >= X86_MAX_INSN)
            return -1;
        switch (p[i]) {
        case 0x66:
            opsz = true;
            break;
        case 0x67:
            addrsz = true;
            break;
        case 0xF0: /* lock */
        case 0xF2: /* repne / scalar-double selector */
        case 0xF3: /* rep / scalar-single selector */
        case 0x2E:
        case 0x36:
        case 0x3E:
        case 0x26: /* segment overrides; 2E/3E double as branch hints */
        case 0x64:
        case 0x65: /* fs/gs: Go's TLS accesses use these */
            break;
        default:
            goto prefixes_done;
        }
        i++;
    }
prefixes_done:
    /* REX, when present, is the last prefix before the opcode. */
    if ((p[i] & 0xf0) == 0x40) {
        rex_w = (p[i] & 0x08) != 0;
        if (++i >= n)
            return -1;
    }

    *op_off = i;
    op = p[i++];
    if (op == 0x0f) {
        if (i >= n)
            return -1;
        op = p[i++];
        if (op == 0x38 || op == 0x3a) {
            /* Three-byte maps: one more opcode byte, always ModRM, and the
             * 3A map always carries an imm8. */
            if (i >= n)
                return -1;
            i++;
            flags = OP_MODRM | (op == 0x3a ? OP_IMM8 : 0u);
        } else {
            flags = op2[op];
        }
    } else {
        flags = op1[op];
    }
    if (flags & OP_BAD)
        return -1;

    if (flags & OP_MODRM) {
        unsigned mod, rm;
        uint8_t modrm;

        if (i >= n)
            return -1;
        modrm = p[i++];
        mod = modrm >> 6;
        rm = modrm & 7;
        /* F6/F7 are two instructions in one opcode: test takes an immediate,
         * the not/neg/mul/div forms do not. ModRM.reg decides. */
        if (flags & OP_GRP1) {
            unsigned reg = (modrm >> 3) & 7;

            if (reg <= 1)
                flags |= (op == 0xf6) ? OP_IMM8 : OP_IMM_Z;
        }
        if (mod != 3) {
            if (rm == 4) { /* SIB byte */
                uint8_t sib;

                if (i >= n)
                    return -1;
                sib = p[i++];
                if (mod == 0 && (sib & 7) == 5)
                    i += 4; /* no base register: disp32 */
            } else if (mod == 0 && rm == 5) {
                i += 4; /* RIP-relative */
            }
            if (mod == 1)
                i += 1;
            else if (mod == 2)
                i += 4;
        }
    }

    if (flags & OP_IMM8)
        i += 1;
    if (flags & OP_IMM16)
        i += 2;
    /* rel16 branches (0x66 on E8/E9/0F 8x) are legal on paper and emitted by no
     * compiler; the operand-size rule below reads them as such anyway. */
    if (flags & OP_IMM_Z)
        i += opsz ? 2 : 4;
    if (flags & OP_IMM_V)
        i += rex_w ? 8 : (opsz ? 2 : 4);
    if (flags & OP_IMM_A)
        i += addrsz ? 4 : 8;

    if (i > n || i > X86_MAX_INSN)
        return -1;
    return (int)i;
}

int lk_x86_insn_len(const uint8_t *p, size_t n)
{
    size_t op_off;

    return insn_len(p, n, &op_off);
}

int lk_x86_find_rets(const uint8_t *code, size_t len, uint32_t *out, int max)
{
    size_t off = 0;
    int nret = 0;

    if (!code || !out || max <= 0 || !len)
        return -1;
    while (off < len) {
        size_t op_off;
        int l = insn_len(code + off, len - off, &op_off);

        if (l <= 0)
            return -1; /* unknown opcode, or the body ends mid-instruction */
        /* `ret` (C3) and its rarely-emitted `ret imm16` sibling (C2) are the
         * only near returns; both leave the function here. The uprobe goes on
         * the first byte of the instruction, prefixes and all — `rep ret`
         * (F3 C3) is one instruction, not a prefix followed by a return. */
        if (code[off + op_off] == 0xc3 || code[off + op_off] == 0xc2) {
            if (nret == max)
                return -1; /* more exits than the caller can hook: refuse */
            out[nret++] = (uint32_t)off;
        }
        off += (size_t)l;
    }
    if (off != len)
        return -1; /* the last instruction overran the function: walk is lost */
    return nret;
}
