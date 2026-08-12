// SPDX-License-Identifier: GPL-2.0
/* See go_pclntab.h. The layout, as of Go 1.18 (runtime/symtab.go, `pcHeader`);
 * every offset below is relative to the start of the table:
 *
 *    0  magic     u32   0xFFFFFFF0 (1.18/1.19) or 0xFFFFFFF1 (1.20+)
 *    4  pad       u8[2] both zero — part of the validation
 *    6  minLC     u8    instruction alignment (1 on x86-64)
 *    7  ptrSize   u8    8 here
 *    8  nfunc     i64   number of functions
 *   16  nfiles    u64
 *   24  textStart u64   virtual address the entry offsets are relative to
 *   32  funcnameOffset u64   -> the name string table
 *   40  cuOffset       u64
 *   48  filetabOffset  u64
 *   56  pctabOffset    u64
 *   64  pclnOffset     u64   -> the function table
 *
 * The function table at `pclnOffset` is nfunc+1 pairs of u32:
 *
 *   { entryOff, funcOff } ... { textEnd, - }
 *
 * sorted by entryOff, with a sentinel whose entryOff is the end of the text
 * segment — which is what gives the last function a size. `funcOff` points
 * (again from the table start, past pclnOffset) at a `_func`, whose first two
 * fields are the ones this module reads:
 *
 *    0  entryOff u32
 *    4  nameOff  i32   -> funcnametab, a NUL-terminated name
 *
 * Everything else in `_func` is line tables and metadata a probe does not care
 * about, so nothing here depends on the parts of the struct that keep changing
 * between releases (startLine arrived in 1.20, funcID values move around). */
#include "go_pclntab.h"

#include <string.h>

#define GO_MAGIC_118 0xfffffff0u /* Go 1.18, 1.19 */
#define GO_MAGIC_120 0xfffffff1u /* Go 1.20+ */

/* Offsets inside the header, for ptrSize == 8. */
#define HDR_NFUNC     8
#define HDR_TEXTSTART 24
#define HDR_FUNCNAME  32
#define HDR_PCLN      64
#define HDR_SIZE      72

/* A function's own entry in the table: what a probe needs and nothing else. */
#define FUNC_NAMEOFF 4

/* Bounded little-endian reads. Every one of them is checked against the table
 * size by its caller having already validated the range — the helpers take the
 * length so a malformed header cannot walk past the buffer. */
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

/* A NUL-terminated name inside the table, compared without copying it out. */
static int name_is(const uint8_t *tab, size_t n, uint64_t off, const char *name)
{
    size_t len = strlen(name);

    if (off >= n || n - off <= len)
        return 0;
    if (memcmp(tab + off, name, len))
        return 0;
    return tab[off + len] == '\0';
}

int lk_go_pclntab_find(const uint8_t *tab, size_t n, uint64_t text_base, const char *name,
                       uint64_t *vaddr, uint64_t *size)
{
    uint64_t nfunc, text_start, funcname_off, pcln_off;
    uint32_t magic;

    if (!tab || !name || !vaddr || !size || n < HDR_SIZE)
        return -2;

    magic = rd32(tab);
    if (magic != GO_MAGIC_118 && magic != GO_MAGIC_120)
        return -2; /* Go 1.17 or older, or not a pclntab at all */
    if (tab[4] || tab[5] || tab[7] != 8)
        return -2; /* pad must be zero; 64-bit pointers only */
    if (tab[6] == 0)
        return -2; /* minLC of zero is not a table we understand */

    nfunc = rd64(tab + HDR_NFUNC);
    /* Zero in the file image of every Go binary examined — the runtime fills it
     * from the loaded module — so the caller's `.text` address stands in. */
    text_start = rd64(tab + HDR_TEXTSTART);
    if (!text_start)
        text_start = text_base;
    funcname_off = rd64(tab + HDR_FUNCNAME);
    pcln_off = rd64(tab + HDR_PCLN);

    /* The function table is nfunc+1 pairs of u32; anything that does not fit in
     * the buffer means the header is not describing this buffer. */
    if (funcname_off >= n || pcln_off >= n)
        return -2;
    if (nfunc == 0 || nfunc + 1 > (n - pcln_off) / 8)
        return -2;

    for (uint64_t i = 0; i < nfunc; i++) {
        const uint8_t *ent = tab + pcln_off + i * 8;
        uint64_t func_off = pcln_off + rd32(ent + 4);
        uint64_t entry_off = rd32(ent);
        uint64_t next_off;
        int32_t name_off;

        if (func_off + 8 > n)
            return -2;
        name_off = (int32_t)rd32(tab + func_off + FUNC_NAMEOFF);
        if (name_off < 0)
            continue;
        if (!name_is(tab, n, funcname_off + (uint64_t)name_off, name))
            continue;

        /* Size comes from where the next function starts — the table is sorted
         * by entry offset and carries a sentinel past the last one, so this is
         * defined for every function including the last. The gap includes the
         * inter-function padding, which is int3 and decodes as such. */
        next_off = rd32(tab + pcln_off + (i + 1) * 8);
        if (next_off <= entry_off)
            return -2; /* not sorted: not a table we can reason about */
        *vaddr = text_start + entry_off;
        *size = next_off - entry_off;
        return 0;
    }
    return -1;
}
