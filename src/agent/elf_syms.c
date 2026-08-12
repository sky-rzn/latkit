// SPDX-License-Identifier: GPL-2.0
/* See elf_syms.h. Three passes over a file, all bounded:
 *
 *   1. the ELF header (identity, class, endianness, machine, section table);
 *   2. the section headers, to find SHT_SYMTAB and the string table it links;
 *   3. the symbol table itself, streamed in blocks, looking for one name.
 *
 * Plus the program headers, used for the one arithmetic step that matters: a
 * symbol's virtual address is not its position in the file, and a uprobe is
 * placed by file offset. The PT_LOAD segment covering the address gives the
 * translation (file_off = vaddr - p_vaddr + p_offset), which is exactly what
 * the kernel's own uprobe registration inverts when it maps the probe back into
 * every process that has the file mapped. */
#include "elf_syms.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Sanity ceilings. A real binary is far below all of them; a corrupt header is
 * the reason they exist — the allocations below are sized from file data. */
#define ELF_MAX_PHNUM  (1u << 12)
#define ELF_MAX_SYMS   (1u << 22)
#define ELF_SYM_BLOCK  256 /* symbols read per pread */
#define ELF_MAX_STRTAB (1u << 26)

struct lk_elf {
    int fd;
    off_t size;
    Elf64_Ehdr eh;
    Elf64_Phdr *ph; /* program headers, for vaddr -> file offset */
    unsigned nph;
    Elf64_Shdr *sh;
    unsigned nsh;
};

/* pread the whole range or fail; short reads are treated as failures because
 * every caller here reads a structure, not a stream. */
static int read_exact(struct lk_elf *e, void *buf, size_t n, uint64_t off)
{
    uint8_t *p = buf;

    if (off > (uint64_t)e->size || n > (uint64_t)e->size - off)
        return -1;
    while (n) {
        ssize_t got = pread(e->fd, p, n, (off_t)off);

        if (got <= 0) {
            if (got < 0 && errno == EINTR)
                continue;
            return -1;
        }
        p += got;
        off += (uint64_t)got;
        n -= (size_t)got;
    }
    return 0;
}

static int load_table(struct lk_elf *e, uint64_t off, unsigned count, size_t entsize, void **out)
{
    void *buf;

    if (!count)
        return 0;
    buf = calloc(count, entsize);
    if (!buf)
        return -1;
    if (read_exact(e, buf, (size_t)count * entsize, off)) {
        free(buf);
        return -1;
    }
    *out = buf;
    return 0;
}

struct lk_elf *lk_elf_open(const char *path)
{
    struct lk_elf *e;
    struct stat st;

    if (!path)
        return NULL;
    e = calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    e->fd = open(path, O_RDONLY | O_CLOEXEC);
    if (e->fd < 0)
        goto fail;
    if (fstat(e->fd, &st) || !S_ISREG(st.st_mode))
        goto fail;
    e->size = st.st_size;
    if (read_exact(e, &e->eh, sizeof(e->eh), 0))
        goto fail;
    if (memcmp(e->eh.e_ident, ELFMAG, SELFMAG) || e->eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        e->eh.e_ident[EI_DATA] != ELFDATA2LSB)
        goto fail;
    if (e->eh.e_shentsize != sizeof(Elf64_Shdr) && e->eh.e_shnum)
        goto fail;
    if (e->eh.e_phnum > ELF_MAX_PHNUM)
        goto fail;

    e->nsh = e->eh.e_shnum;
    e->nph = e->eh.e_phnum;
    if (e->eh.e_phentsize == sizeof(Elf64_Phdr) &&
        load_table(e, e->eh.e_phoff, e->nph, sizeof(Elf64_Phdr), (void **)&e->ph))
        goto fail;
    if (load_table(e, e->eh.e_shoff, e->nsh, sizeof(Elf64_Shdr), (void **)&e->sh))
        goto fail;
    return e;

fail:
    lk_elf_close(e);
    return NULL;
}

void lk_elf_close(struct lk_elf *e)
{
    if (!e)
        return;
    if (e->fd >= 0)
        close(e->fd);
    free(e->ph);
    free(e->sh);
    free(e);
}

uint16_t lk_elf_machine(const struct lk_elf *e)
{
    return e ? e->eh.e_machine : 0;
}

static const Elf64_Shdr *find_symtab(const struct lk_elf *e)
{
    for (unsigned i = 0; i < e->nsh; i++)
        if (e->sh[i].sh_type == SHT_SYMTAB && e->sh[i].sh_entsize == sizeof(Elf64_Sym))
            return &e->sh[i];
    return NULL;
}

bool lk_elf_has_symtab(const struct lk_elf *e)
{
    return e && e->sh && find_symtab(e) != NULL;
}

/* Virtual address -> file offset through the PT_LOAD segment that contains it.
 * Only p_filesz counts: a .bss address has no bytes in the file and no code we
 * could ever probe. Falls back to the section headers when a program header
 * table is absent (an unlinked object), which is not a case Go produces but
 * costs four lines to be right about. */
static int vaddr_to_off(const struct lk_elf *e, uint64_t v, uint64_t *out)
{
    for (unsigned i = 0; i < e->nph; i++) {
        const Elf64_Phdr *p = &e->ph[i];

        if (p->p_type != PT_LOAD || !p->p_filesz)
            continue;
        if (v >= p->p_vaddr && v - p->p_vaddr < p->p_filesz) {
            *out = v - p->p_vaddr + p->p_offset;
            return 0;
        }
    }
    for (unsigned i = 0; i < e->nsh; i++) {
        const Elf64_Shdr *s = &e->sh[i];

        if (!(s->sh_flags & SHF_ALLOC) || s->sh_type == SHT_NOBITS || !s->sh_size)
            continue;
        if (v >= s->sh_addr && v - s->sh_addr < s->sh_size) {
            *out = v - s->sh_addr + s->sh_offset;
            return 0;
        }
    }
    return -1;
}

/* Read a NUL-terminated name out of a string table section, bounded by it. */
static int read_name(struct lk_elf *e, const Elf64_Shdr *strtab, uint64_t idx, char *buf,
                     size_t bufsz)
{
    size_t n;

    if (idx >= strtab->sh_size)
        return -1;
    n = strtab->sh_size - idx;
    if (n > bufsz - 1)
        n = bufsz - 1;
    if (read_exact(e, buf, n, strtab->sh_offset + idx))
        return -1;
    buf[n] = '\0';
    return 0;
}

int lk_elf_find_func(struct lk_elf *e, const char *name, struct lk_elf_func *out)
{
    const Elf64_Shdr *symtab, *strtab;
    Elf64_Sym block[ELF_SYM_BLOCK];
    /* Go method names are long ("crypto/tls.(*Conn).WriteTo"); this is far more
     * than any of them and bounds the per-symbol string read. */
    char sym_name[512];
    uint64_t nsyms, done = 0;

    if (!e || !name || !out || !e->sh)
        return -1;
    symtab = find_symtab(e);
    if (!symtab || symtab->sh_link >= e->nsh)
        return -1;
    strtab = &e->sh[symtab->sh_link];
    if (strtab->sh_type != SHT_STRTAB || strtab->sh_size > ELF_MAX_STRTAB)
        return -1;

    nsyms = symtab->sh_size / sizeof(Elf64_Sym);
    if (nsyms > ELF_MAX_SYMS)
        return -1;

    while (done < nsyms) {
        uint64_t chunk = nsyms - done;

        if (chunk > ELF_SYM_BLOCK)
            chunk = ELF_SYM_BLOCK;
        if (read_exact(e, block, (size_t)chunk * sizeof(block[0]),
                       symtab->sh_offset + done * sizeof(block[0])))
            return -1;
        for (uint64_t i = 0; i < chunk; i++) {
            const Elf64_Sym *s = &block[i];
            uint64_t off;

            if (ELF64_ST_TYPE(s->st_info) != STT_FUNC || !s->st_size || s->st_shndx == SHN_UNDEF)
                continue;
            if (read_name(e, strtab, s->st_name, sym_name, sizeof(sym_name)) ||
                strcmp(sym_name, name))
                continue;
            if (vaddr_to_off(e, s->st_value, &off))
                return -1;
            if (off > (uint64_t)e->size || s->st_size > (uint64_t)e->size - off)
                return -1; /* the body is not fully in the file: refuse it */
            out->vaddr = s->st_value;
            out->file_off = off;
            out->size = s->st_size;
            return 0;
        }
        done += chunk;
    }
    return -1;
}

int lk_elf_read_at(struct lk_elf *e, uint64_t off, void *buf, size_t n)
{
    if (!e || !buf)
        return -1;
    return read_exact(e, buf, n, off);
}

int lk_elf_vaddr_to_off(const struct lk_elf *e, uint64_t vaddr, uint64_t *off)
{
    if (!e || !off)
        return -1;
    return vaddr_to_off(e, vaddr, off);
}

int lk_elf_section(struct lk_elf *e, const char *name, uint64_t *off, uint64_t *size,
                   uint64_t *addr)
{
    const Elf64_Shdr *shstr;
    char buf[64];

    if (!e || !name || !e->sh || e->eh.e_shstrndx >= e->nsh)
        return -1;
    shstr = &e->sh[e->eh.e_shstrndx];
    if (shstr->sh_type != SHT_STRTAB)
        return -1;
    for (unsigned i = 0; i < e->nsh; i++) {
        if (read_name(e, shstr, e->sh[i].sh_name, buf, sizeof(buf)) || strcmp(buf, name))
            continue;
        if (off)
            *off = e->sh[i].sh_offset;
        if (size)
            *size = e->sh[i].sh_size;
        if (addr)
            *addr = e->sh[i].sh_addr;
        return 0;
    }
    return -1;
}
