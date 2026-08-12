/* SPDX-License-Identifier: GPL-2.0 */
/* Minimal ELF64 symbol reader: enough to answer "where in this file does the
 * function NAME live, and how long is it" (РH13.3, PLAN-HTTP.md М7).
 *
 * libbpf already resolves a symbol name for us when attaching a uprobe, so why
 * this exists: the Go channel does not attach at a function's entry alone, it
 * attaches inside the body, at every `ret`. That needs the function's bytes —
 * hence its size and its position *in the file* — which the attach API does not
 * hand back. The conversion from a symbol's virtual address to a file offset is
 * the same one libbpf performs internally, and the same one a uprobe expects.
 *
 * Deliberately hand-rolled rather than libelf-based: it is a few hundred lines
 * of bounded reads, it keeps this module free of libbpf/libelf so the unit test
 * can link it on its own, and there is nothing here that a shared library would
 * do better. Every read is bounds-checked against the file size; a malformed or
 * hostile ELF yields a clean failure, never a walk off the end.
 *
 * Scope: ELF64, little-endian, SHT_SYMTAB only. A binary stripped of its symtab
 * (`-s -w` on a Go build) resolves nothing here — that is an honest blind zone
 * the caller reports, not something to guess around. */
#ifndef LATKIT_ELF_SYMS_H
#define LATKIT_ELF_SYMS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct lk_elf;

/* A resolved function symbol. `file_off` is what a uprobe wants; `vaddr` and
 * `size` come straight from the symbol table. */
struct lk_elf_func {
    uint64_t vaddr;
    uint64_t file_off;
    uint64_t size;
};

/* Open and validate the ELF header. NULL when the file cannot be read or is not
 * a little-endian ELF64 object. */
struct lk_elf *lk_elf_open(const char *path);
void lk_elf_close(struct lk_elf *e);

/* e_machine (EM_X86_64 = 62, EM_AARCH64 = 183, ...), so the caller can refuse a
 * binary built for another architecture before decoding a single byte. */
uint16_t lk_elf_machine(const struct lk_elf *e);

/* Whether the object carries a symbol table at all — the difference between
 * "this Go binary has no TLS in it" and "this Go binary was stripped". */
bool lk_elf_has_symtab(const struct lk_elf *e);

/* Look up a defined function symbol by exact name. Returns 0 and fills *out, or
 * -1 when the name is absent, is not a function, or has zero size (nothing to
 * decode). Symbol names are compared byte for byte: Go spells its methods
 * `crypto/tls.(*Conn).Write`, punctuation included. */
int lk_elf_find_func(struct lk_elf *e, const char *name, struct lk_elf_func *out);

/* Read n bytes at a file offset (the function body, in practice). Returns 0, or
 * -1 if the range is not fully inside the file. */
int lk_elf_read_at(struct lk_elf *e, uint64_t off, void *buf, size_t n);

/* Locate a section by name — used for `.gopclntab`, the table a stripped Go
 * binary keeps when its symbol table is gone (go_pclntab.h). Any of the three
 * out-params may be NULL. Returns 0 on success, -1 if there is no such section
 * or the object has no section-name table. */
int lk_elf_section(struct lk_elf *e, const char *name, uint64_t *off, uint64_t *size,
                   uint64_t *addr);

/* The virtual-address-to-file-offset translation on its own, for callers that
 * resolved an address by other means than the symbol table. Returns 0, or -1
 * when no loadable segment covers the address. */
int lk_elf_vaddr_to_off(const struct lk_elf *e, uint64_t vaddr, uint64_t *off);

#endif /* LATKIT_ELF_SYMS_H */
