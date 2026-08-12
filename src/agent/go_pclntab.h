/* SPDX-License-Identifier: GPL-2.0 */
/* Go's `.gopclntab`: finding a function in a binary whose symbol table is gone
 * (PLAN-HTTP.md М7, РH13.3).
 *
 * Why this exists, in one measurement. The М0 reconnaissance (see the corpus
 * README, item 3) looked at the Go servers this track names — Caddy, Traefik,
 * MinIO — and every one of them ships built with `-ldflags "-s -w"`: no ELF
 * symbol table at all. Only a plain `go build` keeps one. So resolving
 * `crypto/tls.(*Conn).Read/Write` through the symbol table alone would work on
 * a binary you built yourself and on essentially nothing you deploy.
 *
 * What `-s -w` does *not* remove is the runtime's own function table. Go needs
 * it for panics, profiles and stack traces, so every binary carries the entry
 * address and the name of every function it contains. That is exactly the two
 * facts a probe needs, and reading them is a bounded, well-documented parse.
 *
 * Scope: Go 1.18 and newer (the pcHeader layouts that carry `textStart`, magic
 * 0xFFFFFFF0 / 0xFFFFFFF1), 64-bit little-endian. Older layouts are refused
 * rather than guessed at — as is a table whose header does not validate. The
 * failure mode of a wrong answer here is a probe at the wrong address inside a
 * live server, so everything unrecognised is a refusal.
 *
 * Pure: the lookup works on a byte buffer, so it is testable without a Go
 * toolchain (tests/unit/test_go_pclntab.c builds a synthetic table). */
#ifndef LATKIT_GO_PCLNTAB_H
#define LATKIT_GO_PCLNTAB_H

#include <stddef.h>
#include <stdint.h>

/* Find `name` in the pclntab image `tab` (`n` bytes, as it appears in the file
 * and in memory). On success writes the function's virtual address and its
 * size — the distance to the next function's entry, so it may include the
 * padding between them, which decodes as the int3 filler it is.
 *
 * `text_base` is where the text segment is loaded, and it is needed because the
 * header's own `textStart` field is **zero in the file** of every Go binary
 * checked (it is filled in at run time): the entry offsets are then relative to
 * the start of `.text`, whose address the caller reads from the ELF. When a
 * binary does carry a non-zero `textStart`, that one wins — the file said so.
 * Verified both ways against a binary that has *both* tables: the address this
 * returns is the address its symbol table gives.
 *
 * Returns 0 on success, -1 when the name is absent, and -2 when the table is
 * not one this code understands (bad magic, an unsupported Go layout, a header
 * whose offsets do not fit). The two are distinguished because they mean
 * different things to an operator: "this binary has no TLS in it" versus "this
 * binary needs a newer latkit". */
int lk_go_pclntab_find(const uint8_t *tab, size_t n, uint64_t text_base, const char *name,
                       uint64_t *vaddr, uint64_t *size);

#endif /* LATKIT_GO_PCLNTAB_H */
