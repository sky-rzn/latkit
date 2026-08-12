// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the ELF symbol reader (PLAN-HTTP.md М7, РH13.3,
 * src/agent/elf_syms.c).
 *
 * The interesting assertion is the address arithmetic, and it is checked
 * against reality rather than against a fixture: the test looks up one of its
 * own functions in its own binary, reads the bytes the module says that
 * function occupies *in the file*, and compares them with the bytes at the
 * function's address *in memory*. If the virtual-address-to-file-offset
 * translation were wrong — the exact mistake that would put a Go uprobe at a
 * random place in a running server — the two would not match.
 *
 * The rest is the failure surface: a path that is not an ELF file, a symbol
 * that is not there, a read past the end. Each must fail cleanly, because every
 * one of them is a thing an operator can point --tls-go at by accident. */
#include <stdio.h>
#include <string.h>

#include "elf_syms.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* The lookup target: a function with a stable name, not static (a static one
 * may be renamed or dropped by the compiler) and not inlinable. */
__attribute__((noinline)) int lk_test_target_function(int x)
{
    /* Nothing clever: the body only has to exist and be non-trivial enough that
     * the compiler emits real instructions for it. */
    volatile int acc = 0;

    for (int i = 0; i < x; i++)
        acc += i * 3;
    return acc;
}

static int test_self_lookup(void)
{
    struct lk_elf *e = lk_elf_open("/proc/self/exe");
    struct lk_elf_func fn;
    unsigned char from_file[32];

    CHECK(e != NULL);
    CHECK(lk_elf_has_symtab(e)); /* the unit tests are not built stripped */
    CHECK(lk_elf_find_func(e, "lk_test_target_function", &fn) == 0);
    CHECK(fn.size > 0 && fn.vaddr != 0 && fn.file_off != 0);

    /* The claim under test: these bytes, at this file offset, are that
     * function. Compared against the mapped copy, which the loader placed at a
     * possibly different address — the content is what has to agree. */
    size_t n = fn.size < sizeof(from_file) ? (size_t)fn.size : sizeof(from_file);

    CHECK(lk_elf_read_at(e, fn.file_off, from_file, n) == 0);
    CHECK(memcmp(from_file, (const void *)(uintptr_t)lk_test_target_function, n) == 0);

    /* A read that runs past the end of the file is refused rather than
     * short-read: the caller sizes a decode from it. */
    CHECK(lk_elf_read_at(e, fn.file_off, from_file, (size_t)1 << 40) == -1);

    lk_elf_close(e);
    return 0;
}

static int test_machine(void)
{
    struct lk_elf *e = lk_elf_open("/proc/self/exe");

    CHECK(e != NULL);
    /* EM_X86_64 = 62 on the platform this test runs on; elsewhere the value
     * simply has to be the host's, which is what tls_go.c compares against. */
    CHECK(lk_elf_machine(e) != 0);
    lk_elf_close(e);
    return 0;
}

static int test_failures(void)
{
    struct lk_elf *e;
    struct lk_elf_func fn;

    CHECK(lk_elf_open("/nonexistent/path/to/nothing") == NULL);
    CHECK(lk_elf_open("/etc/hostname") == NULL); /* a real file, not an ELF */
    CHECK(lk_elf_open("/proc") == NULL);         /* not a regular file */
    CHECK(lk_elf_open(NULL) == NULL);

    e = lk_elf_open("/proc/self/exe");
    CHECK(e != NULL);
    /* The name a Go binary would carry; this one does not, and saying so is the
     * difference between "no TLS here" and a wrong attach. */
    CHECK(lk_elf_find_func(e, "crypto/tls.(*Conn).Write", &fn) == -1);
    CHECK(lk_elf_find_func(e, "", &fn) == -1);
    CHECK(lk_elf_find_func(e, NULL, &fn) == -1);
    lk_elf_close(e);
    lk_elf_close(NULL); /* NULL-safe */
    return 0;
}

int main(void)
{
    if (test_self_lookup() || test_machine() || test_failures())
        return 1;
    printf("ok\n");
    return 0;
}
