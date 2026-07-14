// SPDX-License-Identifier: GPL-2.0
/* Allocation-counting shims for the micro-benches. Linked with
 * -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free so every heap call
 * the module code under test issues is redirected here, tallied, and forwarded
 * to the real allocator. See bench_util.h for the rationale. */
#include <stddef.h>

#include "bench_util.h"

struct bench_alloc g_alloc;

extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void *__real_realloc(void *, size_t);
extern void __real_free(void *);

void *__wrap_malloc(size_t n)
{
    g_alloc.calls++;
    g_alloc.bytes += n;
    return __real_malloc(n);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
    g_alloc.calls++;
    g_alloc.bytes += (unsigned long long)nmemb * size;
    return __real_calloc(nmemb, size);
}

void *__wrap_realloc(void *p, size_t n)
{
    g_alloc.calls++;
    g_alloc.bytes += n;
    return __real_realloc(p, n);
}

void __wrap_free(void *p)
{
    if (p)
        g_alloc.frees++;
    __real_free(p);
}
