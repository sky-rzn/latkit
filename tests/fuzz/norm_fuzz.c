// SPDX-License-Identifier: GPL-2.0
/* SQL normaliser fuzz driver (task 4.1, groundwork for stage 8).
 *
 * lk_norm_sql takes untrusted, possibly-truncated bytes (Р22): the same input
 * an attacker controls off the wire. lk_norm_fuzz_one (in src/norm/norm_sql.c)
 * normalises the bytes and reads back every output field, so an OOB write into
 * the text buffer or a missing NUL terminator surfaces under ASAN/UBSAN. This
 * file is just the two entry points, sharing that one function:
 *
 *   - default: a `main` that runs each argv through the harness (CI feeds the
 *     committed fixtures under -fsanitize=address,undefined — no privileges);
 *   - -DLK_FUZZ_LIBFUZZER: LLVMFuzzerTestOneInput, the real libFuzzer target.
 *
 * Built only behind LATKIT_FUZZ, like pg_fuzz. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "norm_sql.h"

#ifdef LK_FUZZ_LIBFUZZER

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return lk_norm_fuzz_one(data, size);
}

#else

static int run_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    long sz;
    uint8_t *buf;
    size_t got;

    if (!f) {
        fprintf(stderr, "fuzz: cannot open %s\n", path);
        return 1;
    }
    if (fseek(f, 0, SEEK_END) || (sz = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
        fclose(f);
        fprintf(stderr, "fuzz: cannot size %s\n", path);
        return 1;
    }
    buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return 1;
    }
    got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    lk_norm_fuzz_one(buf, got);
    free(buf);
    printf("ok fuzz %s (%zu bytes)\n", path, got);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        /* Smoke the edges even without a corpus: empty, a lone byte, and an
         * unterminated literal (mid-token truncation). */
        static const uint8_t frag[] = "select * from t where s = 'oo";

        lk_norm_fuzz_one(NULL, 0);
        lk_norm_fuzz_one((const uint8_t *)"'", 1);
        lk_norm_fuzz_one(frag, sizeof(frag) - 1);
        printf("ok fuzz (built-in smoke inputs; pass corpus files as arguments)\n");
        return 0;
    }
    for (int i = 1; i < argc; i++)
        if (run_file(argv[i]))
            return 1;
    printf("ok\n");
    return 0;
}

#endif /* LK_FUZZ_LIBFUZZER */
