// SPDX-License-Identifier: GPL-2.0
/* Writes each fixture's LKT1 trace to <out-dir>/<name>.lkt (task 2.5). Run to
 * (re)generate the committed tests/fixtures; test_replay guards that the
 * committed bytes match what these builders produce, so a stale fixture is a
 * test failure, not silent drift. */
#include <stdio.h>
#include <stdlib.h>

#include "fixtures_gen.h"

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : ".";

    for (size_t i = 0; i < lk_nfixtures; i++) {
        struct fx x;
        char path[1024];
        FILE *f;

        lk_fixtures[i].build(&x);
        snprintf(path, sizeof(path), "%s/%s.lkt", dir, lk_fixtures[i].name);
        f = fopen(path, "wb");
        if (!f || fwrite(x.buf, 1, x.len, f) != x.len || fclose(f)) {
            fprintf(stderr, "failed to write %s\n", path);
            free(x.buf);
            return 1;
        }
        free(x.buf);
        printf("wrote %s (%zu bytes)\n", path, x.len);
    }
    return 0;
}
