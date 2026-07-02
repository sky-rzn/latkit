// SPDX-License-Identifier: GPL-2.0
/* Smoke test: invariants of the kernel<->userspace event ABI.
 * Real unit tests (protocol parser etc.) arrive in stage 3. */
#include <linux/types.h>
#include <stddef.h>
#include <stdio.h>

#include "latkit.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

int main(void)
{
    /* Verifier-friendly length clipping (len & (POC_CHUNK - 1)) requires a
     * power of two. */
    CHECK(POC_CHUNK > 0 && (POC_CHUNK & (POC_CHUNK - 1)) == 0);

    /* Fixed header before payload; catches accidental ABI drift. */
    CHECK(offsetof(struct lk_event, payload) == 36);
    /* header + payload, plus trailing padding to 8-byte struct alignment */
    CHECK(sizeof(struct lk_event) == 36 + POC_CHUNK + 4);

    CHECK(LK_DIR_SEND == 0 && LK_DIR_RECV == 1);

    printf("ok\n");
    return 0;
}
