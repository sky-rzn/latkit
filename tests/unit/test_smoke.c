// SPDX-License-Identifier: GPL-2.0
/* Smoke test: invariants of the kernel<->userspace event ABI (format v1).
 * Behavioral tests live next door: test_decode.c, test_seqtrack.c. */
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
    /* Verifier-friendly length clipping requires powers of two. */
    CHECK(LK_CHUNK_SMALL > 0 && (LK_CHUNK_SMALL & (LK_CHUNK_SMALL - 1)) == 0);
    CHECK(LK_CHUNK_FULL > 0 && (LK_CHUNK_FULL & (LK_CHUNK_FULL - 1)) == 0);
    CHECK(LK_CHUNK_SMALL < LK_CHUNK_FULL);

    /* Every ringbuf record starts with lk_ev_hdr; userspace discriminates on
     * hdr.type, so the header must sit at offset 0 with no compiler holes. */
    CHECK(sizeof(struct lk_ev_hdr) == 24);
    CHECK(offsetof(struct lk_ev_conn, hdr) == 0);
    CHECK(offsetof(struct lk_ev_data, hdr) == 0);

    /* Fixed layouts; catches accidental ABI drift. */
    CHECK(sizeof(struct lk_tuple) == 44);
    CHECK(offsetof(struct lk_ev_data, payload) == 40);
    CHECK(sizeof(struct lk_ev_conn) == 80);

    CHECK(LK_DIR_SEND == 0 && LK_DIR_RECV == 1);
    CHECK(LK_EV_DATA == 0 && LK_EV_CONN_OPEN == 1 && LK_EV_CONN_CLOSE == 2);

    printf("ok\n");
    return 0;
}
