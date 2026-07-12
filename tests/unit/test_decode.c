// SPDX-License-Identifier: GPL-2.0
/* Unit tests (task 1.7) for the ringbuf record decoder: classification by
 * hdr.type, per-type minimum sizes, both payload size classes, and the
 * cap_len clamp against the record boundary. Records are crafted the same
 * way the BPF side lays them out: header at offset 0, payload after
 * lk_ev_data. */
#include <linux/types.h>
#include <stdio.h>
#include <string.h>

#include "decode.h"
#include "latkit.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* Big enough for the FULL size class. */
static __u8 buf[sizeof(struct lk_ev_data) + LK_CHUNK_FULL];

static struct lk_ev_data *mk_data(__u32 total, __u32 cap, __u32 off)
{
    struct lk_ev_data *d = (void *)buf;

    memset(buf, 0, sizeof(buf));
    d->hdr.type = LK_EV_DATA;
    d->hdr.conn_id = 0xabcdef;
    d->total_len = total;
    d->cap_len = cap;
    d->off = off;
    return d;
}

int main(void)
{
    struct lk_ev_view v;

    /* CONN_OPEN / CONN_CLOSE: fixed-size records. */
    {
        struct lk_ev_conn c = {0};

        c.hdr.type = LK_EV_CONN_OPEN;
        c.hdr.conn_id = 42;
        CHECK(lk_ev_decode(&c, sizeof(c), &v) == LK_DEC_CONN);
        CHECK(v.hdr == &c.hdr && v.conn == &c && !v.data);
        CHECK(v.hdr->conn_id == 42);

        c.hdr.type = LK_EV_CONN_CLOSE;
        CHECK(lk_ev_decode(&c, sizeof(c), &v) == LK_DEC_CONN);

        /* A conn record cut short must not be exposed. */
        CHECK(lk_ev_decode(&c, sizeof(c) - 1, &v) == LK_DEC_SHORT);
        CHECK(!v.conn);
        /* ...even when only the header survives: type says conn. */
        CHECK(lk_ev_decode(&c, sizeof(struct lk_ev_hdr), &v) == LK_DEC_SHORT);
        CHECK(v.hdr != NULL);
    }

    /* Records smaller than the common header carry nothing usable. */
    {
        struct lk_ev_hdr h = {0};

        CHECK(lk_ev_decode(&h, sizeof(h) - 1, &v) == LK_DEC_SHORT);
        CHECK(!v.hdr && !v.conn && !v.data);
        CHECK(lk_ev_decode(&h, 0, &v) == LK_DEC_SHORT);
    }

    /* Unknown type: reported as such, header still visible to the caller. */
    {
        struct lk_ev_conn c = {0};

        c.hdr.type = 0x77;
        CHECK(lk_ev_decode(&c, sizeof(c), &v) == LK_DEC_UNKNOWN);
        CHECK(v.hdr != NULL);
    }

    /* DATA, SMALL size class: cap_len within the record is passed through. */
    {
        struct lk_ev_data *d = mk_data(4000, 100, 0);

        CHECK(lk_ev_decode(d, sizeof(*d) + LK_CHUNK_SMALL, &v) == LK_DEC_DATA);
        CHECK(v.data == d && v.hdr == &d->hdr && !v.conn);
        CHECK(v.cap_len == 100);
    }

    /* DATA, FULL size class: a full chunk fills the whole payload. */
    {
        struct lk_ev_data *d = mk_data(100000, LK_CHUNK_FULL, 4096);

        CHECK(lk_ev_decode(d, sizeof(*d) + LK_CHUNK_FULL, &v) == LK_DEC_DATA);
        CHECK(v.cap_len == LK_CHUNK_FULL);
        CHECK(v.data->off == 4096 && v.data->total_len == 100000);
    }

    /* An empty data event (unsupported iterator, budget 0) is valid: the
     * record still advances the stream by total_len. */
    {
        struct lk_ev_data *d = mk_data(8192, 0, 0);

        d->hdr.flags = LK_F_TRUNC;
        CHECK(lk_ev_decode(d, sizeof(*d) + LK_CHUNK_SMALL, &v) == LK_DEC_DATA);
        CHECK(v.cap_len == 0);
        CHECK(v.hdr->flags & LK_F_TRUNC);
    }

    /* A kernel-written cap_len larger than the record must be clamped to the
     * record boundary — never trust the length over the actual size. */
    {
        struct lk_ev_data *d = mk_data(4096, LK_CHUNK_FULL, 0);

        CHECK(lk_ev_decode(d, sizeof(*d) + LK_CHUNK_SMALL, &v) == LK_DEC_DATA);
        CHECK(v.cap_len == LK_CHUNK_SMALL);

        d = mk_data(4096, 0xffffffff, 0);
        CHECK(lk_ev_decode(d, sizeof(*d) + LK_CHUNK_FULL, &v) == LK_DEC_DATA);
        CHECK(v.cap_len == LK_CHUNK_FULL);
    }

    /* A data record whose dir byte is garbage is corrupt, not routable: dir
     * indexes lk_conn.frame[2] downstream (found by fuzz_pipe, task 8.3 —
     * reachable from a damaged --record file, never from the kernel). */
    {
        struct lk_ev_data *d = mk_data(64, 64, 0);

        d->hdr.dir = 2;
        CHECK(lk_ev_decode(d, sizeof(*d) + LK_CHUNK_SMALL, &v) == LK_DEC_UNKNOWN);
        d->hdr.dir = 0xee;
        CHECK(lk_ev_decode(d, sizeof(*d) + LK_CHUNK_SMALL, &v) == LK_DEC_UNKNOWN);
    }

    /* A data record with no room for even the fixed part is short. */
    {
        struct lk_ev_data *d = mk_data(10, 10, 0);

        CHECK(lk_ev_decode(d, sizeof(*d) - 1, &v) == LK_DEC_SHORT);
        CHECK(v.hdr != NULL && !v.data);
        /* Exactly the fixed part, zero payload room: valid, cap clamps to 0. */
        CHECK(lk_ev_decode(d, sizeof(*d), &v) == LK_DEC_DATA);
        CHECK(v.cap_len == 0);
    }

    printf("ok\n");
    return 0;
}
