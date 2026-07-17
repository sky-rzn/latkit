/* SPDX-License-Identifier: GPL-2.0 */
/* Dev tool: validate + summarise LKT1 traces (М0 of the MySQL track needs a
 * "every recorded trace replays" check before any MySQL protocol code
 * exists). Replays each file through the same lk_replay_file + lk_ev_decode
 * path the offline harness uses and prints one summary line per trace.
 *
 *   lkt_info FILE.lkt...
 *
 * Exit is nonzero if any file fails to replay (bad magic, truncated record)
 * or contains a record the decoder rejects (SHORT/UNKNOWN). */
#include <stdio.h>
#include <string.h>

#include "decode.h"
#include "record.h"

struct tally {
    unsigned long long records, open, close, data, send, recv, decrypted, trunc, gap;
    unsigned long long cap_bytes, total_bytes;
    unsigned long long dec_short, dec_unknown;
};

static int on_record(void *ctx, const void *data, __u32 size)
{
    struct tally *t = ctx;
    struct lk_ev_view v;

    t->records++;
    switch (lk_ev_decode(data, size, &v)) {
    case LK_DEC_CONN:
        if (v.hdr->type == LK_EV_CONN_OPEN)
            t->open++;
        else
            t->close++;
        break;
    case LK_DEC_DATA:
        t->data++;
        if (v.hdr->dir == LK_DIR_SEND)
            t->send++;
        else
            t->recv++;
        if (v.hdr->flags & LK_F_DECRYPTED)
            t->decrypted++;
        if (v.hdr->flags & LK_F_TRUNC)
            t->trunc++;
        if (v.hdr->flags & LK_F_GAP)
            t->gap++;
        t->cap_bytes += v.cap_len;
        t->total_bytes += v.data->total_len;
        break;
    case LK_DEC_SHORT:
        t->dec_short++;
        break;
    case LK_DEC_UNKNOWN:
        t->dec_unknown++;
        break;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int rc = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE.lkt...\n", argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        struct tally t;

        memset(&t, 0, sizeof(t));
        if (lk_replay_file(argv[i], on_record, &t)) {
            printf("%s: REPLAY FAILED (bad magic or truncated record)\n", argv[i]);
            rc = 1;
            continue;
        }
        printf("%s: records=%llu open=%llu close=%llu data=%llu"
               " (send=%llu recv=%llu decrypted=%llu trunc=%llu"
               " gap=%llu) bytes=%llu/%llu",
               argv[i], t.records, t.open, t.close, t.data, t.send, t.recv, t.decrypted, t.trunc,
               t.gap, t.cap_bytes, t.total_bytes);
        if (t.dec_short || t.dec_unknown) {
            printf(" BAD short=%llu unknown=%llu", t.dec_short, t.dec_unknown);
            rc = 1;
        }
        printf("\n");
    }
    return rc;
}
