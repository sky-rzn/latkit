// SPDX-License-Identifier: GPL-2.0
#include "record.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct lk_recorder {
    FILE *f;
    int failed; /* latched on the first write error (Р14) */
};

struct lk_recorder *lk_recorder_open(const char *path)
{
    struct lk_recorder *rec = calloc(1, sizeof(*rec));

    if (!rec)
        return NULL;
    rec->f = fopen(path, "wb");
    if (!rec->f) {
        free(rec);
        return NULL;
    }
    if (fwrite(LK_RECORD_MAGIC, 1, LK_RECORD_MAGIC_LEN, rec->f) != LK_RECORD_MAGIC_LEN) {
        fclose(rec->f);
        free(rec);
        return NULL;
    }
    return rec;
}

void lk_recorder_write(struct lk_recorder *rec, const void *data, __u32 size)
{
    if (!rec || rec->failed)
        return;
    if (fwrite(&size, sizeof(size), 1, rec->f) != 1 || fwrite(data, 1, size, rec->f) != size)
        rec->failed = 1;
}

int lk_recorder_close(struct lk_recorder *rec)
{
    int failed;

    if (!rec)
        return 0;
    failed = rec->failed || fflush(rec->f);
    if (fclose(rec->f))
        failed = 1;
    free(rec);
    return failed ? -1 : 0;
}

int lk_replay_mem(const void *buf, size_t len, lk_replay_fn fn, void *ctx)
{
    const __u8 *p = buf;
    size_t pos = LK_RECORD_MAGIC_LEN;

    if (len < LK_RECORD_MAGIC_LEN || memcmp(p, LK_RECORD_MAGIC, LK_RECORD_MAGIC_LEN))
        return -1;
    while (pos < len) {
        __u32 size;
        int rc;

        if (len - pos < sizeof(size))
            return -1; /* truncated length prefix */
        memcpy(&size, p + pos, sizeof(size));
        pos += sizeof(size);
        if (len - pos < size)
            return -1; /* truncated record */
        rc = fn(ctx, p + pos, size);
        if (rc)
            return rc;
        pos += size;
    }
    return 0;
}

int lk_replay_file(const char *path, lk_replay_fn fn, void *ctx)
{
    FILE *f = fopen(path, "rb");
    long size;
    void *buf;
    int rc;

    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) || (size = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
        fclose(f);
        return -1;
    }
    buf = malloc((size_t)size + 1); /* +1: malloc(0) must not read back NULL */
    if (!buf) {
        fclose(f);
        return -1;
    }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);
    rc = lk_replay_mem(buf, (size_t)size, fn, ctx);
    free(buf);
    return rc;
}
