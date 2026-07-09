// SPDX-License-Identifier: GPL-2.0
/* See pbuf.h. */
#include "pbuf.h"

#include <stdlib.h>
#include <string.h>

#define PB_MIN_CAP 256

void pb_init(struct pbuf *p)
{
    p->buf = NULL;
    p->len = 0;
    p->cap = 0;
    p->oom = false;
}

void pb_free(struct pbuf *p)
{
    free(p->buf);
    p->buf = NULL;
    p->len = p->cap = 0;
    p->oom = false;
}

void pb_reset(struct pbuf *p)
{
    p->len = 0;
    p->oom = false;
}

/* Ensure room for n more bytes; set the sticky OOM flag on failure. Returns
 * false when the buffer is poisoned (already or newly), so callers become
 * no-ops without each having to test. */
static bool pb_reserve(struct pbuf *p, size_t n)
{
    size_t need, cap;
    uint8_t *nb;

    if (p->oom)
        return false;
    need = p->len + n;
    if (need <= p->cap)
        return true;
    cap = p->cap ? p->cap : PB_MIN_CAP;
    while (cap < need)
        cap *= 2;
    nb = realloc(p->buf, cap);
    if (!nb) {
        p->oom = true;
        return false;
    }
    p->buf = nb;
    p->cap = cap;
    return true;
}

void pb_raw(struct pbuf *p, const void *data, size_t n)
{
    if (!pb_reserve(p, n))
        return;
    memcpy(p->buf + p->len, data, n);
    p->len += n;
}

/* Base-128 varint, little-endian groups, high bit = continuation. */
void pb_varint(struct pbuf *p, uint64_t v)
{
    uint8_t tmp[10];
    size_t n = 0;

    do {
        tmp[n] = v & 0x7f;
        v >>= 7;
        if (v)
            tmp[n] |= 0x80;
        n++;
    } while (v);
    pb_raw(p, tmp, n);
}

void pb_tag(struct pbuf *p, uint32_t field, uint32_t wire)
{
    pb_varint(p, ((uint64_t)field << 3) | wire);
}

void pb_field_varint(struct pbuf *p, uint32_t field, uint64_t v)
{
    pb_tag(p, field, PB_WIRE_VARINT);
    pb_varint(p, v);
}

void pb_field_sint32(struct pbuf *p, uint32_t field, int32_t v)
{
    /* zigzag: map signed to unsigned so small magnitudes stay short. */
    uint32_t zz = ((uint32_t)v << 1) ^ (uint32_t)(v >> 31);

    pb_tag(p, field, PB_WIRE_VARINT);
    pb_varint(p, zz);
}

void pb_field_bool(struct pbuf *p, uint32_t field, bool v)
{
    pb_tag(p, field, PB_WIRE_VARINT);
    pb_varint(p, v ? 1 : 0);
}

void pb_field_fixed64(struct pbuf *p, uint32_t field, uint64_t v)
{
    uint8_t b[8];

    for (int i = 0; i < 8; i++)
        b[i] = (uint8_t)(v >> (8 * i)); /* little-endian */
    pb_tag(p, field, PB_WIRE_I64);
    pb_raw(p, b, 8);
}

void pb_field_double(struct pbuf *p, uint32_t field, double v)
{
    uint64_t bits;

    memcpy(&bits, &v, sizeof(bits));
    pb_field_fixed64(p, field, bits);
}

void pb_field_bytes(struct pbuf *p, uint32_t field, const void *data, size_t n)
{
    pb_tag(p, field, PB_WIRE_LEN);
    pb_varint(p, n);
    pb_raw(p, data, n);
}

void pb_field_string(struct pbuf *p, uint32_t field, const char *s)
{
    pb_field_bytes(p, field, s, strlen(s));
}

size_t pb_submsg_begin(struct pbuf *p, uint32_t field)
{
    pb_tag(p, field, PB_WIRE_LEN);
    return p->len;
}

/* Number of bytes a varint of v occupies. */
static size_t varint_len(uint64_t v)
{
    size_t n = 1;

    while (v >>= 7)
        n++;
    return n;
}

void pb_submsg_end(struct pbuf *p, size_t start)
{
    size_t body = p->len - start;
    size_t vlen = varint_len(body);

    if (!pb_reserve(p, vlen)) /* make room for the length prefix */
        return;
    /* Shift the body up by vlen, then write the length varint into the gap.
     * Valid only because the body is the buffer's tail (LIFO close order). */
    memmove(p->buf + start + vlen, p->buf + start, body);
    p->len += vlen;
    {
        uint64_t v = body;
        size_t i = start;

        do {
            uint8_t byte = v & 0x7f;

            v >>= 7;
            if (v)
                byte |= 0x80;
            p->buf[i++] = byte;
        } while (v);
    }
}
