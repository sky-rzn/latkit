// SPDX-License-Identifier: GPL-2.0
/* Golden-byte tests for the protobuf writer (task 5.2). The proto3 wire format
 * is fully specified, so the expected bytes are hand-derived from the spec (and
 * match the canonical examples in Google's encoding docs, e.g. field 1 string
 * "testing" -> 0a 07 74 ...). The live Collector is the schema authority for the
 * OTLP message shape; this pins the primitives underneath it. */
#include "pbuf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(const char *what, const struct pbuf *p, const uint8_t *want, size_t wn)
{
    if (p->oom) {
        printf("FAIL %s: OOM\n", what);
        failures++;
        return;
    }
    if (p->len != wn || memcmp(p->buf, want, wn) != 0) {
        printf("FAIL %s: got [", what);
        for (size_t i = 0; i < p->len; i++)
            printf("%02x ", p->buf[i]);
        printf("] want [");
        for (size_t i = 0; i < wn; i++)
            printf("%02x ", want[i]);
        printf("]\n");
        failures++;
        return;
    }
    printf("ok   %s\n", what);
}

#define CHECK(what, p, ...)                                                                        \
    do {                                                                                          \
        const uint8_t _w[] = {__VA_ARGS__};                                                       \
        check(what, p, _w, sizeof(_w));                                                           \
    } while (0)

int main(void)
{
    struct pbuf p;

    pb_init(&p);

    /* --- varints --- */
    pb_reset(&p);
    pb_varint(&p, 0);
    CHECK("varint 0", &p, 0x00);
    pb_reset(&p);
    pb_varint(&p, 127);
    CHECK("varint 127", &p, 0x7f);
    pb_reset(&p);
    pb_varint(&p, 128);
    CHECK("varint 128", &p, 0x80, 0x01);
    pb_reset(&p);
    pb_varint(&p, 150);
    CHECK("varint 150", &p, 0x96, 0x01);
    pb_reset(&p);
    pb_varint(&p, 300);
    CHECK("varint 300", &p, 0xac, 0x02);
    pb_reset(&p);
    pb_varint(&p, 16384);
    CHECK("varint 16384", &p, 0x80, 0x80, 0x01);

    /* --- scalar fields --- */
    pb_reset(&p);
    pb_field_varint(&p, 1, 150);
    CHECK("field1 varint 150", &p, 0x08, 0x96, 0x01);

    pb_reset(&p);
    pb_field_string(&p, 1, "testing");
    CHECK("field1 string testing", &p, 0x0a, 0x07, 't', 'e', 's', 't', 'i', 'n', 'g');

    /* zigzag: -1 -> 1, 2 -> 4, -53 -> 105 */
    pb_reset(&p);
    pb_field_sint32(&p, 1, -1);
    CHECK("field1 sint32 -1", &p, 0x08, 0x01);
    pb_reset(&p);
    pb_field_sint32(&p, 6, 2);
    CHECK("field6 sint32 2 (scale)", &p, 0x30, 0x04);
    pb_reset(&p);
    pb_field_sint32(&p, 1, -53);
    CHECK("field1 sint32 -53 (offset)", &p, 0x08, 0x69);

    pb_reset(&p);
    pb_field_bool(&p, 3, true);
    CHECK("field3 bool true", &p, 0x18, 0x01);

    pb_reset(&p);
    pb_field_fixed64(&p, 1, 1);
    CHECK("field1 fixed64 1", &p, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

    pb_reset(&p);
    pb_field_double(&p, 1, 1.0);
    CHECK("field1 double 1.0", &p, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f);

    /* --- submessage: length inserted after body (memmove) --- */
    pb_reset(&p);
    {
        size_t s = pb_submsg_begin(&p, 1); /* field 1, LEN */
        pb_field_string(&p, 1, "hi");      /* 0a 02 68 69 -> body len 4 */
        pb_submsg_end(&p, s);
    }
    CHECK("submsg len 4", &p, 0x0a, 0x04, 0x0a, 0x02, 'h', 'i');

    /* Multi-byte length prefix: a 200-byte body -> varint c8 01. Build the body
     * as field 1 bytes of 197 payload (0a c5 01 + 197 = 200). Check the prefix. */
    pb_reset(&p);
    {
        static uint8_t payload[197];
        size_t s;

        memset(payload, 0xAB, sizeof(payload));
        s = pb_submsg_begin(&p, 2); /* field 2, LEN */
        pb_field_bytes(&p, 1, payload, sizeof(payload));
        pb_submsg_end(&p, s);
        if (p.oom || p.len != 3 /*outer tag+len*/ + 200 || p.buf[0] != 0x12 || p.buf[1] != 0xc8 ||
            p.buf[2] != 0x01 || p.buf[3] != 0x0a || p.buf[4] != 0xc5 || p.buf[5] != 0x01 ||
            p.buf[6] != 0xAB || p.buf[p.len - 1] != 0xAB) {
            printf("FAIL submsg 200-byte body prefix (len=%zu)\n", p.len);
            failures++;
        } else {
            printf("ok   submsg 200-byte body prefix\n");
        }
    }

    /* --- nested submessages, LIFO close --- */
    pb_reset(&p);
    {
        size_t outer = pb_submsg_begin(&p, 1);
        size_t inner = pb_submsg_begin(&p, 1);

        pb_field_varint(&p, 1, 1); /* 08 01 -> inner body 2 */
        pb_submsg_end(&p, inner);  /* 0a 02 08 01 -> outer body 4 */
        pb_submsg_end(&p, outer);
    }
    CHECK("nested submsg", &p, 0x0a, 0x04, 0x0a, 0x02, 0x08, 0x01);

    pb_free(&p);
    printf(failures ? "\n%d FAILURES\n" : "\nall pbuf tests passed\n", failures);
    return failures ? 1 : 0;
}
