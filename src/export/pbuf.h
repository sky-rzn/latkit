/* SPDX-License-Identifier: GPL-2.0 */
/* Append-only protobuf (proto3 wire format) writer (Р31, STAGE5.md task 5.2).
 * No opentelemetry-cpp, no protobuf-c: the OTLP subset we emit is small and
 * stable, and proto3 on the wire is just varints and length-delimited fields.
 *
 * The writer grows one heap buffer and appends. Nested (length-delimited)
 * messages are written body-first: pb_submsg_begin writes the field tag and
 * returns the body's start offset; the body is appended; pb_submsg_end computes
 * the now-known length and inserts its varint before the body with a memmove.
 * Because a submessage is finished while it is still the buffer's tail, that
 * memmove only shifts its own body — so submessages must be closed in LIFO
 * order (the natural nesting order). The messages we build are small (tens of
 * bytes), and only the two outermost levels ever memmove the whole payload,
 * once each. Golden-byte tests (test_pbuf.c) pin the encoding; the live
 * Collector is the schema authority (it rejects malformed protobuf with 400).
 *
 * Allocation failure is sticky (`oom`): every call after it is a no-op and the
 * caller checks pb->oom once, at the end, instead of on every append. */
#ifndef LATKIT_PBUF_H
#define LATKIT_PBUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* proto3 wire types. */
#define PB_WIRE_VARINT 0
#define PB_WIRE_I64    1
#define PB_WIRE_LEN    2
#define PB_WIRE_I32    5

struct pbuf {
    uint8_t *buf;
    size_t len;
    size_t cap;
    bool oom; /* sticky: set on any allocation failure, poisons the buffer */
};

void pb_init(struct pbuf *p);
void pb_free(struct pbuf *p);
void pb_reset(struct pbuf *p); /* keep the allocation, drop the contents */

/* --- primitives ----------------------------------------------------------- */
void pb_raw(struct pbuf *p, const void *data, size_t n);
void pb_varint(struct pbuf *p, uint64_t v);
void pb_tag(struct pbuf *p, uint32_t field, uint32_t wire);

/* --- scalar fields (tag + value) ------------------------------------------ */
void pb_field_varint(struct pbuf *p, uint32_t field, uint64_t v);
void pb_field_sint32(struct pbuf *p, uint32_t field, int32_t v); /* zigzag */
void pb_field_bool(struct pbuf *p, uint32_t field, bool v);
void pb_field_fixed64(struct pbuf *p, uint32_t field, uint64_t v);
void pb_field_double(struct pbuf *p, uint32_t field, double v);
void pb_field_bytes(struct pbuf *p, uint32_t field, const void *data, size_t n);
void pb_field_string(struct pbuf *p, uint32_t field, const char *s);

/* --- length-delimited submessages (LIFO) ---------------------------------- */
/* Writes the field tag, returns the start offset of the (still empty) body. */
size_t pb_submsg_begin(struct pbuf *p, uint32_t field);
/* Inserts the length prefix for the body that was appended since `start`. */
void pb_submsg_end(struct pbuf *p, size_t start);

#endif /* LATKIT_PBUF_H */
