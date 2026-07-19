/* SPDX-License-Identifier: GPL-2.0 */
/* Shared Р51 invariant checks for the fuzz harnesses (task 8.3). ASAN catches
 * memory, these asserts catch logic: a fuzzer that only proves "no crash" lets
 * a framer that emits garbage-but-in-bounds messages pass silently. Each check
 * states a documented contract of the module under test — reassembly.h for
 * messages, proto.h for observations, norm_sql.h for the normaliser — so a
 * failure is a bug in the module or in the contract's wording, never a harness
 * heuristic. FZ_ASSERT aborts (not assert(): NDEBUG must not disarm a fuzzer),
 * which libFuzzer treats like a crash and minimises the input for.
 *
 * Everything is static inline: each harness is a single-TU binary and only
 * pays for the checks it calls. */
#ifndef LATKIT_FUZZ_INVARIANTS_H
#define LATKIT_FUZZ_INVARIANTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "norm_sql.h"
#include "proto.h"

#define FZ_ASSERT(cond)                                                                            \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "INVARIANT FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
            abort();                                                                               \
        }                                                                                          \
    } while (0)

/* Observation sink for byte ranges: a volatile accumulator the compiler cannot
 * elide, so every byte is genuinely read (and bounds-checked under ASAN). */
static volatile uint64_t fz_byte_sink;

static inline void fz_read_bytes(const void *p, size_t n)
{
    const unsigned char *b = (const unsigned char *)p;
    uint64_t acc = 0;

    for (size_t i = 0; i < n; i++)
        acc += b[i];
    fz_byte_sink += acc;
}

/* Framer message contract (reassembly.h, Р10/Р11/Р19). The two protocols
 * differ in what lk_msg.len means, so the contract is parameterised:
 *
 *   PG    — len is the wire length field, which *includes* its own 4-byte
 *           prefix, so the body is len-4; len == 0 is the lone untyped
 *           one-byte SSL/GSSENC reply; a startup packet is >= 8 bytes.
 *   MySQL — len is the logical payload length itself (no self-inclusion), so
 *           the body is len; len == 0 is a legitimate empty packet (the LOAD
 *           DATA end marker); a 1-byte command (COM_QUIT) has len == 1.
 *
 * Common to both: the captured body prefix never exceeds the payload or the
 * Р11 cap, and "truncated" is exactly "prefix shorter than the payload" —
 * trunc is not mutually exclusive with a valid message. A STARTUP packet is
 * untyped (type == 0) in either protocol. */
static inline void fz_check_msg(const struct lk_msg *m, bool mysql)
{
    uint32_t body; /* the wire payload length the captured prefix belongs to */

    if (mysql) {
        FZ_ASSERT(m->body_cap <= LK_MSG_BODY_MAX);
        if (m->flags & LK_MSG_STARTUP)
            FZ_ASSERT(m->type == 0);
        body = m->len;
    } else {
        if (m->len == 0) {
            FZ_ASSERT(m->body_cap == 0);
            FZ_ASSERT(!(m->flags & (LK_MSG_BODY_TRUNC | LK_MSG_STARTUP)));
            return;
        }
        FZ_ASSERT(m->len >= 4 && m->len <= (1u << 30));
        if (m->flags & LK_MSG_STARTUP) {
            FZ_ASSERT(m->type == 0);
            FZ_ASSERT(m->len >= 8);
        }
        FZ_ASSERT(m->body_cap <= LK_MSG_BODY_MAX);
        body = m->len - 4;
    }
    FZ_ASSERT(m->body_cap <= body);
    FZ_ASSERT(((m->flags & LK_MSG_BODY_TRUNC) != 0) == (m->body_cap < body));
    if (m->body_cap) {
        FZ_ASSERT(m->body != NULL);
        fz_read_bytes(m->body, m->body_cap);
    }
}

/* Observation contract (proto.h, Р16-Р18): the parser may emit "no text" or a
 * truncated prefix, but never a dangling or inconsistent one, and sqlstate is
 * always a bounded C-string. Every field is read so an out-of-bounds pointer
 * surfaces at emit time, not only at parse time. */
static inline void fz_check_obs(const struct lk_query_obs *o)
{
    FZ_ASSERT(o->kind <= LK_Q_CANCEL);
    FZ_ASSERT(memchr(o->sqlstate, '\0', sizeof(o->sqlstate)) != NULL);
    if (o->flags & LK_QO_NO_TEXT)
        FZ_ASSERT(!o->text && !o->text_len);
    if (o->text) {
        FZ_ASSERT(o->text_len > 0);
        fz_read_bytes(o->text, o->text_len);
    } else {
        FZ_ASSERT(o->text_len == 0);
    }
    fz_byte_sink += o->ts_start_ns ^ o->ts_first_row_ns ^ o->ts_complete_ns ^ o->ts_ready_ns;
    fz_byte_sink += o->rows + o->bytes + o->flags + (unsigned char)o->txn_status;
}

/* Normaliser contract (norm_sql.h, Р22): text_len under the cap and terminated,
 * and the fingerprint is a pure function of the input — two runs over the same
 * bytes agree bit-for-bit (a hash reading uninitialised or out-of-bounds memory
 * fails this before ASAN ever notices). */
static inline void fz_check_norm_stable(const char *sql, size_t len, enum lk_sql_dialect dialect)
{
    struct lk_norm_out a, b;

    lk_norm_sql(sql, len, dialect, &a);
    lk_norm_sql(sql, len, dialect, &b);
    FZ_ASSERT(a.text_len < LK_NORM_TEXT_MAX);
    FZ_ASSERT(a.text[a.text_len] == '\0');
    FZ_ASSERT(a.fp == b.fp && a.text_len == b.text_len && a.trunc == b.trunc);
    FZ_ASSERT(memcmp(a.text, b.text, a.text_len + 1) == 0);
    fz_read_bytes(a.text, a.text_len);
}

#endif /* LATKIT_FUZZ_INVARIANTS_H */
