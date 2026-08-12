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

#include "http.h" /* the HTTP framer's synthetic dictionary (РH3) */
#include "norm_redact.h"
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

/* HTTP framer message contract (http.h, РH3). The stream mode publishes a
 * dictionary of its own, and the invariants are shape rules rather than length
 * arithmetic — there is no length field on the wire to cross-check against:
 *
 *   'R' / 'S' / 'I'  a header block: len is its length, the captured prefix is
 *                    body_cap, and "truncated" is exactly "prefix shorter than
 *                    the block". Never longer than the Р11 cap, because the
 *                    framer refuses a head that would not fit;
 *   'D' / 'E' / '!'  counts and codes, never payload: body is NULL by
 *                    construction (РH12 — bodies are not read, so they cannot
 *                    leak), so a non-NULL one here means the framer handed out
 *                    a pointer it had no business having.
 *
 * A note's code must be a defined one: an out-of-range code would mean the
 * handler tallies a degradation it cannot name. */
static inline void fz_check_http_msg(const struct lk_msg *m)
{
    FZ_ASSERT(m->body_cap <= LK_MSG_BODY_MAX);
    FZ_ASSERT(!(m->flags & LK_MSG_STARTUP)); /* HTTP has no startup framing */
    switch (m->type) {
    case LK_HTTP_MSG_REQ:
    case LK_HTTP_MSG_RESP:
    case LK_HTTP_MSG_INTER:
        /* len is the block we captured and body_cap is all of it — unlike the
         * message mode there is no length field to compare against, so
         * LK_MSG_BODY_TRUNC means "the block never terminated, its real length
         * is unknown and larger" rather than "cap < len" (http.h). */
        FZ_ASSERT(m->len && m->len <= LK_MSG_BODY_MAX);
        FZ_ASSERT(m->body_cap == m->len);
        FZ_ASSERT(m->body != NULL);
        fz_read_bytes(m->body, m->body_cap);
        break;
    case LK_HTTP_MSG_NOTE:
        FZ_ASSERT(m->len > 0 && m->len < (__u32)LK_HTTP_NOTE_MAX);
        /* fall through */
    case LK_HTTP_MSG_DATA:
    case LK_HTTP_MSG_END:
        FZ_ASSERT(m->body == NULL && m->body_cap == 0);
        FZ_ASSERT(!(m->flags & LK_MSG_BODY_TRUNC));
        break;
    default:
        FZ_ASSERT(0); /* a type outside the dictionary */
    }
}

/* Observation contract (proto.h, Р16-Р18): the parser may emit "no text" or a
 * truncated prefix, but never a dangling or inconsistent one, and sqlstate is
 * always a bounded C-string. Every field is read so an out-of-bounds pointer
 * surfaces at emit time, not only at parse time. */
static inline void fz_check_obs(const struct lk_query_obs *o)
{
    FZ_ASSERT(o->kind <= LK_Q_REQUEST);
    FZ_ASSERT(memchr(o->sqlstate, '\0', sizeof(o->sqlstate)) != NULL);
    if (o->flags & LK_QO_NO_TEXT)
        FZ_ASSERT(!o->text && !o->text_len);
    if (o->text) {
        FZ_ASSERT(o->text_len > 0);
        fz_read_bytes(o->text, o->text_len);
    } else {
        FZ_ASSERT(o->text_len == 0);
    }
    /* Borrowed-for-the-callback strings must be readable in full, or not
     * offered at all: `op` and `err_name` are the HTTP/S3 half of the contract
     * and a dangling one would be invisible without this read (РH8). */
    if (o->op)
        fz_read_bytes(o->op, strlen(o->op));
    if (o->err_name)
        fz_read_bytes(o->err_name, strlen(o->err_name));
    /* The same rule for the РH11 span material (М6), which is the largest bundle
     * of borrowed pointers the contract has: a trace context is offered whole or
     * not at all — a trace id without a parent id would send the span builder
     * reading eight bytes that were never there. */
    if (o->http) {
        const struct lk_http_obs *h = o->http;

        FZ_ASSERT((h->trace_id != NULL) == (h->parent_id != NULL));
        if (h->trace_id) {
            fz_read_bytes(h->trace_id, 16);
            fz_read_bytes(h->parent_id, 8);
        }
        if (h->tracestate)
            fz_read_bytes(h->tracestate, h->tracestate_len);
        else
            FZ_ASSERT(h->tracestate_len == 0);
        if (h->req_id)
            fz_read_bytes(h->req_id, strlen(h->req_id));
        if (h->ctype)
            fz_read_bytes(h->ctype, strlen(h->ctype));
    }
    /* РH5's ordering: the request cannot finish before it started. The other
     * three stamps are deliberately *not* ordered against each other — a
     * response head can precede the end of the request body (an early 413), and
     * a degraded unit may carry zeros. */
    if (o->ts_req_done_ns)
        FZ_ASSERT(o->ts_req_done_ns >= o->ts_start_ns);
    fz_byte_sink += o->ts_start_ns ^ o->ts_first_row_ns ^ o->ts_complete_ns ^ o->ts_ready_ns;
    fz_byte_sink += o->ts_req_done_ns ^ o->bytes_in ^ o->bytes_out;
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

/* Route templater contract (norm_route.h, РH7). Same two properties as the SQL
 * normaliser — bounded, terminated, deterministic — plus the two the route has
 * of its own and the whole track depends on:
 *
 *   - **no byte of the query reaches the template** unless a key was named.
 *     Checked structurally rather than by comparing strings: with no query keys
 *     configured, a '?' in the output can only have come from the query.
 *   - **no control byte reaches the template**, whatever the input. This is the
 *     privacy/format invariant of РH12 at its narrowest point: everything
 *     downstream (a Prometheus label, an OTLP attribute) assumes it. */
static inline void fz_check_route_stable(const char *method, size_t mlen, const char *target,
                                         size_t tlen, const struct lk_route_cfg *cfg)
{
    struct lk_route_out a, b;

    lk_norm_route(method, (uint32_t)mlen, target, (uint32_t)tlen, cfg, &a);
    lk_norm_route(method, (uint32_t)mlen, target, (uint32_t)tlen, cfg, &b);
    FZ_ASSERT(a.text_len < LK_ROUTE_TEXT_MAX);
    FZ_ASSERT(a.text[a.text_len] == '\0');
    FZ_ASSERT(a.fp == b.fp && a.text_len == b.text_len && a.flags == b.flags);
    FZ_ASSERT(memcmp(a.text, b.text, a.text_len + 1) == 0);
    for (uint32_t i = 0; i < a.text_len; i++) {
        unsigned char c = (unsigned char)a.text[i];

        FZ_ASSERT(c >= 0x20 && c != 0x7f);
        if (!cfg || !cfg->nquery_keys)
            FZ_ASSERT(c != '?');
    }
    fz_read_bytes(a.text, a.text_len);
}

/* The query-string redactor (РH12, М6) over the same untrusted target. Three
 * contracts, and the middle one is load-bearing: http.c sizes its scratch buffer
 * at 2n + 3 on the strength of it, so a shape that made the redacted form grow
 * faster than that would be a heap overflow rather than a wrong label.
 *
 * What is deliberately *not* asserted here is "no secret survives": that is a
 * statement about which keys are sensitive, it is table-driven, and it belongs
 * in test_norm_redact.c where the table is. The fuzzer's job is the memory
 * safety and the bounds. */
static inline void fz_check_redact_stable(const char *target, size_t tlen)
{
    char a[2 * 4096 + 8], b[sizeof(a)], inplace[4096];
    uint32_t na, nb;

    if (tlen > sizeof(inplace))
        tlen = sizeof(inplace);
    na = lk_url_redact(target, (uint32_t)tlen, a, sizeof(a));
    nb = lk_url_redact(target, (uint32_t)tlen, b, sizeof(b));
    FZ_ASSERT(na == nb && memcmp(a, b, na) == 0);
    FZ_ASSERT(na <= 2 * tlen + LK_REDACT_MARK_LEN);
    /* needed() and redact() must agree: a target the scan calls clean has to
     * come through byte for byte, or a caller that trusts the scan keeps the
     * original while the redactor would have changed it. */
    if (!lk_url_redact_needed(target, (uint32_t)tlen))
        FZ_ASSERT(na == tlen && memcmp(a, target, na) == 0);
    if (tlen) {
        memcpy(inplace, target, tlen);
        lk_url_redact_inplace(inplace, (uint32_t)tlen);
        fz_read_bytes(inplace, tlen); /* same length, always: it overwrites */
    }
    fz_read_bytes(a, na);
}

#endif /* LATKIT_FUZZ_INVARIANTS_H */
