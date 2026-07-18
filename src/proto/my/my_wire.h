/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded read cursor over one MySQL classic-protocol packet body (РМ3,
 * MYSQL.md М2) — pg_wire.h transplanted to the MySQL wire order: multi-byte
 * ints are little-endian, and the protocol's own variable-size scalars
 * (length-encoded integers and strings) get first-class readers. The input is
 * untrusted: every accessor checks the bound before touching a byte, so a
 * read past `end` is impossible by construction — the only way the parser may
 * walk a body (direct pointer arithmetic over lk_msg.body is a review
 * reject), and the invariant the fuzz harness leans on.
 *
 * `end` is body_cap, i.e. the captured prefix — possibly shorter than the
 * real body (LK_MSG_BODY_TRUNC). As with pg_wire, a cursor running dry has
 * two meanings and my_wire does NOT decide between them — it only reports
 * `overrun`:
 *
 *   - overrun on a LK_MSG_BODY_TRUNC body  -> truncation: the missing fields
 *     are unknown, not an error (mark the field truncated, move on);
 *   - overrun on a full body               -> corruption: bump parse_errors,
 *     drop the unit.
 *
 * Header-only and dependency-light so unit tests and the fuzz harness include
 * it directly. */
#ifndef LATKIT_MY_WIRE_H
#define LATKIT_MY_WIRE_H

#include <linux/types.h>
#include <stdbool.h>
#include <string.h>

struct my_wire {
    const __u8 *p;   /* next unread byte */
    const __u8 *end; /* one past the last readable byte (body + body_cap) */
    bool overrun;    /* a bounds check has failed since init */
};

static inline void my_wire_init(struct my_wire *w, const __u8 *body, __u32 body_cap)
{
    w->p = body;
    /* body may be NULL for a zero-length packet; pointer arithmetic on NULL
     * is UB (the pg_wire clang-18 UBSAN lesson), so only offset a real
     * pointer. A NULL body leaves end == NULL and the first read trips
     * overrun, as intended. */
    w->end = body ? body + body_cap : body;
    w->overrun = false;
}

/* True while every read so far stayed in bounds. */
static inline bool my_wire_ok(const struct my_wire *w)
{
    return !w->overrun;
}

static inline __u32 my_wire_remaining(const struct my_wire *w)
{
    return w->p < w->end ? (__u32)(w->end - w->p) : 0;
}

/* Bounds failure: latch the flag, park the cursor at `end` so subsequent
 * reads also fail (never wrap), and let the getter zero its out-param. */
static inline bool my_wire_fail(struct my_wire *w)
{
    w->overrun = true;
    w->p = w->end;
    return false;
}

/* Each getter advances only on success; on overrun the out-param is zeroed. */
static inline bool my_wire_get_u8(struct my_wire *w, __u8 *out)
{
    if (my_wire_remaining(w) < 1) {
        *out = 0;
        return my_wire_fail(w);
    }
    *out = *w->p++;
    return true;
}

static inline bool my_wire_get_u16(struct my_wire *w, __u16 *out)
{
    if (my_wire_remaining(w) < 2) {
        *out = 0;
        return my_wire_fail(w);
    }
    *out = (__u16)((__u16)w->p[1] << 8 | w->p[0]);
    w->p += 2;
    return true;
}

static inline bool my_wire_get_u24(struct my_wire *w, __u32 *out)
{
    if (my_wire_remaining(w) < 3) {
        *out = 0;
        return my_wire_fail(w);
    }
    *out = (__u32)w->p[2] << 16 | (__u32)w->p[1] << 8 | w->p[0];
    w->p += 3;
    return true;
}

static inline bool my_wire_get_u32(struct my_wire *w, __u32 *out)
{
    if (my_wire_remaining(w) < 4) {
        *out = 0;
        return my_wire_fail(w);
    }
    *out = (__u32)w->p[3] << 24 | (__u32)w->p[2] << 16 | (__u32)w->p[1] << 8 | w->p[0];
    w->p += 4;
    return true;
}

static inline bool my_wire_get_u64(struct my_wire *w, __u64 *out)
{
    if (my_wire_remaining(w) < 8) {
        *out = 0;
        return my_wire_fail(w);
    }
    *out = 0;
    for (int i = 7; i >= 0; i--)
        *out = *out << 8 | w->p[i];
    w->p += 8;
    return true;
}

/* Skip n bytes (fields we do not read, packet tails). */
static inline bool my_wire_skip(struct my_wire *w, __u32 n)
{
    if (my_wire_remaining(w) < n)
        return my_wire_fail(w);
    w->p += n;
    return true;
}

/* Length-encoded integer. First-byte semantics: < 0xfb literal, 0xfc +u16,
 * 0xfd +u24, 0xfe +u64. 0xfb (row NULL marker) and 0xff (never a lenenc
 * head — the ERR byte) are NOT lenenc ints: the cursor does not move, no
 * overrun is latched, and false says "look at the byte yourself" — the
 * caller's phase context decides what it means. Running out of bytes is an
 * ordinary overrun. */
static inline bool my_wire_get_lenenc(struct my_wire *w, __u64 *out)
{
    __u8 head;

    *out = 0;
    if (my_wire_remaining(w) < 1)
        return my_wire_fail(w);
    head = w->p[0];
    if (head == 0xfb || head == 0xff)
        return false; /* not a lenenc int; cursor untouched */
    w->p++;
    if (head < 0xfb) {
        *out = head;
        return true;
    }
    if (head == 0xfc) {
        __u16 v;

        if (!my_wire_get_u16(w, &v))
            return false;
        *out = v;
        return true;
    }
    if (head == 0xfd) {
        __u32 v;

        if (!my_wire_get_u24(w, &v))
            return false;
        *out = v;
        return true;
    }
    return my_wire_get_u64(w, out); /* 0xfe */
}

/* Length-encoded string: lenenc length + that many bytes. On success *out
 * points into the buffer (valid as long as the body is) and *len is the
 * byte length. A length running past `end` is an overrun; out/len still
 * describe the available bytes, so a truncated body can salvage the prefix
 * while a full body treats it as corruption (the pg_wire_cstring pattern).
 * *out is never NULL. A 0xfb/0xff head is passed through from
 * my_wire_get_lenenc: false with the cursor untouched and no overrun. */
static inline bool my_wire_get_lenenc_str(struct my_wire *w, const char **out, __u32 *len)
{
    __u64 sz;

    *out = w->p ? (const char *)w->p : ""; /* NULL body: a valid empty string */
    *len = 0;
    if (!my_wire_get_lenenc(w, &sz))
        return false;
    *out = (const char *)w->p;
    if (sz > my_wire_remaining(w)) {
        *len = my_wire_remaining(w);
        return my_wire_fail(w);
    }
    *len = (__u32)sz;
    w->p += sz;
    return true;
}

/* NUL-terminated string (server version, auth plugin name, user, database).
 * Same salvage semantics as pg_wire_cstring: a missing terminator is an
 * overrun, but out/len still describe the unterminated bytes. */
static inline bool my_wire_cstring(struct my_wire *w, const char **out, __u32 *len)
{
    __u32 avail = my_wire_remaining(w);
    const __u8 *nul = avail ? (const __u8 *)memchr(w->p, 0, avail) : NULL;

    *out = w->p ? (const char *)w->p : ""; /* NULL body: a valid empty string */
    if (!nul) {
        *len = avail;
        return my_wire_fail(w);
    }
    *len = (__u32)(nul - w->p);
    w->p = nul + 1;
    return true;
}

#endif /* LATKIT_MY_WIRE_H */
