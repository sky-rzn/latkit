/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded read cursor over one PG message body (Р18, STAGE3.md). The input is
 * untrusted: every accessor checks the bound before touching a byte, so a read
 * past `end` is impossible by construction — this is the only way the parser
 * is allowed to walk a body (direct pointer arithmetic over lk_msg.body is a
 * review reject). Big-endian is the PG wire order for all multi-byte ints.
 *
 * `end` is body_cap, i.e. the captured prefix — which may be shorter than the
 * real body when the capture budget truncated it (lk_msg carries
 * LK_MSG_BODY_TRUNC). So a cursor running out of bytes has two meanings, and
 * pg_wire does NOT decide between them — it only reports `overrun`:
 *
 *   - overrun on a LK_MSG_BODY_TRUNC body  -> truncation: the missing fields
 *     are simply unknown, not an error (mark the field truncated, move on);
 *   - overrun on a full body               -> corruption: bump parse_errors,
 *     drop the unit, resync to the next Z.
 *
 * Header-only and dependency-light so unit tests and the fuzz harness (3.6)
 * include it directly. */
#ifndef LATKIT_PG_WIRE_H
#define LATKIT_PG_WIRE_H

#include <linux/types.h>
#include <stdbool.h>
#include <string.h>

struct pg_wire {
    const __u8 *p;   /* next unread byte */
    const __u8 *end; /* one past the last readable byte (body + body_cap) */
    bool overrun;    /* a bounds check has failed since init */
};

static inline void pg_wire_init(struct pg_wire *w, const __u8 *body, __u32 body_cap)
{
    w->p = body;
    w->end = body + body_cap;
    w->overrun = false;
}

/* True while every read so far stayed in bounds. */
static inline bool pg_wire_ok(const struct pg_wire *w)
{
    return !w->overrun;
}

static inline __u32 pg_wire_remaining(const struct pg_wire *w)
{
    return w->p < w->end ? (__u32)(w->end - w->p) : 0;
}

/* Each getter advances only on success. On overrun it sets the flag, leaves
 * the cursor at `end` (so subsequent reads also fail, not wrap) and zeroes the
 * out-param, then returns false. */
static inline bool pg_wire_get_u8(struct pg_wire *w, __u8 *out)
{
    if (pg_wire_remaining(w) < 1) {
        w->overrun = true;
        w->p = w->end;
        *out = 0;
        return false;
    }
    *out = *w->p++;
    return true;
}

static inline bool pg_wire_get_u16(struct pg_wire *w, __u16 *out)
{
    if (pg_wire_remaining(w) < 2) {
        w->overrun = true;
        w->p = w->end;
        *out = 0;
        return false;
    }
    *out = (__u16)((__u16)w->p[0] << 8 | w->p[1]);
    w->p += 2;
    return true;
}

static inline bool pg_wire_get_u32(struct pg_wire *w, __u32 *out)
{
    if (pg_wire_remaining(w) < 4) {
        w->overrun = true;
        w->p = w->end;
        *out = 0;
        return false;
    }
    *out = (__u32)w->p[0] << 24 | (__u32)w->p[1] << 16 | (__u32)w->p[2] << 8 | w->p[3];
    w->p += 4;
    return true;
}

/* Skip n bytes (message tails, fields we do not read). */
static inline bool pg_wire_skip(struct pg_wire *w, __u32 n)
{
    if (pg_wire_remaining(w) < n) {
        w->overrun = true;
        w->p = w->end;
        return false;
    }
    w->p += n;
    return true;
}

/* NUL-terminated string. On success *out points at the string inside the
 * buffer (valid as long as the body is), *len is its length excluding the NUL,
 * and the cursor advances past the terminator.
 *
 * Missing terminator before `end` is an overrun: the flag is set, the cursor
 * moves to `end`, and out/len still describe the available (unterminated)
 * bytes — so a truncated body can salvage the prefix while a full body treats
 * it as corruption. *out is never NULL (empty range -> valid empty string). */
static inline bool pg_wire_cstring(struct pg_wire *w, const char **out, __u32 *len)
{
    __u32 avail = pg_wire_remaining(w);
    const __u8 *nul = avail ? (const __u8 *)memchr(w->p, 0, avail) : NULL;

    *out = (const char *)w->p;
    if (!nul) {
        *len = avail;
        w->overrun = true;
        w->p = w->end;
        return false;
    }
    *len = (__u32)(nul - w->p);
    w->p = nul + 1;
    return true;
}

#endif /* LATKIT_PG_WIRE_H */
