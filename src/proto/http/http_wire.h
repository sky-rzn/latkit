/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded text cursor over one HTTP/1.x header block (РH3/РH4, PLAN-HTTP.md
 * М2) — the pg_wire.h / my_wire.h of this protocol. The input is untrusted:
 * a header block comes off the wire and may be truncated (capture budget),
 * corrupt, or deliberately shaped to desynchronise two hops, so every accessor
 * takes an explicit (pointer, length) pair and no function here ever reads past
 * the range it was handed. Direct pointer walking over lk_msg.body is a review
 * reject, exactly as in the two database protocols.
 *
 * The difference from those two: HTTP has no length prefixes at all, so there
 * is no "field is longer than the body" corruption to report — the cursor
 * reports *shape* failures instead, through the HTTP_HEAD_* flags on the
 * iterator (obs-fold, space before the colon, a missing line terminator) and
 * through the false returns of the start-line parsers. What a caller does with
 * them is policy and lives in http_frame.c: the framer rejects the message,
 * the М3 handler will keep the fields it did manage to read.
 *
 * Two rules encoded here rather than in the caller, because getting them wrong
 * is the request-smuggling class of bug (notes-httpproto.md §"Body length"):
 *
 *   - `Content-Length` accepts one value, or a comma list of *identical*
 *     values (RFC 9110 §8.6 permits `5, 5`); any disagreement is a reject,
 *     not a best guess;
 *   - a field name may not be followed by whitespace before its colon, and a
 *     line may not begin with SP/HTAB (obs-fold, obsolete since RFC 9112
 *     §5.2) — both desynchronise header parsing between hops.
 *
 * Header-only and dependency-light so unit tests and the fuzz harness include
 * it directly. Bare LF is accepted as a line terminator and *reported*
 * (HTTP_HEAD_LF_ONLY): servers disagree about it in practice (measured, М0
 * corpus `lf-only`), and an observer that rejected what the server accepted
 * would go blind exactly where the traffic is interesting. */
#ifndef LATKIT_HTTP_WIRE_H
#define LATKIT_HTTP_WIRE_H

#include <linux/types.h>
#include <stdbool.h>
#include <string.h>

/* A borrowed byte range: never NUL-terminated, never owned, valid only as long
 * as the buffer it points into. `p` may be NULL only when `n` is 0. */
struct http_span {
    const char *p;
    __u32 n;
};

static inline struct http_span http_span(const char *p, __u32 n)
{
    struct http_span s = {p, n};

    return s;
}

/* --- character classes (RFC 9110 §5.6.2, RFC 9112 §2) --------------------- */

static inline char http_lc(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

static inline bool http_is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static inline bool http_is_ows(char c)
{
    return c == ' ' || c == '\t';
}

/* tchar: what a field name and a method token may consist of. Anything else in
 * either position is malformed, not merely unknown. Spelled as a switch rather
 * than a strchr over a literal: this runs once per byte of every field name on
 * every head, and a libc call there is not worth the two lines it saves. */
static inline bool http_is_tchar(char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || http_is_digit(c))
        return true;
    switch (c) {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '^':
    case '_':
    case '`':
    case '|':
    case '~':
        return true;
    default:
        return false;
    }
}

static inline int http_hex_val(char c)
{
    if (http_is_digit(c))
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* --- span helpers --------------------------------------------------------- */

/* Case-insensitive compare against a lowercase NUL-terminated literal. */
static inline bool http_span_eq_ci(struct http_span s, const char *lit)
{
    __u32 i;

    for (i = 0; i < s.n; i++) {
        if (!lit[i] || http_lc(s.p[i]) != lit[i])
            return false;
    }
    return lit[i] == 0;
}

static inline struct http_span http_trim_ows(struct http_span s)
{
    while (s.n && http_is_ows(s.p[0])) {
        s.p++;
        s.n--;
    }
    while (s.n && http_is_ows(s.p[s.n - 1]))
        s.n--;
    return s;
}

/* Comma-separated token list: does it contain `tok` (lowercase literal)?
 * Used for `Connection: keep-alive, Upgrade`, `Expect: 100-continue` and the
 * `Transfer-Encoding` chain. */
static inline bool http_list_has(struct http_span v, const char *tok)
{
    __u32 i = 0;

    while (i < v.n) {
        __u32 start;

        while (i < v.n && (v.p[i] == ',' || http_is_ows(v.p[i])))
            i++;
        start = i;
        while (i < v.n && v.p[i] != ',')
            i++;
        if (http_span_eq_ci(http_trim_ows(http_span(v.p + start, i - start)), tok))
            return true;
    }
    return false;
}

/* The last member of a comma-separated list — for `Transfer-Encoding`, where
 * only the *final* encoding decides the framing (RFC 9112 §6.1). Empty span
 * when the list holds no token at all. */
static inline struct http_span http_list_last(struct http_span v)
{
    struct http_span last = http_span(v.p, 0);
    __u32 i = 0;

    while (i < v.n) {
        __u32 start;

        while (i < v.n && (v.p[i] == ',' || http_is_ows(v.p[i])))
            i++;
        start = i;
        while (i < v.n && v.p[i] != ',')
            i++;
        if (i > start)
            last = http_trim_ows(http_span(v.p + start, i - start));
    }
    return last;
}

/* All-digit decimal, no sign, no whitespace, no overflow past 2^62 (a body
 * length beyond that is corruption, not a big file). */
static inline bool http_parse_u64(struct http_span s, __u64 *out)
{
    __u64 v = 0;

    if (!s.n)
        return false;
    for (__u32 i = 0; i < s.n; i++) {
        if (!http_is_digit(s.p[i]))
            return false;
        if (v > ((__u64)1 << 62) / 10)
            return false;
        v = v * 10 + (__u64)(s.p[i] - '0');
    }
    *out = v;
    return true;
}

/* Content-Length (RFC 9112 §6.3.4): one value, or a comma list whose members
 * are all equal — `Content-Length: 5, 5` is legal and means 5. Anything else,
 * including a single unparsable value, is a reject: when two hops can disagree
 * about where the message ends, any length we pick is a guess. */
static inline bool http_parse_content_length(struct http_span v, __u64 *out)
{
    bool first = true;
    __u64 val = 0;
    __u32 i = 0;

    while (i < v.n) {
        struct http_span tok;
        __u64 cur;
        __u32 start;

        while (i < v.n && (v.p[i] == ',' || http_is_ows(v.p[i])))
            i++;
        start = i;
        while (i < v.n && v.p[i] != ',')
            i++;
        if (i == start)
            continue;
        tok = http_trim_ows(http_span(v.p + start, i - start));
        if (!http_parse_u64(tok, &cur))
            return false;
        if (first) {
            val = cur;
            first = false;
        } else if (cur != val) {
            return false;
        }
    }
    if (first)
        return false; /* header present but empty */
    *out = val;
    return true;
}

/* --- header block iterator ------------------------------------------------ */

/* Shape observations, sticky once set. BAD stops the iteration: past a
 * malformed field line nothing can be trusted to be a field line. */
#define HTTP_HEAD_LF_ONLY (1 << 0) /* a line ended with a bare LF */
#define HTTP_HEAD_BAD     (1 << 1) /* obs-fold / space before colon / no colon */
#define HTTP_HEAD_NO_EOL  (1 << 2) /* the block ends mid-line (truncated head) */

struct http_head {
    const char *p, *end;
    __u16 flags; /* HTTP_HEAD_* */
};

static inline void http_head_init(struct http_head *h, const void *head, __u32 n)
{
    h->p = (const char *)head;
    h->end = h->p ? h->p + n : NULL;
    h->flags = 0;
}

/* Next line with its terminator stripped. false when the block is exhausted.
 * An empty line is returned as an empty span — the caller (http_head_field)
 * reads it as the end of the field section. A final line with no terminator is
 * returned once, flagged NO_EOL: a head cut by the capture budget still carries
 * a readable prefix, and refusing to look at it would throw away the start
 * line, which is the one part that always arrives (РH14). */
static inline bool http_head_line(struct http_head *h, struct http_span *out)
{
    const char *nl;
    __u32 avail = h->p < h->end ? (__u32)(h->end - h->p) : 0;
    __u32 len;

    if (!avail)
        return false;
    nl = (const char *)memchr(h->p, '\n', avail);
    if (!nl) {
        *out = http_span(h->p, avail);
        h->p = h->end;
        h->flags |= HTTP_HEAD_NO_EOL;
        return true;
    }
    len = (__u32)(nl - h->p);
    if (len && h->p[len - 1] == '\r')
        len--;
    else
        h->flags |= HTTP_HEAD_LF_ONLY;
    *out = http_span(h->p, len);
    h->p = nl + 1;
    return true;
}

/* Next field line, split and trimmed. false ends the field section: the empty
 * line, the end of the block, or a malformed line (HTTP_HEAD_BAD). */
static inline bool http_head_field(struct http_head *h, struct http_span *name,
                                   struct http_span *val)
{
    struct http_span line;
    __u32 i;

    if (h->flags & HTTP_HEAD_BAD)
        return false;
    if (!http_head_line(h, &line))
        return false;
    if (!line.n)
        return false; /* the empty line: end of the header block */
    if (http_is_ows(line.p[0])) {
        h->flags |= HTTP_HEAD_BAD; /* obs-fold (RFC 9112 §5.2) */
        return false;
    }
    for (i = 0; i < line.n && line.p[i] != ':'; i++) {
        if (!http_is_tchar(line.p[i])) {
            h->flags |= HTTP_HEAD_BAD;
            return false;
        }
    }
    if (i == 0 || i == line.n) {
        h->flags |= HTTP_HEAD_BAD; /* no colon, or an empty name */
        return false;
    }
    *name = http_span(line.p, i);
    *val = http_trim_ows(http_span(line.p + i + 1, line.n - i - 1));
    return true;
}

/* --- start lines ---------------------------------------------------------- */

/* Methods we know by name (RFC 9110 §9 + PATCH from RFC 5789). Any other token
 * parses fine and is reported as HTTP_M_OTHER — an unknown method must cost a
 * label, never the framing. The same list is the resync anchor alphabet
 * (http_frame.c), which is why it stays short. */
enum http_method {
    HTTP_M_OTHER = 0,
    HTTP_M_GET,
    HTTP_M_HEAD,
    HTTP_M_POST,
    HTTP_M_PUT,
    HTTP_M_DELETE,
    HTTP_M_CONNECT,
    HTTP_M_OPTIONS,
    HTTP_M_TRACE,
    HTTP_M_PATCH,
};

static inline enum http_method http_method_id(struct http_span m)
{
    static const struct {
        const char *name;
        __u8 id;
    } tab[] = {
        {"GET", HTTP_M_GET},         {"HEAD", HTTP_M_HEAD},     {"POST", HTTP_M_POST},
        {"PUT", HTTP_M_PUT},         {"DELETE", HTTP_M_DELETE}, {"CONNECT", HTTP_M_CONNECT},
        {"OPTIONS", HTTP_M_OPTIONS}, {"TRACE", HTTP_M_TRACE},   {"PATCH", HTTP_M_PATCH},
    };

    for (unsigned i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        size_t len = strlen(tab[i].name);

        if (m.n == len && !memcmp(m.p, tab[i].name, len)) /* methods are case-sensitive */
            return (enum http_method)tab[i].id;
    }
    return HTTP_M_OTHER;
}

/* request-line = method SP request-target SP "HTTP/1." ("0" / "1")
 *
 * Strict on purpose: exactly two spaces, a non-empty target with no CTL and no
 * space, nothing after the version token. HTTP/0.9 (`GET /path` with no
 * version) and HTTP/2.0 both fail here — the first is out of scope, the second
 * is recognised before this by its preface. A malformed request line is not a
 * message we can frame, so the framer drops the direction into resync rather
 * than guessing (notes-httpproto.md §"Start lines"). */
static inline bool http_parse_req_line(struct http_span line, struct http_span *method,
                                       struct http_span *target, __u8 *minor)
{
    __u32 i = 0, ms, ts;

    while (i < line.n && line.p[i] != ' ') {
        if (!http_is_tchar(line.p[i]))
            return false;
        i++;
    }
    ms = i;
    if (!ms || i == line.n)
        return false;
    i++; /* SP */
    ts = i;
    while (i < line.n && line.p[i] != ' ') {
        if ((unsigned char)line.p[i] <= 0x20 || (unsigned char)line.p[i] == 0x7f)
            return false;
        i++;
    }
    if (i == ts || i == line.n)
        return false;
    *target = http_span(line.p + ts, i - ts);
    i++; /* SP */
    if (line.n - i != 8 || memcmp(line.p + i, "HTTP/1.", 7))
        return false;
    if (line.p[i + 7] != '0' && line.p[i + 7] != '1')
        return false;
    *minor = (__u8)(line.p[i + 7] - '0');
    *method = http_span(line.p, ms);
    return true;
}

/* status-line = "HTTP/1." ("0" / "1") SP 3DIGIT [ SP reason-phrase ]
 *
 * The reason phrase is optional (RFC 9112 §4) and ignored; a bare
 * `HTTP/1.1 204` parses like `HTTP/1.1 204 No Content`. The status must be
 * three digits with a leading 1..5 — the same constraint that makes this the
 * strongest resync anchor of the three protocols. */
static inline bool http_parse_status_line(struct http_span line, __u16 *code, __u8 *minor)
{
    if (line.n < 12 || memcmp(line.p, "HTTP/1.", 7))
        return false;
    if (line.p[7] != '0' && line.p[7] != '1')
        return false;
    if (line.p[8] != ' ')
        return false;
    if (line.p[9] < '1' || line.p[9] > '5' || !http_is_digit(line.p[10]) ||
        !http_is_digit(line.p[11]))
        return false;
    if (line.n > 12 && line.p[12] != ' ')
        return false;
    *minor = (__u8)(line.p[7] - '0');
    *code = (__u16)((line.p[9] - '0') * 100 + (line.p[10] - '0') * 10 + (line.p[11] - '0'));
    return true;
}

#endif /* LATKIT_HTTP_WIRE_H */
