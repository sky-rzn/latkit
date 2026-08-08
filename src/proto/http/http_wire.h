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

/* Case-insensitive compare against a lowercase NUL-terminated literal.
 *
 * The length is settled first rather than by walking off the end of `lit` and
 * checking its NUL afterwards. That earlier shape was safe — the walk returns
 * false at the terminator, so the trailing index can only ever land *on* it —
 * but the compiler cannot see that, and at -O2 it reports the read as an
 * out-of-bounds subscript on the longest literal in the file
 * ("content-length", 14 chars). This form is provably in bounds, and it is also
 * the faster one: a header name that does not match is usually the wrong length
 * and now costs a compare rather than a loop. strlen on a literal folds to a
 * constant. */
static inline bool http_span_eq_ci(struct http_span s, const char *lit)
{
    if (s.n != strlen(lit))
        return false;
    for (__u32 i = 0; i < s.n; i++) {
        if (http_lc(s.p[i]) != lit[i])
            return false;
    }
    return true;
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

/* The canonical spelling of a known method, for the `op` field of an
 * observation and the `method` label. NULL for HTTP_M_OTHER: an unknown method
 * is reported by its own bytes (bounded, copied by the caller), never by a
 * guess. */
static inline const char *http_method_name(enum http_method id)
{
    switch (id) {
    case HTTP_M_GET:
        return "GET";
    case HTTP_M_HEAD:
        return "HEAD";
    case HTTP_M_POST:
        return "POST";
    case HTTP_M_PUT:
        return "PUT";
    case HTTP_M_DELETE:
        return "DELETE";
    case HTTP_M_CONNECT:
        return "CONNECT";
    case HTTP_M_OPTIONS:
        return "OPTIONS";
    case HTTP_M_TRACE:
        return "TRACE";
    case HTTP_M_PATCH:
        return "PATCH";
    default:
        return NULL;
    }
}

/* One letter per method for the per-direction message tally (lk_proto_stats
 * .by_type, printed by the stats line): a stream framer's own message types
 * carry no information a caller wants counted, the methods do. Distinct from
 * the response side's status-class digits by construction — different
 * direction, and letters vs digits anyway. */
static inline char http_method_tag(enum http_method id)
{
    switch (id) {
    case HTTP_M_GET:
        return 'G';
    case HTTP_M_HEAD:
        return 'H';
    case HTTP_M_POST:
        return 'P';
    case HTTP_M_PUT:
        return 'U';
    case HTTP_M_DELETE:
        return 'D';
    case HTTP_M_CONNECT:
        return 'C';
    case HTTP_M_OPTIONS:
        return 'O';
    case HTTP_M_TRACE:
        return 'T';
    case HTTP_M_PATCH:
        return 'A';
    default:
        return '?';
    }
}

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

/* --- request-target and header values the handler reads (М3) -------------- */

/* Split a request-target into the three pieces the handler labels with. All
 * four forms of RFC 9112 §3.2 are accepted, because all four are in the М0
 * corpus:
 *
 *   origin-form     /orders/42?x=1        path=/orders/42  query=x=1
 *   absolute-form   http://h:8080/o?x=1   authority=h:8080, then as above
 *   authority-form  h:443                 authority=h:443, path empty (CONNECT)
 *   asterisk-form   *                     path=*           (OPTIONS *)
 *
 * The authority of an absolute-form target *overrides* the Host header
 * (notes-httpproto.md §"Start lines"): a proxy request carries the real target
 * host there, and Host may name the proxy. Any piece may come back empty; none
 * is ever NUL-terminated. The scheme is recognised but not returned — `http` vs
 * `https` on the wire says nothing useful when the observer is the one
 * decrypting. */
static inline void http_target_split(struct http_span t, struct http_span *path,
                                     struct http_span *query, struct http_span *authority)
{
    __u32 i = 0, s;

    *authority = http_span(t.p, 0);
    /* scheme "://" — only ever at the very start, and only ASCII letters,
     * digits, "+", "-", "." before it (RFC 3986 §3.1). */
    while (i < t.n && t.p[i] != ':' && t.p[i] != '/' && t.p[i] != '?')
        i++;
    if (i && i + 2 < t.n && t.p[i] == ':' && t.p[i + 1] == '/' && t.p[i + 2] == '/') {
        i += 3;
        s = i;
        while (i < t.n && t.p[i] != '/' && t.p[i] != '?')
            i++;
        *authority = http_span(t.p + s, i - s);
    } else if (t.n && t.p[0] != '/' && t.p[0] != '*') {
        /* authority-form: no scheme, no leading slash — CONNECT's target. */
        *authority = t;
        *path = http_span(t.p, 0);
        *query = http_span(t.p, 0);
        return;
    } else {
        i = 0;
    }
    s = i;
    while (i < t.n && t.p[i] != '?')
        i++;
    *path = http_span(t.p + s, i - s);
    if (i < t.n)
        i++; /* the '?' itself belongs to neither piece */
    *query = http_span(t.p + i, t.n - i);
}

/* The first token of a comma/semicolon-parameterised value: `text/html` out of
 * `text/html; charset=utf-8`. Used for Content-Type, which goes into a span
 * attribute and must not carry the parameters (they are low-value and
 * occasionally identifying). */
static inline struct http_span http_first_token(struct http_span v)
{
    __u32 i = 0;

    while (i < v.n && v.p[i] != ';' && v.p[i] != ',')
        i++;
    return http_trim_ows(http_span(v.p, i));
}

/* W3C Trace Context (РH11):
 *
 *   traceparent: 00-<32 hex trace-id>-<16 hex parent-id>-<2 hex flags>
 *
 * Accepted only in that exact shape: version `00`, four dash-separated fields
 * of the right lengths, hex only, and neither id all-zero. Anything else is
 * ignored rather than patched up — a malformed header must not produce a span
 * attached to a made-up trace, which is worse than no parent at all. Lowercase
 * is what the spec mandates; uppercase hex is accepted on the read side because
 * rejecting a trace over letter case would be pedantry with a real cost.
 *
 * A version other than `00` is *not* accepted here even though the spec asks
 * forward-compatible parsers to try: a future version may reorder the fields,
 * and this parser has no way to know. */
static inline bool http_parse_traceparent(struct http_span v, __u8 trace_id[16], __u8 parent_id[8],
                                          __u8 *flags)
{
    static const __u8 zeros[16] = {0};
    __u8 buf[1 + 16 + 8 + 1]; /* version, trace-id, parent-id, flags */
    __u32 i = 0;
    /* field byte lengths, in order: version, trace-id, parent-id, flags */
    static const __u8 want[4] = {1, 16, 8, 1};
    __u8 *out = buf;

    for (unsigned f = 0; f < 4; f++) {
        for (unsigned b = 0; b < want[f]; b++) {
            int hi, lo;

            if (i + 1 >= v.n)
                return false;
            hi = http_hex_val(v.p[i]);
            lo = http_hex_val(v.p[i + 1]);
            if (hi < 0 || lo < 0)
                return false;
            *out++ = (__u8)(hi * 16 + lo);
            i += 2;
        }
        if (f < 3) {
            if (i >= v.n || v.p[i] != '-')
                return false;
            i++;
        }
    }
    /* Trailing garbage after the flags field is how a *later* version would
     * look; the spec says to ignore it, and a version-00 prefix is still
     * unambiguous, so only a non-dash separator is a reject. */
    if (i < v.n && v.p[i] != '-')
        return false;
    if (buf[0] != 0x00)
        return false;
    if (!memcmp(buf + 1, zeros, 16) || !memcmp(buf + 17, zeros, 8))
        return false;
    memcpy(trace_id, buf + 1, 16);
    memcpy(parent_id, buf + 17, 8);
    *flags = buf[25];
    return true;
}

static inline int http_b64_val(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (http_is_digit(c))
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

/* `Authorization: Basic <base64(user ":" password)>` → the user half, and only
 * with --http-user basic (РH10).
 *
 * The decode stops at the first colon by construction. base64 is a 4-character
 * → 3-byte code, so up to two bytes past the colon pass through a local
 * variable; they are never written to `out` and the buffer dies with the call.
 * That is the whole guarantee the plan asks for: the password is not decoded
 * past the colon and reaches nothing that outlives this function.
 *
 * Any other scheme — `Bearer` above all — returns false without a byte being
 * looked at. false also for a name that does not fit `cap`, an unterminated
 * name, or invalid base64: a truncated identity is worse than none. */
static inline bool http_basic_user(struct http_span v, char *out, __u32 cap)
{
    __u32 i = 0, n = 0;
    __u32 acc = 0, bits = 0;

    if (v.n < 6 || !http_span_eq_ci(http_span(v.p, 5), "basic") || v.p[5] != ' ')
        return false;
    for (i = 6; i < v.n && http_is_ows(v.p[i]); i++)
        ;
    for (; i < v.n; i++) {
        int d = http_b64_val(v.p[i]);

        if (v.p[i] == '=')
            break;
        if (d < 0)
            return false;
        acc = (acc << 6) | (__u32)d;
        bits += 6;
        if (bits < 8)
            continue;
        bits -= 8;
        char c = (char)((acc >> bits) & 0xff);

        if (c == ':') {
            out[n] = '\0';
            return n > 0;
        }
        if (n + 1 >= cap)
            return false;
        if (c < 0x20 || c == 0x7f)
            return false; /* control bytes in a label: reject the whole value */
        out[n++] = c;
    }
    return false; /* no colon: not a user:password pair, so not a user */
}

#endif /* LATKIT_HTTP_WIRE_H */
