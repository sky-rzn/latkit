// SPDX-License-Identifier: GPL-2.0
/* HTTP route templater (РH7, PLAN-HTTP.md М4). See norm_route.h for the rule
 * set and the three-layer contract; this file is the machine.
 *
 * Shape of one classification:
 *
 *     target ──split at '?'──▶ path ──▶ [ map lookup ]  ──hit──▶ pattern text
 *                                │                 └──miss──▶ segment walk
 *                                └── query ──▶ the named keys only
 *                                                      │
 *                                        text buffer + streaming XXH3 ◀┘
 *
 * Every byte that reaches the output goes through emit(), which clips at
 * LK_ROUTE_TEXT_MAX while the hash keeps consuming — so a clipped label never
 * changes a route's identity (the norm_sql.c property, for the same reason).
 *
 * The segment classifiers are the interesting part and they are all *shape*
 * tests: no dictionary, no learning, no state between requests. A classifier
 * that needed to remember previous paths would be a cache with an eviction
 * policy on the hot path, and its answers would depend on capture order — two
 * agents watching the same traffic would disagree about what a route is. */
#include "norm_route.h"

#include <stdlib.h>
#include <string.h>

/* Header-only XXH3, as in norm_sql.c: the implementation lands in this TU. */
#define XXH_INLINE_ALL
#include "xxhash.h"

/* --- character classes ---------------------------------------------------- */

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static bool is_hex(char c)
{
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static bool is_alpha(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static bool is_alnum(char c)
{
    return is_alpha(c) || is_digit(c);
}

/* A byte that must never reach a Prometheus label or an OTLP attribute. High
 * bytes are *not* on this list: a path segment in UTF-8 (the corpus has
 * Cyrillic ones) is a legitimate literal route element. */
static bool is_ctl(char c)
{
    unsigned char b = (unsigned char)c;

    return b < 0x20 || b == 0x7f;
}

/* --- the emitter: bounded text, unbounded hash ---------------------------- */

struct rctx {
    struct lk_route_out *out;
    XXH3_state_t *xh;
};

static void emit(struct rctx *rx, const char *s, uint32_t n)
{
    struct lk_route_out *o = rx->out;
    uint32_t room = LK_ROUTE_TEXT_MAX - 1 - o->text_len;

    if (!n)
        return; /* also keeps a (NULL, 0) span away from memcpy's nonnull */
    XXH3_64bits_update(rx->xh, s, n);
    if (n > room) {
        o->flags |= LK_ROUTE_F_TRUNC;
        n = room;
    }
    memcpy(o->text + o->text_len, s, n);
    o->text_len += n;
}

static void emit_cstr(struct rctx *rx, const char *s)
{
    emit(rx, s, (uint32_t)strlen(s));
}

/* --- segment classifiers (РH7 layer 2) ------------------------------------ */

/* 8-4-4-4-12 hex with dashes. Case-insensitive on the read side: a UUID that
 * arrives upper-cased is still a UUID, and refusing to see it would split one
 * route in two the first time a client changed its formatter. */
static bool looks_uuid(const char *p, uint32_t n)
{
    static const uint8_t group[5] = {8, 4, 4, 4, 12};
    uint32_t i = 0;

    if (n != 36)
        return false;
    for (unsigned g = 0; g < 5; g++) {
        for (unsigned k = 0; k < group[g]; k++) {
            if (!is_hex(p[i++]))
                return false;
        }
        if (g < 4 && p[i++] != '-')
            return false;
    }
    return true;
}

/* Crockford base32, 26 characters — a ULID (and, to the same test, a KSUID-ish
 * sortable id). The alphabet excludes I, L, O and U; accepting them anyway would
 * cost nothing here and lose the ability to tell a 26-character word from an id,
 * so the check stays strict. */
static bool looks_ulid(const char *p, uint32_t n)
{
    if (n != 26)
        return false;
    for (uint32_t i = 0; i < n; i++) {
        char c = p[i];

        if (is_digit(c))
            continue;
        if (!is_alpha(c))
            return false;
        c = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
        if (c == 'I' || c == 'L' || c == 'O' || c == 'U')
            return false;
    }
    return true;
}

/* `YYYY-MM-DD`. A date in a path is a partition key, never a handler name, and
 * it is the one identifier shape that is neither long nor digit-dense enough for
 * the general rules (`2024-01-02` is 10 characters, 80 % digits — caught by the
 * ratio rule, but only because that rule exists; spelling it out keeps the
 * intent readable and survives a change to the ratio). */
static bool looks_date(const char *p, uint32_t n)
{
    if (n != 10 || p[4] != '-' || p[7] != '-')
        return false;
    for (uint32_t i = 0; i < n; i++) {
        if (i != 4 && i != 7 && !is_digit(p[i]))
            return false;
    }
    return true;
}

/* base64 / base64url-ish opaque blob: a token, a signature, a content hash.
 * Bounded below at 16 because shorter mixed-case-plus-digit words are ordinary
 * (`v2Beta1`, `oAuth2`), and required to mix classes so a plain word of 20
 * letters stays a literal. */
static bool looks_b64(const char *p, uint32_t n)
{
    bool up = false, lo = false, dig = false;

    if (n < 16)
        return false;
    for (uint32_t i = 0; i < n; i++) {
        char c = p[i];

        if (c >= 'A' && c <= 'Z')
            up = true;
        else if (c >= 'a' && c <= 'z')
            lo = true;
        else if (is_digit(c))
            dig = true;
        else if (c != '+' && c != '/' && c != '=' && c != '-' && c != '_')
            return false;
    }
    return up && lo && dig;
}

/* Digit-heavy: `2024q1`, `ab12cd34ef`, `user1234`. The plan's rule is "more than
 * 40 % digits"; the minimum length is this file's addition and it is not
 * optional. `/api/v1/users` is the single most common route shape there is, and
 * `v1` is 50 % digits — without a floor the heuristic would eat the version
 * segment of every REST API on earth and report `/api/{id}/users`. Six is the
 * shortest length at which a digit-dense token is more likely an id than a
 * word, measured against the М0 corpus paths. */
static bool looks_digit_heavy(const char *p, uint32_t n)
{
    uint32_t d = 0;

    if (n < 6)
        return false;
    for (uint32_t i = 0; i < n; i++) {
        if (is_digit(p[i]))
            d++;
    }
    return d * 10 > n * 4;
}

/* Does this run of bytes look like a value rather than a name? The union of the
 * classifiers above plus the two blunt ones: all digits (any length — `/1` is an
 * id), and anything over 24 characters (a route element nobody typed).
 *
 * Control bytes make a segment opaque too, which is a privacy rule wearing a
 * classifier's clothes: it guarantees that no byte outside [0x20, 0x7f] ∪
 * high-UTF-8 can reach a label through this module, whatever the input. */
static bool seg_opaque(const char *p, uint32_t n)
{
    uint32_t digits = 0, hex = 0;

    if (!n)
        return false; /* an empty segment is `//` in the path: literal, kept */
    for (uint32_t i = 0; i < n; i++) {
        if (is_ctl(p[i]))
            return true;
        if (is_digit(p[i]))
            digits++;
        if (is_hex(p[i]))
            hex++;
    }
    if (digits == n)
        return true; /* a plain number */
    if (n > 24)
        return true; /* nobody names a handler this */
    if (hex == n && n >= 8)
        return true; /* a hash, a git sha, an object id */
    return looks_uuid(p, n) || looks_ulid(p, n) || looks_date(p, n) || looks_b64(p, n) ||
           looks_digit_heavy(p, n);
}

/* A dotted segment is classified component by component (`app.a83bf2ef.js`):
 * the extension decides the *shape* of the template and the stem decides
 * whether to template at all. Splitting on every dot rather than only the last
 * is what catches the build-hash-in-the-middle convention every bundler uses —
 * on the stem as a whole, `app.a83bf2ef` is only 25 % digits and would pass for
 * a literal, while its second component is an 8-character hex blob. */
static bool stem_opaque(const char *p, uint32_t n)
{
    uint32_t start = 0;

    for (uint32_t i = 0; i <= n; i++) {
        if (i == n || p[i] == '.') {
            if (seg_opaque(p + start, i - start))
                return true;
            start = i + 1;
        }
    }
    return false;
}

/* The extension of a file-shaped segment: the last dot, 1..8 alphanumerics with
 * at least one letter among them, and something in front of it. The letter is
 * what tells `report.csv` from `1.2.3` — every real extension has one, and
 * without the rule a semantic version would come back as `{file}.3`, which is
 * both wrong and unreadable. Anything that fails here is not a file name and
 * goes through the ordinary classifier whole. */
static bool split_ext(const char *p, uint32_t n, uint32_t *stem_len)
{
    uint32_t dot = 0;
    bool found = false, alpha = false;

    for (uint32_t i = 0; i < n; i++) {
        if (p[i] == '.') {
            dot = i;
            found = true;
        }
    }
    if (!found || dot == 0 || dot + 1 >= n || n - dot - 1 > 8)
        return false;
    for (uint32_t i = dot + 1; i < n; i++) {
        if (!is_alnum(p[i]))
            return false;
        alpha = alpha || is_alpha(p[i]);
    }
    if (!alpha)
        return false;
    *stem_len = dot;
    return true;
}

/* Emit one path segment, templated or not. Returns true when it collapsed. */
static bool put_segment(struct rctx *rx, const char *p, uint32_t n)
{
    uint32_t stem;

    if (split_ext(p, n, &stem)) {
        /* `{file}.js` keeps the one part of a generated file name that carries
         * information — a spike in `.js` next to a flat `.png` is a story, and
         * `{id}` for both would not tell it. */
        if (stem_opaque(p, stem)) {
            emit_cstr(rx, "{file}.");
            emit(rx, p + stem + 1, n - stem - 1);
            return true;
        }
        emit(rx, p, n);
        return false;
    }
    if (seg_opaque(p, n)) {
        emit_cstr(rx, "{id}");
        return true;
    }
    emit(rx, p, n);
    return false;
}

/* --- the explicit map (РH7 layer 1) --------------------------------------- */

struct route_pat {
    const char *method; /* NULL = `*`, any method */
    uint32_t method_len;
    const char *text; /* the pattern as written, the route label on a hit */
    uint32_t text_len;
    /* Segments of `text`, split on '/'; `var` marks a `{...}` placeholder. */
    struct {
        const char *p;
        uint16_t n;
        bool var;
    } seg[LK_ROUTE_SEG_MAX];
    uint8_t nseg;
};

struct lk_route_map {
    char *text; /* owned copy of the parsed buffer; patterns point into it */
    uint32_t npat;
    struct route_pat pat[];
};

/* Split a path into segments for matching. Returns the count, or > max when the
 * path is deeper than any pattern could be (the caller then skips the map). The
 * leading '/' introduces the first segment; a trailing one introduces a final
 * empty segment, so `/a` and `/a/` are different routes — which is what servers
 * do, and what a redirect between them is for. */
static uint32_t path_segments(const char *p, uint32_t n, const char **seg, uint16_t *seglen,
                              uint32_t max)
{
    uint32_t cnt = 0, i = 0;

    while (i < n) {
        uint32_t s;

        if (p[i] == '/')
            i++;
        s = i;
        while (i < n && p[i] != '/')
            i++;
        if (cnt < max) {
            seg[cnt] = p + s;
            seglen[cnt] = (uint16_t)(i - s);
        }
        cnt++;
    }
    return cnt;
}

static bool pat_matches(const struct route_pat *pat, const char *method, uint32_t method_len,
                        const char **seg, const uint16_t *seglen, uint32_t nseg)
{
    if (pat->nseg != nseg)
        return false;
    if (pat->method && (pat->method_len != method_len || memcmp(pat->method, method, method_len)))
        return false;
    for (uint32_t i = 0; i < nseg; i++) {
        if (pat->seg[i].var)
            continue;
        if (pat->seg[i].n != seglen[i] || memcmp(pat->seg[i].p, seg[i], seglen[i]))
            return false;
    }
    return true;
}

/* Fill in a pattern's segment table. false rejects the line: deeper than the
 * segment ceiling, or empty. Rejecting rather than truncating matters — half a
 * pattern would match paths its author never wrote. */
static bool pat_split(struct route_pat *pat)
{
    const char *p = pat->text;
    uint32_t n = pat->text_len, i = 0;

    pat->nseg = 0;
    while (i < n) {
        uint32_t s;

        if (p[i] == '/')
            i++;
        s = i;
        while (i < n && p[i] != '/')
            i++;
        if (pat->nseg >= LK_ROUTE_SEG_MAX)
            return false;
        pat->seg[pat->nseg].p = p + s;
        pat->seg[pat->nseg].n = (uint16_t)(i - s);
        pat->seg[pat->nseg].var = (i - s >= 2 && p[s] == '{' && p[i - 1] == '}');
        pat->nseg++;
    }
    return pat->nseg > 0;
}

struct lk_route_map *lk_route_map_parse(const char *text, size_t len, uint32_t *rejected)
{
    struct lk_route_map *m;
    uint32_t bad = 0, i = 0, lines = 1;

    if (rejected)
        *rejected = 0;
    if (!text || !len)
        return NULL;
    /* One pattern slot per line, capped: a pattern is ~400 bytes, so sizing the
     * array by the ceiling would mean a fixed 200 KB for a two-line map — and
     * this runs per input in the fuzzer as well as once at startup. */
    for (size_t k = 0; k < len; k++)
        lines += text[k] == '\n';
    if (lines > LK_ROUTE_MAP_MAX)
        lines = LK_ROUTE_MAP_MAX;
    m = calloc(1, sizeof(*m) + lines * sizeof(struct route_pat));
    if (!m)
        return NULL;
    m->text = malloc(len);
    if (!m->text) {
        free(m);
        return NULL;
    }
    memcpy(m->text, text, len);

    while (i < len) {
        struct route_pat *pat;
        uint32_t ls, le, ms, me, ps;
        bool ok = true;

        /* one line */
        ls = i;
        while (i < len && m->text[i] != '\n')
            i++;
        le = i;
        if (i < len)
            i++;
        if (le > ls && m->text[le - 1] == '\r')
            le--;
        while (ls < le && (m->text[ls] == ' ' || m->text[ls] == '\t'))
            ls++;
        while (le > ls && (m->text[le - 1] == ' ' || m->text[le - 1] == '\t'))
            le--;
        if (ls == le || m->text[ls] == '#')
            continue; /* blank or comment: not a rejection */

        /* method SP+ pattern */
        ms = ls;
        while (ls < le && m->text[ls] != ' ' && m->text[ls] != '\t')
            ls++;
        me = ls;
        while (ls < le && (m->text[ls] == ' ' || m->text[ls] == '\t'))
            ls++;
        ps = ls;
        if (me == ms || ps == le || m->text[ps] != '/') {
            bad++;
            continue;
        }
        /* A pattern is a *path* template. A '?' or '#' in it means the operator
         * wrote a query string or a fragment into the pattern, and neither is
         * ever matched against — the line could not fire, so it is reported as
         * rejected rather than silently kept. (It is also what keeps the "no
         * byte of the query reaches the template" invariant true for a map hit:
         * a '?' in the output can then only come from --http-query-keys.) */
        for (uint32_t k = ms; k < le && ok; k++)
            ok = !is_ctl(m->text[k]) && m->text[k] != '?' && m->text[k] != '#';
        if (!ok || le - ps >= LK_ROUTE_TEXT_MAX || m->npat >= lines) {
            bad++;
            continue;
        }

        pat = &m->pat[m->npat];
        pat->method = (me - ms == 1 && m->text[ms] == '*') ? NULL : m->text + ms;
        pat->method_len = me - ms;
        pat->text = m->text + ps;
        pat->text_len = le - ps;
        if (!pat_split(pat)) {
            bad++;
            continue;
        }
        m->npat++;
    }

    if (rejected)
        *rejected = bad;
    if (!m->npat) {
        lk_route_map_free(m);
        return NULL;
    }
    return m;
}

void lk_route_map_free(struct lk_route_map *m)
{
    if (!m)
        return;
    free(m->text);
    free(m);
}

uint32_t lk_route_map_count(const struct lk_route_map *m)
{
    return m ? m->npat : 0;
}

/* --- the query string (РH7, `--http-query-keys`) -------------------------- */

/* Find `key` in a `k=v&k2=v2` query. `*val` is the raw value (possibly empty);
 * a key present without `=` yields an empty value and a true return, because
 * `?debug` is as much a route as `?debug=1`. Keys are matched case-sensitively:
 * query keys are case-sensitive in every framework that reads them, and folding
 * case here would merge two parameters an application tells apart. */
static bool query_find(const char *q, uint32_t qn, const char *key, const char **val,
                       uint32_t *val_len)
{
    uint32_t klen = (uint32_t)strlen(key), i = 0;

    while (i < qn) {
        uint32_t s = i, eq;

        while (i < qn && q[i] != '&')
            i++;
        eq = s;
        while (eq < i && q[eq] != '=')
            eq++;
        if (eq - s == klen && !memcmp(q + s, key, klen)) {
            *val = q + (eq < i ? eq + 1 : i);
            *val_len = eq < i ? i - eq - 1 : 0;
            return true;
        }
        if (i < qn)
            i++; /* the '&' */
    }
    return false;
}

/* --- the entry points ----------------------------------------------------- */

static void route_start(struct rctx *rx, XXH3_state_t *xh, struct lk_route_out *out,
                        const char *method, uint32_t method_len)
{
    static const char nul = '\0';

    out->text_len = 0;
    out->flags = 0;
    out->fp = 0;
    rx->out = out;
    rx->xh = xh;
    XXH3_64bits_reset(xh);
    /* The method is hashed but never printed: the label set carries it in its
     * own dimension (РH9), so putting it in the template text too would only
     * make every route label longer. It is part of the *identity* all the same —
     * `GET /orders/{id}` and `DELETE /orders/{id}` are two routes. */
    XXH3_64bits_update(xh, method, method_len);
    XXH3_64bits_update(xh, &nul, 1);
}

static void route_finish(struct rctx *rx)
{
    rx->out->text[rx->out->text_len] = '\0';
    rx->out->fp = XXH3_64bits_digest(rx->xh);
}

void lk_norm_route(const char *method, uint32_t method_len, const char *target, uint32_t target_len,
                   const struct lk_route_cfg *cfg, struct lk_route_out *out)
{
    static const struct lk_route_cfg defaults = {0};
    XXH3_state_t xh; /* ~576 B, aligned by its own type — stack is fine */
    struct rctx rx;
    const char *path = target, *query = NULL;
    uint32_t path_len = 0, query_len = 0;
    uint32_t depth, nseg, i = 0, kept = 0;

    if (!cfg)
        cfg = &defaults;
    depth = cfg->depth ? cfg->depth : LK_ROUTE_DEPTH_DEF;
    if (depth > LK_ROUTE_DEPTH_MAX)
        depth = LK_ROUTE_DEPTH_MAX;
    if (!method)
        method_len = 0;
    if (!target)
        target_len = 0;

    /* The one split that has to happen here rather than in the caller: after it,
     * `query` is touched only through cfg->query_keys, which is what makes "the
     * query does not reach the template" checkable in one place (fuzz). */
    while (path_len < target_len && target[path_len] != '?')
        path_len++;
    if (path_len < target_len) {
        query = target + path_len + 1;
        query_len = target_len - path_len - 1;
    }

    route_start(&rx, &xh, out, method, method_len);

    /* Layer 1: the explicit map. Cheap to miss (a segment-count compare per
     * pattern) and exact when it hits. */
    if (cfg->map && path_len) {
        const char *seg[LK_ROUTE_SEG_MAX];
        uint16_t seglen[LK_ROUTE_SEG_MAX];

        nseg = path_segments(path, path_len, seg, seglen, LK_ROUTE_SEG_MAX);
        if (nseg <= LK_ROUTE_SEG_MAX) {
            for (uint32_t k = 0; k < cfg->map->npat; k++) {
                const struct route_pat *pat = &cfg->map->pat[k];

                if (pat_matches(pat, method, method_len, seg, seglen, nseg)) {
                    emit(&rx, pat->text, pat->text_len);
                    out->flags |= LK_ROUTE_F_FROM_MAP | LK_ROUTE_F_TEMPLATED;
                    goto query_keys;
                }
            }
        }
    }

    /* Layer 2: the heuristic. `*` (OPTIONS *) is a route in itself and the one
     * target with no path structure at all. */
    if (path_len == 1 && path[0] == '*') {
        emit(&rx, "*", 1);
        goto query_keys;
    }
    while (i < path_len) {
        uint32_t s;

        if (kept == depth) {
            /* Deeper than we agreed to look. The tail folds into one token
             * rather than being dropped silently: `/a/b/.../...` and `/a/b` are
             * different routes and the label says which is which. */
            emit_cstr(&rx, "/...");
            out->flags |= LK_ROUTE_F_DEPTH_CLIP | LK_ROUTE_F_TEMPLATED;
            break;
        }
        if (path[i] == '/') {
            emit(&rx, "/", 1);
            i++;
        }
        s = i;
        while (i < path_len && path[i] != '/')
            i++;
        if (put_segment(&rx, path + s, i - s))
            out->flags |= LK_ROUTE_F_TEMPLATED;
        kept++;
    }

query_keys:
    /* The query string is dropped whole except for the keys the operator named
     * — for the APIs where `?action=…` is the handler and the path is one
     * constant. The value goes through the same classifiers as a path segment,
     * so `?id=42` templates instead of forking the route per id. */
    for (uint32_t k = 0; k < cfg->nquery_keys && query_len; k++) {
        const char *key = cfg->query_keys[k], *val;
        uint32_t vlen;

        if (!key || !key[0] || !query_find(query, query_len, key, &val, &vlen))
            continue;
        emit(&rx, (out->flags & LK_ROUTE_F_QUERY) ? "&" : "?", 1);
        emit_cstr(&rx, key);
        emit(&rx, "=", 1);
        if (vlen > LK_ROUTE_QUERY_VAL_MAX || seg_opaque(val, vlen))
            emit_cstr(&rx, "{id}");
        else
            emit(&rx, val, vlen);
        out->flags |= LK_ROUTE_F_QUERY;
    }
    route_finish(&rx);
}

void lk_norm_route_given(const char *method, uint32_t method_len, const char *route,
                         uint32_t route_len, struct lk_route_out *out)
{
    XXH3_state_t xh;
    struct rctx rx;
    uint32_t s = 0;

    if (!method)
        method_len = 0;
    if (!route)
        route_len = 0;
    route_start(&rx, &xh, out, method, method_len);
    /* Trusted for its content, not for its bytes: control characters are
     * dropped (they would break the exposition format the label ends up in),
     * everything else travels as the application wrote it. Runs are emitted in
     * one call so the common case — no control bytes at all — is a single
     * memcpy. */
    for (uint32_t i = 0; i <= route_len; i++) {
        if (i == route_len || is_ctl(route[i])) {
            if (i > s)
                emit(&rx, route + s, i - s);
            s = i + 1;
        }
    }
    out->flags |= LK_ROUTE_F_GIVEN;
    route_finish(&rx);
}

/* --- fuzz entry ----------------------------------------------------------- */

/* Input layout: `method \n target` (the first newline splits; no newline means
 * the whole input is the target and the method is empty), with everything after
 * a second newline parsed as an `--http-routes` map. That gives the mutator a
 * single flat byte string that can reach all three layers, including a map whose
 * patterns are as hostile as the paths. */
int lk_norm_route_fuzz_one(const uint8_t *data, size_t n)
{
    static volatile uint64_t sink;
    struct lk_route_cfg cfg = {0};
    struct lk_route_out out;
    const char *s = (const char *)data;
    const char *nl, *nl2;
    uint32_t mlen = 0, tlen;
    uint64_t acc;

    if (!n) {
        lk_norm_route("GET", 3, NULL, 0, NULL, &out);
        return 0;
    }
    nl = memchr(s, '\n', n);
    if (nl) {
        mlen = (uint32_t)(nl - s);
        tlen = (uint32_t)(n - mlen - 1);
        nl2 = memchr(nl + 1, '\n', tlen);
        if (nl2) {
            size_t maplen = (size_t)(s + n - nl2 - 1);

            tlen = (uint32_t)(nl2 - nl - 1);
            cfg.map = lk_route_map_parse(nl2 + 1, maplen, NULL);
        }
        /* One query key, taken from the tail of the method token, so the mutator
         * can reach the query branch without a second input format. */
        if (mlen > 1) {
            static char key[LK_ROUTE_QUERY_KEY_MAX];
            uint32_t klen = mlen < sizeof(key) ? mlen : (uint32_t)sizeof(key) - 1;

            memcpy(key, s, klen);
            key[klen] = '\0';
            cfg.query_keys[0] = key;
            cfg.nquery_keys = 1;
        }
        lk_norm_route(s, mlen, nl + 1, tlen, &cfg, &out);
    } else {
        lk_norm_route("GET", 3, s, (uint32_t)n, &cfg, &out);
    }

    /* Touch every field so a sanitizer flags an OOB write into text[] or a
     * missing NUL terminator; the volatile store cannot be elided. */
    acc = out.fp ^ out.text_len ^ out.flags;
    for (uint32_t i = 0; i < out.text_len; i++)
        acc += (unsigned char)out.text[i];
    acc += (unsigned char)out.text[out.text_len];

    lk_norm_route_given(s, mlen, s, (uint32_t)n, &out);
    acc += out.fp ^ out.text_len;
    acc += (unsigned char)out.text[out.text_len];

    sink += acc;
    lk_route_map_free((struct lk_route_map *)cfg.map);
    return 0;
}
