// SPDX-License-Identifier: GPL-2.0
/* SQL normaliser + fingerprint (Р22, STAGE4.md task 4.1). See norm_sql.h for
 * the rule set and the contract; this file is the machine.
 *
 * Shape of the pipeline (all streaming, all O(1) state):
 *
 *     lexer  ->  f1 (?,?,... collapse)  ->  f2 ((?),(?),... collapse)
 *            ->  sink (trailing-; drop, text buffer + XXH3 hash)
 *
 * Each stage forwards tokens by value to the next. Tokens carry a kind (so the
 * collapse filters can match `( ? , )` structurally) plus the canonical text.
 * Only K_OTHER tokens (identifiers / operators) carry variable text; the
 * punctuation kinds the filters buffer — ( ) , ? ; — are single constant
 * characters, so the filters never need to store token text. That is what keeps
 * the whole thing zero-alloc with a fixed-size context on the stack. */
#include "norm_sql.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Header-only XXH3: XXH_INLINE_ALL pulls in the implementation (and the full
 * XXH3_state_t definition) as static functions in this one TU. */
#define XXH_INLINE_ALL
#include "xxhash.h"

/* --- token kinds ---------------------------------------------------------- */
enum tok_kind {
    K_OTHER = 0, /* identifier, keyword, quoted ident, operator run */
    K_LP,        /* (  */
    K_RP,        /* )  */
    K_COMMA,     /* ,  */
    K_PH,        /* ?  placeholder (literal / number / $N / bare ?) */
    K_SEMI,      /* ;  */
};

/* f2 group-detection state: how much of a `( ? )` group we have emitted. */
enum f2_grp { G0 = 0, G_LP, G_LPQ };

/* f2 repeat-match buffer: how much of a `, ( ? )` repeat we have consumed. */
enum f2_match { M_NONE = 0, M_COMMA, M_LP, M_QMARK };

struct norm_ctx {
    /* output / sink */
    struct lk_norm_out *out;
    XXH3_state_t *xh;
    uint32_t text_cap; /* LK_NORM_TEXT_MAX - 1, room for the NUL */
    bool first;        /* no token materialised yet (spacing) */
    uint32_t pending_semi;

    /* f1: collapse `? , ? , ...` -> `?` (only inside parens: a top-level list
     * like `select 1, 2` must stay distinct from `select 1`) */
    uint8_t f1_prev;   /* kind of the previous forwarded token */
    uint32_t f1_depth; /* open-paren nesting seen so far */
    bool f1_held_comma;

    /* f2: collapse `( ? ) , ( ? ) , ...` -> `( ? )` */
    uint8_t f2_grp;
    uint8_t f2_match;
    bool f2_have_group; /* the last emitted group was exactly `( ? )` */
};

/* --- sink: text buffer + streaming hash ----------------------------------- */

static void put_bytes(struct norm_ctx *nx, const char *s, uint32_t n)
{
    struct lk_norm_out *o = nx->out;

    for (uint32_t i = 0; i < n; i++) {
        if (o->text_len < nx->text_cap)
            o->text[o->text_len++] = s[i];
        else {
            o->trunc = true;
            return;
        }
    }
}

/* Materialise one token: space-join into the text buffer (clipping at the cap),
 * and feed the token bytes + a NUL separator into the hash regardless of
 * clipping — the fingerprint spans the whole input. `lower` lower-cases ASCII
 * on the fly (identifiers), chunked so an arbitrarily long token needs no
 * buffer of its own. */
static void out_token(struct norm_ctx *nx, bool lower, const char *text, uint32_t len)
{
    static const char nul = '\0';

    if (!nx->first)
        put_bytes(nx, " ", 1);
    nx->first = false;

    if (lower) {
        uint32_t i = 0;

        while (i < len) {
            char tmp[64];
            uint32_t n = 0;

            while (i < len && n < sizeof(tmp)) {
                char c = text[i++];

                tmp[n++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
            }
            XXH3_64bits_update(nx->xh, tmp, n);
            put_bytes(nx, tmp, n);
        }
    } else {
        XXH3_64bits_update(nx->xh, text, len);
        put_bytes(nx, text, len);
    }
    XXH3_64bits_update(nx->xh, &nul, 1);
}

static void sink_push(struct norm_ctx *nx, uint8_t kind, bool lower, const char *text, uint32_t len)
{
    if (kind == K_SEMI) {
        /* Hold semicolons: a trailing run is dropped at finish, an inner one is
         * flushed when a real token follows. */
        nx->pending_semi++;
        return;
    }
    while (nx->pending_semi > 0) {
        out_token(nx, false, ";", 1);
        nx->pending_semi--;
    }
    out_token(nx, lower, text, len);
}

/* --- f2: collapse `( ? ) , ( ? ) , ...` -> `( ? )` ------------------------ */

static void f2_emit(struct norm_ctx *nx, uint8_t kind, bool lower, const char *text, uint32_t len)
{
    switch (kind) {
    case K_LP:
        nx->f2_grp = G_LP;
        nx->f2_have_group = false;
        break;
    case K_PH:
        nx->f2_grp = (nx->f2_grp == G_LP) ? G_LPQ : G0;
        nx->f2_have_group = false;
        break;
    case K_RP:
        nx->f2_have_group = (nx->f2_grp == G_LPQ);
        nx->f2_grp = G0;
        break;
    default:
        nx->f2_grp = G0;
        nx->f2_have_group = false;
        break;
    }
    sink_push(nx, kind, lower, text, len);
}

/* Emit the `, ( ?` prefix buffered while trying to match a `, ( ? )` repeat,
 * when the match failed partway. */
static void f2_flush_match(struct norm_ctx *nx)
{
    uint8_t m = nx->f2_match;

    nx->f2_match = M_NONE;
    if (m >= M_COMMA)
        f2_emit(nx, K_COMMA, false, ",", 1);
    if (m >= M_LP)
        f2_emit(nx, K_LP, false, "(", 1);
    if (m >= M_QMARK)
        f2_emit(nx, K_PH, false, "?", 1);
}

static void f2_push(struct norm_ctx *nx, uint8_t kind, bool lower, const char *text, uint32_t len)
{
    if (nx->f2_match != M_NONE) {
        /* Mid-attempt at a `, ( ? )` repeat after a completed group. */
        switch (nx->f2_match) {
        case M_COMMA:
            if (kind == K_LP) {
                nx->f2_match = M_LP;
                return;
            }
            break;
        case M_LP:
            if (kind == K_PH) {
                nx->f2_match = M_QMARK;
                return;
            }
            break;
        case M_QMARK:
            if (kind == K_RP) {
                /* Full `, ( ? )` — drop it; f2_have_group stays true so the
                 * next comma keeps the run going. */
                nx->f2_match = M_NONE;
                return;
            }
            break;
        }
        f2_flush_match(nx); /* mismatch: emit what we buffered, then this token */
    }
    if (nx->f2_have_group && kind == K_COMMA) {
        nx->f2_match = M_COMMA;
        return;
    }
    f2_emit(nx, kind, lower, text, len);
}

static void f2_finish(struct norm_ctx *nx)
{
    if (nx->f2_match != M_NONE)
        f2_flush_match(nx);
}

/* --- f1: collapse `? , ? , ...` -> `?` ------------------------------------ */

static void f1_push(struct norm_ctx *nx, uint8_t kind, bool lower, const char *text, uint32_t len)
{
    if (nx->f1_held_comma) {
        if (kind == K_PH) {
            /* `? , ?` -> keep just the first `?`. */
            nx->f1_held_comma = false;
            nx->f1_prev = K_PH;
            return;
        }
        /* comma was not followed by `?` after all: let it through. */
        f2_push(nx, K_COMMA, false, ",", 1);
        nx->f1_held_comma = false;
        nx->f1_prev = K_COMMA;
    }
    if (kind == K_COMMA && nx->f1_prev == K_PH && nx->f1_depth > 0) {
        nx->f1_held_comma = true;
        return;
    }
    if (kind == K_LP)
        nx->f1_depth++;
    else if (kind == K_RP && nx->f1_depth > 0)
        nx->f1_depth--;
    f2_push(nx, kind, lower, text, len);
    nx->f1_prev = kind;
}

static void f1_finish(struct norm_ctx *nx)
{
    if (nx->f1_held_comma) {
        f2_push(nx, K_COMMA, false, ",", 1);
        nx->f1_held_comma = false;
    }
}

/* Lexer -> pipeline entry. */
static void emit(struct norm_ctx *nx, uint8_t kind, bool lower, const char *text, uint32_t len)
{
    f1_push(nx, kind, lower, text, len);
}

/* --- character classes ---------------------------------------------------- */

static bool is_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

static bool is_digit(unsigned char c)
{
    return c >= '0' && c <= '9';
}

static bool is_alpha(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/* Identifier start: letter, underscore, or any high byte (PG allows non-ASCII
 * letters; we treat every >=0x80 byte as identifier material). */
static bool is_ident_start(unsigned char c)
{
    return is_alpha(c) || c == '_' || c >= 0x80;
}

static bool is_ident_cont(unsigned char c)
{
    return is_ident_start(c) || is_digit(c) || c == '$';
}

/* PG operator characters. `?` is deliberately excluded (handled as a
 * placeholder so JDBC `?` merges with `$N`); `-` and `/` are here but the
 * scanner below stops an operator run before a `--` or block-comment opener. */
static bool is_op_char(unsigned char c)
{
    switch (c) {
    case '+':
    case '-':
    case '*':
    case '/':
    case '<':
    case '>':
    case '=':
    case '~':
    case '!':
    case '@':
    case '#':
    case '%':
    case '^':
    case '&':
    case '|':
    case '`':
    case ':':
        return true;
    default:
        return false;
    }
}

/* --- the lexer ------------------------------------------------------------ */

void lk_norm_sql(const char *sql, size_t len, struct lk_norm_out *out)
{
    XXH3_state_t xh; /* ~576 B, 64-byte aligned by its own type — stack is fine */
    struct norm_ctx nx = {
        .out = out,
        .xh = &xh,
        .text_cap = LK_NORM_TEXT_MAX - 1,
        .first = true,
        .f1_prev = K_OTHER,
    };
    const unsigned char *p = (const unsigned char *)sql;
    const unsigned char *const end = p + len;

    out->text_len = 0;
    out->trunc = false;
    out->fp = 0;
    XXH3_64bits_reset(&xh);

    while (p < end) {
        unsigned char c = *p;

        /* whitespace */
        if (is_space(c)) {
            p++;
            continue;
        }

        /* line comment -- ... \n */
        if (c == '-' && p + 1 < end && p[1] == '-') {
            p += 2;
            while (p < end && *p != '\n')
                p++;
            continue;
        }

        /* block comment, nested (PG nests them) */
        if (c == '/' && p + 1 < end && p[1] == '*') {
            int depth = 1;

            p += 2;
            while (p < end && depth > 0) {
                if (p + 1 < end && p[0] == '/' && p[1] == '*') {
                    depth++;
                    p += 2;
                } else if (p + 1 < end && p[0] == '*' && p[1] == '/') {
                    depth--;
                    p += 2;
                } else {
                    p++;
                }
            }
            if (depth > 0)
                out->trunc = true; /* unterminated: ran off the captured prefix */
            continue;
        }

        /* string literals -> ? */
        {
            bool is_estr = (c == 'e' || c == 'E') && p + 1 < end && p[1] == '\'';
            bool is_pref =
                (c == 'b' || c == 'B' || c == 'x' || c == 'X') && p + 1 < end && p[1] == '\'';

            if (c == '\'' || is_estr || is_pref) {
                bool backslash = is_estr; /* only E'' honours backslash escapes */

                p += (c == '\'') ? 1 : 2; /* skip opening quote (and prefix) */
                while (p < end) {
                    if (backslash && *p == '\\') {
                        p += (p + 1 < end) ? 2 : 1; /* escape: skip next byte */
                        continue;
                    }
                    if (*p == '\'') {
                        if (p + 1 < end && p[1] == '\'') { /* '' -> literal quote */
                            p += 2;
                            continue;
                        }
                        p++; /* closing quote */
                        break;
                    }
                    p++;
                }
                if (p >= end)
                    out->trunc = true; /* unterminated literal */
                emit(&nx, K_PH, false, "?", 1);
                continue;
            }
        }

        /* quoted identifier "..." -> verbatim (case significant) */
        if (c == '"') {
            const char *start = (const char *)p;

            p++;
            while (p < end) {
                if (*p == '"') {
                    if (p + 1 < end && p[1] == '"') { /* "" -> literal quote */
                        p += 2;
                        continue;
                    }
                    p++; /* closing quote */
                    break;
                }
                p++;
            }
            if (p >= end)
                out->trunc = true;
            emit(&nx, K_OTHER, false, start, (uint32_t)((const char *)p - start));
            continue;
        }

        /* dollar: parameter $N, or dollar-quoted string $tag$...$tag$ */
        if (c == '$') {
            unsigned char nxt = (p + 1 < end) ? p[1] : 0;

            if (is_digit(nxt)) { /* $1, $2, ... -> ? */
                p += 2;
                while (p < end && is_digit(*p))
                    p++;
                emit(&nx, K_PH, false, "?", 1);
                continue;
            }
            if (nxt == '$' || is_ident_start(nxt)) {
                /* scan a tag: letters/digits/_ up to the closing $ */
                const unsigned char *t = p + 1;

                while (t < end && (is_ident_cont(*t) && *t != '$'))
                    t++;
                if (t < end && *t == '$') {
                    /* valid open delimiter $tag$ = [p .. t] inclusive */
                    uint32_t dlen = (uint32_t)(t - p) + 1;
                    const unsigned char *body = t + 1;
                    const unsigned char *q = body;
                    bool closed = false;

                    while (q + dlen <= end) {
                        if (q[0] == '$' && memcmp(q, p, dlen) == 0) {
                            q += dlen;
                            closed = true;
                            break;
                        }
                        q++;
                    }
                    p = closed ? q : end;
                    if (!closed)
                        out->trunc = true;
                    emit(&nx, K_PH, false, "?", 1);
                    continue;
                }
            }
            /* a lone $ that opens nothing: emit it as a plain token */
            emit(&nx, K_OTHER, false, "$", 1);
            p++;
            continue;
        }

        /* numbers -> ? (integer, decimal, exponent, 0x/0o/0b, 1_000) */
        if (is_digit(c) || (c == '.' && p + 1 < end && is_digit(p[1]))) {
            p++;
            if (c == '0' && p < end &&
                (*p == 'x' || *p == 'X' || *p == 'o' || *p == 'O' || *p == 'b' || *p == 'B')) {
                p++; /* radix prefix; consume the alnum/underscore run */
                while (p < end && (is_ident_cont(*p) && *p != '$'))
                    p++;
            } else {
                while (p < end && (is_digit(*p) || *p == '_'))
                    p++;
                if (p < end && *p == '.') {
                    p++;
                    while (p < end && (is_digit(*p) || *p == '_'))
                        p++;
                }
                if (p < end && (*p == 'e' || *p == 'E')) {
                    const unsigned char *e = p + 1;

                    if (e < end && (*e == '+' || *e == '-'))
                        e++;
                    if (e < end && is_digit(*e)) { /* exponent only if digits follow */
                        p = e + 1;
                        while (p < end && (is_digit(*p) || *p == '_'))
                            p++;
                    }
                }
            }
            emit(&nx, K_PH, false, "?", 1);
            continue;
        }

        /* unquoted identifier / keyword -> lower-cased */
        if (is_ident_start(c)) {
            const char *start = (const char *)p;

            p++;
            while (p < end && is_ident_cont(*p))
                p++;
            emit(&nx, K_OTHER, true, start, (uint32_t)((const char *)p - start));
            continue;
        }

        /* structural punctuation */
        if (c == '(') {
            emit(&nx, K_LP, false, "(", 1);
            p++;
            continue;
        }
        if (c == ')') {
            emit(&nx, K_RP, false, ")", 1);
            p++;
            continue;
        }
        if (c == ',') {
            emit(&nx, K_COMMA, false, ",", 1);
            p++;
            continue;
        }
        if (c == ';') {
            emit(&nx, K_SEMI, false, ";", 1);
            p++;
            continue;
        }
        if (c == '?') { /* bare placeholder (JDBC-style) */
            emit(&nx, K_PH, false, "?", 1);
            p++;
            continue;
        }

        /* operator run (stops before a comment opener) */
        if (is_op_char(c)) {
            const char *start = (const char *)p;

            p++;
            while (p < end && is_op_char(*p)) {
                if (*p == '-' && p + 1 < end && p[1] == '-')
                    break;
                if (*p == '/' && p + 1 < end && p[1] == '*')
                    break;
                p++;
            }
            emit(&nx, K_OTHER, false, start, (uint32_t)((const char *)p - start));
            continue;
        }

        /* anything else (. [ ] { } \ etc.): one verbatim token */
        {
            const char *start = (const char *)p;

            p++;
            emit(&nx, K_OTHER, false, start, 1);
        }
    }

    /* drain the pipeline: held comma -> f2, buffered match -> sink, trailing ;
     * dropped, then finalise text + fingerprint. */
    f1_finish(&nx);
    f2_finish(&nx);

    out->text[out->text_len] = '\0';
    out->fp = XXH3_64bits_digest(&xh);
}

/* --- fuzz entry ----------------------------------------------------------- */

int lk_norm_fuzz_one(const uint8_t *data, size_t n)
{
    static volatile uint64_t sink;
    struct lk_norm_out out;
    uint64_t acc;

    lk_norm_sql((const char *)data, n, &out);

    /* Touch every field so a sanitizer flags an OOB write into text[] or a
     * missing NUL terminator; the compiler cannot elide the volatile store. */
    acc = out.fp ^ out.text_len ^ out.trunc;
    for (uint32_t i = 0; i < out.text_len; i++)
        acc += (unsigned char)out.text[i];
    acc += (unsigned char)out.text[out.text_len]; /* the terminator */
    sink += acc;
    return 0;
}
