// SPDX-License-Identifier: GPL-2.0
/* See norm_redact.h. One pass over the target, no allocation, no state. */
#include "norm_redact.h"

/* The names that make a query key sensitive, matched as case-insensitive
 * substrings (see the header for why substrings). Kept short on purpose: this is
 * the list from РH12, and every entry is a rule someone has to be able to
 * predict. `access_token` and `signature` are absent because `token` and `sig`
 * already cover them — a redundant entry would only suggest the matching is
 * exact, which is the one thing to get wrong here. */
static const char *const secret_keys[] = {
    "token",    /* access_token, csrftoken, X-Amz-Security-Token, id_token */
    "sig",      /* signature, X-Amz-Signature, sig */
    "password", /* password, passwd is *not* covered — see below */
    "passwd",   /* ... so it is spelled out */
    "secret",   /* client_secret */
    "key",      /* api_key, apikey, private_key */
    "code",     /* the OAuth authorization code, exchangeable for a token */
    "auth",     /* auth, authorization, oauth_token */
};

static char lc(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

/* Case-insensitive "does the span contain this NUL-terminated needle". Bounded
 * by construction: the outer loop stops where the needle would run past the
 * span's end, so no comparison reads outside (p, n). */
static bool span_contains_ci(const char *p, uint32_t n, const char *needle)
{
    uint32_t m = 0;

    while (needle[m])
        m++;
    if (!m || m > n)
        return false;
    for (uint32_t i = 0; i + m <= n; i++) {
        uint32_t j = 0;

        while (j < m && lc(p[i + j]) == needle[j])
            j++;
        if (j == m)
            return true;
    }
    return false;
}

static bool key_is_secret(const char *p, uint32_t n)
{
    for (unsigned i = 0; i < sizeof(secret_keys) / sizeof(secret_keys[0]); i++)
        if (span_contains_ci(p, n, secret_keys[i]))
            return true;
    return false;
}

/* Both entry points walk the query the same way, so the walk lives here once and
 * the two differ only in what they do with a pair. `&` and `;` both separate:
 * the semicolon form is legacy (and deprecated), but servers that still accept
 * it would otherwise hide a whole credential behind one character. */
static bool is_sep(char c)
{
    return c == '&' || c == ';';
}

bool lk_url_redact_needed(const char *in, uint32_t n)
{
    uint32_t i = 0;

    if (!in)
        return false;
    while (i < n && in[i] != '?')
        i++;
    if (i >= n)
        return false; /* no query string: the common case, and it is free */
    i++;
    while (i < n) {
        uint32_t ks = i, ke;

        while (i < n && in[i] != '=' && !is_sep(in[i]))
            i++;
        ke = i;
        if (i < n && in[i] == '=') {
            /* A key with no value has nothing to hide, so the '=' is what makes
             * this worth reporting — `?token` alone is not a leak. */
            if (key_is_secret(in + ks, ke - ks))
                return true;
            while (i < n && !is_sep(in[i]))
                i++;
        }
        if (i < n)
            i++; /* the separator */
    }
    return false;
}

void lk_url_redact_inplace(char *p, uint32_t n)
{
    uint32_t i = 0;

    if (!p)
        return;
    while (i < n && p[i] != '?')
        i++;
    if (i >= n)
        return;
    i++;
    while (i < n) {
        uint32_t ks = i, ke;

        while (i < n && p[i] != '=' && !is_sep(p[i]))
            i++;
        ke = i;
        if (i < n && p[i] == '=') {
            bool secret = key_is_secret(p + ks, ke - ks);

            i++;
            while (i < n && !is_sep(p[i])) {
                if (secret)
                    p[i] = '*';
                i++;
            }
        }
        if (i < n)
            i++;
    }
}

/* Bounded append: everything written goes through here, so the outcap check
 * exists in exactly one place and a clip is a short result rather than a stray
 * byte past the caller's buffer. */
static void put(char *out, uint32_t outcap, uint32_t *w, const char *p, uint32_t n)
{
    for (uint32_t i = 0; i < n && *w < outcap; i++)
        out[(*w)++] = p[i];
}

uint32_t lk_url_redact(const char *in, uint32_t n, char *out, uint32_t outcap)
{
    uint32_t i = 0, w = 0;

    if (!in || !out || !outcap)
        return 0;
    while (i < n && in[i] != '?')
        i++;
    put(out, outcap, &w, in, i); /* the path, always verbatim */
    if (i >= n)
        return w;
    put(out, outcap, &w, "?", 1);
    i++;

    while (i < n) {
        uint32_t ks = i, ke, vs, ve;

        while (i < n && in[i] != '=' && !is_sep(in[i]))
            i++;
        ke = i;
        put(out, outcap, &w, in + ks, ke - ks);
        if (i < n && in[i] == '=') {
            put(out, outcap, &w, "=", 1);
            i++;
            vs = i;
            while (i < n && !is_sep(in[i]))
                i++;
            ve = i;
            if (key_is_secret(in + ks, ke - ks))
                put(out, outcap, &w, LK_REDACT_MARK, LK_REDACT_MARK_LEN);
            else
                put(out, outcap, &w, in + vs, ve - vs);
        }
        if (i < n) {
            put(out, outcap, &w, in + i, 1); /* the separator, as it was written */
            i++;
        }
    }
    return w;
}
