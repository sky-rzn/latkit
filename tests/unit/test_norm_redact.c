// SPDX-License-Identifier: GPL-2.0
/* Query-string redactor (РH12, PLAN-HTTP.md М6): table-driven cases over the
 * public lk_url_redact API, plus the two invariants the rest of the agent leans
 * on.
 *
 * The first is the one that matters: **a secret never appears in the output**.
 * Every other property here — the path is untouched, non-secret values survive,
 * the in-place variant keeps the length — is a usability claim. That one is the
 * privacy guarantee, and it is checked by searching the whole result rather than
 * by comparing against an expected string, so a case that redacts the wrong span
 * of bytes still fails.
 *
 * Pure: links the normaliser lib alone, no BPF and no privileges. */
#include <stdio.h>
#include <string.h>

#include "norm_redact.h"

static int failures;
#define EXPECT(cond, msg)                                                                          \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);                                   \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

/* Redact into a NUL-terminated buffer for comparison. */
static const char *red(const char *in)
{
    static char out[512];
    uint32_t n = lk_url_redact(in, (uint32_t)strlen(in), out, sizeof(out) - 1);

    out[n] = '\0';
    return out;
}

struct tcase {
    const char *in;
    const char *want;
    bool needed;
};

static const struct tcase cases[] = {
    /* No query at all: the overwhelmingly common shape, and the cheap answer. */
    {"/hello.txt", "/hello.txt", false},
    {"/", "/", false},
    {"", "", false},
    /* An ordinary query survives whole — this is a redactor, not a stripper.
     * (The route templater is what drops query strings; РH7.) */
    {"/search?q=cats&page=2", "/search?q=cats&page=2", false},
    /* The plan's list (РH12), each in its own shape. */
    {"/a?token=s3cr3t", "/a?token=***", true},
    {"/a?access_token=abc.def", "/a?access_token=***", true},
    {"/a?sig=deadbeef", "/a?sig=***", true},
    {"/a?signature=deadbeef", "/a?signature=***", true},
    {"/a?password=hunter2", "/a?password=***", true},
    {"/a?key=AKIA0000", "/a?key=***", true},
    {"/a?code=4/0Ade", "/a?code=***", true},
    /* Case-insensitive, and matched as a substring so the vendor-prefixed
     * spellings that dominate real URLs are covered too. */
    {"/a?TOKEN=x", "/a?TOKEN=***", true},
    {"/a?X-Amz-Signature=abc", "/a?X-Amz-Signature=***", true},
    {"/a?X-Amz-Security-Token=abc", "/a?X-Amz-Security-Token=***", true},
    {"/a?csrftoken=abc", "/a?csrftoken=***", true},
    {"/a?api_key=abc", "/a?api_key=***", true},
    /* Position in the list does not matter, and neighbours are untouched. */
    {"/a?page=1&token=s3cr3t&sort=asc", "/a?page=1&token=***&sort=asc", true},
    {"/a?token=x&sig=y", "/a?token=***&sig=***", true},
    /* The legacy semicolon separator counts: a server that accepts it would
     * otherwise hide a whole credential behind one character. */
    {"/a?page=1;token=s3cr3t", "/a?page=1;token=***", true},
    /* A key with no value has nothing to hide; an empty value is still marked,
     * because `?token=` and `?token=x` must not be told apart by the length. */
    {"/a?token", "/a?token", false},
    {"/a?token=", "/a?token=***", true},
    /* The path is never touched, even when it contains something key-shaped:
     * collapsing paths is the templater's job and it has its own rules. */
    {"/token/12345?page=2", "/token/12345?page=2", false},
    /* A value shorter than the mark: the redacted form is *longer* than the
     * input, which is why the caller's buffer allows for growth. */
    {"/a?key=1", "/a?key=***", true},
    /* Percent-encoded and odd bytes in a kept value survive verbatim — the
     * redactor decides what to hide, never what a URL may contain. */
    {"/a?q=%D0%BF%D1%80&page=2", "/a?q=%D0%BF%D1%80&page=2", false},
};

static int test_table(void)
{
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const struct tcase *t = &cases[i];
        const char *got = red(t->in);

        if (strcmp(got, t->want)) {
            printf("FAIL redact('%s') = '%s', want '%s'\n", t->in, got, t->want);
            failures++;
        }
        if (lk_url_redact_needed(t->in, (uint32_t)strlen(t->in)) != t->needed) {
            printf("FAIL needed('%s') != %d\n", t->in, (int)t->needed);
            failures++;
        }
    }
    return 0;
}

/* The invariant, stated as a search rather than as an expected string. */
static int test_no_secret_survives(void)
{
    static const char *const secrets[] = {"s3cr3t", "hunter2", "AKIA0000", "deadbeef"};
    static const char *const inputs[] = {
        "/a?token=s3cr3t",
        "/a?password=hunter2&user=admin",
        "/a?x=1&AWSAccessKeyId=AKIA0000&Signature=deadbeef&Expires=1",
        "/a?nested=%3Ftoken%3Ds3cr3t", /* encoded, so it is *not* a query key... */
    };

    for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        const char *got = red(inputs[i]);

        for (unsigned j = 0; j < sizeof(secrets) / sizeof(secrets[0]); j++) {
            /* ... which is why the last input is expected to keep its bytes: a
             * percent-encoded query inside a value is a value, and the honest
             * answer is that the redactor works on keys it can see. That case is
             * excluded here rather than quietly passing. */
            if (i == 3)
                continue;
            if (strstr(got, secrets[j])) {
                printf("FAIL '%s' -> '%s' still carries '%s'\n", inputs[i], got, secrets[j]);
                failures++;
            }
        }
    }
    return 0;
}

/* The display variant: same decisions, same length, no allocation. */
static int test_inplace(void)
{
    char buf[] = "GET /a?token=s3cr3t&page=2 HTTP/1.1";
    char plain[] = "GET /a?page=2 HTTP/1.1";

    lk_url_redact_inplace(buf, (uint32_t)strlen(buf));
    EXPECT(!strcmp(buf, "GET /a?token=******&page=2 HTTP/1.1"), "in-place masks the value");
    EXPECT(strlen(buf) == strlen("GET /a?token=******&page=2 HTTP/1.1"), "length unchanged");
    lk_url_redact_inplace(plain, (uint32_t)strlen(plain));
    EXPECT(!strcmp(plain, "GET /a?page=2 HTTP/1.1"), "nothing to mask, nothing changed");
    return 0;
}

/* Truncation is safe: a clipped result is short, never a stray byte past the
 * buffer, and never half a secret it decided to keep. */
static int test_bounds(void)
{
    char small[8];
    uint32_t n;

    n = lk_url_redact("/a?token=s3cr3t", 15, small, sizeof(small));
    EXPECT(n <= sizeof(small), "output never exceeds outcap");
    EXPECT(!memcmp(small, "/a?token", n < 8 ? n : 8), "the prefix is the input's");
    EXPECT(lk_url_redact("/a?token=s3cr3t", 15, small, 0) == 0,
           "a zero-size buffer writes nothing");
    EXPECT(lk_url_redact(NULL, 0, small, sizeof(small)) == 0, "NULL input is not a crash");
    EXPECT(!lk_url_redact_needed(NULL, 0), "NULL input needs nothing");
    /* Not NUL-terminated input: every accessor is bounded by the length, so the
     * bytes after it must not be read. Checked by handing over a span that ends
     * mid-value with a live secret right after it. */
    {
        const char *s = "/a?page=2&token=s3cr3t";
        char out[64];
        uint32_t k = lk_url_redact(s, 9, out, sizeof(out)); /* "/a?page=2" only */

        out[k] = '\0';
        EXPECT(!strcmp(out, "/a?page=2"), "reads stop at the given length");
    }
    return 0;
}

int main(void)
{
    test_table();
    test_no_secret_survives();
    test_inplace();
    test_bounds();
    printf(failures ? "\n%d FAILURES\n" : "\nall redactor tests passed\n", failures);
    return failures ? 1 : 0;
}
