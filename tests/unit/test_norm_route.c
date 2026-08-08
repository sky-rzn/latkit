// SPDX-License-Identifier: GPL-2.0
/* Table-driven tests for the HTTP route templater (РH7, PLAN-HTTP.md М4).
 * Drives the public lk_norm_route / lk_norm_route_given / lk_route_map_* over
 * hand-written cases and checks:
 *
 *   - the segment classifiers, one case per rule and one counter-case per rule
 *     (numbers, UUID, ULID, hex, dates, overlong, digit-heavy, base64-ish) —
 *     including the ones that must NOT template, because a heuristic that eats
 *     `/api/v1/users` is worse than none;
 *   - file names: `{file}.ext` for a generated stem, verbatim for `index.html`;
 *   - depth clipping, empty segments, trailing slashes, `%`-encoding, `..`,
 *     Cyrillic paths, control bytes (which must never reach the label);
 *   - the query string: dropped whole by default — asserted as a *byte*
 *     property, not just a text compare — and promoted key by key when
 *     `--http-query-keys` asks;
 *   - the explicit map: matching, `*` methods, first-match-wins, rejected lines,
 *     and that a map hit beats the heuristic;
 *   - identity: the method is part of the fingerprint, a clipped label still
 *     carries a distinct fingerprint, and the hash is a pure function of the
 *     input;
 *   - the quality invariant the plan asks for (РH7, risk 1): a million random
 *     paths from a generator that imitates real traffic must collapse into a
 *     *bounded* number of templates. That number is pinned here — if a change
 *     to the classifiers makes the heuristic leakier, this test says by how
 *     much before a dashboard does. */
#include <stdio.h>
#include <string.h>

#include "norm_route.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static struct lk_route_out route_cfg(const char *method, const char *target,
                                     const struct lk_route_cfg *cfg)
{
    struct lk_route_out o;

    lk_norm_route(method, (uint32_t)strlen(method), target, (uint32_t)strlen(target), cfg, &o);
    return o;
}

static struct lk_route_out route(const char *target)
{
    return route_cfg("GET", target, NULL);
}

static const char *rt(const char *target)
{
    static char buf[LK_ROUTE_TEXT_MAX];

    memcpy(buf, route(target).text, sizeof(buf));
    return buf;
}

/* --- the segment classifiers ---------------------------------------------- */

static int test_segments(void)
{
    static const struct {
        const char *path;
        const char *want;
    } cases[] = {
        /* the base shapes */
        {"/", "/"},
        {"/hello", "/hello"},
        {"/orders/42", "/orders/{id}"},
        {"/orders/42/items/7", "/orders/{id}/items/{id}"},
        {"/1", "/{id}"},
        /* the version segment every REST API has: 50 % digits, must survive */
        {"/api/v1/users", "/api/v1/users"},
        {"/api/v2beta/users", "/api/v2beta/users"},
        /* UUID, both cases; ULID; a git-sha-shaped hex; a date */
        {"/u/3f2504e0-4f89-11d3-9a0c-0305e82c3301", "/u/{id}"},
        {"/u/3F2504E0-4F89-11D3-9A0C-0305E82C3301", "/u/{id}"},
        {"/e/01ARZ3NDEKTSV4RRFFQ69G5FAV", "/e/{id}"},
        {"/commit/a83bf2ef", "/commit/{id}"},
        {"/commit/9c2f1b3a4d5e6f70", "/commit/{id}"},
        {"/logs/2024-01-02", "/logs/{id}"},
        /* below the hex floor (8): a short hex run is judged by the ordinary
         * rules, so `a83bf2e` still templates (43 % digits) while a hex-looking
         * *word* does not — the floor buys `/commit/decade` and `/x/beef`, not
         * an exemption for anything that could be a hash */
        {"/commit/a83bf2e", "/commit/{id}"},
        {"/commit/decade", "/commit/decade"},
        {"/x/beef", "/x/beef"},
        /* overlong, digit-heavy, base64-ish */
        {"/x/thisisaveryverylongsegmentindeed", "/x/{id}"},
        {"/x/2024q1", "/x/{id}"},
        {"/x/user1234", "/x/{id}"},
        {"/x/aGVsbG8gd29ybGQx", "/x/{id}"},
        /* ... and the words that must not trip those rules */
        {"/x/dashboard", "/x/dashboard"},
        {"/x/quarterly", "/x/quarterly"},
        {"/x/AUTHENTICATION", "/x/AUTHENTICATION"},
        {"/settings/notifications", "/settings/notifications"},
        /* a slug: the documented miss of the heuristic (РH7 — layer 1 is the fix) */
        {"/posts/why-we-left-the-cloud", "/posts/why-we-left-the-cloud"},
        /* file names */
        {"/static/app.a83bf2ef.js", "/static/{file}.js"},
        {"/static/index.html", "/static/index.html"},
        {"/static/logo.2x.png", "/static/logo.2x.png"},
        {"/dl/1234.json", "/dl/{file}.json"},
        {"/dl/report.2024-01-02.csv", "/dl/{file}.csv"},
        /* not an extension: too long, not alphanumeric, nothing in front */
        {"/x/name.extension1", "/x/name.extension1"},
        {"/x/1.2.3", "/x/1.2.3"},
        {"/x/.hidden", "/x/.hidden"},
        /* structure that has to survive: empty segments, trailing slash */
        {"/a//b", "/a//b"},
        {"/a/", "/a/"},
        {"/a/b/", "/a/b/"},
        /* percent-encoding is never decoded: two spellings of one path are two
         * routes, which is honest — decoding would invent an identity the
         * server may not agree with */
        {"/x/%2E%2E", "/x/%2E%2E"},
        {"/x/..", "/x/.."},
        {"/%D0%BA%D0%B0%D1%82%D0%B0%D0%BB%D0%BE%D0%B3", "/{id}"}, /* 30 chars: overlong */
        /* raw UTF-8 stays a literal — 16 bytes of Cyrillic is a route name */
        {"/\xd0\xba\xd0\xb0\xd1\x82\xd0\xb0\xd0\xbb\xd0\xbe\xd0\xb3", "/\xd0\xba\xd0\xb0\xd1\x82"
                                                                      "\xd0\xb0\xd0\xbb\xd0\xbe"
                                                                      "\xd0\xb3"},
        /* asterisk-form (OPTIONS *) is a route in itself */
        {"*", "*"},
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct lk_route_out o = route(cases[i].path);

        if (strcmp(o.text, cases[i].want)) {
            fprintf(stderr, "FAIL %s:%d: '%s' -> '%s', want '%s'\n", __FILE__, __LINE__,
                    cases[i].path, o.text, cases[i].want);
            return 1;
        }
        CHECK(o.text_len == strlen(o.text));
    }
    return 0;
}

static int test_flags(void)
{
    CHECK(!(route("/hello").flags & LK_ROUTE_F_TEMPLATED));
    CHECK(route("/orders/42").flags & LK_ROUTE_F_TEMPLATED);
    CHECK(!(route("/orders/42").flags & (LK_ROUTE_F_FROM_MAP | LK_ROUTE_F_GIVEN)));
    CHECK(!(route("/a/b/c").flags & LK_ROUTE_F_DEPTH_CLIP));
    return 0;
}

/* Control bytes are a privacy rule wearing a classifier's clothes: whatever the
 * input, the template must not carry a byte that a Prometheus label or an OTLP
 * attribute would choke on. */
static int test_control_bytes(void)
{
    struct lk_route_out o;
    static const char path[] = "/a/b\tc\n/d";

    lk_norm_route("GET", 3, path, sizeof(path) - 1, NULL, &o);
    for (uint32_t i = 0; i < o.text_len; i++)
        CHECK((unsigned char)o.text[i] >= 0x20 && (unsigned char)o.text[i] != 0x7f);
    CHECK(!strcmp(o.text, "/a/{id}/d"));

    /* NUL inside the path: a length-counted input, so it must not end the walk */
    lk_norm_route("GET", 3, "/a/b\0c/d", 8, NULL, &o);
    CHECK(!strcmp(o.text, "/a/{id}/d"));
    return 0;
}

static int test_depth(void)
{
    struct lk_route_cfg cfg = {.depth = 3};
    struct lk_route_out o = route_cfg("GET", "/a/b/c/d/e", &cfg);

    CHECK(!strcmp(o.text, "/a/b/c/..."));
    CHECK(o.flags & LK_ROUTE_F_DEPTH_CLIP);
    /* exactly at the limit: no tail, no flag */
    o = route_cfg("GET", "/a/b/c", &cfg);
    CHECK(!strcmp(o.text, "/a/b/c"));
    CHECK(!(o.flags & LK_ROUTE_F_DEPTH_CLIP));
    /* the default depth is 8 */
    CHECK(!strcmp(rt("/1/2/3/4/5/6/7/8/9"), "/{id}/{id}/{id}/{id}/{id}/{id}/{id}/{id}/..."));
    /* an out-of-range depth clamps rather than reading off the end */
    cfg.depth = 200;
    CHECK(!strcmp(route_cfg("GET", "/a/b/c/d/e", &cfg).text, "/a/b/c/d/e"));
    return 0;
}

/* --- the query string ------------------------------------------------------ */

static int test_query(void)
{
    struct lk_route_cfg cfg = {0};
    struct lk_route_out o;

    /* dropped whole by default */
    CHECK(!strcmp(rt("/search?q=secret&token=abc"), "/search"));
    CHECK(!(route("/search?q=secret").flags & LK_ROUTE_F_QUERY));

    /* ... and the byte-level version of the same claim, which is the invariant
     * the fuzzer checks: no byte of the query reaches the template. */
    o = route("/x/a?needle=NEEDLE");
    CHECK(!memmem(o.text, o.text_len, "NEEDLE", 6));

    /* promoted keys, in the configured order regardless of wire order */
    cfg.query_keys[0] = "action";
    cfg.query_keys[1] = "sub";
    cfg.nquery_keys = 2;
    o = route_cfg("GET", "/api?sub=list&action=Describe&secret=x", &cfg);
    CHECK(!strcmp(o.text, "/api?action=Describe&sub=list"));
    CHECK(o.flags & LK_ROUTE_F_QUERY);
    /* a promoted value is classified like a segment: an id stays an id */
    CHECK(!strcmp(route_cfg("GET", "/api?action=41231", &cfg).text, "/api?action={id}"));
    /* present without a value, and absent */
    CHECK(!strcmp(route_cfg("GET", "/api?action", &cfg).text, "/api?action="));
    CHECK(!strcmp(route_cfg("GET", "/api?other=1", &cfg).text, "/api"));
    /* a prefix of a key is not the key */
    CHECK(!strcmp(route_cfg("GET", "/api?actions=x", &cfg).text, "/api"));
    /* an overlong value is an identifier whatever it looks like */
    CHECK(!strcmp(route_cfg("GET", "/api?action=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &cfg).text,
                  "/api?action={id}"));
    /* an empty query after the '?' is not a route element */
    CHECK(!strcmp(route_cfg("GET", "/api?", &cfg).text, "/api"));
    return 0;
}

/* --- the explicit map (layer 1) -------------------------------------------- */

static int test_map(void)
{
    static const char text[] = "# comment\n"
                               "\n"
                               "GET /users/{id}/orders/{id}\n"
                               "POST /users/{id}\n"
                               "GET /users/{id}\n"
                               "*   /health\n"
                               "  GET   /spaced/{x}  \r\n"
                               "garbage\n"           /* no pattern */
                               "GET relative/path\n" /* pattern must start with / */
                               "GET /search?q={q}\n" /* a query is never matched */
                               "\n";
    struct lk_route_cfg cfg = {0};
    struct lk_route_map *m;
    struct lk_route_out o;
    uint32_t rejected = 0;

    m = lk_route_map_parse(text, sizeof(text) - 1, &rejected);
    CHECK(m != NULL);
    CHECK(lk_route_map_count(m) == 5);
    CHECK(rejected == 3);
    cfg.map = m;

    /* a hit reports the pattern as written, and says it came from the map */
    o = route_cfg("GET", "/users/7/orders/9", &cfg);
    CHECK(!strcmp(o.text, "/users/{id}/orders/{id}"));
    CHECK(o.flags & LK_ROUTE_F_FROM_MAP);
    /* the method is part of the match: same path, two patterns */
    CHECK(!strcmp(route_cfg("POST", "/users/7", &cfg).text, "/users/{id}"));
    /* a `{...}` segment matches a *literal* segment too — the map is the
     * operator's statement about their own service, not a guess */
    CHECK(!strcmp(route_cfg("GET", "/users/me", &cfg).text, "/users/{id}"));
    /* `*` matches any method */
    CHECK(!strcmp(route_cfg("DELETE", "/health", &cfg).text, "/health"));
    /* segment counts must agree: no prefix matching */
    o = route_cfg("GET", "/users/7/orders", &cfg);
    CHECK(!strcmp(o.text, "/users/{id}/orders"));
    CHECK(!(o.flags & LK_ROUTE_F_FROM_MAP)); /* the heuristic answered */
    /* a miss falls through to the heuristic, whole */
    CHECK(!strcmp(route_cfg("GET", "/other/7", &cfg).text, "/other/{id}"));
    /* leading/trailing whitespace in a line is not part of the pattern */
    CHECK(!strcmp(route_cfg("GET", "/spaced/1", &cfg).text, "/spaced/{x}"));
    /* the map does not touch the query rules */
    CHECK(!strcmp(route_cfg("GET", "/health?token=abc", &cfg).text, "/health"));

    lk_route_map_free(m);

    /* nothing usable is not a map: the caller must be able to tell */
    CHECK(lk_route_map_parse("# only comments\n", 16, &rejected) == NULL);
    CHECK(lk_route_map_parse("", 0, &rejected) == NULL);
    CHECK(lk_route_map_parse(NULL, 0, NULL) == NULL);
    CHECK(lk_route_map_count(NULL) == 0);
    return 0;
}

/* A pattern deeper than the segment ceiling is rejected rather than truncated:
 * a half-loaded pattern would match paths its author never wrote. */
static int test_map_limits(void)
{
    char deep[512] = "GET";
    uint32_t rejected = 0;

    for (int i = 0; i < LK_ROUTE_SEG_MAX + 1; i++)
        strcat(deep, "/x");
    CHECK(lk_route_map_parse(deep, (uint32_t)strlen(deep), &rejected) == NULL);
    CHECK(rejected == 1);
    return 0;
}

/* --- the app-declared route (--http-route-header) -------------------------- */

static int test_given(void)
{
    struct lk_route_out o;

    lk_norm_route_given("GET", 3, "/posts/{slug}", 13, &o);
    CHECK(!strcmp(o.text, "/posts/{slug}"));
    CHECK(o.flags & LK_ROUTE_F_GIVEN);
    /* trusted for its content, not for its bytes */
    lk_norm_route_given("GET", 3, "/a\r\nb", 5, &o);
    CHECK(!strcmp(o.text, "/ab"));
    /* still the same identity rule: the method is in the fingerprint */
    {
        struct lk_route_out a, b;

        lk_norm_route_given("GET", 3, "/x", 2, &a);
        lk_norm_route_given("PUT", 3, "/x", 2, &b);
        CHECK(a.fp != b.fp);
    }
    /* an oversized declaration is clipped as a label and still distinct as an
     * identity — the norm_sql.h property, for the same reason */
    {
        char big[LK_ROUTE_TEXT_MAX * 2];
        struct lk_route_out a, b;

        memset(big, 'a', sizeof(big));
        big[0] = '/';
        lk_norm_route_given("GET", 3, big, sizeof(big), &a);
        big[sizeof(big) - 1] = 'b';
        lk_norm_route_given("GET", 3, big, sizeof(big), &b);
        CHECK(a.flags & LK_ROUTE_F_TRUNC);
        CHECK(a.text_len == b.text_len && !strcmp(a.text, b.text));
        CHECK(a.fp != b.fp);
    }
    return 0;
}

/* --- identity ------------------------------------------------------------- */

static int test_fingerprint(void)
{
    struct lk_route_out a = route_cfg("GET", "/orders/1", NULL);
    struct lk_route_out b = route_cfg("GET", "/orders/2", NULL);
    struct lk_route_out c = route_cfg("DELETE", "/orders/1", NULL);
    struct lk_route_out d = route_cfg("GET", "/orders/1", NULL);

    CHECK(a.fp == b.fp); /* one route, two ids */
    CHECK(a.fp != c.fp); /* the method is part of the route (РH7) */
    CHECK(a.fp == d.fp); /* pure function of the input */
    CHECK(a.fp != route_cfg("GET", "/orders", NULL).fp);
    /* a template that reaches the cap keeps a distinct identity per input */
    {
        char p1[LK_ROUTE_TEXT_MAX * 2], p2[LK_ROUTE_TEXT_MAX * 2];
        struct lk_route_cfg cfg = {.depth = LK_ROUTE_DEPTH_MAX};
        struct lk_route_out o1, o2;
        size_t n = 0;

        for (int i = 0; i < LK_ROUTE_DEPTH_MAX; i++)
            n += (size_t)snprintf(p1 + n, sizeof(p1) - n, "/segment%02d", i);
        memcpy(p2, p1, n + 1);
        p2[n - 1] = 'x';
        o1 = route_cfg("GET", p1, &cfg);
        o2 = route_cfg("GET", p2, &cfg);
        CHECK(o1.flags & LK_ROUTE_F_TRUNC);
        CHECK(o1.text_len == o2.text_len && !strcmp(o1.text, o2.text));
        CHECK(o1.fp != o2.fp);
        CHECK(o1.text_len < LK_ROUTE_TEXT_MAX);
    }
    /* empty and degenerate inputs are answered, not crashed on */
    {
        struct lk_route_out e1, e2;

        lk_norm_route(NULL, 0, NULL, 0, NULL, &e1);
        lk_norm_route("", 0, "", 0, NULL, &e2);
        CHECK(e1.text_len == 0 && e1.text[0] == '\0');
        CHECK(e1.fp == e2.fp);
    }
    return 0;
}

/* --- the cardinality invariant (РH7, risk 1) ------------------------------- */

/* xorshift64*: a deterministic generator, so a failure here reproduces. */
static uint64_t rng_state = 0x9e3779b97f4a7c15ull;

static uint64_t rng(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545f4914f6cdd1dull;
}

/* A path generator in the shape of real traffic: a handful of handlers, each
 * with volatile parts drawn from the id shapes an application actually emits.
 * The point is not realism for its own sake — it is that a million *requests*
 * against a service with a few dozen routes must produce a few dozen labels.
 * If the classifiers regress, the number below moves and the test says so. */
static void gen_path(char *buf, size_t cap)
{
    static const char *const nouns[] = {"users", "orders", "items",    "carts",
                                        "posts", "files",  "sessions", "events"};
    static const char *const verbs[] = {"list", "detail", "export", "archive"};
    uint64_t r = rng();
    unsigned shape = (unsigned)(r % 8);
    const char *noun = nouns[(r >> 8) % 8];
    const char *verb = verbs[(r >> 16) % 4];
    unsigned n = (unsigned)((r >> 24) % 1000000);

    switch (shape) {
    case 0:
        snprintf(buf, cap, "/api/v1/%s/%u", noun, n);
        break;
    case 1:
        snprintf(buf, cap, "/api/v1/%s/%u/%s", noun, n, verb);
        break;
    case 2: /* UUID */
        snprintf(buf, cap, "/api/v2/%s/%08x-%04x-%04x-%04x-%012llx", noun, (unsigned)rng(),
                 (unsigned)(rng() & 0xffff), (unsigned)(rng() & 0xffff), (unsigned)(rng() & 0xffff),
                 (unsigned long long)(rng() & 0xffffffffffffull));
        break;
    case 3: /* content-addressed asset */
        snprintf(buf, cap, "/static/app.%08x.js", (unsigned)rng());
        break;
    case 4: /* a date partition */
        snprintf(buf, cap, "/reports/%04u-%02u-%02u", 2020 + n % 6, 1 + n % 12, 1 + n % 28);
        break;
    case 5: /* a session token */
        snprintf(buf, cap, "/s/%016llx%016llx", (unsigned long long)rng(),
                 (unsigned long long)rng());
        break;
    case 6: /* a query string, which must not reach the label at all */
        snprintf(buf, cap, "/search?q=%u&page=%u", n, n % 20);
        break;
    default: /* a constant route */
        snprintf(buf, cap, "/%s", verb);
        break;
    }
}

/* Distinct-template counter: a small open-addressed set over the fingerprints,
 * because the point of the test is how many there are. */
#define FP_SET_BITS 16
#define FP_SET_SIZE (1u << FP_SET_BITS)

static int test_cardinality(void)
{
    static uint64_t seen[FP_SET_SIZE];
    static bool used[FP_SET_SIZE];
    static const char *const methods[] = {"GET", "POST", "PUT", "DELETE"};
    unsigned distinct = 0;
    char path[256];

    for (unsigned i = 0; i < 1000000; i++) {
        const char *method = methods[i & 3];
        struct lk_route_out o;
        uint64_t h;

        gen_path(path, sizeof(path));
        lk_norm_route(method, (uint32_t)strlen(method), path, (uint32_t)strlen(path), NULL, &o);
        /* the invariant that must hold for every single one of them */
        if (strchr(path, '?') && strchr(o.text, '?')) {
            fprintf(stderr, "FAIL: query reached the template: '%s' -> '%s'\n", path, o.text);
            return 1;
        }
        h = o.fp;
        for (unsigned k = 0; k < FP_SET_SIZE; k++) {
            unsigned slot = (unsigned)((h + k) & (FP_SET_SIZE - 1));

            if (used[slot] && seen[slot] == h)
                break;
            if (!used[slot]) {
                used[slot] = true;
                seen[slot] = h;
                distinct++;
                break;
            }
        }
    }
    /* 8 shapes × 8 nouns × 4 methods bounds the honest answer at a couple of
     * hundred; the threshold leaves room for the generator's shapes to differ
     * per noun and none at all for an id leaking into a label. A million random
     * paths through a leaky classifier would run into five or six digits. */
    if (distinct > 400) {
        fprintf(stderr, "FAIL: 1e6 paths produced %u distinct templates (want <= 400)\n", distinct);
        return 1;
    }
    printf("  1e6 generated paths -> %u distinct route templates\n", distinct);
    return 0;
}

int main(void)
{
    int rc = 0;

    rc |= test_segments();
    rc |= test_flags();
    rc |= test_control_bytes();
    rc |= test_depth();
    rc |= test_query();
    rc |= test_map();
    rc |= test_map_limits();
    rc |= test_given();
    rc |= test_fingerprint();
    rc |= test_cardinality();
    if (!rc)
        printf("test_norm_route: all cases passed\n");
    return rc;
}
