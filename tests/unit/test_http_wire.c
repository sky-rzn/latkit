// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the header-value readers the М3 handler runs on every head
 * (http_wire.h — the pieces М2 did not need, because framing does not care who
 * you are). Four of them, and each exists because getting it wrong has a
 * specific cost:
 *
 *   - http_target_split — all four request-target forms of RFC 9112 §3.2 reach
 *     a real server, and the route (М4) is built out of the pieces this
 *     returns. Split it wrong and every label downstream is wrong;
 *   - http_parse_traceparent — a header that fails to parse must produce *no*
 *     parent, never a made-up one: a span hung off a garbage trace id is worse
 *     than an unparented span, because it silently corrupts someone else's
 *     trace;
 *   - http_basic_user — the one place the agent reads a credential header at
 *     all, and it must stop at the colon;
 *   - http_first_token / http_method_name / http_method_tag — small, but they
 *     decide what a label says.
 *
 * Header-only code with no state, so these are table tests over spans; the
 * framer-level cases live in test_http_frame.c and the handler-level ones in
 * test_http_req.c. */
#include <linux/types.h>
#include <stdio.h>
#include <string.h>

#include "http_wire.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static struct http_span sp(const char *s)
{
    return http_span(s, (__u32)strlen(s));
}

static bool eq(struct http_span s, const char *lit)
{
    return s.n == strlen(lit) && (!s.n || !memcmp(s.p, lit, s.n));
}

/* --- request-target forms ------------------------------------------------- */

static int test_target_forms(void)
{
    struct http_span path, query, auth;

    /* origin-form: the overwhelmingly common one */
    http_target_split(sp("/orders/42"), &path, &query, &auth);
    CHECK(eq(path, "/orders/42") && eq(query, "") && eq(auth, ""));

    http_target_split(sp("/orders/42?x=1&y=2"), &path, &query, &auth);
    CHECK(eq(path, "/orders/42") && eq(query, "x=1&y=2") && eq(auth, ""));

    /* A '?' with nothing after it: an empty query, not a query named "". The
     * distinction matters because М4 drops the query from the route either
     * way, and a path ending in '?' would not be a route anyone recognises. */
    http_target_split(sp("/a?"), &path, &query, &auth);
    CHECK(eq(path, "/a") && eq(query, ""));

    /* absolute-form: proxies, and any client that feels like it. The authority
     * is returned separately because it *overrides* Host (РH10). */
    http_target_split(sp("http://shop.example/orders/42?x=1"), &path, &query, &auth);
    CHECK(eq(auth, "shop.example") && eq(path, "/orders/42") && eq(query, "x=1"));

    http_target_split(sp("https://shop.example:8443/a"), &path, &query, &auth);
    CHECK(eq(auth, "shop.example:8443") && eq(path, "/a"));

    /* An absolute-form target whose query starts right after the authority. */
    http_target_split(sp("http://h?x=1"), &path, &query, &auth);
    CHECK(eq(auth, "h") && eq(path, "") && eq(query, "x=1"));

    /* authority-form: CONNECT, and nothing else. No path exists, which is what
     * makes such a unit LK_QO_NO_TEXT rather than one with an empty route. */
    http_target_split(sp("shop.example:443"), &path, &query, &auth);
    CHECK(eq(auth, "shop.example:443") && eq(path, "") && eq(query, ""));

    /* asterisk-form: `OPTIONS *`. It is a target, not an authority. */
    http_target_split(sp("*"), &path, &query, &auth);
    CHECK(eq(path, "*") && eq(auth, "") && eq(query, ""));

    /* A colon in the *path* is legal and must not read as a scheme. */
    http_target_split(sp("/a:b/c"), &path, &query, &auth);
    CHECK(eq(path, "/a:b/c") && eq(auth, ""));

    /* Nothing at all: every piece empty, nothing read. */
    http_target_split(http_span(NULL, 0), &path, &query, &auth);
    CHECK(!path.n && !query.n && !auth.n);
    return 0;
}

/* --- traceparent (РH11) --------------------------------------------------- */

static int test_traceparent(void)
{
    const char *good = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    __u8 tid[16], pid[8], fl;

    CHECK(http_parse_traceparent(sp(good), tid, pid, &fl));
    CHECK(tid[0] == 0x4b && tid[15] == 0x36);
    CHECK(pid[0] == 0x00 && pid[1] == 0xf0 && pid[7] == 0xb7);
    CHECK(fl == 0x01); /* sampled */

    /* The unsampled flag parses and is reported as such — a non-sampled request
     * still reaches the span layer, which may export it on the slow-query
     * threshold (РH11, documented asymmetry). */
    CHECK(http_parse_traceparent(sp("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"), tid,
                                 pid, &fl));
    CHECK(fl == 0x00);

    /* Uppercase hex is off-spec on the write side; accepted on the read side,
     * because refusing a whole trace over letter case would be pedantry with a
     * real cost. */
    CHECK(http_parse_traceparent(sp("00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01"), tid,
                                 pid, &fl));

    /* Everything below must fail, and failing means "no parent", not "a parent
     * we guessed at". */
    CHECK(!http_parse_traceparent(sp(""), tid, pid, &fl));
    /* an all-zero trace id or parent id is invalid by the spec */
    CHECK(!http_parse_traceparent(sp("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
                                  tid, pid, &fl));
    CHECK(!http_parse_traceparent(sp("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"),
                                  tid, pid, &fl));
    /* a future version: the field layout is not ours to assume */
    CHECK(!http_parse_traceparent(sp("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
                                  tid, pid, &fl));
    /* too short a trace id */
    CHECK(!http_parse_traceparent(sp("00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01"), tid,
                                  pid, &fl));
    /* non-hex */
    CHECK(!http_parse_traceparent(sp("00-4bf92f3577b34da6a3ce929d0e0e47zz-00f067aa0ba902b7-01"),
                                  tid, pid, &fl));
    /* wrong separators */
    CHECK(!http_parse_traceparent(sp("00_4bf92f3577b34da6a3ce929d0e0e4736_00f067aa0ba902b7_01"),
                                  tid, pid, &fl));
    /* truncated mid-field: must not read past the span */
    CHECK(!http_parse_traceparent(sp("00-4bf92f3577b34da6"), tid, pid, &fl));
    /* trailing junk that is not a further dash-separated field */
    CHECK(!http_parse_traceparent(sp("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01x"),
                                  tid, pid, &fl));
    /* ... but a version-00 prefix followed by a real extra field is still
     * unambiguous, and the spec asks us to ignore what we do not know */
    CHECK(http_parse_traceparent(sp("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-ff"),
                                 tid, pid, &fl));
    return 0;
}

/* --- Authorization: Basic (РH10) ------------------------------------------ */

static int test_basic_user(void)
{
    char out[40];

    /* "admin:hunter2" */
    CHECK(http_basic_user(sp("Basic YWRtaW46aHVudGVyMg=="), out, sizeof(out)));
    CHECK(!strcmp(out, "admin"));

    /* The scheme token is case-insensitive (RFC 9110 §11.1). */
    CHECK(http_basic_user(sp("basic YWRtaW46aHVudGVyMg=="), out, sizeof(out)));
    CHECK(!strcmp(out, "admin"));

    /* An empty password is still a user:password pair — "admin:" */
    CHECK(http_basic_user(sp("Basic YWRtaW46"), out, sizeof(out)) && !strcmp(out, "admin"));

    /* Bearer is never touched, whatever it holds. This is the case the flag
     * exists to keep safe: a bearer token is a credential in full, not half of
     * an identity pair. */
    out[0] = 'x';
    CHECK(!http_basic_user(sp("Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc"), out, sizeof(out)));
    CHECK(out[0] == 'x'); /* untouched */

    /* No colon at all: not a user:password pair, so not a user. Base64 of
     * "adminonly". */
    CHECK(!http_basic_user(sp("Basic YWRtaW5vbmx5"), out, sizeof(out)));

    /* Malformed base64, an empty value, a missing space: all rejected. */
    CHECK(!http_basic_user(sp("Basic !!!!"), out, sizeof(out)));
    CHECK(!http_basic_user(sp("Basic "), out, sizeof(out)));
    CHECK(!http_basic_user(sp("Basic"), out, sizeof(out)));
    CHECK(!http_basic_user(sp(""), out, sizeof(out)));

    /* An empty user name is not a label. Base64 of ":pw". */
    CHECK(!http_basic_user(sp("Basic OnB3"), out, sizeof(out)));

    /* The exact ceiling: a name of cap-1 characters fits (39 a's here), one
     * character more is rejected outright rather than truncated — a clipped
     * identity is worse than none, because it may collide with another one. */
    CHECK(http_basic_user(sp("Basic YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhOng="), out,
                          sizeof(out)));
    CHECK(strlen(out) == sizeof(out) - 1);
    CHECK(!http_basic_user(sp("Basic YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYTp4"),
                           out, sizeof(out)));

    /* A control byte inside the name: rejected, it would end up in a label.
     * Base64 of "a\nb:x". */
    CHECK(!http_basic_user(sp("Basic YQpiOng="), out, sizeof(out)));
    return 0;
}

/* --- the small ones ------------------------------------------------------- */

static int test_tokens(void)
{
    CHECK(eq(http_first_token(sp("text/html; charset=utf-8")), "text/html"));
    CHECK(eq(http_first_token(sp("application/json")), "application/json"));
    CHECK(eq(http_first_token(sp("  text/plain  ; x=1")), "text/plain"));
    CHECK(eq(http_first_token(sp("")), ""));

    CHECK(!strcmp(http_method_name(HTTP_M_GET), "GET"));
    CHECK(!strcmp(http_method_name(HTTP_M_PATCH), "PATCH"));
    CHECK(http_method_name(HTTP_M_OTHER) == NULL);

    /* Every known method gets its own tally letter, and none of them collides:
     * a duplicate would silently merge two methods in the stats line. */
    for (int a = HTTP_M_OTHER; a <= HTTP_M_PATCH; a++)
        for (int b = a + 1; b <= HTTP_M_PATCH; b++)
            CHECK(http_method_tag((enum http_method)a) != http_method_tag((enum http_method)b));
    CHECK(http_method_tag(HTTP_M_OTHER) == '?');
    return 0;
}

int main(void)
{
    if (test_target_forms() || test_traceparent() || test_basic_user() || test_tokens())
        return 1;
    printf("ok\n");
    return 0;
}
