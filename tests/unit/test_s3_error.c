// SPDX-License-Identifier: GPL-2.0
/* The S3 error code (PLAN-MINIO.md МS1, РS5) — the one place in the agent where
 * a response *body* byte is looked at, and therefore the one that has to be
 * argued for rather than merely tested.
 *
 * The argument: a `404` from an object store is `NoSuchKey`, `NoSuchBucket`,
 * `NoSuchTagSet`, `NoSuchLifecycleConfiguration` or six others, and they mean
 * completely different things to whoever is on call. The status alone cannot
 * separate them. So a failing response — and only a failing one — hands the
 * dialect a bounded prefix of its body, which is read for `<Code>` and dropped.
 *
 * The same prefix contains `<Key>` and `<Resource>`, which is to say the object
 * key, and that is what the assertions here are really about: the code comes
 * out, nothing else does, and a viewer of the message stream sees none of it.
 *
 * Four fallbacks, all of them ending in "report the status and say nothing
 * else", because a made-up error name is worse than a missing one: a truncated
 * body, a non-XML body, a body a hole ate, and a HEAD, which by construction has
 * no body at all — the last one answered by MinIO's own header. */
#include "http_obs.h"
#include "s3_wire.h"

/* MinIO's error body, verbatim in shape: an XML declaration, `<Code>` as the
 * first child of `<Error>`, and the object key two elements later. */
#define ERRBODY(code, key)                                                                         \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"                                                   \
    "<Error><Code>" code "</Code><Message>The specified thing does not exist.</Message>"           \
    "<Key>" key "</Key><BucketName>lkbucket</BucketName><Resource>/lkbucket/" key "</Resource>"    \
    "<RequestId>18CBFB5B237EC7FE</RequestId><HostId>dd9025ba</HostId></Error>"

static void s3_reset(void)
{
    lk_proto_http_configure(NULL);
    h_reset_proto(&lk_proto_s3_ops, 0);
}

/* One failing exchange: a signed GET, then a status with the given body. */
static void fail_with(int status, const char *extra_hdr, const char *body)
{
    char head[512];

    h_call(LK_DIR_RECV, "GET /lkbucket/secret-report.pdf HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    snprintf(head, sizeof(head),
             "HTTP/1.1 %d Error\r\nContent-Type: application/xml\r\nContent-Length: %u\r\n%s\r\n",
             status, (unsigned)strlen(body), extra_hdr);
    h_call(LK_DIR_SEND, head, 2000);
    if (*body)
        h_bytes(LK_DIR_SEND, body, (__u32)strlen(body), 2100);
}

/* --- the code comes out --------------------------------------------------- */

static int test_xml_code(void)
{
    s3_reset();
    fail_with(404, "", ERRBODY("NoSuchKey", "secret-report.pdf"));
    CHECK(h_nobs == 1);
    CHECK(h_obs[0].status == 404);
    CHECK(!strcmp(h_obs[0].err_name, "NoSuchKey"));
    CHECK(h_obs[0].flags & LK_QO_CLIENT_ERR);
    /* The key was in the bytes the dialect just read. It is in the raw target,
     * where a span needs it, and in nothing that can become a label. */
    CHECK(!strstr(h_obs[0].err_name, "secret") && !strstr(h_obs[0].route, "secret"));
    CHECK(!strstr(h_obs[0].host, "secret") && !strstr(h_obs[0].user, "secret"));

    /* Two `404`s that are not the same failure — the whole reason the body is
     * read at all. */
    s3_reset();
    fail_with(404, "", ERRBODY("NoSuchBucket", "k"));
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].err_name, "NoSuchBucket"));

    s3_reset();
    fail_with(403, "", ERRBODY("SignatureDoesNotMatch", "k"));
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].err_name, "SignatureDoesNotMatch"));

    /* A 5xx is the server's failure and keeps the flag that says so. */
    s3_reset();
    fail_with(500, "", ERRBODY("InternalError", "k"));
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].err_name, "InternalError"));
    CHECK((h_obs[0].flags & LK_QO_ERROR) && !(h_obs[0].flags & LK_QO_CLIENT_ERR));
    return 0;
}

/* A code outside the vocabulary is `other`, not itself: a server is free to
 * invent a code and must not be free to invent a series with it. */
static int test_unknown_code(void)
{
    s3_reset();
    fail_with(400, "", ERRBODY("SomeCodeFromTheFuture", "k"));
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].err_name, "other"));

    /* An element that is *there* but empty names nothing, and "nothing" is not
     * `other`: `other` means "a code we do not know", and reporting it here
     * would put a shape MinIO never produces into the same bucket as the
     * genuinely-new codes the dashboard watches for. */
    s3_reset();
    fail_with(400, "", ERRBODY("", "k"));
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].err_name, ""));
    return 0;
}

/* --- the four fallbacks --------------------------------------------------- */

static int test_no_body(void)
{
    /* A `2xx` never yields a prefix: the framer arms the request only on a
     * status ≥ 400, so a successful download's body is not looked at even by
     * this dialect. */
    s3_reset();
    h_call(LK_DIR_RECV, "GET /lkbucket/k HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n<Code>x<", 2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].err_name, ""));

    /* A HEAD error has no body at all — a property of S3, not a gap in ours.
     * MinIO fills it with a header, and reading that costs nothing because the
     * head is parsed anyway. */
    s3_reset();
    h_call(LK_DIR_RECV, "HEAD /lkbucket/k HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    h_call(LK_DIR_SEND,
           "HTTP/1.1 404 Not Found\r\n"
           "Content-Length: 0\r\n"
           "X-Minio-Error-Code: NoSuchKey\r\n"
           "X-Minio-Error-Desc: \"The specified key does not exist.\"\r\n\r\n",
           2000);
    CHECK(h_nobs == 1 && h_obs[0].status == 404);
    CHECK(!strcmp(h_obs[0].err_name, "NoSuchKey"));
    CHECK(!strcmp(h_obs[0].route, "HeadObject"));

    /* A server that is not MinIO sends neither, and then the status is the whole
     * answer — which is what boto3 is left with too. */
    s3_reset();
    h_call(LK_DIR_RECV, "HEAD /lkbucket/k HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 2000);
    CHECK(h_nobs == 1 && h_obs[0].status == 404 && !strcmp(h_obs[0].err_name, ""));
    return 0;
}

static int test_non_xml_body(void)
{
    /* An HTML error page from a proxy in front of MinIO: no element, no code,
     * and above all no parse error — the input was fine, it simply was not the
     * document we hoped for. */
    s3_reset();
    fail_with(502, "", "<html><head><title>502 Bad Gateway</title></head><body>nope</body></html>");
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].err_name, "") && h_obs[0].status == 502);
    CHECK(h_stats()->parse_errors == 0);

    /* Binary rubbish where an error body belongs. */
    s3_reset();
    fail_with(400, "", "\x01\x02\x03<Code>\x7f\x80");
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].err_name, ""));
    CHECK(h_stats()->parse_errors == 0);
    return 0;
}

static int test_truncated_body(void)
{
    /* The element opened and the capture ended before it closed: no code, and
     * the observation is otherwise complete — status, route, timings. */
    s3_reset();
    h_call(LK_DIR_RECV, "GET /lkbucket/k HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 404 Not Found\r\nContent-Length: 40\r\n\r\n", 2000);
    h_feed(LK_DIR_SEND, 40, 0, "<Error><Code>NoSuchK", 20, 2100); /* the rest is a hole */
    h_hole(LK_DIR_SEND, 20);
    CHECK(h_nobs == 1 && h_obs[0].status == 404 && !strcmp(h_obs[0].err_name, ""));
    CHECK(!strcmp(h_obs[0].route, "GetObject"));
    CHECK(h_stats()->parse_errors == 0);

    /* And a hole *instead of* the body: the prefix is spent on captured bytes
     * only, so a holed error body costs the code and nothing else. */
    s3_reset();
    h_call(LK_DIR_RECV, "GET /lkbucket/k HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 404 Not Found\r\nContent-Length: 40\r\n\r\n", 2000);
    h_hole(LK_DIR_SEND, 40);
    CHECK(h_nobs == 1 && h_obs[0].status == 404 && !strcmp(h_obs[0].err_name, ""));
    CHECK(h_obs[0].bytes_out == 40); /* the bytes were on the wire, and are counted */
    return 0;
}

/* The code must not survive its own response: the next exchange on a keep-alive
 * connection is a different failure, or none. */
static int test_scratch_is_per_response(void)
{
    s3_reset();
    fail_with(404, "", ERRBODY("NoSuchKey", "k"));
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].err_name, "NoSuchKey"));

    h_call(LK_DIR_RECV, "GET /lkbucket/k2 HTTP/1.1\r\nHost: h\r\n\r\n", 3000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 4000);
    CHECK(h_nobs == 2 && !strcmp(h_obs[1].err_name, ""));

    h_call(LK_DIR_RECV, "GET /lkbucket/k3 HTTP/1.1\r\nHost: h\r\n\r\n", 5000);
    h_call(LK_DIR_SEND,
           "HTTP/1.1 403 Forbidden\r\nContent-Length: 231\r\n\r\n" ERRBODY("AccessDenied", "k3"),
           6000);
    CHECK(h_nobs == 3 && !strcmp(h_obs[2].err_name, "AccessDenied"));
    return 0;
}

/* The base dialect asks the framer for nothing, so an error body on a plain
 * HTTP port is never carried at all — the exception of РS5 is one dialect's,
 * not the protocol's. */
static int test_base_dialect_reads_no_body(void)
{
    h_reset();
    h_call(LK_DIR_RECV, "GET /lkbucket/k HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 404 Not Found\r\nContent-Length: 231\r\n\r\n", 2000);
    h_bytes(LK_DIR_SEND, ERRBODY("NoSuchKey", "k"), (__u32)strlen(ERRBODY("NoSuchKey", "k")), 2100);
    CHECK(h_nobs == 1 && h_obs[0].status == 404 && !strcmp(h_obs[0].err_name, ""));
    return 0;
}

/* --- the extractor, directly ---------------------------------------------- */

static int test_extractor(void)
{
    char out[LK_HTTP_ERRNAME_MAX];
    static const char body[] = ERRBODY("NoSuchKey", "cat.jpg");

    CHECK(s3_error_code(body, (__u32)sizeof(body) - 1, out, sizeof(out)));
    CHECK(!strcmp(out, "NoSuchKey"));

    /* The prefix the framer actually carries is bounded, and the element is
     * within it: `<Code>` is the first child of `<Error>` in every response the
     * corpus contains, so 256 bytes always suffice. */
    CHECK(s3_error_code(body, LK_HTTP_ERRB_MAX, out, sizeof(out)));
    CHECK(!strcmp(out, "NoSuchKey"));

    /* Refusals: no element, an element that never closes, an empty buffer. */
    CHECK(!s3_error_code("<Error><Message>x</Message></Error>", 35, out, sizeof(out)));
    CHECK(!s3_error_code("<Error><Code>NoSuchK", 20, out, sizeof(out)));
    CHECK(!s3_error_code("", 0, out, sizeof(out)));
    CHECK(!s3_error_code(NULL, 0, out, sizeof(out)));

    /* An element longer than the label slot cannot overrun it; it folds to
     * `other` like any code the vocabulary does not know. */
    {
        static const char huge[] = "<Error><Code>"
                                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                   "</Code></Error>";

        CHECK(s3_error_code(huge, (__u32)sizeof(huge) - 1, out, sizeof(out)));
        CHECK(!strcmp(out, "other"));
    }
    /* The longest code the vocabulary holds still fits its slot whole. */
    {
        static const char longest[] =
            "<Error><Code>ServerSideEncryptionConfigurationNotFoundError</Code></Error>";

        CHECK(s3_error_code(longest, (__u32)sizeof(longest) - 1, out, sizeof(out)));
        CHECK(!strcmp(out, "ServerSideEncryptionConfigurationNotFoundError"));
    }
    return 0;
}

/* The prefix must not reach a viewer: `--messages --hexdump` runs every body
 * through lk_msg_body_for_display, and for an 'X' that has to come back blank
 * (РS5 — the same bytes hold the object key). */
static int test_prefix_is_masked(void)
{
    static const char body[] = ERRBODY("NoSuchKey", "payroll-2026.xlsx");
    struct lk_msg m = {
        .type = LK_HTTP_MSG_ERRB,
        .len = (__u32)sizeof(body) - 1,
        .body_cap = (__u32)sizeof(body) - 1,
        .body = (const __u8 *)body,
    };
    __u8 shown[LK_HTTP_ERRB_MAX];
    __u32 n = lk_msg_body_for_display(&lk_proto_s3_ops, &m, shown, sizeof(shown));

    CHECK(n && n <= sizeof(shown));
    for (__u32 i = 0; i < n; i++)
        CHECK(shown[i] == '*');
    return 0;
}

int main(void)
{
    int rc = test_xml_code() || test_unknown_code() || test_no_body() || test_non_xml_body() ||
             test_truncated_body() || test_scratch_is_per_response() ||
             test_base_dialect_reads_no_body() || test_extractor() || test_prefix_is_masked();

    h_free();
    lk_proto_http_configure(NULL);
    if (rc)
        return 1;
    printf("test_s3_error: all ok\n");
    return 0;
}
