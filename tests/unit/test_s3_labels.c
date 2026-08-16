// SPDX-License-Identifier: GPL-2.0
/* The S3 dialect's labels (PLAN-MINIO.md МS1, РS3/РS4/РS6) — the bucket, the
 * access key and the two byte counts, asserted on the observation that comes
 * out of the real chain rather than on the parsers underneath it, because the
 * observation is what a metric and a span are made of.
 *
 * The header strings are the ones the МS0 corpus contains, spelling included:
 * aws-cli and boto3 write `, ` between the SigV4 components, minio-go (`mc`,
 * `warp`, the Go SDK) writes a bare `,`, and a parser that only survived one of
 * them would lose the `user` label for every request from half the clients on a
 * real MinIO stand.
 *
 * The invariant that runs through the whole file, and the sharpest one in the
 * dialect: **no object key is ever in an observation's labels.** The targets
 * below carry file names, e-mail-shaped keys and directory trees; every
 * assertion about `route`, `host` and `user` is also an assertion that none of
 * that reached them. */
#include "http_obs.h"
#include "s3_wire.h"

#define RESP200 "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

/* A signed GET, in the two spellings the corpus contains. */
#define CRED "Credential=AKIAIOSFODNN7EXAMPLE/20260815/us-east-1/s3/aws4_request"
#define SIGV4_SPACED                                                                               \
    "Authorization: AWS4-HMAC-SHA256 " CRED ", SignedHeaders=host;x-amz-date, "                    \
    "Signature=74b6a95379dc2f1a3f4b9f52dbe9b0a6f5f8c4d2e1b0a9f8e7d6c5b4a3928170\r\n"
#define SIGV4_TIGHT                                                                                \
    "Authorization: AWS4-HMAC-SHA256 " CRED ",SignedHeaders=host;x-amz-date,"                      \
    "Signature=74b6a95379dc2f1a3f4b9f52dbe9b0a6f5f8c4d2e1b0a9f8e7d6c5b4a3928170\r\n"

static void s3_reset(void)
{
    lk_proto_http_configure(NULL); /* no --s3-domain: every request is path-style */
    h_reset_proto(&lk_proto_s3_ops, 0);
}

static void s3_reset_vhost(void)
{
    struct lk_http_cfg cfg = {0};

    cfg.s3.domains[0] = "s3.example.com";
    cfg.s3.ndomains = 1;
    lk_proto_http_configure(&cfg);
    h_reset_proto(&lk_proto_s3_ops, 0);
}

static void answer(__u64 ts)
{
    h_call(LK_DIR_SEND, RESP200, ts);
}

/* --- the base case: operation, bucket, access key ------------------------- */

static int test_signed_get(void)
{
    s3_reset();
    h_call(LK_DIR_RECV,
           "GET /photos/2026/holiday%20photo.jpg HTTP/1.1\r\n"
           "Host: minio.internal:9000\r\n"
           "X-Amz-Content-Sha256: UNSIGNED-PAYLOAD\r\n"
           "X-Amz-Date: 20260815T124726Z\r\n" SIGV4_SPACED "\r\n",
           1000);
    h_call(LK_DIR_SEND,
           "HTTP/1.1 200 OK\r\n"
           "Content-Length: 4\r\n"
           "X-Amz-Request-Id: 18CBFB5B237EC7FE\r\n"
           "Server: MinIO\r\n\r\n"
           "abcd",
           2000);

    CHECK(h_nobs == 1);
    /* The operation is the identity, the method is the verb, and neither is the
     * path — which is the whole of РS2 in three assertions. */
    CHECK(!strcmp(h_obs[0].route, "GetObject"));
    CHECK(!strcmp(h_obs[0].method, "GET"));
    CHECK(!strcmp(h_obs[0].host, "photos")); /* the bucket, in the host slot (РS3) */
    CHECK(!strcmp(h_obs[0].user, "AKIAIOSFODNN7EXAMPLE"));
    CHECK(!strcmp(h_obs[0].req_id, "18CBFB5B237EC7FE"));
    CHECK(h_obs[0].status == 200 && h_obs[0].bytes_out == 4);
    /* The key is in the raw target — the span needs `url.path` — and in nothing
     * else. `route`, `host` and `user` above are the labels, and none of them
     * has ever seen it. */
    CHECK(h_target_is(0, "/photos/2026/holiday%20photo.jpg"));
    CHECK(!strstr(h_obs[0].route, "holiday") && !strstr(h_obs[0].host, "holiday"));
    CHECK(!strstr(h_obs[0].user, "holiday"));
    return 0;
}

/* minio-go's spelling of the same header. */
static int test_signature_spellings(void)
{
    s3_reset();
    h_call(LK_DIR_RECV, "PUT /lkbucket/small.bin HTTP/1.1\r\nHost: h\r\n" SIGV4_TIGHT "\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].user, "AKIAIOSFODNN7EXAMPLE"));
    CHECK(!strcmp(h_obs[0].route, "PutObject"));

    /* SigV2, which MinIO refuses with `403 AccessDenied` — and that refusal is
     * exactly when an operator wants to know whose key is still speaking it. */
    s3_reset();
    h_call(LK_DIR_RECV,
           "GET /lkbucket/small.bin HTTP/1.1\r\nHost: h\r\n"
           "Authorization: AWS AKIAIOSFODNN7EXAMPLE:frJIUN8DYpKDtOLCwo//yllqDzg=\r\n\r\n",
           1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", 2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].user, "AKIAIOSFODNN7EXAMPLE"));
    CHECK(h_obs[0].status == 403 && (h_obs[0].flags & LK_QO_CLIENT_ERR));
    return 0;
}

/* A refused request still identifies its caller: the label extractor runs on the
 * request, not on the outcome (`badsig.lkt`). */
static int test_bad_signature(void)
{
    s3_reset();
    h_call(LK_DIR_RECV, "GET /lkbucket/small.bin HTTP/1.1\r\nHost: h\r\n" SIGV4_SPACED "\r\n",
           1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", 2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].user, "AKIAIOSFODNN7EXAMPLE"));
    CHECK(!strcmp(h_obs[0].route, "GetObject") && h_obs[0].status == 403);
    return 0;
}

static int test_presigned(void)
{
    s3_reset();
    h_call(LK_DIR_RECV,
           "GET /photos/cat.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256"
           "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260815%2Fus-east-1%2Fs3%2Faws4_request"
           "&X-Amz-Date=20260815T124726Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host"
           "&X-Amz-Signature=deadbeef HTTP/1.1\r\n"
           "Host: minio.internal:9000\r\n\r\n",
           1000);
    answer(2000);
    CHECK(h_nobs == 1);
    CHECK(!strcmp(h_obs[0].user, "AKIAIOSFODNN7EXAMPLE"));
    CHECK(!strcmp(h_obs[0].route, "GetObject") && !strcmp(h_obs[0].host, "photos"));
    /* The presigned query keys are not sub-resources, so they change nothing
     * about the operation — and the signature never becomes a label. */
    CHECK(!strstr(h_obs[0].user, "deadbeef"));
    return 0;
}

static int test_anonymous(void)
{
    s3_reset();
    h_call(LK_DIR_RECV, "GET /public/logo.png HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].user, ""));
    CHECK(!strcmp(h_obs[0].route, "GetObject") && !strcmp(h_obs[0].host, "public"));

    /* A credential we could not read whole is not a credential: a prefix of an
     * identity is a *different* identity, so the request is reported as the
     * anonymous one it is indistinguishable from. */
    s3_reset();
    h_call(LK_DIR_RECV,
           "GET /public/logo.png HTTP/1.1\r\nHost: h\r\n"
           "Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\r\n\r\n",
           1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].user, ""));

    /* Nor is a scheme we do not speak. */
    s3_reset();
    h_call(LK_DIR_RECV,
           "GET /public/logo.png HTTP/1.1\r\nHost: h\r\n"
           "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig\r\n\r\n",
           1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].user, ""));
    return 0;
}

/* `--s3-user off` (РS4): the header is not read at all, which is a stronger
 * claim than "the label is dropped". */
static int test_user_off(void)
{
    struct lk_http_cfg cfg = {0};

    cfg.s3.no_user = true;
    lk_proto_http_configure(&cfg);
    h_reset_proto(&lk_proto_s3_ops, 0);
    h_call(LK_DIR_RECV, "GET /lkbucket/k HTTP/1.1\r\nHost: h\r\n" SIGV4_SPACED "\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].user, ""));
    CHECK(!strcmp(h_obs[0].route, "GetObject")); /* everything else is unaffected */
    return 0;
}

/* --- the bucket (РS3) ------------------------------------------------------ */

static int test_bucket_forms(void)
{
    s3_reset_vhost();
    h_call(LK_DIR_RECV, "GET /2026/cat.jpg HTTP/1.1\r\nHost: photos.s3.example.com\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].host, "photos"));
    /* Virtual-host style makes the whole path the key, so this is an object
     * read and not a listing of bucket `2026` — the difference the Host makes,
     * and the reason the form is decided once and remembered. */
    CHECK(!strcmp(h_obs[0].route, "GetObject"));

    /* The same bytes without a matching suffix are path-style. */
    s3_reset();
    h_call(LK_DIR_RECV, "GET /2026/cat.jpg HTTP/1.1\r\nHost: photos.s3.example.com\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].host, "2026"));
    return 0;
}

static int test_bucket_validation(void)
{
    /* A name that fails the S3 rules came off the wire and is not going into a
     * series: MinIO would have answered it `400 InvalidBucketName`. */
    s3_reset();
    h_call(LK_DIR_RECV, "GET /a_b_c/key HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].host, "other"));

    s3_reset();
    h_call(LK_DIR_RECV, "GET /192.168.1.1/key HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].host, "other"));

    /* No bucket at all is a different fact from a bucket we refused to name,
     * and the two must not fold together: `ListBuckets` has no bucket. */
    s3_reset();
    h_call(LK_DIR_RECV, "GET / HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].host, "") && !strcmp(h_obs[0].route, "ListBuckets"));
    return 0;
}

/* MinIO's own surface is classified and counted, and it is still an
 * observation — what РS2 keeps out of the metrics is the *name*, not the
 * exchange (МS2 decides what to do with `op="internal"`). */
static int test_internal(void)
{
    s3_reset();
    h_call(LK_DIR_RECV, "GET /minio/health/live HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].route, "internal"));
    CHECK(!strcmp(h_obs[0].host, "")); /* `minio` is not a bucket */
    return 0;
}

/* --- two byte counts for one upload (РS6) --------------------------------- */

static int test_chunked_upload(void)
{
    /* An `aws-chunked` PUT, as minio-go sends it: no `Content-Encoding` header
     * at all — only the STREAMING marker and the decoded length — which is
     * exactly why the detection is keyed on the latter (notes-s3proto.md
     * §"Two sizes"). The wire carries 40 bytes of signed chunk framing around
     * 16 bytes of object. */
    static const char body[] = "10;chunk-signature=aa\r\n0123456789abcdef\r\n"
                               "0;chunk-signature=bb\r\n\r\n";
    const __u32 wire = (__u32)sizeof(body) - 1; /* 65: 16 of object, 49 of framing */
    char head[512];

    s3_reset();
    snprintf(head, sizeof(head),
             "PUT /lkbucket/small.bin HTTP/1.1\r\n"
             "Host: minio.internal:9000\r\n"
             "Content-Length: %u\r\n"
             "X-Amz-Content-Sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n"
             "X-Amz-Decoded-Content-Length: 16\r\n" SIGV4_TIGHT "\r\n",
             wire);
    h_call(LK_DIR_RECV, head, 1000);
    h_bytes(LK_DIR_RECV, body, wire, 1100);
    answer(2000);

    CHECK(h_nobs == 1);
    CHECK(!strcmp(h_obs[0].route, "PutObject"));
    /* On the wire: every byte of the signed stream, which is what the framer
     * accounted and what a throughput panel needs. */
    CHECK(h_obs[0].bytes_in == wire);
    /* The object: what a size histogram needs, because the framing overhead is
     * 17 % at 1 KB chunks and a distribution that moves with the client's buffer
     * size is worthless. */
    CHECK(h_obs[0].obj_bytes == 16);
    return 0;
}

static int test_plain_upload(void)
{
    /* aws-cli and boto3 precompute a checksum and send an ordinary body, so the
     * two counts agree — and they must agree by *arithmetic*, not by the
     * dialect quietly reporting the same number twice. */
    s3_reset();
    h_call(LK_DIR_RECV,
           "PUT /lkbucket/small.bin HTTP/1.1\r\n"
           "Host: h\r\nContent-Length: 8\r\n"
           "X-Amz-Content-Sha256: UNSIGNED-PAYLOAD\r\n" SIGV4_SPACED "\r\n"
           "01234567",
           1000);
    answer(2000);
    CHECK(h_nobs == 1 && h_obs[0].bytes_in == 8 && h_obs[0].obj_bytes == 8);

    /* A download reports the object on the response side. */
    s3_reset();
    h_call(LK_DIR_RECV, "GET /lkbucket/small.bin HTTP/1.1\r\nHost: h\r\n\r\n", 1000);
    h_call(LK_DIR_SEND, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", 2000);
    CHECK(h_nobs == 1 && h_obs[0].bytes_out == 5 && h_obs[0].obj_bytes == 5);
    return 0;
}

static int test_copy_object(void)
{
    /* Server-side copy: no object bytes cross the wire at all, and the
     * operation still has to be right (a documented blind spot for `bytes_*`,
     * not for the operation, the status or the timings). */
    s3_reset();
    h_call(LK_DIR_RECV,
           "PUT /dst/key.bin HTTP/1.1\r\n"
           "Host: h\r\nContent-Length: 0\r\n"
           "x-amz-copy-source: /src/key.bin\r\n" SIGV4_SPACED "\r\n",
           1000);
    answer(2000);
    CHECK(h_nobs == 1 && !strcmp(h_obs[0].route, "CopyObject"));
    CHECK(!strcmp(h_obs[0].host, "dst"));
    /* The *source* key travelled through a header this dialect looks at, and
     * still reaches nothing: only its presence was read. */
    CHECK(!strstr(h_obs[0].host, "src") && !strstr(h_obs[0].route, "src"));
    CHECK(h_obs[0].bytes_in == 0 && h_obs[0].bytes_out == 0);
    return 0;
}

/* --- the span attributes (МS1) -------------------------------------------- */

static int test_span_attrs(void)
{
    s3_reset();
    h_call(LK_DIR_RECV, "PUT /lkbucket/k HTTP/1.1\r\nHost: h\r\n" SIGV4_SPACED "\r\n", 1000);
    h_call(LK_DIR_SEND,
           "HTTP/1.1 200 OK\r\n"
           "Content-Length: 0\r\n"
           "X-Amz-Request-Id: 18CBFB5B237EC7FE\r\n"
           "X-Amz-Version-Id: 3f6a1c9e-0000-4000-8000-000000000001\r\n"
           "ETag: \"8adca938e4324fcc79dc2279eb53f597\"\r\n\r\n",
           2000);
    CHECK(h_nobs == 1 && h_obs[0].have_http);
    CHECK(!strcmp(h_obs[0].req_id, "18CBFB5B237EC7FE"));
    CHECK(!strcmp(h_obs[0].obj_version, "3f6a1c9e-0000-4000-8000-000000000001"));

    /* A second exchange on the same socket must not inherit the first one's
     * version: the response scratch is per response, not per connection. */
    h_call(LK_DIR_RECV, "PUT /lkbucket/k2 HTTP/1.1\r\nHost: h\r\n" SIGV4_SPACED "\r\n", 3000);
    answer(4000);
    CHECK(h_nobs == 2 && !strcmp(h_obs[1].obj_version, ""));
    return 0;
}

/* --- the base dialect is untouched (РH15) --------------------------------- */

static int test_base_dialect_unchanged(void)
{
    h_reset(); /* lk_proto_http_ops: the same bytes, the other flavour */
    h_call(LK_DIR_RECV,
           "GET /photos/2026/cat.jpg HTTP/1.1\r\n"
           "Host: minio.internal:9000\r\n" SIGV4_SPACED "\r\n",
           1000);
    answer(2000);
    CHECK(h_nobs == 1);
    /* A templated route, the Host in the host slot, and no user — the S3
     * dialect's every rule is off, which is what "the flavour is the port"
     * means. */
    CHECK(!strcmp(h_obs[0].route, "/photos/{id}/cat.jpg"));
    CHECK(!strcmp(h_obs[0].host, "minio.internal:9000"));
    CHECK(!strcmp(h_obs[0].user, ""));
    CHECK(!strcmp(h_obs[0].err_name, "") && h_obs[0].obj_bytes == 0);
    return 0;
}

/* --- the wire parsers, directly ------------------------------------------- */

/* The shapes that must *not* yield a key, checked at the parser rather than
 * through an observation: a truncated header, a control byte, an overlong
 * value. Each of them would otherwise put wire bytes into a label. */
static int test_key_parser_refusals(void)
{
    char out[LK_S3_AK_MAX];
    static const char *const bad[] = {
        "AWS4-HMAC-SHA256 Credential=/20260815/us-east-1/s3/aws4_request", /* empty key */
        "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=ff",               /* no Credential */
        "AWS4-HMAC-SHA256 Credential=AK\x01Z/20260815",                    /* control byte */
        "AWS4-HMAC-SHA256",
        "AWS ",
        "AWS nocolon",
        /* A SigV2 key with a path in it. The scope separator of SigV4 is the
         * one byte an access key cannot contain, and this branch is the only
         * one that could have copied it into a label (МS4's fuzzer found it). */
        "AWS lkbucket/small.bin:frJIUN8DYpKDtOLCwo//yllqDzg=",
        "AWS /:sig",
        "",
    };

    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct http_span v = http_span(bad[i], (__u32)strlen(bad[i]));

        if (s3_auth_access_key(v, out, sizeof(out))) {
            fprintf(stderr, "FAIL: '%s' yielded an access key '%s'\n", bad[i], out);
            return 1;
        }
    }
    /* A key longer than the slot is refused rather than clipped. */
    {
        static const char longcred[] =
            "AWS4-HMAC-SHA256 Credential=AKIA0123456789012345678901234567890123456789/2026";
        struct http_span v = http_span(longcred, (__u32)sizeof(longcred) - 1);

        CHECK(!s3_auth_access_key(v, out, sizeof(out)));
    }
    /* And the presigned side: a value with no separator is not a whole key. */
    {
        struct http_span q = http_span("X-Amz-Credential=AKIAIOSFODNN7EXAMPLE", 36);

        CHECK(!s3_query_access_key(q, out, sizeof(out)));
    }
    {
        struct http_span q = http_span("a=1&X-Amz-Credential=AK%2f2026&b=2", 33);

        CHECK(s3_query_access_key(q, out, sizeof(out)) && !strcmp(out, "AK"));
    }
    return 0;
}

int main(void)
{
    int rc = test_signed_get() || test_signature_spellings() || test_bad_signature() ||
             test_presigned() || test_anonymous() || test_user_off() || test_bucket_forms() ||
             test_bucket_validation() || test_internal() || test_chunked_upload() ||
             test_plain_upload() || test_copy_object() || test_span_attrs() ||
             test_base_dialect_unchanged() || test_key_parser_refusals();

    h_free();
    lk_proto_http_configure(NULL);
    if (rc)
        return 1;
    printf("test_s3_labels: all ok\n");
    return 0;
}
