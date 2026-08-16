// SPDX-License-Identifier: GPL-2.0
/* The S3 classifier (PLAN-MINIO.md МS1, src/norm/norm_s3.c) — the operation
 * table of РS2 and the addressing rules of РS3, driven directly rather than
 * through the handler, because what is asserted here is a *function*: the same
 * request must always produce the same operation, and the set of operations it
 * can produce must be the table.
 *
 * The case list is the table of docs/notes-s3proto.md §"The operation table",
 * row for row, plus the four things only a live server teaches — a trailing
 * slash on a bucket is still bucket level, `?uploadId` is ambiguous by method
 * and only by method, an unknown query key on a known shape still classifies,
 * and `%2F` in a key is not a separator.
 *
 * The last test is the one the plan asks for by name: a million generated paths
 * must not produce a single label outside the table. It is what makes "the
 * cardinality of `op` is bounded by construction" a checked claim rather than a
 * design intention. */
#include <stdio.h>
#include <string.h>

#include "norm_s3.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* One classification, the way the dialect performs it: split the target at the
 * first `?`, locate the bucket, look the operation up. `host` may be NULL, and
 * then no suffix can match and everything is path-style. */
static const char *op_of(const char *host, const char *method, const char *target,
                         const struct lk_s3_cfg *cfg, uint16_t flags)
{
    struct lk_s3_addr a;
    uint32_t tlen = (uint32_t)strlen(target), plen = 0;

    while (plen < tlen && target[plen] != '?')
        plen++;
    lk_s3_addr(host, host ? (uint32_t)strlen(host) : 0, target, plen, cfg, &a);
    return lk_s3_op(method, (uint32_t)strlen(method),
                    plen < tlen ? target + plen + 1 : target + tlen,
                    plen < tlen ? tlen - plen - 1 : 0, &a, flags);
}

static int op_is(const char *method, const char *target, const char *want)
{
    const char *got = op_of(NULL, method, target, NULL, 0);

    if (strcmp(got, want)) {
        fprintf(stderr, "FAIL: %s %s -> '%s', want '%s'\n", method, target, got, want);
        return 0;
    }
    return 1;
}

/* --- the table, row for row ----------------------------------------------- */

static int test_shapes(void)
{
    /* Service level. */
    CHECK(op_is("GET", "/", "ListBuckets"));
    CHECK(op_is("GET", "", "ListBuckets"));

    /* Bucket level. A trailing slash is not a key — `mc` sends one and aws-cli
     * does not, for the same operation. */
    CHECK(op_is("GET", "/lkbucket", "ListObjects"));
    CHECK(op_is("GET", "/lkbucket/", "ListObjects"));
    CHECK(op_is("PUT", "/lkbucket", "CreateBucket"));
    CHECK(op_is("DELETE", "/lkbucket", "DeleteBucket"));
    CHECK(op_is("HEAD", "/lkbucket", "HeadBucket"));
    CHECK(op_is("POST", "/lkbucket", "PostObject"));

    /* Object level. */
    CHECK(op_is("GET", "/lkbucket/small.bin", "GetObject"));
    CHECK(op_is("HEAD", "/lkbucket/small.bin", "HeadObject"));
    CHECK(op_is("PUT", "/lkbucket/small.bin", "PutObject"));
    CHECK(op_is("DELETE", "/lkbucket/small.bin", "DeleteObject"));
    /* A deep key is still one key: the segments past the bucket are not a
     * hierarchy anyone here is entitled to count. */
    CHECK(op_is("GET", "/lkbucket/a/b/c/d/e/f/g/h/i/j/k.txt", "GetObject"));
    return 0;
}

static int test_listings(void)
{
    CHECK(op_is("GET", "/lkbucket?list-type=2", "ListObjectsV2"));
    CHECK(
        op_is("GET", "/lkbucket?list-type=2&prefix=a/&delimiter=%2F&max-keys=10", "ListObjectsV2"));
    /* `list-type` is the one query *value* the classifier reads, and only
     * because `=2` is a documented enum. Anything else falls back to the shape
     * rules, where `GET /{bucket}` is already the V1 listing. */
    CHECK(op_is("GET", "/lkbucket?list-type=9", "ListObjects"));
    CHECK(op_is("GET", "/lkbucket?list-type", "ListObjects"));
    CHECK(op_is("GET", "/lkbucket?versions", "ListObjectVersions"));
    CHECK(op_is("GET", "/lkbucket?uploads", "ListMultipartUploads"));
    CHECK(op_is("GET", "/lkbucket?prefix=x&marker=y", "ListObjects"));
    return 0;
}

static int test_multipart(void)
{
    /* Four operations behind one query key; the method is the whole
     * discriminator (notes-s3proto.md §"The operation table"). */
    CHECK(op_is("POST", "/lkbucket/big.bin?uploads=", "CreateMultipartUpload"));
    CHECK(op_is("PUT", "/lkbucket/big.bin?partNumber=1&uploadId=abc", "UploadPart"));
    CHECK(op_is("GET", "/lkbucket/big.bin?uploadId=abc", "ListParts"));
    CHECK(op_is("POST", "/lkbucket/big.bin?uploadId=abc", "CompleteMultipartUpload"));
    CHECK(op_is("DELETE", "/lkbucket/big.bin?uploadId=abc", "AbortMultipartUpload"));
    /* `partNumber` is not a recognised sub-resource, so key order does not
     * change the answer. */
    CHECK(op_is("PUT", "/lkbucket/big.bin?uploadId=abc&partNumber=1", "UploadPart"));
    return 0;
}

static int test_copy_source(void)
{
    /* The one header in the classifier, and it flips two rows. */
    CHECK(op_is("PUT", "/dst/key", "PutObject"));
    CHECK(!strcmp(op_of(NULL, "PUT", "/dst/key", NULL, LK_S3_F_COPY_SRC), "CopyObject"));
    CHECK(!strcmp(op_of(NULL, "PUT", "/dst/key?partNumber=2&uploadId=u", NULL, LK_S3_F_COPY_SRC),
                  "UploadPartCopy"));
    /* ... and nothing else. A copy-source on a GET is not a row. */
    CHECK(!strcmp(op_of(NULL, "GET", "/dst/key", NULL, LK_S3_F_COPY_SRC), "GetObject"));
    return 0;
}

static int test_subresources(void)
{
    static const struct {
        const char *method, *target, *op;
    } tab[] = {
        {"GET", "/b?acl", "GetBucketAcl"},
        {"PUT", "/b?acl", "PutBucketAcl"},
        {"GET", "/b?location=", "GetBucketLocation"},
        {"GET", "/b/", "ListObjects"},
        {"GET", "/b?policy", "GetBucketPolicy"},
        {"DELETE", "/b?policy", "DeleteBucketPolicy"},
        {"GET", "/b?policyStatus", "GetBucketPolicyStatus"},
        {"GET", "/b?versioning", "GetBucketVersioning"},
        {"PUT", "/b?versioning", "PutBucketVersioning"},
        {"GET", "/b?tagging", "GetBucketTagging"},
        {"DELETE", "/b?tagging", "DeleteBucketTagging"},
        {"GET", "/b?lifecycle", "GetBucketLifecycleConfiguration"},
        {"GET", "/b?notification", "GetBucketNotificationConfiguration"},
        {"GET", "/b?encryption", "GetBucketEncryption"},
        {"GET", "/b?replication", "GetBucketReplication"},
        {"GET", "/b?object-lock", "GetObjectLockConfiguration"},
        {"GET", "/b?cors", "GetBucketCors"},
        {"GET", "/b?accelerate", "GetBucketAccelerateConfiguration"},
        {"GET", "/b?logging", "GetBucketLogging"},
        {"GET", "/b?requestPayment", "GetBucketRequestPayment"},
        {"GET", "/b?website", "GetBucketWebsite"},
        {"GET", "/b?publicAccessBlock", "GetPublicAccessBlock"},
        {"POST", "/b?delete", "DeleteObjects"},
        {"GET", "/b/k?acl", "GetObjectAcl"},
        {"PUT", "/b/k?tagging", "PutObjectTagging"},
        {"DELETE", "/b/k?tagging", "DeleteObjectTagging"},
        {"GET", "/b/k?retention", "GetObjectRetention"},
        {"PUT", "/b/k?legal-hold", "PutObjectLegalHold"},
        {"GET", "/b/k?attributes", "GetObjectAttributes"},
        {"POST", "/b/k?restore", "RestoreObject"},
        {"POST", "/b/k?select&select-type=2", "SelectObjectContent"},
    };

    for (unsigned i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        if (!op_is(tab[i].method, tab[i].target, tab[i].op))
            return 1;
    }
    /* A sub-resource at the wrong level or under the wrong method is not a
     * guess: it is `other`, and the share of `other` is the dashboard's signal
     * that the taxonomy has aged (риск 5). */
    CHECK(op_is("DELETE", "/b?acl", "other"));
    CHECK(op_is("GET", "/b?delete", "other"));
    CHECK(op_is("POST", "/b/k?uploads&extra=1", "CreateMultipartUpload"));
    return 0;
}

/* --- addressing (РS3) ------------------------------------------------------ */

static int test_addressing(void)
{
    static const char *const doms[] = {"s3.example.com"};
    struct lk_s3_cfg cfg = {.domains = {doms[0]}, .ndomains = 1};
    struct lk_s3_addr a;

    /* Path style, which is what happens with no `--s3-domain` at all: the same
     * request means two different things and the server's configuration is what
     * decides, so ours has to as well. */
    CHECK(op_is("GET", "/photos/2026/cat.jpg", "GetObject"));

    /* Virtual-host style: the bucket is in the Host and the *whole* path is the
     * key, so the same request is now an object read of `photos/2026/cat.jpg`
     * rather than of bucket `2026`. */
    CHECK(!strcmp(op_of("photos.s3.example.com", "GET", "/2026/cat.jpg", &cfg, 0), "GetObject"));
    CHECK(!strcmp(op_of("photos.s3.example.com", "GET", "/", &cfg, 0), "ListObjects"));
    CHECK(!strcmp(op_of("photos.s3.example.com", "GET", "", &cfg, 0), "ListObjects"));
    /* The port is not part of the name. */
    CHECK(!strcmp(op_of("photos.s3.example.com:9000", "GET", "/k", &cfg, 0), "GetObject"));
    /* The suffix itself is not a bucket. */
    CHECK(!strcmp(op_of("s3.example.com", "GET", "/photos", &cfg, 0), "ListObjects"));

    lk_s3_addr("photos.s3.example.com", 21, "/2026/cat.jpg", 13, &cfg, &a);
    CHECK(a.vhost && a.valid && a.bucket_len == 6 && !memcmp(a.bucket, "photos", 6));
    CHECK(a.key_len == 12); /* `2026/cat.jpg` — located, never copied */

    /* A dotted bucket name is one bucket, not a subdomain of one: cutting at
     * the first label would report a bucket nobody created. */
    lk_s3_addr("my.bucket.s3.example.com", 24, "/k", 2, &cfg, &a);
    CHECK(a.vhost && a.valid && a.bucket_len == 9 && !memcmp(a.bucket, "my.bucket", 9));

    lk_s3_addr("minio.internal:9000", 19, "/photos/2026/cat.jpg", 20, &cfg, &a);
    CHECK(!a.vhost && a.valid && a.bucket_len == 6 && !memcmp(a.bucket, "photos", 6));
    CHECK(a.key_len == 12);

    lk_s3_addr(NULL, 0, "/", 1, NULL, &a);
    CHECK(!a.bucket_len && !a.key_len && !a.valid);
    return 0;
}

/* The rules MinIO enforces with `400 InvalidBucketName`, so a name this accepts
 * is a name the server would have routed (notes-s3proto.md §"Addressing"). */
static int test_bucket_names(void)
{
    /* 63 bytes: the longest name S3 allows, and 64: the first it does not. */
    static const char name63[] = "a23456789012345678901234567890123456789012345678901234567890123";
    static const char name64[] = "a234567890123456789012345678901234567890123456789012345678901234";
    static const char *const ok[] = {"abc", "a-b.c", "lkbucket", "192-168-1-1", "1a2", name63};
    static const char *const bad[] = {"AB",          "a",       "ab",      "a_b_c",
                                      "192.168.1.1", "bucket.", ".bucket", "bucket..name",
                                      "-bucket",     "buck$et", name64};

    for (unsigned i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        if (!lk_s3_bucket_valid(ok[i], (uint32_t)strlen(ok[i]))) {
            fprintf(stderr, "FAIL: '%s' should be a valid bucket name\n", ok[i]);
            return 1;
        }
    }
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (lk_s3_bucket_valid(bad[i], (uint32_t)strlen(bad[i]))) {
            fprintf(stderr, "FAIL: '%s' should be rejected\n", bad[i]);
            return 1;
        }
    }
    CHECK(!lk_s3_bucket_valid(NULL, 0));
    return 0;
}

/* --- MinIO's own surface, and the rubbish a port collects ------------------ */

static int test_internal(void)
{
    /* Pointer identity, not spelling: `internal` is the one operation a
     * consumer has to *recognise* rather than merely report — МS2 counts it and
     * never turns it into an observation — so the sentinel is compared, and a
     * bucket a client happened to name `internal` cannot impersonate it. */
    CHECK(op_of(NULL, "GET", "/minio/health/live", NULL, 0) == lk_s3_op_internal());
    CHECK(op_of(NULL, "PROPFIND", "/b/k", NULL, 0) == lk_s3_op_other());
    CHECK(op_of(NULL, "GET", "/internal/k", NULL, 0) != lk_s3_op_internal());

    CHECK(op_is("GET", "/minio/health/live", "internal"));
    CHECK(op_is("GET", "/minio/health/cluster", "internal"));
    CHECK(op_is("GET", "/minio/admin/v3/info", "internal"));
    CHECK(op_is("POST", "/minio/peer/v40/loadbucketmetadata", "internal"));
    CHECK(op_is("GET", "/minio", "internal"));
    /* A bucket whose name merely *starts* with the prefix is not internal. */
    CHECK(op_is("GET", "/miniobucket/key", "GetObject"));
    CHECK(op_is("GET", "/minio-data", "ListObjects"));

    /* ... but in virtual-host style the whole path is an object key, and a
     * client is entitled to store one called `minio/health/live`. */
    {
        static const char *const dom = "localhost";
        struct lk_s3_cfg cfg = {.domains = {dom}, .ndomains = 1};

        CHECK(!strcmp(op_of("b.localhost", "GET", "/minio/health/live", &cfg, 0), "GetObject"));
    }
    return 0;
}

static int test_garbage(void)
{
    CHECK(op_is("PROPFIND", "/b/k", "other"));
    CHECK(op_is("get", "/b/k", "other")); /* methods are case-sensitive */
    CHECK(op_is("", "/b/k", "other"));
    CHECK(op_is("GET", "///", "other")); /* an empty first segment is no bucket */
    CHECK(op_is("PUT", "/", "other"));   /* there is no such thing as PUT service */
    CHECK(op_is("GET", "/../../etc/passwd", "GetObject")); /* a key, and only a key */
    CHECK(op_is("GET", "/b/k?\x01\x02", "GetObject"));
    /* `%2F` is not a separator: an encoded slash lives *inside* one key, which
     * is why nothing here decodes the path (`encoded-keys.lkt`). */
    CHECK(op_is("GET", "/b/a%2Fb%2Fc", "GetObject"));
    CHECK(op_is("GET", "/b%2Fk", "ListObjects")); /* ... including in the bucket segment */
    return 0;
}

/* --- the closed-set invariant (МS1 acceptance) ----------------------------- */

/* Is this pointer one of the table's own? Pointer identity, not strcmp: the
 * claim is that lk_s3_op never *builds* a string, which is what bounds the
 * label's cardinality at compile time (РS2). A classifier that returned a slice
 * of the input would pass a text comparison and fail this. */
static bool in_table(const char *op)
{
    for (uint32_t i = 0; lk_s3_op_at(i); i++) {
        if (lk_s3_op_at(i) == op)
            return true;
    }
    return false;
}

static int test_closed_set(void)
{
    static const char *const seg[] = {"b",     "k",      "acl",   "uploads", "..",   "%2F",
                                      "minio", "health", "a.b-c", "",        "?x=1", "\xff\xfe"};
    static const char *const meth[] = {"GET", "PUT", "POST", "DELETE", "HEAD", "PROPFIND", "g"};
    static const char *const dom = "s3.example.com";
    struct lk_s3_cfg cfg = {.domains = {dom}, .ndomains = 1};
    uint32_t x = 0x12345678;
    char path[128], host[64];

    /* A million paths built out of hostile-looking pieces — encoded slashes,
     * traversal, high bytes, the internal prefix, empty segments — under both
     * addressing forms and every method the table knows plus two it does not.
     * Not one of them may produce a label outside the table. */
    for (uint32_t i = 0; i < 1000000; i++) {
        uint32_t n, len = 0;
        const char *op, *h = NULL;

        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        n = 1 + (x % 6);
        for (uint32_t k = 0; k < n && len + 24 < sizeof(path); k++) {
            const char *s = seg[(x >> (k * 3)) % (sizeof(seg) / sizeof(seg[0]))];

            path[len++] = '/';
            len += (uint32_t)snprintf(path + len, sizeof(path) - len, "%s", s);
        }
        path[len] = '\0';
        if (x & 0x40000000) {
            snprintf(host, sizeof(host), "%s.s3.example.com",
                     seg[(x >> 9) % (sizeof(seg) / sizeof(seg[0]))]);
            h = host;
        }
        op = op_of(h, meth[(x >> 21) % (sizeof(meth) / sizeof(meth[0]))], path, &cfg,
                   (x & 0x80000000) ? LK_S3_F_COPY_SRC : 0);
        if (!in_table(op)) {
            fprintf(stderr, "FAIL: '%s' produced an op outside the table: '%s'\n", path, op);
            return 1;
        }
    }
    return 0;
}

/* --- which operations move an object (МS2) --------------------------------- */

/* The four names that feed latkit_s3_object_size_bytes are compared as strings
 * (the caller holds a copy of the operation, not the table entry), so they can
 * drift from the table without anything failing to compile. Here they cannot:
 * each must be a value the classifier can actually produce, and the operations
 * whose bodies are *not* object data must stay out. */
static int test_data_ops(void)
{
    const char *op;

    for (uint32_t i = 0; (op = lk_s3_data_op_at(i)); i++) {
        CHECK(in_table(op));
        CHECK(lk_s3_op_is_data(op, (uint32_t)strlen(op)));
    }
    CHECK(lk_s3_op_is_data("GetObject", 9));
    CHECK(lk_s3_op_is_data("UploadPart", 10));
    /* A listing, a manifest, an event stream and a server-side copy all carry
     * payload, and none of it is an object (РS7). */
    CHECK(!lk_s3_op_is_data("ListObjectsV2", 13));
    CHECK(!lk_s3_op_is_data("CompleteMultipartUpload", 23));
    CHECK(!lk_s3_op_is_data("SelectObjectContent", 19));
    CHECK(!lk_s3_op_is_data("CopyObject", 10));
    CHECK(!lk_s3_op_is_data("UploadPartCopy", 14));
    CHECK(!lk_s3_op_is_data("HeadObject", 10));
    CHECK(!lk_s3_op_is_data("other", 5));
    CHECK(!lk_s3_op_is_data("internal", 8));
    /* Length-honest: a prefix of a data op is not one. */
    CHECK(!lk_s3_op_is_data("GetObjectTagging", 16));
    CHECK(!lk_s3_op_is_data("GetObject", 3));
    CHECK(!lk_s3_op_is_data(NULL, 0));
    return 0;
}

/* --- the fingerprint ------------------------------------------------------- */

static int test_fingerprint(void)
{
    struct lk_route_out a, b;
    struct lk_s3_addr ad;

    lk_s3_split(false, "/lkbucket/small.bin", 19, &ad);
    lk_norm_s3("GET", 3, NULL, 0, &ad, 0, &a);
    CHECK(!strcmp(a.text, "GetObject") && a.text_len == 9);
    CHECK(a.flags & LK_ROUTE_F_TEMPLATED);

    /* The identity is `method NUL operation`, exactly as for a templated route:
     * a different *key* is the same identity, and a different method is not. */
    lk_s3_split(false, "/lkbucket/other.bin", 19, &ad);
    lk_norm_s3("GET", 3, NULL, 0, &ad, 0, &b);
    CHECK(a.fp == b.fp);

    lk_s3_split(false, "/lkbucket/small.bin", 19, &ad);
    lk_norm_s3("HEAD", 4, NULL, 0, &ad, 0, &b);
    CHECK(!strcmp(b.text, "HeadObject") && a.fp != b.fp);
    return 0;
}

int main(void)
{
    if (test_shapes() || test_listings() || test_multipart() || test_copy_source() ||
        test_subresources() || test_addressing() || test_bucket_names() || test_internal() ||
        test_garbage() || test_data_ops() || test_fingerprint() || test_closed_set())
        return 1;
    printf("test_s3_op: all ok\n");
    return 0;
}
