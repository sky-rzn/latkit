// SPDX-License-Identifier: GPL-2.0
/* S3 request classification (РS2/РS3/РS5, PLAN-MINIO.md МS1). See norm_s3.h for
 * the contract; this file is the table and the three walks over it.
 *
 * Shape of one classification:
 *
 *     Host ──┬─ suffix match ──▶ virtual-host style: bucket = the Host prefix
 *            └─ no match ──────▶ path style:         bucket = the first segment
 *                                                            │
 *     path ──┬─ /minio/… ─────────────────────────────▶ "internal"
 *            └─ how many segments past the bucket ──▶ service | bucket | object
 *                                                            │
 *     query ── first *recognised* key ──┐                     │
 *                                        └──▶ (key, level, method, copy?) ──▶ row
 *                                                            │
 *                                             no row ────────┴──▶ "other"
 *
 * Three properties are the whole point of doing it this way:
 *
 *   - **the answer is a pointer into the table.** lk_s3_op never builds a
 *     string, so the set of values it can return is the set of values written
 *     here, and the `op` label's cardinality is a compile-time constant rather
 *     than a hope about the input (РS2). The fuzz entry at the bottom asserts
 *     exactly that.
 *   - **the object key is an input to nothing.** The classifier asks the path
 *     how many segments it has and never what they say; the key is not copied,
 *     not hashed and not compared. It is the most sensitive part of an S3
 *     request (notes-s3proto.md §"Errors") and the safest way to keep it out of
 *     a label is for no rule to depend on it.
 *   - **an unknown query key is ignored, an unknown shape is `other`.** A
 *     future `?newthing` on `/{bucket}/{key}` still classifies as a GetObject;
 *     a shape the table does not describe folds into one bounded bucket whose
 *     *share* is the dashboard's signal that the taxonomy has aged (риск 5). */
#include "norm_s3.h"

#include <string.h>

/* Header-only XXH3, as in norm_route.c: the implementation lands in this TU. */
#define XXH_INLINE_ALL
#include "xxhash.h"

/* --- methods, levels, and the copy-source distinction --------------------- */

/* The five methods S3 uses. Anything else — a WebDAV verb, a typo, a method a
 * scanner made up — is S3_M_NONE, which no row carries and which therefore
 * classifies as `other`. Zero on purpose: a row nobody filled in matches
 * nothing rather than matching GET. */
enum s3_m { S3_M_NONE = 0, S3_M_GET, S3_M_HEAD, S3_M_PUT, S3_M_POST, S3_M_DELETE };

/* The three path shapes, after the bucket has been located. A trailing slash on
 * a bucket is *not* a key: `mc` sends `GET /lkbucket/?location=` and aws-cli
 * sends `GET /lkbucket?location=` for the same operation. */
enum s3_lvl { S3_L_SERVICE = 0, S3_L_BUCKET, S3_L_OBJECT };

/* Whether a row needs `x-amz-copy-source`. Two operation pairs differ by that
 * header and by nothing else on the wire (PutObject/CopyObject,
 * UploadPart/UploadPartCopy), so the constraint is part of the row rather than
 * a special case around the lookup. */
enum s3_copy { S3_C_ANY = 0, S3_C_NO, S3_C_YES };

/* The recognised sub-resource keys (notes-s3proto.md §"The operation table",
 * step 2). Only their *presence* matters — never their value, with the single
 * exception of S3_K_LIST_TYPE, whose `=2` is a documented enum and not user
 * input.
 *
 * A row below names a key by this enum rather than by its text, so a row and
 * the key table cannot drift apart over a spelling and the lookup is an integer
 * compare. S3_K_NONE is index 0 and means "no sub-resource": the shape rules. */
enum s3_key {
    S3_K_NONE = 0,
    S3_K_ACL,
    S3_K_TAGGING,
    S3_K_POLICY,
    S3_K_POLICY_STATUS,
    S3_K_VERSIONING,
    S3_K_LIFECYCLE,
    S3_K_LOCATION,
    S3_K_NOTIFICATION,
    S3_K_ENCRYPTION,
    S3_K_REPLICATION,
    S3_K_OBJECT_LOCK,
    S3_K_CORS,
    S3_K_ACCELERATE,
    S3_K_LOGGING,
    S3_K_REQUEST_PAYMENT,
    S3_K_WEBSITE,
    S3_K_PUBLIC_ACCESS_BLOCK,
    S3_K_ATTRIBUTES,
    S3_K_RETENTION,
    S3_K_LEGAL_HOLD,
    S3_K_RESTORE,
    S3_K_SELECT,
    S3_K_DELETE,
    S3_K_UPLOADS,
    S3_K_UPLOAD_ID,
    S3_K_VERSIONS,
    S3_K_LIST_TYPE,
    S3_K_MAX,
};

/* The lengths are precomputed because this array is walked once per query key
 * of every request, and a length compare rejects almost all of them before a
 * single byte is looked at. */
static const struct {
    const char *s;
    uint8_t n;
} s3_subres[S3_K_MAX] = {
    [S3_K_ACL] = {"acl", 3},
    [S3_K_TAGGING] = {"tagging", 7},
    [S3_K_POLICY] = {"policy", 6},
    [S3_K_POLICY_STATUS] = {"policyStatus", 12},
    [S3_K_VERSIONING] = {"versioning", 10},
    [S3_K_LIFECYCLE] = {"lifecycle", 9},
    [S3_K_LOCATION] = {"location", 8},
    [S3_K_NOTIFICATION] = {"notification", 12},
    [S3_K_ENCRYPTION] = {"encryption", 10},
    [S3_K_REPLICATION] = {"replication", 11},
    [S3_K_OBJECT_LOCK] = {"object-lock", 11},
    [S3_K_CORS] = {"cors", 4},
    [S3_K_ACCELERATE] = {"accelerate", 10},
    [S3_K_LOGGING] = {"logging", 7},
    [S3_K_REQUEST_PAYMENT] = {"requestPayment", 14},
    [S3_K_WEBSITE] = {"website", 7},
    [S3_K_PUBLIC_ACCESS_BLOCK] = {"publicAccessBlock", 17},
    [S3_K_ATTRIBUTES] = {"attributes", 10},
    [S3_K_RETENTION] = {"retention", 9},
    [S3_K_LEGAL_HOLD] = {"legal-hold", 10},
    [S3_K_RESTORE] = {"restore", 7},
    [S3_K_SELECT] = {"select", 6},
    [S3_K_DELETE] = {"delete", 6},
    [S3_K_UPLOADS] = {"uploads", 7},
    [S3_K_UPLOAD_ID] = {"uploadId", 8},
    [S3_K_VERSIONS] = {"versions", 8},
    [S3_K_LIST_TYPE] = {"list-type", 9},
};

struct s3_row {
    uint8_t key;    /* enum s3_key; S3_K_NONE = the shape rules */
    uint8_t lvl;    /* enum s3_lvl */
    uint8_t method; /* enum s3_m */
    uint8_t copy;   /* enum s3_copy */
    const char *op;
};

/* The operation table. Rows with a `copy` constraint come before their
 * unconstrained twin so the first match is the specific one.
 *
 * The status column of notes-s3proto.md §"The table" is deliberately *not* here:
 * "S3 defines this operation" and "MinIO answers it" are different claims, and
 * only the first one belongs in a classifier — a `501 NotImplemented` still has
 * an operation, and reporting it as `other` would hide exactly the request an
 * operator wants to see. */
static const struct s3_row s3_rows[] = {
    /* --- service level ---------------------------------------------------- */
    {S3_K_NONE, S3_L_SERVICE, S3_M_GET, S3_C_ANY, "ListBuckets"},

    /* --- bucket level, sub-resources -------------------------------------- */
    {S3_K_ACL, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketAcl"},
    {S3_K_ACL, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketAcl"},
    {S3_K_TAGGING, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketTagging"},
    {S3_K_TAGGING, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketTagging"},
    {S3_K_TAGGING, S3_L_BUCKET, S3_M_DELETE, S3_C_ANY, "DeleteBucketTagging"},
    {S3_K_POLICY, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketPolicy"},
    {S3_K_POLICY, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketPolicy"},
    {S3_K_POLICY, S3_L_BUCKET, S3_M_DELETE, S3_C_ANY, "DeleteBucketPolicy"},
    {S3_K_POLICY_STATUS, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketPolicyStatus"},
    {S3_K_VERSIONING, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketVersioning"},
    {S3_K_VERSIONING, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketVersioning"},
    {S3_K_LIFECYCLE, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketLifecycleConfiguration"},
    {S3_K_LIFECYCLE, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketLifecycleConfiguration"},
    {S3_K_LIFECYCLE, S3_L_BUCKET, S3_M_DELETE, S3_C_ANY, "DeleteBucketLifecycleConfiguration"},
    {S3_K_LOCATION, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketLocation"},
    {S3_K_NOTIFICATION, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketNotificationConfiguration"},
    {S3_K_NOTIFICATION, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketNotificationConfiguration"},
    {S3_K_ENCRYPTION, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketEncryption"},
    {S3_K_ENCRYPTION, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketEncryption"},
    {S3_K_ENCRYPTION, S3_L_BUCKET, S3_M_DELETE, S3_C_ANY, "DeleteBucketEncryption"},
    {S3_K_REPLICATION, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketReplication"},
    {S3_K_REPLICATION, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketReplication"},
    {S3_K_REPLICATION, S3_L_BUCKET, S3_M_DELETE, S3_C_ANY, "DeleteBucketReplication"},
    {S3_K_OBJECT_LOCK, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetObjectLockConfiguration"},
    {S3_K_OBJECT_LOCK, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutObjectLockConfiguration"},
    {S3_K_CORS, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketCors"},
    {S3_K_CORS, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketCors"},
    {S3_K_CORS, S3_L_BUCKET, S3_M_DELETE, S3_C_ANY, "DeleteBucketCors"},
    {S3_K_ACCELERATE, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketAccelerateConfiguration"},
    {S3_K_ACCELERATE, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketAccelerateConfiguration"},
    {S3_K_LOGGING, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketLogging"},
    {S3_K_LOGGING, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketLogging"},
    {S3_K_REQUEST_PAYMENT, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketRequestPayment"},
    {S3_K_REQUEST_PAYMENT, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketRequestPayment"},
    {S3_K_WEBSITE, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetBucketWebsite"},
    {S3_K_WEBSITE, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutBucketWebsite"},
    {S3_K_WEBSITE, S3_L_BUCKET, S3_M_DELETE, S3_C_ANY, "DeleteBucketWebsite"},
    {S3_K_PUBLIC_ACCESS_BLOCK, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "GetPublicAccessBlock"},
    {S3_K_PUBLIC_ACCESS_BLOCK, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "PutPublicAccessBlock"},
    {S3_K_PUBLIC_ACCESS_BLOCK, S3_L_BUCKET, S3_M_DELETE, S3_C_ANY, "DeletePublicAccessBlock"},
    {S3_K_DELETE, S3_L_BUCKET, S3_M_POST, S3_C_ANY, "DeleteObjects"},
    {S3_K_UPLOADS, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "ListMultipartUploads"},
    {S3_K_VERSIONS, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "ListObjectVersions"},
    {S3_K_LIST_TYPE, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "ListObjectsV2"},

    /* --- bucket level, shape ---------------------------------------------- */
    {S3_K_NONE, S3_L_BUCKET, S3_M_GET, S3_C_ANY, "ListObjects"},
    {S3_K_NONE, S3_L_BUCKET, S3_M_PUT, S3_C_ANY, "CreateBucket"},
    {S3_K_NONE, S3_L_BUCKET, S3_M_DELETE, S3_C_ANY, "DeleteBucket"},
    {S3_K_NONE, S3_L_BUCKET, S3_M_HEAD, S3_C_ANY, "HeadBucket"},
    {S3_K_NONE, S3_L_BUCKET, S3_M_POST, S3_C_ANY, "PostObject"},

    /* --- object level, sub-resources -------------------------------------- */
    {S3_K_ACL, S3_L_OBJECT, S3_M_GET, S3_C_ANY, "GetObjectAcl"},
    {S3_K_ACL, S3_L_OBJECT, S3_M_PUT, S3_C_ANY, "PutObjectAcl"},
    {S3_K_TAGGING, S3_L_OBJECT, S3_M_GET, S3_C_ANY, "GetObjectTagging"},
    {S3_K_TAGGING, S3_L_OBJECT, S3_M_PUT, S3_C_ANY, "PutObjectTagging"},
    {S3_K_TAGGING, S3_L_OBJECT, S3_M_DELETE, S3_C_ANY, "DeleteObjectTagging"},
    {S3_K_RETENTION, S3_L_OBJECT, S3_M_GET, S3_C_ANY, "GetObjectRetention"},
    {S3_K_RETENTION, S3_L_OBJECT, S3_M_PUT, S3_C_ANY, "PutObjectRetention"},
    {S3_K_LEGAL_HOLD, S3_L_OBJECT, S3_M_GET, S3_C_ANY, "GetObjectLegalHold"},
    {S3_K_LEGAL_HOLD, S3_L_OBJECT, S3_M_PUT, S3_C_ANY, "PutObjectLegalHold"},
    {S3_K_ATTRIBUTES, S3_L_OBJECT, S3_M_GET, S3_C_ANY, "GetObjectAttributes"},
    {S3_K_RESTORE, S3_L_OBJECT, S3_M_POST, S3_C_ANY, "RestoreObject"},
    {S3_K_SELECT, S3_L_OBJECT, S3_M_POST, S3_C_ANY, "SelectObjectContent"},
    {S3_K_UPLOADS, S3_L_OBJECT, S3_M_POST, S3_C_ANY, "CreateMultipartUpload"},
    /* `?uploadId` alone is ambiguous by method and only by method: four
     * operations share the key and the method is what separates them. */
    {S3_K_UPLOAD_ID, S3_L_OBJECT, S3_M_PUT, S3_C_YES, "UploadPartCopy"},
    {S3_K_UPLOAD_ID, S3_L_OBJECT, S3_M_PUT, S3_C_NO, "UploadPart"},
    {S3_K_UPLOAD_ID, S3_L_OBJECT, S3_M_GET, S3_C_ANY, "ListParts"},
    {S3_K_UPLOAD_ID, S3_L_OBJECT, S3_M_POST, S3_C_ANY, "CompleteMultipartUpload"},
    {S3_K_UPLOAD_ID, S3_L_OBJECT, S3_M_DELETE, S3_C_ANY, "AbortMultipartUpload"},

    /* --- object level, shape ---------------------------------------------- */
    {S3_K_NONE, S3_L_OBJECT, S3_M_GET, S3_C_ANY, "GetObject"},
    {S3_K_NONE, S3_L_OBJECT, S3_M_HEAD, S3_C_ANY, "HeadObject"},
    {S3_K_NONE, S3_L_OBJECT, S3_M_PUT, S3_C_YES, "CopyObject"},
    {S3_K_NONE, S3_L_OBJECT, S3_M_PUT, S3_C_NO, "PutObject"},
    {S3_K_NONE, S3_L_OBJECT, S3_M_DELETE, S3_C_ANY, "DeleteObject"},
};

/* MinIO's own surface, which is never an S3 operation: counted, never observed
 * (РS2). `other` is everything the table does not describe. Both are ordinary
 * table values so that "the label set is closed" needs no exception. */
static const char s3_op_internal[] = "internal";
static const char s3_op_other[] = "other";

const char *lk_s3_op_internal(void)
{
    return s3_op_internal;
}

const char *lk_s3_op_other(void)
{
    return s3_op_other;
}

const char *lk_s3_op_at(uint32_t i)
{
    uint32_t n = (uint32_t)(sizeof(s3_rows) / sizeof(s3_rows[0]));

    if (i < n)
        return s3_rows[i].op;
    if (i == n)
        return s3_op_internal;
    if (i == n + 1)
        return s3_op_other;
    return NULL;
}

/* --- addressing (РS3) ----------------------------------------------------- */

static bool s3_is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static bool s3_is_lower_alnum(char c)
{
    return s3_is_digit(c) || (c >= 'a' && c <= 'z');
}

/* Four dot-separated decimal groups — an IPv4 address, which S3 refuses as a
 * bucket name because a virtual-host request for one would be unroutable. The
 * groups are not range-checked: `999.1.1.1` is not an address either, but it is
 * also not a name any server will accept, and the rule exists to reject a shape
 * rather than to validate an address. */
static bool s3_looks_ipv4(const char *p, uint32_t n)
{
    uint32_t i = 0, groups = 0;

    while (i < n) {
        uint32_t d = 0;

        while (i < n && s3_is_digit(p[i])) {
            i++;
            d++;
        }
        if (!d)
            return false;
        groups++;
        if (i == n)
            break;
        if (p[i] != '.')
            return false;
        i++;
    }
    return groups == 4;
}

bool lk_s3_bucket_valid(const char *p, uint32_t n)
{
    if (!p || n < 3 || n > LK_S3_BUCKET_MAX - 1)
        return false;
    if (!s3_is_lower_alnum(p[0]) || !s3_is_lower_alnum(p[n - 1]))
        return false;
    for (uint32_t i = 0; i < n; i++) {
        char c = p[i];

        if (!s3_is_lower_alnum(c) && c != '-' && c != '.')
            return false;
        if (c == '.' && i && p[i - 1] == '.')
            return false; /* `bucket..name` */
    }
    return !s3_looks_ipv4(p, n);
}

/* MinIO's own API, recognised before any shape rule and only in path style: on a
 * single node `/minio/storage/…` falls through to the S3 router and answers
 * `404 NoSuchBucket` for a bucket named `minio`, which is precisely the
 * misreading this prevents (notes-s3proto.md §"MinIO's own surface").
 *
 * Path style only, because in virtual-host style the whole path is an object key
 * and a client is entitled to store one called `minio/health/live`. */
static bool s3_path_internal(const char *path, uint32_t n)
{
    static const char pfx[] = "/minio";
    const uint32_t pn = sizeof(pfx) - 1;

    if (n < pn || memcmp(path, pfx, pn))
        return false;
    return n == pn || path[pn] == '/';
}

void lk_s3_split(bool vhost, const char *path, uint32_t path_len, struct lk_s3_addr *out)
{
    uint32_t i = 0;

    memset(out, 0, sizeof(*out));
    out->vhost = vhost;
    if (!path)
        path_len = 0;
    if (!vhost && s3_path_internal(path, path_len)) {
        /* Not a bucket and not a key: the server's own surface, located here so
         * that every caller — the classifier and the label extractor alike —
         * gets one answer and neither has to re-test the prefix. */
        out->internal = true;
        return;
    }
    if (path_len && path[0] == '/') {
        path++;
        path_len--;
    }
    if (vhost) {
        /* The bucket is in the Host, so every byte of the path is key — and a
         * key is exactly one thing here: a length that says "object level" or
         * "bucket level". */
        out->key = path;
        out->key_len = path_len;
        return;
    }
    while (i < path_len && path[i] != '/')
        i++;
    out->bucket = path;
    out->bucket_len = i;
    if (i < path_len) {
        out->key = path + i + 1;
        out->key_len = path_len - i - 1;
    }
    out->valid = lk_s3_bucket_valid(out->bucket, out->bucket_len);
}

void lk_s3_addr(const char *host, uint32_t host_len, const char *path, uint32_t path_len,
                const struct lk_s3_cfg *cfg, struct lk_s3_addr *out)
{
    uint32_t hn = 0;

    if (host) {
        /* The port is not part of the name. A bracketed IPv6 literal has no
         * label prefix and therefore never matches a suffix, so stopping at the
         * first colon is safe as well as short. */
        while (hn < host_len && host[hn] != ':')
            hn++;
    }
    if (cfg) {
        for (uint8_t k = 0; k < cfg->ndomains && k < LK_S3_DOMAIN_MAX; k++) {
            const char *d = cfg->domains[k];
            uint32_t dn = d ? (uint32_t)strlen(d) : 0;

            /* `<prefix>.<suffix>`: the prefix is the bucket, whole. Not "the
             * first label" — a bucket name may legally contain dots, so
             * `my.bucket.s3.example.com` is one bucket called `my.bucket`, and
             * cutting at the first dot would report a bucket nobody created. */
            if (!dn || hn <= dn + 1 || host[hn - dn - 1] != '.')
                continue;
            if (memcmp(host + hn - dn, d, dn))
                continue;
            lk_s3_split(true, path, path_len, out);
            out->bucket = host;
            out->bucket_len = hn - dn - 1;
            out->valid = lk_s3_bucket_valid(out->bucket, out->bucket_len);
            return;
        }
    }
    lk_s3_split(false, path, path_len, out);
}

/* --- the operation (РS2) -------------------------------------------------- */

static uint8_t s3_method(const char *m, uint32_t n)
{
    static const struct {
        const char *s;
        uint8_t n, id;
    } tab[] = {
        {"GET", 3, S3_M_GET},   {"PUT", 3, S3_M_PUT},       {"HEAD", 4, S3_M_HEAD},
        {"POST", 4, S3_M_POST}, {"DELETE", 6, S3_M_DELETE},
    };

    if (!m)
        return S3_M_NONE;
    for (unsigned i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        if (n == tab[i].n && !memcmp(m, tab[i].s, n)) /* methods are case-sensitive */
            return tab[i].id;
    }
    return S3_M_NONE;
}

/* The first recognised sub-resource key of a query string, plus its value.
 * Keys are compared case-sensitively and unrecognised ones are skipped rather
 * than rejected: a query we do not understand must not cost the operation. */
static uint8_t s3_subresource(const char *q, uint32_t qn, const char **val, uint32_t *val_len)
{
    uint32_t i = 0;

    *val = NULL;
    *val_len = 0;
    while (i < qn) {
        uint32_t ks = i, ke, ve;

        while (i < qn && q[i] != '&' && q[i] != '=')
            i++;
        ke = i;
        ve = i;
        if (i < qn && q[i] == '=') {
            i++;
            ve = i;
            while (i < qn && q[i] != '&')
                i++;
        }
        for (unsigned k = S3_K_NONE + 1; k < S3_K_MAX; k++) {
            if (ke - ks != s3_subres[k].n || memcmp(q + ks, s3_subres[k].s, s3_subres[k].n))
                continue;
            *val = q + ve;
            *val_len = i - ve;
            return (uint8_t)k;
        }
        if (i < qn)
            i++; /* the '&' */
    }
    return S3_K_NONE;
}

const char *lk_s3_op(const char *method, uint32_t method_len, const char *query, uint32_t query_len,
                     const struct lk_s3_addr *a, uint16_t flags)
{
    const char *val = NULL;
    uint32_t val_len = 0;
    uint8_t key, m, lvl, copy;

    if (!method)
        method_len = 0;
    if (!query)
        query_len = 0;

    if (a->internal)
        return s3_op_internal;

    m = s3_method(method, method_len);
    if (m == S3_M_NONE)
        return s3_op_other;
    copy = (flags & LK_S3_F_COPY_SRC) ? S3_C_YES : S3_C_NO;

    if (a->vhost || a->bucket_len)
        lvl = a->key_len ? S3_L_OBJECT : S3_L_BUCKET;
    else if (a->key_len)
        /* An empty first segment with something behind it (`///`, `//key`).
         * There is no bucket here and the rest is not a key of one, so this is
         * not a shape the table describes — and inventing a `ListBuckets` for it
         * would put a malformed request under the label of a real operation. */
        return s3_op_other;
    else
        lvl = S3_L_SERVICE;

    key = s3_subresource(query, query_len, &val, &val_len);
    /* The one query *value* that is read, and it is a documented enum rather
     * than user input: `list-type=2` is the V2 listing, anything else falls back
     * to the shape rules, where `GET /{bucket}` is already the V1 listing. */
    if (key == S3_K_LIST_TYPE && !(val_len == 1 && val[0] == '2'))
        key = S3_K_NONE;

    for (unsigned i = 0; i < sizeof(s3_rows) / sizeof(s3_rows[0]); i++) {
        const struct s3_row *r = &s3_rows[i];

        if (r->key != key || r->lvl != lvl || r->method != m)
            continue;
        if (r->copy != S3_C_ANY && r->copy != copy)
            continue;
        return r->op;
    }
    return s3_op_other;
}

/* --- error codes (РS5) ---------------------------------------------------- */

/* The AWS S3 error vocabulary plus the codes MinIO adds to it. A code outside
 * this list is reported as `other`: the code arrives in a response body and a
 * server that invents one must not be able to invent a series with it.
 *
 * The list is long and that is fine — it is walked only when a request actually
 * failed, and the alternative (trusting whatever the body said) is the one
 * shape of unbounded label this dialect otherwise does not have. */
static const char *const s3_codes[] = {
    "AccessDenied",
    "AccountProblem",
    "AllAccessDisabled",
    "AmbiguousGrantByEmailAddress",
    "AuthorizationHeaderMalformed",
    "AuthorizationQueryParametersError",
    "BadDigest",
    "BadRequest",
    "BucketAlreadyExists",
    "BucketAlreadyOwnedByYou",
    "BucketNotEmpty",
    "CredentialsNotSupported",
    "CrossLocationLoggingProhibited",
    "EntityTooLarge",
    "EntityTooSmall",
    "ExpiredToken",
    "IllegalVersioningConfigurationException",
    "IncompleteBody",
    "IncorrectNumberOfFilesInPostRequest",
    "InlineDataTooLarge",
    "InternalError",
    "InvalidAccessKeyId",
    "InvalidAddressingHeader",
    "InvalidArgument",
    "InvalidBucketName",
    "InvalidBucketState",
    "InvalidDigest",
    "InvalidEncryptionAlgorithmError",
    "InvalidLocationConstraint",
    "InvalidObjectState",
    "InvalidPart",
    "InvalidPartOrder",
    "InvalidPayer",
    "InvalidPolicyDocument",
    "InvalidRange",
    "InvalidRequest",
    "InvalidSOAPRequest",
    "InvalidSecurity",
    "InvalidStorageClass",
    "InvalidTargetBucketForLogging",
    "InvalidToken",
    "InvalidURI",
    "InvalidWriteOffset",
    "KeyTooLongError",
    "MalformedACLError",
    "MalformedPOSTRequest",
    "MalformedXML",
    "MaxMessageLengthExceeded",
    "MaxPostPreDataLengthExceededError",
    "MetadataTooLarge",
    "MethodNotAllowed",
    "MissingAttachment",
    "MissingContentLength",
    "MissingRequestBodyError",
    "MissingSecurityElement",
    "MissingSecurityHeader",
    "NoLoggingStatusForKey",
    "NoSuchAccessPoint",
    "NoSuchBucket",
    "NoSuchBucketPolicy",
    "NoSuchCORSConfiguration",
    "NoSuchKey",
    "NoSuchLifecycleConfiguration",
    "NoSuchObjectLockConfiguration",
    "NoSuchTagSet",
    "NoSuchUpload",
    "NoSuchVersion",
    "NoSuchWebsiteConfiguration",
    "NotImplemented",
    "NotSignedUp",
    "ObjectLockConfigurationNotFoundError",
    "OperationAborted",
    "PermanentRedirect",
    "PreconditionFailed",
    "Redirect",
    "ReplicationConfigurationNotFoundError",
    "RequestHeaderSectionTooLarge",
    "RequestIsNotMultiPartContent",
    "RequestTimeTooSkewed",
    "RequestTimeout",
    "RequestTorrentOfBucketError",
    "RestoreAlreadyInProgress",
    "ServerSideEncryptionConfigurationNotFoundError",
    "ServiceUnavailable",
    "SignatureDoesNotMatch",
    "SlowDown",
    "TemporaryRedirect",
    "TokenRefreshRequired",
    "TooManyBuckets",
    "TooManyParts",
    "UnexpectedContent",
    "UnresolvableGrantByEmailAddress",
    "UserKeyMustBeSpecified",
    "XAmzContentSHA256Mismatch",
    "XMinioInvalidObjectName",
    "XMinioMalformedIAMPolicy",
    "XMinioObjectExistsAsDirectory",
    "XMinioServerNotInitialized",
    "XMinioStorageFull",
};

bool lk_s3_code_known(const char *p, uint32_t n)
{
    if (!p || !n || n >= LK_S3_CODE_MAX)
        return false;
    for (unsigned i = 0; i < sizeof(s3_codes) / sizeof(s3_codes[0]); i++) {
        if (strlen(s3_codes[i]) == n && !memcmp(p, s3_codes[i], n))
            return true;
    }
    return false;
}

/* --- which operations move an object (МS2, РS7) --------------------------- */

/* The four whose body *is* object data. Everything else that carries a body
 * carries something else: a listing's XML, the key list of a `DeleteObjects`,
 * the manifest of a `CompleteMultipartUpload`, the event stream of a `Select`,
 * or an error document. All of those are payload and none of them is an object,
 * so `latkit_s3_object_size_bytes` would stop describing objects the moment it
 * counted them — a distribution mixing 300-byte error bodies with 64 MiB parts
 * says nothing about either. `CopyObject` and `UploadPartCopy` do move objects,
 * and deliberately not through us: the bytes stay inside the server, which is
 * the same documented blind spot `bytes_*` has for them.
 *
 * Names rather than pointers because the caller holds a *copy* of the operation
 * (the route text of an observation), not the table entry lk_s3_op returned.
 * test_s3_op checks every name here against the table, so a typo is a failing
 * test and not a family that quietly stopped recording. */
static const char *const s3_data_ops[] = {"GetObject", "PutObject", "UploadPart", "PostObject"};

bool lk_s3_op_is_data(const char *op, uint32_t n)
{
    if (!op)
        return false;
    for (uint32_t i = 0; i < sizeof(s3_data_ops) / sizeof(s3_data_ops[0]); i++)
        if (strlen(s3_data_ops[i]) == n && !memcmp(s3_data_ops[i], op, n))
            return true;
    return false;
}

const char *lk_s3_data_op_at(uint32_t i)
{
    return i < sizeof(s3_data_ops) / sizeof(s3_data_ops[0]) ? s3_data_ops[i] : NULL;
}

/* --- the entry point ------------------------------------------------------ */

void lk_norm_s3(const char *method, uint32_t method_len, const char *query, uint32_t query_len,
                const struct lk_s3_addr *a, uint16_t flags, struct lk_route_out *out)
{
    static const char nul = '\0';
    const char *op = lk_s3_op(method, method_len, query, query_len, a, flags);
    uint32_t n = (uint32_t)strlen(op);
    XXH3_state_t xh;

    if (!method)
        method_len = 0;
    /* No clip is possible and none is written for: every name in the table is
     * far shorter than LK_ROUTE_TEXT_MAX, which is the structural difference
     * between an operation and a path (РS2). */
    memcpy(out->text, op, n);
    out->text[n] = '\0';
    out->text_len = n;
    /* The identity rule is the base dialect's, unchanged: `method NUL name`, so
     * `GET ListParts` and `DELETE AbortMultipartUpload` stay two routes and a
     * per-operation latency panel reads the way РH7 promised. */
    XXH3_64bits_reset(&xh);
    XXH3_64bits_update(&xh, method, method_len);
    XXH3_64bits_update(&xh, &nul, 1);
    XXH3_64bits_update(&xh, op, n);
    out->fp = XXH3_64bits_digest(&xh);
    /* Not a path with its identifiers collapsed but a name from a closed set —
     * so it is "templated" in the only sense a consumer cares about: it is safe
     * to be a label. The second flag travels the one fact a consumer cannot
     * recover from the name: `internal` is the server's own surface and not an
     * S3 operation (РS2), which is what keeps a health-check flood out of every
     * family that says "requests" (МS2). By pointer, because that is the
     * property the table guarantees — `lk_s3_op` returns table entries and never
     * a slice of the input. */
    out->flags = LK_ROUTE_F_TEMPLATED;
    if (op == lk_s3_op_internal())
        out->flags |= LK_ROUTE_F_INTERNAL;
}

/* --- fuzz entry ----------------------------------------------------------- */

/* Input layout: `host \n method \n target`, so one flat byte string reaches the
 * Host suffix match, the method table, the path shapes and the query walk. The
 * `--s3-domain` suffix is taken from the host line's own tail, which is how the
 * mutator can make a suffix match happen at all.
 *
 * The invariant asserted here is the one the whole label bound rests on
 * (МS1 acceptance): the operation is a pointer *into the table*, so no input
 * can produce a value outside it. A returned pointer that is not one of the
 * table's own is a bug that no amount of string comparison would catch. */
int lk_norm_s3_fuzz_one(const uint8_t *data, size_t n)
{
    static volatile uint64_t sink;
    struct lk_s3_cfg cfg = {0};
    struct lk_s3_addr addr;
    struct lk_route_out out;
    const char *s = (const char *)data;
    const char *host = s, *method = s, *target = s;
    uint32_t hlen = 0, mlen = 0, tlen = (uint32_t)n;
    const char *nl, *op;
    char domain[64];
    uint64_t acc;
    bool found = false;

    nl = n ? memchr(s, '\n', n) : NULL;
    if (nl) {
        hlen = (uint32_t)(nl - s);
        method = nl + 1;
        tlen = (uint32_t)(n - hlen - 1);
        nl = memchr(method, '\n', tlen);
        if (nl) {
            mlen = (uint32_t)(nl - method);
            target = nl + 1;
            tlen = (uint32_t)(tlen - mlen - 1);
        } else {
            mlen = tlen;
            target = s;
            tlen = 0;
        }
    }
    /* A suffix the host can actually end with, so the virtual-host branch is
     * reachable rather than theoretical. */
    if (hlen > 2) {
        uint32_t dn = hlen / 2 < sizeof(domain) - 1 ? hlen / 2 : (uint32_t)sizeof(domain) - 1;

        memcpy(domain, host + hlen - dn, dn);
        domain[dn] = '\0';
        cfg.domains[0] = domain;
        cfg.ndomains = 1;
    }

    /* The target is split exactly as http_req.c splits it: path, then query. */
    {
        uint32_t plen = 0;

        while (plen < tlen && target[plen] != '?')
            plen++;
        lk_s3_addr(host, hlen, target, plen, &cfg, &addr);
        op = lk_s3_op(method, mlen, target + (plen < tlen ? plen + 1 : tlen),
                      plen < tlen ? tlen - plen - 1 : 0, &addr, LK_S3_F_COPY_SRC);
        lk_norm_s3(method, mlen, target + (plen < tlen ? plen + 1 : tlen),
                   plen < tlen ? tlen - plen - 1 : 0, &addr, 0, &out);
    }

    for (uint32_t i = 0; lk_s3_op_at(i); i++) {
        if (lk_s3_op_at(i) == op) {
            found = true;
            break;
        }
    }
    if (!found)
        __builtin_trap(); /* the closed-set invariant of РS2 */

    /* A bucket that made it past the validator must be a label-safe one, and a
     * key must never have been copied anywhere: the only way to check the
     * second is that there is nowhere for it to have been copied to. */
    if (addr.valid && !lk_s3_bucket_valid(addr.bucket, addr.bucket_len))
        __builtin_trap();

    acc = out.fp ^ out.text_len ^ out.flags;
    for (uint32_t i = 0; i <= out.text_len; i++)
        acc += (unsigned char)out.text[i];
    acc += lk_s3_code_known(target, tlen);
    sink += acc;
    return 0;
}
