/* SPDX-License-Identifier: GPL-2.0 */
/* S3 request classification (РS2/РS3, PLAN-MINIO.md МS1) — the norm_route.h of
 * the S3 dialect, and the reason that dialect needs almost no code of its own.
 *
 * norm_route.h exists because a URL has no bounded identity: `/orders/8123` is
 * one of millions of paths a single handler serves, so the label has to be
 * *reconstructed* by a heuristic and then bounded again by a top-K dictionary.
 * S3 has the property that HTTP lacks. The API is a closed set of operations,
 * and which operation a request is can be read off `(method, path shape, query
 * keys)` alone — so the answer here is a **lookup in a fixed table**, the
 * heuristic of РH7 is switched off entirely, and the cardinality of the `op`
 * label is bounded by construction rather than by a downstream dictionary.
 *
 * Three things live here, and all three are the same kind of thing: a value
 * that arrives from the wire and may become a Prometheus label only after it
 * has been checked against a closed set.
 *
 *   1. **the operation** (lk_s3_op): the table of docs/notes-s3proto.md
 *      §"The operation table", `/minio/…` folded into `internal`, everything
 *      unrecognised into `other`. The object key is not an input to any rule
 *      and never leaves this file — it is the most sensitive part of an S3
 *      request and it is not a candidate for a label at any point (РS2).
 *   2. **the bucket** (lk_s3_addr): located path-style or virtual-host-style
 *      and then validated against the S3 naming rules, because a name that
 *      fails them is a hostile or broken client writing arbitrary bytes into a
 *      label. Anything that fails → `other` (РS3).
 *   3. **the error code** (lk_s3_code_known): the symbolic `<Code>` of an S3
 *      error body, matched against a dictionary of known codes so a server that
 *      invents one cannot invent a series with it (РS5).
 *
 * Pure, like the rest of src/norm: no I/O, no allocation, no globals. Every
 * accessor takes an explicit (pointer, length) pair — nothing here is
 * NUL-terminated, because none of it is NUL-terminated on the wire. */
#ifndef LATKIT_NORM_S3_H
#define LATKIT_NORM_S3_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "norm_route.h" /* struct lk_route_out: the op travels in the route slot */

/* A bucket name is 3..63 bytes by the S3 rules, so 64 holds the longest one
 * with its terminator — and it is also sizeof(lk_session.database), the dim
 * slot the bucket occupies (РS3). */
#define LK_S3_BUCKET_MAX 64

/* The longest known S3 error code is `ServerSideEncryptionConfigurationNot
 * FoundError` at 45 bytes; 48 holds it and the terminator. */
#define LK_S3_CODE_MAX 48

/* An access key ID is 20 characters for a long-lived pair and up to ~32 for an
 * STS one; 40 covers both and matches LK_HTTP_USER_MAX, the slot it lands in. */
#define LK_S3_AK_MAX 40

/* `--s3-domain` suffixes. Eight is generous: a deployment answers on one or two
 * names, and every extra one is a linear compare on the request path. */
#define LK_S3_DOMAIN_MAX 8

/* The only thing outside `(method, path shape, query keys)` that takes part in
 * classification: the presence of one header (notes-s3proto.md §"The operation
 * table"). Its *value* is a bucket and key on another server and is never read. */
#define LK_S3_F_COPY_SRC (1 << 0) /* `x-amz-copy-source`: Put→Copy, UploadPart→Copy */

struct lk_s3_cfg {
    /* `--s3-domain s3.example.com` (repeatable): the suffixes under which a
     * leading Host label names a bucket. Empty by default, and then *every*
     * request is read path-style — which is the safe reading, because MinIO
     * itself refuses virtual-host addressing unless MINIO_DOMAIN is set, and
     * `GET /x` against `Host: photos.minio` is `photos/x` or a ListObjects on
     * bucket `x` depending on a server-side setting we cannot see (РS3). */
    const char *domains[LK_S3_DOMAIN_MAX]; /* borrowed, NUL-terminated */
    uint8_t ndomains;
    bool no_user; /* `--s3-user off`: never derive a user label from a signature */
};

/* Where the bucket and the key are in one request. Both are borrowed spans into
 * the caller's target/host; `key` exists so the shape rules can tell "bucket
 * level" from "object level" and for **no other purpose** — it is never copied,
 * never hashed and never reported (РS2). */
struct lk_s3_addr {
    const char *bucket;
    uint32_t bucket_len; /* 0 = service level (`/`) or a Host we could not read */
    const char *key;
    uint32_t key_len; /* 0 = bucket level; a trailing `/` is not a key */
    bool vhost;       /* the bucket came from the Host, not from the path */
    bool valid;       /* ... and it passes the S3 naming rules, so it may be a label */
    bool internal;    /* the path is MinIO's own API (`/minio/…`), so there is no
                         bucket here and the first segment must not be read as
                         one — on a single node `/minio/storage/…` otherwise
                         falls through to the S3 router and answers `404
                         NoSuchBucket` for a bucket named `minio` (РS2) */
};

/* Locate the bucket. `host` is the request's authority with any port still on
 * it (the caller's Host header or absolute-form authority); `path` is the
 * request-target's path, query already split off.
 *
 * Always succeeds and always fills `out`: a target of garbage is service level
 * with no bucket, which is exactly what it should report. */
void lk_s3_addr(const char *host, uint32_t host_len, const char *path, uint32_t path_len,
                const struct lk_s3_cfg *cfg, struct lk_s3_addr *out);

/* The path half of the same decision, for a caller that already knows which
 * addressing form this request used. The label extractor decides the form once,
 * at the request head, and by the time the classifier runs the bucket has
 * *replaced* the Host in the unit's dim slot — so re-deciding from the host
 * there would read a bucket as a hostname. One decision per request, made where
 * the evidence is (РS3).
 *
 * With `vhost` the whole path is the key and `bucket` comes back empty: the
 * classifier only ever asks the path how deep it is, never what the bucket is
 * called. */
void lk_s3_split(bool vhost, const char *path, uint32_t path_len, struct lk_s3_addr *out);

/* The S3 bucket naming rules (notes-s3proto.md §"Addressing"): 3..63 bytes of
 * `[a-z0-9.-]`, alphanumeric at both ends, no `..`, and not an IPv4 address.
 * MinIO enforces the same set and answers `400 InvalidBucketName` outside it, so
 * a name this accepts is a name the server would have routed. */
bool lk_s3_bucket_valid(const char *p, uint32_t n);

/* The operation this request is, as a borrowed pointer into a static table:
 * `"GetObject"`, `"ListObjectsV2"`, … plus `"internal"` for MinIO's own surface
 * and `"other"` for anything the table does not know. Never NULL, never
 * allocated, never derived from the object key.
 *
 * `flags` carries LK_S3_F_COPY_SRC; `a` is the addressing decision from
 * lk_s3_addr or lk_s3_split, and it is the *only* thing the path is consulted
 * through — passing the decision in rather than the bytes is what keeps "which
 * segment is the bucket" a single answer per request, and what makes "no rule
 * depends on the object key" checkable by reading this signature. */
const char *lk_s3_op(const char *method, uint32_t method_len, const char *query, uint32_t query_len,
                     const struct lk_s3_addr *a, uint16_t flags);

/* The two sentinels above, as pointers, so a caller can compare rather than
 * strcmp: `lk_s3_op_internal()` is what MinIO's own `/minio/…` traffic
 * classifies to and the one operation that must never become an observation. */
const char *lk_s3_op_internal(void);
const char *lk_s3_op_other(void);

/* Enumerate the operation table: call with i = 0, 1, … until it returns NULL.
 * Every value lk_s3_op can produce appears here, `internal` and `other`
 * included — which is what lets a test state the closed-set invariant ("the set
 * of `op` labels is a subset of the table") against the table itself rather
 * than against a copy of it that can drift. */
const char *lk_s3_op_at(uint32_t i);

/* Does this operation's body carry object data (МS2/РS7)? True for the four
 * operations that move an object's own bytes over the wire, false for every
 * other payload an S3 exchange can carry — a listing, a key list, a multipart
 * manifest, an event stream, an error document. It is what decides whether an
 * exchange's size belongs in `latkit_s3_object_size_bytes`, and it takes the
 * operation *name* because the caller holds the observation's copy of it rather
 * than the table entry. lk_s3_data_op_at enumerates the four (i = 0, 1, … until
 * NULL) so a test can hold them against the table. */
bool lk_s3_op_is_data(const char *op, uint32_t n);
const char *lk_s3_data_op_at(uint32_t i);

/* Is this a code the AWS/MinIO error vocabulary defines? Unknown codes fold to
 * `s3code="other"` upstream — a server is free to invent a code and must not be
 * free to invent a series (РS5). */
bool lk_s3_code_known(const char *p, uint32_t n);

/* One classification, in the shape http_route.c wants back: `out->text` is the
 * operation, `out->fp` is XXH3-64 of `method NUL operation` — the same identity
 * rule as the base dialect, so two methods on one operation name stay two
 * routes. `out->flags` carries LK_ROUTE_F_* (only F_TEMPLATED, meaning "this is
 * a name, not a path"). */
void lk_norm_s3(const char *method, uint32_t method_len, const char *query, uint32_t query_len,
                const struct lk_s3_addr *a, uint16_t flags, struct lk_route_out *out);

/* Fuzz entry (the lk_norm_route_fuzz_one twin): split the input into a host, a
 * method and a target, classify, and assert the invariant the whole label bound
 * rests on — the operation is a pointer *into the table*, never into the input.
 * Returns 0 always. */
int lk_norm_s3_fuzz_one(const uint8_t *data, size_t n);

#endif /* LATKIT_NORM_S3_H */
