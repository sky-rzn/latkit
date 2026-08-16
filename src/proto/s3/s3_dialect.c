// SPDX-License-Identifier: GPL-2.0
/* The S3 dialect (РS1–РS6, PLAN-MINIO.md МS1) — `--port 9000=s3`.
 *
 * This is the whole of what makes MinIO observable, and it is one file because
 * S3 *is* HTTP/1.1: the framer, the unit lifecycle, the four timings of РH5,
 * the body-length decision list, resync and the blind zones are the HTTP track's
 * and are shared byte for byte (РH8). lk_proto_s3_ops at the bottom is
 * lk_proto_http_ops with another lk_http_dialect hanging off it, and that is the
 * entire structural difference between the two protocols the agent speaks.
 *
 * What the dialect knows that the base one does not, in the order an exchange
 * reveals it:
 *
 *   req_field   `Authorization` → the access key ID and nothing else (РS4);
 *               `x-amz-copy-source` → the bit that turns a Put into a Copy;
 *               `x-amz-decoded-content-length` → the object's size behind the
 *               `aws-chunked` framing (РS6).
 *   req_head    the bucket, path-style or virtual-host-style, validated before
 *               it may be a label (РS3), into the same dim slot the base dialect
 *               uses for the host; and, for a presigned request, the access key
 *               out of the query string.
 *   resp_field  `x-amz-request-id` (the accuracy bench's join key),
 *               `x-amz-version-id`, and MinIO's `x-minio-error-code` — the only
 *               way to name the error of a HEAD, which has no body to carry one.
 *   err_body    `<Code>` out of a bounded prefix of a failing response's body
 *               (РS5), matched against a dictionary and dropped.
 *   classify    the operation, from a closed table (РS2).
 *   obs         the two fields the observation has no other source for: the
 *               symbolic error code and the logical object size.
 *
 * Two rules run through all of it, and they are the reason the file reads the
 * way it does:
 *
 *   - **the object key is never a label, and never anywhere else either.** It is
 *     not an input to the classifier, it is not copied out of the target, and
 *     the one place it unavoidably passes through — the error prefix, which
 *     carries `<Key>` next to `<Code>` — is bounded, masked out of every viewer
 *     and read exactly once inside err_body.
 *   - **the signature is not the key.** `Credential=` names the public half of
 *     the pair, which is what an audit log records and what "who is hammering us
 *     with bad credentials" is asked about. `Signature`, the chunk signatures
 *     and `X-Amz-Security-Token` are walked past and never copied.
 *
 * Pure, like the rest of src/proto: no I/O, no allocation, no state between
 * calls beyond the unit and the connection the handler owns. */
#include <string.h>

#include "http.h"
#include "s3_wire.h"

/* --- the request head ------------------------------------------------------ */

static void s3_req_field(struct http_unit *u, const struct lk_http_cfg *cfg, struct http_span name,
                         struct http_span val)
{
    if (http_span_eq_ci(name, "authorization")) {
        /* Read here because the head is here, and only into a bounded buffer
         * after a shape check. `--s3-user off` means the dimension is not wanted
         * at all, and then the header is not looked at — the РH12 rule that
         * what is not read cannot leak, applied to the one identity an S3
         * request always carries (РS4). */
        if (!cfg->s3.no_user && !s3_auth_access_key(val, u->user, sizeof(u->user)))
            u->user[0] = '\0';
    } else if (http_span_eq_ci(name, "x-amz-copy-source")) {
        /* Only that it is *there*. Its value names a bucket and a key on the
         * source side, which is one more object key than we have any use for. */
        u->dflags |= LK_S3_D_COPY_SRC;
    } else if (http_span_eq_ci(name, "x-amz-decoded-content-length")) {
        /* РS6: the object's own size, as opposed to the size of the signed
         * chunk stream carrying it. Detected off this header and the
         * `STREAMING-…` sha256 marker rather than off `Content-Encoding`,
         * because minio-go — `mc`, `warp`, MinIO's own SDK — never sends
         * `Content-Encoding: aws-chunked` and keying on it would miss every
         * upload a MinIO client makes (notes-s3proto.md §"Two sizes"). */
        __u64 v;

        if (http_parse_u64(val, &v))
            u->obj_bytes = v;
    }
}

static void s3_req_head(struct http_unit *u, const struct lk_http_cfg *cfg,
                        const struct lk_http_req *rq)
{
    struct http_span path = http_span(rq->target, rq->target_len), query = http_span(NULL, 0);
    struct lk_s3_addr a;
    __u32 i = 0;

    while (i < path.n && path.p[i] != '?')
        i++;
    if (i < path.n)
        query = http_span(path.p + i + 1, path.n - i - 1);
    path.n = i;

    lk_s3_addr(rq->host, rq->host_len, path.p, path.n, &cfg->s3, &a);
    if (a.vhost)
        u->dflags |= LK_S3_D_VHOST;

    /* The bucket takes the host's dim slot (РS3). A name that failed the S3
     * naming rules becomes `other` rather than travelling into a label: it came
     * off the wire, MinIO would have answered it `400 InvalidBucketName`, and a
     * hostile client must not be able to write arbitrary bytes into a series.
     * No bucket at all — a `ListBuckets`, or a target we never saw — leaves the
     * slot empty, which the registry prints as `-`; that is a different fact
     * from "a bucket we refused to name" and the two must not fold together. */
    if (a.valid)
        http_copy_label(u->host, sizeof(u->host), http_span(a.bucket, a.bucket_len));
    else if (a.bucket_len || a.vhost)
        http_copy_cstr(u->host, sizeof(u->host), "other");
    else
        u->host[0] = '\0';

    /* A presigned request carries its credential in the query instead of a
     * header, and nothing else about it differs — the same access key, the same
     * caller, the same label (РS4). Checked only when the header did not
     * already answer, so an ordinary signed request never walks its query. */
    if (!cfg->s3.no_user && !u->user[0] && query.n)
        s3_query_access_key(query, u->user, sizeof(u->user));
}

/* --- the response head and the error body ---------------------------------- */

static void s3_resp_field(struct http_conn *hc, struct http_unit *u, struct http_span name,
                          struct http_span val)
{
    if (http_span_eq_ci(name, "x-amz-request-id")) {
        /* Every S3 response carries one, and it is the join key `mc admin
         * trace` reports too — which makes it the one field that lets the МS4
         * accuracy bench compare our number with the server's per request
         * rather than in aggregate. It lands in the same span attribute the
         * base dialect fills from `X-Request-Id`. */
        if (!u->req_id[0])
            http_copy_label(u->req_id, sizeof(u->req_id), val);
    } else if (http_span_eq_ci(name, "x-amz-version-id")) {
        http_copy_label(hc->dr.obj_version, sizeof(hc->dr.obj_version), val);
    } else if (http_span_eq_ci(name, "x-minio-error-code")) {
        /* The gap S3 leaves and MinIO fills: an error answering a HEAD has no
         * body at all — `404` with `Content-Length: 0` — so there is no `<Code>`
         * to read and boto3 reports such failures as the literal string "404".
         * MinIO puts the code in a header instead, and reading it costs nothing
         * because the head is parsed anyway. A server that does not send it
         * leaves us with the status, which is the honest fallback (РS5). */
        s3_code_label(val.p, val.n, hc->dr.err_name, sizeof(hc->dr.err_name));
    }
}

static void s3_err_body(struct http_conn *hc, const char *p, __u32 n)
{
    /* The body wins over the header when both are there: `<Code>` is the code S3
     * defines, the header is MinIO's stand-in for when there is no body. In
     * practice they never co-occur (measured — the header appears only on
     * bodiless errors), so this is a tie-break that should not arise and has an
     * obvious right answer if it does. */
    s3_error_code(p, n, hc->dr.err_name, sizeof(hc->dr.err_name));
}

/* --- the operation and the observation ------------------------------------- */

static void s3_classify(const struct lk_http_req *rq, const struct lk_http_cfg *cfg,
                        struct lk_route_out *out)
{
    struct lk_s3_addr a;
    __u32 plen = 0, qlen = 0;
    const char *query = rq->target;

    (void)cfg; /* the addressing decision was made at the head (see below) */
    while (plen < rq->target_len && rq->target[plen] != '?')
        plen++;
    if (plen < rq->target_len) {
        query = rq->target + plen + 1;
        qlen = rq->target_len - plen - 1;
    }
    /* lk_s3_split rather than lk_s3_addr, and this is the one subtlety of the
     * whole dialect: by the time a unit is emitted, `rq->host` holds the
     * *bucket* this request was for, not the Host it arrived with. Asking the
     * suffix matcher again would read a bucket as a hostname. The form was
     * decided once, where the evidence was, and travels here in dflags. */
    lk_s3_split((rq->dflags & LK_S3_D_VHOST) != 0, rq->target, plen, &a);
    lk_norm_s3(rq->method, rq->method_len, query, qlen, &a,
               (rq->dflags & LK_S3_D_COPY_SRC) ? LK_S3_F_COPY_SRC : 0, out);
}

static void s3_obs(const struct http_conn *hc, const struct http_unit *u, struct lk_query_obs *o)
{
    if (hc->dr.err_name[0])
        o->err_name = hc->dr.err_name;
    /* РS6, the logical size: the decoded length when the upload was
     * `aws-chunked`, and otherwise whichever direction carried a body. The
     * distinction matters because the chunk framing costs ~87 bytes per chunk —
     * 0.13 % at 64 KB chunks and 17 % at 1 KB — so a size histogram built on
     * `bytes_in` would move with the client's buffer size rather than with the
     * objects. Which operations feed that histogram is МS2's decision; this is
     * the number it needs, and 0 means "the wire count is the whole story". */
    if (u->obj_bytes)
        o->obj_bytes = u->obj_bytes;
    else
        o->obj_bytes = o->bytes_in ? o->bytes_in : o->bytes_out;
}

const struct lk_http_dialect lk_http_dialect_s3 = {
    .name = "s3",
    /* The one dialect that asks the framer for body bytes, and only for a
     * failing response: an S3 error is a status *and* a code, and `404` alone
     * cannot tell `NoSuchKey` from `NoSuchBucket` — two facts that mean
     * completely different things to whoever is on call (РS5). */
    .flags = LK_HTTP_D_ERR_BODY,
    .classify = s3_classify,
    .req_field = s3_req_field,
    .req_head = s3_req_head,
    .resp_field = s3_resp_field,
    .err_body = s3_err_body,
    .obs = s3_obs,
};

const struct lk_proto_ops lk_proto_s3_ops = {
    .name = "s3", /* `--port 9000=s3`, and the `proto` label value (РМ6) */
    /* Not a database, so db_system stays NULL and otel_kind says so — the span
     * is an HTTP one with S3 attributes on top (РS7), not a db.* one. */
    .otel_kind = LK_OTEL_KIND_HTTP,
    /* The `latkit_s3_*` families of РS7 (МS2): the same engine and the same
     * measurements as the http profile, under the S3 nouns — `op`, `bucket`,
     * the symbolic error code and the object size. */
    .profile = LK_PROTO_PROF_S3,
    .role = LK_ROLE_SERVER,
    .flags = LK_PROTO_F_STREAM,
    .sql_dialect = LK_SQL_PG, /* unused: nothing here reaches the SQL normaliser */
    .dialect = &lk_http_dialect_s3,
    /* Measured rather than assumed: over 9006 requests of a warp run, MinIO's
     * request heads were 405..583 bytes and the server itself refuses one past
     * ~8 KB. S3 heads are *structurally* bounded, unlike browser HTTP, so the
     * РH14 budget covers every head the corpus contains with room to spare. */
    .cap_limit = LK_HTTP_CAPTURE_LIMIT,
    /* The same handler object, not a copy of it: an S3 exchange is an HTTP
     * exchange, and everything about its lifecycle is already right. */
    .proto_new = lk_proto_http_new,
    .stream_bytes = http_stream_bytes,
    .stream_hole = http_stream_hole,
    .mask_body = http_mask_body,
};
