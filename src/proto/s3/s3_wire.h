/* SPDX-License-Identifier: GPL-2.0 */
/* The four values the S3 dialect reads off the wire that no other dialect does
 * (РS4/РS5/РS6, PLAN-MINIO.md МS1) — the http_wire.h of this dialect, and the
 * same discipline: every accessor takes an explicit (pointer, length) pair,
 * nothing walks past the range it was handed, and nothing here is
 * NUL-terminated because nothing on the wire is.
 *
 * What is *not* here is the point of the file. An S3 request carries a
 * signature, a security token, chunk signatures and an object key, all of them
 * within a few bytes of the values below; the parsers walk past every one of
 * them without copying a byte, and the two that must survive the call — the
 * access key and the error code — are written into a bounded caller buffer
 * after a shape check. What is not read cannot leak (РH12, and here it matters
 * more than anywhere else in the agent).
 *
 * Header-only and dependency-light on purpose, like http_wire.h: the unit tests
 * include it directly and drive these functions with the exact byte strings the
 * МS0 corpus contains. */
#ifndef LATKIT_S3_WIRE_H
#define LATKIT_S3_WIRE_H

#include "http_wire.h"
#include "norm_s3.h"

/* The bits the S3 dialect keeps in http_unit.dflags (РH8). Both are facts about
 * the request head that the classifier needs and cannot re-derive at emit time:
 * the head is gone by then, and the host slot holds a bucket rather than a host
 * (РS3), so "was this virtual-host style" has to be *remembered*, not guessed. */
#define LK_S3_D_VHOST    (1 << 0) /* the bucket came from the Host */
#define LK_S3_D_COPY_SRC (1 << 1) /* the request carried `x-amz-copy-source` */

/* A byte that may travel into a label. The same rule http_basic_user applies to
 * the Basic name half: printable ASCII only, and a control byte rejects the
 * *whole* value rather than being stripped out of it — a label silently
 * different from what the wire said is worse than no label. */
static inline bool s3_label_byte(char c)
{
    unsigned char b = (unsigned char)c;

    return b > 0x20 && b < 0x7f;
}

/* Copy a span into a bounded buffer as a C string, refusing rather than
 * clipping. An access key or an error code is an identity: two thirds of one is
 * not a shorter identity, it is a different one. */
static inline bool s3_copy_label(char *out, __u32 cap, const char *p, __u32 n)
{
    if (!n || n >= cap)
        return false;
    for (__u32 i = 0; i < n; i++) {
        if (!s3_label_byte(p[i]))
            return false;
        out[i] = p[i];
    }
    out[n] = '\0';
    return true;
}

/* Find a lowercase literal in a span, case-insensitively. Used for the two
 * places S3 puts a credential, both of which are parameter names inside a
 * larger value rather than fields of their own. Returns the offset or `n`. */
static inline __u32 s3_find_ci(struct http_span s, const char *lit)
{
    __u32 l = (__u32)strlen(lit);

    if (l > s.n)
        return s.n;
    for (__u32 i = 0; i + l <= s.n; i++) {
        __u32 k = 0;

        while (k < l && http_lc(s.p[i + k]) == lit[k])
            k++;
        if (k == l)
            return i;
    }
    return s.n;
}

/* `Authorization` → the access key ID, and nothing else (РS4).
 *
 *   AWS4-HMAC-SHA256 Credential=<AK>/<yyyymmdd>/<region>/s3/aws4_request,
 *                    SignedHeaders=<h;h;h>, Signature=<64 hex>
 *
 * Two spellings have to survive: aws-cli and boto3 write `, ` between the three
 * components, minio-go (`mc`, `warp`, the Go SDK) writes a bare `,`. Neither
 * matters, because the parser looks for `Credential=` and stops at the first
 * `/` — `SignedHeaders` and `Signature` are walked over, never copied, and the
 * secret is not on the wire at all.
 *
 * SigV2 (`AWS <AK>:<sig>`) is recognised too. MinIO answers it `403
 * AccessDenied`, which is exactly the moment an operator wants to know *which
 * key* is still speaking the old protocol.
 *
 * false means "no usable access key in this header": a scheme we do not know
 * (`Bearer`), a truncated value, or a key whose bytes are not label-safe. The
 * caller then reports the request as anonymous, which is honest — we did not
 * learn who it was. */
static inline bool s3_auth_access_key(struct http_span v, char *out, __u32 cap)
{
    static const char v4[] = "aws4-hmac-sha256";
    static const char cred[] = "credential=";
    __u32 i, s;

    if (v.n > 4 && !memcmp(v.p, "AWS ", 4)) {
        /* SigV2: the key runs to the colon that separates it from the
         * signature. No colon means a malformed header, not a nameless key. */
        for (i = 4; i < v.n && v.p[i] != ':'; i++)
            ;
        if (i == v.n)
            return false;
        return s3_copy_label(out, cap, v.p + 4, i - 4);
    }
    if (v.n < sizeof(v4) - 1 || !http_span_eq_ci(http_span(v.p, sizeof(v4) - 1), v4))
        return false;
    i = s3_find_ci(v, cred);
    if (i == v.n)
        return false;
    s = i + (__u32)sizeof(cred) - 1;
    for (i = s; i < v.n && v.p[i] != '/'; i++)
        ;
    /* No `/` at all means the credential scope was cut off — by a capture hole,
     * or by a client that built the header wrong. Either way the bytes we have
     * are not known to be the whole key, and a prefix of an identity is a
     * different identity. */
    if (i == v.n)
        return false;
    return s3_copy_label(out, cap, v.p + s, i - s);
}

/* A presigned request carries the same credential in the query string, percent-
 * encoded (РS4):
 *
 *   ?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=<AK>%2F20260815%2F…
 *
 * So the scan stops at a literal `/` *or* at `%2F` in either case, which is as
 * much decoding as the value needs — the rest of the scope is walked past, and
 * `X-Amz-Signature` and `X-Amz-Security-Token` are never looked at.
 *
 * The key name is matched case-insensitively: the SDKs all spell it
 * `X-Amz-Credential`, and a deployment where one does not is not a reason to
 * lose the label. */
static inline bool s3_query_access_key(struct http_span q, char *out, __u32 cap)
{
    __u32 i = 0;

    while (i < q.n) {
        __u32 ks = i, ke, vs, ve;

        while (i < q.n && q.p[i] != '&' && q.p[i] != '=')
            i++;
        ke = i;
        vs = i;
        if (i < q.n && q.p[i] == '=') {
            i++;
            vs = i;
            while (i < q.n && q.p[i] != '&')
                i++;
        }
        ve = i;
        if (i < q.n)
            i++; /* the '&' */
        if (!http_span_eq_ci(http_span(q.p + ks, ke - ks), "x-amz-credential"))
            continue;
        for (__u32 k = vs; k < ve; k++) {
            if (q.p[k] == '/')
                return s3_copy_label(out, cap, q.p + vs, k - vs);
            if (q.p[k] == '%' && k + 2 < ve && q.p[k + 1] == '2' && http_lc(q.p[k + 2]) == 'f')
                return s3_copy_label(out, cap, q.p + vs, k - vs);
        }
        return false; /* the scope never began: not a whole key (see above) */
    }
    return false;
}

/* A code that arrived from somewhere, bounded into a label (РS5). Known codes
 * travel as themselves; anything else — a code AWS added since this list was
 * written, a code MinIO invented, bytes that are not a code at all — folds into
 * `other`. That fold is the whole cardinality argument for the `s3code` label:
 * a server is free to invent a code and must not be free to invent a series. */
static inline bool s3_code_label(const char *p, __u32 n, char *out, __u32 cap)
{
    if (n && lk_s3_code_known(p, n) && s3_copy_label(out, cap, p, n))
        return true;
    if (!n || cap < sizeof("other"))
        return false;
    memcpy(out, "other", sizeof("other"));
    return true;
}

/* The symbolic code out of an S3 error body (РS5):
 *
 *   <?xml version="1.0" encoding="UTF-8"?>
 *   <Error><Code>SignatureDoesNotMatch</Code><Message>…</Message><Key>…</Key>…
 *
 * A literal search for `<Code>` rather than an XML parse, and that is not
 * laziness: the prefix also contains `<Key>` and `<Resource>`, so the *less*
 * this function understands about the document the fewer places it can be
 * tempted to read from. It looks at one element, folds its text through
 * s3_code_label, and returns.
 *
 * false means "there was no code here to read": a non-XML body (an HTML error
 * page from a proxy in front of MinIO), or a body a capture hole cut before the
 * element closed. Both fall back to the HTTP status, which is what a non-MinIO
 * S3 server would leave us with anyway. A code that *is* there but is not one we
 * know is a different thing and comes back as `other`. */
static inline bool s3_error_code(const char *p, __u32 n, char *out, __u32 cap)
{
    static const char open[] = "<Code>";
    static const char close[] = "</Code>";
    __u32 s;

    if (!p || n < sizeof(open) - 1)
        return false;
    for (s = 0; s + sizeof(open) - 1 <= n; s++) {
        if (!memcmp(p + s, open, sizeof(open) - 1))
            break;
    }
    if (s + sizeof(open) - 1 > n)
        return false;
    s += (__u32)sizeof(open) - 1;
    for (__u32 e = s; e + sizeof(close) - 1 <= n; e++) {
        if (memcmp(p + e, close, sizeof(close) - 1))
            continue;
        return s3_code_label(p + s, e - s, out, cap);
    }
    return false;
}

#endif /* LATKIT_S3_WIRE_H */
