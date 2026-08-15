#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""МS0 (PLAN-MINIO.md): the S3 operation taxonomy, exercised against a live server.

РS2 replaces route templating with a closed table: (method, path shape, query
keys) → operation name. This script *is* that table, written down once and then
fired at MinIO so every row is backed by a request the server actually routed —
including the rows MinIO answers with an error, because "MinIO returns 501
NotImplemented for GetPublicAccessBlock" is exactly the sort of thing a
taxonomy written from AWS documentation gets wrong.

    ./ops.py            # run every row, print op / method / target / status
    ./ops.py --table    # print the table only (the МS1 reference)

Columns: operation, method, the path *shape* (`/`, `/{bucket}`,
`/{bucket}/{key}`), the query keys that select the operation, and the
distinguishing header if there is one. That is the whole input the classifier
gets — no key, no query values.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import raw  # noqa: E402

BUCKET = raw.BUCKET
KEY = "small.bin"

# op, method, shape, query (list of (k, v)), headers, body, note
#   shape: "/" | "/{bucket}" | "/{bucket}/{key}"
# The query *keys* are what selects an operation; the values here are only what
# makes the request work against a live server.
TABLE = [
    # --- service -----------------------------------------------------------
    ("ListBuckets",                 "GET",    "/",              [], {}, b""),
    # --- bucket ------------------------------------------------------------
    ("CreateBucket",                "PUT",    "/{bucket}",      [], {}, b""),
    ("HeadBucket",                  "HEAD",   "/{bucket}",      [], {}, b""),
    ("ListObjects",                 "GET",    "/{bucket}",      [], {}, b""),
    ("ListObjectsV2",               "GET",    "/{bucket}",      [("list-type", "2")], {}, b""),
    ("ListObjectVersions",          "GET",    "/{bucket}",      [("versions", "")], {}, b""),
    ("ListMultipartUploads",        "GET",    "/{bucket}",      [("uploads", "")], {}, b""),
    ("DeleteObjects",               "POST",   "/{bucket}",      [("delete", "")], {},
     b"<Delete><Object><Key>gone.bin</Key></Object></Delete>"),
    ("GetBucketLocation",           "GET",    "/{bucket}",      [("location", "")], {}, b""),
    ("GetBucketAcl",                "GET",    "/{bucket}",      [("acl", "")], {}, b""),
    ("GetBucketPolicy",             "GET",    "/{bucket}",      [("policy", "")], {}, b""),
    ("GetBucketPolicyStatus",       "GET",    "/{bucket}",      [("policyStatus", "")], {}, b""),
    ("GetBucketVersioning",         "GET",    "/{bucket}",      [("versioning", "")], {}, b""),
    ("GetBucketTagging",            "GET",    "/{bucket}",      [("tagging", "")], {}, b""),
    ("GetBucketLifecycleConfiguration", "GET", "/{bucket}",     [("lifecycle", "")], {}, b""),
    ("GetBucketNotificationConfiguration", "GET", "/{bucket}",  [("notification", "")], {}, b""),
    ("GetBucketEncryption",         "GET",    "/{bucket}",      [("encryption", "")], {}, b""),
    ("GetBucketReplication",        "GET",    "/{bucket}",      [("replication", "")], {}, b""),
    ("GetObjectLockConfiguration",  "GET",    "/{bucket}",      [("object-lock", "")], {}, b""),
    ("GetBucketCors",               "GET",    "/{bucket}",      [("cors", "")], {}, b""),
    ("GetBucketRequestPayment",     "GET",    "/{bucket}",      [("requestPayment", "")], {}, b""),
    ("GetBucketLogging",            "GET",    "/{bucket}",      [("logging", "")], {}, b""),
    ("GetBucketWebsite",            "GET",    "/{bucket}",      [("website", "")], {}, b""),
    ("GetBucketAccelerateConfiguration", "GET", "/{bucket}",    [("accelerate", "")], {}, b""),
    ("GetPublicAccessBlock",        "GET",    "/{bucket}",      [("publicAccessBlock", "")], {}, b""),
    ("PutBucketTagging",            "PUT",    "/{bucket}",      [("tagging", "")], {},
     b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>"),
    ("DeleteBucketTagging",         "DELETE", "/{bucket}",      [("tagging", "")], {}, b""),
    ("PutBucketVersioning",         "PUT",    "/{bucket}",      [("versioning", "")], {},
     b"<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>"),
    # --- object ------------------------------------------------------------
    ("GetObject",                   "GET",    "/{bucket}/{key}", [], {}, b""),
    ("HeadObject",                  "HEAD",   "/{bucket}/{key}", [], {}, b""),
    ("PutObject",                   "PUT",    "/{bucket}/{key}", [], {}, b"data"),
    ("CopyObject",                  "PUT",    "/{bucket}/{key}", [],
     {"x-amz-copy-source": "/%s/%s" % (BUCKET, KEY)}, b""),
    ("GetObjectAcl",                "GET",    "/{bucket}/{key}", [("acl", "")], {}, b""),
    ("GetObjectTagging",            "GET",    "/{bucket}/{key}", [("tagging", "")], {}, b""),
    ("PutObjectTagging",            "PUT",    "/{bucket}/{key}", [("tagging", "")], {},
     b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>"),
    ("DeleteObjectTagging",         "DELETE", "/{bucket}/{key}", [("tagging", "")], {}, b""),
    ("GetObjectRetention",          "GET",    "/{bucket}/{key}", [("retention", "")], {}, b""),
    ("GetObjectLegalHold",          "GET",    "/{bucket}/{key}", [("legal-hold", "")], {}, b""),
    ("GetObjectAttributes",         "GET",    "/{bucket}/{key}", [("attributes", "")],
     {"x-amz-object-attributes": "ETag"}, b""),
    ("RestoreObject",               "POST",   "/{bucket}/{key}", [("restore", "")], {},
     b"<RestoreRequest><Days>1</Days></RestoreRequest>"),
    ("SelectObjectContent",         "POST",   "/{bucket}/{key}",
     [("select", ""), ("select-type", "2")], {},
     b"<SelectObjectContentRequest><Expression>select * from S3Object</Expression>"
     b"<ExpressionType>SQL</ExpressionType><InputSerialization><CSV></CSV>"
     b"</InputSerialization><OutputSerialization><CSV></CSV></OutputSerialization>"
     b"</SelectObjectContentRequest>"),
    # --- multipart (uploadId is filled in at run time) ----------------------
    ("DeleteObject",                "DELETE", "/{bucket}/{key}", [], {}, b""),
    ("CreateMultipartUpload",       "POST",   "/{bucket}/{key}", [("uploads", "")], {}, b""),
    ("UploadPart",                  "PUT",    "/{bucket}/{key}",
     [("partNumber", "1"), ("uploadId", "@")], {}, b"x" * (5 * 1024 * 1024)),
    ("UploadPartCopy",              "PUT",    "/{bucket}/{key}",
     [("partNumber", "2"), ("uploadId", "@")],
     {"x-amz-copy-source": "/%s/%s" % (BUCKET, "big8m.bin")}, b""),
    ("ListParts",                   "GET",    "/{bucket}/{key}", [("uploadId", "@")], {}, b""),
    ("CompleteMultipartUpload",     "POST",   "/{bucket}/{key}", [("uploadId", "@")], {}, b"@"),
    ("AbortMultipartUpload",        "DELETE", "/{bucket}/{key}", [("uploadId", "@")], {}, b""),
    ("DeleteBucket",                "DELETE", "/{bucket}",      [], {}, b""),
    # --- MinIO's own surface, which is never an S3 operation (РS2) ----------
    ("internal (health)",           "GET",    "/minio/health/live", [], {}, b""),
    ("internal (admin)",            "GET",    "/minio/admin/v3/info", [], {}, b""),
    ("internal (peer)",             "GET",    "/minio/peer/v41/health", [], {}, b""),
    ("internal (storage)",          "GET",    "/minio/storage/data/v54/diskinfo", [], {}, b""),
]


def print_table():
    print("%-38s %-7s %-18s %s" % ("operation", "method", "path shape", "selector"))
    for op, method, shape, query, hdrs, _ in TABLE:
        sel = ",".join("?" + k for k, _ in query) or "-"
        if hdrs:
            sel += " " + " ".join(hdrs)
        print("%-38s %-7s %-18s %s" % (op, method, shape, sel))


def run():
    import base64
    import hashlib

    ops_bucket = BUCKET + "-ops"
    c = raw.Conn()
    # A bucket of our own for the create/delete rows, plus one object to work on.
    raw._req(c, "PUT", "/" + ops_bucket)
    body = b"opsdata"
    raw._req(c, "PUT", "/%s/%s" % (ops_bucket, KEY), body=body,
             payload_sha=hashlib.sha256(body).hexdigest())
    raw._req(c, "PUT", "/%s/%s" % (ops_bucket, "big8m.bin"), body=b"y" * 65536,
             payload_sha=hashlib.sha256(b"y" * 65536).hexdigest())

    # Report rows by operation name: what is being checked is the mapping from
    # (method, shape, query keys) to the name, so the name has to be on the line.
    current = [""]
    raw.Conn.report = lambda self, method, path, status, payload: (
        print("%-38s %-7s %-52s -> %3d %s"
              % (current[0], method, path[:52], status,
                 (raw.CODE_RE.search(payload or b"") or [b"", b"-"])[1].decode()
                 if raw.CODE_RE.search(payload or b"") else "-")),
        (status, None))[1]

    upload_id, etags = None, []
    print("\n%-38s %-7s %-52s %s" % ("operation", "method", "request target", "answer"))
    for op, method, shape, query, hdrs, body in TABLE:
        bkt = ops_bucket
        path = (shape.replace("{bucket}", bkt).replace("{key}", KEY)
                if shape.startswith("/{") else shape)
        q = [(k, upload_id if v == "@" else v) for k, v in query]
        if any(v is None for _, v in q):
            continue
        h = dict(hdrs)
        if body == b"@":
            body = ("<CompleteMultipartUpload>"
                    + "".join("<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>" % t
                              for t in etags) + "</CompleteMultipartUpload>").encode()
        if op == "DeleteObjects":
            h["Content-Md5"] = base64.b64encode(hashlib.md5(body).digest()).decode()
        sha = hashlib.sha256(body).hexdigest() if body else None
        sign = not path.startswith("/minio/health")
        current[0] = op
        try:
            st, rh, payload = raw._req(c, method, path, q, headers=h, body=body,
                                       payload_sha=sha, sign=sign)
        except (OSError, EOFError):
            c = raw.Conn()          # MinIO closed it (anonymous refusal, 400)
            continue
        if op == "CreateMultipartUpload":
            import re
            m = re.search(rb"<UploadId>([^<]+)</UploadId>", payload)
            upload_id = m.group(1).decode() if m else None
        elif op in ("UploadPart", "UploadPartCopy") and rh.get("etag"):
            etags.append((len(etags) + 1, rh["etag"]))
    c.close()


if __name__ == "__main__":
    if "--table" in sys.argv:
        print_table()
    else:
        run()
