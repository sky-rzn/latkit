#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""МS0 (PLAN-MINIO.md): the boto3 half of the client matrix.

boto3/botocore is the single most common S3 client in the wild and the one
whose wire shape differs most from MinIO's own SDK: it precomputes a checksum
and sends an ordinary `Content-Length` body where minio-go streams
`aws-chunked`, and it puts `Expect: 100-continue` on every upload. Both shapes
have to be in the corpus, and neither can be produced by hand-written sockets
without reimplementing the SDK.

    ./scenarios.py basic | multipart | errors | presigned
"""
import os
import sys

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

ENDPOINT = "http://" + os.environ.get("S3_ENDPOINT", "127.0.0.1:9900")
BUCKET = os.environ.get("S3_BUCKET", "lkbucket")

s3 = boto3.client(
    "s3", endpoint_url=ENDPOINT,
    aws_access_key_id=os.environ.get("S3_AK", "lkroot"),
    aws_secret_access_key=os.environ.get("S3_SK", "lkrootpass123"),
    region_name=os.environ.get("S3_REGION", "us-east-1"),
    # Keep the retry machinery out of the trace: a retried request is a second
    # unit on a second connection and makes the expectation table ambiguous.
    config=Config(retries={"max_attempts": 1}, s3={"addressing_style": "path"}))


def basic():
    s3.put_object(Bucket=BUCKET, Key="boto3.bin", Body=os.urandom(64 * 1024))
    s3.get_object(Bucket=BUCKET, Key="boto3.bin")["Body"].read()
    s3.head_object(Bucket=BUCKET, Key="boto3.bin")
    s3.list_objects_v2(Bucket=BUCKET, MaxKeys=20)
    s3.copy_object(Bucket=BUCKET, Key="boto3-copy.bin",
                   CopySource={"Bucket": BUCKET, "Key": "boto3.bin"})
    s3.delete_objects(Bucket=BUCKET, Delete={"Objects": [{"Key": "boto3-copy.bin"}]})
    s3.delete_object(Bucket=BUCKET, Key="boto3.bin")


def multipart():
    key = "boto3-mp.bin"
    up = s3.create_multipart_upload(Bucket=BUCKET, Key=key)["UploadId"]
    parts = []
    for i in (1, 2, 3):
        r = s3.upload_part(Bucket=BUCKET, Key=key, PartNumber=i, UploadId=up,
                           Body=os.urandom(5 * 1024 * 1024))
        parts.append({"PartNumber": i, "ETag": r["ETag"]})
    s3.list_parts(Bucket=BUCKET, Key=key, UploadId=up)
    s3.complete_multipart_upload(Bucket=BUCKET, Key=key, UploadId=up,
                                 MultipartUpload={"Parts": parts})
    s3.delete_object(Bucket=BUCKET, Key=key)


def errors():
    for call, kw in (("get_object", {"Key": "no-such-key"}),
                     ("head_object", {"Key": "no-such-key"}),
                     ("get_object_tagging", {"Key": "no-such-key"}),
                     ("list_objects_v2", {"Bucket": "no-such-bucket-lk"})):
        kw.setdefault("Bucket", BUCKET)
        try:
            getattr(s3, call)(**kw)
        except ClientError as e:
            print("%-20s -> %s %s" % (call, e.response["ResponseMetadata"]["HTTPStatusCode"],
                                      e.response["Error"]["Code"]))


def presigned():
    import urllib.request
    url = s3.generate_presigned_url("get_object",
                                    Params={"Bucket": BUCKET, "Key": "small.bin"},
                                    ExpiresIn=600)
    urllib.request.urlopen(url, timeout=10).read()
    print("presigned GET ok")


if __name__ == "__main__":
    globals()[sys.argv[1] if len(sys.argv) > 1 else "basic"]()
