# SPDX-License-Identifier: GPL-2.0
"""AWS SigV4 for the МS0 corpus, in ~80 lines and with no dependencies.

The recorded scenarios need requests no SDK will make: a signature that is
deliberately wrong, a virtual-host-style target aimed at a server that resolves
no DNS, `aws-chunked` framing built by hand, fifty operations on one connection.
Every one of those needs a *valid* SigV4 header (MinIO rejects the request
before routing it otherwise), so the corpus carries its own signer rather than
bending an SDK into shapes it does not want to make.

What matters for latkit is only the shape of the two credential carriers —
`Authorization: AWS4-HMAC-SHA256 Credential=<AK>/<date>/<region>/s3/aws4_request,
 SignedHeaders=…, Signature=…` and the presigned `X-Amz-Credential=<AK>/…` query
parameter (РS4) — but the shape has to be attached to a request the server
accepts, so the whole algorithm is here.
"""
import datetime
import hashlib
import hmac
import urllib.parse

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
STREAMING_SHA256 = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
STREAMING_UNSIGNED_TRAILER = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"


def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def signing_key(secret, date, region, service="s3"):
    k = _hmac(("AWS4" + secret).encode(), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def canonical_query(query):
    """query: list of (k, v) or a raw string already in canonical order."""
    if isinstance(query, str):
        return query
    q = sorted((urllib.parse.quote(k, safe="-_.~"), urllib.parse.quote(v, safe="-_.~"))
               for k, v in query)
    return "&".join("%s=%s" % kv for kv in q)


def canonical_uri(path):
    # S3 does not double-encode the key: each segment is encoded once, `/` kept.
    return "/" + "/".join(urllib.parse.quote(seg, safe="-_.~") for seg in path.split("/")[1:])


def sign(method, path, query, headers, payload_sha, ak, sk, region="us-east-1", now=None):
    """Fill `headers` in place with x-amz-date/x-amz-content-sha256/Authorization."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    headers["x-amz-date"] = amzdate
    headers["x-amz-content-sha256"] = payload_sha

    signed = sorted(k.lower() for k in headers)
    canon_headers = "".join("%s:%s\n" % (k, str(headers[hk]).strip())
                            for k in signed
                            for hk in [next(h for h in headers if h.lower() == k)])
    signed_headers = ";".join(signed)
    canon = "\n".join([method, canonical_uri(path), canonical_query(query),
                       canon_headers, signed_headers, payload_sha])
    scope = "%s/%s/s3/aws4_request" % (datestamp, region)
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                         hashlib.sha256(canon.encode()).hexdigest()])
    sig = hmac.new(signing_key(sk, datestamp, region), to_sign.encode(),
                   hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
        % (ak, scope, signed_headers, sig))
    return headers


def presign(method, path, query, host, ak, sk, region="us-east-1", expires=600, now=None):
    """Return the query string of a presigned URL (РS4: X-Amz-Credential)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    scope = "%s/%s/s3/aws4_request" % (datestamp, region)
    q = list(query) + [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
        ("X-Amz-Credential", "%s/%s" % (ak, scope)),
        ("X-Amz-Date", amzdate),
        ("X-Amz-Expires", str(expires)),
        ("X-Amz-SignedHeaders", "host"),
    ]
    cq = canonical_query(q)
    canon = "\n".join([method, canonical_uri(path), cq, "host:%s\n" % host,
                       "host", "UNSIGNED-PAYLOAD"])
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                         hashlib.sha256(canon.encode()).hexdigest()])
    sig = hmac.new(signing_key(sk, datestamp, region), to_sign.encode(),
                   hashlib.sha256).hexdigest()
    return cq + "&X-Amz-Signature=" + sig


def chunk_signature(prev_sig, chunk, sk, datestamp, amzdate, region="us-east-1"):
    """One `aws-chunked` chunk signature (РS6): the chain SigV4 streaming uses."""
    scope = "%s/%s/s3/aws4_request" % (datestamp, region)
    to_sign = "\n".join(["AWS4-HMAC-SHA256-PAYLOAD", amzdate, scope, prev_sig,
                         EMPTY_SHA256, hashlib.sha256(chunk).hexdigest()])
    return hmac.new(signing_key(sk, datestamp, region), to_sign.encode(),
                    hashlib.sha256).hexdigest()
