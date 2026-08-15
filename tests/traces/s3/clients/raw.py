#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""МS0 (PLAN-MINIO.md): the raw-socket half of the S3 trace corpus.

Every scenario an SDK will not produce on demand — a signature that is wrong on
purpose, `aws-chunked` framing built by hand so the chunk headers are known
byte for byte, a virtual-host-style target aimed at a server that resolves no
DNS, fifty operations on one connection, a client that hangs up mid-body — plus
the taxonomy sweep that walks every operation form of docs/notes-s3proto.md and
prints what MinIO answers.

    ./raw.py <scenario> [args…]
    S3_ENDPOINT=127.0.0.1:9900 S3_AK=… S3_SK=… ./raw.py get

Scenarios print one line per exchange (`method path -> status s3code`), which is
what makes them usable both under `--record` (the corpus) and standalone (the
evidence tables in README.md).
"""
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigv4  # noqa: E402

HOST, _, PORT = os.environ.get("S3_ENDPOINT", "127.0.0.1:9900").partition(":")
PORT = int(PORT or 9900)
AK = os.environ.get("S3_AK", "lkroot")
SK = os.environ.get("S3_SK", "lkrootpass123")
REGION = os.environ.get("S3_REGION", "us-east-1")
BUCKET = os.environ.get("S3_BUCKET", "lkbucket")
USE_TLS = os.environ.get("S3_TLS", "") == "1"

CODE_RE = re.compile(rb"<Code>([A-Za-z]{0,64})</Code>")


class Conn:
    """One connection, kept open across requests unless the scenario says otherwise."""

    def __init__(self, host=None, port=None, host_header=None):
        self.host = host or HOST
        self.port = port or PORT
        self.sock = socket.create_connection((self.host, self.port), timeout=20)
        if USE_TLS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(self.sock)
        self.host_header = host_header or "%s:%d" % (self.host, self.port)
        self.buf = b""

    # --- writing ---------------------------------------------------------
    def head(self, method, path, query=(), headers=None, payload_sha=None,
             sign=True, host_header=None, bad_signature=False):
        h = dict(headers or {})
        host_hdr = host_header or self.host_header
        h["host"] = host_hdr
        if sign:
            sigv4.sign(method, path, query, h, payload_sha or sigv4.EMPTY_SHA256,
                       AK, SK, REGION)
            if bad_signature:
                # Same shape, last hex nibble flipped: the label extractor of
                # РS4 must still find the access key in a request MinIO refuses.
                a = h["Authorization"]
                h["Authorization"] = a[:-1] + ("0" if a[-1] != "0" else "1")
        qs = sigv4.canonical_query(query) if not isinstance(query, str) else query
        target = sigv4.canonical_uri(path) + ("?" + qs if qs else "")
        lines = ["%s %s HTTP/1.1" % (method, target)]
        lines += ["%s: %s" % (k, v) for k, v in h.items()]
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    def send(self, data):
        self.sock.sendall(data)

    def request(self, method, path, query=(), headers=None, body=b"",
                payload_sha=None, sign=True, host_header=None,
                bad_signature=False, expect_continue=False, read=True):
        h = dict(headers or {})
        if body and "content-length" not in {k.lower() for k in h}:
            h["Content-Length"] = str(len(body))
        if expect_continue:
            h["Expect"] = "100-continue"
        self.send(self.head(method, path, query, h, payload_sha, sign,
                            host_header, bad_signature))
        if expect_continue:
            st, _, _ = self.response(interim_only=True)
            if st != 100:
                return self.report(method, path, st, b"")
        if body:
            self.send(body)
        if not read:
            return None
        st, hdrs, payload = self.response(no_body=(method == "HEAD"))
        return self.report(method, path, st, payload)

    # --- reading ---------------------------------------------------------
    def recv_into_buf(self):
        d = self.sock.recv(65536)
        if not d:
            raise EOFError
        self.buf += d

    def read_head(self):
        while b"\r\n\r\n" not in self.buf:
            self.recv_into_buf()
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        status = int(lines[0].split()[1])
        hdrs = {}
        for l in lines[1:]:
            k, _, v = l.partition(b":")
            hdrs[k.strip().lower().decode("latin1")] = v.strip().decode("latin1")
        return status, hdrs

    def response(self, interim_only=False, keep=4096, no_body=False):
        while True:
            status, hdrs = self.read_head()
            if 100 <= status < 200:
                if interim_only:
                    return status, hdrs, b""
                continue  # an interim response never ends a unit
            break
        payload = b""
        # A HEAD response describes a body that never comes (РS5: which is why
        # an S3 error code is unreadable on HEAD — there is no XML to read).
        if no_body:
            return status, hdrs, payload
        if hdrs.get("transfer-encoding", "").lower() == "chunked":
            while True:
                while b"\r\n" not in self.buf:
                    self.recv_into_buf()
                size_line, self.buf = self.buf.split(b"\r\n", 1)
                n = int(size_line.split(b";")[0], 16)
                while len(self.buf) < n + 2:
                    self.recv_into_buf()
                payload += self.buf[:n][: max(0, keep - len(payload))]
                self.buf = self.buf[n + 2 :]
                if n == 0:
                    break
        else:
            n = int(hdrs.get("content-length", "0"))
            got = 0
            while got < n:
                if not self.buf:
                    self.recv_into_buf()
                take = self.buf[: n - got]
                payload += take[: max(0, keep - len(payload))]
                got += len(take)
                self.buf = self.buf[len(take) :]
        return status, hdrs, payload

    def report(self, method, path, status, payload):
        m = CODE_RE.search(payload or b"")
        code = m.group(1).decode() if m else "-"
        print("%-6s %-58s -> %3d %s" % (method, path[:58], status, code))
        return status, code

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# --- aws-chunked (РS6) ------------------------------------------------------


def aws_chunked_body(data, chunk_size, seed_sig, datestamp, amzdate):
    """Build a STREAMING-AWS4-HMAC-SHA256-PAYLOAD body, signature chain included."""
    out = []
    prev = seed_sig
    for i in range(0, len(data), chunk_size):
        c = data[i : i + chunk_size]
        prev = sigv4.chunk_signature(prev, c, SK, datestamp, amzdate, REGION)
        out.append(b"%x;chunk-signature=%s\r\n" % (len(c), prev.encode()) + c + b"\r\n")
    prev = sigv4.chunk_signature(prev, b"", SK, datestamp, amzdate, REGION)
    out.append(b"0;chunk-signature=%s\r\n\r\n" % prev.encode())
    return b"".join(out)


def chunked_put(key="raw-chunked.bin", size=1 << 20, chunk_size=64 * 1024):
    """PUT with SigV4 streaming: wire length != object length (РS6)."""
    import datetime

    size, chunk_size = int(size), int(chunk_size)
    data = os.urandom(size)
    now = datetime.datetime.now(datetime.timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    nchunks = (size + chunk_size - 1) // chunk_size
    wire = sum(len(b"%x;chunk-signature=" % chunk_size) + 64 + 2 + 2 for _ in range(nchunks))
    # the last chunk is shorter, so compute the framing exactly
    wire = 0
    for i in range(0, size, chunk_size):
        c = min(chunk_size, size - i)
        wire += len(b"%x" % c) + len(";chunk-signature=") + 64 + 2 + c + 2
    wire += len(b"0") + len(";chunk-signature=") + 64 + 2 + 2

    c = Conn()
    h = {
        "Content-Encoding": "aws-chunked",
        "Content-Length": str(wire),
        "x-amz-decoded-content-length": str(size),
    }
    head = c.head("PUT", "/%s/%s" % (BUCKET, key), (), h, sigv4.STREAMING_SHA256)
    seed = re.search(rb"Signature=([0-9a-f]{64})", head).group(1).decode()
    c.send(head)
    c.send(aws_chunked_body(data, chunk_size, seed, datestamp, amzdate))
    st, hdrs, payload = c.response()
    c.report("PUT", "/%s/%s [aws-chunked %d->%d]" % (BUCKET, key, wire, size), st, payload)
    c.close()


# --- scenarios --------------------------------------------------------------


def s_get(key="small.bin"):
    c = Conn(); c.request("GET", "/%s/%s" % (BUCKET, key)); c.close()


def s_get_large(key="big8m.bin"):
    c = Conn(); c.request("GET", "/%s/%s" % (BUCKET, key)); c.close()


def s_put(key="raw-put.bin", size=65536):
    c = Conn()
    body = os.urandom(int(size))
    import hashlib
    c.request("PUT", "/%s/%s" % (BUCKET, key), body=body,
              payload_sha=hashlib.sha256(body).hexdigest())
    c.close()


def s_continue(key="raw-continue.bin", size=65536):
    """`Expect: 100-continue`, which every real S3 SDK sends on PUT."""
    import hashlib
    c = Conn()
    body = os.urandom(int(size))
    c.request("PUT", "/%s/%s" % (BUCKET, key), body=body,
              payload_sha=hashlib.sha256(body).hexdigest(), expect_continue=True)
    c.close()


def s_keepalive(n=50):
    c = Conn()
    for i in range(int(n)):
        c.request("GET", "/%s/small.bin" % BUCKET)
    c.close()


def s_pipelined():
    """Four operations in one write: in-flight depth > 1 on an S3 port."""
    c = Conn()
    blob = b"".join(c.head("GET", p, q) for p, q in [
        ("/%s/small.bin" % BUCKET, ()),
        ("/%s" % BUCKET, [("list-type", "2")]),
        ("/%s/nope.bin" % BUCKET, ()),
        ("/%s/small.bin" % BUCKET, ()),
    ])
    c.send(blob)
    for _ in range(4):
        st, _, payload = c.response()
        c.report("GET", "(pipelined)", st, payload)
    c.close()


def s_vhost(key="small.bin"):
    """Virtual-host-style addressing (РS3): the bucket is in Host, not the path."""
    c = Conn(host_header="%s.localhost:%d" % (BUCKET, PORT))
    c.request("GET", "/" + key, host_header="%s.localhost:%d" % (BUCKET, PORT))
    c.close()


def s_anon(key="small.bin"):
    """No credentials at all → user="-" (РS4), and MinIO answers 403 AccessDenied.

    One connection per request on purpose: MinIO closes the connection after an
    anonymous refusal, which is itself part of the shape (`Connection: close`
    ends the unit *and* the connection)."""
    for path, query in (("/%s/%s" % (BUCKET, key), ()),
                        ("/%s" % BUCKET, [("list-type", "2")]),
                        ("/minio/health/live", ())):
        c = Conn()
        c.request("GET", path, query, sign=False)
        c.close()


def s_badsig(key="small.bin"):
    """A well-formed credential with a wrong signature → 403 SignatureDoesNotMatch."""
    c = Conn()
    c.request("GET", "/%s/%s" % (BUCKET, key), bad_signature=True)
    c.close()


def s_presigned(key="small.bin", expires=600):
    qs = sigv4.presign("GET", "/%s/%s" % (BUCKET, key), [], "%s:%d" % (HOST, PORT),
                       AK, SK, REGION, int(expires))
    c = Conn()
    c.send(("GET /%s/%s?%s HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
            % (BUCKET, key, qs, HOST, PORT)).encode())
    st, _, payload = c.response()
    c.report("GET", "/%s/%s (presigned)" % (BUCKET, key), st, payload)
    c.close()


def s_presigned_expired(key="small.bin"):
    import datetime
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    qs = sigv4.presign("GET", "/%s/%s" % (BUCKET, key), [], "%s:%d" % (HOST, PORT),
                       AK, SK, REGION, 60, now=past)
    c = Conn()
    c.send(("GET /%s/%s?%s HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
            % (BUCKET, key, qs, HOST, PORT)).encode())
    st, _, payload = c.response()
    c.report("GET", "/%s/%s (presigned, expired)" % (BUCKET, key), st, payload)
    c.close()


def s_errors():
    """The two error shapes the dashboard cares about, plus the HEAD blind spot."""
    c = Conn()
    c.request("GET", "/%s/no-such-key" % BUCKET)                 # 404 NoSuchKey
    c.request("GET", "/no-such-bucket-lk/x")                     # 404 NoSuchBucket
    c.request("HEAD", "/%s/no-such-key" % BUCKET)                # 404, empty body
    c.request("GET", "/%s/small.bin" % BUCKET, bad_signature=True)  # 403
    c.close()


def s_multipart(key="raw-multipart.bin", parts=3, part_size=5 * 1024 * 1024):
    import hashlib
    parts, part_size = int(parts), int(part_size)
    c = Conn()
    st, hdrs, payload = _req(c, "POST", "/%s/%s" % (BUCKET, key), [("uploads", "")])
    upload_id = re.search(rb"<UploadId>([^<]+)</UploadId>", payload).group(1).decode()
    tags = []
    for i in range(1, parts + 1):
        body = os.urandom(part_size)
        st, hdrs, payload = _req(c, "PUT", "/%s/%s" % (BUCKET, key),
                                 [("partNumber", str(i)), ("uploadId", upload_id)],
                                 body=body, payload_sha=hashlib.sha256(body).hexdigest())
        tags.append((i, hdrs.get("etag", "")))
    _req(c, "GET", "/%s/%s" % (BUCKET, key), [("uploadId", upload_id)])  # ListParts
    xml = ("<CompleteMultipartUpload>"
           + "".join("<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>" % t for t in tags)
           + "</CompleteMultipartUpload>").encode()
    _req(c, "POST", "/%s/%s" % (BUCKET, key), [("uploadId", upload_id)],
         body=xml, payload_sha=hashlib.sha256(xml).hexdigest())
    c.close()


def s_multipart_abort(key="raw-multipart-abort.bin", part_size=5 * 1024 * 1024):
    import hashlib
    c = Conn()
    st, hdrs, payload = _req(c, "POST", "/%s/%s" % (BUCKET, key), [("uploads", "")])
    upload_id = re.search(rb"<UploadId>([^<]+)</UploadId>", payload).group(1).decode()
    body = os.urandom(int(part_size))
    _req(c, "PUT", "/%s/%s" % (BUCKET, key),
         [("partNumber", "1"), ("uploadId", upload_id)],
         body=body, payload_sha=hashlib.sha256(body).hexdigest())
    _req(c, "GET", "/%s" % BUCKET, [("uploads", "")])       # ListMultipartUploads
    _req(c, "DELETE", "/%s/%s" % (BUCKET, key), [("uploadId", upload_id)])
    c.close()


def _req(c, method, path, query=(), **kw):
    """request() that also hands the caller the parsed response."""
    h = dict(kw.pop("headers", None) or {})
    body = kw.pop("body", b"")
    if body:
        h["Content-Length"] = str(len(body))
    c.send(c.head(method, path, query, h, kw.pop("payload_sha", None), **kw))
    if body:
        c.send(body)
    st, hdrs, payload = c.response(no_body=(method == "HEAD"))
    c.report(method, path + ("?" + sigv4.canonical_query(query) if query else ""), st, payload)
    return st, hdrs, payload


def s_delete_objects():
    """POST /bucket?delete — the batch delete, whose keys live in the request body."""
    import hashlib
    c = Conn()
    for i in range(3):
        b = os.urandom(64)
        _req(c, "PUT", "/%s/todelete-%d.bin" % (BUCKET, i), body=b,
             payload_sha=hashlib.sha256(b).hexdigest())
    xml = ("<Delete>" + "".join("<Object><Key>todelete-%d.bin</Key></Object>" % i
                                for i in range(3)) + "</Delete>").encode()
    # MinIO rejects a DeleteObjects without Content-MD5 (400 InvalidRequest) —
    # the batch delete is the one S3 operation that still requires it.
    import base64
    _req(c, "POST", "/%s" % BUCKET, [("delete", "")], body=xml,
         headers={"Content-Md5": base64.b64encode(hashlib.md5(xml).digest()).decode()},
         payload_sha=hashlib.sha256(xml).hexdigest())
    c.close()


def s_copy(key="raw-copy.bin"):
    c = Conn()
    _req(c, "PUT", "/%s/%s" % (BUCKET, key),
         headers={"x-amz-copy-source": "/%s/small.bin" % BUCKET})
    c.close()


def s_list():
    c = Conn()
    _req(c, "GET", "/%s" % BUCKET, [("list-type", "2")])
    _req(c, "GET", "/%s" % BUCKET, [("list-type", "2"), ("max-keys", "2"),
                                    ("prefix", "raw-"), ("delimiter", "/")])
    _req(c, "GET", "/%s" % BUCKET, [])                       # ListObjects V1
    _req(c, "GET", "/%s" % BUCKET, [("versions", "")])       # ListObjectVersions
    _req(c, "GET", "/")                                      # ListBuckets
    c.close()


def s_subresources():
    """The `?<subresource>` operations: one GET each, whatever the answer is."""
    c = Conn()
    for sub in ("acl", "tagging", "policy", "versioning", "lifecycle", "location",
                "notification", "encryption", "replication", "object-lock",
                "cors", "policyStatus", "accelerate", "logging", "requestPayment",
                "website", "publicAccessBlock", "attributes"):
        _req(c, "GET", "/%s" % BUCKET, [(sub, "")])
    for sub in ("acl", "tagging", "retention", "legal-hold", "attributes"):
        _req(c, "GET", "/%s/small.bin" % BUCKET, [(sub, "")])
    c.close()


def s_internal():
    """MinIO's own endpoints (РS2): health, cluster peers, admin, console redirect."""
    c = Conn()
    for path in ("/minio/health/live", "/minio/health/ready", "/minio/health/cluster"):
        _req(c, "GET", path, sign=False)
    _req(c, "GET", "/minio/admin/v3/info")
    _req(c, "GET", "/minio/storage/data/v54/diskinfo")
    _req(c, "GET", "/minio/peer/v41/health")
    c.close()


def s_bucket_names():
    """The bucket-name rules of РS3, checked against the server that enforces
    them: every one of these goes into a Prometheus label if the validator lets
    it, so the validator has to agree with S3 rather than with our idea of a
    plausible name."""
    names = ["abc", "a-b.c", "a" * 63,
             "AB", "a", "ab", "a_b_c", "192.168.1.1", "a" * 64,
             "bucket.", ".bucket", "bucket..name", "-bucket", "buck$et"]
    c = Conn()
    for n in names:
        try:
            _req(c, "GET", "/%s/x" % n)
        except (OSError, EOFError):
            c = Conn()
    c.close()


def s_encoded_keys():
    """Keys that carry every byte class a label must never see (РS2, РS6 privacy)."""
    import hashlib
    keys = [
        "dir/sub dir/file name.txt",
        "üñïcode/файл.txt",
        "weird/a+b=c&d?e#f.txt",
        "deep/" + "/".join("l%d" % i for i in range(12)) + "/leaf.bin",
        "a" * 200 + ".bin",
        "no-extension",
        "%2Fencoded%2Fslash",
    ]
    c = Conn()
    for k in keys:
        b = os.urandom(32)
        _req(c, "PUT", "/%s/%s" % (BUCKET, k), body=b,
             payload_sha=hashlib.sha256(b).hexdigest())
        _req(c, "GET", "/%s/%s" % (BUCKET, k))
        _req(c, "HEAD", "/%s/%s" % (BUCKET, k))
    c.close()


def s_fill(n=300, prefix="fill/"):
    """Create N tiny objects so a listing is big enough to be worth compressing
    (Go frames a response chunked only once it outgrows its 2 KB write buffer —
    which is exactly what a gzipped listing does and a small one does not)."""
    import hashlib
    c = Conn()
    body = b"x" * 16
    sha = hashlib.sha256(body).hexdigest()
    for i in range(int(n)):
        c.send(c.head("PUT", "/%s/%s%04d.bin" % (BUCKET, prefix, i), (),
                      {"Content-Length": str(len(body))}, sha))
        c.send(body)
        c.response()
    print("PUT    %d objects under %s%s" % (int(n), BUCKET, prefix))
    c.close()


def s_gzip_listing():
    """A listing with `Accept-Encoding: gzip` — MinIO compresses XML, which drops
    the length and makes the response `Transfer-Encoding: chunked`. The one
    routine way an S3 response body is chunked (recon item 4)."""
    c = Conn()
    _req(c, "GET", "/%s" % BUCKET, [("list-type", "2")],
         headers={"Accept-Encoding": "gzip"})
    _req(c, "GET", "/%s" % BUCKET, [("list-type", "2")],
         headers={"Accept-Encoding": "identity"})
    c.close()


def s_health(n=5):
    """The unauthenticated liveness probe every deployment runs — `/minio/*`,
    i.e. op="internal" and never an observation (РS2)."""
    c = Conn()
    for _ in range(int(n)):
        _req(c, "GET", "/minio/health/live", sign=False)
    c.close()


def s_range(key="big8m.bin"):
    c = Conn()
    _req(c, "GET", "/%s/%s" % (BUCKET, key), headers={"Range": "bytes=0-65535"})
    _req(c, "GET", "/%s/%s" % (BUCKET, key), headers={"Range": "bytes=8000000-"})
    c.close()


def s_garbage():
    """Requests that must not desync the framer and must not invent an operation."""
    c = Conn()
    _req(c, "GET", "/", [("x-nonsense", "1")])
    _req(c, "PROPFIND", "/%s/small.bin" % BUCKET)
    _req(c, "GET", "/%s/%s" % (BUCKET, "../../etc/passwd"))
    c.close()
    c = Conn()
    c.send(b"\x16\x03\x01\x00\xff garbage where a request line goes\r\n\r\n")
    time.sleep(0.3)
    c.close()


def s_abort_midbody(key="big8m.bin"):
    """RST in the middle of a large GET: the unit ends with the connection."""
    c = Conn()
    c.send(c.head("GET", "/%s/%s" % (BUCKET, key)))
    c.sock.recv(65536)
    import struct
    c.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    c.close()
    print("GET    /%s/%s -> RST mid-body" % (BUCKET, key))


def s_torn_body(key="raw-torn.bin"):
    """A PUT that promises 65536 bytes, sends 100 and hangs up."""
    c = Conn()
    c.send(c.head("PUT", "/%s/%s" % (BUCKET, key), (),
                  {"Content-Length": "65536"}, sigv4.EMPTY_SHA256))
    c.send(b"x" * 100)
    time.sleep(0.3)
    c.close()
    print("PUT    /%s/%s -> torn (100 of 65536 bytes)" % (BUCKET, key))


def s_huge_head(key="small.bin", n=8192):
    """A head far past the capture budget: metadata headers are how S3 gets there."""
    c = Conn()
    # Ordinary headers, not `x-amz-meta-*`: MinIO caps user metadata at 2 KB
    # (400 MetadataTooLarge), so a genuinely huge head has to be built out of
    # headers it does not count — which is also what a proxy chain produces.
    pad = {"X-Lk-Pad-%02d" % i: "v" * 200 for i in range(int(n) // 200)}
    _req(c, "GET", "/%s/%s" % (BUCKET, key), headers=pad)
    c.close()


def s_slow_client(key="small.bin"):
    """The request head one byte at a time: several events, one head."""
    c = Conn()
    head = c.head("GET", "/%s/%s" % (BUCKET, key))
    for b in head:
        c.send(bytes([b]))
        time.sleep(0.002)
    st, _, payload = c.response()
    c.report("GET", "/%s/%s (byte-at-a-time)" % (BUCKET, key), st, payload)
    c.close()


def s_select(key="select.csv"):
    """S3 Select: an event-stream response body, a designed blind spot of §1."""
    import hashlib
    c = Conn()
    csv = b"".join(b"%d,name%d,%d\n" % (i, i, i * 7) for i in range(1000))
    _req(c, "PUT", "/%s/%s" % (BUCKET, key), body=csv,
         payload_sha=hashlib.sha256(csv).hexdigest())
    xml = (b"<SelectObjectContentRequest><Expression>select * from S3Object</Expression>"
           b"<ExpressionType>SQL</ExpressionType>"
           b"<InputSerialization><CSV></CSV></InputSerialization>"
           b"<OutputSerialization><CSV></CSV></OutputSerialization>"
           b"</SelectObjectContentRequest>")
    _req(c, "POST", "/%s/%s" % (BUCKET, key), [("select", ""), ("select-type", "2")],
         body=xml, payload_sha=hashlib.sha256(xml).hexdigest())
    c.close()


SCENARIOS = {name[2:].replace("_", "-"): fn
             for name, fn in sorted(globals().items()) if name.startswith("s_")}
SCENARIOS["chunked-put"] = chunked_put

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in SCENARIOS:
        print("scenarios: " + " ".join(sorted(SCENARIOS)))
        sys.exit(2)
    SCENARIOS[sys.argv[1]](*sys.argv[2:])
