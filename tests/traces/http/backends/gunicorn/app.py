# SPDX-License-Identifier: GPL-2.0
# М0 trace-corpus backend: Flask under gunicorn's sync worker (a fourth
# HTTP/1.1 server writer — gunicorn frames responses itself, werkzeug only
# builds them).
#
#   gunicorn -w 1 -b :8084 --chdir backends/gunicorn app:app
#
# Same route contract as backends/go, minus the hijack-only routes.
import time

from flask import Flask, Response, redirect, request

FILLER = b"0123456789abcdef"
app = Flask(__name__)


def _int_arg(key, default):
    try:
        v = int(request.args.get(key, default))
    except ValueError:
        return default
    return v if v >= 0 else default


@app.route("/hello.txt", methods=["GET", "HEAD", "POST", "OPTIONS", "PATCH", "TRACE"])
@app.route("/hello", methods=["GET", "HEAD", "POST", "OPTIONS", "PATCH", "TRACE"])
def hello():
    return Response("hello from gunicorn, method=%s\n" % request.method,
                    mimetype="text/plain")


@app.route("/json/<path:rest>")
def json_route(rest):
    return Response('{"id": "%s", "q": "%s"}\n' % (rest, request.query_string.decode()),
                    mimetype="application/json")


@app.route("/big")
def big():
    n = _int_arg("n", 1 << 20)
    body = (FILLER * (1 + n // len(FILLER)))[:n]
    return Response(body, mimetype="application/octet-stream")


@app.route("/auto")
def auto():
    # Reconnaissance item 2: a str/bytes body — werkzeug always knows the
    # length, so gunicorn frames it with Content-Length at any size.
    n = _int_arg("n", 1024)
    return Response((FILLER * (1 + n // len(FILLER)))[:n], mimetype="text/plain")


@app.route("/chunked")
def chunked():
    # A generator response has no Content-Length, so gunicorn frames it
    # chunked (HTTP/1.1 keep-alive).
    n = _int_arg("n", 5)

    def gen():
        for i in range(n):
            yield "chunk %d of %d\n" % (i, n)
            time.sleep(0.005)

    return Response(gen(), mimetype="text/plain")


@app.route("/echo", methods=["POST", "PUT"])
def echo():
    # gunicorn's sync worker emits "100 Continue" on the first body read when
    # the request carries Expect: 100-continue.
    n = 0
    while True:
        buf = request.stream.read(65536)
        if not buf:
            break
        n += len(buf)
    return Response("read %d bytes, te=%s\n"
                    % (n, request.headers.get("Transfer-Encoding", "-")),
                    mimetype="text/plain")


@app.route("/redirect")
def redirect_route():
    return redirect("/hello", code=302)


@app.route("/boom")
def boom():
    return Response("boom\n", status=500, mimetype="text/plain")


@app.route("/slow")
def slow():
    time.sleep(_int_arg("ms", 200) / 1000.0)
    return Response("slow ok\n", mimetype="text/plain")


@app.route("/truncate")
def truncate():
    # Promise n bytes, deliver 1 KB, then let the worker close the connection:
    # gunicorn detects the short body and drops the connection.
    n = _int_arg("n", 1 << 16)
    return Response((FILLER * 64), status=200,
                    headers={"Content-Length": str(n),
                             "Content-Type": "application/octet-stream"})
