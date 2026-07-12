#!/usr/bin/env python3
"""Dummy OTLP/HTTP collector for benchmark configuration E (Р49).

Accepts any POST (/v1/metrics, /v1/traces), reads the body, answers 200
with an empty protobuf body — the cheapest well-behaved peer, so the
benchmark measures the agent's export path, not a collector.

Usage: otlp_sink.py [port]   (default 43181, binds 127.0.0.1)
"""

import http.server
import sys


class Sink(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    posts = 0

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        Sink.posts += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/x-protobuf")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):  # one line per request is enough
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 43181
    with http.server.ThreadingHTTPServer(("127.0.0.1", port), Sink) as srv:
        print("otlp sink on 127.0.0.1:%d" % port, flush=True)
        srv.serve_forever()
