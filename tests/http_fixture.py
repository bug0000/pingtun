#!/usr/bin/env python3
"""Bounded, generated lab traffic. Listen only on the isolated TUN address."""
import hashlib
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

parser = argparse.ArgumentParser()
parser.add_argument('--bytes', type=int, default=262144)
size = parser.parse_args().bytes
if not 256 <= size <= 16777216:
    parser.error('bytes must be 256..16777216')
PAYLOAD = (bytes(range(256)) * ((size + 255) // 256))[:size]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 16777216:
            self.send_error(400)
            return
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            chunk = self.rfile.read(min(remaining, 16384))
            if not chunk:
                self.send_error(400)
                return
            digest.update(chunk)
            remaining -= len(chunk)
        result = (digest.hexdigest() + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)

    def log_message(self, *_):
        pass


ThreadingHTTPServer(("10.203.0.1", 18089), Handler).serve_forever()
