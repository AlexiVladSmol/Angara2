#!/usr/bin/env python3
"""Tiny loopback origin for the Angara M03 manual lab.

Usage:
    python3 examples/m03-local-origin.py [--host 127.0.0.1] [--port 18080]

It intentionally supports only local test endpoints:
    /          plain text
    /binary    fixed binary payload
    /echo      echoes POST/PUT body length and the first bytes
    /range     byte range (Range: bytes=a-b)
    /sse       chunked server-sent events with a short delay
"""

from __future__ import annotations

import argparse
import hashlib
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


BINARY = bytes(range(256)) * 64


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower().strip() == "chunked":
            body = bytearray()
            while True:
                line = self.rfile.readline().strip()
                size = int(line.split(b";", 1)[0], 16)
                if size == 0:
                    while True:
                        trailer = self.rfile.readline()
                        if trailer in (b"\r\n", b"\n", b""):
                            break
                    return bytes(body)
                body.extend(self.rfile.read(size))
                if self.rfile.read(2) != b"\r\n":
                    raise ValueError("bad chunk terminator")
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def _send(self, status: int, body: bytes, headers: list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        for name, value in headers or []:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self) -> None:
        self._send(200, BINARY, [("Content-Type", "application/octet-stream")])

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/binary":
            self._send(200, BINARY, [("Content-Type", "application/octet-stream")])
        elif path == "/range":
            range_header = self.headers.get("Range", "")
            start, end = 0, 15
            if range_header.startswith("bytes="):
                first, _, last = range_header[6:].partition("-")
                start = int(first or 0)
                end = min(int(last or 15), len(BINARY) - 1)
            chunk = BINARY[start : end + 1]
            self._send(
                206,
                chunk,
                [
                    ("Content-Type", "application/octet-stream"),
                    ("Content-Range", f"bytes {start}-{end}/{len(BINARY)}"),
                ],
            )
        elif path == "/sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            for index in range(8):
                chunk = f"data: event {index}\n\n".encode()
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
                time.sleep(0.25)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        else:
            self._send(200, b"angara m03 local origin\n", [("Content-Type", "text/plain")])

    def do_POST(self) -> None:
        body = self._read_body()
        digest = hashlib.sha256(body).hexdigest()[:16]
        response = f"received {len(body)} bytes sha256={digest}\n".encode()
        self._send(200, response, [("Content-Type", "text/plain")])

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_GET


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"m03 local origin on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
