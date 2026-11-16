#!/usr/bin/env python3
"""Controlled HTTP/HTTPS origin used by the M08 stand tests.

The origin is deliberately small and dependency-free.  It records every
accepted peer and request in a log file so tests can distinguish "the proxy
returned 403" from "the origin was actually contacted".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


BLOCK = bytes(((index * 17) % 251) for index in range(64 * 1024))
LOCK = threading.Lock()


def pattern_hash(total: int) -> str:
    digest = hashlib.sha256()
    remaining = total
    while remaining:
        chunk = min(remaining, len(BLOCK))
        digest.update(BLOCK[:chunk])
        remaining -= chunk
    return digest.hexdigest()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AngaraM08Origin/1.0"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _record(self, extra: str = "") -> None:
        peer = self.client_address[0]
        line = f"{peer}\t{self.command}\t{self.path}\t{extra}\n"
        log_path = getattr(self.server, "request_log", None)
        if log_path:
            with LOCK:
                with open(log_path, "a", encoding="utf-8") as handle:
                    handle.write(line)

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str = "text/plain",
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra_headers or []:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_stream(self, total: int, delay_ms: int = 0) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(total))
        self.end_headers()
        if self.command == "HEAD":
            return
        remaining = total
        while remaining:
            chunk = BLOCK[: min(remaining, len(BLOCK))]
            self.wfile.write(chunk)
            remaining -= len(chunk)
            if delay_ms:
                time.sleep(delay_ms / 1000.0)

    def _send_chunked(self, events: int, delay_ms: int) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for index in range(events):
            payload = f"data: event {index}\n\n".encode()
            self.wfile.write(f"{len(payload):x}\r\n".encode() + payload + b"\r\n")
            self.wfile.flush()
            if delay_ms:
                time.sleep(delay_ms / 1000.0)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def do_HEAD(self) -> None:
        self._record()
        self._send_bytes(200, b"head-ok")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/":
            self._record()
            self._send_bytes(200, b"m08-origin-ok\n")
        elif parsed.path == "/delay":
            delay = int(query.get("ms", ["50"])[0])
            self._record(f"delay={delay}")
            time.sleep(max(delay, 0) / 1000.0)
            self._send_bytes(200, b"delay-ok\n")
        elif parsed.path == "/download":
            total = int(query.get("bytes", ["1048576"])[0])
            delay = int(query.get("delay_ms", ["0"])[0])
            self._record(f"download={total}")
            self._send_stream(total, delay)
        elif parsed.path == "/range":
            self._record()
            data = BLOCK[:1024]
            range_header = self.headers.get("Range", "")
            start, end = 0, 15
            if range_header.startswith("bytes="):
                first, _, last = range_header[6:].partition("-")
                start = int(first or 0)
                end = min(int(last or 15), len(data) - 1)
            chunk = data[start : end + 1]
            self._send_bytes(
                206,
                chunk,
                "application/octet-stream",
                [("Content-Range", f"bytes {start}-{end}/{len(data)}")],
            )
        elif parsed.path == "/headers":
            self._record()
            body = json.dumps(
                {name: value for name, value in self.headers.items()},
                sort_keys=True,
            ).encode()
            self._send_bytes(200, body, "application/json")
        elif parsed.path == "/sse":
            self._record()
            self._send_chunked(int(query.get("events", ["8"])[0]), 50)
        elif parsed.path == "/health":
            self._record()
            self._send_bytes(200, b"healthy\n")
        elif parsed.path == "/slow":
            self._record()
            delay = int(query.get("ms", ["1000"])[0])
            self.send_response(200)
            self.send_header("Content-Length", "32")
            self.end_headers()
            self.wfile.write(b"x" * 8)
            self.wfile.flush()
            time.sleep(max(delay, 0) / 1000.0)
            self.wfile.write(b"y" * 24)
        else:
            self._record("not-found")
            self._send_bytes(404, b"not-found\n")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length)
        if parsed.path == "/upload":
            self._record(f"upload={len(body)}")
            response = json.dumps(
                {"received": len(body), "sha256": hashlib.sha256(body).hexdigest()},
                sort_keys=True,
            ).encode()
            self._send_bytes(200, response, "application/json")
        else:
            self._record("not-found")
            self._send_bytes(404, b"not-found\n")

    do_PUT = do_POST
    do_PATCH = do_POST


class Server(ThreadingHTTPServer):
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--log", default="")
    parser.add_argument("--print-hash", type=int, default=0)
    args = parser.parse_args()
    if args.print_hash:
        print(pattern_hash(args.print_hash))
        return 0

    server = Server((args.host, args.port), Handler)
    server.request_log = args.log or None
    if args.cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"PORT={server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
