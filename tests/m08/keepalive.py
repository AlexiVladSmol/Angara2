#!/usr/bin/env python3
"""Raw HTTP keep-alive probe used by the M08 reload test."""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time


def read_response(stream) -> tuple[int, int]:
    header = b""
    while b"\r\n\r\n" not in header:
        chunk = stream.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before headers")
        header += chunk
    head, _, rest = header.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    length = 0
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    body = rest
    while len(body) < length:
        chunk = stream.recv(length - len(body))
        if not chunk:
            raise RuntimeError("connection closed before body")
        body += chunk
    return status, length


def request(stream, host: str, port: int, path: str) -> tuple[int, int]:
    payload = (
        f"GET http://{host}:{port}{path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode()
    stream.sendall(payload)
    return read_response(stream)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--origin-host", default="127.0.0.1")
    parser.add_argument("--origin-port", type=int, required=True)
    parser.add_argument("--wait-file", required=True)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout
    sock = socket.create_connection((args.proxy_host, args.proxy_port), timeout=5)
    sock.settimeout(5)
    first, first_len = request(sock, args.origin_host, args.origin_port, "/")
    print(f"first={first} first_bytes={first_len}", flush=True)
    while not os.path.exists(args.wait_file):
        if time.monotonic() > deadline:
            raise SystemExit("timed out waiting for reload marker")
        time.sleep(0.05)
    second, second_len = request(sock, args.origin_host, args.origin_port, "/")
    print(f"second={second} second_bytes={second_len}", flush=True)
    sock.close()
    if first != 200:
        raise SystemExit(f"first response was {first}, not 200")
    if second != 403:
        raise SystemExit(f"second response was {second}, not 403")
    return 0


if __name__ == "__main__":
    sys.exit(main())
