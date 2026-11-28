#!/usr/bin/env python3
"""Minimal JSONL client for the M11 systemd acceptance checks."""

import argparse
import json
import socket
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--op", required=True)
    parser.add_argument("--id", type=int, default=1)
    args = parser.parse_args()

    raw = sys.stdin.read().strip()
    extra = json.loads(raw) if raw else {}
    request = {"v": 1, "id": extra.pop("id", args.id), "op": args.op}
    request.update(extra)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect(args.socket)
    except OSError as error:
        print(f"control connect failed: {error}", file=sys.stderr)
        return 2
    try:
        sock.sendall(json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n")
        data = b""
        while b"\n" not in data:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    if b"\n" not in data:
        print("control response is incomplete", file=sys.stderr)
        return 3
    print(data.split(b"\n", 1)[0].decode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
