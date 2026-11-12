#!/usr/bin/env python3
"""HTTPS-through-CONNECT client for M04/M05 tests.

Modes:
  good           verify the test CA and hostname localhost; short GET
  good-upload    POST a 1 MiB binary payload through the tunnel
  good-download  GET and verify a 1 MiB streaming payload through the tunnel
  wrong-name     CA-valid certificate checked against 127.0.0.1 (SAN localhost)
  wrong-ca       default trust store instead of the test CA

An optional --proxy-password adds Basic proxy authorization to CONNECT.
Negative modes succeed only on an expected certificate-verification failure.
Connection, CONNECT, timeout and protocol failures always fail the test.
"""

import argparse
import base64
import hashlib
import http.client
import ssl
import sys

UPLOAD = bytes(range(256)) * 4096
DOWNLOAD = bytes(((index * 17) % 251) for index in range(1024 * 1024))
DOWNLOAD_SHA256 = hashlib.sha256(DOWNLOAD).hexdigest()


def verify_certificate_failure(mode: str, error: ssl.SSLCertVerificationError) -> bool:
    message = (error.verify_message or str(error)).lower()
    code = error.verify_code
    if mode == "wrong-name":
        return code == 62 or "hostname" in message or "ip address mismatch" in message
    if mode == "wrong-ca":
        return (
            code in {18, 19, 20, 21, 27}
            or "self-signed" in message
            or "issuer" in message
            or "unable to get local issuer" in message
        )
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy-host", required=True)
    parser.add_argument("--proxy-port", required=True, type=int)
    parser.add_argument("--target-port", required=True, type=int)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--proxy-password")
    parser.add_argument(
        "--mode",
        choices=["good", "good-upload", "good-download", "wrong-name", "wrong-ca"],
        required=True,
    )
    args = parser.parse_args()

    if args.mode == "wrong-ca":
        context = ssl.create_default_context()
    else:
        context = ssl.create_default_context(cafile=args.ca)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        connection = http.client.HTTPSConnection(
            args.proxy_host,
            args.proxy_port,
            context=context,
            timeout=20,
        )
        host = "127.0.0.1" if args.mode == "wrong-name" else "localhost"
        tunnel_headers = {}
        if args.proxy_password is not None:
            token = base64.b64encode(
                f"alice:{args.proxy_password}".encode("utf-8")
            ).decode("ascii")
            tunnel_headers["Proxy-Authorization"] = f"Basic {token}"
        connection.set_tunnel(host, args.target_port, headers=tunnel_headers)
        if args.mode == "good-upload":
            connection.request(
                "POST",
                "/upload",
                body=UPLOAD,
                headers={"Connection": "close", "Content-Type": "application/octet-stream"},
            )
        else:
            connection.request("GET", "/download" if args.mode == "good-download" else "/",
                               headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        if args.mode in {"wrong-name", "wrong-ca"}:
            print("unexpected-success", file=sys.stderr)
            return 3
        if response.status != 200:
            print(f"bad-response status={response.status} body={body!r}", file=sys.stderr)
            return 4
        if args.mode == "good":
            if body != b"tls-ok":
                print(f"bad GET body {body!r}", file=sys.stderr)
                return 5
            print("TLS_OK")
        elif args.mode == "good-upload":
            expected = f"upload:{len(UPLOAD)}:{hashlib.sha256(UPLOAD).hexdigest()}"
            if body.decode("ascii", "replace") != expected:
                print(f"bad upload response {body!r}", file=sys.stderr)
                return 6
            print("TLS_UPLOAD_OK")
        else:
            if len(body) != 1024 * 1024 or hashlib.sha256(body).hexdigest() != DOWNLOAD_SHA256:
                print(f"bad download len={len(body)}", file=sys.stderr)
                return 7
            print("TLS_DOWNLOAD_OK")
        return 0
    except ssl.SSLCertVerificationError as error:
        if args.mode in {"wrong-name", "wrong-ca"} and verify_certificate_failure(
            args.mode, error
        ):
            print("TLS_REJECTED")
            return 0
        print(f"unexpected certificate failure: {error}", file=sys.stderr)
        return 8
    except ssl.SSLError as error:
        print(f"unexpected TLS protocol failure: {error}", file=sys.stderr)
        return 9
    except OSError as error:
        print(f"unexpected connection failure: {error}", file=sys.stderr)
        return 10


if __name__ == "__main__":
    sys.exit(main())
