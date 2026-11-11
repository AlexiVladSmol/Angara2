#!/usr/bin/env python3
"""HTTPS-through-CONNECT client for M04 tests.

Modes:
  good        verify the test CA and hostname localhost
  wrong-name  verify the CA but connect by 127.0.0.1 (cert SAN is localhost)
  wrong-ca    use the default trust store instead of the test CA
"""

import argparse
import http.client
import ssl
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy-host", required=True)
    parser.add_argument("--proxy-port", required=True, type=int)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", required=True, type=int)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--mode", choices=["good", "wrong-name", "wrong-ca"], required=True)
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
            timeout=10,
        )
        host = "127.0.0.1" if args.mode == "wrong-name" else "localhost"
        connection.set_tunnel(host, args.target_port)
        connection.request("GET", "/", headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        if args.mode != "good":
            print("unexpected-success", file=sys.stderr)
            return 3
        if response.status != 200 or body != b"tls-ok":
            print(f"bad-response status={response.status} body={body!r}", file=sys.stderr)
            return 4
        print("TLS_OK")
        return 0
    except ssl.SSLError as error:
        if args.mode == "good":
            print(f"good TLS failed: {error}", file=sys.stderr)
            return 5
        print("TLS_REJECTED")
        return 0
    except OSError as error:
        if args.mode == "good":
            print(f"good request failed: {error}", file=sys.stderr)
            return 6
        print("TLS_REJECTED")
        return 0


if __name__ == "__main__":
    sys.exit(main())
