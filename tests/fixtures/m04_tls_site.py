#!/usr/bin/env python3
"""Local TLS HTTPS fixture for M04 CONNECT tests.

Generates a temporary CA/server certificate in the supplied directory, then
serves a tiny HTTPS site on 127.0.0.1 and prints its port as PORT=<n>.
The private key stays in the temporary directory and is never committed.
"""

import argparse
import hashlib
import http.server
import os
import socket
import ssl
import subprocess
import sys
import threading


def generate_with_cryptography(directory: str) -> None:
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Angara M04 test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    server = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    with open(os.path.join(directory, "ca.pem"), "wb") as handle:
        handle.write(ca.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(directory, "server.pem"), "wb") as handle:
        handle.write(server.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(directory, "server.key"), "wb") as handle:
        handle.write(
            server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )


def generate_with_openssl(directory: str) -> None:
    ca_key = os.path.join(directory, "ca.key")
    ca_cert = os.path.join(directory, "ca.pem")
    server_key = os.path.join(directory, "server.key")
    server_csr = os.path.join(directory, "server.csr")
    server_cert = os.path.join(directory, "server.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=Angara M04 test CA", "-keyout", ca_key, "-out", ca_cert],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
         "-keyout", server_key, "-out", server_csr],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    with open(os.path.join(directory, "san.cnf"), "w", encoding="ascii") as handle:
        handle.write(
            "subjectAltName=DNS:localhost\n"
            "authorityKeyIdentifier=keyid,issuer\n"
            "subjectKeyIdentifier=hash\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
        )
    subprocess.run(
        ["openssl", "x509", "-req", "-in", server_csr, "-CA", ca_cert, "-CAkey", ca_key,
         "-CAcreateserial", "-days", "1", "-extfile", os.path.join(directory, "san.cnf"),
         "-out", server_cert],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def ensure_certificates(directory: str) -> None:
    try:
        generate_with_cryptography(directory)
    except ImportError:
        generate_with_openssl(directory)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/download":
            body = bytes(((index * 17) % 251) for index in range(1024 * 1024))
        elif self.path == "/":
            body = b"tls-ok"
        else:
            body = b"not-found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/upload":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        response = f"upload:{len(body)}:{hashlib.sha256(body).hexdigest()}".encode("ascii")
        self.send_response(200)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format, *_args):
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True)
    args = parser.parse_args()
    ensure_certificates(args.dir)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        os.path.join(args.dir, "server.pem"),
        os.path.join(args.dir, "server.key"),
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
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
    sys.exit(main())
