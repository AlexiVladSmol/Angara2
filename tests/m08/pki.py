#!/usr/bin/env python3
"""Generate two independent test CAs for M08 proxy/site TLS checks."""

from __future__ import annotations

import argparse
import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def name(common_name: str):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def ca(common_name: str, directory: Path, prefix: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = name(common_name)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now() - datetime.timedelta(minutes=5))
        .not_valid_after(now() + datetime.timedelta(days=2))
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
        .sign(key, hashes.SHA256())
    )
    (directory / f"{prefix}_ca.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    return key, certificate


def leaf(common_name: str, ip: str, ca_key, ca_cert, directory: Path, prefix: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now() - datetime.timedelta(minutes=5))
        .not_valid_after(now() + datetime.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(__import__("ipaddress").ip_address(ip))]
            ),
            critical=False,
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
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    (directory / f"{prefix}_chain.pem").write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    (directory / f"{prefix}_key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, type=Path)
    args = parser.parse_args()
    directory = args.dir
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    proxy_key, proxy_ca = ca("Angara M08 proxy test CA", directory, "proxy")
    site_key, site_ca = ca("Angara M08 site test CA", directory, "site")
    leaf("angara-m08-proxy", "127.0.0.1", proxy_key, proxy_ca, directory, "proxy")
    leaf("angara-m08-site", "127.0.0.1", site_key, site_ca, directory, "site")
    for path in directory.iterdir():
        if path.is_file():
            os.chmod(path, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
