#!/usr/bin/env python3
"""Generate private M06 proxy/site PKI fixtures in a temporary directory.

The generated material is test-only. It never leaves the supplied private
directory and is never committed.
"""

import argparse
import datetime
import ipaddress
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def ca_certificate(subject, issuer, public_key, issuer_key, path_length):
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now() - datetime.timedelta(minutes=5))
        .not_valid_after(now() + datetime.timedelta(days=2))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length), critical=True
        )
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
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        .sign(issuer_key, hashes.SHA256())
    )


def leaf_certificate(
    common_name, san, issuer, issuer_key, public_key, expired=False, ip_sans=()
):
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(common_name))
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now() - datetime.timedelta(minutes=5))
        .not_valid_after(
            now() - datetime.timedelta(minutes=1)
            if expired
            else now() + datetime.timedelta(days=2)
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(value) for value in san]
                + [x509.IPAddress(ipaddress.ip_address(value)) for value in ip_sans]
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
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
    )
    return builder.sign(issuer_key, hashes.SHA256())


def write(path, data):
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, 0o600)


def pem_certificate(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def pem_key(key, encrypted=False):
    encryption = (
        BestAvailableEncryption(b"synthetic-key-password")
        if encrypted
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )


def generate(directory):
    os.makedirs(directory, mode=0o700, exist_ok=True)

    proxy_root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    proxy_root_name = name("Angara M06 proxy root CA")
    proxy_root = ca_certificate(
        proxy_root_name, proxy_root_name, proxy_root_key.public_key(), proxy_root_key, None
    )
    proxy_intermediate_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    proxy_intermediate_name = name("Angara M06 proxy intermediate CA")
    proxy_intermediate = ca_certificate(
        proxy_intermediate_name,
        proxy_root_name,
        proxy_intermediate_key.public_key(),
        proxy_root_key,
        0,
    )

    proxy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    proxy_leaf = leaf_certificate(
        "localhost",
        ["localhost"],
        proxy_intermediate_name,
        proxy_intermediate_key,
        proxy_key.public_key(),
    )
    proxy_chain = pem_certificate(proxy_leaf) + pem_certificate(proxy_intermediate)
    write(os.path.join(directory, "proxy_ca.pem"), pem_certificate(proxy_root))
    write(
        os.path.join(directory, "proxy_intermediate.pem"),
        pem_certificate(proxy_intermediate),
    )
    write(os.path.join(directory, "proxy_chain.pem"), proxy_chain)
    write(os.path.join(directory, "proxy_key.pem"), pem_key(proxy_key))
    write(
        os.path.join(directory, "proxy_chain_leaf_only.pem"),
        pem_certificate(proxy_leaf),
    )

    proxy_ip_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    proxy_ip_leaf = leaf_certificate(
        "127.0.0.1",
        [],
        proxy_intermediate_name,
        proxy_intermediate_key,
        proxy_ip_key.public_key(),
        ip_sans=["127.0.0.1"],
    )
    write(
        os.path.join(directory, "proxy_ip_chain.pem"),
        pem_certificate(proxy_ip_leaf) + pem_certificate(proxy_intermediate),
    )
    write(os.path.join(directory, "proxy_ip_key.pem"), pem_key(proxy_ip_key))

    p256_key = ec.generate_private_key(ec.SECP256R1())
    p256_leaf = leaf_certificate(
        "localhost",
        ["localhost"],
        proxy_intermediate_name,
        proxy_intermediate_key,
        p256_key.public_key(),
    )
    write(
        os.path.join(directory, "proxy_p256_chain.pem"),
        pem_certificate(p256_leaf) + pem_certificate(proxy_intermediate),
    )
    write(os.path.join(directory, "proxy_p256_key.pem"), pem_key(p256_key))

    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_leaf = leaf_certificate(
        "wrong.invalid",
        ["wrong.invalid"],
        proxy_intermediate_name,
        proxy_intermediate_key,
        wrong_key.public_key(),
    )
    write(
        os.path.join(directory, "proxy_wrong_chain.pem"),
        pem_certificate(wrong_leaf) + pem_certificate(proxy_intermediate),
    )
    write(os.path.join(directory, "proxy_wrong_key.pem"), pem_key(wrong_key))

    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_leaf = leaf_certificate(
        "localhost",
        ["localhost"],
        proxy_intermediate_name,
        proxy_intermediate_key,
        expired_key.public_key(),
        expired=True,
    )
    write(
        os.path.join(directory, "proxy_expired_chain.pem"),
        pem_certificate(expired_leaf) + pem_certificate(proxy_intermediate),
    )
    write(os.path.join(directory, "proxy_expired_key.pem"), pem_key(expired_key))
    write(
        os.path.join(directory, "proxy_encrypted_key.pem"),
        pem_key(proxy_key, encrypted=True),
    )

    alt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alt_leaf = leaf_certificate(
        "alt.localhost",
        ["alt.localhost"],
        proxy_intermediate_name,
        proxy_intermediate_key,
        alt_key.public_key(),
    )
    write(
        os.path.join(directory, "proxy_alt_chain.pem"),
        pem_certificate(alt_leaf) + pem_certificate(proxy_intermediate),
    )
    write(os.path.join(directory, "proxy_alt_key.pem"), pem_key(alt_key))

    site_root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    site_root_name = name("Angara M06 site root CA")
    site_root = ca_certificate(
        site_root_name, site_root_name, site_root_key.public_key(), site_root_key, None
    )
    site_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    site_leaf = leaf_certificate(
        "localhost",
        ["localhost"],
        site_root_name,
        site_root_key,
        site_key.public_key(),
    )
    write(os.path.join(directory, "site_ca.pem"), pem_certificate(site_root))
    write(os.path.join(directory, "site_chain.pem"), pem_certificate(site_leaf))
    write(os.path.join(directory, "site_key.pem"), pem_key(site_key))

    site_expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    site_expired_leaf = leaf_certificate(
        "localhost",
        ["localhost"],
        site_root_name,
        site_root_key,
        site_expired_key.public_key(),
        expired=True,
    )
    write(
        os.path.join(directory, "site_expired_chain.pem"),
        pem_certificate(site_expired_leaf),
    )
    write(
        os.path.join(directory, "site_expired_key.pem"),
        pem_key(site_expired_key),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True)
    args = parser.parse_args()
    generate(args.dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
