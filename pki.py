"""
pki.py
======
PKI helpers: certificate generation, trust-anchor verification, and the two
handshake signature operations used by VAULTTLS.

Key choices
-----------
  CA keypair    : Ed25519        — deterministic signatures, compact root CA
  Server keypair: P-256 ECDSA    — used for the server certificate and the
                                   per-session CertificateVerify signature

Trust model
-----------
The client does *not* trust whatever CA certificate arrives on the wire.
Instead, it loads the locally pinned CA certificate from config.CA_CERT_PATH
and requires the on-wire CA certificate to match it byte-for-byte. This is
closer to how a real TLS client uses a root store: trust is established
out-of-band, not by the peer presenting its own trust anchor.

CertificateVerify construction (TLS 1.3-inspired)
-------------------------------------------------
  msg = 0x20*64 || "CSE539 CertificateVerify" || 0x00
        || SHA-512(transcript_hash || server_hello_core)
  sig = ECDSA-P256-SHA256(server_key, msg)

References: RFC 5280, RFC 8032, RFC 8446 §4.4.3, RFC 9525
"""
from __future__ import annotations

import datetime
import os
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from config import (
    CA_CERT_PATH,
    CA_VALIDITY_DAYS,
    CERTS_DIR,
    SERVER_CERT_KEY_PATH,
    SERVER_CERT_PATH,
    SERVER_VALIDITY_DAYS,
)
from tls13_kdf import hash_bytes

BACKEND = default_backend()

# TLS 1.3-style CertificateVerify disambiguation (RFC 8446 §4.4.3 pattern)
_CV_PREFIX = b"\x20" * 64
_CV_LABEL = b"CSE539 CertificateVerify\x00"

# Static ServerConfig signing label
_SC_PREFIX = b"CSE539 ServerConfig\x00"


def _build_cv_message(transcript_hash: bytes, server_hello_core: bytes) -> bytes:
    """
    Build the bytes signed by CertificateVerify.

    transcript_hash is the hash of all handshake messages *before*
    ServerHello is appended. server_hello_core is the signed portion of the
    ServerHello itself. Hashing their concatenation keeps the signed payload
    fixed-length and unambiguous.
    """
    return _CV_PREFIX + _CV_LABEL + hash_bytes(transcript_hash, server_hello_core)


# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

def generate_ca() -> tuple[Ed25519PrivateKey, x509.Certificate]:
    """Generate a self-signed Ed25519 root CA certificate."""
    key = Ed25519PrivateKey.generate()
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSE539 Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CSE539 Root CA v1"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, algorithm=None, backend=BACKEND)
    )
    return key, cert


def generate_server_cert(
        ca_key: Ed25519PrivateKey,
        ca_cert: x509.Certificate,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate a P-256 server certificate signed by the local CA."""
    key = ec.generate_private_key(ec.SECP256R1(), BACKEND)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSE539 VAULTTLS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=SERVER_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_agreement=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, algorithm=None, backend=BACKEND)
    )
    return key, cert


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def save_private_key(key, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )


save_privkey = save_private_key


def save_certificate(cert: x509.Certificate, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


save_cert = save_certificate


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


load_privkey = load_private_key


def load_certificate(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


load_cert = load_certificate


# ---------------------------------------------------------------------------
# Certificate-chain wire format
# ---------------------------------------------------------------------------

def encode_cert_chain(ca_cert: x509.Certificate, srv_cert: x509.Certificate) -> bytes:
    """
    Encode a two-certificate chain as:
        [3-byte len][CA DER][3-byte len][server DER]
    """

    def _wrap(cert: x509.Certificate) -> bytes:
        der = cert.public_bytes(serialization.Encoding.DER)
        return len(der).to_bytes(3, "big") + der

    return _wrap(ca_cert) + _wrap(srv_cert)



def _decode_cert_chain(data: bytes) -> tuple[x509.Certificate, x509.Certificate]:
    pos = 0
    certs: list[x509.Certificate] = []
    while pos < len(data):
        if pos + 3 > len(data):
            raise ValueError("Truncated certificate chain length")
        n = int.from_bytes(data[pos : pos + 3], "big")
        pos += 3
        if pos + n > len(data):
            raise ValueError("Truncated certificate chain body")
        certs.append(x509.load_der_x509_certificate(data[pos : pos + n]))
        pos += n
    if len(certs) != 2:
        raise ValueError(f"Expected exactly 2 certs, got {len(certs)}")
    return certs[0], certs[1]


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------

def _verify_ed25519_cert_signature(issuer_cert: x509.Certificate, cert: x509.Certificate) -> None:
    """Verify an Ed25519-signed certificate with its issuer public key."""
    issuer_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes)



def verify_certificate_chain(
        cert_chain_bytes: bytes,
        expected_name: str = "localhost",
        trusted_ca_cert: Optional[x509.Certificate] = None,
) -> x509.Certificate:
    """
    Parse and verify the server certificate chain against the *pinned* CA.

    Checks:
      1. The on-wire CA certificate exactly matches the locally trusted CA.
      2. The trusted CA is self-signed (sanity check for local setup).
      3. The server certificate is signed by that CA.
      4. The server certificate is currently valid.
      5. The expected DNS name appears in SAN or CN.

    Returns the validated server certificate on success.
    """
    wire_ca_cert, srv_cert = _decode_cert_chain(cert_chain_bytes)
    pinned_ca_cert = trusted_ca_cert or load_certificate(CA_CERT_PATH)

    wire_ca_der = wire_ca_cert.public_bytes(serialization.Encoding.DER)
    pinned_ca_der = pinned_ca_cert.public_bytes(serialization.Encoding.DER)
    if wire_ca_der != pinned_ca_der:
        raise ValueError("Certificate chain is anchored in an untrusted CA")

    try:
        _verify_ed25519_cert_signature(pinned_ca_cert, pinned_ca_cert)
    except Exception as exc:
        raise ValueError(f"Pinned CA certificate failed self-signature check: {exc}") from exc

    try:
        _verify_ed25519_cert_signature(pinned_ca_cert, srv_cert)
    except Exception as exc:
        raise ValueError(f"Server certificate signature invalid: {exc}") from exc

    if srv_cert.issuer != pinned_ca_cert.subject:
        raise ValueError("Server certificate issuer does not match the trusted CA")

    now = datetime.datetime.now(datetime.timezone.utc)
    if now < srv_cert.not_valid_before_utc:
        raise ValueError("Server certificate not yet valid")
    if now > srv_cert.not_valid_after_utc:
        raise ValueError("Server certificate expired")

    try:
        bc = srv_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            raise ValueError("Server certificate incorrectly marked as a CA")
    except x509.ExtensionNotFound:
        raise ValueError("Server certificate missing BasicConstraints")

    try:
        san_ext = srv_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_dns = []

    common_names = [a.value for a in srv_cert.subject if a.oid == NameOID.COMMON_NAME]
    if expected_name not in san_dns + common_names:
        raise ValueError(f"Expected server name {expected_name!r} not found in certificate")

    return srv_cert


# ---------------------------------------------------------------------------
# CertificateVerify
# ---------------------------------------------------------------------------

def sign_cert_verify(
        server_key: ec.EllipticCurvePrivateKey,
        transcript_hash: bytes,
        server_hello_core: bytes,
) -> bytes:
    """Produce the per-session CertificateVerify signature."""
    return server_key.sign(
        _build_cv_message(transcript_hash, server_hello_core),
        ec.ECDSA(hashes.SHA256()),
    )



def verify_certificate_verify_signature(
        cert_verify_sig: bytes,
        transcript_hash: bytes,
        server_hello_core: bytes,
        server_cert: x509.Certificate,
) -> None:
    """Verify the per-session CertificateVerify signature."""
    msg = _build_cv_message(transcript_hash, server_hello_core)
    try:
        server_cert.public_key().verify(cert_verify_sig, msg, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        raise ValueError(f"CertificateVerify invalid: {exc}") from exc


# ---------------------------------------------------------------------------
# ServerConfig signature
# ---------------------------------------------------------------------------

def sign_server_config(
        server_key: ec.EllipticCurvePrivateKey,
        server_config: bytes,
) -> bytes:
    """Sign the static server capability blob."""
    return server_key.sign(_SC_PREFIX + server_config, ec.ECDSA(hashes.SHA256()))



def verify_server_config_signature(
        server_config: bytes,
        server_config_sig: bytes,
        server_cert: x509.Certificate,
) -> None:
    """Verify the static ServerConfig signature using the certified server key."""
    try:
        server_cert.public_key().verify(
            server_config_sig,
            _SC_PREFIX + server_config,
            ec.ECDSA(hashes.SHA256()),
            )
    except Exception as exc:
        raise ValueError(f"ServerConfig signature invalid: {exc}") from exc


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def bootstrap_pki(force: bool = False) -> None:
    """
    Generate CA + server certificate if missing.

    The CA private key is intentionally *not* stored because the client only
    needs the root certificate as a trust anchor for this class project.
    """
    missing = (
            not os.path.exists(CA_CERT_PATH)
            or not os.path.exists(SERVER_CERT_PATH)
            or not os.path.exists(SERVER_CERT_KEY_PATH)
    )
    if not force and not missing:
        return

    os.makedirs(CERTS_DIR, exist_ok=True)
    ca_key, ca_cert = generate_ca()
    srv_key, srv_cert = generate_server_cert(ca_key, ca_cert)

    save_certificate(ca_cert, CA_CERT_PATH)
    save_private_key(srv_key, SERVER_CERT_KEY_PATH)
    save_certificate(srv_cert, SERVER_CERT_PATH)

    # Self-check the generated chain against the pinned root.
    verify_certificate_chain(encode_cert_chain(ca_cert, srv_cert), trusted_ca_cert=ca_cert)


if __name__ == "__main__":
    bootstrap_pki(force=True)
