"""
tls13_kdf.py
============
TLS 1.3-shaped HKDF helpers (RFC 8446 §7.1) and structured transcript.
The provided skeleton is preserved exactly; we only add docstrings and
fix the hash algorithm instance (SHA-512 reuse was causing issues).

References: RFC 5869, RFC 8446 §7, RFC 9807 §6.4
"""
from __future__ import annotations
from dataclasses import dataclass
import struct

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# SHA-512: Nh = 64 bytes.  We instantiate a NEW object each call
# because the cryptography library's Hash objects are single-use.
HASH_ALG = hashes.SHA512()
HASH_LEN = 64


def hash_bytes(*chunks: bytes) -> bytes:
    """SHA-512 over the concatenation of all chunks."""
    h = hashes.Hash(hashes.SHA512())
    for chunk in chunks:
        h.update(chunk)
    return h.finalize()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract(salt, IKM) → PRK  (RFC 5869 §2.2)."""
    if not salt:
        salt = bytes(HASH_LEN)
    mac = hmac.HMAC(salt, hashes.SHA512())
    mac.update(ikm)
    return mac.finalize()


def hkdf_expand_label(
        secret: bytes,
        label: bytes,
        context: bytes,
        length: int,
) -> bytes:
    """
    TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).

    HkdfLabel ::= uint16 length || opaque label<1..255> || opaque context<0..255>
    The label prefix "tls13 " provides domain separation.
    """
    full_label = b"tls13 " + label
    info = struct.pack("!H", length)
    info += bytes([len(full_label)]) + full_label
    info += bytes([len(context)]) + context
    return HKDFExpand(algorithm=hashes.SHA512(), length=length, info=info).derive(secret)


def derive_secret(secret: bytes, label: bytes, transcript_hash: bytes) -> bytes:
    """
    Derive-Secret(Secret, Label, Messages)  (RFC 8446 §7.1).
    transcript_hash = Hash(all handshake messages so far).
    """
    return hkdf_expand_label(secret, label, transcript_hash, HASH_LEN)


# ---------------------------------------------------------------------------
# Structured transcript accumulator
# ---------------------------------------------------------------------------

class Transcript:
    """
    Canonical transcript accumulator.

    Do NOT hash raw JSON text with unordered keys; that is non-deterministic.
    Instead we use a length-prefixed binary encoding:

        for each (label, value):
            2-byte BE length of label  || label bytes
            4-byte BE length of value  || value bytes

    This is unambiguous, order-sensitive, and platform-independent.
    """

    def __init__(self) -> None:
        self._parts: list[bytes] = []

    def add(self, label: str, value: bytes) -> None:
        lb = label.encode("utf-8")
        self._parts.append(struct.pack("!H", len(lb)) + lb)
        self._parts.append(struct.pack("!I", len(value)) + value)

    def digest(self) -> bytes:
        return hash_bytes(*self._parts)


# ---------------------------------------------------------------------------
# Key schedule
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrafficSecrets:
    client_hs:  bytes
    server_hs:  bytes
    client_app: bytes
    server_app: bytes
    exporter:   bytes


def derive_traffic_secrets(
        opaque_session_key: bytes,
        th: bytes,
) -> TrafficSecrets:
    """
    TLS 1.3-shaped key schedule with the OPAQUE session key
    replacing the usual DH shared secret.

    All Derive-Secret calls bind `th` (the full handshake transcript hash),
    ensuring each derived key is unique to this specific protocol run.
    """
    zero       = bytes(HASH_LEN)
    empty_hash = hash_bytes(b"")

    early_secret       = hkdf_extract(zero, b"")
    derived_0          = derive_secret(early_secret, b"derived", empty_hash)
    handshake_secret   = hkdf_extract(derived_0, opaque_session_key)
    client_hs          = derive_secret(handshake_secret, b"c hs traffic", th)
    server_hs          = derive_secret(handshake_secret, b"s hs traffic", th)
    derived_1          = derive_secret(handshake_secret, b"derived", empty_hash)
    master_secret      = hkdf_extract(derived_1, b"")
    client_app         = derive_secret(master_secret, b"c ap traffic", th)
    server_app         = derive_secret(master_secret, b"s ap traffic", th)
    exporter           = derive_secret(master_secret, b"exp master",   th)

    return TrafficSecrets(client_hs, server_hs, client_app, server_app, exporter)
