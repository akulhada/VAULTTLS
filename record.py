"""
record.py
=========
Minimal TLS-inspired record protection using ChaCha20-Poly1305.

Security properties
-------------------
* Per-direction keys and IVs are derived from traffic secrets.
* Nonces follow the TLS 1.3 construction:
      nonce = static_iv XOR (0^32 || seq_num^64)
* The receiver enforces an in-order sequence number, so replayed or reordered
  records are rejected before decryption.
* The associated data authenticates the content type, sequence number, and the
  claimed wire length.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from tls13_kdf import hkdf_expand_label

KEY_LEN = 32
IV_LEN = 12
TAG_LEN = 16

# TLS content-type values (RFC 8446 §5.1)
CT_CHANGE_CIPHER = 0x14
CT_ALERT = 0x15
CT_HANDSHAKE = 0x16
CT_APP_DATA = 0x17


@dataclass
class DirectionState:
    """
    One-directional record protection context.

    The same class is used for a sender and for a receiver, but the semantics
    differ slightly:
      * encrypt(): consumes the current sequence number and increments it.
      * decrypt(): requires the caller-provided sequence number to equal the
        next expected value and increments only after successful verification.
    """

    traffic_secret: bytes
    seq: int = 0

    def __post_init__(self) -> None:
        self.key = hkdf_expand_label(self.traffic_secret, b"key", b"", KEY_LEN)
        self.iv = hkdf_expand_label(self.traffic_secret, b"iv", b"", IV_LEN)
        self.aead = ChaCha20Poly1305(self.key)

    def _nonce(self, seq: int) -> bytes:
        padded_seq = (0).to_bytes(4, "big") + seq.to_bytes(8, "big")
        return bytes(a ^ b for a, b in zip(self.iv, padded_seq))

    def _aad(self, content_type: int, seq: int, wire_len: int) -> bytes:
        return (
                bytes([content_type])
                + seq.to_bytes(8, "big")
                + wire_len.to_bytes(4, "big")
        )

    def encrypt(self, content_type: int, plaintext: bytes) -> tuple[int, bytes]:
        seq = self.seq
        self.seq += 1
        wire_len = len(plaintext) + TAG_LEN
        aad = self._aad(content_type, seq, wire_len)
        nonce = self._nonce(seq)
        ciphertext = self.aead.encrypt(nonce, plaintext, aad)
        return seq, ciphertext

    def decrypt(self, content_type: int, seq: int, ciphertext: bytes) -> bytes:
        if seq != self.seq:
            raise ValueError(
                f"Unexpected record sequence number: expected {self.seq}, got {seq}"
            )
        aad = self._aad(content_type, seq, len(ciphertext))
        nonce = self._nonce(seq)
        plaintext = self.aead.decrypt(nonce, ciphertext, aad)
        self.seq += 1
        return plaintext
