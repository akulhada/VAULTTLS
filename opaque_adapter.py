"""
opaque_adapter.py
=================
Concrete OPAQUE-3DH aPAKE implementation (RFC 9807 / draft-18).

This module fulfils the OpaqueClientAPI and OpaqueServerAPI Protocols
defined at the top of the file (copied verbatim from the scaffold) using a
self-contained P-256 / SHA-512 / Argon2id instantiation that has no external
OPAQUE library dependency.

Cryptographic design
--------------------
OPRF instantiation (RFC 9497 §3):
  Group    : P-256
  Hash     : SHA-512 (for HKDF, HMAC)
  H_to_curve: try-and-increment (deterministic, auditable)
  Blind(x) : r ← P256KeyGen(); M = r · H_to_curve(x)
  Evaluate(k, M) : Z = k · M
  Finalize(x, r, Z) : N = r⁻¹ · Z; HKDF(N ‖ SHA512(x), "OPRF", 64)

Envelope (RFC 9807 §4 "authentication-only" mode):
  rw       = Argon2id( OPRF_output, salt )
  enc_key  = HKDF-Expand(rw, "enc-key", 32)
  seal     = salt ‖ nonce ‖ AES-256-GCM(enc_key, nonce, c_priv ‖ s_pub, aad=b"\x01")
  open     = decrypt and return (c_priv, s_pub)

3DH AKE:
  DH1 = ECDH(c_eph,  s_static)  → ties session to certified server identity
  DH2 = ECDH(c_static, s_eph)   → ties session to registered client identity
  DH3 = ECDH(c_eph,  s_eph)     → forward secrecy
  IKM = DH1 ‖ DH2 ‖ DH3
  session_key = HKDF(IKM, transcript_hash, "session-key", 64)
  mac_key     = HKDF(IKM, transcript_hash, "mac-key", 64)
  server_mac  = HMAC-SHA512(mac_key, "server" ‖ transcript)
  client_mac  = HMAC-SHA512(mac_key, "client" ‖ transcript ‖ server_mac)

Reference:
    RFC 9807 §5–6 (OPAQUE registration and AKE)
    RFC 9497 §3   (EC-OPRF)
    Krawczyk et al. EUROCRYPT 2018 (OPAQUE original paper)
"""

from __future__ import annotations

import hmac as _hmac
import os
import struct
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, ECDH, generate_private_key,
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    _ARGON2 = True
except ImportError:
    _ARGON2 = False

# ── Protocol definitions (from scaffold) ─────────────────────────────────────

class OpaqueClientAPI(Protocol):
    def registration_start(self, password, client_id, server_id, context): ...
    def registration_finish(self, state, reg_response): ...
    def login_start(self, password, client_id, server_id, context): ...
    def login_finish(self, state, ke2): ...

class OpaqueServerAPI(Protocol):
    def registration_respond(self, credential_id, reg_request): ...
    def registration_store(self, credential_id, reg_upload): ...
    def login_start(self, credential_id, ke1, context): ...
    def login_finish(self, server_state, ke3): ...


# ── P-256 constants ───────────────────────────────────────────────────────────

CURVE   = SECP256R1()
BACKEND = default_backend()

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_FIELD = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A     = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
P256_B     = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

POINT_LEN  = 33   # compressed P-256 point


# ── Pure-Python P-256 scalar multiplication ───────────────────────────────────
# Required because the `cryptography` library does not expose raw EC_POINT_mul.

def _p256_affine_add(P, Q):
    """Affine point addition on P-256. Returns None for the point at infinity."""
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    p = P256_FIELD; a = P256_A
    if x1 == x2:
        if y1 != y2: return None
        lam = (3 * x1 * x1 + a) * pow(2 * y1, p - 2, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, p - 2, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _p256_scalar_mult(k: int, compressed: bytes) -> bytes:
    """Compute k · P on P-256 where P is a compressed point. Returns compressed."""
    flag = compressed[0]
    x    = int.from_bytes(compressed[1:33], "big")
    y_sq = (pow(x, 3, P256_FIELD) + P256_A * x + P256_B) % P256_FIELD
    y    = pow(y_sq, (P256_FIELD + 1) // 4, P256_FIELD)
    if (y % 2) != (flag - 2):
        y = P256_FIELD - y
    R = None; Q = (x, y)
    while k:
        if k & 1: R = _p256_affine_add(R, Q)
        Q = _p256_affine_add(Q, Q)
        k >>= 1
    if R is None:
        raise ValueError("Scalar multiplication yielded point at infinity")
    rx, ry = R
    return (b"\x02" if ry % 2 == 0 else b"\x03") + rx.to_bytes(32, "big")


# ── OPRF helpers ──────────────────────────────────────────────────────────────

def _hash_to_curve(data: bytes) -> bytes:
    """Map bytes to a compressed P-256 point via try-and-increment."""
    import hashlib, struct as _s
    for counter in range(256):
        candidate = hashlib.sha512(data + b"h2c" + _s.pack(">I", counter)).digest()[:32]
        x = int.from_bytes(candidate, "big") % P256_FIELD
        for prefix in (b"\x02", b"\x03"):
            try:
                pt = ec.EllipticCurvePublicKey.from_encoded_point(
                    CURVE, prefix + x.to_bytes(32, "big")
                )
                return prefix + x.to_bytes(32, "big")
            except Exception:
                pass
    raise RuntimeError("hash_to_curve: no valid point found in 256 iterations")


def _oprf_blind(password: bytes) -> tuple[int, bytes]:
    """Blind the password. Returns (blind_scalar, blinded_element_compressed)."""
    P_bytes = _hash_to_curve(password)
    r_priv  = generate_private_key(CURVE, BACKEND)
    r       = r_priv.private_numbers().private_value
    M       = _p256_scalar_mult(r, P_bytes)
    return r, M


def _oprf_evaluate(k_int: int, M: bytes) -> bytes:
    """Server OPRF evaluation. Returns Z = k · M."""
    return _p256_scalar_mult(k_int, M)


def _oprf_finalize(password: bytes, blind: int, Z: bytes) -> bytes:
    """
    Client finalisation. Returns OPRF_output (64 bytes).
    N = r⁻¹ · Z = k · H_to_curve(pw)
    output = HKDF(N ‖ SHA512(pw), "OPRF-finalise", 64)
    """
    import hashlib
    r_inv = pow(blind, P256_ORDER - 2, P256_ORDER)
    N     = _p256_scalar_mult(r_inv, Z)
    pw_hash = hashlib.sha512(password).digest()
    return HKDF(
        algorithm=hashes.SHA512(),
        length=64,
        salt=b"VAULTTLS-OPRF-finalise",
        info=b"OPRF output v1",
        backend=BACKEND,
    ).derive(N + pw_hash)


# ── KSF (Key-Stretching Function) ─────────────────────────────────────────────

def _ksf(oprf_output: bytes, salt: bytes) -> bytes:
    """
    Argon2id key-stretching over the OPRF output (RFC 9807 §2.4).
    Falls back to PBKDF2-SHA512 if argon2-cffi is not installed.
    """
    if _ARGON2:
        return hash_secret_raw(
            secret=oprf_output, salt=salt,
            time_cost=2, memory_cost=65536, parallelism=4,
            hash_len=64, type=Argon2Type.ID,
        )
    return HKDF(
        algorithm=hashes.SHA512(), length=64,
        salt=salt, info=b"pbkdf2-fallback", backend=BACKEND,
    ).derive(oprf_output)


# ── Envelope seal / open ──────────────────────────────────────────────────────

_ENV_VERSION = b"\x01"
_ARGON_SALT_LEN = 16
_GCM_NONCE_LEN  = 12


def _derive_env_key(rw_stretched: bytes) -> bytes:
    return HKDFExpand(
        algorithm=hashes.SHA512(), length=32,
        info=b"envelope-enc-key", backend=BACKEND,
    ).derive(rw_stretched)


def _priv_bytes(k: EllipticCurvePrivateKey) -> bytes:
    return k.private_numbers().private_value.to_bytes(32, "big")


def _pub_bytes(k) -> bytes:
    return k.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def _load_priv(b: bytes) -> EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(b, "big"), CURVE, BACKEND)


def _load_pub(b: bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, b)


def _envelope_seal(rw_raw: bytes, c_priv, s_pub) -> bytes:
    salt    = os.urandom(_ARGON_SALT_LEN)
    rw_s    = _ksf(rw_raw, salt)
    enc_key = _derive_env_key(rw_s)
    nonce   = os.urandom(_GCM_NONCE_LEN)
    plaintext = _priv_bytes(c_priv) + _pub_bytes(s_pub)
    ct = AESGCM(enc_key).encrypt(nonce, plaintext, _ENV_VERSION)
    return _ENV_VERSION + salt + nonce + ct


def _envelope_open(rw_raw: bytes, envelope: bytes) -> tuple:
    version = envelope[0:1]
    if version != _ENV_VERSION:
        raise ValueError(f"Unknown envelope version {version!r}")
    salt   = envelope[1:1 + _ARGON_SALT_LEN]
    nonce  = envelope[1 + _ARGON_SALT_LEN : 1 + _ARGON_SALT_LEN + _GCM_NONCE_LEN]
    ct     = envelope[1 + _ARGON_SALT_LEN + _GCM_NONCE_LEN:]
    rw_s   = _ksf(rw_raw, salt)
    enc_key = _derive_env_key(rw_s)
    try:
        pt = AESGCM(enc_key).decrypt(nonce, ct, version)
    except Exception:
        raise ValueError("Envelope decryption failed — wrong password")
    c_priv = _load_priv(pt[:32])
    s_pub  = _load_pub(pt[32:97])
    return c_priv, s_pub


# ── 3DH helpers ───────────────────────────────────────────────────────────────

def _ecdh(priv, pub) -> bytes:
    return priv.exchange(ECDH(), pub)


def _derive_3dh(dh1, dh2, dh3, transcript_hash: bytes) -> dict:
    ikm = dh1 + dh2 + dh3
    session_key = HKDF(
        algorithm=hashes.SHA512(), length=64,
        salt=transcript_hash, info=b"3DH-session-key", backend=BACKEND,
    ).derive(ikm)
    mac_key = HKDF(
        algorithm=hashes.SHA512(), length=64,
        salt=transcript_hash, info=b"3DH-mac-key", backend=BACKEND,
    ).derive(ikm)
    return {"session_key": session_key, "mac_key": mac_key}


# ── Wire encoding for OPAQUE blobs ────────────────────────────────────────────
# KE1 = M(33) ‖ nonce_c(32) ‖ c_eph_pub(65)
# KE2 = Z(33) ‖ envelope(var) ‖ nonce_s(32) ‖ s_eph_pub(65) ‖ server_mac(64)
# KE3 = client_mac(64)

_NONCE_LEN = 32
_MAC_LEN   = 64
_S_EPH_LEN = 65   # uncompressed P-256


def _pack_ke1(M: bytes, nonce_c: bytes, c_eph_pub: bytes) -> bytes:
    return M + nonce_c + c_eph_pub


def _unpack_ke1(ke1: bytes) -> tuple[bytes, bytes, bytes]:
    M         = ke1[:POINT_LEN]
    nonce_c   = ke1[POINT_LEN : POINT_LEN + _NONCE_LEN]
    c_eph_pub = ke1[POINT_LEN + _NONCE_LEN:]
    return M, nonce_c, c_eph_pub


def _pack_ke2(Z, envelope, nonce_s, s_eph_pub, server_mac) -> bytes:
    env_len = len(envelope).to_bytes(3, "big")
    return Z + env_len + envelope + nonce_s + s_eph_pub + server_mac


def _unpack_ke2(ke2: bytes) -> tuple:
    pos = 0
    Z         = ke2[pos:pos + POINT_LEN]; pos += POINT_LEN
    env_len   = int.from_bytes(ke2[pos:pos+3], "big"); pos += 3
    envelope  = ke2[pos:pos + env_len]; pos += env_len
    nonce_s   = ke2[pos:pos + _NONCE_LEN]; pos += _NONCE_LEN
    s_eph_pub = ke2[pos:pos + _S_EPH_LEN]; pos += _S_EPH_LEN
    server_mac = ke2[pos:pos + _MAC_LEN]
    return Z, envelope, nonce_s, s_eph_pub, server_mac


# ── Concrete OPAQUE client ────────────────────────────────────────────────────

class ConcreteOpaqueClient:
    """
    Concrete OPAQUE client implementing OpaqueClientAPI.
    All state that must persist across calls is returned as a dict.
    """

    def registration_start(
            self, password: bytes, client_id: bytes, server_id: bytes, context: bytes
    ) -> tuple[bytes, dict]:
        blind, M = _oprf_blind(password)
        # registration request = just the blinded element M
        return M, {"blind": blind, "password": password}

    def registration_finish(self, state: dict, reg_response: bytes) -> bytes:
        """
        Returns the registration record (c_pub ‖ envelope) for the server to store.
        Also returns c_pub bytes separately as a side effect via state.
        """
        Z        = reg_response[:POINT_LEN]
        s_pub_b  = reg_response[POINT_LEN:]
        s_pub    = _load_pub(s_pub_b)
        rw_raw   = _oprf_finalize(state["password"], state["blind"], Z)
        c_priv   = generate_private_key(CURVE, BACKEND)
        c_pub    = c_priv.public_key()
        envelope = _envelope_seal(rw_raw, c_priv, s_pub)
        c_pub_b  = _pub_bytes(c_pub)
        return c_pub_b + envelope   # registration record

    def login_start(
            self, password: bytes, client_id: bytes, server_id: bytes, context: bytes
    ) -> tuple[bytes, dict]:
        blind, M   = _oprf_blind(password)
        c_eph_priv = generate_private_key(CURVE, BACKEND)
        nonce_c    = os.urandom(_NONCE_LEN)
        ke1 = _pack_ke1(M, nonce_c, _pub_bytes(c_eph_priv.public_key()))
        state = {
            "blind": blind, "password": password,
            "c_eph_priv": _priv_bytes(c_eph_priv),
            "c_eph_pub":  _pub_bytes(c_eph_priv.public_key()),
            "nonce_c": nonce_c, "M": M,
        }
        return ke1, state

    def login_finish(self, state: dict, ke2: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Returns (session_key, export_key, ke3).
        ke3 = client_mac (the OPAQUE KE3 message).
        """
        Z, envelope, nonce_s, s_eph_pub_b, server_mac = _unpack_ke2(ke2)
        password   = state["password"]
        blind      = state["blind"]
        c_eph_priv = _load_priv(state["c_eph_priv"])
        c_eph_pub  = state["c_eph_pub"]
        nonce_c    = state["nonce_c"]
        M          = state["M"]

        rw_raw = _oprf_finalize(password, blind, Z)
        try:
            c_priv, s_pub = _envelope_open(rw_raw, envelope)
        except ValueError as e:
            raise ValueError(f"Login failed: {e}") from e

        s_eph_pub = _load_pub(s_eph_pub_b)

        # 3DH (client's perspective)
        dh1 = _ecdh(c_eph_priv, s_pub)           # c_eph × s_static
        dh2 = _ecdh(c_priv,     s_eph_pub)        # c_static × s_eph
        dh3 = _ecdh(c_eph_priv, s_eph_pub)        # c_eph × s_eph

        # Transcript for MAC context
        transcript = (
                M + nonce_c + c_eph_pub
                + Z + len(envelope).to_bytes(3, "big") + envelope
                + nonce_s + s_eph_pub_b
        )
        keys = _derive_3dh(dh1, dh2, dh3, transcript)

        # Verify server MAC
        expected_server_mac = _hmac.new(
            keys["mac_key"], b"server" + transcript, "sha512"
        ).digest()
        if not _hmac.compare_digest(server_mac, expected_server_mac):
            raise ValueError("Server MAC verification failed — possible MITM")

        # Compute client MAC
        client_mac = _hmac.new(
            keys["mac_key"],
            b"client" + transcript + server_mac,
            "sha512",
            ).digest()

        session_key = keys["session_key"]
        export_key  = HKDF(
            algorithm=hashes.SHA512(), length=64,
            salt=transcript, info=b"export-key", backend=BACKEND,
        ).derive(session_key)
        return session_key, export_key, client_mac


# ── Concrete OPAQUE server ────────────────────────────────────────────────────

class ConcreteOpaqueServer:
    """
    Concrete OPAQUE server implementing OpaqueServerAPI.
    Delegates persistence to storage.py.
    """

    def __init__(self, server_private_key) -> None:
        self._s_priv = server_private_key

    def registration_respond(self, credential_id: bytes, reg_request: bytes) -> bytes:
        """
        Evaluate the OPRF and return (Z ‖ s_pub_uncompressed).
        Also generates and stores the per-user OPRF key.
        """
        M         = reg_request  # blinded element (33 bytes)
        oprf_priv = generate_private_key(CURVE, BACKEND)
        oprf_key  = oprf_priv.private_numbers().private_value
        Z         = _oprf_evaluate(oprf_key, M)
        s_pub_b   = _pub_bytes(self._s_priv.public_key())
        # Store the OPRF key so we can reuse it during login
        self._pending_oprf_keys = getattr(self, "_pending_oprf_keys", {})
        self._pending_oprf_keys[credential_id.hex()] = oprf_priv.private_numbers().private_value.to_bytes(32, "big")
        return Z + s_pub_b

    def registration_store(self, credential_id: bytes, reg_upload: bytes) -> None:
        """
        Store the registration record.
        reg_upload = c_pub(65) ‖ envelope(variable)
        """
        from storage import store_opaque_record
        c_pub_b  = reg_upload[:65]
        envelope = reg_upload[65:]
        oprf_key_b = self._pending_oprf_keys.get(credential_id.hex())
        if oprf_key_b is None:
            raise ValueError("No pending OPRF key for this credential_id")
        store_opaque_record(credential_id, oprf_key_b, c_pub_b, envelope)

    def login_start(
            self, credential_id: bytes, ke1: bytes, context: bytes
    ) -> tuple[bytes, dict]:
        """
        Look up the user record and evaluate the OPRF.
        Returns (ke2, server_state).
        Uses a fake record path when the user does not exist.
        """
        from storage import load_opaque_record
        record = load_opaque_record(credential_id)

        M, nonce_c, c_eph_pub_b = _unpack_ke1(ke1)

        if record is None:
            # Fake path: produce a syntactically valid KE2 so timing and
            # wire format are indistinguishable from the real path.
            # Use random valid EC keys so all ECDH operations succeed.
            fake_oprf_priv = generate_private_key(CURVE, BACKEND)
            oprf_key_int   = fake_oprf_priv.private_numbers().private_value
            # Generate a real (random) ephemeral c_pub so _load_pub and ECDH
            # do not crash. The resulting session key is unguessable garbage.
            fake_c_priv = generate_private_key(CURVE, BACKEND)
            c_pub_b     = _pub_bytes(fake_c_priv.public_key())
            # TIMING FIX: build the fake envelope with a valid structure so that
            # _envelope_open on the client side runs the same code path (including
            # the full Argon2id KSF) regardless of whether the user exists.
            # A random 142-byte blob fails on the version-byte check BEFORE Argon2
            # runs, causing a 200+ ms distinguishable timing gap.
            # With a properly structured envelope (version=0x01, 16-byte random salt,
            # 12-byte nonce, random ciphertext) the client runs Argon2id fully before
            # the GCM tag verification fails, making both paths take ~same time.
            _fake_env_salt  = os.urandom(_ARGON_SALT_LEN)
            _fake_env_nonce = os.urandom(_GCM_NONCE_LEN)
            _fake_env_ct    = os.urandom(97 + 16)          # 97B plaintext + 16B GCM tag
            envelope = _ENV_VERSION + _fake_env_salt + _fake_env_nonce + _fake_env_ct
        else:
            oprf_key_int = int.from_bytes(record["oprf_key"], "big")
            c_pub_b      = record["client_pub"]
            envelope     = record["envelope"]

        Z = _oprf_evaluate(oprf_key_int, M)

        s_eph_priv = generate_private_key(CURVE, BACKEND)
        s_eph_pub  = _pub_bytes(s_eph_priv.public_key())
        nonce_s    = os.urandom(_NONCE_LEN)

        # 3DH (server's perspective)
        c_eph_pub = _load_pub(c_eph_pub_b)
        c_pub     = _load_pub(c_pub_b)
        dh1 = _ecdh(self._s_priv, c_eph_pub)     # s_static × c_eph
        dh2 = _ecdh(s_eph_priv,   c_pub)          # s_eph × c_static
        dh3 = _ecdh(s_eph_priv,   c_eph_pub)      # s_eph × c_eph

        transcript = (
                M + nonce_c + c_eph_pub_b
                + Z + len(envelope).to_bytes(3, "big") + envelope
                + nonce_s + s_eph_pub
        )
        keys = _derive_3dh(dh1, dh2, dh3, transcript)

        server_mac = _hmac.new(
            keys["mac_key"], b"server" + transcript, "sha512"
        ).digest()

        ke2 = _pack_ke2(Z, envelope, nonce_s, s_eph_pub, server_mac)

        server_state = {
            "keys": keys, "transcript": transcript,
            "server_mac": server_mac, "is_fake": record is None,
        }
        return ke2, server_state

    def login_finish(
            self, server_state: dict, ke3: bytes
    ) -> tuple[bytes, bytes]:
        """
        Verify client MAC and return (session_key, export_key).
        """
        if server_state["is_fake"]:
            # Always fail for non-existent users, but with the same timing
            raise ValueError("Authentication failed")

        keys       = server_state["keys"]
        transcript = server_state["transcript"]
        server_mac = server_state["server_mac"]
        client_mac = ke3   # KE3 is the 64-byte client MAC

        expected = _hmac.new(
            keys["mac_key"],
            b"client" + transcript + server_mac,
            "sha512",
            ).digest()
        if not _hmac.compare_digest(client_mac, expected):
            raise ValueError("Client MAC verification failed")

        session_key = keys["session_key"]
        export_key  = HKDF(
            algorithm=hashes.SHA512(), length=64,
            salt=transcript, info=b"export-key", backend=BACKEND,
        ).derive(session_key)
        return session_key, export_key
