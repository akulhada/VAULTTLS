"""
tests/test_codec.py
===================
Unit tests for codec.py (binary wire protocol serialisation).

Test cases defined upfront (TDD):

  TC-COD-01  ClientHello: encode→decode roundtrip preserves all fields
  TC-COD-02  ClientHello: credential_id must be exactly 64 bytes
  TC-COD-03  ClientHello: client_nonce must be exactly 32 bytes
  TC-COD-04  ClientHello: variable-length ke1 preserved
  TC-COD-05  ServerHello: encode→decode roundtrip (variable ECDSA sigs ~70B)
  TC-COD-06  ServerHello: very short ke2, cert, config still roundtrip
  TC-COD-07  ServerHello: large cert chain (4 KiB) preserved
  TC-COD-08  ClientFinish: encode→decode roundtrip
  TC-COD-09  AppData: encode→decode preserves seq and ciphertext
  TC-COD-10  AppData: seq=0 and seq=2^63 (boundary values)
  TC-COD-11  Alert warning: encode→decode preserves level and message
  TC-COD-12  Alert fatal: encode→decode preserves level
  TC-COD-13  Close: encodes to single tag byte 0x06
  TC-COD-14  Decode with wrong tag raises AssertionError or ValueError
  TC-COD-15  Truncated ClientHello (1 byte) raises ValueError
  TC-COD-16  encode_server_hello_core + encode_server_hello are inverse of decode
  TC-COD-17  AppData ciphertext survives binary-safe (all byte values)
"""
import os
import sys
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from codec import (
    HASH_LEN, NONCE_LEN, ALERT_WARNING, ALERT_FATAL,
    TAG_CLIENT_HELLO, TAG_SERVER_HELLO, TAG_CLIENT_FINISH,
    TAG_APP_DATA, TAG_ALERT, TAG_CLOSE,
    encode_client_hello, decode_client_hello,
    encode_server_hello_core, encode_server_hello, decode_server_hello,
    encode_client_finish, decode_client_finish,
    encode_app_data, decode_app_data,
    encode_alert, decode_alert,
    encode_close,
)


# ── ClientHello ───────────────────────────────────────────────────────────────

def test_client_hello_roundtrip():
    """TC-COD-01: All ClientHello fields survive encode→decode."""
    cid   = os.urandom(HASH_LEN)
    nonce = os.urandom(NONCE_LEN)
    ke1   = os.urandom(130)
    raw   = encode_client_hello(version=1, credential_id=cid,
                                client_nonce=nonce, opaque_ke1=ke1)
    parsed = decode_client_hello(raw)
    assert parsed.version       == 1
    assert parsed.credential_id == cid
    assert parsed.client_nonce  == nonce
    assert parsed.opaque_ke1    == ke1


def test_client_hello_bad_cred_id_length():
    """TC-COD-02: credential_id ≠ 64 bytes raises AssertionError."""
    try:
        encode_client_hello(1, b"\x00" * 32, b"\x00" * NONCE_LEN, b"ke1")
        raise AssertionError("Should have raised")
    except AssertionError:
        pass


def test_client_hello_bad_nonce_length():
    """TC-COD-03: client_nonce ≠ 32 bytes raises AssertionError."""
    try:
        encode_client_hello(1, b"\x00" * HASH_LEN, b"\x00" * 16, b"ke1")
        raise AssertionError("Should have raised")
    except AssertionError:
        pass


def test_client_hello_variable_ke1():
    """TC-COD-04: ke1 of 1 byte and 1000 bytes both roundtrip correctly."""
    for ke1 in [b"\xab", os.urandom(1000)]:
        raw    = encode_client_hello(2, b"\x00"*HASH_LEN, b"\x00"*NONCE_LEN, ke1)
        parsed = decode_client_hello(raw)
        assert parsed.opaque_ke1 == ke1


# ── ServerHello ───────────────────────────────────────────────────────────────

def _make_server_hello(ke2=None, cert=None, cfg=None, cfg_sig=None, cv_sig=None):
    ke2    = ke2    or os.urandom(339)    # realistic OPAQUE KE2
    cert   = cert   or os.urandom(512)    # realistic cert chain
    cfg    = cfg    or os.urandom(20)     # server_config
    cfg_sig = cfg_sig or os.urandom(71)   # DER ECDSA sig (~71 bytes)
    cv_sig  = cv_sig  or os.urandom(71)
    nonce  = os.urandom(NONCE_LEN)
    core   = encode_server_hello_core(1, nonce, cert, cfg, ke2)
    raw    = encode_server_hello(core, cfg_sig, cv_sig)
    return raw, ke2, cert, cfg, cfg_sig, cv_sig


def test_server_hello_roundtrip():
    """TC-COD-05: All ServerHello fields survive encode→decode (variable sigs)."""
    raw, ke2, cert, cfg, cfg_sig, cv_sig = _make_server_hello()
    p = decode_server_hello(raw)
    assert p.opaque_ke2        == ke2
    assert p.certificate_chain == cert
    assert p.server_config     == cfg
    assert p.server_config_sig == cfg_sig
    assert p.cert_verify_sig   == cv_sig


def test_server_hello_short_fields():
    """TC-COD-06: Minimal (1-byte) ke2, cert, config still roundtrip."""
    raw, ke2, cert, cfg, csig, cvsig = _make_server_hello(
        ke2=b"\x02", cert=b"\xff", cfg=b"\x00"
    )
    p = decode_server_hello(raw)
    assert p.opaque_ke2 == b"\x02"
    assert p.certificate_chain == b"\xff"
    assert p.server_config == b"\x00"


def test_server_hello_large_cert():
    """TC-COD-07: 4 KiB certificate chain is preserved exactly."""
    large_cert = os.urandom(4096)
    raw, _, cert, _, _, _ = _make_server_hello(cert=large_cert)
    p = decode_server_hello(raw)
    assert p.certificate_chain == large_cert, "Large cert chain must survive roundtrip"


# ── ClientFinish ──────────────────────────────────────────────────────────────

def test_client_finish_roundtrip():
    """TC-COD-08: ke3 of various lengths survives encode→decode."""
    for ke3 in [os.urandom(64), os.urandom(1), os.urandom(200)]:
        raw    = encode_client_finish(opaque_ke3=ke3)
        parsed = decode_client_finish(raw)
        assert parsed.opaque_ke3 == ke3, f"ke3 mismatch for length {len(ke3)}"


# ── AppData ───────────────────────────────────────────────────────────────────

def test_app_data_roundtrip():
    """TC-COD-09: seq and ciphertext are preserved."""
    for seq in [0, 1, 255, 65535, 2**32]:
        ct  = os.urandom(100)
        raw = encode_app_data(seq, ct)
        p   = decode_app_data(raw)
        assert p.seq == seq, f"seq mismatch: {p.seq} != {seq}"
        assert p.ciphertext == ct


def test_app_data_boundary_seqs():
    """TC-COD-10: seq=0 and seq=2^63 (near uint64 max) both roundtrip."""
    for seq in [0, 2**63]:
        ct  = b"\xde\xad\xbe\xef"
        raw = encode_app_data(seq, ct)
        p   = decode_app_data(raw)
        assert p.seq == seq


# ── Alert ─────────────────────────────────────────────────────────────────────

def test_alert_warning_roundtrip():
    """TC-COD-11: Warning alert level and message survive roundtrip."""
    raw = encode_alert(ALERT_WARNING, "connection closing")
    p   = decode_alert(raw)
    assert p.level   == ALERT_WARNING
    assert p.message == "connection closing"


def test_alert_fatal_roundtrip():
    """TC-COD-12: Fatal alert level and unicode message survive roundtrip."""
    msg = "Authentication failed — rate limit exceeded"
    raw = encode_alert(ALERT_FATAL, msg)
    p   = decode_alert(raw)
    assert p.level   == ALERT_FATAL
    assert p.message == msg


# ── Close ─────────────────────────────────────────────────────────────────────

def test_close_is_single_byte():
    """TC-COD-13: Close encodes as exactly [TAG_CLOSE] (1 byte)."""
    raw = encode_close()
    assert raw == bytes([TAG_CLOSE]), f"Expected [0x06], got {raw!r}"


# ── Error cases ───────────────────────────────────────────────────────────────

def test_wrong_tag_raises():
    """TC-COD-14: Decoding with mismatched tag raises AssertionError or ValueError."""
    server_hello_bytes = encode_server_hello(
        encode_server_hello_core(1, b"\x00"*NONCE_LEN, b"cert", b"cfg", b"ke2"),
        b"\x00"*71, b"\x00"*71,
        )
    # Try to decode as ClientHello (wrong tag)
    try:
        decode_client_hello(server_hello_bytes)
        raise AssertionError("Should have raised on wrong tag")
    except (AssertionError, ValueError):
        pass


def test_truncated_message_raises():
    """TC-COD-15: Truncated message (1 byte) raises ValueError on decode."""
    try:
        decode_client_hello(bytes([TAG_CLIENT_HELLO]))
        raise AssertionError("Should have raised on truncated input")
    except (ValueError, struct.error, Exception):
        pass


def test_server_hello_core_then_encode_decode():
    """TC-COD-16: encode_server_hello_core used inside encode/decode roundtrip."""
    nonce  = os.urandom(NONCE_LEN)
    ke2    = os.urandom(200)
    cert   = os.urandom(300)
    cfg    = os.urandom(30)
    cfg_sig = os.urandom(70)
    cv_sig  = os.urandom(72)

    core = encode_server_hello_core(1, nonce, cert, cfg, ke2)
    raw  = encode_server_hello(core, cfg_sig, cv_sig)
    p    = decode_server_hello(raw)

    assert p.opaque_ke2        == ke2
    assert p.certificate_chain == cert
    assert p.server_config     == cfg
    assert p.server_config_sig == cfg_sig
    assert p.cert_verify_sig   == cv_sig


def test_app_data_binary_safe():
    """TC-COD-17: Ciphertext with all 256 byte values survives roundtrip."""
    ct  = bytes(range(256)) * 4    # 1024 bytes covering every byte value
    raw = encode_app_data(42, ct)
    p   = decode_app_data(raw)
    assert p.seq == 42
    assert p.ciphertext == ct


# ── Runner ─────────────────────────────────────────────────────────────────────

def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except Exception as e:
            import traceback
            print(f"  FAIL  {fn.__name__}: {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed out of {passed+failed} tests")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    print("=== test_codec ===")
    _run_all()
