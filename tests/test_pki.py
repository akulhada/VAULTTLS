"""
tests/test_pki.py
=================
Unit tests for pki.py (certificate generation, verification, signatures).

Test cases defined upfront (TDD):

  TC-PKI-01  generate_ca: produces Ed25519 key + self-signed cert (issuer==subject)
  TC-PKI-02  generate_server_cert: server cert is signed by CA (P-256 key)
  TC-PKI-03  verify_certificate_chain: valid chain passes silently
  TC-PKI-04  verify_certificate_chain: expired cert raises ValueError
  TC-PKI-05  verify_certificate_chain: cert signed by wrong CA raises
  TC-PKI-06  verify_certificate_chain: name mismatch raises ValueError
  TC-PKI-07  encode_cert_chain + decode_cert_chain roundtrip (2 certs recovered)
  TC-PKI-08  sign_cert_verify + verify_certificate_verify_signature: valid roundtrip
  TC-PKI-09  verify_cert_verify: different transcript_hash raises
  TC-PKI-10  verify_cert_verify: different server_hello_core raises
  TC-PKI-11  verify_cert_verify: different signing key raises
  TC-PKI-12  sign_server_config + verify_server_config_signature: valid roundtrip
  TC-PKI-13  verify_server_config_signature: tampered config raises
  TC-PKI-14  verify_server_config_signature: wrong key raises
  TC-PKI-15  save_private_key + load_private_key roundtrip (temp file)
  TC-PKI-16  save_certificate + load_certificate roundtrip (temp file)
"""
import datetime
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

import pki
from pki import (
    generate_ca, generate_server_cert,
    encode_cert_chain, _decode_cert_chain,
    verify_certificate_chain,
    sign_cert_verify, verify_certificate_verify_signature,
    sign_server_config, verify_server_config_signature,
    save_private_key, load_private_key,
    save_certificate, load_certificate,
)


# ── Certificate generation ────────────────────────────────────────────────────

def test_generate_ca_self_signed():
    """TC-PKI-01: CA certificate issuer == subject (self-signed)."""
    ca_key, ca_cert = generate_ca()
    assert ca_cert.subject == ca_cert.issuer, "CA must be self-signed"
    # Verify the cert is actually signed by its own key
    try:
        ca_cert.public_key().verify(ca_cert.signature, ca_cert.tbs_certificate_bytes)
    except Exception as e:
        raise AssertionError(f"CA cert signature verification failed: {e}")


def test_generate_server_cert_signed_by_ca():
    """TC-PKI-02: Server cert issuer matches CA subject and signature verifies."""
    ca_key, ca_cert = generate_ca()
    srv_key, srv_cert = generate_server_cert(ca_key, ca_cert)

    # Server cert issuer matches CA subject
    assert srv_cert.issuer == ca_cert.subject

    # CA public key verifies server cert signature
    try:
        ca_cert.public_key().verify(srv_cert.signature, srv_cert.tbs_certificate_bytes)
    except Exception as e:
        raise AssertionError(f"Server cert chain verification failed: {e}")

    # Server key should be P-256
    assert isinstance(srv_key, ec.EllipticCurvePrivateKey)


def test_verify_certificate_chain_valid():
    """TC-PKI-03: Valid chain passes and returns server cert."""
    ca_key, ca_cert = generate_ca()
    srv_key, srv_cert = generate_server_cert(ca_key, ca_cert)
    chain = encode_cert_chain(ca_cert, srv_cert)
    returned = verify_certificate_chain(chain, expected_name="localhost", trusted_ca_cert=ca_cert)
    # Returned cert must match the server cert
    assert returned.public_bytes(__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.DER) == \
           srv_cert.public_bytes(__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.DER)


def test_verify_certificate_chain_expired():
    """TC-PKI-04: Expired server cert raises ValueError."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend as db

    ca_key, ca_cert = generate_ca()
    # Build an expired server cert manually
    key = ec.generate_private_key(ec.SECP256R1(), db())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now  = datetime.datetime.now(datetime.timezone.utc)
    expired_cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(ca_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(now  - datetime.timedelta(days=1))   # expired yesterday
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(ca_key, algorithm=None, backend=db())
    )
    chain = encode_cert_chain(ca_cert, expired_cert)
    try:
        verify_certificate_chain(chain, expected_name="localhost", trusted_ca_cert=ca_cert)
        raise AssertionError("Should have raised for expired cert")
    except ValueError as e:
        assert "expired" in str(e).lower(), f"Unexpected error: {e}"


def test_verify_certificate_chain_wrong_ca():
    """TC-PKI-05: Cert signed by a different CA raises (signature invalid)."""
    ca_key1, ca_cert1 = generate_ca()
    ca_key2, ca_cert2 = generate_ca()   # different CA
    _, srv_cert = generate_server_cert(ca_key2, ca_cert2)   # signed by CA2

    # Build chain with CA1 cert + server cert signed by CA2 — mismatch
    chain = encode_cert_chain(ca_cert1, srv_cert)
    try:
        verify_certificate_chain(chain, expected_name="localhost", trusted_ca_cert=ca_cert1)
        raise AssertionError("Should have raised for wrong CA")
    except ValueError:
        pass


def test_verify_certificate_chain_wrong_name():
    """TC-PKI-06: Cert with mismatched expected_name raises ValueError."""
    ca_key, ca_cert = generate_ca()
    _, srv_cert = generate_server_cert(ca_key, ca_cert)
    chain = encode_cert_chain(ca_cert, srv_cert)
    try:
        verify_certificate_chain(chain, expected_name="evil.example.com", trusted_ca_cert=ca_cert)
        raise AssertionError("Should have raised for wrong name")
    except ValueError as e:
        assert "evil.example.com" in str(e) or "not in" in str(e).lower()


def test_encode_decode_cert_chain_roundtrip():
    """TC-PKI-07: encode_cert_chain + _decode_cert_chain returns both certs."""
    ca_key, ca_cert = generate_ca()
    _, srv_cert = generate_server_cert(ca_key, ca_cert)
    chain = encode_cert_chain(ca_cert, srv_cert)
    decoded_ca, decoded_srv = _decode_cert_chain(chain)

    from cryptography.hazmat.primitives import serialization as ser
    assert decoded_ca.public_bytes(ser.Encoding.DER)  == ca_cert.public_bytes(ser.Encoding.DER)
    assert decoded_srv.public_bytes(ser.Encoding.DER) == srv_cert.public_bytes(ser.Encoding.DER)


# ── CertificateVerify signatures ──────────────────────────────────────────────

def test_sign_and_verify_cert_verify():
    """TC-PKI-08: sign + verify with matching inputs succeeds silently."""
    ca_key, ca_cert = generate_ca()
    srv_key, srv_cert = generate_server_cert(ca_key, ca_cert)
    th   = os.urandom(64)
    core = os.urandom(100)
    sig  = sign_cert_verify(srv_key, th, core)
    # Should not raise
    verify_certificate_verify_signature(sig, th, core, srv_cert)


def test_cert_verify_wrong_transcript():
    """TC-PKI-09: Correct sig but different transcript_hash raises ValueError."""
    ca_key, ca_cert = generate_ca()
    srv_key, srv_cert = generate_server_cert(ca_key, ca_cert)
    core = os.urandom(100)
    sig  = sign_cert_verify(srv_key, os.urandom(64), core)
    try:
        verify_certificate_verify_signature(sig, os.urandom(64), core, srv_cert)
        raise AssertionError("Should have raised with wrong transcript")
    except ValueError:
        pass


def test_cert_verify_wrong_core():
    """TC-PKI-10: Correct sig but different server_hello_core raises ValueError."""
    ca_key, ca_cert = generate_ca()
    srv_key, srv_cert = generate_server_cert(ca_key, ca_cert)
    th   = os.urandom(64)
    sig  = sign_cert_verify(srv_key, th, os.urandom(100))
    try:
        verify_certificate_verify_signature(sig, th, os.urandom(100), srv_cert)
        raise AssertionError("Should have raised with wrong core")
    except ValueError:
        pass


def test_cert_verify_wrong_signing_key():
    """TC-PKI-11: Sig from different key raises ValueError."""
    ca_key, ca_cert = generate_ca()
    srv_key, srv_cert = generate_server_cert(ca_key, ca_cert)
    attacker_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    th   = os.urandom(64)
    core = os.urandom(100)
    sig  = sign_cert_verify(attacker_key, th, core)   # signed by attacker
    try:
        verify_certificate_verify_signature(sig, th, core, srv_cert)
        raise AssertionError("Should have raised with wrong signing key")
    except ValueError:
        pass


# ── ServerConfig signatures ───────────────────────────────────────────────────

def test_sign_and_verify_server_config():
    """TC-PKI-12: sign + verify with matching config and cert succeeds."""
    ca_key, ca_cert = generate_ca()
    srv_key, srv_cert = generate_server_cert(ca_key, ca_cert)
    cfg = os.urandom(30)
    sig = sign_server_config(srv_key, cfg)
    verify_server_config_signature(cfg, sig, srv_cert)   # should not raise


def test_server_config_tampered():
    """TC-PKI-13: Tampered config bytes raise ValueError."""
    ca_key, ca_cert = generate_ca()
    srv_key, srv_cert = generate_server_cert(ca_key, ca_cert)
    cfg = os.urandom(30)
    sig = sign_server_config(srv_key, cfg)
    tampered = bytearray(cfg); tampered[0] ^= 0xFF
    try:
        verify_server_config_signature(bytes(tampered), sig, srv_cert)
        raise AssertionError("Should have raised with tampered config")
    except ValueError:
        pass


def test_server_config_wrong_key():
    """TC-PKI-14: Sig from different key raises ValueError."""
    ca_key, ca_cert = generate_ca()
    srv_key, srv_cert = generate_server_cert(ca_key, ca_cert)
    attacker_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    cfg = os.urandom(30)
    sig = sign_server_config(attacker_key, cfg)   # attacker signs
    try:
        verify_server_config_signature(cfg, sig, srv_cert)
        raise AssertionError("Should have raised with wrong key")
    except ValueError:
        pass


# ── Key/cert serialisation ────────────────────────────────────────────────────

def test_save_load_private_key():
    """TC-PKI-15: P-256 private key survives save→load with same scalar value."""
    from cryptography.hazmat.primitives import serialization
    srv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        path = f.name
    try:
        save_private_key(srv_key, path)
        loaded = load_private_key(path)
        # Compare private scalars
        orig_n   = srv_key.private_numbers().private_value
        loaded_n = loaded.private_numbers().private_value
        assert orig_n == loaded_n, "Private key scalar must survive save/load"
    finally:
        os.unlink(path)


def test_save_load_certificate():
    """TC-PKI-16: Certificate survives save→load (DER bytes match)."""
    from cryptography.hazmat.primitives import serialization
    ca_key, ca_cert = generate_ca()
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        path = f.name
    try:
        save_certificate(ca_cert, path)
        loaded = load_certificate(path)
        assert (ca_cert.public_bytes(serialization.Encoding.DER) ==
                loaded.public_bytes(serialization.Encoding.DER)), \
            "Certificate must survive save/load"
    finally:
        os.unlink(path)


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
    print("=== test_pki ===")
    _run_all()
