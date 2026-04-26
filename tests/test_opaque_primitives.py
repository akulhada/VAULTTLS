"""
tests/test_opaque_primitives.py
================================
Unit tests for opaque_adapter.py primitives.

Test cases defined upfront (TDD):

  TC-OPQ-01  OPRF: Blind→Evaluate→Finalize is deterministic (same pw + key → same output)
  TC-OPQ-02  OPRF: Blind is randomised (same pw → different blinded element each call)
  TC-OPQ-03  OPRF: Different OPRF key → different finalize output
  TC-OPQ-04  OPRF: Different password → different finalize output
  TC-OPQ-05  Envelope: seal+open roundtrip with correct rw returns original (c_priv, s_pub)
  TC-OPQ-06  Envelope: 1-bit flip in ciphertext raises ValueError (GCM tag)
  TC-OPQ-07  Envelope: each seal call produces different bytes (fresh nonce+salt)
  TC-OPQ-08  Envelope: wrong rw raises ValueError
  TC-OPQ-09  OPAQUE end-to-end: register+login with correct pw → matching session keys
  TC-OPQ-10  OPAQUE end-to-end: two users have independent records
  TC-OPQ-11  OPAQUE end-to-end: re-register with new pw → old pw rejected
  TC-OPQ-12  KE1 wire format: len = 33 (point) + 32 (nonce) + 65 (eph_pub) = 130 bytes
  TC-OPQ-13  login_finish: session_key and export_key are distinct
  TC-OPQ-14  login_finish: fresh registration → different session keys each time
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore

from opaque_adapter import (
    ConcreteOpaqueClient, ConcreteOpaqueServer,
    _oprf_blind, _oprf_evaluate, _oprf_finalize,
    _envelope_seal, _envelope_open,
    generate_private_key, CURVE, BACKEND,
    _pub_bytes, _priv_bytes,
)
from config import CONTEXT_STRING, SERVER_ID
from tls13_kdf import hash_bytes


def _new_server():
    sk = ec.generate_private_key(CURVE, default_backend())
    return ConcreteOpaqueServer(sk), sk


def _cred(username: bytes) -> bytes:
    return hash_bytes(CONTEXT_STRING + username)


def _register(srv, username: bytes, password: bytes) -> None:
    cid = _cred(username)
    c   = ConcreteOpaqueClient()
    req, st = c.registration_start(password, username, SERVER_ID, CONTEXT_STRING)
    resp     = srv.registration_respond(cid, req)
    record   = c.registration_finish(st, resp)
    srv.registration_store(cid, record)


# ── OPRF primitives ───────────────────────────────────────────────────────────

def test_oprf_deterministic():
    """TC-OPQ-01: Same password + key always produces same OPRF output."""
    srv   = ec.generate_private_key(CURVE, default_backend())
    oprf_key = srv.private_numbers().private_value
    pw    = b"my_password"

    def _run():
        r, M = _oprf_blind(pw)
        Z    = _oprf_evaluate(oprf_key, M)
        return _oprf_finalize(pw, r, Z)

    out1 = _run()
    out2 = _run()
    assert out1 == out2, "OPRF must be deterministic with same key"


def test_oprf_blind_is_randomised():
    """TC-OPQ-02: Same password produces different blinded elements each call."""
    pw = b"password"
    r1, M1 = _oprf_blind(pw)
    r2, M2 = _oprf_blind(pw)
    assert M1 != M2, "Blinded elements must differ (fresh scalar each time)"
    assert r1 != r2, "Blind scalars must differ"


def test_oprf_key_sensitivity():
    """TC-OPQ-03: Different OPRF key produces different finalize output."""
    pw   = b"password"
    key1 = ec.generate_private_key(CURVE, default_backend()).private_numbers().private_value
    key2 = ec.generate_private_key(CURVE, default_backend()).private_numbers().private_value

    def _run(k):
        r, M = _oprf_blind(pw)
        Z    = _oprf_evaluate(k, M)
        return _oprf_finalize(pw, r, Z)

    assert _run(key1) != _run(key2), "Different OPRF keys must produce different outputs"


def test_oprf_password_sensitivity():
    """TC-OPQ-04: Different passwords produce different OPRF outputs."""
    key  = ec.generate_private_key(CURVE, default_backend()).private_numbers().private_value

    def _run(pw):
        r, M = _oprf_blind(pw)
        Z    = _oprf_evaluate(key, M)
        return _oprf_finalize(pw, r, Z)

    assert _run(b"password1") != _run(b"password2")


# ── Envelope ─────────────────────────────────────────────────────────────────

def test_envelope_roundtrip():
    """TC-OPQ-05: seal+open with correct rw returns original keys."""
    rw    = os.urandom(64)
    c_priv = generate_private_key(CURVE, BACKEND)
    s_priv = generate_private_key(CURVE, BACKEND)
    s_pub  = s_priv.public_key()

    env = _envelope_seal(rw, c_priv, s_pub)
    c_priv2, s_pub2 = _envelope_open(rw, env)

    assert _priv_bytes(c_priv) == _priv_bytes(c_priv2), "Client private key must survive roundtrip"
    assert _pub_bytes(s_pub)   == _pub_bytes(s_pub2),   "Server public key must survive roundtrip"


def test_envelope_bitflip_raises():
    """TC-OPQ-06: 1-bit flip in ciphertext raises ValueError (GCM tag fails)."""
    rw    = os.urandom(64)
    c_priv = generate_private_key(CURVE, BACKEND)
    s_priv = generate_private_key(CURVE, BACKEND)
    env   = _envelope_seal(rw, c_priv, s_priv.public_key())

    # Flip a bit in the ciphertext region (after the 1+16+12 byte header)
    tampered = bytearray(env)
    tampered[30] ^= 0x01
    try:
        _envelope_open(rw, bytes(tampered))
        raise AssertionError("Should have raised on tampered envelope")
    except ValueError:
        pass


def test_envelope_nondeterministic():
    """TC-OPQ-07: Each seal call produces different bytes (fresh nonce+salt)."""
    rw    = os.urandom(64)
    c_priv = generate_private_key(CURVE, BACKEND)
    s_priv = generate_private_key(CURVE, BACKEND)
    env1  = _envelope_seal(rw, c_priv, s_priv.public_key())
    env2  = _envelope_seal(rw, c_priv, s_priv.public_key())
    assert env1 != env2, "Each envelope must use fresh nonce+salt"


def test_envelope_wrong_rw_raises():
    """TC-OPQ-08: Opening with wrong rw raises ValueError."""
    rw     = os.urandom(64)
    bad_rw = os.urandom(64)
    c_priv = generate_private_key(CURVE, BACKEND)
    s_priv = generate_private_key(CURVE, BACKEND)
    env = _envelope_seal(rw, c_priv, s_priv.public_key())
    try:
        _envelope_open(bad_rw, env)
        raise AssertionError("Should have raised with wrong rw")
    except ValueError:
        pass


# ── Full OPAQUE flows ─────────────────────────────────────────────────────────

def test_opaque_register_login_matching_keys():
    """TC-OPQ-09: After registration, login with correct pw produces matching session keys."""
    srv, sk = _new_server()
    _register(srv, b"alice", b"correct_password")
    client = ConcreteOpaqueClient()
    cid    = _cred(b"alice")
    ke1, state = client.login_start(b"correct_password", b"alice", SERVER_ID, CONTEXT_STRING)
    ke2, srv_st = srv.login_start(cid, ke1, CONTEXT_STRING)
    sk_c, ek_c, ke3 = client.login_finish(state, ke2)
    sk_s, ek_s      = srv.login_finish(srv_st, ke3)
    assert sk_c == sk_s, "Session keys must match on both sides"
    assert ek_c == ek_s, "Export keys must match on both sides"


def test_opaque_two_users_independent():
    """TC-OPQ-10: Two registrations produce independent records."""
    srv, _ = _new_server()
    _register(srv, b"alice", b"alice_pass")
    _register(srv, b"bob",   b"bob_pass")

    # Alice can log in with her own password
    c = ConcreteOpaqueClient()
    ke1, st = c.login_start(b"alice_pass", b"alice", SERVER_ID, CONTEXT_STRING)
    ke2, ss = srv.login_start(_cred(b"alice"), ke1, CONTEXT_STRING)
    sk_a, _, ke3 = c.login_finish(st, ke2)
    srv.login_finish(ss, ke3)

    # Bob can log in with his own password
    c2 = ConcreteOpaqueClient()
    ke1b, st2 = c2.login_start(b"bob_pass", b"bob", SERVER_ID, CONTEXT_STRING)
    ke2b, ss2 = srv.login_start(_cred(b"bob"), ke1b, CONTEXT_STRING)
    sk_b, _, ke3b = c2.login_finish(st2, ke2b)
    srv.login_finish(ss2, ke3b)

    # Alice can't use Bob's session key (they differ)
    assert sk_a != sk_b, "Different users must produce different session keys"


def test_opaque_re_registration_invalidates_old_password():
    """TC-OPQ-11: Re-registering with a new password rejects the old one."""
    srv, _ = _new_server()
    _register(srv, b"carol", b"old_password")
    _register(srv, b"carol", b"new_password")   # overwrite

    # New password works
    c = ConcreteOpaqueClient()
    ke1, st = c.login_start(b"new_password", b"carol", SERVER_ID, CONTEXT_STRING)
    ke2, ss = srv.login_start(_cred(b"carol"), ke1, CONTEXT_STRING)
    c.login_finish(st, ke2)   # must not raise

    # Old password is rejected
    c2 = ConcreteOpaqueClient()
    ke1b, st2 = c2.login_start(b"old_password", b"carol", SERVER_ID, CONTEXT_STRING)
    ke2b, _   = srv.login_start(_cred(b"carol"), ke1b, CONTEXT_STRING)
    try:
        c2.login_finish(st2, ke2b)
        raise AssertionError("Old password should be rejected after re-registration")
    except ValueError:
        pass


def test_ke1_wire_length():
    """TC-OPQ-12: KE1 is exactly 33 + 32 + 65 = 130 bytes."""
    c = ConcreteOpaqueClient()
    ke1, _ = c.login_start(b"pw", b"u", SERVER_ID, CONTEXT_STRING)
    assert len(ke1) == 130, f"Expected 130-byte KE1, got {len(ke1)}"


def test_session_key_differs_from_export_key():
    """TC-OPQ-13: session_key and export_key are distinct (no aliasing)."""
    srv, _ = _new_server()
    _register(srv, b"dave", b"pass")
    c = ConcreteOpaqueClient()
    ke1, st = c.login_start(b"pass", b"dave", SERVER_ID, CONTEXT_STRING)
    ke2, ss = srv.login_start(_cred(b"dave"), ke1, CONTEXT_STRING)
    sk, ek, ke3 = c.login_finish(st, ke2)
    assert sk != ek, "session_key and export_key must be distinct"


def test_fresh_session_keys_each_login():
    """TC-OPQ-14: Two consecutive logins with same credentials produce different session keys."""
    srv, _ = _new_server()
    _register(srv, b"eve", b"pass")

    def _login():
        c = ConcreteOpaqueClient()
        ke1, st = c.login_start(b"pass", b"eve", SERVER_ID, CONTEXT_STRING)
        ke2, ss = srv.login_start(_cred(b"eve"), ke1, CONTEXT_STRING)
        sk, _, ke3 = c.login_finish(st, ke2)
        srv.login_finish(ss, ke3)
        return sk

    sk1 = _login()
    sk2 = _login()
    assert sk1 != sk2, "Each login must produce a fresh session key (ephemeral DH)"


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
    print("=== test_opaque_primitives ===")
    _run_all()
