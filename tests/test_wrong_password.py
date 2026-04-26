"""
tests/test_wrong_password.py
============================
Security: wrong password must be rejected before any session key is usable.

Covers:
  1. Envelope decryption fails with wrong password (ValueError)
  2. A forged client_mac is rejected by server login_finish (ValueError)
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import CONTEXT_STRING, SERVER_ID, SERVER_CERT_KEY_PATH
from pki import bootstrap_pki, load_private_key
from opaque_adapter import ConcreteOpaqueClient, ConcreteOpaqueServer
from tls13_kdf import hash_bytes


def _cred_id(username: bytes) -> bytes:
    return hash_bytes(CONTEXT_STRING + username)


def _direct_register(srv, username: bytes, password: bytes) -> None:
    """Register a user directly without sockets."""
    cid = _cred_id(username)
    client = ConcreteOpaqueClient()
    req, st = client.registration_start(password, username, SERVER_ID, CONTEXT_STRING)
    resp = srv.registration_respond(cid, req)
    record = client.registration_finish(st, resp)
    srv.registration_store(cid, record)


def test_wrong_password():
    bootstrap_pki()
    server_key = load_private_key(SERVER_CERT_KEY_PATH)

    srv = ConcreteOpaqueServer(server_key)
    _direct_register(srv, b"bob", b"correct_password")
    print("  User 'bob' registered")

    # 1. Wrong password → client login_finish raises before mac step
    client_wrong = ConcreteOpaqueClient()
    cid = _cred_id(b"bob")
    ke1, state = client_wrong.login_start(b"WRONG", b"bob", SERVER_ID, CONTEXT_STRING)
    ke2, srv_state = srv.login_start(cid, ke1, CONTEXT_STRING)

    try:
        client_wrong.login_finish(state, ke2)
        raise AssertionError("Should have raised with wrong password")
    except ValueError as e:
        msg = str(e).lower()
        assert "wrong password" in msg or "failed" in msg, f"Unexpected msg: {e}"
        print(f"  Wrong pw rejected: {e}")

    # 2. Forged KE3 (random 64 bytes) → server login_finish raises
    client_right = ConcreteOpaqueClient()
    ke1b, state2 = client_right.login_start(b"correct_password", b"bob", SERVER_ID, CONTEXT_STRING)
    _, srv_state2 = srv.login_start(cid, ke1b, CONTEXT_STRING)
    try:
        srv.login_finish(srv_state2, os.urandom(64))
        raise AssertionError("Should have raised with forged KE3")
    except ValueError as e:
        print(f"  Forged KE3 rejected: {e}")

    print("test_wrong_password: PASS ✓")


if __name__ == "__main__":
    test_wrong_password()
