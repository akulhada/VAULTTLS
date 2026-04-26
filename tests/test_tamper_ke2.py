"""
tests/test_tamper_ke2.py
========================
Security: bit-flipping any byte in KE2 must cause an error before session
key derivation completes.

A network attacker who modifies KE2 will either:
  (a) corrupt the OPRF output Z → wrong rw → envelope open fails, OR
  (b) corrupt the envelope → GCM tag fail, OR
  (c) corrupt nonce_s / s_eph_pub / server_mac → 3DH or HMAC verify fails.
All three paths end with a ValueError before any secrets are returned.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import CONTEXT_STRING, SERVER_ID, SERVER_CERT_KEY_PATH
from pki import bootstrap_pki, load_private_key
from opaque_adapter import ConcreteOpaqueClient, ConcreteOpaqueServer
from tls13_kdf import hash_bytes


def _cred_id(u: bytes) -> bytes:
    return hash_bytes(CONTEXT_STRING + u)


def _register(srv, username, password):
    cid = _cred_id(username)
    c = ConcreteOpaqueClient()
    req, st = c.registration_start(password, username, SERVER_ID, CONTEXT_STRING)
    resp = srv.registration_respond(cid, req)
    rec = c.registration_finish(st, resp)
    srv.registration_store(cid, rec)


def test_tamper_ke2():
    bootstrap_pki()
    sk = load_private_key(SERVER_CERT_KEY_PATH)
    srv = ConcreteOpaqueServer(sk)
    _register(srv, b"charlie", b"s3cr3t")

    cid = _cred_id(b"charlie")
    client = ConcreteOpaqueClient()
    ke1, state = client.login_start(b"s3cr3t", b"charlie", SERVER_ID, CONTEXT_STRING)
    ke2, _ = srv.login_start(cid, ke1, CONTEXT_STRING)

    # Flip bytes at several offsets across KE2
    offsets = [0, len(ke2)//4, len(ke2)//2, len(ke2)-1]
    for off in offsets:
        tampered = bytearray(ke2)
        tampered[off] ^= 0xFF
        try:
            client.login_finish(state, bytes(tampered))
            raise AssertionError(f"Should have raised for tampered offset {off}")
        except ValueError as e:
            print(f"  offset={off:3d}: correctly rejected — {e}")
        # Must re-blind for each attempt (fresh state)
        ke1, state = client.login_start(b"s3cr3t", b"charlie", SERVER_ID, CONTEXT_STRING)
        ke2, _ = srv.login_start(cid, ke1, CONTEXT_STRING)

    print("test_tamper_ke2: PASS ✓")


if __name__ == "__main__":
    test_tamper_ke2()
