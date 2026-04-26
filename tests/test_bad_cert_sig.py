"""
tests/test_bad_cert_sig.py
==========================
Security: invalid CertificateVerify or ServerConfig signatures must be
rejected before any session key is usable.

Three scenarios:
  1. Random 64-byte blob instead of a real CV signature → verify fails
  2. CV signature from a different (attacker) key → verify fails
  3. Correct CV signature but computed over a different transcript → verify fails
  4. Random ServerConfig signature → verify fails
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import CONTEXT_STRING, SERVER_ID, SERVER_CERT_KEY_PATH, SERVER_CERT_PATH, CA_CERT_PATH
from pki import (
    bootstrap_pki, load_private_key, load_certificate,
    generate_ca, generate_server_cert,
    encode_cert_chain, sign_server_config, sign_cert_verify,
    verify_certificate_verify_signature, verify_server_config_signature,
    verify_certificate_chain,
)
from opaque_adapter import ConcreteOpaqueClient, ConcreteOpaqueServer
from server_config import encode_server_config
from codec import encode_server_hello_core
from tls13_kdf import Transcript, hash_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


def _cred_id(u: bytes) -> bytes:
    return hash_bytes(CONTEXT_STRING + u)


def test_bad_cert_sig():
    bootstrap_pki()
    server_key  = load_private_key(SERVER_CERT_KEY_PATH)
    server_cert = load_certificate(SERVER_CERT_PATH)
    ca_cert     = load_certificate(CA_CERT_PATH)

    # Build a realistic core and transcript hash for testing
    client = ConcreteOpaqueClient()
    cid = _cred_id(b"alice")
    ke1, _ = client.login_start(b"pw", b"alice", SERVER_ID, CONTEXT_STRING)

    srv = ConcreteOpaqueServer(server_key)
    ke2, _ = srv.login_start(cid, ke1, CONTEXT_STRING)

    srv_cfg    = encode_server_config()
    cert_chain = encode_cert_chain(ca_cert, server_cert)
    core = encode_server_hello_core(1, os.urandom(32), cert_chain, srv_cfg, ke2)

    transcript = Transcript()
    transcript.add("client_hello", b"fake_client_hello_bytes")
    th = transcript.digest()

    # Scenario 1: random garbage CV signature
    try:
        verify_certificate_verify_signature(os.urandom(72), th, core, server_cert)
        raise AssertionError("Should reject random sig")
    except ValueError as e:
        print(f"  S1 (random CV sig): rejected — {e}")

    # Scenario 2: CV sig from different key
    attacker_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    attacker_sig = sign_cert_verify(attacker_key, th, core)
    try:
        verify_certificate_verify_signature(attacker_sig, th, core, server_cert)
        raise AssertionError("Should reject attacker sig")
    except ValueError as e:
        print(f"  S2 (wrong key CV sig): rejected — {e}")

    # Scenario 3: correct sig but wrong transcript
    correct_sig = sign_cert_verify(server_key, th, core)
    wrong_th = os.urandom(64)
    try:
        verify_certificate_verify_signature(correct_sig, wrong_th, core, server_cert)
        raise AssertionError("Should reject mismatched transcript")
    except ValueError as e:
        print(f"  S3 (wrong transcript): rejected — {e}")

    # Scenario 4: random ServerConfig signature
    try:
        verify_server_config_signature(srv_cfg, os.urandom(72), server_cert)
        raise AssertionError("Should reject random cfg sig")
    except ValueError as e:
        print(f"  S4 (random cfg sig): rejected — {e}")

    # Sanity: correct signatures pass
    good_cv  = sign_cert_verify(server_key, th, core)
    good_cfg = sign_server_config(server_key, srv_cfg)
    verify_certificate_verify_signature(good_cv, th, core, server_cert)
    verify_server_config_signature(srv_cfg, good_cfg, server_cert)
    print("  Sanity (valid sigs): accepted ✓")

    print("test_bad_cert_sig: PASS ✓")


if __name__ == "__main__":
    test_bad_cert_sig()
