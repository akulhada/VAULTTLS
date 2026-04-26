"""
tests/test_pinned_ca.py
=======================
Security: the client must reject a certificate chain anchored in an untrusted
CA, even if that rogue CA successfully signs a localhost server certificate.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pki import (
    bootstrap_pki,
    encode_cert_chain,
    generate_ca,
    generate_server_cert,
    load_certificate,
    verify_certificate_chain,
)
from config import CA_CERT_PATH, SERVER_CERT_PATH


def test_pinned_ca():
    bootstrap_pki()
    trusted_ca = load_certificate(CA_CERT_PATH)
    trusted_srv = load_certificate(SERVER_CERT_PATH)

    # Sanity: the real chain verifies.
    verify_certificate_chain(
        encode_cert_chain(trusted_ca, trusted_srv),
        expected_name="localhost",
    )

    # Attack: rogue CA + rogue localhost server cert.
    rogue_ca_key, rogue_ca_cert = generate_ca()
    _, rogue_srv_cert = generate_server_cert(rogue_ca_key, rogue_ca_cert)

    try:
        verify_certificate_chain(
            encode_cert_chain(rogue_ca_cert, rogue_srv_cert),
            expected_name="localhost",
        )
        raise AssertionError("Untrusted CA chain should have been rejected")
    except ValueError as exc:
        assert "untrusted ca" in str(exc).lower()

if __name__ == "__main__":
    try:
        test_pinned_ca()
        print("Pinned-CA rejection: PASS ✓")
    except Exception as e:
        print(f"Pinned-CA rejection: FAIL — {e}")
        raise SystemExit(1)
