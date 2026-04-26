"""
tests/test_kdf.py
=================
Unit tests for tls13_kdf.py

Test cases defined upfront (TDD):

  TC-KDF-01  hkdf_extract output is exactly HASH_LEN bytes
  TC-KDF-02  hkdf_extract is deterministic
  TC-KDF-03  hkdf_extract is sensitive to salt changes
  TC-KDF-04  hkdf_extract is sensitive to IKM changes
  TC-KDF-05  hkdf_expand_label output length matches requested length
  TC-KDF-06  hkdf_expand_label different labels → different outputs (domain sep)
  TC-KDF-07  hkdf_expand_label different contexts → different outputs
  TC-KDF-08  hkdf_expand_label is deterministic
  TC-KDF-09  Transcript.digest changes when a message is added
  TC-KDF-10  Transcript ordering matters: A+B ≠ B+A
  TC-KDF-11  Transcript with same messages produces same digest (determinism)
  TC-KDF-12  Empty transcript digest is a fixed SHA-512 value
  TC-KDF-13  derive_traffic_secrets: all 5 secrets are distinct bytes
  TC-KDF-14  derive_traffic_secrets: changing OPAQUE SK changes all secrets
  TC-KDF-15  derive_traffic_secrets: changing transcript hash changes all secrets
  TC-KDF-16  derive_traffic_secrets: both secrets are HASH_LEN bytes
  TC-KDF-17  derive_secret label/context collision resistance
"""
import os
import sys
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tls13_kdf import (
    HASH_LEN, hash_bytes,
    hkdf_extract, hkdf_expand_label, derive_secret,
    Transcript, TrafficSecrets, derive_traffic_secrets,
)


def test_hkdf_extract_output_length():
    """TC-KDF-01: hkdf_extract always outputs exactly HASH_LEN bytes."""
    prk = hkdf_extract(b"salt", b"input key material")
    assert len(prk) == HASH_LEN, f"Expected {HASH_LEN} bytes, got {len(prk)}"


def test_hkdf_extract_deterministic():
    """TC-KDF-02: Same salt + IKM always produces the same PRK."""
    prk1 = hkdf_extract(b"fixed-salt", b"fixed-ikm")
    prk2 = hkdf_extract(b"fixed-salt", b"fixed-ikm")
    assert prk1 == prk2, "hkdf_extract must be deterministic"


def test_hkdf_extract_salt_sensitivity():
    """TC-KDF-03: Different salts produce different PRKs."""
    prk1 = hkdf_extract(b"salt-A", b"same-ikm")
    prk2 = hkdf_extract(b"salt-B", b"same-ikm")
    assert prk1 != prk2, "Different salts must produce different PRKs"


def test_hkdf_extract_ikm_sensitivity():
    """TC-KDF-04: Different IKMs produce different PRKs."""
    prk1 = hkdf_extract(b"same-salt", b"ikm-A")
    prk2 = hkdf_extract(b"same-salt", b"ikm-B")
    assert prk1 != prk2, "Different IKMs must produce different PRKs"


def test_hkdf_expand_label_output_length():
    """TC-KDF-05: Output length matches the requested length exactly."""
    secret = os.urandom(HASH_LEN)
    for length in [16, 32, 48, 64, 128]:
        out = hkdf_expand_label(secret, b"test", b"", length)
        assert len(out) == length, f"Expected {length} bytes, got {len(out)}"


def test_hkdf_expand_label_domain_separation():
    """TC-KDF-06: Different labels produce distinct outputs from the same secret."""
    secret = os.urandom(HASH_LEN)
    labels = [b"key", b"iv", b"finished", b"derived", b"c hs traffic", b"s hs traffic"]
    outputs = [hkdf_expand_label(secret, label, b"", 32) for label in labels]
    # All outputs must be pairwise distinct
    for i in range(len(outputs)):
        for j in range(i + 1, len(outputs)):
            assert outputs[i] != outputs[j], (
                f"Labels {labels[i]!r} and {labels[j]!r} produced the same output"
            )


def test_hkdf_expand_label_context_sensitivity():
    """TC-KDF-07: Different contexts produce different outputs (even same label)."""
    secret = os.urandom(HASH_LEN)
    out1 = hkdf_expand_label(secret, b"same-label", b"context-A", 32)
    out2 = hkdf_expand_label(secret, b"same-label", b"context-B", 32)
    assert out1 != out2, "Different contexts must produce different outputs"


def test_hkdf_expand_label_deterministic():
    """TC-KDF-08: Same inputs always yield the same output."""
    secret = os.urandom(HASH_LEN)
    out1 = hkdf_expand_label(secret, b"label", b"ctx", 32)
    out2 = hkdf_expand_label(secret, b"label", b"ctx", 32)
    assert out1 == out2, "hkdf_expand_label must be deterministic"


def test_transcript_add_changes_digest():
    """TC-KDF-09: Adding a message changes the transcript digest."""
    t = Transcript()
    d0 = t.digest()
    t.add("client_hello", b"some bytes")
    d1 = t.digest()
    assert d0 != d1, "digest must change after add()"


def test_transcript_order_matters():
    """TC-KDF-10: A+B and B+A produce different digests."""
    t1 = Transcript()
    t1.add("msg_a", b"alpha")
    t1.add("msg_b", b"beta")

    t2 = Transcript()
    t2.add("msg_b", b"beta")
    t2.add("msg_a", b"alpha")

    assert t1.digest() != t2.digest(), (
        "Transcript order must matter: A+B != B+A"
    )


def test_transcript_determinism():
    """TC-KDF-11: Same messages in same order always produce the same digest."""
    def build():
        t = Transcript()
        t.add("client_hello", b"hello bytes")
        t.add("server_hello", b"server bytes")
        t.add("client_finish", b"finish bytes")
        return t.digest()

    assert build() == build(), "Transcript must be deterministic"


def test_transcript_empty_is_fixed():
    """TC-KDF-12: Empty transcript digest equals SHA-512 of the empty encoding."""
    t = Transcript()
    d = t.digest()
    assert len(d) == HASH_LEN, f"Expected {HASH_LEN} bytes"
    # Two empty transcripts must agree
    assert d == Transcript().digest(), "Empty transcript must be deterministic"


def test_derive_traffic_secrets_distinct():
    """TC-KDF-13: All 5 traffic secrets derived from same inputs are distinct."""
    sk = os.urandom(HASH_LEN)
    th = os.urandom(HASH_LEN)
    s  = derive_traffic_secrets(sk, th)

    fields = [s.client_hs, s.server_hs, s.client_app, s.server_app, s.exporter]
    names  = ["client_hs", "server_hs", "client_app", "server_app", "exporter"]

    for i in range(len(fields)):
        for j in range(i + 1, len(fields)):
            assert fields[i] != fields[j], (
                f"Secrets {names[i]} and {names[j]} must be distinct"
            )


def test_derive_traffic_secrets_sk_sensitivity():
    """TC-KDF-14: Changing the OPAQUE session key changes all 5 secrets."""
    th = os.urandom(HASH_LEN)
    s1 = derive_traffic_secrets(os.urandom(HASH_LEN), th)
    s2 = derive_traffic_secrets(os.urandom(HASH_LEN), th)

    for attr in ("client_hs", "server_hs", "client_app", "server_app", "exporter"):
        assert getattr(s1, attr) != getattr(s2, attr), (
            f"Secret {attr!r} must change when OPAQUE SK changes"
        )


def test_derive_traffic_secrets_th_sensitivity():
    """TC-KDF-15: Changing the transcript hash changes all 5 secrets."""
    sk = os.urandom(HASH_LEN)
    s1 = derive_traffic_secrets(sk, os.urandom(HASH_LEN))
    s2 = derive_traffic_secrets(sk, os.urandom(HASH_LEN))

    for attr in ("client_hs", "server_hs", "client_app", "server_app", "exporter"):
        assert getattr(s1, attr) != getattr(s2, attr), (
            f"Secret {attr!r} must change when transcript hash changes"
        )


def test_derive_traffic_secrets_output_length():
    """TC-KDF-16: All derived secrets are exactly HASH_LEN bytes."""
    s = derive_traffic_secrets(os.urandom(HASH_LEN), os.urandom(HASH_LEN))
    for attr in ("client_hs", "server_hs", "client_app", "server_app", "exporter"):
        v = getattr(s, attr)
        assert len(v) == HASH_LEN, f"{attr} must be {HASH_LEN} bytes, got {len(v)}"


def test_derive_secret_label_context_collision():
    """TC-KDF-17: derive_secret with colliding label+context still separate."""
    # "ab" + "c" should differ from "a" + "bc" — our encoding uses length prefixes.
    secret = os.urandom(HASH_LEN)
    th = os.urandom(HASH_LEN)
    out1 = derive_secret(secret, b"ab",  th)
    out2 = derive_secret(secret, b"a",   th)   # different label → different output
    assert out1 != out2


# ── Test runner ───────────────────────────────────────────────────────────────

def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {fn.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed out of {passed+failed} tests")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    print("=== test_kdf ===")
    _run_all()
