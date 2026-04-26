"""
tests/test_storage_ratelimit.py
================================
Unit tests for storage.py and ratelimit.py.

Test cases defined upfront (TDD):

  TC-STO-01  store + load roundtrip: all four fields (oprf_key, client_pub,
             envelope, credential_id) are byte-identical after hex round-trip
  TC-STO-02  load unknown credential_id returns None
  TC-STO-03  overwrite: second store replaces first value
  TC-STO-04  hex encoding is lossless for all-zero and all-FF bytes

  TC-RLT-01  first MAX_TRIES attempts are all allowed
  TC-RLT-02  MAX_TRIES+1th attempt within window is denied
  TC-RLT-03  different IPs are tracked independently
  TC-RLT-04  different credential_ids on same IP are tracked independently
  TC-RLT-05  after window expiry, attempts are allowed again
  TC-RLT-06  reset() clears the counter so next attempt is allowed
  TC-RLT-07  denied attempt is not recorded (retry after denial still counts correctly)

  TC-SCF-01  server_config encode→decode roundtrip preserves all fields
  TC-SCF-02  two calls with different timestamps produce different blobs
"""
import os
import sys
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Storage ───────────────────────────────────────────────────────────────────

def test_storage_roundtrip():
    """TC-STO-01: All four OPAQUE record fields survive store→load byte-identical."""
    # Use a temporary DB file so tests don't pollute the real database
    import json, os
    from unittest.mock import patch

    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    try:
        with patch("storage.USERS_DB_PATH", tmp.name):
            # Re-import to pick up patched path
            import importlib, storage
            importlib.reload(storage)
            storage._users_store = None   # clear singleton

            cred_id   = os.urandom(64)
            oprf_key  = os.urandom(32)
            client_pub = os.urandom(65)
            envelope  = os.urandom(142)

            storage.store_opaque_record(cred_id, oprf_key, client_pub, envelope)
            rec = storage.load_opaque_record(cred_id)

            assert rec is not None,               "Record must exist after store"
            assert rec["oprf_key"]   == oprf_key,   "oprf_key mismatch"
            assert rec["client_pub"] == client_pub, "client_pub mismatch"
            assert rec["envelope"]   == envelope,   "envelope mismatch"
            assert rec["credential_id"] == cred_id, "credential_id mismatch"
    finally:
        os.unlink(tmp.name)
        import storage as _s; _s._users_store = None   # reset


def test_storage_unknown_returns_none():
    """TC-STO-02: load_opaque_record for unknown credential_id returns None."""
    import importlib, storage
    storage._users_store = None
    rec = storage.load_opaque_record(os.urandom(64))
    assert rec is None, "Unknown record must return None"


def test_storage_overwrite():
    """TC-STO-03: Second store with same cred_id overwrites the first."""
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    try:
        from unittest.mock import patch
        with patch("storage.USERS_DB_PATH", tmp.name):
            import importlib, storage
            importlib.reload(storage); storage._users_store = None

            cred_id = os.urandom(64)
            oprf1   = os.urandom(32)
            oprf2   = os.urandom(32)

            storage.store_opaque_record(cred_id, oprf1, os.urandom(65), os.urandom(142))
            storage.store_opaque_record(cred_id, oprf2, os.urandom(65), os.urandom(142))

            rec = storage.load_opaque_record(cred_id)
            assert rec["oprf_key"] == oprf2, "Second store must overwrite first"
    finally:
        os.unlink(tmp.name)
        import storage as _s; _s._users_store = None


def test_storage_hex_lossless():
    """TC-STO-04: Hex encoding is lossless for all-zero and all-FF bytes."""
    zeros = bytes(64)
    ff_bytes = bytes([0xFF] * 64)
    assert bytes.fromhex(zeros.hex())    == zeros
    assert bytes.fromhex(ff_bytes.hex()) == ff_bytes


# ── Rate Limiter ──────────────────────────────────────────────────────────────

def _make_limiter(max_tries=5, window=60):
    from ratelimit import RateLimiter
    return RateLimiter(window_s=window, max_tries=max_tries)


def test_ratelimit_first_n_allowed():
    """TC-RLT-01: First max_tries attempts within window are all allowed."""
    rl  = _make_limiter(max_tries=5)
    cid = os.urandom(8)
    for i in range(5):
        assert rl.allow("1.2.3.4", cid), f"Attempt {i+1} should be allowed"


def test_ratelimit_n_plus_1_denied():
    """TC-RLT-02: The max_tries+1th attempt within window is denied."""
    rl  = _make_limiter(max_tries=5)
    cid = os.urandom(8)
    for _ in range(5):
        rl.allow("1.2.3.4", cid)
    assert not rl.allow("1.2.3.4", cid), "6th attempt must be denied"


def test_ratelimit_different_ips_independent():
    """TC-RLT-03: Rate limits are per-(IP, cred_id): different IPs don't interfere."""
    rl  = _make_limiter(max_tries=3)
    cid = os.urandom(8)
    # Exhaust IP-A
    for _ in range(3):
        rl.allow("10.0.0.1", cid)
    assert not rl.allow("10.0.0.1", cid), "IP-A should be rate limited"
    # IP-B is independent
    assert rl.allow("10.0.0.2", cid), "IP-B should still be allowed"


def test_ratelimit_different_creds_independent():
    """TC-RLT-04: Different credential_ids on same IP are tracked independently."""
    rl   = _make_limiter(max_tries=3)
    cid1 = os.urandom(8)
    cid2 = os.urandom(8)
    for _ in range(3):
        rl.allow("1.2.3.4", cid1)
    assert not rl.allow("1.2.3.4", cid1), "cid1 should be rate limited"
    assert rl.allow("1.2.3.4", cid2),     "cid2 should be independent"


def test_ratelimit_window_expiry():
    """TC-RLT-05: After window expires, attempts are allowed again."""
    rl  = _make_limiter(max_tries=2, window=0.05)   # 50ms window
    cid = os.urandom(8)
    rl.allow("1.2.3.4", cid)
    rl.allow("1.2.3.4", cid)
    assert not rl.allow("1.2.3.4", cid), "Should be rate limited"
    time.sleep(0.1)   # wait for window to expire
    assert rl.allow("1.2.3.4", cid), "After expiry, should be allowed again"


def test_ratelimit_reset():
    """TC-RLT-06: reset() clears counter so next attempt is allowed immediately."""
    rl  = _make_limiter(max_tries=2)
    cid = os.urandom(8)
    rl.allow("1.2.3.4", cid)
    rl.allow("1.2.3.4", cid)
    assert not rl.allow("1.2.3.4", cid), "Should be rate limited before reset"
    rl.reset("1.2.3.4", cid)
    assert rl.allow("1.2.3.4", cid), "After reset, should be allowed"


def test_ratelimit_denied_not_recorded():
    """TC-RLT-07: A denied attempt is not added to the history count."""
    rl  = _make_limiter(max_tries=3)
    cid = os.urandom(8)
    # 3 allowed attempts
    for _ in range(3):
        rl.allow("1.2.3.4", cid)
    # 4th denied (not recorded)
    assert not rl.allow("1.2.3.4", cid)
    # 5th should also be denied (not reset to 3)
    assert not rl.allow("1.2.3.4", cid), "Denied attempts must not reset the counter"


# ── ServerConfig ──────────────────────────────────────────────────────────────

def test_server_config_roundtrip():
    """TC-SCF-01: encode→decode preserves version, kex, aead, hash, server_name."""
    from server_config import encode_server_config, decode_server_config
    cfg = encode_server_config(server_name=b"localhost")
    d   = decode_server_config(cfg)
    assert d["version"]        == 1
    assert d["supported_kex"]  == 0x01
    assert d["supported_aead"] == 0x02
    assert d["supported_hash"] == 0x03
    assert d["server_name"]    == b"localhost"
    assert isinstance(d["timestamp"], int) and d["timestamp"] > 0


def test_server_config_different_timestamps():
    """TC-SCF-02: Two calls at different times produce different blobs."""
    from server_config import encode_server_config
    cfg1 = encode_server_config()
    time.sleep(1.1)   # ensure timestamp differs by at least 1 second
    cfg2 = encode_server_config()
    assert cfg1 != cfg2, "Different timestamps must produce different server_config blobs"


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
    print("=== test_storage_ratelimit ===")
    _run_all()
