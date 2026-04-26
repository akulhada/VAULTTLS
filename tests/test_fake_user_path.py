"""
tests/test_fake_user_path.py
============================
Security: non-existent user gets a syntactically valid KE2 (fake record path)
and is rejected at login_finish — without leaking user existence in the error
message or via timing differences detectable under a 1-second threshold.
"""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import CONTEXT_STRING, SERVER_ID, SERVER_CERT_KEY_PATH
from pki import bootstrap_pki, load_private_key
from opaque_adapter import ConcreteOpaqueClient, ConcreteOpaqueServer
from tls13_kdf import hash_bytes


def _cred_id(u: bytes) -> bytes:
    return hash_bytes(CONTEXT_STRING + u)


def _register(srv, username, password):
    cid = _cred_id(username)
    c   = ConcreteOpaqueClient()
    req, st = c.registration_start(password, username, SERVER_ID, CONTEXT_STRING)
    resp = srv.registration_respond(cid, req)
    rec  = c.registration_finish(st, resp)
    srv.registration_store(cid, rec)


def test_fake_user_path():
    bootstrap_pki()
    server_key = load_private_key(SERVER_CERT_KEY_PATH)
    srv        = ConcreteOpaqueServer(server_key)

    # Register a real user for comparison
    _register(srv, b"realuser", b"realpass")
    client = ConcreteOpaqueClient()

    # ── 1. Non-existent user gets a fake KE2 (no exception from login_start) ──
    ghost_cid = _cred_id(b"ghost_nobody_xyz")
    ke1, state = client.login_start(b"anypass", b"ghost", SERVER_ID, CONTEXT_STRING)
    ke2, srv_state = srv.login_start(ghost_cid, ke1, CONTEXT_STRING)

    assert ke2 is not None,              "login_start must return a KE2 for unknown user"
    assert srv_state["is_fake"] is True, "is_fake must be True for unknown user"
    assert len(ke2) > 32,               "fake KE2 must look real (non-trivial length)"
    print("  Fake KE2 returned (looks real) ✓")

    # ── 2. login_finish raises with a generic error (no user-existence leak) ──
    forged_ke3 = os.urandom(64)
    try:
        srv.login_finish(srv_state, forged_ke3)
        raise AssertionError("login_finish must raise for fake user")
    except ValueError as e:
        msg = str(e).lower()
        assert "not found" not in msg and "no such" not in msg and "unknown user" not in msg, \
            f"Error leaks user existence: {e}"
        print(f"  Fake user rejected with generic message: {e}")

    # ── 3. Timing: |real − fake| < 1 second (loose bound for CI) ─────────────
    real_cid = _cred_id(b"realuser")
    REPS = 5

    def _time_login_start(cid):
        total = 0.0
        for _ in range(REPS):
            ke1_t, _ = client.login_start(b"pw", b"u", SERVER_ID, CONTEXT_STRING)
            t0 = time.perf_counter()
            srv.login_start(cid, ke1_t, CONTEXT_STRING)
            total += time.perf_counter() - t0
        return total / REPS

    real_avg  = _time_login_start(real_cid)
    fake_avg  = _time_login_start(ghost_cid)
    diff = abs(real_avg - fake_avg)
    print(f"  Timing avg: real={real_avg*1000:.1f}ms  fake={fake_avg*1000:.1f}ms  |diff|={diff*1000:.1f}ms")
    assert diff < 1.0, f"Timing difference too large: {diff:.3f}s — possible oracle"

    print("test_fake_user_path: PASS ✓")


if __name__ == "__main__":
    test_fake_user_path()
