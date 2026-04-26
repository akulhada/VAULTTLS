"""
tests/test_record_replay.py
===========================
Security: replayed or out-of-order records must be rejected.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from record import CT_APP_DATA, DirectionState


def test_record_replay_and_reordering():
    traffic_secret = os.urandom(64)
    sender = DirectionState(traffic_secret)
    receiver = DirectionState(traffic_secret)

    seq0, ct0 = sender.encrypt(CT_APP_DATA, b"first")
    seq1, ct1 = sender.encrypt(CT_APP_DATA, b"second")

    assert receiver.decrypt(CT_APP_DATA, seq0, ct0) == b"first"

    try:
        receiver.decrypt(CT_APP_DATA, seq0, ct0)
        raise AssertionError("Replay should have failed")
    except ValueError as exc:
        assert "sequence" in str(exc).lower()

    try:
        receiver.decrypt(CT_APP_DATA, seq1 + 1, ct1)
        raise AssertionError("Out-of-order record should have failed")
    except ValueError as exc:
        assert "sequence" in str(exc).lower()

    # The correct next record still works.
    assert receiver.decrypt(CT_APP_DATA, seq1, ct1) == b"second"

if __name__ == "__main__":
    try:
        test_record_replay_and_reordering()
        print("Record replay/reordering rejection: PASS ✓")
    except Exception as e:
        print(f"Record replay/reordering rejection: FAIL — {e}")
        raise SystemExit(1)
