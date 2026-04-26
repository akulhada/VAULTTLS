"""
ratelimit.py
============
Sliding-window rate limiter for login attempts.

Motivation
----------
OPAQUE prevents offline dictionary attacks by requiring an OPRF evaluation
per guess.  But an online attacker can still hammer the server.  A rate
limiter at the session layer caps the attacker's guessing speed and provides
a first line of defence before the expensive OPAQUE computation runs.

Design
------
• State is a dict mapping (ip, credential_id_hex) → list[float] of timestamps.
• On each attempt, timestamps older than WINDOW are purged, then the count is
  checked.  If ≤ MAX_TRIES, the timestamp is recorded and the attempt is
  allowed; otherwise it is denied.
• All state is in-process memory — a restart resets counts.  For production,
  use Redis with a sorted set per key (ZADD + ZREMRANGEBYSCORE + ZCARD).
• A threading.Lock ensures correctness under concurrent connections.

Reference:
    OWASP Authentication Cheat Sheet — account lockout / rate limiting
    Boneh & Shoup §21 (online guessing attacks)
"""

import threading
import time
from collections import defaultdict

from config import RATE_LIMIT_WINDOW_S, RATE_LIMIT_MAX_TRIES


class RateLimiter:
    """
    Sliding-window rate limiter.

    Each (ip, credential_id_hex) pair is tracked independently.
    Call allow(ip, credential_id) before the OPAQUE computation;
    it returns False immediately if the limit is exceeded.
    """

    def __init__(
            self,
            window_s: float = RATE_LIMIT_WINDOW_S,
            max_tries: int  = RATE_LIMIT_MAX_TRIES,
    ) -> None:
        self._window   = window_s
        self._max      = max_tries
        self._lock     = threading.Lock()
        # (ip, cred_hex) → sorted list of Unix timestamps
        self._history: dict[tuple, list[float]] = defaultdict(list)

    def allow(self, ip: str, credential_id: bytes) -> bool:
        """
        Return True and record the attempt if it is within the rate limit.
        Return False (without recording) if the limit is exceeded.

        Calling code must NOT proceed with the OPAQUE computation if this
        returns False — doing so would let the attacker enumerate passwords.
        """
        key = (ip, credential_id.hex())
        now = time.monotonic()

        with self._lock:
            timestamps = self._history[key]
            # Drop timestamps outside the sliding window
            cutoff    = now - self._window
            timestamps[:] = [t for t in timestamps if t > cutoff]

            if len(timestamps) >= self._max:
                return False          # rate limit exceeded

            timestamps.append(now)
            return True

    def reset(self, ip: str, credential_id: bytes) -> None:
        """Clear the history for a specific key (e.g. after successful auth)."""
        key = (ip, credential_id.hex())
        with self._lock:
            self._history.pop(key, None)


# Module-level singleton used by the server
_limiter: RateLimiter | None = None


def get_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter
