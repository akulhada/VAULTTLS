"""
storage.py
==========
Thread-safe persistent storage for the OPAQUE password database and server
state, backed by JSON files.

Design
------
• The entire file is read into memory on first access and written back on
  every mutation.  This is fine for a class project; a production system
  would use SQLite or a proper KV store with atomic transactions.
• Writes use the write-then-rename pattern (write to .tmp, then os.replace)
  to prevent a crash mid-write from corrupting the database.
• A threading.Lock guards all reads and writes so the server can handle
  concurrent connections safely.

OPAQUE password record layout (JSON, per user):
  {
    "oprf_key_hex":     "<hex>",     # per-user OPRF server key
    "client_pub_hex":   "<hex>",     # client's long-term public key
    "envelope_hex":     "<hex>",     # AES-GCM sealed client credentials
    "credential_id_hex":"<hex>"      # SHA-512( context ‖ username )
  }
"""

import json
import os
import threading
from typing import Any

from config import USERS_DB_PATH, SERVER_STATE_PATH, DB_DIR


class JSONStore:
    """Generic thread-safe JSON file store."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        os.makedirs(DB_DIR, exist_ok=True)
        if not os.path.exists(path):
            self._write_raw({})

    def _read_raw(self) -> dict:
        with open(self._path) as f:
            return json.load(f)

    def _write_raw(self, data: dict) -> None:
        tmp = self._path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self._path)   # atomic on POSIX

    def get(self, key: str) -> Any | None:
        with self._lock:
            return self._read_raw().get(key)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            data = self._read_raw()
            data[key] = value
            self._write_raw(data)

    def delete(self, key: str) -> None:
        with self._lock:
            data = self._read_raw()
            data.pop(key, None)
            self._write_raw(data)

    def exists(self, key: str) -> bool:
        with self._lock:
            return key in self._read_raw()

    def all(self) -> dict:
        with self._lock:
            return dict(self._read_raw())


# ── Singleton stores ──────────────────────────────────────────────────────────

_users_store:  JSONStore | None = None
_state_store:  JSONStore | None = None


def users_db() -> JSONStore:
    """Return the singleton user password database store."""
    global _users_store
    if _users_store is None:
        _users_store = JSONStore(USERS_DB_PATH)
    return _users_store


def server_state_db() -> JSONStore:
    """Return the singleton server state store."""
    global _state_store
    if _state_store is None:
        _state_store = JSONStore(SERVER_STATE_PATH)
    return _state_store


# ── OPAQUE record helpers ─────────────────────────────────────────────────────

def store_opaque_record(
        credential_id: bytes,
        oprf_key: bytes,
        client_pub: bytes,
        envelope: bytes,
) -> None:
    """
    Persist an OPAQUE registration record.
    Key is hex(credential_id) so it is safe as a JSON key.
    """
    key = credential_id.hex()
    users_db().set(key, {
        "oprf_key_hex":      oprf_key.hex(),
        "client_pub_hex":    client_pub.hex(),
        "envelope_hex":      envelope.hex(),
        "credential_id_hex": credential_id.hex(),
    })


def load_opaque_record(credential_id: bytes) -> dict | None:
    """
    Load an OPAQUE record.  Returns None if no such user exists.
    All hex fields are decoded back to bytes before returning.
    """
    raw = users_db().get(credential_id.hex())
    if raw is None:
        return None
    return {
        "oprf_key":      bytes.fromhex(raw["oprf_key_hex"]),
        "client_pub":    bytes.fromhex(raw["client_pub_hex"]),
        "envelope":      bytes.fromhex(raw["envelope_hex"]),
        "credential_id": bytes.fromhex(raw["credential_id_hex"]),
    }


def record_exists(credential_id: bytes) -> bool:
    return users_db().exists(credential_id.hex())
