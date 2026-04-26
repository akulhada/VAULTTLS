"""
server_config.py
================
Static server capability blob.

The client verifies this structure after verifying its signature with the
certified server public key. This prevents a peer from silently swapping the
advertised algorithm suite or service name.

Wire format (all big-endian):
    version        : uint8
    supported_kex  : uint8   (0x01 = OPAQUE-3DH-P256)
    supported_aead : uint8   (0x02 = ChaCha20-Poly1305)
    supported_hash : uint8   (0x03 = SHA-512)
    server_name    : uint16-length-prefixed UTF-8 string
    timestamp      : uint64  (Unix epoch seconds)
"""
from __future__ import annotations

import struct
import time

from config import SERVER_ID

SUPPORTED_KEX = 0x01   # OPAQUE-3DH-P256
SUPPORTED_AEAD = 0x02  # ChaCha20-Poly1305
SUPPORTED_HASH = 0x03  # SHA-512
SERVER_CONFIG_VERSION = 1
SERVER_CONFIG_MAX_AGE_S = 24 * 60 * 60


def encode_server_config(server_name: bytes = SERVER_ID) -> bytes:
    """Build the signed server capability blob."""
    ts = int(time.time())
    name_field = struct.pack("!H", len(server_name)) + server_name
    return (
            bytes([
                SERVER_CONFIG_VERSION,
                SUPPORTED_KEX,
                SUPPORTED_AEAD,
                SUPPORTED_HASH,
            ])
            + name_field
            + struct.pack("!Q", ts)
    )



def decode_server_config(data: bytes) -> dict:
    """Parse a server_config blob into a dict."""
    if len(data) < 14:
        raise ValueError("ServerConfig too short")
    version = data[0]
    supported_kex = data[1]
    supported_aead = data[2]
    supported_hash = data[3]
    name_len = struct.unpack_from("!H", data, 4)[0]
    if len(data) < 6 + name_len + 8:
        raise ValueError("ServerConfig truncated")
    server_name = data[6 : 6 + name_len]
    timestamp = struct.unpack_from("!Q", data, 6 + name_len)[0]
    return {
        "version": version,
        "supported_kex": supported_kex,
        "supported_aead": supported_aead,
        "supported_hash": supported_hash,
        "server_name": server_name,
        "timestamp": timestamp,
    }



def validate_server_config(
        data: bytes,
        expected_name: bytes = SERVER_ID,
        max_age_seconds: int = SERVER_CONFIG_MAX_AGE_S,
) -> dict:
    """
    Enforce the fixed algorithm suite and service identity expected by the
    client for this project.
    """
    cfg = decode_server_config(data)
    if cfg["version"] != SERVER_CONFIG_VERSION:
        raise ValueError(f"Unsupported ServerConfig version {cfg['version']}")
    if cfg["supported_kex"] != SUPPORTED_KEX:
        raise ValueError("Unexpected key-exchange suite in ServerConfig")
    if cfg["supported_aead"] != SUPPORTED_AEAD:
        raise ValueError("Unexpected AEAD suite in ServerConfig")
    if cfg["supported_hash"] != SUPPORTED_HASH:
        raise ValueError("Unexpected hash suite in ServerConfig")
    if cfg["server_name"] != expected_name:
        raise ValueError("ServerConfig service identity mismatch")

    now = int(time.time())
    if abs(now - cfg["timestamp"]) > max_age_seconds:
        raise ValueError("ServerConfig timestamp is stale or implausible")
    return cfg
