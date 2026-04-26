"""
transcript.py
=============
Two responsibilities:
  1. TCP socket framing — send_frame / recv_frame (length-prefix protocol)
  2. Re-export of Transcript from tls13_kdf for convenient import

Why combine them here?
  The protocol needs both framing and transcript hashing;
  having one import target keeps callers simple.

TCP framing format: [uint32 length BE] [payload bytes]
Maximum payload: 4 MiB (guards against memory exhaustion).
"""
import struct
import socket as _socket

from tls13_kdf import Transcript   # re-export

MAX_FRAME = 4 * 1024 * 1024


def send_frame(sock: _socket.socket, payload: bytes) -> None:
    """Send one length-prefixed binary frame via sendall()."""
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_frame(sock: _socket.socket) -> bytes:
    """Receive exactly one length-prefixed binary frame."""
    header = _recv_exactly(sock, 4)
    length = struct.unpack("!I", header)[0]
    if length > MAX_FRAME:
        raise ValueError(f"Frame too large: {length} > {MAX_FRAME}")
    return _recv_exactly(sock, length)


def _recv_exactly(sock: _socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                f"Peer closed connection after {len(buf)}/{n} bytes"
            )
        buf.extend(chunk)
    return bytes(buf)
