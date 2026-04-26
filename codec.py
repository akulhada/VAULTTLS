"""
codec.py
========
Binary wire serialisation / deserialisation for all protocol messages.

Every message is a raw byte string prefixed with a 1-byte message-type tag.
All multi-byte integers are big-endian.  Transport framing (4-byte length
prefix) is handled by transcript.py.

Message-type tags
-----------------
  0x01  ClientHello
  0x02  ServerHello
  0x03  ClientFinish
  0x04  AppData
  0x05  Alert
  0x06  Close

Wire layouts
------------
ClientHello:
  tag:1 | version:1 | cred_id:64 | client_nonce:32 | ke1_len:2 | ke1

ServerHello:
  tag:1 | version:1 | srv_nonce:32
        | ke2_len:2 | ke2
        | cert_len:3 | cert_chain
        | cfg_len:2  | server_config
        | cfg_sig_len:2 | cfg_sig       (ECDSA DER, variable)
        | cv_sig_len:2  | cv_sig        (ECDSA DER, variable)

ClientFinish:
  tag:1 | ke3_len:2 | ke3

AppData:
  tag:1 | seq:8 | ct_len:4 | ciphertext

Alert:
  tag:1 | level:1 | msg_len:2 | msg_utf8

Close:
  tag:1
"""
from __future__ import annotations
import struct
from dataclasses import dataclass

# ── Tags ─────────────────────────────────────────────────────────────────────
TAG_CLIENT_HELLO  = 0x01
TAG_SERVER_HELLO  = 0x02
TAG_CLIENT_FINISH = 0x03
TAG_APP_DATA      = 0x04
TAG_ALERT         = 0x05
TAG_CLOSE         = 0x06

HASH_LEN  = 64   # SHA-512 credential-id length
NONCE_LEN = 32

ALERT_WARNING = 1
ALERT_FATAL   = 2


# ── Parsed message dataclasses ────────────────────────────────────────────────
@dataclass
class ParsedClientHello:
    version:       int
    credential_id: bytes   # 64 bytes
    client_nonce:  bytes   # 32 bytes
    opaque_ke1:    bytes

@dataclass
class ParsedServerHello:
    version:           int
    server_nonce:      bytes   # 32 bytes
    opaque_ke2:        bytes
    certificate_chain: bytes
    server_config:     bytes
    server_config_sig: bytes   # DER ECDSA (variable length)
    cert_verify_sig:   bytes   # DER ECDSA (variable length)

@dataclass
class ParsedClientFinish:
    opaque_ke3: bytes

@dataclass
class ParsedAppData:
    seq:        int
    ciphertext: bytes

@dataclass
class ParsedAlert:
    level:   int
    message: str


# ── Reader helper ─────────────────────────────────────────────────────────────
class _R:
    def __init__(self, d: bytes) -> None:
        self._d = d; self._p = 0
    def read(self, n: int) -> bytes:
        c = self._d[self._p:self._p+n]
        if len(c) != n:
            raise ValueError(f"Truncated at offset {self._p}: need {n}, have {len(c)}")
        self._p += n; return c
    def u8(self)  -> int: return self.read(1)[0]
    def u16(self) -> int: return struct.unpack("!H", self.read(2))[0]
    def u24(self) -> int: return int.from_bytes(self.read(3), "big")
    def u32(self) -> int: return struct.unpack("!I", self.read(4))[0]
    def u64(self) -> int: return struct.unpack("!Q", self.read(8))[0]
    def v16(self) -> bytes: return self.read(self.u16())
    def v24(self) -> bytes: return self.read(self.u24())

def _p16(d: bytes) -> bytes:
    return struct.pack("!H", len(d)) + d

def _p24(d: bytes) -> bytes:
    return len(d).to_bytes(3, "big") + d


# ── ClientHello ───────────────────────────────────────────────────────────────
def encode_client_hello(
        version: int,
        credential_id: bytes,
        client_nonce: bytes,
        opaque_ke1: bytes,
) -> bytes:
    assert len(credential_id) == HASH_LEN,  f"credential_id must be {HASH_LEN}B"
    assert len(client_nonce)  == NONCE_LEN, f"client_nonce must be {NONCE_LEN}B"
    return (bytes([TAG_CLIENT_HELLO, version])
            + credential_id + client_nonce + _p16(opaque_ke1))

def decode_client_hello(data: bytes) -> ParsedClientHello:
    r = _R(data)
    assert r.u8() == TAG_CLIENT_HELLO, "Not a ClientHello"
    return ParsedClientHello(r.u8(), r.read(HASH_LEN), r.read(NONCE_LEN), r.v16())


# ── ServerHello ───────────────────────────────────────────────────────────────
def encode_server_hello_core(
        version: int,
        server_nonce: bytes,
        certificate: bytes,
        server_config: bytes,
        opaque_ke2: bytes,
) -> bytes:
    """The portion of ServerHello that is signed by CertificateVerify."""
    assert len(server_nonce) == NONCE_LEN
    return (bytes([version]) + server_nonce
            + _p16(opaque_ke2) + _p24(certificate) + _p16(server_config))

def encode_server_hello(
        core: bytes,
        server_config_sig: bytes,   # DER ECDSA, variable length
        cert_verify_sig:   bytes,   # DER ECDSA, variable length
) -> bytes:
    """Wrap core + both length-prefixed signatures into the final ServerHello."""
    return (bytes([TAG_SERVER_HELLO]) + core
            + _p16(server_config_sig)
            + _p16(cert_verify_sig))

def decode_server_hello(data: bytes) -> ParsedServerHello:
    r = _R(data)
    assert r.u8() == TAG_SERVER_HELLO, "Not a ServerHello"
    version = r.u8()
    srv_nonce = r.read(NONCE_LEN)
    ke2  = r.v16()
    cert = r.v24()
    cfg  = r.v16()
    csig = r.v16()
    cvsig = r.v16()
    return ParsedServerHello(version, srv_nonce, ke2, cert, cfg, csig, cvsig)


# ── ClientFinish ──────────────────────────────────────────────────────────────
def encode_client_finish(opaque_ke3: bytes) -> bytes:
    return bytes([TAG_CLIENT_FINISH]) + _p16(opaque_ke3)

def decode_client_finish(data: bytes) -> ParsedClientFinish:
    r = _R(data)
    assert r.u8() == TAG_CLIENT_FINISH, "Not a ClientFinish"
    return ParsedClientFinish(r.v16())


# ── AppData ───────────────────────────────────────────────────────────────────
def encode_app_data(seq: int, ciphertext: bytes) -> bytes:
    return (bytes([TAG_APP_DATA])
            + struct.pack("!Q", seq)
            + struct.pack("!I", len(ciphertext))
            + ciphertext)

def decode_app_data(data: bytes) -> ParsedAppData:
    r = _R(data)
    assert r.u8() == TAG_APP_DATA, "Not AppData"
    seq = r.u64()
    ct  = r.read(r.u32())
    return ParsedAppData(seq, ct)


# ── Alert ─────────────────────────────────────────────────────────────────────
def encode_alert(level: int, message: str) -> bytes:
    return bytes([TAG_ALERT, level]) + _p16(message.encode("utf-8"))

def decode_alert(data: bytes) -> ParsedAlert:
    r = _R(data)
    assert r.u8() == TAG_ALERT, "Not an Alert"
    return ParsedAlert(r.u8(), r.v16().decode("utf-8", errors="replace"))


# ── Close ─────────────────────────────────────────────────────────────────────
def encode_close() -> bytes:
    return bytes([TAG_CLOSE])
