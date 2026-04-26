"""
register_user.py
================
OPAQUE registration with server authentication.

The registration exchange reuses ClientHello / ServerHello / ClientFinish but
still authenticates the server exactly the way the login path does:
  * pinned-CA certificate-chain verification
  * signed ServerConfig verification
  * CertificateVerify over the live registration transcript

Because this codebase uses the same P-256 key as both the certified server key
and the OPAQUE static key, we also check that the OPAQUE static public key in
reg_response matches the public key embedded in the validated certificate.
"""
from __future__ import annotations

import argparse
import getpass
import hmac
import os
import socket
import sys

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import CONTEXT_STRING, HOST, SERVER_ID, SOCKET_TIMEOUT, PORT
from codec import (
    TAG_ALERT,
    TAG_CLOSE,
    decode_alert,
    decode_server_hello,
    encode_client_finish,
    encode_client_hello,
    encode_server_hello_core,
)
from opaque_adapter import ConcreteOpaqueClient, POINT_LEN
from pki import (
    bootstrap_pki,
    verify_certificate_chain,
    verify_certificate_verify_signature,
    verify_server_config_signature,
)
from server_config import validate_server_config
from tls13_kdf import Transcript, hash_bytes
from transcript import recv_frame, send_frame

REG_VERSION = 2



def _make_cred_id(username: str) -> bytes:
    return hash_bytes(CONTEXT_STRING + username.encode())



def _cert_public_key_bytes(cert) -> bytes:
    return cert.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )



def register(username: str, password: str) -> None:
    bootstrap_pki()
    client = ConcreteOpaqueClient()
    cred_id = _make_cred_id(username)

    reg_request, reg_state = client.registration_start(
        password.encode(),
        username.encode(),
        SERVER_ID,
        CONTEXT_STRING,
    )

    transcript = Transcript()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((HOST, PORT))
    print(f"[REG] Connected to {HOST}:{PORT}")

    try:
        client_hello = encode_client_hello(
            version=REG_VERSION,
            credential_id=cred_id,
            client_nonce=os.urandom(32),
            opaque_ke1=reg_request,
        )
        transcript.add("client_hello", client_hello)
        send_frame(sock, client_hello)

        server_hello_raw = recv_frame(sock)
        if server_hello_raw[0] == TAG_ALERT:
            raise RuntimeError(f"Server: {decode_alert(server_hello_raw).message}")
        transcript.add("server_hello", server_hello_raw)
        parsed = decode_server_hello(server_hello_raw)

        server_cert = verify_certificate_chain(parsed.certificate_chain, expected_name="localhost")
        verify_server_config_signature(parsed.server_config, parsed.server_config_sig, server_cert)
        validate_server_config(parsed.server_config, expected_name=SERVER_ID)

        pre_server_hello = Transcript()
        pre_server_hello.add("client_hello", client_hello)
        core = encode_server_hello_core(
            version=parsed.version,
            server_nonce=parsed.server_nonce,
            certificate=parsed.certificate_chain,
            server_config=parsed.server_config,
            opaque_ke2=parsed.opaque_ke2,
        )
        verify_certificate_verify_signature(
            parsed.cert_verify_sig,
            pre_server_hello.digest(),
            core,
            server_cert,
        )

        opaque_static_pub = parsed.opaque_ke2[POINT_LEN:]
        cert_pub = _cert_public_key_bytes(server_cert)
        if not hmac.compare_digest(opaque_static_pub, cert_pub):
            raise ValueError("Registration response OPAQUE static key does not match the certified server key")

        record = client.registration_finish(reg_state, parsed.opaque_ke2)
        send_frame(sock, encode_client_finish(opaque_ke3=record))

        ack = recv_frame(sock)
        if ack[0] != TAG_CLOSE:
            raise RuntimeError(f"Unexpected ack tag 0x{ack[0]:02x}")
        print(f"[REG] Registered {username!r} ✓")
    finally:
        sock.close()



def main() -> None:
    parser = argparse.ArgumentParser(description="Register a VAULTTLS user")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", default=None)
    args = parser.parse_args()
    password = args.password or getpass.getpass(f"Password for {args.user!r}: ")
    try:
        register(args.user, password)
    except Exception as exc:
        print(f"[REG] Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
