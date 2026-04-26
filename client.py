"""
client.py
=========
VAULTTLS client.

Handshake steps
---------------
1. OPAQUE login_start      — blind password and build KE1
2. Send ClientHello
3. Receive ServerHello
4. Verify certificate chain against the pinned local CA
5. Verify ServerConfig signature and fixed-suite contents
6. Verify CertificateVerify over the live transcript
7. Complete OPAQUE login_finish and verify the server MAC
8. Send ClientFinish (KE3)
9. Derive TLS 1.3-shaped traffic secrets
10. Exchange encrypted application data
"""
from __future__ import annotations

import getpass
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import CONTEXT_STRING, HOST, PORT, SERVER_ID, SOCKET_TIMEOUT
from codec import (
    TAG_ALERT,
    TAG_CLOSE,
    decode_alert,
    decode_app_data,
    decode_server_hello,
    encode_app_data,
    encode_client_finish,
    encode_client_hello,
    encode_close,
    encode_server_hello_core,
)
from opaque_adapter import ConcreteOpaqueClient
from pki import (
    bootstrap_pki,
    verify_certificate_chain,
    verify_certificate_verify_signature,
    verify_server_config_signature,
)
from record import CT_APP_DATA, DirectionState
from server_config import validate_server_config
from tls13_kdf import Transcript, derive_traffic_secrets, hash_bytes
from transcript import recv_frame, send_frame



def _make_login_credential_id(username: str) -> bytes:
    """credential_id = SHA-512(context || username)."""
    return hash_bytes(CONTEXT_STRING + username.encode())



def client_login(
        sock: socket.socket,
        username: str,
        password: str,
        opaque_client: ConcreteOpaqueClient,
):
    """Execute the full client-side handshake and return (TrafficSecrets, export_key)."""
    transcript = Transcript()
    credential_id = _make_login_credential_id(username)

    ke1, client_state = opaque_client.login_start(
        password=password.encode(),
        client_id=username.encode(),
        server_id=SERVER_ID,
        context=CONTEXT_STRING,
    )

    client_hello = encode_client_hello(
        version=1,
        credential_id=credential_id,
        client_nonce=client_state["nonce_c"],
        opaque_ke1=ke1,
    )
    transcript.add("client_hello", client_hello)
    send_frame(sock, client_hello)

    server_hello_raw = recv_frame(sock)
    if server_hello_raw[0] == TAG_ALERT:
        raise RuntimeError(f"Server alert: {decode_alert(server_hello_raw).message}")

    transcript.add("server_hello", server_hello_raw)
    parsed = decode_server_hello(server_hello_raw)

    server_cert = verify_certificate_chain(
        parsed.certificate_chain,
        expected_name="localhost",
    )
    verify_server_config_signature(parsed.server_config, parsed.server_config_sig, server_cert)
    validate_server_config(parsed.server_config, expected_name=SERVER_ID)

    pre_server_hello = Transcript()
    pre_server_hello.add("client_hello", client_hello)
    transcript_hash_before_sh = pre_server_hello.digest()

    core = encode_server_hello_core(
        version=parsed.version,
        server_nonce=parsed.server_nonce,
        certificate=parsed.certificate_chain,
        server_config=parsed.server_config,
        opaque_ke2=parsed.opaque_ke2,
    )
    verify_certificate_verify_signature(
        parsed.cert_verify_sig,
        transcript_hash_before_sh,
        core,
        server_cert,
    )

    session_key, export_key, ke3 = opaque_client.login_finish(client_state, parsed.opaque_ke2)

    client_finish = encode_client_finish(opaque_ke3=ke3)
    transcript.add("client_finish", client_finish)
    send_frame(sock, client_finish)

    secrets = derive_traffic_secrets(session_key, transcript.digest())
    return secrets, export_key



def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="VAULTTLS client")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", default=None)
    parser.add_argument("--message", default="Hello, VAULTTLS!")
    args = parser.parse_args()

    bootstrap_pki()
    password = args.password or getpass.getpass(f"Password for {args.user!r}: ")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((HOST, PORT))
    print(f"[CLIENT] Connected to {HOST}:{PORT}")

    try:
        secrets, export_key = client_login(sock, args.user, password, ConcreteOpaqueClient())
        print(f"[CLIENT] Secure channel established. export_key[:8]={export_key[:8].hex()}")

        send_enc = DirectionState(secrets.client_app)
        recv_enc = DirectionState(secrets.server_app)

        seq, ct = send_enc.encrypt(CT_APP_DATA, args.message.encode())
        send_frame(sock, encode_app_data(seq, ct))
        print(f"[CLIENT] Sent: {args.message!r}")

        resp = recv_frame(sock)
        if resp[0] == 0x04:
            ad = decode_app_data(resp)
            pt = recv_enc.decrypt(CT_APP_DATA, ad.seq, ad.ciphertext)
            print(f"[CLIENT] Received: {pt.decode()!r}")
        send_frame(sock, encode_close())
    finally:
        sock.close()


if __name__ == "__main__":
    main()
