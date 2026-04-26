"""
server.py
=========
VAULTTLS server.

Each client connection runs one of two flows:

  Registration (ClientHello.version == 2)
    C -> S : ClientHello   carrying OPRF blind
    S -> C : ServerHello   carrying OPRF response, cert chain, signed config,
                           and CertificateVerify
    C -> S : ClientFinish  carrying the stored OPAQUE record
    S -> C : Close

  Login / handshake (ClientHello.version == 1)
    C -> S : ClientHello   carrying OPAQUE KE1
    S -> C : ServerHello   carrying OPAQUE KE2, cert chain, signed config,
                           and CertificateVerify
    C -> S : ClientFinish  carrying OPAQUE KE3
    ...    : encrypted application data after traffic-key derivation

Security features
-----------------
* certificate-chain validation against a pinned local CA
* CertificateVerify for live transcript binding
* OPAQUE 3DH for password-authenticated key exchange
* fake-record path for unknown users
* rate limiting per (IP, credential_id)
* replay-resistant record layer sequence checks
"""
from __future__ import annotations

import os
import socket
import threading
import traceback

from codec import (
    ALERT_FATAL,
    TAG_CLIENT_HELLO,
    TAG_CLOSE,
    decode_app_data,
    decode_client_finish,
    decode_client_hello,
    encode_alert,
    encode_app_data,
    encode_close,
    encode_server_hello,
    encode_server_hello_core,
)
from config import CA_CERT_PATH, CONTEXT_STRING, HOST, PORT, SERVER_CERT_KEY_PATH, SERVER_CERT_PATH, SOCKET_TIMEOUT
from opaque_adapter import ConcreteOpaqueServer
from pki import (
    bootstrap_pki,
    encode_cert_chain,
    load_certificate,
    load_private_key,
    sign_cert_verify,
    sign_server_config,
)
from ratelimit import get_limiter
from record import CT_APP_DATA, DirectionState
from server_config import encode_server_config
from tls13_kdf import Transcript, derive_traffic_secrets
from transcript import recv_frame, send_frame

REG_VERSION = 2


class ServerSession:
    """Handle one complete TCP connection."""

    def __init__(self, conn, addr, server_key, server_cert, ca_cert):
        self.conn = conn
        self.addr = addr
        self.server_key = server_key
        self.server_cert = server_cert
        self.ca_cert = ca_cert
        self.opaque = ConcreteOpaqueServer(server_key)

    def run(self) -> None:
        ip = self.addr[0]
        print(f"[SERVER] {ip}:{self.addr[1]} connected")
        try:
            self.conn.settimeout(SOCKET_TIMEOUT)
            raw = recv_frame(self.conn)
            if raw[0] != TAG_CLIENT_HELLO:
                self._alert(f"Expected ClientHello, got tag 0x{raw[0]:02x}")
                return
            ch = decode_client_hello(raw)
            if ch.version == REG_VERSION:
                self._handle_registration(ch, raw)
            else:
                self._handle_login(ch, raw, ip)
        except (ConnectionError, TimeoutError) as exc:
            print(f"[SERVER] {ip} connection error: {exc}")
        except Exception:
            print(f"[SERVER] {ip} unhandled error:")
            traceback.print_exc()
        finally:
            try:
                self.conn.close()
            except Exception:
                pass
            print(f"[SERVER] {ip} disconnected")

    def _build_signed_server_hello(self, transcript_before_sh: Transcript, opaque_ke2: bytes) -> bytes:
        """Construct ServerHello and attach both static and per-session signatures."""
        server_config = encode_server_config()
        server_config_sig = sign_server_config(self.server_key, server_config)
        cert_chain = encode_cert_chain(self.ca_cert, self.server_cert)
        core = encode_server_hello_core(
            version=1,
            server_nonce=os.urandom(32),
            certificate=cert_chain,
            server_config=server_config,
            opaque_ke2=opaque_ke2,
        )
        cert_verify_sig = sign_cert_verify(
            self.server_key,
            transcript_before_sh.digest(),
            core,
        )
        return encode_server_hello(core, server_config_sig, cert_verify_sig)

    def _handle_registration(self, ch, raw_client_hello: bytes) -> None:
        """
        Registration flow. The opaque_ke1 field carries the OPRF blind and the
        ClientFinish carries the stored OPAQUE record.
        """
        transcript = Transcript()
        transcript.add("client_hello", raw_client_hello)

        reg_response = self.opaque.registration_respond(ch.credential_id, ch.opaque_ke1)
        server_hello = self._build_signed_server_hello(transcript, reg_response)
        send_frame(self.conn, server_hello)

        cf = decode_client_finish(recv_frame(self.conn))
        self.opaque.registration_store(ch.credential_id, cf.opaque_ke3)
        send_frame(self.conn, encode_close())
        print(f"[SERVER] Registered cred={ch.credential_id[:6].hex()}…")

    def _handle_login(self, ch, raw_client_hello: bytes, ip: str) -> None:
        """Full VAULTTLS login handshake."""
        credential_id = ch.credential_id

        if not get_limiter().allow(ip, credential_id):
            self._alert("Rate limit exceeded — retry later")
            return

        transcript = Transcript()
        transcript.add("client_hello", raw_client_hello)

        try:
            ke2, server_state = self.opaque.login_start(
                credential_id=credential_id,
                ke1=ch.opaque_ke1,
                context=CONTEXT_STRING,
            )
        except Exception as exc:
            self._alert(f"Internal error: {exc}")
            return

        server_hello = self._build_signed_server_hello(transcript, ke2)
        transcript.add("server_hello", server_hello)
        send_frame(self.conn, server_hello)

        cf_raw = recv_frame(self.conn)
        cf = decode_client_finish(cf_raw)
        transcript.add("client_finish", cf_raw)

        try:
            session_key, _export_key = self.opaque.login_finish(server_state, cf.opaque_ke3)
        except ValueError as exc:
            self._alert(str(exc))
            return

        secrets = derive_traffic_secrets(session_key, transcript.digest())
        send_enc = DirectionState(secrets.server_app)
        recv_enc = DirectionState(secrets.client_app)

        get_limiter().reset(ip, credential_id)
        print(f"[SERVER] Handshake OK sk[:8]={session_key[:8].hex()}")
        self._app_loop(send_enc, recv_enc)

    def _app_loop(self, send_enc: DirectionState, recv_enc: DirectionState) -> None:
        """Minimal encrypted echo service."""
        while True:
            try:
                frame = recv_frame(self.conn)
            except ConnectionError:
                break
            if frame[0] == TAG_CLOSE:
                break
            if frame[0] != 0x04:
                break
            ad = decode_app_data(frame)
            try:
                plaintext = recv_enc.decrypt(CT_APP_DATA, ad.seq, ad.ciphertext)
            except Exception as exc:
                self._alert(f"Decryption failed: {exc}")
                break
            print(f"[SERVER] Received: {plaintext.decode(errors='replace')!r}")
            reply = f"echo:{plaintext.decode(errors='replace')}".encode()
            seq, ct = send_enc.encrypt(CT_APP_DATA, reply)
            send_frame(self.conn, encode_app_data(seq, ct))

    def _alert(self, msg: str) -> None:
        try:
            send_frame(self.conn, encode_alert(ALERT_FATAL, msg))
        except Exception:
            pass
        print(f"[SERVER] Alert: {msg}")



def main() -> None:
    bootstrap_pki()
    server_key = load_private_key(SERVER_CERT_KEY_PATH)
    server_cert = load_certificate(SERVER_CERT_PATH)
    ca_cert = load_certificate(CA_CERT_PATH)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(10)
    print(f"[SERVER] VAULTTLS listening on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(
                target=ServerSession(conn, addr, server_key, server_cert, ca_cert).run,
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutdown")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
