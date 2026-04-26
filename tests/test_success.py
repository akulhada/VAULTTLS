"""
tests/test_success.py
=====================
Happy-path integration test.

Phase 1: OPAQUE registration over loopback sockets
Phase 2: Full VaultTLS handshake + encrypted echo
"""
import os, sys, socket, threading, time, traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import CONTEXT_STRING, SERVER_ID, SERVER_CERT_KEY_PATH, SERVER_CERT_PATH, CA_CERT_PATH
from tls13_kdf import Transcript, derive_traffic_secrets, hash_bytes
from transcript import send_frame, recv_frame
from codec import (
    encode_client_hello, decode_client_hello,
    encode_server_hello_core, encode_server_hello, decode_server_hello,
    encode_client_finish, decode_client_finish,
    encode_app_data, decode_app_data,
    encode_close, TAG_CLOSE, TAG_ALERT, decode_alert,
)
from pki import (
    bootstrap_pki, load_private_key, load_certificate,
    encode_cert_chain, sign_server_config, sign_cert_verify,
)
from record import DirectionState, CT_APP_DATA
from opaque_adapter import ConcreteOpaqueClient, ConcreteOpaqueServer
from server_config import encode_server_config
from client import client_login

REG_VERSION = 2

def _cred_id(username: bytes) -> bytes:
    return hash_bytes(CONTEXT_STRING + username)


def _srv_reg(conn, server_key, ca_cert, server_cert):
    raw = recv_frame(conn)
    ch  = decode_client_hello(raw)
    opaque_srv = ConcreteOpaqueServer(server_key)
    reg_resp   = opaque_srv.registration_respond(ch.credential_id, ch.opaque_ke1)
    srv_cfg    = encode_server_config()
    core = encode_server_hello_core(1, os.urandom(32),
                                    encode_cert_chain(ca_cert, server_cert), srv_cfg, reg_resp)
    sh = encode_server_hello(core, sign_server_config(server_key, srv_cfg), b"\x00"*71)
    send_frame(conn, sh)
    cf = decode_client_finish(recv_frame(conn))
    opaque_srv.registration_store(ch.credential_id, cf.opaque_ke3)
    send_frame(conn, encode_close())


def _srv_login(conn, server_key, ca_cert, server_cert, result):
    raw = recv_frame(conn)
    ch  = decode_client_hello(raw)
    transcript = Transcript(); transcript.add("client_hello", raw)
    opaque_srv = ConcreteOpaqueServer(server_key)
    ke2, srv_state = opaque_srv.login_start(ch.credential_id, ch.opaque_ke1, CONTEXT_STRING)
    srv_cfg = encode_server_config()
    cert_chain = encode_cert_chain(ca_cert, server_cert)
    core = encode_server_hello_core(1, os.urandom(32), cert_chain, srv_cfg, ke2)
    cv_sig = sign_cert_verify(server_key, transcript.digest(), core)
    sh = encode_server_hello(core, sign_server_config(server_key, srv_cfg), cv_sig)
    transcript.add("server_hello", sh); send_frame(conn, sh)
    cf_raw = recv_frame(conn); cf = decode_client_finish(cf_raw)
    transcript.add("client_finish", cf_raw)
    sk, ek = opaque_srv.login_finish(srv_state, cf.opaque_ke3)
    secrets = derive_traffic_secrets(sk, transcript.digest())
    enc = DirectionState(secrets.server_app); dec = DirectionState(secrets.client_app)
    ad = decode_app_data(recv_frame(conn))
    pt = dec.decrypt(CT_APP_DATA, ad.seq, ad.ciphertext)
    seq, ct = enc.encrypt(CT_APP_DATA, f"echo:{pt.decode()}".encode())
    send_frame(conn, encode_app_data(seq, ct))
    try: recv_frame(conn)
    except ConnectionError: pass
    result["sk"] = sk; result["ek"] = ek


def _one_shot(host, port, fn, *args):
    errs = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port)); srv.listen(1)
    def _run():
        c, _ = srv.accept()
        try: fn(c, *args)
        except Exception: errs.append(traceback.format_exc())
        finally: c.close(); srv.close()
    t = threading.Thread(target=_run, daemon=True); t.start()
    return t, errs


def test_success():
    bootstrap_pki()
    sk = load_private_key(SERVER_CERT_KEY_PATH)
    sc = load_certificate(SERVER_CERT_PATH)
    ca = load_certificate(CA_CERT_PATH)
    H  = "127.0.0.1"

    # Phase 1: registration
    t, errs = _one_shot(H, 19500, _srv_reg, sk, ca, sc)
    time.sleep(0.05)
    client = ConcreteOpaqueClient()
    req, st = client.registration_start(b"s3cr3t", b"alice", SERVER_ID, CONTEXT_STRING)
    cid = _cred_id(b"alice")
    sock = socket.socket(); sock.connect((H, 19500))
    send_frame(sock, encode_client_hello(REG_VERSION, cid, os.urandom(32), req))
    sh = recv_frame(sock)
    assert sh[0] != TAG_ALERT, decode_alert(sh).message
    rec = client.registration_finish(st, decode_server_hello(sh).opaque_ke2)
    send_frame(sock, encode_client_finish(opaque_ke3=rec))
    ack = recv_frame(sock); assert ack[0] == TAG_CLOSE
    sock.close(); t.join(timeout=3)
    assert not errs, errs
    print("  Phase 1 (registration): PASS ✓")

    # Phase 2: login
    result = {}
    t2, errs2 = _one_shot(H, 19501, _srv_login, sk, ca, sc, result)
    time.sleep(0.05)
    cli = socket.socket(); cli.connect((H, 19501))
    secrets, ek = client_login(cli, "alice", "s3cr3t", ConcreteOpaqueClient())
    enc = DirectionState(secrets.client_app); dec = DirectionState(secrets.server_app)
    seq, ct = enc.encrypt(CT_APP_DATA, b"ping")
    send_frame(cli, encode_app_data(seq, ct))
    resp = recv_frame(cli); ad = decode_app_data(resp)
    pt = dec.decrypt(CT_APP_DATA, ad.seq, ad.ciphertext)
    assert pt == b"echo:ping", f"unexpected reply {pt}"
    send_frame(cli, encode_close()); cli.close()
    t2.join(timeout=5); assert not errs2, errs2
    assert result["sk"] is not None
    print(f"  Phase 2 (login+appdata): PASS ✓  sk[:8]={result['sk'][:8].hex()}")
    print("test_success: PASS ✓")


if __name__ == "__main__":
    test_success()
