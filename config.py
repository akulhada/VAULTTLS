"""
config.py
=========
Single source of truth for all protocol constants and file paths.
"""
import os

# ── Network ───────────────────────────────────────────────────────────────────
HOST           = "127.0.0.1"
PORT           = 9443
SOCKET_TIMEOUT = 30

# ── Protocol identity ─────────────────────────────────────────────────────────
PROTOCOL_VERSION = 1
CONTEXT_STRING   = b"CSE539-TLS-OPAQUE13-v1"
SERVER_ID        = b"localhost"

# ── File paths ────────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
DB_DIR    = os.path.join(BASE_DIR, "db")

# These names are used by pki.py and server.py
CA_CERT_PATH         = os.path.join(CERTS_DIR, "ca_cert.pem")
SRV_CERT_PATH        = os.path.join(CERTS_DIR, "server_cert.pem")
SRV_KEY_PATH         = os.path.join(CERTS_DIR, "server_cert_key.pem")

# Aliases for pki.py compatibility
SERVER_CERT_PATH     = SRV_CERT_PATH
SERVER_CERT_KEY_PATH = SRV_KEY_PATH

USERS_DB_PATH     = os.path.join(DB_DIR, "users.json")
SERVER_STATE_PATH = os.path.join(DB_DIR, "server_state.json")

# ── Crypto sizes ──────────────────────────────────────────────────────────────
NONCE_LEN = 32
KEY_LEN   = 32
IV_LEN    = 12
TAG_LEN   = 16
HASH_LEN  = 64

# ── Certificate validity ──────────────────────────────────────────────────────
CA_VALIDITY_DAYS     = 3650
SERVER_VALIDITY_DAYS = 365

# ── Rate limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_WINDOW_S  = 60
RATE_LIMIT_MAX_TRIES = 10
