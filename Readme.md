# VAULTTLS

VAULTTLS is a research-oriented applied cryptography project that implements a **TLS 1.3-shaped secure channel** with:

- **certificate-authenticated server login**
- **password-authenticated client login** using an **OPAQUE-style augmented PAKE**
- **HKDF-based traffic-secret derivation**
- **AEAD-protected application records**

The project was built for an Applied Cryptography course and follows the class requirement of combining key exchange, digital signatures, certificates, password-based authentication, key derivation, and authenticated encryption in one modular localhost client/server protocol.

> **Status:** Educational and Research-oriented artifact  
> **Not claimed:** Standards-complete TLS, production OPAQUE, or a fully machine-checked proof artifact

---

## What this Project does

VAULTTLS replaces the usual TLS-style client-authentication gap with a password-authenticated handshake. The server is authenticated by certificate and transcript-bound signatures, while the client proves password knowledge inside the handshake through an OPAQUE-style flow. After handshake completion, application data is protected with per-direction AEAD traffic keys derived using a TLS 1.3-shaped HKDF schedule.

Key security-oriented features include:

- pinned-CA certificate validation
- transcript-bound `CertificateVerify`
- authenticated registration
- signed and validated `ServerConfig`
- replay and reordering rejection in the record layer
- fake-record handling for reduced user-enumeration leakage
- rate limiting for repeated online password attempts

---

## Repository Map

### Runtime protocol code
- `client.py` — client login and protected messaging
- `server.py` — registration, login, encrypted echo service
- `register_user.py` — authenticated registration client
- `opaque_adapter.py` — educational OPAQUE-style OPRF, envelope, and 3DH logic
- `pki.py` — PKI bootstrap, pinned-CA validation, transcript signatures
- `tls13_kdf.py` — TLS 1.3-shaped key schedule
- `record.py` — AEAD record protection
- `codec.py` — deterministic binary wire encoding
- `server_config.py` — signed capability/config blob
- `storage.py` — JSON persistence
- `ratelimit.py` — online guessing throttling
- `transcript.py` — framing and transcript helpers

### Tests and tooling
- `tests/` — unit, integration, and invariant tests
- `tools/benchmark_artifact.py` — microbenchmarks
- `tools/compare_baselines.py` — baseline comparison
- `tools/measure_fake_user_timing.py` — enumeration-leakage timing study
- `tools/fuzz_codec.py` — parser robustness campaign

### Documentation and models
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/threat_model.md`](docs/threat_model.md)
- [`docs/security_properties.md`](docs/security_properties.md)
- [`docs/standards_alignment.md`](docs/standards_alignment.md)
- [`docs/related_work.md`](docs/related_work.md)
- [`formal/README-Formal.md`](formal/README-Formal.md)
- `formal/vaulttls_tamarin.spthy`
- `formal/vaulttls_proverif.pv`
- `formal/vaulttls_symbolic_model.md`
- `report.md`

--- 

## Quick start

### 1. Install dependencies

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 2. 


---

## Protocol Overview
### Registartion
The client authenticates the server before uploading the final password-derived registration record. Registration validates the pinned CA, the server certificate, the signed `ServerConfig`, and a transcript-bound `CertificateVerify`.

### Login / Handshake
The client sends an OPAQUE-style first flight plus an identifier and nonce. The server replies with a certificate chain, signed `ServerConfig`, transcript-bound signature, and OPAQUE-style second flight. The client verifies the server, returns `KE3`, and both sides derive traffic secrets only after handshake completion succeeds.

### Secure Channel
Application messages are protected with ChaCha20-Poly1305 using per-direction keys derived from the OPAQUE session key and the final transcript. Record nonces follow the TLS 1.3-style IV XOR sequence_number pattern.

---

## Security Properties - At a glance
VAULTTLS is designed to support:
- Server Authentication
- Client Authentication by Password Knowledge
- Application-Data secrecy and integrity
- Transcript binding
- Forward secrecy for complete session
- Replay and Simple reordering resistance
- Reduced User-enumeration leakage
- Online password-guess throttling
- Authenticated Registration

Reference:
- [`docs/threat_model.md`](docs/threat_model.md)
- [`docs/security_properties.md`](docs/security_properties.md)

---

## Result Snapshot
Current artifact snapshots report:
- **Resgistration Latency:** ~449.68 ms mean
- **Login Lateency:** ~436.81 ms mean
- **Application Round Trip:** ~2.23 ms mean
- **Throughput:** ~1.02 MiB/s mean
- **Overhead vs Password -Over TLS Baseline:** ~116.03 ms (~49.6%)
- **Fake user vs Wrong Password Mean Timing Gap:** ~2.03 ms
- **Codec Fizzing:** No unexpected exception in the sample campaign

---

## Limitations
VAULTTLS is intentionally RFC-shape, not RFC-complete.

Notable Limits:
- The OPAQUE logic is educational and self-contained, not a vetted RFC 9807 implementation
- Certificate validation is intentionally narrower tahn full PXIX processing
- The TLS-like layer omit many RFC 8446 features such as negotiation, resumption, `KeyUpdate`, and full alert handling
- The formal files are strong analysis artifacts, but external solver should be attached before claiming machine-checked proofs

Reference:
- [`docs/standards_alignment.md`](docs/standards_alignment.md)
- [`docs/related_work.md`](docs/related_work.md)
- [`formal/README-Formal.md`](formal/README-Formal.md)

## Standards coverage

VAULTTLS implements the **security-relevant core** of an OPAQUE-style augmented PAKE and a **TLS 1.3-shaped** secure channel:

- OPAQUE-style registration, OPRF-based password hardening, envelope storage, and 3DH-style password-authenticated login
- TLS 1.3-shaped transcript binding, `HKDF-Expand-Label`,`Derive-Secret`, per-direction traffic secrets, and AEAD record protection
- pinned-CA certificate validation with SAN/service-name checks in a narrow two-certificate PKI model

It is intentionally **not** a wire-compatible implementation of RFC 9807 or RFC 8446. The repository omits negotiation, resumption, full PKIX validation, and broader interoperability machinery because they are outside the project’s closed localhost threat model.

For the full matrix of what is implemented, adapted, omitted, and the security impact of each omission, see [`docs/standards_alignment.md`](docs/standards_alignment.md).

