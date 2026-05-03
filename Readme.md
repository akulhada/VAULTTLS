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

### 1. Create and Activate a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 3. Generate the Certificates

A. Generate Directly
```bash
python3 pki.py
```

B. Generate Automatically

```bash
python3 server.py
```

On startup, the server calls the PKI bootstrap path and creates the same files if they are missing.

### 3. Generate the DB Files

A. Create Empty DB Files

If you want both `db/users.json` and `db/server_state.json` to exist right away, run:
```bash
python3 -c "from storage import users_db, server_state_db; users_db(),server_state_db(); print('db initialized')"
```

B. Generate the DB using Protocol

Keep the serve running in one terminal:
```bash
python3 server.py
```

Then in another terminal:
```bash
python3 register_user.py --user alice --password s3cr3t
```

This creates:
```
db/users.json
db/server_state.json
```

### 4. Run the Regression Suite

Before generating artifact outputs, it is a good idea to confirm the repo is healthy"
```bash
pytest -q
```

### 5. Generate the `results/` Files
#### Important Rule
For the benchmark, fake-user timing, and baseline scripts, do not keep python server.py running manually unless the script documentation explicitly says to. These tools start their own background server subprocess.

#### 1. Benchmark results

Generate the benchmark JSON:
```bash
python3 tools/benchmark_artifact.py \
  --iterations 8 \
  --app-rounds 16 \
  --message-size 1024 \
  --output results/benchmark_sample.json \
  --server-log results/benchmark_server.log
```

This matches the benchmark sample configuration already saved in the artifact: 8 iterations, 16 app rounds, 1024-byte messages. The current sample reports about 449.68 ms registration latency, 436.81 ms login latency, 2.23 ms app round-trip, and 1.02 MiB/s throughput.

Creates:
```
results/benchmark_sample.json
results/benchmark_server.log
```

#### 2. Fake-user timing results

Generate the timing-study JSON:
```bash
python tools/measure_fake_user_timing.py \
  --trials 12 \
  --output results/fake_user_timing_sample.json \
  --server-log results/fake_user_timing_server.log
```

The current saved sample uses 12 trials per class and reports a 2.03 ms mean timing gap.

Creates:
```
results/fake_user_timing_sample.json
results/fake_user_timing_server.log
```

#### 3. Codec fuzzing results

Generate the fuzz report:
```bash
python tools/fuzz_codec.py \
  --iterations 1000 \
  --seed 539 \
  --output results/fuzz_codec_sample.json
```

The sample fuzzing campaign uses 1000 iterations per decoder with seed 539 and reports no unexpected exceptions.

Creates:
```
results/fuzz_codec_sample.json
```

#### 4. Baseline comparison results

Generate the baseline comparison with:
```bash
python tools/compare_baselines.py \
  --iterations 6 \
  --output results/baseline_comparison.json \
  --server-log results/baseline_server.log
```

The saved baseline comparison reports:
- password-over-TLS mean: 234.12 ms
- certificate-only mutual-auth mean: 0.74 ms
- VAULTTLS mean: 350.15 ms
- overhead vs password-over-TLS: 116.03 ms (49.6%)

Creates:
```
results/baseline_comparison.json
```

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
### Verification
The concrete trace checker reports **11/11 lemmas hold** with **0 violations**. The verification log also states explicitly that this is not a full formal proof; it shows that the implementation satisfies the stated lemmas on concrete runs.

### Performance
Main benchmark configuration: **8 iterations, 16 app rounds, 1024-byte messages**. In this run, VAULTTLS reports:
- **Registration latency**: 253.68 ms mean
- **Login latency**: 251.58 ms mean
- **Application round trip**: 0.168 ms mean
- **Throughput**: 6.10 MiB/s mean

### Fake-user Timing Study
The fake-user vs wrong-password study uses **12 trials per class**. The results are:
- **Wrong-password Mean Failure Time**: 251.98 ms
- **Unknown-user Mean failure time**: 252.85 ms
- **Mean timing gap**: 0.878 ms
- 
The `ServerHello` length distributions overlap on both paths, with observed lengths of **1431, 1432, and 1433 bytes** for both wrong-password and unknown-user cases. This is encouraging for reduced user-enumeration leakage, though it is not a proof of indistinguishability.

### Codec Fuzzing
The codec fuzzing campaign uses **1000 iterations per decoder** with **seed 539**. No unexpected exceptions were observed.

Per-decoder outcomes in the current sample are:
- `decode_client_hello`: 275 accepted, 492 `AssertionError`, 233 `ValueError`
- `decode_server_hello`: 233 accepted, 527 `AssertionError`, 240 `ValueError`
- `decode_client_finish`: 232 accepted, 537 `AssertionError`, 231 `ValueError`
- `decode_app_data`: 258 accepted, 496 `AssertionError`, 246 `ValueError`
- `decode_alert`: 229 accepted, 531 `AssertionError`, 240 `ValueError`

### Additional Benchmark File
The current file named `baseline_comparison.json` is actually another **VAULTTLS benchmark snapshot**, not a protocol-comparison table. For **6 iterations, 32 app rounds, and 1024-byte messages**, it reports:
- **Registration latency**: 269.21 ms mean
- **Login latency**: 259.27 ms mean
- **Application round trip**: 0.135 ms mean
- **Throughput**: 7.33 MiB/s mean

These results are intended as artifact-level evidence, not a production benchmark suite.

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