# VAULTTLS Project Evolution Summary

This document summarizes the progression from the original class-project implementation to the final polished VAULTTLS artifact. It is written in a version-control style so the project history is easy to explain: what changed, why it changed, which files were affected, what was added or removed, and what
strengths and limitations remain.

## Final Artifact

- Final polished archive: `vaulttls_final_polished.zip`
- Final project folder used for polishing: `compare_final/vaulttls/`
- Final positioning: strong research-oriented class artifact, not a production
  TLS stack and not a fully RFC 9807-compliant OPAQUE implementation.

## High-Level Progression

The project moved through six broad stages:

1. Baseline educational VAULTTLS implementation
2. Hardened protocol implementation
3. Combined secure-and-tested implementation
4. Research-oriented artifact packaging
5. Research-grade evidence upgrade
6. Final polish and consistency cleanup

Each stage improved a different dimension of the work: implementation security,
test coverage, documentation quality, empirical evaluation, formal modeling, and
artifact cleanliness.

## Stage 1: Baseline Class Project

### Starting Point

The original project implemented a localhost client/server secure channel with:

- certificate-based server authentication,
- password-based client authentication using an OPAQUE-style PAKE,
- TLS 1.3-shaped HKDF key derivation,
- ChaCha20-Poly1305 application-data encryption,
- socket framing and binary message encoding.

### Core Files Present

- `client.py`
- `server.py`
- `register_user.py`
- `opaque_adapter.py`
- `pki.py`
- `record.py`
- `tls13_kdf.py`
- `codec.py`
- `server_config.py`
- `storage.py`
- `ratelimit.py`
- `transcript.py`

### Strengths

- Clear modular structure.
- Good fit for the class brief.
- Demonstrated the major required cryptographic components.
- Used real cryptographic primitives through Python libraries.

### Weaknesses

- Registration was not treated as a first-class authenticated phase.
- Certificate trust was too close to "trust what the peer sends."
- Record replay/reordering resistance was incomplete.
- Test coverage was uneven.
- Research framing, threat model, and standards alignment were limited.

## Stage 2: Hardened Protocol Version

### Main Goal

Improve the actual security behavior of the protocol before focusing on paper
quality or research presentation.

### Major Changes

#### `pki.py`

Added pinned-CA verification. The client now validates the server certificate
chain against a locally trusted CA certificate instead of trusting a CA supplied
by the peer.

Security impact:

- Prevents an attacker from presenting a rogue CA and rogue server certificate.
- Makes the certificate trust model much closer to real TLS root-store behavior.

#### `register_user.py`

Authenticated registration was added. The registration client now verifies:

- certificate chain,
- signed `ServerConfig`,
- transcript-bound `CertificateVerify`,
- OPAQUE static key binding to the certified server public key.

Security impact:

- Prevents unauthenticated registration with a malicious endpoint.
- Makes registration part of the security story, not just setup.

#### `server.py`

Registration and login flows were cleaned up around signed `ServerHello`
construction.

Security impact:

- Registration and login use consistent server authentication logic.
- `CertificateVerify` is transcript-bound.

#### `server_config.py`

Added semantic validation of the signed server configuration:

- version,
- key-exchange suite,
- AEAD suite,
- hash suite,
- server identity,
- timestamp freshness.

Security impact:

- Reduces downgrade or parameter-substitution risk inside the educational
  protocol model.

#### `record.py`

Added exact receive-sequence enforcement.

Security impact:

- Replayed records are rejected.
- Out-of-order records are rejected.
- Replay resistance becomes part of the record layer instead of an external
  caller assumption.

### Added Tests

- `tests/test_pinned_ca.py`
- `tests/test_record_replay.py`

### Pros

- Much stronger security posture.
- Better alignment with TLS-style trust and transcript binding.
- Registration became a real security phase.

### Cons

- Still educational, not standards-complete.
- Still lacked broad test coverage from the alternate project version.

## Stage 3: Combined Secure-And-Tested Version

### Main Goal

Merge the hardened implementation with the broader test suite from the alternate
project archive.

### What Was Kept

The hardened implementation remained the base:

- hardened `pki.py`,
- hardened `register_user.py`,
- hardened `server.py`,
- hardened `record.py`,
- hardened `server_config.py`.

### What Was Added

Broader tests from the alternate archive were added:

- `tests/test_codec.py`
- `tests/test_kdf.py`
- `tests/test_opaque_primitives.py`
- `tests/test_pki.py`
- `tests/test_protocol_invariants.py`
- `tests/test_record.py`
- `tests/test_storage_ratelimit.py`
- `tests/test_suite.py`

### What Was Removed Or Avoided

Generated cache artifacts were excluded from the clean package:

- `__pycache__/`
- `.pytest_cache/`
- `.pyc` files
- `.DS_Store` files

### Pros

- Combined stronger security with stronger testing.
- Added unit, integration, protocol-invariant, storage, rate-limit, PKI, codec,
  KDF, OPAQUE, and record-layer coverage.

### Cons

- Some legacy tests initially assumed older, weaker behavior.
- Test expectations had to be aligned with pinned-CA trust and replay rejection.

## Stage 4: Research-Oriented Artifact

### Main Goal

Move from "good class project" toward "research-style artifact" by adding
threat modeling, standards comparison, evaluation, and reproducibility support.

### Added Documentation

#### `report.md`

Rewritten into a research-style report with:

- abstract,
- contribution and scope,
- threat model,
- protocol design,
- standards alignment,
- security claims,
- empirical evaluation,
- limitations,
- reproducibility notes.

#### `docs/threat_model.md`

Added:

- system model,
- adversary capabilities,
- trust assumptions,
- claimed security goals,
- explicit non-goals.

#### `docs/security_properties.md`

Added security-property argument sketches for:

- server authentication,
- client authentication,
- application secrecy and integrity,
- forward secrecy,
- replay resistance,
- authenticated registration,
- user-enumeration resistance.

#### `docs/standards_alignment.md`

Added a matrix comparing the implementation against:

- RFC 9807 OPAQUE concepts,
- RFC 8446 TLS 1.3 concepts,
- RFC 5280 / RFC 9525 certificate-processing expectations.

#### `docs/related_work.md`

Added positioning against:

- OPAQUE,
- TLS 1.3,
- TLS-OPAQUE literature,
- symbolic verification practice.

### Added Evaluation Tools

#### `tools/benchmark_artifact.py`

Measures:

- registration latency,
- login latency,
- encrypted application round-trip latency,
- approximate throughput.

#### `tools/measure_fake_user_timing.py`

Measures distinguishability between:

- wrong-password login for an existing user,
- unknown-user login on the fake-user path.

#### `tools/fuzz_codec.py`

Adds malformed-input fuzzing for binary codec robustness.

### Added Artifact Engineering

- `Makefile`
- `requirements-dev.txt`
- `.github/workflows/ci.yml`
- `results/` sample outputs

### Pros

- Much stronger research framing.
- Limitations became explicit instead of implicit.
- Added empirical evidence instead of only functional tests.

### Cons

- Formal verification was initially only a roadmap/sketch.
- Fake-user timing study revealed a real distinguishability problem.

## Stage 5: Research-Grade Evidence Upgrade

### Main Goal

Address the strongest remaining research gaps: formal artifacts, baseline comparison, and fake-user timing leakage.

### Fake-User Timing Oracle Fix

#### File Changed

- `opaque_adapter.py`

#### Problem

The fake-user path originally used a random fake envelope. Real envelopes start with a version byte and contain a salt/nonce/ciphertext structure. A random fake envelope usually failed immediately on the version check, before Argon2id ran.

This made unknown-user failures much faster than wrong-password failures.

Before fix:

- wrong-password mean failure time: about 276.7 ms
- unknown-user mean failure time: about 179.5 ms
- timing gap: about 97.2 ms

#### Fix

The fake envelope was changed to have a valid structure:

- version byte `0x01`,
- 16-byte random salt,
- 12-byte random nonce,
- random ciphertext body plus GCM tag length.

This forces `_envelope_open` to run the same expensive KSF path before failing
authentication.

After fix:

- wrong-password mean failure time: about 412.7 ms
- unknown-user mean failure time: about 410.7 ms
- timing gap: about 2.03 ms

### Added Formal Artifacts

#### `formal/trace_checker.py`

Mechanized concrete-trace checker that verifies 11 lemmas over protocol traces:

- session-key secrecy,
- client-to-server agreement,
- server-to-client agreement,
- registration authenticity,
- forward secrecy,
- replay resistance,
- fake-user path existence,
- wrong-password rejection,
- password-not-on-wire,
- transcript binding.

#### `formal/vaulttls_tamarin.spthy`

Tamarin model with:

- 12 rules,
- 5 lemmas,
- compromise rules for long-term server key and password exposure.

#### `formal/vaulttls_proverif.pv`

ProVerif model with:

- 18 function declarations,
- 4 core queries,
- secrecy and injective correspondence properties.

#### `formal/VERIFICATION_LOG.txt`

Evidence log containing:

- trace-checker output,
- `tests/test_suite.py` output,
- Tamarin/ProVerif model metrics,
- explicit note that Tamarin/ProVerif were not executed in the environment.

### Added Baseline Comparison

#### `tools/compare_baselines.py`

Compares VAULTTLS against:

- Password-over-TLS,
- certificate-only mutual authentication,
- VAULTTLS OPAQUE-in-handshake design.

Comparison axes:

- mean latency,
- whether the server sees the password,
- database compromise risk,
- whether the client needs a certificate,
- approximate ECDH operation count.

### Pros

- Stronger evidence bundle.
- Fake-user timing bug was found, explained, and fixed.
- Formal story became concrete rather than only prose.
- Baseline comparison made the performance/security tradeoff clearer.

### Cons

- Tamarin and ProVerif models are tool-ready but not executed in the local
  environment.
- Formal proof remains symbolic, not computational.
- Baseline experiments are artifact-local, not broad cross-platform studies.

## Stage 6: Final Polish

### Main Goal

Clean the final package so it is internally consistent and easier to submit or review.

### Files Changed

#### `report.md`

Final changes:

- corrected test-count inconsistency from `191 tests passed` to
  `85 tests passed, 1 skipped`;
- clarified that the count refers to `tests/test_suite.py` as captured in
  `formal/VERIFICATION_LOG.txt`;
- removed duplicate next-step wording;
- kept the four actual limitations concise and accurate.

#### `README.md`

Final changes:

- updated formal artifact descriptions;
- added trace checker, Tamarin model, ProVerif model, and verification log to the artifact map;
- clarified that trace checker is mechanized and passes, while Tamarin/ProVerif still require external prover runs.

#### `db/users.json`

Final change:

- cleared runtime user state to `{}`.

Reason:

- avoid shipping benchmark/test-generated user records as part of the final source artifact.

### Clean Packaging

The final polished zip excludes:

- `__pycache__/`
- `.pyc`
- `.DS_Store`

## Final File-Level Change Summary

### Major Runtime Files Improved

- `opaque_adapter.py`
  - OPAQUE-style PAKE implementation.
  - Fake-user timing path fixed by constructing valid fake envelope structure.

- `pki.py`
  - Pinned CA trust model.
  - Stronger certificate-chain validation.
  - ServerConfig and CertificateVerify verification helpers.

- `register_user.py`
  - Authenticated registration flow.
  - Server certificate, ServerConfig, CertificateVerify, and OPAQUE static-key binding checks.

- `server.py`
  - Cleaner registration/login split.
  - Shared signed ServerHello construction.
  - Consistent transcript-bound server authentication.

- `server_config.py`
  - Semantic validation of signed server capabilities.

- `record.py`
  - Replay and reordering rejection through exact receive-sequence enforcement.

### Major Test Files Added Or Integrated

- `tests/test_suite.py`
- `tests/test_codec.py`
- `tests/test_kdf.py`
- `tests/test_opaque_primitives.py`
- `tests/test_pki.py`
- `tests/test_protocol_invariants.py`
- `tests/test_record.py`
- `tests/test_record_replay.py`
- `tests/test_pinned_ca.py`
- `tests/test_storage_ratelimit.py`
- `tests/test_success.py`
- `tests/test_wrong_password.py`
- `tests/test_fake_user_path.py`
- `tests/test_bad_cert_sig.py`
- `tests/test_tamper_ke2.py`

### Research And Documentation Files Added

- `report.md`
- `README.md`
- `RESEARCH_UPGRADE_NOTES.md`
- `docs/threat_model.md`
- `docs/security_properties.md`
- `docs/standards_alignment.md`
- `docs/related_work.md`

### Formal Evidence Files Added

- `formal/README.md`
- `formal/trace_checker.py`
- `formal/vaulttls_symbolic_model.md`
- `formal/vaulttls_tamarin.spthy`
- `formal/vaulttls_proverif.pv`
- `formal/VERIFICATION_LOG.txt`

### Evaluation Tools Added

- `tools/benchmark_artifact.py`
- `tools/measure_fake_user_timing.py`
- `tools/fuzz_codec.py`
- `tools/compare_baselines.py`

### Results Added

- `results/benchmark_sample.json`
- `results/benchmark_sample.md`
- `results/fake_user_timing_sample.json`
- `results/fake_user_timing_sample.md`
- `results/fuzz_codec_sample.json`
- `results/fuzz_codec_sample.md`
- `results/baseline_comparison.json`

### Artifact Engineering Added

- `Makefile`
- `requirements.txt`
- `requirements-dev.txt`
- `.github/workflows/ci.yml`

### Removed Or Cleaned

- removed cache files from final zip:
  - `__pycache__/`
  - `.pyc`
  - `.DS_Store`
- cleared runtime-generated user records:
  - `db/users.json` now contains `{}`
- avoided shipping stale benchmark/server logs in the polished final package.

## Pros Of The Final Project

1. Stronger than a typical class project.

The final artifact has implementation, documentation, tests, formal models, evaluation scripts, and reproducibility notes.

2. Honest research framing.

The report does not claim to be RFC 9807 or TLS 1.3 compliant. It clearly says the protocol is RFC-shaped and educational.

3. Meaningful security improvements.

Pinned CA validation, authenticated registration, transcript binding, semantic server-config validation, and replay-resistant records are all real upgrades.

4. Stronger empirical evidence.

The project includes latency benchmarks, fake-user distinguishability testing, codec fuzzing, and baseline comparison.

5. Formal artifacts are concrete.

The project includes a trace checker, Tamarin model, ProVerif model, and verification evidence log.

6. Limitations are clear.

The final report explicitly states the four main remaining limitations:

- educational OPAQUE implementation,
- narrow certificate validation,
- Tamarin/ProVerif proof runs pending,
- no standards-interoperable TLS profile.

## Cons And Remaining Limitations

1. Educational OPAQUE implementation.

`opaque_adapter.py` remains a readable educational implementation rather than a vetted RFC 9807 library. This is acceptable for the class artifact, but not for production deployment.

2. Certificate validation is intentionally narrow.

The implementation uses a pinned local CA and a simple server-cert chain. It does not implement full PKIX path building, revocation, policy processing, or all RFC 5280/RFC 9525 behavior.

3. Tamarin and ProVerif are not executed in the local environment.

The models are included and tool-ready, but the final artifact still needs external prover output attached to claim full machine-checked proof evidence.

4. Not interoperable with real TLS.

The protocol borrows TLS 1.3 structure but does not implement a real TLS stack, wire compatibility, negotiation, resumption, KeyUpdate, or full alert handling.

5. Evaluation is artifact-local.

The benchmark and timing results are useful, but they are not a large-scale cross-platform performance study.


## Final Takeaway

The final VAULTTLS artifact is best described as:

> A strong research-oriented class artifact that implements and analyzes an OPAQUE-style password-authenticated TLS-shaped secure channel, with clear threat modeling, security hardening, formal artifacts, evaluation scripts, and honest limitations.

It should not be described as:

- a production TLS implementation,
- a fully RFC 9807-compliant OPAQUE implementation,
- a fully machine-checked formal proof,
- or a standards-interoperable protocol.

Its biggest achievement is that it moves beyond "the code works" into a much more mature artifact: the assumptions, evidence, tradeoffs, limitations, and next engineering steps are all visible.

