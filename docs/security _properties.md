# Security Properties and Argument Sketches

## Purpose

This document states the main security claims made by VAULTTLS, explains which code mechanisms support each claim, and identifies the most important residual limitations. It is not a formal proof. Its purpose is to make the security story concrete, testable, and auditable.

---

## Summary table

| Property | Intended claim | Main mechanisms | Residual gap |
|---|---|---|---|
| Server authentication | client accepts only the certified server for this session | pinned CA, service-name checks, signed `ServerConfig`, transcript-bound `CertificateVerify` | narrow PKI model |
| Client authentication by password | server accepts only a client who proves password knowledge | OPAQUE-style KE3 verification | educational OPAQUE implementation |
| Authenticated registration | client verifies the server before uploading final registration record | registration-side certificate/config/transcript checks | shared cert/OPAQUE role key |
| Session secrecy and integrity | post-handshake records are protected against network attackers | transcript-bound traffic secrets, AEAD, per-direction keys | simplified TLS record layer |
| Forward secrecy | later long-term key disclosure should not reveal past sessions | OPAQUE-style 3DH-derived session key, fresh transcript-bound derivation | depends on ephemeral hygiene |
| Replay/reordering resistance | replayed or out-of-order records are rejected | exact receive-sequence checks | only per live connection |
| Reduced user enumeration leakage | unknown users do not trigger an obvious special-case path | fake-record response path, timing study | not a proof of indistinguishability |
| Online guessing resistance | repeated guesses are throttled | rate limiter | local in-memory scope only |

---

## 1. Server authentication

### Claim
A client that completes login has verified that the peer is the intended server and that the certified private key was actively used in this specific session.

### Mechanisms
The server-authentication story relies on several layers:

1. **pinned trust anchor**  
   The client validates the server certificate chain against a locally pinned CA.

2. **service identity checks**  
   The expected service name is checked.

3. **signed `ServerConfig`**  
   The server’s capability/configuration blob is signed and validated.

4. **transcript-bound `CertificateVerify`**  
   The server signs the live handshake context, binding its certified key to the current session.

### Why these layers matter
A certificate alone is not enough if it is not clearly tied to the current handshake. A live transcript signature prevents the client from trusting only static material. A signed `ServerConfig` also prevents capability or role misbinding.

### Residual gap
Certificate validation is intentionally much narrower than a full PKIX validator.

---

## 2. Client authentication by password

### Claim
The server accepts a client only after the client proves knowledge of the registered password through the OPAQUE-style final handshake step.

### Mechanisms
- the client computes a final OPAQUE-style message based on password-derived state and the server’s second flight
- the server verifies that final message before deriving or accepting application traffic secrets
- the internal OPAQUE logic includes transcript-tied MAC verification

### Why this matters
This is stronger than “establish a secure channel first, then send a password inside it.” The password proof becomes part of session establishment itself.

### Residual gap
The OPAQUE layer is implemented as a readable educational module rather than as a mature externally audited RFC 9807 implementation.

---

## 3. Authenticated registration

### Claim
The client authenticates the server before sending the final registration record.

### Mechanisms
Registration validates:
- the pinned CA
- the service identity
- the signed `ServerConfig`
- the transcript-bound `CertificateVerify`

The client only uploads the final password-derived registration state after these checks succeed.

### Why this matters
Registration is security-critical because it creates the long-term password-derived state. If registration is unauthenticated, a malicious endpoint could capture or redirect account setup.

### Residual gap
The current implementation reuses the same P-256 key role more than an ideal production design would. A stronger design would separate the certificate key from the OPAQUE static key and bind them explicitly.

---

## 4. Session secrecy and integrity

### Claim
After a successful handshake, application messages are confidential and integrity-protected against active network attackers.

### Mechanisms
- a shared session secret emerges from the password-authenticated handshake
- traffic secrets are derived from that secret and the final transcript
- the record layer derives per-direction keys and IVs
- ChaCha20-Poly1305 authenticates each protected record

### Why transcript binding matters
A transcript-bound key schedule ensures that the secure channel depends not only on shared secret material but also on the exact handshake that produced it.

### Residual gap
The record layer intentionally omits many production TLS features such as padding, full alert taxonomy, and rekeying.

---

## 5. Forward secrecy for completed sessions

### Claim
Past application traffic should remain protected even if certain long-term keys are later disclosed, assuming the active session was not compromised and ephemeral material was not retained.

### Mechanisms
- each successful login derives a fresh session secret
- traffic secrets are derived per session
- application protection is keyed from session-specific values

### Caveat
This is a design-level and implementation-intended property in the usual educational sense. It depends on reasonable handling of ephemeral material and should not be overstated as a production-grade verified guarantee.

---

## 6. Resistance to offline guessing after DB compromise

### Claim
A snapshot of the server’s password database should not trivially reveal plaintext passwords or collapse to a naive lookup table.

### Mechanisms
- password material is stored in an OPAQUE-style record rather than as a direct plaintext-equivalent verifier
- password hardening uses Argon2id in the envelope path
- the server does not need to directly observe the password at login time

### Why this matters
This property is one of the main reasons to prefer an augmented PAKE over simpler password-over-TLS designs.

### Residual gap
The exact strength depends on password quality, Argon2id parameters, and the fact that the implementation is educational rather than production-reviewed.

---

## 7. Replay and reordering resistance

### Claim
Within an active connection, replayed and out-of-order application records are rejected.

### Mechanisms
- the receiver expects the next exact sequence number
- the AEAD nonce depends on that sequence number
- the receiver increments state only after successful verification

### Why this matters
Even on TCP, applications should not assume that replay protection is “handled for free” at a higher level. Enforcing it at the record layer makes the secure-channel behavior explicit.

### Residual gap
This is connection-local replay defense, not a global anti-replay mechanism across transports or resumptions.

---

## 8. Reduced user-enumeration leakage

### Claim
Unknown-user login attempts do not immediately reveal themselves through a special-case server response path.

### Mechanisms
- the server uses a fake-record path for unknown users
- the client still receives and processes a normal-looking handshake response
- the repository includes a timing-study script to measure remaining differences

### Why the repository includes measurement
“Reduced leakage” is not the same as “perfect indistinguishability.” The timing and message-shape study exists because this claim needs empirical support.

### Residual gap
This artifact reports a small mean timing gap in the current study, but that is still not a proof of indistinguishability in all environments.

---

## 9. Online guessing resistance

### Claim
The server makes repeated online password guessing more expensive.

### Mechanisms
- an in-memory rate limiter tracks repeated attempts
- the server applies throttling based on client/network identity and credential context

### Residual gap
The limiter is local to one process and does not provide distributed or cross-instance protection.

---

## What this document does not claim

This document does **not** claim:
- complete formal verification
- standards-complete TLS behavior
- full RFC 9807 wire compatibility
- full PKIX validation
- strong side-channel protection on hostile hosts

Its purpose is narrower: make the intended security properties explicit, show what in the code supports them, and identify the remaining gaps honestly.

For the exact RFC coverage, deliberate omissions, and their security impact, see [`docs/standards_alignment.md`](docs/standards_alignment.md).
