# Threat Model, Assumptions, Goals, and Non-Goals

## Purpose

This document defines what VAULTTLS is trying to protect, what the attacker is allowed to do, which assumptions are load-bearing, and where the implementation intentionally stops short of a production protocol.

A clear threat model matters because this repository is a **research-oriented artifact**, not only a demo implementation. Security claims are meaningful only if the adversary model is explicit.

---

## System model

The protocol has three parties:

- a **client** that knows a username and password
- a **server** that stores OPAQUE-style password records and holds a certified private key
- an emulated **CA** whose certificate is pinned out of band by the client

The transport is a reliable, in-order TCP connection over localhost. This matches the class-project setting and intentionally avoids unrelated distributed-systems complexity.

---

## Assets to protect

VAULTTLS is primarily concerned with protecting:

1. **application-data confidentiality**
2. **application-data integrity**
3. **server authenticity**
4. **client authenticity by password knowledge**
5. **password-derived database material**
6. **registration integrity**
7. **session-key secrecy**
8. **record-layer ordering assumptions inside a live connection**

The design does **not** claim full user-identity privacy on the wire.

---

## Adversary capabilities

The modeled attacker can:

1. passively observe all network traffic
2. actively tamper with, inject, delay, drop, replay, and reorder traffic
3. stand in the middle between client and server
4. submit repeated online password guesses
5. obtain a snapshot of the server’s stored database after some sessions have completed
6. attempt registration against a malicious endpoint
7. send malformed or truncated wire messages to exercise parser behavior
8. compare failure behavior between valid-user/wrong-password and unknown-user attempts

This is a strong active network-attacker model with additional password and parser-focused capabilities.

---

## Trust assumptions

The following assumptions are considered load-bearing:

### A1. Pinned CA distribution
The client receives the correct CA certificate securely out of band.

### A2. Primitive correctness
The cryptographic primitives provided through the Python cryptographic stack behave as intended.

### A3. Endpoint sanity during a live session
The attacker does not fully compromise both endpoints during the session whose secrecy is being claimed.

### A4. Ephemeral secret hygiene
Ephemeral session material is not retained forever after a session completes.

### A5. Localhost scope
The project runs in a local test environment and does not attempt to model complex deployment issues such as routing, distributed trust stores, or large-scale multi-tenant server farms.

---

## Security goals

## G1. Server authentication
The client should complete the handshake only if it is communicating with the party holding the private key corresponding to the pinned-CA-certified server certificate and that party signs the live transcript.

## G2. Client authentication by password
The server should complete the handshake only if the client demonstrates knowledge of the registered password through the final OPAQUE-style handshake step.

## G3. Application-data secrecy and integrity
After a successful handshake, application messages should be confidential and integrity-protected against active network attackers.

## G4. Forward secrecy for completed sessions
Disclosure of long-term keys after a session completes should not reveal past application traffic, assuming session-ephemeral material was not retained and the live session was not compromised.

## G5. Resistance to offline guessing after DB compromise
A stolen password database should not trivially reveal plaintext passwords or collapse into a simple precomputed lookup.

## G6. Replay and simple reordering resistance
The record layer should reject replayed and out-of-order records within an active connection.

## G7. Reduced user-enumeration leakage
Unknown-user login attempts should follow a normal-looking path intended to reduce observable differences relative to wrong-password failures.

## G8. Authenticated registration
The client should verify the server before uploading the final password-derived registration record.

---

## Explicit non-goals

The current artifact does **not** claim:

- full RFC 8446 interoperability
- full RFC 5280 path building, revocation, or policy processing
- full username privacy on the wire
- side-channel resistance against host-level cache, memory, power, or advanced timing attacks
- post-compromise security after an endpoint is fully compromised during a live session
- completed computational proofs
- production readiness

These non-goals are intentional and documented so that the artifact is judged on the properties it actually targets.

---

## Threats addressed by design

### Active MITM during login
Addressed by:
- pinned-CA certificate validation
- service-name checks
- signed `ServerConfig`
- transcript-bound `CertificateVerify`

### Database compromise after sessions
Addressed by:
- OPAQUE-style password record structure
- Argon2id-based password hardening
- no direct “server sees the password” path during login

### Replay of application data
Addressed by:
- exact receive-sequence enforcement in the record layer
- per-direction nonce derivation from sequence number

### User enumeration by protocol shape
Addressed by:
- fake-record path for unknown users
- timing-study tooling to measure residual differences

### Repeated online guessing
Addressed by:
- in-memory rate limiting keyed by network/client identity

### Malformed wire messages
Addressed by:
- deterministic binary codec
- parser checks
- codec fuzzing harness

---

## Threats only partially addressed

### Full PKI complexity
The project validates a pinned CA and one service certificate but does not implement a full PKIX validator.

### Strong side-channel resistance
The code reduces some protocol-level leakage but does not claim hardening against all local or microarchitectural side channels.

### Global anti-replay
Record replay rejection is per connection, not a global distributed anti-replay mechanism across resumptions or clustered servers.

### Identity privacy
The username is not fully hidden on the wire; the design only avoids exposing it in the most naive form.

---

## Why the threat model matters

This artifact is strongest when read as:

- a modular protocol implementation
- with explicit claims
- under an explicit adversary model
- with clearly named residual gaps

That framing makes the project much easier to evaluate honestly and helps separate “what is implemented” from “what would still be needed for production or publication.”