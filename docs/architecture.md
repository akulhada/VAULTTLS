# Architecture

## Overview

VAULTTLS is a localhost client/server protocol that combines certificate-based server authentication with password-based client authentication inside a single handshake. It is modular by design so that each cryptographic and systems component is easy to identify, test, and reason about.

The implementation is organized around three phases:

1. **Registration**
2. **Login / handshake**
3. **Protected application-data exchange**

The code is not a general-purpose TLS implementation. It is a focused educational design that reuses the *shape* of TLS 1.3 and OPAQUE where those structures are most useful for this project.

---

## Parties

### Client
The client knows:
- a username
- a password
- the pinned CA certificate

The client is responsible for:
- authenticating the server
- running registration and login
- deriving traffic keys after successful handshake completion
- sending protected application messages

### Server
The server holds:
- a certified private key
- OPAQUE-style server state
- a password-record database
- a rate limiter

The server is responsible for:
- responding to registration and login requests
- proving possession of the certified private key
- verifying client password knowledge
- deriving traffic keys after successful handshake completion
- protecting application messages

### CA
The CA is emulated locally and used only to issue and anchor trust in the server certificate. Its public certificate is pinned to the client out of band.

---

## Protocol phases

## 1. Registration phase

The registration phase creates a password-derived server record without sending the plaintext password to the server.

At a high level:

1. the client connects to the server
2. the server sends authentication material
3. the client validates:
   - the pinned-CA trust chain
   - the expected service identity
   - the signed `ServerConfig`
   - the transcript-bound `CertificateVerify`
4. the client and server perform the registration flow
5. the server stores the final OPAQUE-style password record

### Why registration is first-class
Many toy password systems secure only the login phase. VAULTTLS treats registration as a first-class authenticated phase because registration is when the long-term password-derived state is created. If this phase were unauthenticated, a malicious endpoint could capture or redirect account setup.

---

## 2. Login / handshake phase

The login phase authenticates both sides and establishes a shared session secret.

At a high level:

1. the client sends a first handshake message containing:
   - a credential identifier
   - a client nonce
   - an OPAQUE-style first flight
2. the server responds with:
   - a certificate chain
   - a signed `ServerConfig`
   - a transcript-bound `CertificateVerify`
   - an OPAQUE-style second flight
3. the client verifies the server-side authentication data
4. the client computes and sends the final OPAQUE-style handshake message
5. both sides derive traffic secrets only after the password-authenticated handshake succeeds

### Design intent
The handshake is structured so that:
- server authentication is based on PKI and transcript signatures
- client authentication is based on password knowledge
- the final secure channel depends on both sides’ successful participation

---

## 3. Record-protected application phase

After a successful handshake, the client and server exchange application messages under AEAD protection.

The record layer:
- derives one traffic secret per direction
- derives a key and IV from each traffic secret
- constructs nonces as `static_iv XOR sequence_number`
- rejects replayed and out-of-order records inside a live connection

The current demo application is a protected localhost message exchange / echo loop.

---

## Module map

| Module | Responsibility |
|---|---|
| `client.py` | client login, handshake verification, encrypted messaging |
| `server.py` | server registration/login handling and encrypted application loop |
| `register_user.py` | authenticated registration client |
| `opaque_adapter.py` | OPRF, envelope, 3DH, and handshake MAC logic |
| `pki.py` | PKI bootstrap, certificate issuance/loading, trust checks, transcript signatures |
| `server_config.py` | signed server capability blob and semantic validation |
| `tls13_kdf.py` | transcript hashing and TLS 1.3-shaped key derivation |
| `record.py` | AEAD key/IV derivation, nonce construction, encrypt/decrypt, sequence enforcement |
| `codec.py` | binary message encoding and decoding |
| `storage.py` | atomic JSON persistence for records and server state |
| `ratelimit.py` | online guessing throttling |
| `transcript.py` | framing and transcript helpers |

---

## Cryptographic building blocks

VAULTTLS composes the following primitives:

- **certificate-based authentication** for the server
- **digital signatures** for transcript binding
- **OPAQUE-style augmented PAKE** for password authentication
- **HKDF** for traffic-secret derivation
- **ChaCha20-Poly1305** for authenticated encryption
- **Argon2id** for password hardening in the envelope path

The design intentionally keeps the primitive boundaries visible so that the implementation can be inspected and graded component by component.

---

## Stored state

### Client-side long-term inputs
- username
- password
- pinned CA certificate

### Server-side long-term inputs
- server certificate and private key
- OPAQUE-style server state
- user registration records
- rate-limit state

### Per-session state
- nonces
- transcript state
- OPAQUE handshake state
- traffic secrets
- record-layer sequence numbers

---

## Trust boundaries

The main trust boundaries are:

1. **CA trust boundary**  
   The client trusts only the pinned CA certificate, not any arbitrary CA sent on the wire.

2. **Handshake trust boundary**  
   The client does not trust the server until the chain, service identity, signed `ServerConfig`, and transcript signature have all been verified.

3. **Password trust boundary**  
   The server does not accept the client until password-derived handshake completion succeeds.

4. **Application-data trust boundary**  
   Application data is not trusted or processed as secure until the record layer verifies the AEAD tag and expected sequence number.

---

## Why this architecture is useful

This architecture is intentionally stronger than “send a password inside an encrypted tunnel after the handshake.” It demonstrates how password authentication can become part of session establishment itself, while still keeping the design modular enough for testing, benchmarking, and formal-analysis artifacts.

It also gives the project a clear research-oriented structure:

- a protocol model
- a code artifact
- tests and negative tests
- timing and benchmark tools
- symbolic-model starting points