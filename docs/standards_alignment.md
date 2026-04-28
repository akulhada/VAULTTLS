# Standards Alignment, Implemented Core, and Deliberate Omissions

## Purpose

This document explains how VAULTTLS relates to the main standards and
reference designs that shape it:

- **RFC 9807 / OPAQUE-style augmented PAKE**
- **RFC 8446 / TLS 1.3-style authenticated secure channel**
- **RFC 5280 / X.509 certificate processing in a narrow pinned-CA model**

The key point is:

> **VAULTTLS implements the security-relevant core of an OPAQUE-style login
> and a TLS 1.3-shaped secure channel, but it is not a byte-for-byte,
> interoperable implementation of RFC 9807 or RFC 8446.**

This is an intentional design choice for a closed localhost artifact.

---

## What is implemented or closely adapted

## From RFC 9807 / OPAQUE-style design

The following OPAQUE-style components are implemented in the repository:

- **OPRF-style blind / evaluate / finalize flow** over **P-256 scalar
  multiplication**, following the same high-level blind-evaluate-finalize
  pattern used in modern OPRF constructions
- **Argon2id** as the password hardening / key-stretching function
- **Envelope seal and open** using **AES-256-GCM** to protect the stored
  envelope payload
- **Registration flow** with client start, server response, client finish,
  and server-side record storage
- **3DH-style authenticated key exchange** using three ECDH computations,
  plus a server MAC and client MAC
- **Fake-user path** that produces a syntactically valid `KE2`-like response
  for unknown credentials to reduce user-enumeration leakage
- **Per-user OPRF key material** stored separately from the envelope
- **Server public key recovered from the envelope and checked against the
  authenticated server key path**
- **Application-defined credential identifier** derived from
  `SHA-512(context || username)`

These pieces mirror the same high-level decomposition used in OPAQUE:
registration, OPRF-based password hardening, envelope-based storage, and a
password-authenticated key exchange with forward-secrecy intent.

### Important wording note

This should be described as **OPAQUE-style** or **RFC 9807-shaped**, not as
full RFC 9807 wire compatibility. The code intentionally uses an educational,
self-contained implementation rather than a ciphersuite-complete or
interoperable RFC library.

---

## From RFC 8446 / TLS 1.3-shaped design

The following TLS 1.3 ideas are implemented or closely adapted:

- **HKDF key schedule shape**:
  `Early Secret -> Handshake Secret -> Master Secret`
- **`HKDF-Expand-Label`** with the `tls13 ` prefix
- **`Derive-Secret`** with transcript-hash binding
- **Per-direction traffic secrets**, from which `write_key` and `write_iv`
  are derived
- **Nonce construction** as:
  `static_iv XOR sequence_number`
- **Transcript hash accumulation** over ordered handshake messages
- **`CertificateVerify`-style signature input** using:
  - 64 bytes of `0x20`
  - a context label
  - transcript-bound message hashing
- **ChaCha20-Poly1305** as the record AEAD
- **Transcript-bound traffic-secret derivation**, so the final channel keys
  depend on both the OPAQUE session key and the exact handshake transcript

### Important wording note

This should be described as a **TLS 1.3-shaped secure channel** rather than a
literal TLS 1.3 implementation. The code borrows the security-relevant core
patterns from RFC 8446 without claiming wire compatibility or interoperability
with deployed TLS stacks.

### Not included in the “implemented” list

Two TLS 1.3 features should **not** be claimed as fully implemented:

- **TLS `Finished` as a distinct RFC 8446 handshake message**  
  The current artifact instead relies on:
  - transcript-bound `CertificateVerify`
  - OPAQUE-style server/client MACs
  - the final OPAQUE-style `KE3`
  - transcript-bound traffic-secret derivation

  That is a strong handshake-completion story, but it is not a literal TLS
  `Finished` exchange on the wire.

- **`TLSInnerPlaintext` / content-type hiding**  
  The current record layer does **not** implement TLS 1.3 content-type
  encryption. Content-type semantics are simpler and explicit in the local
  protocol design.

---

## From RFC 5280 / X.509 certificate processing

The certificate layer includes the main security-relevant checks needed for
this project:

- a local **CA** that issues the server certificate
- **BasicConstraints**
- **KeyUsage**
- **ExtendedKeyUsage**
- **SubjectAlternativeName**
- **AuthorityKeyIdentifier**
- certificate **validity period** checks
- **pinned-CA verification** of the server chain
- **service-name checking** against the expected server identity

This is intentionally a **narrow PKI model** suitable for a controlled
two-party localhost system, not a full RFC 5280 validator.

---

## What is intentionally omitted or simplified, and why

## RFC 8446 omissions and simplifications

| Feature | RFC location | Why omitted or simplified | Security impact |
|---|---|---|---|
| Cipher-suite negotiation | §4.2.7, §4.2.9 | The implementation uses one fixed suite instead of negotiation. | No downgrade surface exists while only one suite is supported. This would matter in a multi-suite or interoperable system. |
| TLS record framing (`ContentType`, legacy version `0x0303`) | §5.1 | The repository uses simpler 4-byte length-prefixed framing plus custom message tags. | Acceptable for a closed system, but not interoperable with any real TLS stack. |
| Full alert protocol | §6 | The implementation uses a small custom alert format rather than the full TLS alert space. | Little effect on the core secrecy/authenticity claims, but much less operational detail than real TLS. |
| Session resumption / PSKs / 0-RTT | §2.2, §4.2.11 | Every session performs a fresh full handshake. | No loss for the claimed properties; this is mainly a performance/deployment feature. |
| Key update mid-session | §4.6.3 | Traffic keys are derived once per session. | Acceptable for short-lived localhost sessions. Long-lived channels would benefit from rekeying. |
| Post-handshake authentication | §4.6.2 | Client authentication happens during the handshake via the OPAQUE-style flow. | None for this design goal; OPAQUE replaces the need for post-handshake password authentication. |
| HelloRetryRequest | §4.1.4 | Only one key-exchange group is used, so retry is never needed. | None in the current fixed-group design. |
| Middlebox compatibility workarounds | Appendix D | No `ChangeCipherSpec` injection or legacy padding hacks. | None for a localhost educational artifact. |
| Extension framework (`SNI`, `ALPN`, etc.) | §4.2 | No general extension negotiation is implemented. | Acceptable for a single-protocol localhost system; not enough for a general-purpose network protocol. |
| TLS `Finished` as a distinct message | §4.4.4 | Not implemented as a separate TLS record/message. Handshake completion instead uses OPAQUE-style server/client MACs, `KE3`, `CertificateVerify`, and transcript-bound key derivation. | No loss to the project’s core authentication story, but should not be claimed as literal RFC 8446 `Finished`. |
| `TLSInnerPlaintext` / hidden content type | §5.4 | Not implemented. The local record layer does not encrypt TLS content-type bytes. | Some record semantics remain explicit to the local framing model. Acceptable here, but not a literal TLS 1.3 record layer. |

---

## RFC 9807 omissions, choices, and simplifications

| Feature / choice | RFC location | Why omitted or simplified | Security impact |
|---|---|---|---|
| Full OPAQUE-3DH ciphersuite constants and identifiers | Appendix B | The repository uses fixed local labels/parameters rather than interoperable RFC ciphersuite identifiers. | No interoperability with other OPAQUE implementations. No intrinsic security loss as long as both sides are consistent. |
| Full ciphersuite catalog | Appendix B | Only one concrete instantiation is implemented. | Acceptable in a single implementation; not standards-complete. |
| Alternate groups such as Ristretto255 or P-384 | Appendix B.1 | The code uses P-256 only. | No security regression for this artifact; P-256 remains a standard 128-bit security choice. |
| `export_key` application usage | §6.5 | The value may be derived but is not used by the application layer. | No impact on the secure-channel claims in this repository. |
| Credential identifier format | §4 | The code uses `SHA-512(context || username)` instead of an arbitrary application-defined byte string. | Acceptable; the credential identifier is application-defined in the spec family anyway. |
| Wire compatibility with other OPAQUE implementations | Entire RFC / ciphersuite definitions | The implementation is educational and self-contained. | No interoperability claim should be made. |
| Separate certified key and OPAQUE static key roles | Design choice beyond base RFC structure | The current implementation reuses the same P-256 key role more than an ideal production design would. | Acceptable for the artifact, but a stronger design would separate the roles and bind them explicitly. |

---

## RFC 5280 omissions and simplifications

| Feature | RFC location | Why omitted or simplified | Security impact |
|---|---|---|---|
| Full PKIX path validation | §6 | Only a single-level chain (`CA -> server`) is validated. | Acceptable for a controlled two-party system with one pinned local CA. Insufficient for general Internet-style PKI. |
| CRL / OCSP revocation checking | §5 / related revocation ecosystem | Revocation is not implemented. | A compromised server certificate cannot be revoked through protocol machinery before expiry. |
| Name constraints | §4.2.1.10 | Not implemented. | Negligible impact in the single-server localhost setting. |
| Certificate policies | §4.2.1.4 | Not implemented. | No practical impact in this closed system. |
| Multi-CA / intermediate CA / cross-certification handling | RFC 5280 ecosystem | The trust model is deliberately a single pinned CA. | Narrow but appropriate for the artifact’s threat model. |

---

## Production-hardening omissions

The following gaps are not flaws in the class-project scope, but they are still
important to document honestly.

| Item | What a production system would do |
|---|---|
| OPAQUE implementation | Use a vetted RFC-oriented OPAQUE implementation rather than a self-contained educational Python implementation. |
| Constant-time EC operations | Avoid pure-Python scalar-multiplication paths for security-critical operations; use hardened constant-time library implementations end to end. |
| Password handling in memory | Minimize password lifetime in memory and use languages/runtime support that allow stronger control over zeroing and object lifetime. |
| CA private-key lifecycle | Store and protect the CA private key securely if future certificate issuance or revocation workflows are required. |
| Concurrent-connection limits | Add connection caps, timeouts, and operational DoS controls. |
| Structured logging and audit trails | Add structured security logs and authentication-event audit trails. |
| Broader side-channel hardening | Treat timing, cache, power, and host-side leakage as explicit engineering concerns. |
| Long-lived session management | Add rekeying, richer alert/state handling, and possibly session lifecycle controls. |

---

## One-line honest summary

**VAULTTLS implements the security-relevant core of an OPAQUE-style augmented
PAKE and a TLS 1.3-shaped secure channel — including transcript-bound
authentication, HKDF-based traffic-secret derivation, certificate-anchored
server authentication, password-based client authentication, and AEAD record
protection — within a closed two-party localhost system. It deliberately omits
negotiation, resumption, full PKIX validation, and interoperability features
that are outside its threat model, and it uses a self-contained educational
OPAQUE implementation rather than a vetted standards-grade library. All major
omissions are documented together with their security impact.**