# Related Work and Positioning

## Overview

VAULTTLS-R sits at the intersection of three important lines of work:

1. **augmented PAKEs**, especially OPAQUE-style designs
2. **TLS 1.3-style authenticated secure channels**
3. **protocol-analysis practice**, especially symbolic verification workflows

The project is not claiming a new cryptographic primitive. Its value lies in careful composition, explicit threat modeling, authenticated registration, and a structured artifact with tests, measurements, and analysis scaffolding.

---

## OPAQUE as the primary password-authentication reference point

The closest cryptographic reference point for the client-authentication side is **OPAQUE**.

OPAQUE matters because it shows how to build password-authenticated session establishment without turning the server into a plaintext-password verifier. The key conceptual pieces that matter for this repository are:

- a registration phase
- password hardening
- a server-stored record
- an authenticated online login phase
- forward-secrecy-oriented session establishment

VAULTTLS-R follows that overall shape closely enough to make the design recognizable:
- registration is separate from login
- the password-derived state is stored in a server record
- the online flow uses OPRF- and 3DH-style logic
- the server does not authenticate the client by simply checking a password sent in the clear inside a tunnel

### Difference from mature OPAQUE implementations
The repository intentionally uses an educational self-contained implementation. That improves readability and auditability for a course project, but it also means the assurance story is weaker than with a mature reviewed implementation.

---

## TLS 1.3 as the secure-channel reference point

The secure-channel side of the repository is inspired by **TLS 1.3**, especially its structural ideas:

- transcript-bound server authentication
- the `CertificateVerify` pattern
- HKDF traffic-secret derivation
- separate client/server traffic keys
- record nonces based on `IV XOR sequence_number`

This is why the repository is best described as **TLS 1.3-shaped** rather than “a TLS implementation.” The design borrows the parts of TLS 1.3 that are most pedagogically useful for a project focused on authenticated key establishment and protected application traffic.

### What VAULTTLS-R does not try to do
It does not aim for interoperability, full negotiation, resumption, broad alert handling, or the rest of the TLS operational ecosystem.

---

## Why “password over TLS” is not the strongest comparison point

A common baseline is:
1. establish a secure channel
2. then send a password inside it

That baseline is simple and practical, but it does not provide the same composition story as an augmented PAKE. In particular, it usually means the server directly handles the password during the authenticated application phase.

VAULTTLS-R’s comparison to a password-over-TLS baseline is useful because it highlights a classic tradeoff:

- simpler design and lower overhead on one side
- stronger password-handling story and better resistance after DB compromise on the other

This repository explicitly includes a baseline-comparison script for that reason.

---

## Certificate-only mutual authentication as a second baseline

Another useful baseline is certificate-only mutual authentication.

That approach avoids passwords entirely and can be extremely fast in a localhost artifact, but it requires every client to hold a certificate and corresponding key material. In many application settings, that is operationally unrealistic. The course project itself motivates password-authenticated client login precisely because client certificates are often impractical.

VAULTTLS-R therefore occupies a middle position:
- stronger than password-over-TLS in password-handling design
- more deployable than certificate-only client authentication for ordinary users

---

## TLS-OPAQUE composition literature

The strongest research-grade comparison point is not generic TLS or generic OPAQUE, but **explicit composition work around OPAQUE and TLS-style channels**.

That literature is important because the interesting problems are often not in either building block individually, but in the way they are composed:

- how the channel is bound to password authentication
- how server identity is bound to the password-authenticated flow
- how transcript semantics interact with client authentication
- whether authentication happens during handshake or after it

VAULTTLS-R is most compelling when read through that lens. Its most interesting design choice is not “it has encryption,” but “it treats authenticated registration and transcript-bound password-authenticated login as first-class phases of the channel design.”

---

## Symbolic verification practice

In modern protocol work, symbolic tools such as Tamarin and ProVerif are realistic next steps for artifact strengthening. They are especially useful when a design combines several ideas that are individually familiar but subtly composed.

For VAULTTLS-R, the symbolic-modeling strategy is:

1. abstract the OPAQUE internals into a password-authenticated key-establishment component
2. model transcript-bound signatures and server identity checks explicitly
3. state secrecy and authentication properties at the protocol level
4. add compromise rules carefully so that the claimed properties match the threat model

The repository includes both concrete-trace checking and symbolic-model files to move in that direction.

---

## Positioning statement

The most accurate positioning for VAULTTLS-R is:

> a research-oriented educational artifact that combines an OPAQUE-style password-authenticated login with a TLS 1.3-shaped secure channel, while making authenticated registration, standards transparency, measurement, and formal-analysis scaffolding first-class parts of the repository.

That is stronger and more honest than calling it either:
- a production OPAQUE implementation, or
- a production TLS implementation

---

## Practical contribution of this repository

The strongest contribution of VAULTTLS-R is not novelty at the primitive level. It is the combination of:

- a modular runnable artifact
- explicit registration authentication
- explicit trust-anchor handling
- transcript-bound session authentication
- measurement and robustness tooling
- clear documentation of goals, non-goals, and deviations

This makes the project useful as:
- a class submission
- a portfolio artifact
- a basis for a stronger protocol-analysis or systems-security write-up

---

## What would make the research positioning stronger

The next strongest upgrades would be:

1. completed Tamarin / ProVerif runs with attached outputs
2. a sharper formal claim around authenticated registration
3. replacement of the educational OPAQUE core with a vetted implementation
4. broader empirical comparisons across environments
5. a more explicit contribution statement if the project is written as a paper

Until then, the fairest label remains:

**research-oriented artifact, not final research result**