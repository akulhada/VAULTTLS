# Symbolic model sketch for VAULTTLS

This file is deliberately tool-agnostic but written in a style that maps closely
to Tamarin or ProVerif.

## State facts

- `PinnedCA(CA)` — client trusts CA out of band.
- `ServerCert(S, PKs, CA)` — CA certifies the server signing key.
- `PwRec(U, S, Rec)` — server stores the user's OPAQUE-style record.
- `ClientPw(U, S, Pw)` — honest client password knowledge.
- `RegAuth(U, S)` — client has authenticated the server during registration.
- `SessC(U, S, sid, th, sk)` — client-side completed session.
- `SessS(U, S, sid, th, sk)` — server-side completed session.
- `CompromiseDB(S)` — attacker learns the password database.
- `CompromisePw(U, S)` — attacker learns the user's password.

## Abstract terms

- `rec = RegRecord(Pw, salt, server_static)`
- `ke1 = KE1(U, nc, eph_c)`
- `ke2 = KE2(S, ns, eph_s, mac_s, fake_flag)`
- `ke3 = KE3(U, mac_c)`
- `th  = H(ClientHello, ServerHello, ClientFinish)`
- `sk  = KDF(opaque_session_key, th)`

The symbolic model intentionally treats the OPRF, envelope, and 3DH internals as
an abstract authenticated password-based session-key establishment mechanism.

## Registration rules

### R1. Honest server registration response

Preconditions:

- `PinnedCA(CA)`
- `ServerCert(S, PKs, CA)`
- client sends `RegReq(U, S, pw_material)`

Effects:

- server sends `RegResp(S, cert_chain, server_config, cv_sig, opaque_reg_resp)`
- action fact `RegServerAuth(S)`

### R2. Client accepts authenticated registration

Preconditions:

- received `RegResp(...)`
- certificate chain validates against `PinnedCA(CA)`
- `server_config` verifies and matches `S`
- `cv_sig` verifies against the transcript

Effects:

- action fact `RegClientAccept(U, S)`
- persistent fact `RegAuth(U, S)`
- client uploads final record, creating `PwRec(U, S, Rec)`

## Login rules

### L1. Client starts login

Preconditions:

- `ClientPw(U, S, Pw)`
- optionally `RegAuth(U, S)` if registration authenticity is part of the claim

Effects:

- sends `ClientHello(U, sid, ke1)`
- action fact `ClientStart(U, S, sid)`

### L2. Honest server responds

Case A: real user

Preconditions:

- `PwRec(U, S, Rec)`
- `ServerCert(S, PKs, CA)`

Effects:

- sends `ServerHello(S, sid, ke2, cert_chain, server_config, cv_sig)`
- action fact `ServerRespond(U, S, sid)`

Case B: unknown user

Preconditions:

- no matching `PwRec(U, S, Rec)`

Effects:

- sends syntactically valid `ServerHello(S, sid, fake_ke2, cert_chain, server_config, cv_sig)`
- action fact `ServerFakeRespond(U, S, sid)`

### L3. Client finishes

Preconditions:

- received `ServerHello(...)`
- certificate chain validates against the pinned CA
- `ServerConfig` verifies and matches the expected suite / identity
- transcript signature verifies
- password check succeeds inside abstract OPAQUE accept relation

Effects:

- sends `ClientFinish(U, sid, ke3)`
- derives `th` and `sk`
- action facts `ClientComplete(U, S, sid, th)` and `Secret(sk)`
- fact `SessC(U, S, sid, th, sk)`

### L4. Server finishes

Preconditions:

- receives `ClientFinish(U, sid, ke3)`
- abstract OPAQUE accept relation succeeds

Effects:

- derives the same `th` and `sk`
- action fact `ServerComplete(U, S, sid, th)`
- fact `SessS(U, S, sid, th, sk)`

## Candidate lemmas

### Lemma 1. Session-key secrecy

If `SessC(U,S,sid,th,sk)` and `SessS(U,S,sid,th,sk)` occur and neither
`CompromisePw(U,S)` nor a live-session compromise occurs beforehand, then the
attacker does not derive `sk`.

### Lemma 2. Client-to-server agreement

If `ClientComplete(U,S,sid,th)` occurs, then previously `ServerRespond(U,S,sid)`
and `ServerComplete(U,S,sid,th)` occurred for the same `sid` and `th`.

### Lemma 3. Server-to-client agreement

If `ServerComplete(U,S,sid,th)` occurs, then previously `ClientStart(U,S,sid)`
and `ClientComplete(U,S,sid,th)` occurred.

### Lemma 4. Registration authenticity

If `PwRec(U,S,Rec)` exists for an honest server, then previously
`RegClientAccept(U,S)` occurred.

### Lemma 5. Replay resistance (symbolic approximation)

No two successful record-accept events on the same channel use the same record
sequence number.

## What remains for a real proof

A machine-checked proof would need:

- a precise abstraction of the OPAQUE accept condition,
- compromise rules and freshness conditions,
- injective correspondence lemmas rather than only non-injective agreement,
- explicit ordering constraints for replay resistance,
- careful treatment of registration-vs-login state.
