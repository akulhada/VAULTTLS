# Formal Verification Artifacts for VAULTTLS

This directory contains three formal security artifacts at escalating levels
of rigor.  Start with the trace checker (runs immediately); install Tamarin
or ProVerif to run the full symbolic models.

## Quick start — trace checker (no extra tools needed)

```bash
python formal/trace_checker.py
```

Expected output: 11/11 lemmas HOLD.

---

## Artifacts

### 1. `trace_checker.py` — Mechanized Trace Checker

Runs the actual implementation against a Dolev-Yao attacker model and
verifies 11 security lemmas on concrete protocol traces.

| Lemma | Property |
|---|---|
| L1 | Session key never appears in attacker channel view |
| L2 | Server finishes iff client finished with same key (injective) |
| L3 | Client finishes iff server responded first |
| L4 | Record stored only after server authenticated itself |
| L5 | Revealing server long-term key does not expose past sk |
| L6 | Replayed KE3 rejected |
| L7 | Unknown user gets syntactically valid fake KE2 |
| L8 | Wrong password fails before key derivation |
| L9 | Password bytes never appear on channel |
| L10 | Two sessions produce different keys (transcript entropy) |

**Scope:** Trace-level, not proof-level.  Verifies correct + attack traces
on concrete outputs.  Does not quantify over all adversary strategies.

---

### 2. `vaulttls_tamarin.spthy` — Tamarin Prover Model

```bash
tamarin-prover --prove formal/vaulttls_tamarin.spthy
```

Five lemmas: session_key_secrecy, client_to_server_agreement,
server_to_client_agreement, registration_authenticity, forward_secrecy.

Includes full compromise rules (long-term key, password).
Symbolic (Dolev-Yao) model — not a computational proof.

---

### 3. `vaulttls_proverif.pv` — ProVerif Model

```bash
proverif formal/vaulttls_proverif.pv
```

Four queries: secrecy + three injective correspondence lemmas.

---

## What remains for a full research proof

1. Run Tamarin/ProVerif and attach the verified output.
2. Add equational theory for DH in the Tamarin model.
3. Add a computational forward-secrecy argument referencing DDH.
4. Formally model the fake-user path for timing indistinguishability.
