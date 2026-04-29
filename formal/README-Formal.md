# Formal Verification Artifacts for VAULTTLS

This directory contains three formal security artifacts at escalating levels of rigor.  Start with the trace checker (runs immediately); install Tamarin or ProVerif to run the full symbolic models.

## Quick Start (No Extra Tools Needed)

```bash
python formal/trace_checker.py
```

To save the output:
```bash
python formal/trace_checker.py | tee formal/VERIFICATION_LOG.txt
```
Expected output: 11/11 lemmas HOLD.

## Run Symbolic Models (Need Dependencies)

### Tamarin
#### Installation Steps
1. **Install Dependencies & Tamarin** 
   
   Run the following command in your terminal(macOS or Linux) to install Tamarin and its dependencies (Maude and GraphViz)
   ```bash
   brew install tamarin-prover/tap/tamarin-prover
   brew install tamarin-prover/tap/maude graphviz haskell-stack
   ```
   On **Windowa**, the official recommendation is to use WSL2 with Ubuntu, then install Tamarin inside Ubuntu and use the browser on the Windows side for the GUI.

2. **Verify Installations**
   
   Check if the installation was successful by running:
   ```bash
   tamarin-prover --version
   maude --version
   dot -V
   ```
   if `maude` and `dot` is missing, Tamarin may install but parts of the workflow will fail.

#### Running a Model 
1. **Parse/Sanity - Check the Model**
   
   The Tamarin manual says calling `tamarin-prover your_file.spthy` parses the file, checks wellformedness, and pretty-prints the theory. That is the best first step before asking it to prove anything.
    ```bash
    tamarin-prover --prove formal/vaulttls_tamarin.spthy
    ```
    The Tamarin manual shows the `--prove` workflow for verifying lemmas in a `.spthy` theory, and it also documents proving individual lemmas with `--prove=<lemma>`.

    If you want to save the output:
    ```bash
    tamarin-prover --prove formal/vaulttls_tamarin.spthy | tee formal/tamarin_output.txt
    ```

    If you want to prove one lemma only:
    ```bash
    tamarin-prover --prove=LemmaName formal/vaulttls_tamarin.spthy
    ``` 

2. **Start Interactive Mode**
   
   Navigate to your project folder in the terminal and run:
   ```bash
   tamarin-prover interactive formal/vaulttls_tamarin.spthy --quit-on-warning
   ```
   that `--quit-on-warning` flag is recommended by the Tamarin manual so you do not miss well-formedness problem. 

3. **Access Web UI**
   
   In interactive mode, Tamarin serves a local interface; the docs reference port `3001` for the browser UI.

   Open a web browser and go to `http://localhost:3001`.


### Proverif
#### Installations Steps
1. **Install Prerequisites:**
   Open Terminal and install OCaml, OPAM, and Graphviz using Homebrew:
   ```bash
   brew install ocaml opam graphviz
   ``` 

2. **Initialize OPAM:**
   ```bash
   opam init
   opam update
   opam depext conf-graphviz
   ```
   It also notes that Graphviz is only needed for graphical attack display, and GTK is only needed for the interactive simulator. The proverif executable ends up under your OPAM switch’s bin directory, which is typically already in PATH.

3. **Install Proverif:**
   ```bash
   opam install proverif
   opam depext proverif
   ```

4. **Verify Installation:**
   ```bash
   which proverif
   proverif -version
   ```

#### Running a ProVerif Model
1. **Create a Model File**
   
   Write your protocol in a file , typicall ending in `.pv`.

2. **Run the Analyzer**
   
   ```bash
   proverif formal/vaulttls_proverif.pv
   ```
   The offical ProVerif README says the tool takes a protocol description as input and shows the standard usage form `proverif <file>.pv`.

   To save the output:
   ```bash
   proverif formal/vaulttls_proverif.pv | tee formal/proverif_output.txt
   ```

3. **Run the Interactive Simulator**

   ```bash
   proverif_interact formal/vaulttls_proverif.pv 
---

## Artifacts

### 1. `trace_checker.py` — Mechanized Trace Checker

Runs the actual implementation against a Dolev-Yao attacker model and verifies 11 security lemmas on concrete protocol traces.

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

**Scope:** Trace-level, not proof-level.  Verifies correct + attack traces on concrete outputs.  Does not quantify over all adversary strategies.

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

## How to Interpret the Results
### If the Concrete Checker Passes
That means the implementation's observed traces satisfy the repository's encoded trace -level checks.
This is valuable but narrower than symbolic proof.

### If Tamarin/ProVerif return the expected results
That would significantly strengthen the artifacts because it would move the repository from `"model written"` toward `"model checked"`.

### If a Symbolic Lemma Fails
a failed lemmas does not automatically mean the implementation is broken. It may indicate:
- A real protocol weakness
- A mismatch between the model and the code
- An over-strong claim
- An incomplete or incorrect abstraction

That is why the prose symbolic model remains useful even when mechanized tools are present.

---

## Scope & Limits
These artifacts do not by themselves prove:
- Production-grade side-channel resistance
- Full computational security
- Standards-complete TLS or OPAQUE conformance
- Correctness of every implementation detail in Python

They do support a much stronger artifact story than tests alone.