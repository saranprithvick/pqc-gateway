# PQC Gateway

> This project designs and evaluates, in simulation, a gateway that lets a legacy vehicle
> communicate with a PQC-capable peer using a hybrid post-quantum handshake and symmetric
> session protection. V2V is the target application scenario. Wireless behaviour, vehicle
> mobility and broadcast safety messages are outside the evaluated scope and listed as
> future work.

A software prototype that runs entirely in Python. The gateway sits between a legacy CAN
bus and a modern (PQC-capable) peer, performs a hybrid post-quantum handshake, and then
wraps every CAN frame in an authenticated-encrypted record for the network link.

---

## Architecture

```
LegacyNode(s) --CAN (virtual)--> CanAdapter --> Gateway ==(LinkEmulator)== ModernPeer
 (no crypto)                                    (initiator)               (responder)
```

Five components inside the gateway (matching Fig. 3.1 of the mid-term report):

| Component | Module | Role |
|---|---|---|
| Legacy Interface | `src/pqcgw/legacy/can_adapter.py` (`CanAdapter`) | Reads/writes CAN frames on the virtual bus |
| Protocol / Message Adapter | `src/pqcgw/nodes/adapter.py` (`MessageAdapter`) | Converts CAN frames ↔ record plaintext |
| Security & Session Manager | `src/pqcgw/protocol/session.py` (`SessionManager`) | Handshake, key schedule, record layer, replay window, rekey |
| Crypto-Abstraction Layer | `src/pqcgw/crypto/` | Four interfaces: KEM, Signature, KDF, AEAD |
| Modern / PQC Interface | `src/pqcgw/net/link.py` (`Link`) | Sends/receives protected records to `ModernPeer` |

---

## Configurations

| ID | Name | Algorithms |
|---|---|---|
| C0 | Baseline | No gateway security; plaintext forwarding |
| C1 | Classical | X25519 + ECDSA-P256 + HKDF-SHA-256 + AES-256-GCM |
| C2 | PQC only | ML-KEM-768 + ML-DSA-65 + HKDF-SHA-256 + AES-256-GCM |
| C3 | Hybrid | X25519+ML-KEM-768, ECDSA-P256+ML-DSA-65, HKDF-SHA-256, AES-256-GCM |

C1 isolates the cost of *having a gateway* from the cost of *PQC*. C3 is the
recommended production configuration: classical algorithms remain secure today; ML-KEM
protects against harvest-now-decrypt-later (HNDL) attacks by future quantum adversaries.

---

## Requirements

- **Python** ≥ 3.11 (tested on 3.13.2)
- **CMake** ≥ 3.20 (for the liboqs source build)
- **liboqs 0.16.0** — built project-locally into `.oqs/` (see Setup below)
- Python packages: `liboqs-python==0.16.0.2`, `cryptography`, `python-can`, `pandas`,
  `matplotlib` (installed automatically by `make setup`)

> **Platform note**: all benchmark numbers were collected on Apple arm64 (M-series,
> macOS 25.6.0). Results on other hardware will differ in absolute value but the
> relative ordering between configurations is expected to hold.

---

## Setup

### 1. Build liboqs 0.16.0 project-locally

```bash
git clone --depth 1 --branch 0.16.0 \
    https://github.com/open-quantum-safe/liboqs .oqs-src

cmake -S .oqs-src -B .oqs-src/build \
    -DCMAKE_INSTALL_PREFIX=$PWD/.oqs \
    -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=ON

cmake --build .oqs-src/build --parallel 8
cmake --install .oqs-src/build
```

This installs `liboqs.dylib` (macOS) or `liboqs.so` (Linux) into `.oqs/lib/`.
Both `.oqs/` and `.oqs-src/` are gitignored.

### 2. Create the virtual environment and install Python packages

```bash
make setup
```

This creates `.venv/`, installs all dependencies (including `liboqs-python` pointed at
`.oqs/`), and writes `requirements.lock`.

---

## Running the tests

```bash
make test
```

Expected output: **≥ 795 tests pass** (547 security, 13 agility, 202 unit/smoke,
33 regression). Slow tests (heavy PQC or large iterations) are included; to skip them:

```bash
.venv/bin/pytest -m "not slow"
```

Security tests only:

```bash
.venv/bin/pytest tests/security/ -v
```

---

## Running the benchmarks

```bash
make bench
```

Runs micro-benchmarks, end-to-end benchmarks (C0–C3 × 7 network profiles, 200 trials
each), the agility matrix (13 config-only swaps), security test suite, three analytical
scripts, and generates plots and a results brief.

**Expected runtime: approximately 2.5 hours** on Apple arm64 (the agility matrix +
security test suite accounts for most of this). Frozen results from commit `5c9a197`
(2026-11-20) are already in `results/`; re-running overwrites them.

Outputs:
- `results/raw/` — raw per-trial JSON
- `results/tables/` — aggregated CSV tables (one per metric)
- `results/figures/` — matplotlib PNG figures

---

## Reading the results

Start with **`docs/RESULTS_BRIEF.md`** (or `docs/RESULTS_BRIEF.html`) for a narrative
summary of every metric with tables and embedded figures.

Key tables:

| Table | Contents |
|---|---|
| `results/tables/handshake.csv` | Handshake timing, message sizes, fragment counts per config/profile |
| `results/tables/latency.csv` | Per-record end-to-end latency (median/p95/p99) per config/profile |
| `results/tables/overhead.csv` | Per-record byte overhead breakdown, amortised handshake cost |
| `results/tables/micro.csv` | Per-primitive operation timing |
| `results/tables/security_t1_t13.csv` | T1–T13 pass/fail table |
| `results/tables/agility.csv` | Config-only swap pass/fail matrix |

Every CSV file carries a metadata header (Python version, OS, CPU, liboqs version, git commit, seed).

---

## Repository layout

```
pqc-gateway/
  CLAUDE.md  README.md  pyproject.toml  requirements.lock
  configs/
    suites/        hybrid.toml  classical.toml  pqc.toml
    scenarios/     basic.toml
    network/       ideal.toml  delay5.toml  delay20.toml  delay50.toml
                   loss1.toml  loss5.toml  bw6000.toml
    sessions/      default.toml
    keys/          (gitignored; generated by scripts/gen_keys.py)
    matrix.toml
  src/pqcgw/
    crypto/        interfaces.py  registry.py  hybrid.py  providers/
    protocol/      messages.py  handshake.py  keyschedule.py  record.py
                   replay.py  rekey.py  session.py  hooks.py
    legacy/        can_model.py  legacy_node.py  can_adapter.py
    net/           link.py  emulator.py  fragment.py
    nodes/         gateway.py  adapter.py  peer.py  passthrough.py
    attacks/       attacker.py  scenarios.py
    bench/         micro.py  e2e.py  metrics.py
                   analytical/  bus_time.py  contact_window.py  beacon_cost.py
  tests/
    unit/          test_crypto*.py  test_handshake*.py  test_record*.py  ...
    security/      test_t*.py
    agility/       test_agility.py
  scripts/         run_matrix.py  make_plots.py  gen_keys.py
                   make_security_table.py  make_brief.py
  results/
    raw/           per-trial JSON
    tables/        aggregated CSV
    figures/       matplotlib PNG
  docs/
    PROTOCOL.md  THREAT_MODEL.md  LIMITATIONS.md
    RESULTS_BRIEF.md  RESULTS_BRIEF.html
  milestone-logs/  M0.md … M7.md
```

---

## Known limitations

The following six limitations are stated verbatim in the project scope and must be
preserved in all documentation.

1. **Unauthenticated legacy CAN bus.** The legacy CAN side stays unauthenticated. The
   gateway protects only the gateway↔peer link. A forged frame on the CAN bus is
   forwarded (protected) by the gateway.

2. **Relative timing results.** Results are **relative** comparisons between
   configurations on a laptop/desktop, not real-vehicle timings.

3. **Custom, unverified protocol.** The handshake is a **custom protocol, not formally
   verified**. It follows TLS 1.3-style patterns but is not TLS and has not been subject
   to formal analysis or external security review.

4. **Limited algorithm agility.** Agility covers only algorithms that fit the four
   interfaces in the Crypto-Abstraction Layer (KEM, Signature, KDF, AEAD). No claim is
   made about future algorithms.

5. **FN-DSA and HQC are experimental.** FN-DSA and HQC are included only if the
   installed library exposes them, and are labelled experimental.

6. **Link emulation is not a wireless channel model.** The LinkEmulator does not model
   a physical wireless channel, radio propagation, 802.11p PHY/MAC, or C-V2X.

See [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) for the full list including measurement
limitations.

---

## License

This is a university capstone prototype. No production or safety claims are made.

Code was developed with AI assistance (Claude Code) under the author's specification and review.
