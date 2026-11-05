# CLAUDE.md — Gateway-based hybrid PQC for legacy-to-modern vehicle communication

Read this file fully at the start of every session. It is the source of truth. If a request conflicts with it, stop and ask.

## 1. What this project is

A **software prototype**, evaluated in simulation, of a **gateway** that lets a legacy vehicle's CAN traffic reach a PQC-capable peer under a **hybrid post-quantum handshake plus symmetric session protection**. V2V is the *target application scenario*, not something the prototype implements or tests.

The deliverable is: working code, a security test suite, a benchmark harness, and raw results. **The human writes the project report. Do not write report prose.** Produce code, tests, raw results, tables, plots and short technical docs only.

### Scope sentence (keep consistent in README and docs)
> This project designs and evaluates, in simulation, a gateway that lets a legacy vehicle communicate with a PQC-capable peer using a hybrid post-quantum handshake and symmetric session protection. V2V is the target application scenario. Wireless behaviour, vehicle mobility and broadcast safety messages are outside the evaluated scope and listed as future work.

### In scope
- Gateway + modern peer + emulated legacy CAN side + emulated network link, all in Python.
- Hybrid (and PQC-only, and classical) handshake; AES-GCM session protection; replay protection; rekeying.
- Crypto abstraction layer with a limited, explicit set of swappable algorithms.
- Configurations C0–C4 (section 7), metrics (section 8), security tests (section 9).
- Three small **analytical scripts** (not simulations): CAN bus time, contact-window vs handshake time, broadcast-beacon cost.

### Out of scope (do not build, do not suggest building)
- SUMO / Veins / OMNeT++ (future work only). Raspberry Pi / embedded hardware. Real radios, 802.11p, C-V2X.
- Broadcast safety beacons as an implemented feature (analysis script only).
- PKI / certificate chains / revocation (identity keys are pre-provisioned trust anchors).
- Real-time or safety (ISO 26262) claims. Production-readiness claims. Formal security proofs.
- Inventing or hand-writing cryptographic primitives.

### Known limitations that must be preserved in README and docs/LIMITATIONS.md
1. The legacy CAN side stays unauthenticated. The gateway protects only the gateway↔peer link. A forged frame on the CAN bus is forwarded (protected) by the gateway.
2. Results are **relative** comparisons between configurations on a laptop/desktop, not real-vehicle timings.
3. The handshake is a **custom protocol, not formally verified**. It follows TLS 1.3-style patterns but is not TLS.
4. Agility covers only algorithms that fit the four interfaces in section 4. No claim about future algorithms.
5. FN-DSA and HQC are included only if the installed library exposes them, and are labelled experimental.
6. Link emulation is not a wireless channel model.

## 2. Working rules for Claude Code

1. **One milestone at a time** (section 11). Start each milestone in plan mode: show the plan, wait for approval, then implement.
2. **Never hand-write crypto.** Use `liboqs` (via `liboqs-python`) for ML-KEM / ML-DSA / SLH-DSA (and FN-DSA / HQC if exposed) and the `cryptography` package for X25519, ECDSA P-256, HKDF, HMAC, AES-GCM, ChaCha20-Poly1305. If `liboqs-python` cannot be installed or imported, **stop and report**. Do not substitute a pure-Python PQC implementation for anything that is benchmarked.
3. **Tests first** for security-critical code (handshake, key schedule, nonce, replay window, rekey).
4. **Commit after every milestone** with a clear message. Never rewrite history.
5. **No scope creep.** Do not add features, dependencies or protocols not in this file without asking.
6. **Explain security-critical code** in docstrings and in the milestone summary: handshake, key schedule, nonce construction, replay window, rekey. The human must be able to defend these to an examiner.
7. **Determinism:** all randomness that is not cryptographic (traffic generators, link emulation, attack scripts) takes a seed from config. Cryptographic randomness always comes from the OS CSPRNG.
8. **Test keys** in fixtures are test-only; mark them clearly. No real secrets in the repo.
9. **Discover algorithms at runtime** (`oqs.get_enabled_kem_mechanisms()`, `oqs.get_enabled_sig_mechanisms()`); liboqs mechanism names change between versions (e.g. Kyber768 vs ML-KEM-768). The registry maps friendly names to whatever the installed version exposes and fails with a clear message if missing.
10. Pin versions that actually install and record them in `requirements.lock`. Record Python, OS, CPU and liboqs versions in every results file.
11. Keep dependencies minimal: `liboqs-python`, `cryptography`, `python-can`, `pytest`, `pandas`, `matplotlib`. Config files are TOML (`tomllib`, Python ≥ 3.11). Optional: `hypothesis`.
12. When something is ambiguous, ask. Do not guess on protocol or measurement definitions.
13. **Session continuity:** sessions do not share memory. Maintain `PROGRESS.md` at the repo root (milestone status, decisions made, open issues, the exact next step). Read it at the start of every session; update it before finishing any milestone. Keep the "Commands" section at the end of this file accurate.
14. **Environment safety:** use a project-local virtual environment and never install packages globally. Ask before any destructive command (`rm -rf`, `git reset --hard`, force-push, deleting results). Do not modify this file except the "Commands" section, unless I ask.
15. **Git workflow:** the repository already exists with remote `origin` and `CLAUDE.md` is committed on `main`. In M0, create `.gitignore` first (virtualenv, `__pycache__`, `.pytest_cache`, `.env`, private keys, generated keys under `configs/keys/`, large raw result files). One branch per milestone (`m1-crypto-layer`, `m2-handshake`, ...); small, frequent commits with clear messages; merge to `main` only after tests pass and I approve; tag each finished milestone (`m1-done`, ...). **Never push until I say so.** Never force-push or rewrite history. Never commit secrets: keys are generated by `scripts/gen_keys.py` and gitignored; only clearly marked throwaway test-fixture keys may be committed. Commit small result tables; ask before committing any file over 5 MB. Never ask me for credentials; if git authentication fails, tell me.

### Expertise and quality standards to apply
Work as an engineer with these competencies, and say so when a requirement in this file conflicts with them:
- **Applied cryptography engineering:** standard constructions only; strict nonce/counter discipline; domain-separation labels in every KDF call; transcript binding; fixed ordering of hybrid secrets; no custom primitives; compare MACs/tags only with constant-time functions (`hmac.compare_digest`); never log keys, secrets, plaintext payloads or nonces in release paths.
- **Defensive parsing and protocol code:** validate every length and field before use; reject malformed, truncated or oversized messages; bound buffers and retransmissions; fail closed with no distinguishing error details on the wire; explicit state machines with no implicit transitions.
- **Testing:** known-answer tests, round-trip tests, adversarial tests (section 9), property-based tests for nonce uniqueness and the replay window; every bug fix gets a regression test.
- **Benchmarking method:** warm-up, many repetitions, median/p95/p99, `gc.collect()` before timed sections, no logging or disk I/O inside timed regions, separate crypto time from link-emulation time, record environment metadata, flag high variance instead of hiding it.
- **Python systems work:** `asyncio`, `python-can` (CAN 2.0 vs CAN FD frame limits), type hints, clear module boundaries matching section 3.
- **Reproducibility and honesty:** one command to reproduce results; never claim more than section 1 allows; report negative or surprising results as they are.

## 3. Architecture

```
LegacyNode(s) --CAN (virtual)--> CanAdapter --> Gateway ==(LinkEmulator)== ModernPeer
 (no crypto)                                    (initiator)               (responder)
```

| Component | Responsibility |
|---|---|
| `LegacyNode` | Simulated ECU. Emits periodic CAN frames (configurable IDs, rates, payload patterns); accepts commands. No crypto. |
| `CanAdapter` | Reads/writes frames on a `python-can` virtual bus (SocketCAN `vcan` optional on Linux). Supports CAN 2.0 (≤8 B) and CAN FD (≤64 B) via config. |
| `MessageAdapter` | Converts CAN frames ⇄ record plaintext and back (report: "Protocol / Message Adapter"). Used by `Gateway`. |
| `Gateway` | Handshake **initiator**. Reads CAN frames, packs them into protected records, sends to peer; unpacks peer records and writes to CAN. Owns rekey scheduling. |
| `ModernPeer` | Handshake **responder**. Stands in for the other (PQC-capable) vehicle. Receives, verifies, decrypts, delivers to an application sink. |
| `LinkEmulator` | Emulates delay, jitter, loss, bandwidth cap, reordering; fragments to MTU; handshake retransmission. Seeded. |
| `CryptoProvider` layer | Four interfaces + registry + hybrid combiner (section 4). |
| `SessionManager` | Handshake state machines, key schedule, record layer, replay window, rekey. |
| `PassthroughPath` | C0 baseline: no handshake, no crypto, frames framed and forwarded. |
| `Attacker` | Test harness that sniffs/modifies/injects/replays on the link or on CAN. |
| `bench/` | Micro-benchmarks, end-to-end runs, analytical scripts, plots. |

The modern peer is a software endpoint; the "other vehicle" is represented by it. No vehicle mobility is modelled.

### Mapping to the architecture in the mid-term report (keep naming consistent in code and docs)
The report (Fig. 3.1) defines a gateway with five components between a legacy domain and a modern/PQC-capable domain. The code must keep these five as clearly named modules:

| Report component | Code module | Notes |
|---|---|---|
| Legacy Interface | `legacy/can_adapter.py` (`CanAdapter`) | Receives/sends frames on the virtual CAN bus |
| Protocol / Message Adapter | `nodes/adapter.py` (`MessageAdapter`) | Converts CAN frames ⇄ record plaintext (`[can_id, dlc, data]`), and the reverse for peer→legacy. Must be a **separate module**, not buried in `Gateway` |
| Security & Session Manager | `protocol/session.py` (`SessionManager`) | Handshake, key schedule, record layer, replay window, rekey |
| Crypto-Abstraction Layer | `crypto/` | Four interfaces (KEM, Signature, KDF, AEAD). The report names only KEM and signatures; KDF and AEAD are additions |
| Modern / PQC Interface | `net/link.py` client side used by `Gateway` | Sends/receives protected records over the emulated link toward `ModernPeer` |

Evaluation-only pieces not in the report's architecture: `PassthroughPath` (C0 baseline), `Attacker`, `bench/`. Keep them out of the gateway's production path.

## 4. Crypto abstraction layer

Four interfaces (abstract base classes). Every algorithm is selected **only by config** (a "suite" TOML file). The session manager and protocol code must never import a concrete algorithm.

| Interface | Operations | Algorithms (friendly name → implementation) |
|---|---|---|
| `KEM` | `keygen()`, `encaps(pk)`, `decaps(sk, ct)`; exposes `pk_len`, `ct_len`, `ss_len` | `x25519` (classical, wrapped as a KEM-style interface), `ml-kem-512`, `ml-kem-768`, `ml-kem-1024`, `hqc-*` (experimental, only if enabled) |
| `Signature` | `keygen()`, `sign(sk, msg)`, `verify(pk, msg, sig)`; exposes `pk_len`, `sig_len` | `ecdsa-p256` (classical), `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, one `slh-dsa-*` variant (large-signature stress test), `fn-dsa-*` (experimental, only if enabled) |
| `KDF` | `extract(salt, ikm)`, `expand(prk, info, length)` | `hkdf-sha256`, `hkdf-sha384` |
| `AEAD` | `encrypt(key, nonce, aad, pt)`, `decrypt(...)`; exposes `key_len`, `nonce_len`, `tag_len` | `aes-256-gcm`, `aes-128-gcm`, `chacha20-poly1305` |

### Hybrid combiners
- **Hybrid KEM:** runs component KEMs (default `x25519` + `ml-kem-768`), concatenates public keys / ciphertexts (length-prefixed, fixed order from the suite file) and concatenates the shared secrets in the same fixed order before the KDF. It must itself implement the `KEM` interface.
- **Hybrid signature (C3):** dual signature, `ecdsa-p256` + `ml-dsa-65`, concatenated with length prefixes; **both must verify**. This is a simple dual-signature scheme, **not** a standardized composite. Say so in the docstring and docs.
- Single-algorithm suites use the same code path with one component.

### Suite file (example, `configs/suites/hybrid.toml`)
```toml
suite_id = 3                 # 1 byte, signed into the handshake transcript
name = "hybrid"
kem = ["x25519", "ml-kem-768"]
signature = ["ecdsa-p256", "ml-dsa-65"]
kdf = "hkdf-sha256"
aead = "aes-256-gcm"
```

### Sanity-check sizes (tests must assert these for the enabled algorithms; they come from FIPS 203/204)
| Algorithm | Public key | Ciphertext / signature |
|---|---|---|
| ML-KEM-512 | 800 B | ct 768 B |
| ML-KEM-768 | 1184 B | ct 1088 B |
| ML-KEM-1024 | 1568 B | ct 1568 B |
| ML-DSA-44 | 1312 B | sig 2420 B |
| ML-DSA-65 | 1952 B | sig 3309 B |
| ML-DSA-87 | 2592 B | sig 4627 B |
| X25519 | 32 B | shared secret 32 B |

If the installed library disagrees, stop and report.

### Agility pass criteria (a swap passes only if all hold)
1. The change is **config only**: no source files change.
2. Handshake and traffic work end-to-end.
3. Security tests T1–T11 and T13 still pass (T12 documents a known non-prevention and is unaffected).
4. New message sizes are handled automatically (fragmentation, buffers).
5. `scripts/run_matrix.py` runs the whole swap matrix and writes a pass/fail table to `results/tables/agility.csv`.

## 5. Protocol specification

Terminology: **Gateway** = initiator (I). **Peer** = responder (R). H = SHA-256 (or the suite's hash). `||` = concatenation; every variable-length field is length-prefixed.

### 5.1 Provisioning (offline, pre-handshake)
Each side holds its own signature key pair and the other side's public key as a trust anchor (loaded from files under `configs/keys/`, generated by a script). No certificate chains. Optionally model certificate bytes as padding when measuring "with certificates" handshake size (config flag, default off).

### 5.2 Handshake (3 messages)
1. **HELLO_I** (I → R): `version, suite_id, session_id (4 B random), gateway_id, peer_id, nonce_i (32 B), kem_pk_I (ephemeral, hybrid pks), sig_I`
   - `sig_I = Sign(sk_I_id, "hs-v1-I" || H(all preceding fields))`
2. **HELLO_R** (R → I): `version, suite_id, session_id, nonce_r (32 B), kem_ct (hybrid ciphertexts), sig_R`
   - R verifies `sig_I`, checks `suite_id` is in its allowed list and `peer_id` is itself, encapsulates to `kem_pk_I`.
   - `sig_R = Sign(sk_R_id, "hs-v1-R" || H(HELLO_I || HELLO_R_without_sig))`
3. **FINISHED_I** (I → R): `HMAC(k_finished, H(HELLO_I || HELLO_R))`
   - I verifies `sig_R`, decapsulates, derives keys, sends FINISHED_I. R verifies it, then the session is established. R may send an optional `FINISHED_R` (same construction, label `"R"`); implement it.

All verification failures abort the handshake with no distinguishing error detail on the wire. Log details locally.

### 5.3 Key schedule
```
ss        = ss_comp1 || ss_comp2 || ...            (fixed suite order)
prk       = KDF.extract(salt = nonce_i || nonce_r, ikm = ss)
th        = H(HELLO_I || HELLO_R)                  (transcript hash, before FINISHED)
k_i2r     = expand(prk, "key i2r"  || suite_id || th, key_len)
k_r2i     = expand(prk, "key r2i"  || suite_id || th, key_len)
salt_i2r  = expand(prk, "salt i2r" || suite_id || th, 4)
salt_r2i  = expand(prk, "salt r2i" || suite_id || th, 4)
k_finished= expand(prk, "finished" || suite_id || th, 32)
rekey_sec0= expand(prk, "rekey0"   || suite_id || th, 32)
```
Separate keys per direction (so reflection fails). Zeroize intermediate secrets where Python allows; document that Python cannot guarantee this.

### 5.4 Downgrade protection
No algorithm negotiation in v1. Each side has a **fixed allowed-suite list** in config. `suite_id` and both identities are inside the signed transcript. Mismatch or modification → abort. A test must show a downgrade attempt fails (T6).

### 5.5 Record layer
Header (16 B, also used as AEAD associated data):

| Field | Size |
|---|---|
| version/type (type: DATA, REKEY_REQ, REKEY_ACK, CLOSE, ALERT) | 1 |
| session_id | 4 |
| epoch | 1 |
| counter | 8 |
| payload length | 2 |

`record = header || AEAD.encrypt(key[dir][epoch], nonce, aad = header, plaintext) ` where `nonce = salt[dir] (4 B) || counter (8 B)` and the ciphertext includes the 16 B tag. Fixed overhead with this layout is therefore **32 B per record** (16 B header + 16 B tag). **Measure and report the actual overhead; do not assume.**

DATA plaintext = one or more CAN frames: `[can_id (4 B incl. flags), dlc (1 B), data (0–64 B)]` repeated. Default: **one frame per record**. Optional experiment flag `aggregation_window_ms` / `max_frames_per_record` (milestone M7 stretch): batch several frames per record to cut overhead at the cost of latency.

Latency measurement uses **out-of-band** monotonic timestamps keyed by `(session_id, epoch, counter)`. Do not put timestamps on the wire.

### 5.6 Counters and replay window
- Counter is per direction, per epoch, starts at 0, increments by 1 per record. Never reused under a key.
- Receiver keeps a sliding window (default 64, configurable) per direction per epoch: accept an in-window, not-yet-seen counter once; reject duplicates and anything older than the window; accept new highest and slide.
- Counter hard limit (default 2^32, configurable low for tests): when reached, force rekey; if rekey fails, close the session.

### 5.7 Rekeying
- **Light rekey (ratchet):** `rekey_sec_{n+1} = expand(rekey_sec_n, "rekey", 32)`; new epoch keys/salts derived from `rekey_sec_{n+1}` with epoch-labelled expands; counters reset to 0 for the new epoch. Old secrets deleted after the grace period. Documented limitation: gives forward secrecy for past epochs but does **not** evict an attacker who already holds the current secret.
- **Full rekey:** run a new handshake (new `session_id`) and replace all keys.
- **Triggers (all configurable):** elapsed time, record count, byte count, session start (ignition), N consecutive authentication failures, manual.
- **Initiation:** the gateway sends an authenticated `REKEY_REQ` (type in header, protected under the current epoch); the peer replies `REKEY_ACK`; both switch epoch.
- **Overlap:** after switching, the receiver accepts the previous epoch for a grace period (default 2 s or 64 records, configurable) so in-flight records are not lost. After the grace period, the previous epoch is rejected.
- Epoch is 1 byte; force a full rekey before epoch 255.
- Failure handling: if rekey does not complete before a hard limit, raise ALERT and close the session. Never silently keep using an expired key.

### 5.8 Error handling
Authentication failure or replay → drop silently on the wire, increment a counter, log locally. N consecutive failures (config) → close the session and alert. Session expiry → CLOSE record then teardown.

### 5.9 Known protocol caveat to document
A replayed valid HELLO_I makes the responder do work (encapsulation, signing) but cannot yield a session (the attacker lacks the KEM secret key). Note it in docs/THREAT_MODEL.md as a DoS consideration; rate limiting is out of scope.

## 6. Link emulator and CAN side

### LinkEmulator parameters (all in `configs/network/*.toml`)
`delay_ms`, `jitter_ms`, `loss_pct`, `bandwidth_kbps`, `reorder_pct`, `mtu_bytes` (default 1500), `seed`.
- **Fragmentation:** messages larger than `mtu_bytes - fragment_header` are split. Fragment header (8 B): `msg_id, frag_idx, frag_count`. Reassembly at receiver. Count packets per message.
- **Handshake retransmission:** whole-message retransmit on timeout (default 200 ms, exponential backoff, max 5 tries). Record handshake success/failure.
- Build this as a plain asyncio component behind a small `Link` interface so a real network simulator could be plugged in later.

### CAN model
- Virtual bus via `python-can` (`virtual` interface). SocketCAN `vcan` optional on Linux.
- `LegacyNode` traffic profiles in `configs/scenarios/*.toml`, e.g. 100 Hz / 50 Hz / 10 Hz signals with different IDs and payload lengths; CAN 2.0 and CAN FD variants.
- Bus time is **computed analytically** in `bench/analytical/bus_time.py` (virtual CAN has no real timing). Document the approximation used (frame bits ≈ overhead + 8 × DLC, optional worst-case stuffing factor; CAN FD with separate arbitration/data bitrates). State clearly it is an approximation.
- Gateway forwards legacy→peer and peer→legacy (commands). Legacy frames are **not authenticated** by the gateway; this is a documented limitation (test T12).

## 7. Configurations

| ID | Name | Description |
|---|---|---|
| C0 | Baseline | No gateway security. Frames framed and forwarded in plaintext over the emulated link. No handshake. |
| C1 | Gateway, classical | `x25519` + `ecdsa-p256` + `hkdf-sha256` + `aes-256-gcm` |
| C2 | Gateway, PQC only | `ml-kem-768` + `ml-dsa-65` + same KDF/AEAD |
| C3 | Gateway, hybrid | `x25519 + ml-kem-768`, `ecdsa-p256 + ml-dsa-65` (dual), same KDF/AEAD |
| C4 | Agility matrix | Config-only swaps: KEM ∈ {ml-kem-512, -768, -1024, hybrid}; SIG ∈ {ml-dsa-44, -65, -87, slh-dsa (one variant), ecdsa-p256}; KDF ∈ {sha256, sha384}; AEAD ∈ {aes-256-gcm, aes-128-gcm, chacha20-poly1305}; `fn-dsa` / `hqc` only if enabled (experimental). Not the full cross product: a defined list in `configs/matrix.toml`, one-factor-at-a-time from the C3 default. |

C1 exists to separate the cost of *having a gateway* from the cost of *PQC*.

## 8. Metrics and measurement rules

**Per-operation micro-benchmarks** (`bench/micro.py`): keygen, encaps, decaps, sign, verify, KDF, AEAD encrypt/decrypt for each enabled algorithm and each payload size (8, 64, 256, 1024 B). ≥ 1000 iterations after ≥ 50 warm-up iterations discarded. Use `time.perf_counter_ns`.

**End-to-end** (`bench/e2e.py`), for each configuration and each network profile:
- Handshake: total time (split into compute vs link time), bytes per message and total, packet count after fragmentation, success rate over ≥ 200 trials per loss setting.
- Steady state: per-record overhead bytes (actual), per-message latency (gateway CAN ingest → peer delivery), crypto-only processing time reported **separately** from link delay, throughput (frames/s), process CPU time (`time.process_time`), peak memory (`tracemalloc` or `resource`).
- Rekey: light and full rekey cost (time, bytes, records dropped if any); sweep of rekey interval vs total overhead.
- Report **median, p95, p99** and sample count. Never a single run.

**Network profiles** (illustrative, not claims about any real radio): ideal; delay {5, 20, 50} ms; loss {0, 1, 5} %; bandwidth {6000 kbps, unlimited}.

**Output:** raw CSV/JSON to `results/raw/`, tables to `results/tables/`, matplotlib figures to `results/figures/`. Every file carries environment metadata (Python, OS, CPU, library versions, git commit, seed).

### Analytical scripts (`bench/analytical/`, parameters in config, all clearly labelled "illustrative")
1. `bus_time.py` — CAN / CAN FD bus occupancy of frames and of the equivalent protected-record traffic.
2. `contact_window.py` — `window_s = 2 × range_m / (relative_speed_kmh / 3.6)` for ranges and speeds in config; compare against measured handshake p95 under each network profile and print the ratio. Header the output with: "Analytical estimate, not a simulation."
3. `beacon_cost.py` — for a broadcast beacon (default payload 200 B, 10 Hz, configurable): added bytes per beacon for each signature scheme (signature + optional public key/certificate bytes), bytes/s per sender, and verification CPU load = `neighbours × rate × t_verify` using measured verify times. Purpose: show why per-message PQC signatures are costly for broadcast. Defaults are assumptions, not standards-derived values.

## 9. Security tests (acceptance criteria)

Run every test against C0 (to show the baseline is vulnerable where applicable) and C1/C2/C3 (to show it is blocked). Tests live in `tests/security/`; the attacker harness is in `attacks/`.

| ID | Test | Expected on C1/C2/C3 | Expected on C0 |
|---|---|---|---|
| T1 | Replay a captured valid record | Rejected (replay window) | Accepted |
| T2 | Modify payload or any header field (counter, epoch, session, CAN ID in AAD) | Rejected (tag failure) | Accepted |
| T3 | Inject forged / random records without the key | Rejected | Accepted |
| T4 | Handshake with an unknown identity key (wrong peer / wrong gateway) | Handshake aborts | n/a |
| T5 | MITM modifies a KEM public key, ciphertext or nonce in the handshake | Handshake fails | n/a |
| T6 | Downgrade: change `suite_id` or force a weaker suite | Aborts (signed transcript + fixed list) | n/a |
| T7 | Out-of-order and out-of-window counters | In-window unseen accepted once; older/duplicate rejected | n/a |
| T8 | Rekey: records across the boundary survive during overlap; old epoch rejected after grace period; failed rekey raises ALERT | Pass | n/a |
| T9 | Nonce uniqueness: property test that `(key, nonce)` never repeats over ≥ 10^5 records and across rekeys | Pass | n/a |
| T10 | Counter exhaustion (low limit in test config) forces rekey or closes session | Pass | n/a |
| T11 | Reflection: send a record back to its sender | Rejected (per-direction keys) | n/a |
| T12 | Forged frame injected on the **legacy CAN bus** | **Forwarded by the gateway (NOT prevented)** — test asserts and documents this known limitation | Forwarded |
| T13 | Reflect a FINISHED message back to its sender during the handshake | Handshake fails | n/a |

Also required: known-answer / round-trip tests for every primitive wrapper, size assertions (section 4), and handshake tests under loss (retransmission) and fragmentation.

## 10. Repository layout

```
pqc-gateway/
  CLAUDE.md  README.md  pyproject.toml  requirements.lock
  configs/{suites,scenarios,network,keys}/  configs/matrix.toml
  src/pqcgw/
    crypto/    interfaces.py registry.py hybrid.py providers/
    protocol/  messages.py handshake.py keyschedule.py record.py replay.py rekey.py session.py
    legacy/    can_model.py legacy_node.py can_adapter.py
    net/       link.py emulator.py fragment.py
    nodes/     gateway.py adapter.py peer.py passthrough.py
    attacks/   attacker.py scenarios.py
    bench/     micro.py e2e.py metrics.py analytical/{bus_time,contact_window,beacon_cost}.py
  tests/{unit,security,agility}/
  scripts/   run_matrix.py make_plots.py gen_keys.py
  results/{raw,tables,figures}/
  docs/      PROTOCOL.md THREAT_MODEL.md LIMITATIONS.md
```

## 11. Milestones (target ≈ 3 weeks of work + buffer; the human has 3–4 weeks total)

| ID | Days | Deliverable | Done when |
|---|---|---|---|
| M0 | 1 | Repo skeleton, venv, `make test`, liboqs smoke test printing enabled KEM/SIG mechanisms | Smoke test passes; versions recorded; **report if liboqs-python fails to install** |
| M1 | 1–3 | Crypto abstraction layer, registry, suite config, hybrid combiners, KAT/round-trip/size tests | All four interfaces work for C1–C3 algorithms; size assertions pass |
| M2 | 3–6 | Handshake state machines, transcript, key schedule over an in-memory link | Handshake succeeds for C1/C2/C3; T4, T5, T6, T13 pass |
| M3 | 6–8 | Record layer, nonce, replay window | T1, T2, T3, T7, T9, T11 pass |
| M4 | 8–10 | Rekeying (light + full), epochs, overlap, limits | T8, T10 pass |
| M5 | 10–13 | `python-can` virtual bus, LegacyNode, CanAdapter, Gateway, ModernPeer, LinkEmulator (fragmentation, retransmit), C0 passthrough | End-to-end demo for C0–C3; T12 documented |
| M6 | 13–16 | Full security suite across C0–C3, agility matrix runner | T1–T13 table generated; `agility.csv` generated |
| M7 | 16–20 | Benchmark harness, all network profiles, rekey sweep, three analytical scripts, tables and plots | Raw results + tables + figures in `results/` with metadata |
| M8 | 20+ | README, docs/PROTOCOL.md, THREAT_MODEL.md, LIMITATIONS.md, results summary tables | A new reader can reproduce results from the README |

**Stretch (only after M8):** frame aggregation experiment (`aggregation_window_ms`), additional matrix entries, extra plots. Nothing else.

## 12. Definition of done
- All tests pass; T12 documented as an expected non-prevention.
- Results reproducible from one documented command; every result file has environment metadata.
- README states the scope sentence and the six limitations verbatim.
- No claims in code, docs or README beyond section 1.

## 13. Decisions already made (do not reopen without asking)
- Python-only, simulation-only; V2V is a target scenario, not an implemented one.
- Hybrid default = X25519 + ML-KEM-768 with dual signatures ECDSA-P256 + ML-DSA-65.
- Session-based traffic only; broadcast beacons are an analysis script.
- Gateway = initiator; peer = responder; per-direction keys; counter-based nonces; no on-wire timestamps.
- No SUMO/Veins, no Raspberry Pi, no PKI.

## 14. Commands (maintained by Claude Code; fill in during M0, keep accurate)
- Setup: `make setup`  (requires liboqs already built into `.oqs/` via cmake; creates `.venv`, installs all deps with `OQS_INSTALL_PATH=$PWD/.oqs`, writes `requirements.lock`; see PROGRESS.md OI-3 for the cmake command)
- Run tests: `make test`
- Run security tests only: `.venv/bin/pytest tests/security/ -v`
- Run benchmarks / agility matrix: `python scripts/run_matrix.py` *(completed in M7)*

## 15. Resolved decisions (from the M0 review; these take precedence over earlier sections where they conflict)
1. **Where code runs:** on the student's own machine via terminal Claude Code. All benchmark and result files must come from there, never from a cloud sandbox.
2. **liboqs install:** build project-local with `OQS_INSTALL_PATH=$PWD/.oqs` (gitignored). Pin matching liboqs and liboqs-python versions and record both. Python: use the newest of 3.13 / 3.12 / 3.11 that installs and imports cleanly; do not hardcode a version; stop and report if none works.
3. **Git in M0:** the repository already exists (rule 15). Do **not** run `git init`. Work on branch `m0-setup`. `.gitignore` must include everything listed in rule 15 plus `.venv` and `.oqs`.
4. **Algorithm names** are resolved at runtime from the installed liboqs. SLH-DSA variant: SHA2-128f (large-signature stress test, about 17 KB signature); 128s optional. Falcon is **not** FN-DSA: expose it as `falcon-*`, labelled pre-standard and experimental, only if enabled. Use `fn-dsa-*` only if the library exposes that exact name. HQC variants: experimental, only if enabled.
5. **ML-DSA context string:** empty; document in the docstring.
6. **ECDSA-P256 signatures:** raw fixed 64-byte `r || s` (convert to/from DER with `cryptography`). Hybrid signature fields are length-prefixed.
7. **Hash H** (transcript hash and FINISHED HMAC) follows the suite's KDF hash: SHA-256 for `hkdf-sha256`, SHA-384 for `hkdf-sha384`.
8. **Label encoding:** `info = u8(len(label)) || label_ascii || u8(suite_id) || th || u8(epoch)`; epoch is 0 for the handshake keys. Header byte 0: high nibble = version (1), low nibble = type: DATA 0, REKEY_REQ 1, REKEY_ACK 2, CLOSE 3, ALERT 4. Light rekey: `rekey_sec_n = expand(rekey_sec_{n-1}, info("rekey", epoch=n), 32)`; epoch-n traffic keys and salts are expanded from `rekey_sec_n` with the labels in section 5.3.
9. **Retransmitted HELLO_I:** the responder caches HELLO_R keyed by `(session_id, H(HELLO_I))` for the handshake timeout and resends it byte-identical, with no repeated encapsulation or signing. After cache expiry a replayed HELLO_I is treated as a new handshake (documented DoS caveat, section 5.9).
10. **Grace period:** ends at whichever comes first, 2 s or 64 records on the new epoch.
11. **FINISHED_R:** always sent. The initiator treats the session as established after verifying FINISHED_R; the responder may send data after verifying FINISHED_I.
12. **Latency measurement:** `perf_counter_ns`; report crypto time and link time separately; asyncio scheduling noise is covered by limitation 2.
13. **PROGRESS.md** is created by Claude Code inside the repo, not copied from elsewhere.
14. **FINISHED messages:** `FINISHED_I = HMAC(k_finished, "I" || th)`. `FINISHED_R = HMAC(k_finished, "R" || th || FINISHED_I)`. The two values can never be identical, and FINISHED_R also confirms the responder saw FINISHED_I. Add security test **T13**: a reflected FINISHED message must make the handshake fail.
15. **Light rekey sequence:** (a) the gateway sends REKEY_REQ under the current epoch; (b) the peer replies REKEY_ACK under the current epoch and then sends under the new epoch; (c) the gateway starts sending under the new epoch when the ACK arrives. Both sides can compute the next epoch's keys in advance (deterministic ratchet). A receiver accepts epoch n+1 records **only while a rekey is in progress** (REKEY_REQ sent or received), and accepts epoch n during the grace period (item 10). Retransmit REKEY_REQ/REKEY_ACK on timeout; if rekey does not complete by a hard limit, raise ALERT and close the session. Tests: records in flight across the switch survive; old-epoch records are rejected after the grace period (T8).
16. **Full rekey:** run the new handshake as a **separate session with a new session_id while the old session keeps carrying traffic**. When the new session is established, the gateway sends new traffic on it; the old session is accepted for the grace period and then closed. `session_id` in the record header identifies the session. Measure the cost of a handshake running alongside live traffic.
17. **Fair overhead comparison:** C0 uses **minimal framing** only: `[can_id (4 B), dlc (1 B), data]`, which is what a real unsecured link would carry. C1–C3 add the 16 B record header and 16 B tag. The 8 B fragment header applies to **every** link message in **every** configuration. IP/UDP headers are not modelled; state this in docs/LIMITATIONS.md. Report overhead in layers: baseline, + record header, + tag, + handshake (amortised over session length).
18. **Loss and fragmentation metrics:** for every run record handshake success rate, number of retransmissions, total fragments sent, and handshake completion time including retries, per network profile. A lost fragment loses the whole message; this is an expected finding to report, not a bug.
19. **Precedence:** the older body text in sections 5.2 (FINISHED construction), 5.3 (label encoding) and 5.7 (rekey formula, switch order) is superseded by items 8, 11, 14, 15 and 16 above. Follow section 15. If you find any other place where the body text and section 15 differ, follow section 15 and list the difference in PROGRESS.md.
20. **Lost or duplicate FINISHED messages:** if the responder receives a byte-identical duplicate FINISHED_I, it resends its cached FINISHED_R; any other duplicate or different FINISHED_I is dropped. The initiator **buffers** CAN frames that arrive before FINISHED_R is verified, in a bounded queue (default 64 frames, drop-oldest with a drop counter) and flushes it once the session is established; if the handshake fails or times out the buffer is discarded and the loss is counted. The responder drops any DATA record that arrives before it has verified FINISHED_I.
21. **Rekey window and defaults:** "rekey in progress" starts when REKEY_REQ is sent or received and ends when the grace period for the previous epoch expires. A duplicate REKEY_REQ received during the grace period makes the peer resend its cached REKEY_ACK without ratcheting again. Defaults (all configurable): `rekey_timeout_ms = 400` (fixed, no backoff), `rekey_max_retries = 3` (worst case 4 × 400 ms = 1.6 s), `max_consecutive_auth_failures = 10`. Config loading rejects any setting where the rekey retry budget (including any backoff) is not shorter than the grace period time. Reaching `max_consecutive_auth_failures` raises ALERT and closes the session (this supersedes the rekey trigger listed in section 5.7); the counter resets after any successfully authenticated record. If REKEY_ACK is lost and the grace period expires, the session fails closed with ALERT; document this behaviour.
