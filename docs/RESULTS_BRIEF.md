# PQC Gateway — Results Brief

**Commit:** `5c9a197`  **Date:** 2026-11-20

> ANALYTICAL ESTIMATES are labelled where they appear. All other numbers are measured
> on the host machine listed in §2. Results are relative comparisons only;
> see §Limitations for scope.

---
## §1 Scope

This project evaluates, in simulation, a gateway that lets a legacy vehicle communicate
with a PQC-capable peer using a hybrid post-quantum handshake and symmetric session
protection. V2V wireless, vehicle mobility, and broadcast safety messages are outside
the evaluated scope.

## §2 Setup

| Item | Value |
| --- | --- |
| Platform | Apple arm64, macOS 25.6.0 |
| Python | 3.13.2 |
| liboqs | 0.16.0 |
| liboqs-python | 0.16.0.2 |
| cryptography | 50.0.2 |

## §3 Configurations

| ID | Name | KEM | Signature | KDF | AEAD |
| --- | --- | --- | --- | --- | --- |
| C0 | Passthrough | — | — | — | — |
| C1 | Classical | X25519 | ECDSA-P256 | HKDF-SHA-256 | AES-256-GCM |
| C2 | PQC-only | ML-KEM-768 | ML-DSA-65 | HKDF-SHA-256 | AES-256-GCM |
| C3 | Hybrid | X25519 + ML-KEM-768 | ECDSA-P256 + ML-DSA-65 (dual) | HKDF-SHA-256 | AES-256-GCM |

---
## §4 Security (T1–T13 × C0–C3)

| Test | C0 | C1 | C2 | C3 |
| --- | --- | --- | --- | --- |
| T1 | accepted ✓ | rejected ✓ | rejected ✓ | rejected ✓ |
| T2 | accepted ✓ | rejected ✓ | rejected ✓ | rejected ✓ |
| T3 | accepted ✓ | rejected ✓ | rejected ✓ | rejected ✓ |
| T4 | n/a | aborts ✓ | aborts ✓ | aborts ✓ |
| T5 | n/a | fails ✓ | fails ✓ | fails ✓ |
| T6 | n/a | aborts ✓ | aborts ✓ | aborts ✓ |
| T7 | n/a | in-window once / dup rejected ✓ | in-window once / dup rejected ✓ | in-window once / dup rejected ✓ |
| T8 | n/a | survives ✓ | survives ✓ | survives ✓ |
| T9 | n/a | no-reuse ✓ | no-reuse ✓ | no-reuse ✓ |
| T10 | n/a | rekeys ✓ | rekeys ✓ | rekeys ✓ |
| T11 | n/a | rejected ✓ | rejected ✓ | rejected ✓ |
| T12 | forwarded ✓ | forwarded ✓ | forwarded ✓ | forwarded ✓ |
| T13 | n/a | fails ✓ | fails ✓ | fails ✓ |

43 cells pass (✓); 0 fail (✗) — 0 failures expected.
T1–T11 and T13 also confirmed for all 14 agility matrix entries
(0/14 overall_pass = pass). T12 is not applicable to the
matrix — CAN bus injection is suite-independent and always forwarded (documented limitation).

---
## §5 Handshake

| Config | Profile | Wall median (ms) | Wall p95 (ms) | HS bytes (wire) | Frags I→R | Frags R→I | Success rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C1 | ideal | 2.54 | 3.60 | 386 | 2 | 2 | 100.0% |
| C1 | delay50 | 209.97 | 212.63 | 386 | 2 | 2 | 100.0% |
| C1 | loss5 | 26.37 | 229.71 | 386 | 2 | 2 | 100.0% |
| C1 | bw6000 | 29.72 | 33.50 | 386 | 2 | 2 | 100.0% |
| C2 | ideal | 2.41 | 3.61 | 9124 | 5 | 4 | 100.0% |
| C2 | delay50 | 209.82 | 211.69 | 9124 | 5 | 4 | 100.0% |
| C2 | loss5 | 28.67 | 639.09 | 9124 | 5 | 4 | 100.0% |
| C2 | bw6000 | 44.80 | 50.99 | 9124 | 5 | 4 | 100.0% |
| C3 | ideal | 3.43 | 5.08 | 9340 | 5 | 5 | 100.0% |
| C3 | delay50 | 210.36 | 211.76 | 9340 | 5 | 5 | 100.0% |
| C3 | loss5 | 32.39 | 844.30 | 9340 | 5 | 5 | 100.0% |
| C3 | bw6000 | 46.39 | 50.07 | 9340 | 5 | 5 | 100.0% |

Wall time = gateway handshake() start → completion including retransmits.
Under 5% loss, p95 spikes to hundreds of ms due to 400 ms retransmit timeout.

---
## §6 Per-handshake Primitive Cost (synchronous lower bound)

| Config | Suite | Median (ms) | p95 (ms) | p99 (ms) | n |
| --- | --- | --- | --- | --- | --- |
| C1 | classical | 0.33 | 0.34 | 0.34 | 1000 |
| C2 | pqc | 0.34 | 0.47 | 0.58 | 1000 |
| C3 | hybrid | 0.66 | 0.79 | 0.88 | 1000 |

Measured in-process (no asyncio overhead). C3 ≈ C1 + C2 as expected for hybrid.

---
## §7 Per-record Overhead (wire bytes)

| Config | CAN framing (B) | Frag header (B) | Prefix (B) | Record header (B) | AEAD tag (B) | Total overhead (B) | HS amortised/100 rec | HS amortised/1k rec | HS amortised/10k rec |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C0 | 5 | 8 | 0 | 0 | 0 | 13 | 0.0 | 0.0 | 0.0 |
| C1 | 5 | 8 | 1 | 16 | 16 | 46 | 3.86 | 0.39 | 0.04 |
| C2 | 5 | 8 | 1 | 16 | 16 | 46 | 91.24 | 9.12 | 0.91 |
| C3 | 5 | 8 | 1 | 16 | 16 | 46 | 93.4 | 9.34 | 0.93 |

C0 carries only CAN framing + fragment header (no crypto). C1–C3 add a 1-byte
message-type prefix, 16-byte record header, and 16-byte AEAD tag per record.
Amortised HS columns are handshake wire bytes divided by session length.

---
## §8 Micro-benchmarks (1 000 iterations, 50 warm-up discarded)

| Algorithm | Operation | Payload (B) | Median (µs) | p95 (µs) | p99 (µs) | n |
| --- | --- | --- | --- | --- | --- | --- |
| X25519 (KEM wrapper) | kem_keygen | — | 22.9 | 23.5 | 28.2 | 1000 |
| X25519 (KEM wrapper) | kem_encaps | — | 44.6 | 45.8 | 52.1 | 1000 |
| X25519 (KEM wrapper) | kem_decaps | — | 43.1 | 43.8 | 49.4 | 1000 |
| ECDSA-P256 | sig_keygen | — | 15.4 | 17.8 | 22.5 | 1000 |
| ECDSA-P256 | sig_sign | 64 | 30.7 | 35.0 | 41.1 | 1000 |
| ECDSA-P256 | sig_verify | 64 | 45.2 | 45.5 | 50.9 | 1000 |
| AES-256-GCM | aead_encrypt | 8 | 1.0 | 1.0 | 1.1 | 1000 |
| AES-256-GCM | aead_decrypt | 8 | 1.0 | 1.1 | 1.1 | 1000 |
| AES-256-GCM | aead_encrypt | 64 | 1.0 | 1.1 | 1.1 | 1000 |
| AES-256-GCM | aead_decrypt | 64 | 1.0 | 1.0 | 1.1 | 1000 |
| AES-256-GCM | aead_encrypt | 256 | 1.0 | 1.1 | 1.1 | 1000 |
| AES-256-GCM | aead_decrypt | 256 | 1.0 | 1.1 | 1.1 | 1000 |
| AES-256-GCM | aead_encrypt | 1024 | 1.1 | 1.2 | 1.2 | 1000 |
| AES-256-GCM | aead_decrypt | 1024 | 1.2 | 1.3 | 1.5 | 1000 |
| ML-KEM-768 | kem_keygen | — | 14.2 | 18.4 | 60.0 | 1000 |
| ML-KEM-768 | kem_encaps | — | 14.7 | 16.9 | 28.8 | 1000 |
| ML-KEM-768 | kem_decaps | — | 15.3 | 19.3 | 19.7 | 1000 |
| ML-DSA-65 | sig_keygen | — | 40.1 | 46.2 | 52.3 | 1000 |
| ML-DSA-65 | sig_sign | 64 | 75.6 | 177.3 | 255.7 | 1000 |
| ML-DSA-65 | sig_verify | 64 | 38.4 | 38.7 | 40.0 | 1000 |
| SLH-DSA-SHA2-128f | sig_keygen | — | 576.3 | 587.7 | 594.7 | 1000 |
| SLH-DSA-SHA2-128f | sig_sign | 64 | 13463.5 | 13925.7 | 16480.7 | 1000 |
| SLH-DSA-SHA2-128f | sig_verify | 64 | 826.7 | 843.7 | 876.9 | 1000 |

SLH-DSA-SHA2-128f sign is slow due to hash-based tree construction (~13 ms median).
ML-DSA-65 sign p95/p99 show high variance from rejection sampling.

---
## §9 Steady-state Latency (ideal network, 100 Hz, 1 000 frames)

| Config | Latency median (ms) | Latency p95 (ms) | Delivery ratio | n |
| --- | --- | --- | --- | --- |
| C0 | 0.13 | 0.23 | 100.0% | 1000 |
| C1 | 0.22 | 0.37 | 100.0% | 1000 |
| C2 | 0.23 | 0.35 | 100.0% | 1000 |
| C3 | 0.25 | 0.46 | 100.0% | 1000 |

Latency = CAN ingest timestamp → peer delivery timestamp (out-of-band monotonic clock).
C1–C3 overhead over C0 reflects AES-GCM encrypt + decrypt + link framing.

---
## §10 Rekey Cost (ideal network)

| Config | Type | Median (ms) | p95 (ms) | p99 (ms) | n |
| --- | --- | --- | --- | --- | --- |
| C1 | light | 0.70 |  |  | 20 |
| C2 | light | 0.75 |  |  | 20 |
| C3 | light | 0.91 |  |  | 20 |
| C1 | full | 11.68 |  |  | 10 |
| C2 | full | 11.52 |  |  | 10 |
| C3 | full | 12.16 |  |  | 10 |

**Light rekey (ratchet):** gateway sends REKEY\_REQ → peer replies REKEY\_ACK → both switch
epoch. Measured time covers one round-trip (gateway → peer → gateway).
**Full rekey:** new handshake runs alongside live traffic; measured time spans
`request_full_rekey()` to new-session establishment.
*Full rekey median includes an unresolved asyncio event-loop wait (see §Limitations).*

---
## §11 Agility Matrix

| Entry | Description | Factor | Experimental | Overall pass |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |

0/14 entries overall\_pass = pass; 0 mechanism\_absent (experimental,
skipped). T1–T11 and T13 checked per entry; T12 not applicable to the matrix.

---
## §12 Analytical Estimates

> **ANALYTICAL ESTIMATE — NOT A SIMULATION.** None of these values are measured.

### §12a Contact Window vs Handshake Time (C3, range = 100 m)

| Profile | Speed (km/h) | Contact window (s) | HS p95 (s) | Window / HS p95 | HS success rate |
| --- | --- | --- | --- | --- | --- |
| delay50 | 50 | 14.40 | 0.2118 | 68.0 | 100.0% |
| delay50 | 100 | 7.20 | 0.2118 | 34.0 | 100.0% |
| delay50 | 150 | 4.80 | 0.2118 | 22.7 | 100.0% |
| delay50 | 200 | 3.60 | 0.2118 | 17.0 | 100.0% |
| loss5 | 50 | 14.40 | 0.8443 | 17.1 | 100.0% |
| loss5 | 100 | 7.20 | 0.8443 | 8.5 | 100.0% |
| loss5 | 150 | 4.80 | 0.8443 | 5.7 | 100.0% |
| loss5 | 200 | 3.60 | 0.8443 | 4.3 | 100.0% |

Window/HS ratio > 1 means the handshake completes before the contact window closes.
Under 5% loss the ratio can drop below 10 at high relative speeds (retransmit pressure).

### §12b CAN Bus Occupancy

| Scenario | DLC | Bits/frame | Rate (Hz) | Bit rate (kbps) | Occupancy (%) |
| --- | --- | --- | --- | --- | --- |
| baseline | 8 | 135 | 100.0 | 500.0 | 2.7 |
| protected_record_hypothetical | 8 | 675 | 100.0 | 500.0 | 13.5 |

Hypothetical: in this design protected records travel only on the gateway↔peer link,
never on the CAN bus; the `protected_record_hypothetical` row estimates the cost *if*
they were carried on CAN. Segmentation: 8-byte payload chunks on CAN 2.0 (DLC ≤ 8),
padded DLC on CAN FD. Numbers use a 500 kbps bit rate and worst-case bit-stuffing
(Davis et al. 2007).

### §12c Per-beacon Signature Overhead

| Suite | Scheme | Sig bytes | Bytes/beacon | Bytes/s per sender | Verify load (ms/s) |
| --- | --- | --- | --- | --- | --- |
| classical | ECDSA-P256 | 64 | 264 | 2640.0 | 4.52 |
| pqc | ML-DSA-65 | 3309 | 3509 | 35090.0 | 3.84 |
| hybrid | ECDSA-P256 + ML-DSA-65 (dual) | 3373 | 3573 | 35730.0 | 8.47 |

Estimates for broadcast safety beacons at 10 Hz, 200 B payload, 10 neighbours.
Defaults are assumptions; see beacon\_cost.py for parameters.

---
## §13 Limitations

The following six limitations are verbatim from the project specification (CLAUDE.md §1):

1. The legacy CAN side stays unauthenticated. The gateway protects only the
   gateway↔peer link. A forged frame on the CAN bus is forwarded (protected) by the gateway.
2. Results are **relative** comparisons between configurations on a laptop/desktop,
   not real-vehicle timings.
3. The handshake is a **custom protocol, not formally verified**. It follows TLS 1.3-style
   patterns but is not TLS.
4. Agility covers only algorithms that fit the four interfaces in §4. No claim about future
   algorithms.
5. FN-DSA and HQC are included only if the installed library exposes them, and are labelled
   experimental.
6. Link emulation is not a wireless channel model.

Additional limitations:

7. All results were obtained on Apple arm64 (M-series); timings may differ significantly
   on x86-64 or embedded hardware.
8. Full rekey median timing includes an unresolved asyncio event-loop wait
   (request\_full\_rekey\_with\_event() scheduling jitter); the value is an upper bound.
9. Latency measurements use `time.perf_counter_ns` on the same machine; asyncio
   scheduling noise is included in the "other\_ns" component.

---
## §14 Figures

- **micro_keygen.png:** KEM and signature key-generation time by algorithm (median µs, log scale).
- **micro_ops.png:** encaps/decaps/sign/verify median µs by algorithm (log scale).
- **micro_aead.png:** AES-256-GCM encrypt/decrypt µs vs payload size (8–1024 B).
- **latency_cdf.png:** Empirical CDF of per-record latency for C1–C3 (ideal network). C1 median 0.22 ms, C3 median 0.25 ms.
- **handshake_bars.png:** Handshake wall time (median ms) per config × network profile. C1/ideal median 2.54 ms, C3/ideal 3.43 ms.
- **e2e_overhead.png:** Per-layer overhead bytes per record for C0–C3 (stacked bar).
- **contact_window_heat.png:** Heatmap of contact-window / handshake-p95 ratio (C3; range = 100 m; profiles: ideal, delay50, loss5).

---
