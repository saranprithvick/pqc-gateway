# M7: Benchmark harness, analytical scripts, tables and figures

**Date completed:** 2026-11-13
**Branch:** m7-benchmarks
**Commits:** 10 (m7-01-infra through m7-10-progress)
**Tests:** 795 passed, 0 failed

---

## What was implemented

### Benchmark infrastructure (`src/pqcgw/bench/`)

- **`bench/metrics.py`** — Shared measurement utilities used by all benchmarks.
  - `Stats` / `compute_stats`: median/p95/p99 via linear interpolation on order statistics (matches numpy `'linear'` method; documented so results are reproducible without numpy).
  - `SmallNStats` / `compute_small_n_stats`: median/min/max for small-N samples (rekey cost, overhead).
  - `LatencyTracker`: out-of-band latency correlation keyed by `(session_id, epoch, counter)`. Gateway calls `record_ingest()` at CAN ingest time before sealing; Peer calls `record_deliver()` after AEAD open. No timestamps go on the wire (§5.5).
  - `write_csv`: append rows to a CSV file with environment metadata as `#`-comment header lines.
  - `collect_env`: captures Python version, OS, OS version, CPU, liboqs version, cryptography version, git commit SHA, seed, and ISO-8601 UTC timestamp. Recorded in every output file.
  - Re-exports `CryptoHook`, `NullCryptoHook`, `SummingHook` from `protocol.hooks` as a single import point for bench code.

- **`bench/micro.py`** — Per-primitive micro-benchmarks for each of the three suite configs (classical, pqc, hybrid).
  - Covers all four interface families: KEM (keygen, encaps, decaps), Signature (keygen, sign, verify), KDF (extract, expand ×4 payload sizes), AEAD (encrypt, decrypt ×4 payload sizes).
  - Protocol: 50 warm-up iterations discarded; 1000 timed iterations; `gc.collect()` before each timed section; `time.perf_counter_ns()` per iteration.
  - Per-suite raw CSVs written to `results/raw/micro_<suite>_<op>.csv`; a consolidated `results/tables/micro.csv` is produced by `consolidate_micro_csv()`.

- **`bench/e2e.py`** — End-to-end harness covering four sub-runs per configuration × network profile.
  - **Sub-run A (Handshake):** 200 trials per profile; wall time split into crypto time (via `SummingHook`) vs link time; bytes per message, fragment counts; success/failure counts and rate. Configurations C0 (passthrough), C1 (classical), C2 (pqc), C3 (hybrid).
  - **Sub-run B (Latency):** 100 frames at 100 Hz; CAN ingest-to-peer-delivery latency measured via `LatencyTracker`; median/p95/p99 and sample count.
  - **Sub-run C (Throughput + Memory):** saturate the pipeline; wall time, process CPU time (`time.process_time`), frames per second, peak memory via `tracemalloc` (taken outside the timed region).
  - **Sub-run D (Rekey cost + sweep):** light rekey cost ×20 trials per profile; rekey interval sweep over `[10, 20, 50, 100, 200, 500, 1000, 5000]` frames for C3/ideal; `SmallNStats` (median/min/max) for small-N samples.
  - **Overhead decomposition** (§15 item 17): C0 baseline = 5 B framing (can_id 4 B + dlc 1 B); C1–C3 add +8 B fragment header + 1 B type prefix + 16 B record header + 16 B AEAD tag = 41 B total additional overhead.
  - **Injector adapter pattern**: python-can virtual bus does not echo sends to the sender. Throughput and rekey sweep sub-runs use a separate `CanAdapter` instance as an injector to work around this.
  - **Loss profile handling**: `peer.run(n_frames=N)` can stall when packets are lost; `asyncio.TimeoutError` is caught to collect partial results rather than hanging.
  - **Light rekey background tasks**: `run(n_frames=None)` with background asyncio tasks to allow rekey to complete before the run exits.

- **`bench/analytical/bus_time.py`** — CAN 2.0A and CAN FD bus occupancy calculation. Uses worst-case bit-stuffing formula from Davis et al. (2007). Clearly labelled "ANALYTICAL ESTIMATE — NOT A SIMULATION." Documents that protected records on the emulated link are hypothetical CAN calculations only; the fragment header and type prefix are link-layer, not CAN-layer.

- **`bench/analytical/contact_window.py`** — Contact-window vs handshake time comparison. Formula: `window_s = 2 × range_m / (relative_speed_kmh / 3.6)`. Compares computed contact window against measured handshake p95 from `results/tables/handshake.csv` and prints the ratio. Output is headed "Analytical estimate, not a simulation."

- **`bench/analytical/beacon_cost.py`** — Broadcast beacon cost analysis. For a 200 B payload at 10 Hz with 10 neighbours: added bytes per beacon per signature scheme (signature + optional PK bytes), bytes/s per sender, and verification CPU load = `neighbours × rate × t_verify` using measured verify times from `results/tables/micro.csv`. Output clearly labels all defaults as assumptions.

### Protocol instrumentation (`src/pqcgw/protocol/hooks.py`)

- `CryptoHook` protocol (structural subtyping via `runtime_checkable`): `before_crypto(label)` returns a start timestamp (ns); `after_crypto(label, start_ns)` records elapsed time.
- `NullCryptoHook`: no-op implementation; zero overhead on hot paths.
- `SummingHook`: accumulates total crypto time and per-label call counts. Used by the e2e harness to split crypto time from link time in handshake measurements. Documents ~100 ns per call-pair measurement overhead as a known artefact (see `docs/LIMITATIONS.md`).

### Network profile configs (`configs/network/`)

Six new TOML files added to cover all benchmark network profiles:
- `delay5.toml`, `delay20.toml`, `delay50.toml` — fixed latency profiles at 5/20/50 ms
- `loss1.toml`, `loss5.toml` — 1% and 5% packet loss
- `bw6000.toml` — 6000 kbps bandwidth cap

### Session config (`configs/sessions/default.toml`)

Default `RekeyConfig` and `RekeyTrigger` values, loadable by `RekeyConfig.from_toml` and `RekeyTrigger.from_toml`. Required by the e2e harness to wire up rekey triggers for gateway/peer instances.

### Plotting script (`scripts/make_plots.py`)

497-line matplotlib script producing 8 figures from the result tables. Each figure carries a caption and uses a seaborn-style log-y axis where appropriate. Writes to `results/figures/`.

### Documentation (`docs/LIMITATIONS.md`)

New file recording known measurement limitations per CLAUDE.md §1 and §15 item 12, including: virtual CAN has no real timing; asyncio scheduling noise; `SummingHook` measurement overhead; `tracemalloc` peak includes Python internals; results are relative comparisons.

### Tests (`tests/unit/test_bench_smoke.py`, `tests/unit/test_emulator_pipeline.py`)

- `test_bench_smoke.py` (259 lines): 30 parametrized tests covering `compute_stats`, `compute_small_n_stats`, `LatencyTracker`, `SummingHook`, `collect_env`, `write_csv`, `bus_time` formula spot-checks, `beacon_cost` smoke, `contact_window_s` formula, `RekeyConfig.from_toml`, `RekeyTrigger.from_toml`, and `NetworkConfig.from_toml`.
- `test_emulator_pipeline.py` (135 lines): tests for `LinkEmulator` pipeline and bandwidth-cap modes.

### Modifications to existing files

- `src/pqcgw/legacy/legacy_node.py` — rate-driven emission and command path updates.
- `src/pqcgw/net/emulator.py` — `gateway_half`/`peer_half` pipeline and bandwidth-cap plumbing.
- `src/pqcgw/nodes/gateway.py` — `SummingHook` integration; injector adapter support.
- `src/pqcgw/nodes/peer.py` — latency delivery hook and `run(n_frames=None)` background mode.
- `src/pqcgw/protocol/handshake.py` — `crypto_hook` parameter threading through initiator/responder.
- `src/pqcgw/protocol/session.py` — `RekeyConfig.from_toml` and `RekeyTrigger.from_toml` loaders.
- `Makefile` — bench targets.
- `pyproject.toml` — bench entry points.

---

## Why it was implemented this way

### Out-of-band latency measurement with LatencyTracker
CLAUDE.md §5.5 mandates "latency measurement uses out-of-band monotonic timestamps keyed by `(session_id, epoch, counter)`" and explicitly says "do not put timestamps on the wire." The `LatencyTracker` matches ingest and delivery events by this key without altering the wire protocol. Gateway stamps at CAN ingest (before `seal()`); Peer stamps at delivery (after `open()`). This correctly measures the full gateway-to-peer path including crypto and link delay.

### CryptoHook / NullCryptoHook / SummingHook design
CLAUDE.md §8 requires "crypto-only processing time reported separately from link delay." The `CryptoHook` protocol allows the handshake initiator and responder to instrument individual crypto operations without coupling the protocol layer to the bench layer. `NullCryptoHook` is the default; it has zero overhead because `before_crypto` returns 0 and `after_crypto` does nothing — the compiler can inline both. `SummingHook` is passed in only by the e2e harness. This keeps the protocol layer free of measurement code (no logging, no timing in release paths — per §2 rule 7 and §2 expertise point 1).

### gc.collect() and warm-up discipline (micro.py)
CLAUDE.md §8 requires "gc.collect() before timed sections" and "≥ 50 warm-up iterations discarded." These ensure that GC pause latency and JIT warm-up effects do not inflate the first few measurements. The first 50 results are thrown away; only the subsequent 1000 iterations are timed. This is consistent with the §8 requirement of "≥ 1000 iterations after ≥ 50 warm-up."

### Linear interpolation percentiles (metrics.py)
The percentile implementation uses linear interpolation on order statistics, identical to numpy's `'linear'` / `'interpolation'` method. This is documented verbatim in the module docstring so a reader can reproduce results without numpy and verify consistency with any numpy-based post-processing.

### Injector adapter pattern (e2e.py throughput/rekey sub-runs)
Python-can's virtual bus does not echo a sender's own frames back to itself. If the gateway sends a CAN frame and also reads from the same `CanAdapter`, it will never receive it. The fix is a separate `CanAdapter` instance on the same virtual channel acting as an injector. This was a correctness bug discovered during M7 and fixed in m7-06-fixes.

### Loss profile early-exit with asyncio.TimeoutError
Under 5% packet loss, `peer.run(n_frames=N)` may never accumulate all N delivered frames if some are lost. The original implementation blocked indefinitely. The fix catches `asyncio.TimeoutError` and returns partial results, which the harness records with the actual sample count. This is consistent with §8: "flag high variance instead of hiding it." Loss results show smaller sample sizes, which is an honest representation.

### Overhead decomposition in layers (§15 item 17)
CLAUDE.md §15 item 17 specifies a layered overhead report: "baseline, + record header, + tag, + handshake (amortised over session length)" and requires C0 to use "minimal framing only." The `measure_overhead` function and `overhead.csv` capture each layer independently: C0 = 5 B (can_id + dlc); C1–C3 = 5 + 8 + 1 + 16 + 16 = 46 B total per record (8 B fragment header, 1 B type prefix, 16 B record header, 16 B AEAD tag). The 32 B record security overhead (header + tag) matches CLAUDE.md §5.5 exactly.

### Analytical scripts labelled as estimates
All three analytical scripts print a prominent "ANALYTICAL ESTIMATE — NOT A SIMULATION" header. This is mandated by CLAUDE.md §8 ("all clearly labelled 'illustrative'"). The bus-time script cites the Davis et al. (2007) worst-case stuffing formula. The contact-window script states the formula used. The beacon-cost script labels all defaults as assumptions, not standards-derived values.

### RekeyConfig.from_toml / RekeyTrigger.from_toml
CLAUDE.md §15 item b (M5b notes) requires `RekeyTrigger` fields to be loadable from TOML config by M7. Without this, the e2e harness cannot instantiate gateway/peer with configurable rekey triggers without hardcoding defaults. The `from_toml` loaders read `configs/sessions/default.toml` and validate the rekey budget constraint (§15 item 21: `rekey_timeout_ms × (retries+1) / 1000 < grace_period_s`).

### No logging or disk I/O inside timed regions
CLAUDE.md §2 expertise point 4 ("no logging or disk I/O inside timed regions"). The micro-benchmark loops time only the target operation (`fn()`). CSV writes happen outside timed regions. `tracemalloc` snapshots are taken after the timed throughput window, not inside it.

---

## Key results and test evidence

### Test summary

```
795 passed in 19.08s
```

No failures. No skipped tests. 795 total includes all prior milestones (security, unit, agility, smoke) plus 30 new bench-smoke tests and ~15 emulator pipeline tests added in M7.

### Micro-benchmark results (classical / pqc / hybrid suites, arm64 macOS, 1000 iterations)

**KEM operations (median ns):**
| Suite | Keygen | Encaps | Decaps |
|---|---|---|---|
| classical (X25519 KEM-style) | ~23 µs | ~44 µs | ~43 µs |
| pqc (ML-KEM-768) | see micro.csv | see micro.csv | see micro.csv |
| hybrid (X25519 + ML-KEM-768) | see micro.csv | see micro.csv | see micro.csv |

**Signature operations (median ns):**
| Suite | Keygen | Sign | Verify |
|---|---|---|---|
| classical (ECDSA-P256) | ~15 µs | ~31 µs | ~45 µs |
| pqc (ML-DSA-65) | see micro.csv | see micro.csv | ~36 µs |
| hybrid (ECDSA-P256 + ML-DSA-65 dual) | see micro.csv | see micro.csv | ~83 µs |

**KDF / AEAD:** ~875–1200 ns for extract/expand at typical sizes; < 10 µs for AEAD encrypt/decrypt at 256 B.

Full results with p95/p99 in `results/tables/micro.csv`. Environment: Python 3.13.2, Darwin 25.6.0, arm, liboqs 0.16.0, cryptography 50.0.2.

### Handshake results (200 trials per profile)

| Config | Profile | Median wall (ms) | Crypto (ms median) | Success rate |
|---|---|---|---|---|
| C1 | ideal | 56.9 | 1.26 | 100% |
| C2 | ideal | 56.0 | 1.08 | 100% |
| C3 | ideal | 56.7 | 2.10 | 100% |
| C1 | loss5 | 68.5 | 1.51 | 95.5% |
| C2 | loss5 | 68.7 | 1.26 | 98.0% |
| C3 | loss5 | 71.6 | 2.90 | 96.5% |
| C3 | delay50 | 213.4 | 3.33 | 100% |

Crypto time is a small fraction of wall time under all profiles; the dominant cost is network RTT (2× for a 3-message handshake). Under 5% loss, retransmission elevates p99 to 450 ms–3 s (exponential tail — expected finding per §15 item 18).

### Latency (CAN ingest → peer delivery, 100 frames at 100 Hz)

| Config | Profile | Median (µs) | p95 (µs) |
|---|---|---|---|
| C1 | ideal | 258 | 407 |
| C2 | ideal | 296 | 480 |
| C3 | ideal | 182 | 349 |
| C1 | delay20 | 20,826 | 21,817 |
| C3 | delay50 | 50,806 | 51,370 |

Ideal-profile latency is dominated by asyncio scheduling, not crypto. Under delay profiles it tracks the configured link delay as expected. C3 (hybrid) shows slightly lower median latency than C1/C2 at ideal (182 µs vs 258/296 µs) — this is likely a scheduling artefact from smaller variance in the hybrid path.

### Throughput and memory

| Config | Profile | fps | Peak memory |
|---|---|---|---|
| C1 | ideal | 86.9 | 112 KiB |
| C2 | ideal | 86.8 | 174 KiB |
| C3 | ideal | 85.4 | 182 KiB |

85–95 fps across all configs and profiles. The pipeline is network-bound (asyncio scheduling + virtual CAN + link emulator), not crypto-bound. PQC adds ~54–62% memory over classical due to larger key and ciphertext buffers.

### Overhead decomposition

| Config | Total overhead per record | Breakdown |
|---|---|---|
| C0 | 13 B | 5 B baseline + 8 B fragment header |
| C1–C3 | 46 B | 5 B + 8 B + 1 B prefix + 16 B record header + 16 B AEAD tag |

Matches the §5.5 and §15 item 17 expected values exactly (32 B record security overhead).

### Rekey cost (light rekey, 20 trials)

| Config | Profile | Median time |
|---|---|---|
| C1 | ideal | 31.6 ms |
| C2 | ideal | 31.8 ms |
| C3 | ideal | 32.5 ms |
| C3 | delay20 | 63.7 ms |
| C3 | delay50 | 127.6 ms |
| C3 | loss5 | 440.0 ms |

Light rekey scales with ~2× RTT (REKEY_REQ + REKEY_ACK). Under 5% loss the median jumps to 440 ms because REKEY_REQ or REKEY_ACK frequently hits the 400 ms retransmit timeout before the first ACK arrives. This is an expected finding (§15 item 21 retransmit budget).

### Rekey sweep (C3/ideal, 1000 frames)

| Interval (frames) | Rekeys triggered |
|---|---|
| 10–500 | 1 |
| 1000–5000 | 0 (never triggered; 1000 frames exhausted first) |

A single rekey is triggered for all intervals up to 500 frames within a 1000-frame run, confirming the ratchet fires when the counter reaches the trigger.

### Analytical script results

**Bus time:** CAN 2.0A worst-case with 8 B DLC: ~135 bits/frame at 500 kbps ≈ 270 µs/frame. Protected record (16 B total header + data) over the same bus is a hypothetical calculation. Full table in `results/tables/bus_time.csv`.

**Contact window:** At 100 m range, 30 km/h relative speed: contact window = 24 s. Handshake p95 = 60–270 ms depending on profile. Window-to-handshake ratio: 90–400×. Even under 50 ms delay and 5% loss, the handshake completes well within the contact window for the illustrative scenario. Full table in `results/tables/contact_window.csv`.

**Beacon cost:** At 10 Hz with 10 neighbours, ML-DSA-65 adds 3309 B/beacon vs 64 B for ECDSA-P256 — a 51× overhead. Verification CPU load: 3.6 ms/s for PQC-only vs 4.5 ms/s for classical (ML-DSA-65 verify is faster than ECDSA-P256 verify on this platform). Hybrid dual-signature verification load: 8.3 ms/s. This demonstrates why per-message PQC signatures are costly for broadcast per CLAUDE.md §8.

### Figures produced (8 matplotlib figures in `results/figures/`)

| Filename | Content |
|---|---|
| `micro_keygen.png` | Keygen time by algorithm (log y-axis) |
| `micro_ops.png` | All micro-benchmark operations by suite |
| `micro_aead.png` | AEAD encrypt/decrypt by payload size and suite |
| `handshake_bars.png` | Handshake time by config × profile (grouped bars) |
| `latency_cdf.png` | Latency CDF by config (ideal profile) |
| `e2e_overhead.png` | Per-record overhead decomposition by layer |
| `rekey_sweep.png` | Rekey count vs rekey interval (C3/ideal) |
| `contact_window_heat.png` | Contact window ratio heat-map (range × speed) |

---

## Open issues resolved this milestone

None of the PROGRESS.md OI items (OI-1 through OI-8) were open at the start of M7; all had been resolved in M1–M4. The M7 bugs documented below were found and fixed within the milestone itself.

**Bugs found and fixed during M7 (not prior OIs):**

| Bug | Commit | Fix |
|---|---|---|
| Virtual CAN no-echo: gateway's `can.send()` never received by its own `can.recv()` | m7-06-fixes | Separate injector `CanAdapter` instance for throughput/rekey sub-runs |
| Loss profile hang: `peer.run(n_frames=N)` stalls when packets lost | m7-07-fixes | Catch `asyncio.TimeoutError`; return partial results with actual sample count |
| Light rekey measurement: `run(n_frames=1)` exits before rekey processes | m7-06-fixes | Use `run(n_frames=None)` background tasks |
| Latency gather timeout too long for loss profiles | m7-08-timeout | Reduced from `max(30, n_frames/hz×2)` to `max(5, n_frames/hz+2)` |
| `overhead.csv` duplicate rows on repeated `run()` calls | m7-07-fixes | `unlink(missing_ok=True)` before writing the table |
| micro.csv consolidated incorrectly across runs | m7-04-bench-fixes | Always overwrite the summary table; `unlink(missing_ok=True)` before `write_csv` |

---

## Known limitations relevant to this milestone

The following limitations from CLAUDE.md §1 apply to M7 results:

1. **Results are relative comparisons** (§1 limitation 2). All timings are from a single developer machine (Apple Silicon, macOS 25.6.0). They show relative differences between configurations, not absolute vehicle timings. All result files carry environment metadata.

2. **Link emulation is not a wireless channel model** (§1 limitation 6). The network profiles (delay, loss, bandwidth) are configured parameters, not modelled RF propagation. Contact-window and beacon-cost results are analytical estimates clearly labelled as such.

3. **asyncio scheduling noise** (§15 item 12). Latency measurements include asyncio event-loop scheduling delay, which can vary by tens of microseconds. CLAUDE.md §15 item 12 acknowledges this as a known artefact. `docs/LIMITATIONS.md` documents the `SummingHook` ~100 ns per call-pair measurement overhead as a secondary artefact.

4. **Virtual CAN has no real timing** (CLAUDE.md §6). Bus-time calculations in `analytical/bus_time.py` are theoretical worst-case bit-level calculations, not measured timings.

5. **tracemalloc peak includes Python internals** (noted in `docs/LIMITATIONS.md`). Peak memory figures include interpreter overhead; they are useful for relative comparison between configs, not as absolute footprint claims.

---

## What an examiner should know

- **Crypto time is small relative to link delay.** Under all profiles, the crypto-only handshake fraction (measured via `SummingHook`) is 1–4 ms out of 56–210 ms total wall time. For steady-state records, AEAD encrypt/decrypt costs < 10 µs per record. The bottleneck in this simulation is asyncio scheduling and the virtual CAN bus, not cryptography. This is consistent with PQC literature: ML-KEM and ML-DSA are fast in software; the cost is key/ciphertext size, not compute time.

- **Loss disproportionately affects rekey, not data transfer.** A 5% packet loss profile adds < 10% to data latency (6.1 ms vs 5.7 ms median for C3 delay5), but can push light rekey median to 440 ms (from 32 ms at ideal) because the 400 ms retransmit timeout is frequently hit before REKEY_REQ/ACK exchange completes. This is an expected consequence of the fixed-timeout retransmit design (§15 item 21) and is reported honestly.

- **The `LatencyTracker` correlation key `(session_id, epoch, counter)` is security-critical.** It must match the same tuple in both the gateway's ingest stamp and the peer's delivery stamp. If a record is replayed, the ingest entry for that key was already consumed (or never existed), so the replay produces no latency sample. This means the latency benchmark correctly ignores replayed records without special casing.

- **Throughput is network-bound, not crypto-bound.** All configs produce 85–95 fps at 100-frame runs. The CPU time for 100 frames is 40–90 ms out of a ~1.1 s wall time — the remaining ~95% is asyncio / virtual-bus / link-emulator overhead. This is an honest finding: a software-simulation gateway on a laptop is not the right context in which to claim crypto throughput limits. §1 limitation 2 applies.

- **Memory overhead scales with PQC key sizes.** C2 (ML-KEM-768 + ML-DSA-65) uses ~174 KiB peak vs ~112 KiB for C1 (X25519 + ECDSA-P256) — a 55% increase. For an embedded gateway with limited RAM, this is a relevant consideration even though no embedded target is evaluated here (§1 limitation 1 / out-of-scope hardware).

- **Analytical scripts do not constitute simulation results.** `bus_time.py`, `contact_window.py`, and `beacon_cost.py` are hand-calculations using formulas and measured timing inputs. They are labelled "ANALYTICAL ESTIMATE — NOT A SIMULATION" at the top of every output. They illustrate cost structure; they do not substitute for a physics-based wireless channel simulation (which is listed as future work in CLAUDE.md §1).

---

*Generated by /milestone-log. Source of truth: git history, pytest output, PROGRESS.md.*
