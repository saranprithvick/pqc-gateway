# Known Limitations

The six limitations below are stated verbatim in the project scope (CLAUDE.md §1).
They must be preserved in all documentation and results files.

---

## 1. Unauthenticated legacy CAN bus

The legacy CAN side stays unauthenticated.  The gateway protects only the
gateway↔peer link.  A forged frame on the CAN bus is forwarded (protected) by
the gateway.  Security test T12 asserts and documents this behaviour; it is a
known non-prevention, not a bug.

## 2. Relative timing results

Results are **relative** comparisons between configurations on a laptop/desktop,
not real-vehicle timings.  All numbers are labelled with the hardware they were
measured on (Python version, OS, CPU, liboqs version, git commit) so they can be
reproduced on the same machine but should not be compared against on-vehicle
measurements.

## 3. Custom, unverified protocol

The handshake is a **custom protocol, not formally verified**.  It follows
TLS 1.3-style patterns (dual nonces, transcript binding, FINISHED MAC, separate
per-direction keys) but is not TLS and has not been subject to formal analysis
or external security review.

## 4. Limited algorithm agility

Agility covers only algorithms that fit the four interfaces defined in the
Crypto-Abstraction Layer (KEM, Signature, KDF, AEAD).  No claim is made about
future algorithms or about algorithms that require interface extensions.

## 5. FN-DSA and HQC are experimental

FN-DSA and HQC are included only if the installed liboqs exposes them, and are
labelled experimental.  Falcon (pre-standard) is exposed as `falcon-*` if
present.  These entries are skipped in the agility test suite if the mechanism
is absent; they are not part of the C1–C3 baseline configurations.

## 6. Link emulation is not a wireless channel model

The LinkEmulator is a parameterised delay/jitter/loss/bandwidth model running
in the same Python process.  It does not model a physical wireless channel,
radio propagation, 802.11p PHY/MAC, C-V2X, or multi-path fading.  The network
profiles (ideal, delay5…delay50, loss1/5%, bw6000kbps) are illustrative
parameter choices, not measurements of any real radio link.

---

## Measurement limitations (added in M7)

### Crypto hook overhead

Crypto time is measured via optional in-code hooks (`SummingHook`) that call
`time.perf_counter_ns()` immediately before and after each crypto operation.
The `perf_counter_ns()` call overhead is approximately 100 ns on the test
hardware, which is systematic and negligible relative to typical crypto
operation times (µs–ms range).  The hook is a no-op when not attached.

### asyncio scheduling noise

Latency measurements include asyncio event-loop scheduling noise (typically
tens of µs on a desktop OS).  This is covered by limitation 2 (relative results
only).  Crypto time and link delay are reported separately to allow comparison
across configurations.

### tracemalloc separation

Peak-memory measurements use a separate, non-timed `tracemalloc` run so that
the allocator tracing does not affect throughput timing.  The two runs are
consecutive (not interleaved), so they may differ slightly in GC state.

### IP/UDP headers not modelled

The LinkEmulator operates at a logical message level.  IP, UDP, and Ethernet
headers are not modelled.  Overhead figures report only the pqcgw-protocol
bytes (baseline frame + fragment header + type prefix + record header + AEAD
tag).  Real deployment would add ≥28 B per datagram (IPv4/UDP) or ≥48 B (IPv6).
See also CLAUDE.md §15 item 17.

### Loss and fragmentation

The fragment reassembly model is stop-and-wait: a lost fragment loses the
entire message, requiring a retransmission of the whole handshake message.
This inflates retransmit counts and latency at higher loss rates.  It is an
expected finding, not a bug.

### C0 latency not measured

C0 (passthrough) latency via `PassthroughPath` is not measured in the M7
benchmark harness because `PassthroughPath` does not expose the same
`LatencyTracker` hooks as `Gateway`/`ModernPeer`.  Overhead for C0 is
computed analytically (baseline + fragment header bytes).

### Python cannot guarantee key zeroization

The key schedule and rekey ratchet overwrite the previous `rekey_sec` by
returning a new `SessionKeys` object whose `rekey_sec0` field holds the new
secret.  Python's garbage collector controls when the old object's memory is
reclaimed and may not zero it.  This is a documented limitation of using Python
for security-critical code; it does not affect the correctness of the protocol.

### Full-rekey timing includes an unresolved event-loop wait

The full-rekey asyncio task starts on the next event-loop iteration after
`request_full_rekey()` is called.  Measured full-rekey wall time therefore
includes at least one event-loop scheduling delay (typically tens of µs on a
desktop OS) in addition to the new handshake's crypto and link time.

### Rekey triggers checked on each run-loop iteration (~10 ms)

The Gateway run loop uses `asyncio.wait_for` with a ~10 ms timeout to poll for
CAN frames.  Automatic rekey triggers (elapsed time, record count, byte count)
are checked once per loop iteration, so the actual trigger may fire up to ~10 ms
after the configured threshold is crossed.

### Constant ~6–8 ms overhead in handshake wall time on delay profiles

Handshake timing on delay profiles shows a constant offset of approximately
6–8 ms above the expected value (≈ 4 × delay_ms + ideal_time).  This is
consistent across C1–C3 and all delay settings.  The source has not been
isolated; the offset is likely a combination of asyncio event-loop scheduling,
python-can virtual bus overhead, and task startup time.  It does not affect the
relative comparison between configurations.

### Apple arm64 only

All benchmark numbers were collected on Apple arm64 (M-series, macOS 25.6.0,
Python 3.13.2, liboqs 0.16.0).  Absolute values on other hardware will differ.
See limitation 2 (relative timing results).

### Analytical scripts are estimates

The three analytical scripts (`bus_time.py`, `contact_window.py`,
`beacon_cost.py`) produce illustrative estimates using configurable parameters
and measured timing from the benchmark runs.  They are labelled "Analytical
estimate, not a simulation." in their output headers.  The contact-window and
beacon-cost estimates in particular depend on assumed vehicle speeds, ranges,
and beacon rates that are not derived from any standard or measurement.
