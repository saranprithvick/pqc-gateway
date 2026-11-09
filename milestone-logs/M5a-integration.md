# M5a: Integration — CAN stack, link emulator, gateway, peer, E2E tests

**Date completed:** 2026-11-05
**Branch:** m5a-integration
**Commits:** 3 (8e59294 m5a-01-can, 247f703 m5a-02-net, 26d85e0 m5a-03-core)
**Tests:** 226 passed, 0 failed (up from 164 after m4-fixes pre-merge)

---

## What was implemented

### CAN frame model (`src/pqcgw/legacy/can_model.py`)
`CANFrame` dataclass for one CAN 2.0 or CAN FD data frame. Fields: `can_id`, `dlc`
(actual payload byte count), `data`, `is_fd`, `is_extended`. `__post_init__` validates
the arbitration ID against its type (11-bit for standard, 29-bit for extended) and
validates `dlc` against `VALID_FD_LENGTHS` (the non-contiguous DLC code table 0–64 B)
for FD frames or 0–8 for CAN 2.0 frames. Constants `MSG_EFF_FLAG` (bit 31),
`MSG_FD_FLAG` (bit 29), and `MSG_ID_MASK` (bits 28:0) encode the flags that are
packed into the 4-byte wire field.

### CAN adapter (`src/pqcgw/legacy/can_adapter.py`)
`CanAdapter` wraps a `python-can` Bus on the `virtual` interface. `send()` converts a
`CANFrame` to a `can.Message` and transmits it; `receive(timeout)` calls `bus.recv()`
and converts back, dropping malformed messages with a warning log rather than raising.
Supports context manager. `is_fd=True` opens the bus in CAN FD mode. The `virtual`
interface is pure-Python and requires no OS setup, so tests run on any platform.

### Legacy node (`src/pqcgw/legacy/legacy_node.py`)
`LegacyNode` holds a list of `TrafficProfile` entries (each with `can_id`, `rate_hz`,
`dlc`, `payload_pattern`, `is_fd`, `is_extended`). `emit_one(profile_idx)` generates
one frame according to the matching profile and transmits it via `CanAdapter`. Three
payload patterns: `counter` (incrementing 8-bit value in first byte, rest zeros),
`zeros`, and `random` (per-profile seeded `random.Random` for reproducibility). Rate
scheduling and command forwarding are deferred to M7; in M5a the node generates frames
only on demand. Validation of `TrafficProfile` mirrors `CANFrame` validation.

### Message adapter (`src/pqcgw/nodes/adapter.py`)
`MessageAdapter` encodes and decodes a single CAN frame to/from record plaintext bytes.
Wire layout: 4-byte encoded `can_id` (big-endian uint32 containing the arbitration ID
plus `MSG_EFF_FLAG` and `MSG_FD_FLAG`) followed by 1-byte `dlc` and `dlc` bytes of
payload data — matching CLAUDE.md §5.5. `decode()` validates every field (minimum
length, dlc bounds, payload length matches dlc) and raises `ValueError` on any
violation before constructing a `CANFrame`. This is a separate module as required by
CLAUDE.md §3 (report component "Protocol / Message Adapter").

### Link interface and loopback (`src/pqcgw/net/link.py`)
`Link` abstract base class with two async methods: `send(msg: bytes)` and `recv(timeout)
-> Optional[bytes]`. `LoopbackLink` implements `Link` backed by a pair of
`asyncio.Queue` objects; `LoopbackLink.make_pair()` returns `(gateway_half, peer_half)`
where `gateway_half.send()` feeds `peer_half.recv()` and vice versa. Used in all C0–C3
unit tests where network impairment is not under test.

### Fragmenter and reassembler (`src/pqcgw/net/fragment.py`)
`fragment(msg_id, payload, mtu)` splits a payload into fragments each at most `mtu`
bytes including an 8-byte header (`msg_id uint32`, `frag_idx uint16`, `frag_count uint16`,
big-endian). Single-fragment messages include the header with `frag_count=1`. `Reassembler`
class collects fragments by `msg_id` and returns the reassembled message bytes when all
fragments arrive. Defensive parsing: `frag_idx >= frag_count` raises `ValueError`
(hard reject); `frag_count > MAX_FRAG_COUNT` (256) or reassembled size > `MAX_MSG_BYTES`
(65536) are silently dropped; duplicates are ignored; stale partials older than
`STALE_TIMEOUT_S` (5 s) are evicted; concurrent pending messages capped at `MAX_PENDING`
(64) with oldest evicted on overflow.

### Link emulator (`src/pqcgw/net/emulator.py`)
`LinkEmulator` implements a bidirectional emulated link. `NetworkConfig` dataclass holds
`delay_ms`, `jitter_ms`, `loss_pct`, `bandwidth_kbps`, `reorder_pct`, `mtu_bytes`, and
`seed`; it can be loaded from a TOML file via `NetworkConfig.from_toml()`. Two
`asyncio.Task` impairment coroutines (one per direction) run in a lazy start: each
accepts a message, calls `fragment()` to split to `mtu_bytes`, then per fragment applies
Bernoulli loss (seeded per-direction sub-RNG) and sleeps for `delay_ms ± jitter_ms`
(clamped ≥ 0) before feeding to `Reassembler`. `make_pair(config)` returns
`(gateway_link, peer_link)` as `Link` instances, with `._emulator` attached for
fragment counter inspection. Reorder and bandwidth-cap are noted as deferred to M7.

### Network config files
- `configs/network/ideal.toml` — zero delay, zero loss, 1500-byte MTU, seed 42.
- `configs/network/lossy.toml` — 5 ms delay, 1 ms jitter, 1% loss, 6000 kbps
  bandwidth, 1500-byte MTU, seed 42.

### C0 passthrough (`src/pqcgw/nodes/passthrough.py`)
`PassthroughPath` implements the C0 baseline: no handshake, no crypto.
`run_gateway_side(can_adapter, link, n_frames)` reads CAN frames and encodes them with
`MessageAdapter.encode()` before forwarding over the link. `run_peer_side(link, sink, n_frames)`
decodes and places frames in a sink queue. Wire framing uses the same 5-byte
`can_id+dlc` prefix as C1–C3; the 8-byte fragment header is applied by the
`Link`/`Emulator` layer transparently. This matches CLAUDE.md §15 item 17: fair
overhead comparison uses minimal framing only.

### Gateway (`src/pqcgw/nodes/gateway.py`)
`Gateway` is the async handshake initiator and bidirectional CAN↔link forwarder.
`handshake()` sends `HELLO_I` and waits for `HELLO_R` with exponential-backoff
retransmit (default timeout 200 ms, max 5 retries). After receiving `HELLO_R` it starts
the `_buffer_can()` background task (§15 item 20 pre-session buffer, bound `deque` of
64 frames) and then sends `FINISHED_I` with the same retransmit loop. After
`FINISHED_R` is verified a `SessionManager` is constructed and the pre-session buffer is
flushed into the data path. `run(n_frames)` calls `handshake()` then enters the
bidirectional loop: I2R reads from CAN and calls `seal()`, R2I reads from the link and
calls `open()`. `send_frame()` catches `CounterExhausted` and buffers the unsent frame
in `_pending` (another bounded deque of 64) while queuing the `REKEY_REQ` via
`take_outbound()`. Instrumentation properties: `handshake_success`, `handshake_retransmit_count`,
`handshake_duration_ns`, `pre_session_drops`, `pending_drops`.

### Modern peer (`src/pqcgw/nodes/peer.py`)
`ModernPeer` is the async handshake responder. `handshake()` awaits `HELLO_I`, sends
`HELLO_R`, then loops on inbound messages: a byte-identical `HELLO_I` retransmit causes
the cached `HELLO_R` to be resent without re-encapsulating (§15 item 9). Once a
`FINISHED_I` is received it is processed and `FINISHED_R` sent; both are cached for
the data phase. `_handle_inbound()` checks whether the incoming wire bytes equal the
cached `FINISHED_I` (data-phase retransmit scenario per §15 item 20) and resends the
cached `FINISHED_R` if so; DATA records received before the session is established are
dropped. `run(n_frames, commands)` accepts an optional list of R2I `CANFrame` commands
to send to the gateway; `n_frames=None` runs indefinitely (needed for loss/retransmit
tests where the peer must stay alive to handle FINISHED_I retransmits).

### Attacker (`src/pqcgw/attacks/attacker.py`)
`Attacker` opens a `python-can` virtual bus on a specified channel and provides
`inject_can_frame(frame)`. Labelled "FOR TESTS ONLY" in module docstring and class
docstring; not part of the production gateway path. Used by T12 to inject a forged
frame on the same channel the Gateway is reading from.

### Test infrastructure (`tests/conftest.py`)
`can_channel` fixture returns a unique 8-character hex-suffixed string per test
(e.g. `m5_3f8a2c10`). This prevents cross-test contamination on the shared in-process
virtual bus: each test gets its own channel namespace.

### Unit tests: CAN model (`tests/unit/test_can_model.py`)
Tests for `CANFrame` construction, `MSG_EFF_FLAG`/`MSG_FD_FLAG`/`MSG_ID_MASK` constants,
CAN 2.0 and FD DLC validation, standard vs extended ID bounds, `MessageAdapter.encode()`
round-trips, and `MessageAdapter.decode()` rejection of truncated, inconsistent, and
out-of-bounds inputs.

### Unit tests: fragmenter and reassembler (`tests/unit/test_fragment.py`)
Single-fragment and multi-fragment round-trips, partial delivery returning `None`,
out-of-order delivery, duplicate fragment suppression, stale eviction, concurrent
message interleaving, and `ValueError` on structurally invalid `frag_idx >= frag_count`.

### Unit tests: link emulator (`tests/unit/test_link_emulator.py`)
`NetworkConfig.from_toml()` parses both network configs; ideal-config sends and receives
unchanged; lossy-config drops some fragments at 50% loss; `fragments_sent_i2r` counter
increments correctly; delay is applied.

### End-to-end tests over LoopbackLink (`tests/unit/test_e2e.py`)
Six tests:
1. `test_e2e_c0_passthrough` — C0 passthrough forwards 5 CAN frames without crypto.
2. `test_e2e_c1_classical` — C1 (X25519 + ECDSA-P256) handshake + 5 I2R frames.
3. `test_e2e_c2_pqc` — C2 (ML-KEM-768 + ML-DSA-65) handshake + 5 I2R frames.
4. `test_e2e_c3_hybrid` — C3 (hybrid KEM + dual signatures) handshake + 5 I2R frames.
5. `test_e2e_reverse_path` — Peer sends 2 R2I command frames; Gateway writes them to CAN; a third adapter reads them back.
6. `test_e2e_pre_session_buffer` — CAN frames injected while Gateway awaits `FINISHED_R` are buffered and flushed after session establishment.

### End-to-end tests over LinkEmulator (`tests/unit/test_e2e_link.py`)
Two tests:
1. `test_e2e_c1_fragmented_handshake` — C1 handshake succeeds over `mtu_bytes=200`; every HELLO message is fragmented; 3 I2R frames arrive correctly; zero retransmits at zero loss.
2. `test_e2e_c1_loss_retransmit` — C1 handshake succeeds at 30% loss (seed 42, 5 ms delay); Gateway retransmit counter is non-negative; handshake both sides report success.

### Security test: T12 (`tests/security/test_t12.py`)
`test_t12_forged_can_frame_forwarded` — an `Attacker` injects a forged CAN frame
(extended ID 0xDEAD, data `\xDE\xAD\xBE\xEF`) onto the same channel the Gateway is
reading. The test asserts the frame DOES arrive at the peer (known limitation, not a
bug). The assertion message names the limitation explicitly: "KNOWN LIMITATION: Gateway
forwarded a forged CAN frame unchanged."

---

## Why it was implemented this way

### Why the CAN adapter uses the `virtual` interface rather than SocketCAN `vcan`

CLAUDE.md §6 specifies `python-can` with the `virtual` interface (pure-Python) as the
primary target; SocketCAN `vcan` is optional on Linux. The `virtual` interface requires
no OS configuration and runs on macOS, Windows, and Linux without root or kernel module
setup, which is consistent with CLAUDE.md §15 item 1 ("on the student's own machine via
terminal Claude Code"). All test isolation relies on unique channel names, not on OS
namespacing.

### Why sends from a sender bus are not visible on the same bus instance

The `python-can` virtual bus does not echo a message back to the bus instance that sent
it. This matches the behaviour of a real CAN bus (a node does not receive its own
transmissions). Tests that need to inject frames the Gateway will read must open a
separate `CanAdapter` instance on the same channel — a sender instance distinct from the
receiver instance. This is documented in `test_e2e.py`'s module docstring and in the
`_inject()` helper. The `conftest.py` fixture ensures channels are unique per test to
prevent injected frames from leaking into unrelated tests.

### Why the `_buffer_can` cancel race was fixed with `asyncio.wait` rather than immediate `cancel()`

After `FINISHED_R` is processed, `_buffering` is set to `False`. The buffering task calls
`can_adapter.receive(0.05)` via `run_in_executor()` — once the executor thread has started
the blocking `bus.recv()` call, cancelling the future does not stop the underlying thread;
the thread consumes the next frame from the virtual bus and discards it. Using
`asyncio.wait({buf_task}, timeout=0.15)` gives the task one more receive cycle to notice
`_buffering=False` and exit cleanly. This avoids losing a CAN frame that arrives during
the FINISHED exchange. The fallback `cancel()` after 0.15 s is a last resort that fires
only if the task is unaccountably slow.

### Why HELLO_I retransmit in the peer uses a byte-identical check rather than parsing

CLAUDE.md §15 item 9 specifies: "the responder caches HELLO_R keyed by
`(session_id, H(HELLO_I))` for the handshake timeout and resends it byte-identical, with
no repeated encapsulation or signing." The implementation compares the inbound wire bytes
to the cached `_cached_hello_i` directly. This is correct because HELLO_I is a fixed
serialisation of a deterministic structure; two runs of the same HELLO_I generation
produce identical bytes. The byte-identical check is simpler and cheaper than parsing and
re-hashing, and it is functionally equivalent: a retransmit is the same message, so wire
equality implies semantic equality in this context.

### Why the peer loops on inbound messages during the FINISHED_I phase

After sending `HELLO_R`, the peer may receive another copy of `HELLO_I` before it
receives `FINISHED_I` (if the gateway did not receive `HELLO_R` on the first attempt and
retransmits). The inner `while True` loop in `peer.handshake()` handles this transparently:
`HELLO_I` retransmits are served without leaving the handshake function and without
creating a new responder object. This avoids a race where the responder has committed the
encapsulation but the gateway's state machine is still in the HELLO_I phase.

### Why DATA records received before FINISHED_I are dropped at the peer (§15 item 20)

The `SessionManager` is not instantiated until after `process_finished_i()` succeeds, so
any DATA record received before that point cannot be opened. CLAUDE.md §15 item 20 states
explicitly: "The responder drops any DATA record that arrives before it has verified
FINISHED_I." This is the correct secure behaviour: the responder has not yet derived the
session keys.

### Why FINISHED_I retransmit in the data phase is handled in `_handle_inbound()`

After the session is established, the gateway may retransmit `FINISHED_I` if
`FINISHED_R` was lost in transit. The peer's `_handle_inbound()` checks whether the
incoming bytes equal `_cached_finished_i` before attempting `SessionManager.open()`.
If they match, the cached `FINISHED_R` is resent and the method returns without touching
the session state. This prevents the `SessionManager` from treating a retransmitted
`FINISHED_I` as an unknown record (which would result in a replay-window rejection) and
ensures the gateway can complete its handshake even when the last leg is lost.

### Why PassthroughPath uses the same `MessageAdapter` encoding as C1–C3 (§15 item 17)

CLAUDE.md §15 item 17 defines the fair overhead comparison rule: C0 uses minimal framing
(`can_id 4 B, dlc 1 B, data`), which is what a real unsecured link would carry. The same
encoding is used in C1–C3. The 8-byte fragment header is applied by the
`Link`/`LinkEmulator` layer uniformly to every configuration. This means the overhead
comparison is: C0 baseline (5 B + fragment header per frame), C1–C3 add the 16-byte
record header and 16-byte AEAD tag.

### Why the Gateway uses `n_frames=None` for the reverse-path and loss tests

The gateway must continue processing R2I records (commands from the peer) after all I2R
frames have been forwarded. If `n_frames` were finite the gateway would exit before the
peer's command frames could be opened and written to the CAN bus. For the loss test
(`test_e2e_c1_loss_retransmit`), the peer must remain alive after the gateway exits
handshake so it can respond to `FINISHED_I` retransmits if `FINISHED_R` was dropped.
Using `n_frames=None` and task cancellation from the test harness is the cleanest pattern
that handles both cases without special-casing the data loop.

### Why the Attacker opens its own bus instance rather than sharing one with CanAdapter

A `can.Bus` instance on the `virtual` interface can send and receive, but its own sends
are not echoed to itself. If the Attacker shared the Gateway's `CanAdapter` bus it would
not be able to inject a frame that the Gateway's receive loop could read. Opening a
separate bus on the same channel means the Attacker's `send()` is visible to any other
bus on that channel, which is exactly the threat model: physical access to the CAN bus
allows injection from a device the gateway does not control.

### Why the `can_channel` fixture uses a UUID prefix

The `python-can` virtual interface maintains in-process channel state keyed by channel
name. If two concurrently running tests share a channel name, frames injected by one test
can arrive on the other's bus. Using a UUID-derived prefix per test (`m5_<8-hex>`)
makes collision probability negligible and removes all ordering dependencies between
tests. The `m5_` prefix makes it easy to identify these channels in log output.

---

## Key results and test evidence

### Test summary

226 tests collected, 226 passed, 0 failed, 0 skipped.

Breakdown by milestone of origin:
- 6 smoke (M0)
- 51 unit crypto (M1)
- 18 unit handshake + 10 security T4/T5/T6/T13 (M2)
- 19 unit record + 14 security T1/T2/T3/T7/T9/T11 (M3)
- 10 unit rekey + 9 security T8/T10 + 2 security T9 rekey span + 25 OI regressions (M4/m4-fixes)
- **62 new in M5a:** CAN model, fragmenter, link emulator, E2E loopback (C0–C3), E2E over
  LinkEmulator (fragmented + lossy), T12, plus conftest fixture.

### C0–C3 end-to-end round-trip

All four configurations (C0 passthrough, C1 classical, C2 PQC-only, C3 hybrid) pass the
5-frame I2R round-trip test over `LoopbackLink`. Each test asserts:
- `gateway.handshake_success` and `peer.handshake_success` are both `True`.
- Exactly 5 frames are received at the peer.
- Each frame's `can_id` and `data` bytes match the original.

### Reverse path (R2I)

`test_e2e_reverse_path` verifies that two command frames sent by the peer (IDs 0x200 and
0x201) arrive on the CAN bus and are read by a third adapter instance. This exercises the
full R2I path: `ModernPeer.send_command()` → `SessionManager.seal(direction=R2I)` → link
→ `Gateway._handle_inbound()` → `MessageAdapter.decode()` → `CanAdapter.send()`.

### Pre-session buffer (§15 item 20)

`test_e2e_pre_session_buffer` injects 3 CAN frames from a separate sender immediately
before the gateway begins its handshake. The frames are queued in `_pre_session_buf`
during the HELLO/FINISHED exchange and flushed into the data path once the session is
established. All 3 frames arrive at the peer in order. This confirms the bounded deque
and the `asyncio.wait`-based cancel pattern work correctly.

### Fragmented handshake

`test_e2e_c1_fragmented_handshake` uses `mtu_bytes=200`. C1 HELLO messages (which include
ECDSA-P256 signatures and X25519 public keys) exceed 200 bytes, so each HELLO is split
into multiple fragments. The handshake succeeds, 3 DATA frames arrive correctly, and the
retransmit count is 0 (no loss in this test).

### Loss + retransmit

`test_e2e_c1_loss_retransmit` uses `loss_pct=30.0, seed=42, delay_ms=5`. The gateway
retransmits `HELLO_I` when `HELLO_R` is lost, and retransmits `FINISHED_I` when
`FINISHED_R` is lost. Both sides report `handshake_success=True`. The retransmit count is
asserted to be a non-negative integer (the exact count depends on the seed and loss path;
the test does not assert a specific value, only success).

### T12: known limitation documented

`test_t12_forged_can_frame_forwarded` asserts that a frame with extended ID 0xDEAD and
data `\xDE\xAD\xBE\xEF` injected by the `Attacker` arrives at the peer with matching
`can_id` and `data`. This is the expected behaviour of an unauthenticated CAN side. The
assertion message reads: "KNOWN LIMITATION: Gateway forwarded a forged CAN frame
unchanged. CAN-side authentication is out of scope (see docs/LIMITATIONS.md §1)."

---

## Open issues resolved this milestone

None of the formally tracked open issues (OI-1 through OI-8) were assigned to M5a; they
were all resolved in M1–M4 or the m4-fixes pre-merge hardening pass.

M5a does introduce one implementation note that was identified during development and
recorded in PROGRESS.md: the `_buffer_can` cancel race (the `asyncio.wait` solution
described above). This was an implementation subtlety, not a tracked open issue.

---

## Known limitations relevant to this milestone

**Limitation 1 (CLAUDE.md §1 item 1, documented by T12):** The legacy CAN side is
unauthenticated. The Gateway protects only the gateway↔peer link. A forged frame
injected onto the CAN bus is forwarded (sealed and transmitted) exactly as if it came
from a legitimate ECU. T12 asserts this. Mitigation (CAN-layer MAC or CAN XL) is out of
scope for this prototype. See `docs/LIMITATIONS.md` item 1 and `docs/THREAT_MODEL.md`.

**Limitation 2 (CLAUDE.md §1 item 2):** Results are relative comparisons on a
laptop/desktop, not real-vehicle timings. The virtual CAN bus has no real bus timing;
bus-time analysis is deferred to the analytical scripts in M7.

**Limitation 6 (CLAUDE.md §1 item 6):** Link emulation is not a wireless channel model.
The `LinkEmulator` provides configurable delay, jitter, and loss but no path model,
fading, or Doppler effects.

**Deferred within M5:** Light-rekey triggers in the async Gateway/Peer event loop,
REKEY_REQ retransmit over the link, full rekey (§15 item 16, parallel session), epoch-255
guard, and flush of `_pending` after REKEY_ACK are all deferred to M5b. The
`_pending` buffer accumulates frames on `CounterExhausted` but the flush path is not yet
wired (the buffer will be drained once the REKEY_ACK arrives in M5b).

**LegacyNode rate-driven emission** (§6 traffic profiles at configurable Hz rates) is
deferred to M7. In M5a the node generates frames only on explicit `emit_one()` calls.

---

## What an examiner should know

- **Why two bus instances are needed for injection.** The `python-can` virtual interface
  does not echo a node's own transmissions, matching the physical CAN bus behaviour. Any
  test that injects frames the Gateway must receive must open a *separate* `CanAdapter` or
  `Attacker` instance on the same channel. If a test sends from the gateway's own adapter
  the frames are never received. This is a property of the library, not a bug, and is
  documented in every test module that injects frames.

- **The pre-session buffer exists to avoid losing CAN frames during the handshake.** The
  handshake takes non-trivial time (especially for C2/C3 with ML-KEM and ML-DSA
  operations). CAN frames that arrive from the legacy ECU while the gateway is waiting for
  `FINISHED_R` would be lost if the gateway were only reading from the network link.
  CLAUDE.md §15 item 20 mandates a bounded queue (64 frames, drop-oldest with a drop
  counter). The queue is flushed immediately after session establishment so no frame is
  silently discarded without incrementing the drop counter.

- **T12 is an affirmative test of a known non-prevention.** Unlike T1–T11 which assert
  that attacks are blocked, T12 asserts that the gateway *does* forward a forged CAN
  frame. The assertion is positive and the test docstring names the limitation explicitly.
  An examiner should understand that this is a deliberate architectural constraint
  (CAN-side authentication is out of scope), not an oversight.

- **The 8-byte fragment header applies to every configuration including C0.** This is
  essential for the fair overhead comparison in M7. C0 carries `5 B frame encoding +
  8 B fragment header` per message; C1–C3 add `16 B record header + 16 B AEAD tag`. The
  fragment header overhead is the same across all configurations and therefore cancels
  out when comparing C1–C3 against C0. CLAUDE.md §15 item 17 mandates this design.

- **Handshake retransmit uses exponential backoff (I → R direction) but the peer uses a
  fixed long timeout.** The gateway doubles the timeout on each HELLO_I retransmit attempt
  (default 200 ms × 2^attempt). The peer's `handshake_recv_timeout` is a single fixed
  value (default 30 s) because the responder has no way to predict when the next HELLO_I
  will arrive; it simply waits. This asymmetry is intentional: the initiator drives
  retransmit timing; the responder is passive.

- **The `Attacker` class is structurally separated from the production path.** It lives in
  `src/pqcgw/attacks/` and is imported only by test files under `tests/security/`. The
  production modules (`Gateway`, `ModernPeer`, `PassthroughPath`) have no dependency on
  `attacks/`. This separation is enforced by the module structure and can be verified by
  import graph inspection.

- **M5b scope:** The rekey triggers in the async loop (elapsed time, record count, byte
  count), REKEY_REQ retransmit over the link, the full-rekey parallel-session path
  (§15 item 16), epoch-255 guard, and the `_pending` buffer flush after REKEY_ACK are all
  out of scope for M5a and will be added in M5b before the `m5-done` tag is applied.

---

*Generated by /milestone-log. Source of truth: git history, pytest output, PROGRESS.md.*
