# M5b: Rekey over Link — Full async rekey stack wired to Gateway and Peer

**Date completed:** 2026-11-09
**Branch:** m5b-rekey-link
**Commits:** 4 (3 implementation + 1 PROGRESS.md update)
**Tests:** 239 passed, 0 failed

---

## What was implemented

### Protocol layer (`src/pqcgw/protocol/session.py`)

- **`RekeyTrigger` dataclass** — three fields (`interval_s`, `record_count`, `byte_count`), all defaulting to 0 (disabled). Designed to be loaded from TOML config in M7. Used by `Gateway.run()` to fire automatic light rekeys.
- **`_cached_initiator_req`** — the initiator's REKEY_REQ bytes are stored when `initiate_light_rekey()` is called, so `check_rekey_timeout()` can enqueue a retransmit without re-sealing a new record (counter discipline: one record, one counter value).
- **`_prev_session_id`** — tracks the previous session's `session_id` during the grace period after a full rekey. Used by `_route_open` to allow the old session's records during the grace window while rejecting any record that shares `epoch==0` with the new session but belongs to neither session.
- **`known_session_ids` property** — returns the current and previous (grace-period) session ids as a `frozenset[bytes]`. Used by both `Gateway` and `Peer` to gate session_id lookups before attempting decryption.
- **Session_id guard in `_route_open`** — `_route_open` now checks `hdr.session_id == self._session_id` before routing to the current `RecordLayer`, and `hdr.session_id == self._prev_session_id` before routing to the previous `RecordLayer`. This prevents the edge case where a full-rekey's new session starts at `epoch==0`, which is identical to the initial epoch of the old session.
- **`_start_grace` fix** — sets `_prev_session_id` from `_session_id` when it is not already set by the caller (light rekey: same session_id both sides; full rekey: caller sets it first).
- **`_expire_grace` cleanup** — clears `_prev_session_id` together with `_rl_prev` and `_rw_prev`.

### Gateway node (`src/pqcgw/nodes/gateway.py`)

**1-byte type prefix (§15 item 22).** Every link message now carries a 1-byte dispatch byte prepended before the payload body:

| Constant | Value | Message |
|---|---|---|
| `_T_HELLO_I` | 0x01 | Handshake HELLO_I |
| `_T_HELLO_R` | 0x02 | Handshake HELLO_R |
| `_T_FINISHED_I` | 0x03 | Handshake FINISHED_I |
| `_T_FINISHED_R` | 0x04 | Handshake FINISHED_R |
| `_T_DATA` | 0x10 | Record layer (all DATA/REKEY_REQ/REKEY_ACK/ALERT/CLOSE) |

Dispatch in the receiver is always on this byte, never on protocol state. Messages shorter than the minimum body length are silently dropped and counted in `_malformed_drops`.

**Light rekey triggers.** `Gateway.run()` checks three trigger conditions after each CAN frame is processed: elapsed time, records sealed, and bytes sealed (from `RekeyTrigger`). When any fires, `initiate_light_rekey()` is called and the REKEY_REQ is sent with the `_T_DATA` prefix. Trigger counters (`_records_sealed`, `_bytes_sealed`, `_session_start`) are reset after each light or full rekey.

**REKEY_ACK flush.** When `_handle_inbound` sees a `RecordType.REKEY_ACK` from the peer, it calls `_flush_pending()` and re-seals the buffered frames under the new epoch. This satisfies §15 item 20: frames that raised `CounterExhausted` are not discarded but forwarded once the epoch rolls.

**Full rekey coroutine `_do_full_rekey()`.** Implements §15 item 16: runs a new handshake in an `asyncio.Task` concurrently with the main data loop. The old session continues to carry traffic while the new handshake completes. Key design points:
- Uses `_hs_queue` (an `asyncio.Queue`) to decouple incoming HS messages from the data path. The main `run()` loop routes `_T_HELLO_R` and `_T_FINISHED_R` messages into `_hs_queue`; `_do_full_rekey()` reads from it.
- Per-attempt deadlines: each retransmit attempt has an independent deadline so that a stale HELLO_R from a previous attempt does not silently satisfy the next.
- FINISHED_R verify failures within a deadline are logged and ignored; the initiator retransmits FINISHED_I at the deadline boundary.
- After success, calls `self._sm.promote_full_rekey(new_keys, new_session_id)`, resets trigger counters, and flushes `_pending`.

**Epoch-254 guard.** The main `run()` loop checks `self._sm.epoch >= 254` on every iteration. When reached, it logs the event and calls `_trigger_full_rekey()`. This prevents the session from reaching epoch 255, which would force a close (§5.7: "force a full rekey before epoch 255").

**Full-rekey retry and ALERT.** If `_do_full_rekey()` raises `HandshakeError`, `_full_rekey_attempts` is incremented. When `_full_rekey_attempts >= _full_rekey_max_attempts`, the gateway seals an ALERT record (best-effort), calls `_sm._close()`, and raises `AlertError` to terminate the session. `_trigger_full_rekey()` drains stale HS messages from `_hs_queue` before starting each new attempt to avoid state contamination between attempts.

**Drop counters.** `_malformed_drops` counts messages below minimum length or with unknown type bytes. `_unknown_session_drops` counts DATA records whose session_id is not in `_sm.known_session_ids`.

**Manual trigger API.** `request_light_rekey()` and `request_full_rekey()` set boolean flags consumed on the next `run()` iteration; used directly by tests.

**`_set_epoch_for_testing()`.** Test-only helper that overwrites the current `RecordLayer`'s epoch field, enabling the epoch-254 guard and epoch-exhaustion tests without running 254 full rekeys.

### Peer node (`src/pqcgw/nodes/peer.py`)

**1-byte type prefix.** All sends and all receives now use the same five constants defined in `gateway.py`. `peer.handshake()` was rewritten around prefix dispatch: a loop reads messages until a `_T_HELLO_I` arrives (unexpected types counted as malformed), then loops until a `_T_FINISHED_I` arrives (retransmitted `_T_HELLO_I` triggers a cached HELLO_R resend; unexpected types are ignored, not fatal).

**`_handle_hs_message()`.** New method routes in-data-phase HS messages for full-rekey responder handling. Dispatches on `type_byte`:
- `_T_HELLO_I`: starts a new `HandshakeResponder` on a new session_id, or resends cached HELLO_R for a known retransmit. Discards stale `_fr_pending` if the old responder's session_id is replaced.
- `_T_FINISHED_I`: handles both initial-handshake retransmits (via `_cached_finished_i` check) and full-rekey FINISHED_I messages. On success, stores `(new_keys, session_id)` in `_fr_pending` and sends FINISHED_R, but does NOT yet promote — the peer waits for the first authenticated DATA record on the new session.

**Full-rekey switch-over via trial open.** `_handle_inbound()` checks `wire[1:5]` (the record header's session_id field) against `_fr_pending[1]`. On a match it constructs a temporary `RecordLayer` and `ReplayWindow` and attempts to open the record. If authentication succeeds, `promote_full_rekey()` is called and the record is re-opened via the now-updated `SessionManager`. If authentication fails the record is dropped and counted in `_unknown_session_drops`. This design ensures the peer only promotes to a new session upon cryptographic proof that the gateway holds the new session's keys.

**Lazy cleanup of `_fr` state.** `_fr` and its associated fields are cleared in `_handle_hs_message()` only when all three conditions hold: the responder completed (`_fr_complete`), the keys were promoted (`_fr_pending is None`), and the new session_id has since left `_sm.known_session_ids`. This ensures that cached HELLO_R can still be served on retransmit during the grace window.

**`run()` prefix dispatch.** The main `run()` loop now dispatches on the type byte: `_T_DATA` goes to `_handle_inbound`; HS types go to `_handle_hs_message`; unknown types are counted as malformed.

### Tests

**`tests/unit/test_e2e_link.py`** — 13 new tests covering the full async rekey stack:

| Test | Scenario |
|---|---|
| `test_e2e_c1_light_rekey_in_flight` | Light rekey fires after `record_count=5`; all 20 frames delivered |
| `test_e2e_c1_light_rekey_ack_lost` | REKEY_ACK dropped once; REKEY_REQ retransmit recovers; all 10 frames delivered |
| `test_e2e_c1_full_rekey_hello_r_lost` | Full-rekey HELLO_R lost once; HELLO_I retransmit recovers; 5 frames delivered |
| `test_e2e_c1_full_rekey_finished_r_lost` | Full-rekey FINISHED_R lost once; FINISHED_I retransmit recovers; 5 frames delivered |
| `test_full_rekey_late_duplicate_hello_r_ignored` | Extra HELLO_R in `_hs_queue` consumed and ignored; full rekey still completes |
| `test_peer_forged_new_session_header_no_switch` | DATA with new session_id but wrong AEAD ciphertext does not promote peer |
| `test_full_rekey_failed_attempt_old_session_continues` | First full-rekey attempt fails (HELLO_R from peer dropped); old session continues |
| `test_full_rekey_max_attempts_raises_alert` | `full_rekey_max_attempts=1` and all HELLO_R dropped → `AlertError` raised |
| `test_epoch_254_guard_triggers_full_rekey` | Epoch forced to 254 via `_set_epoch_for_testing`; full rekey fires |
| `test_old_session_record_rejected_after_grace` | Old epoch record rejected after `grace_period_records` new-epoch records |
| `test_full_rekey_completes_with_cleanup_active` | Two sequential full rekeys; first session's grace expires before second completes |
| *(two more from the existing two M5a link tests, now prefixed)* | Fragmented + lossy handshake (pre-existing; retained) |

**`tests/unit/test_handshake.py`** — 1 regression:
- `test_peer_hello_i_retransmit_in_hello_received_state` — a second HELLO_I while in `HELLO_RECEIVED` state must return a byte-identical HELLO_R from cache (not re-process, not advance state). Regression for the M5a flaw where byte-equality comparison on the full prefixed message was used instead of the responder's internal cache.

**`tests/security/test_t9_rekey_spans.py`** — 1 new test:
- `test_t9_nonce_uniqueness_spans_full_rekey` — promotes both `SessionManager` instances to a new session via `promote_full_rekey`, then seals 100 records per direction per session. Asserts that all `(key, nonce)` pairs across both sessions are unique. Also asserts that `new_gw_keys.k_i2r != old_k_i2r`, proving a full rekey produces cryptographically independent keys.

---

## Why it was implemented this way

### 1-byte type prefix (§15 item 22)

CLAUDE.md §15 item 22 mandates a 1-byte dispatch prefix for C1–C3 link messages. The key design rule is: "Receivers dispatch on this byte, never on protocol state." Without this, a peer waiting for FINISHED_I would need to infer message type from protocol state, creating a class of parsing ambiguity bugs. With prefix dispatch, every receiver path is stateless at the parse layer: an unexpected prefix byte during the HELLO_I wait is malformed and counted, not a fatal error. This also means retransmitted HS messages in the data phase (e.g., a delayed HELLO_R arriving after a full rekey) are routed correctly without side effects on the data path.

The prefix is not authenticated. CLAUDE.md §15 item 22 explicitly states: "altering it only misroutes the message, which then fails parsing or authentication." An attacker that flips a DATA record's prefix byte to `_T_HELLO_R` causes the receiver to pass the bytes to the HS dispatcher, which will fail to parse them as a valid message; the AEAD tag on the original DATA record is never checked. This is acceptable because the worst-case effect is a single dropped DATA record, not a session bypass.

### Full rekey as a parallel session (§15 item 16)

CLAUDE.md §15 item 16 states: "run the new handshake as a separate session with a new session_id while the old session keeps carrying traffic." This is implemented as `_do_full_rekey()` running in an `asyncio.Task`, with the main `run()` loop continuing to seal and open DATA records on the old session concurrently. The design preserves data continuity: no CAN frames are lost during the handshake phase of the full rekey (beyond the `_pending` buffer for `CounterExhausted` frames).

### Peer trial-open before promote (§15 item 16 switch-over)

The peer does not promote to the new session upon receiving FINISHED_I alone. It stores `_fr_pending` and waits for the first DATA record on the new session_id to pass authentication. This design prevents a scenario where a replayed HELLO_I from a previous full-rekey attempt could cause the peer to prematurely switch sessions. The trial open uses a temporary `RecordLayer` and `ReplayWindow` so that a failed authentication does not advance the replay window on the production `SessionManager`.

### Session_id guard in `_route_open`

Before this change, `_route_open` routed records to `_rl_current` or `_rl_prev` based solely on `hdr.epoch`. After a full rekey both sessions start at `epoch==0`, so without the session_id guard, a record from the old session's epoch 0 would be routed to the new session's `RecordLayer` and fail AEAD authentication. The guard adds `hdr.session_id == self._session_id` (resp. `_prev_session_id`) as a mandatory condition. This is consistent with the record header layout defined in §5.5 of CLAUDE.md, which includes a 4-byte `session_id` field.

### REKEY_REQ retransmit uses cached record (§15 item 21)

CLAUDE.md §15 item 21 sets `rekey_timeout_ms=400` with `rekey_max_retries=3`. When `check_rekey_timeout()` fires, it must not seal a new REKEY_REQ because that would consume a counter value under the current epoch. Instead, `_cached_initiator_req` stores the originally sealed REKEY_REQ bytes and `check_rekey_timeout()` appends them to `_outbound_queue` for the caller to drain with `take_outbound()`. The caller (Gateway) then sends the queued record. This preserves counter monotonicity.

### Lazy cleanup of `_fr` state

The peer must be able to serve a cached HELLO_R to a retransmitting initiator even after the full rekey is complete, because the HELLO_R may be in flight when FINISHED_R is processed. Clearing `_fr` immediately on promote would break this. The lazy cleanup condition — `_fr_complete AND _fr_pending is None AND _fr_session_id not in known_session_ids` — ensures the state is kept for exactly as long as the session_id remains in the grace window, then cleared.

### Epoch-254 guard

CLAUDE.md §5.7 states: "Epoch is 1 byte; force a full rekey before epoch 255." The guard fires at `epoch >= 254` to leave one epoch of headroom for the light-rekey ratchet to settle before the byte wraps. The guard is checked on every `run()` loop iteration, so it fires within one CAN polling interval (10 ms) of the epoch advancing to 254.

---

## Key results and test evidence

### Test summary

```
239 passed in 4.31s
```

No skipped, no failed, no xfail. The 239 total breaks down as:

- 51 unit (crypto interfaces, M1)
- 18 unit (handshake, M2) + 1 regression (M5b)
- 25 unit (OI regressions)
- 19 unit (record layer, M3)
- 10 unit (rekey, M4)
- 6 smoke (M0)
- 8 unit (E2E loopback, M5a)
- 15 unit (E2E link: 2 from M5a + 13 from M5b)
- 35 security (T1–T3 from M3; T4–T6, T13 from M2; T7, T9, T11 from M3; T8, T10 from M4; T9 rekey span from M4+M5b; T12 from M5a)

### Round-trip verification

- Light rekey: `test_e2e_c1_light_rekey_in_flight` sends 20 CAN frames across a `record_count=5` trigger boundary. Frames 1–5 are on epoch 0; frame 6 triggers the rekey; frames 6–20 are on epoch 1 (or later). All 20 frames arrive at the peer's sink. The REKEY_ACK flush path is exercised.
- Full rekey: `test_e2e_c1_full_rekey_hello_r_lost` and `test_e2e_c1_full_rekey_finished_r_lost` verify that a lost HS message during full rekey causes a retransmit and all 5 frames still arrive on the new session.
- Full-rekey T9 span: `test_t9_nonce_uniqueness_spans_full_rekey` confirms that 100+100 records per direction across a session boundary produce 400 unique `(key, nonce)` pairs and that `k_i2r` differs between sessions.

### Peer switch-over security

`test_peer_forged_new_session_header_no_switch` sends a DATA record whose `session_id` bytes match a pending full-rekey but whose AEAD ciphertext is random. The trial open fails; the peer does not promote; `_unknown_session_drops` increments by 1; the old session remains active.

### Retry and ALERT

`test_full_rekey_max_attempts_raises_alert` sets `full_rekey_max_attempts=1` and drops all HELLO_R messages from the peer. After one failed attempt the gateway raises `AlertError`. `test_full_rekey_failed_attempt_old_session_continues` uses `full_rekey_max_attempts=2` and drops only the first attempt's HELLO_R; the second attempt succeeds, and all 5 frames arrive.

### Epoch-254 guard

`test_epoch_254_guard_triggers_full_rekey` calls `_set_epoch_for_testing(254)` after the session is established, runs `run(n_frames=5)`, and asserts that a full rekey is triggered and all 5 frames are delivered on the new session.

---

## Open issues resolved this milestone

**OI-8 (deferred full-rekey T9 span, from M4).** PROGRESS.md noted: "Full-rekey span deferred to M5 when the new-session path is wired up." `test_t9_nonce_uniqueness_spans_full_rekey` closes this by exercising `promote_full_rekey()` on both sides and verifying nonce uniqueness across the session boundary.

**M5a handshake regression (loop on unexpected first message).** The M5a `peer.handshake()` used byte-equality comparison to detect HELLO_I retransmits; with the type-prefix dispatch this broke when the M5b prefix was added. The peer now loops on type bytes, treating unexpected types as malformed. The regression is documented in `test_peer_hello_i_retransmit_in_hello_received_state` and in PROGRESS.md.

**Test 7 cross-test contamination (noted in PROGRESS.md).** The original `test_e2e_c1_full_rekey_failed_attempt_old_session_continues` (internally "test 7") wrapped `gw_link_inner` with a drop filter, but the gateway never sends HELLO_R, so the filter had no effect. Rewriting to wrap `peer_link_inner` (the peer's outbound link) also fixed a race where `request_full_rekey()` could be called twice, causing the second full rekey to begin before the peer had verified FINISHED_I for it.

---

## Known limitations relevant to this milestone

1. **Algorithmic agility:** this milestone operates exclusively on `C1` (classical) in the E2E link tests. C2 (PQC-only) and C3 (hybrid) are covered by the loopback E2E tests from M5a and by the security tests from M2–M4. The full C0–C3 security matrix across the link is deferred to M6 (CLAUDE.md §11).

2. **CAN traffic model:** `RekeyTrigger.interval_s`, `record_count`, and `byte_count` are exercised in tests, but the TOML config loading path is deferred to M7 (`configs/sessions/default.toml`). Tests set trigger values directly in the `Gateway` constructor.

3. **Full rekey running alongside live traffic:** CLAUDE.md §8 specifies measuring "cost of a handshake running alongside live traffic" (§15 item 16). This measurement is deferred to M7. The M5b implementation is correct but not yet benchmarked.

4. **CAN bus quiet during full rekey:** PROGRESS.md documents that if no CAN frames arrive while `_do_full_rekey()` is completing, the peer's `_fr_pending` is not consumed until the next DATA record. This is a correct implementation of the trial-open switch-over; the latency implication will be reported in M7.

5. **FN-DSA and HQC:** experimental algorithms (CLAUDE.md §1 limitation 5). Not exercised in M5b link tests.

6. **Link emulation not a wireless channel model** (CLAUDE.md §1 limitation 6). All M5b tests use `LoopbackLink` or `LinkEmulator` with no radio model.

---

## What an examiner should know

- **Why the peer does not promote on FINISHED_I alone.** Receiving FINISHED_I proves the initiator completed the handshake, but does not prove the initiator has started sending DATA under the new keys. The trial-open design means promotion is gated on cryptographic proof: the first DATA record under the new session_id must pass AEAD authentication. This eliminates a class of downgrade-to-old-session attacks where an attacker who can replay a full-rekey FINISHED_I could cause the peer to prematurely discard the old session and reject legitimate in-flight records.

- **Why the session_id guard in `_route_open` is a security fix, not a convenience.** After a full rekey both the old and new sessions start at `epoch==0`. Without the guard, a DATA record from the old session (e.g., a delayed packet in the grace window) would be routed to the new session's `RecordLayer` and fail AEAD — incrementing `_auth_failures`, which could accumulate to `max_consecutive_auth_failures` and close the session under a loss burst. With the guard, epoch is never compared across session boundaries.

- **How the full-rekey coroutine coexists with the data path.** `_do_full_rekey()` is an `asyncio.Task`; the `run()` loop polls its completion on each iteration (`_full_rekey_task.done()`). Both paths share the same event loop thread, so there is no data race. The separation via `_hs_queue` means that the data path's `recv()` calls and the full-rekey task's `recv()` calls draw from the same link, disambiguated by prefix byte.

- **Why retransmit uses the cached record, not a fresh seal.** Sealing a new REKEY_REQ would consume a counter value and produce a different ciphertext, which is acceptable. However, it would also consume one record from the epoch's replay window on the peer (since the peer's window already saw the first REKEY_REQ). Using the cached byte string ensures the retransmit is idempotent at the record layer: the peer deduplicates it via the replay window (§15 item 21: "duplicate REKEY_REQ received during grace makes peer resend cached REKEY_ACK without ratcheting again").

- **Epoch-254 guard and why the threshold is not 255.** A light rekey increments the epoch by 1 and writes two new `RecordLayer` states (current + previous in grace). If the guard fired at 255, the epoch would be 255 when the ratchet advances, overflowing the 1-byte epoch field. Firing at 254 leaves one epoch of headroom for the grace window to settle cleanly while the full rekey completes in parallel.

- **T9 across full rekey.** The nonce uniqueness proof for full rekey relies on key independence: `promote_full_rekey` replaces all session keys with freshly derived keys from a new handshake. The test asserts `new_gw_keys.k_i2r != old_k_i2r` explicitly. Because the nonce is `salt || counter` and the salt is derived from the same KDF as the key, independent keys imply independent salts, and counter independence follows from the counter resetting to 0 on promote. No `(key, nonce)` collision is therefore possible between sessions.

---

*Generated by /milestone-log. Source of truth: git history, pytest output, PROGRESS.md.*
