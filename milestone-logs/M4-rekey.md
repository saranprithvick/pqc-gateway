# M4: Rekeying — light rekey, epochs, grace period, T8/T10

**Date completed:** 2026-11-04
**Branch:** m4-rekey
**Commits:** 1 (1ab4202 M4: rekeying — light rekey, epochs, grace period, T8/T10)
**Tests:** 137 passed, 0 failed

---

## What was implemented

### Ratchet key derivation
- `src/pqcgw/protocol/rekey.py` — `derive_rekey_epoch(suite, keys) -> SessionKeys`. Single
  public function that advances a `SessionKeys` by one epoch using the deterministic KDF
  ratchet defined in CLAUDE.md §15 item 8. Derives `rekey_sec_n`, then all five per-epoch
  secrets (`k_i2r`, `k_r2i`, `salt_i2r`, `salt_r2i`, `k_finished`) from that seed. The
  function is stateless and pure: same inputs always produce the same outputs.

### Session manager
- `src/pqcgw/protocol/session.py` — `SessionManager` class (450 lines). Owns two
  `RecordLayer` instances (current epoch and previous epoch for the grace window), two
  `ReplayWindow` dicts, and the light-rekey state machine. Public API: `seal()`, `open()`,
  `initiate_light_rekey()`, `check_rekey_timeout()`, `promote_full_rekey()`,
  `take_outbound()`. Supporting dataclass `RekeyConfig` holds all configurable thresholds.
  Enumerations `SessionRole` (INITIATOR / RESPONDER) and `RekeyState`
  (IDLE / REQ_SENT / ACK_SENT / GRACE). Exceptions `SessionError` and `AlertError`.

### Key schedule modification
- `src/pqcgw/protocol/keyschedule.py` — `SessionKeys` dataclass gained one field: `th`
  (the original handshake transcript hash). This field is immutable for the session
  lifetime and is threaded through every ratchet step so that all expand calls are bound
  to the specific session that produced them.

### Unit tests
- `tests/unit/test_rekey.py` — 10 tests covering ratchet determinism, key distinctness
  from epoch 0, both sides independently converging on the same epoch-1 keys, chained
  epochs are pairwise distinct across five steps, epoch counter increments correctly, key
  and salt lengths match the suite for all three suite configs (classical / pqc / hybrid),
  `th` is preserved unchanged through the chain, and `suite_id` is preserved.

### Security tests
- `tests/security/test_t8_t10.py` — 9 tests covering T8 (old-epoch records survive the
  grace window; old-epoch records are rejected after grace-record exhaustion; old-epoch
  records are rejected immediately when `grace_period_s=0`; new-epoch records work after
  rekey; duplicate REKEY_REQ resends a byte-identical cached ACK without re-ratcheting;
  failed rekey raises `AlertError`; two successive rekeys advance epoch by 2) and T10
  (counter hard limit triggers a light rekey and the REKEY_REQ is returned from `seal()`;
  counter exhaustion with an immediately-expiring timeout raises `AlertError`).

---

## Why it was implemented this way

### Why a deterministic ratchet rather than a fresh key exchange per epoch

CLAUDE.md §5.7 specifies the light rekey as a KDF ratchet: `rekey_sec_n = expand(rekey_sec_{n-1}, ...)`.
This is the cheapest possible epoch advance — two sides independently compute identical
keys without exchanging any additional KEM messages. The asymmetry in cost compared to a
full handshake is intentional (§11 M4 scope) and is explicitly documented as a limitation:
the ratchet provides forward secrecy for past epochs but does not evict an attacker who
already holds the current session secret. A full rekey (new handshake, §15 item 16) is
required for that stronger guarantee. The docstring in `rekey.py` states this explicitly
so an examiner cannot mistake the security property.

### Why the transcript hash `th` is threaded into every expand call

CLAUDE.md §15 item 8 gives the label formula as
`info = u8(len(label)) || label_ascii || u8(suite_id) || th || u8(epoch)`.
Including `th` in every ratchet expand call binds all derived keys to the specific
handshake session that established the master secret. Without `th`, two sessions with the
same `suite_id` could, in principle, produce the same ratchet keys from epoch 1 onward if
their `rekey_sec0` values were equal. Storing `th` in `SessionKeys` (the
`keyschedule.py` change) is the minimal change needed: it must travel with the keys
through every ratchet step.

### Why REKEY_REQ / REKEY_ACK are sealed records rather than plaintext control messages

Both control messages are sealed under the current epoch's RecordLayer (REKEY_REQ under
I2R, REKEY_ACK under R2I). This means they carry a valid AEAD tag and pass through the
replay window. An attacker cannot inject a spurious rekey trigger without the session key.
CLAUDE.md §5.7: "the gateway sends an authenticated REKEY_REQ ... protected under the
current epoch".

### Why the REKEY_ACK is sealed under the old epoch before the responder switches

§15 item 15 specifies the sequence: the responder seals the REKEY_ACK under epoch n, then
switches to epoch n+1 for new sends. This guarantees the initiator can verify the ACK
using its current epoch-n key, which it has not discarded yet. If the responder sealed
the ACK under the new epoch, the initiator could not open it because it has not yet
advanced to epoch n+1 at that point.

### Why duplicate REKEY_REQ resends the cached ACK byte-identically without re-ratcheting

§15 item 21: "a duplicate REKEY_REQ received during the grace period makes the peer
resend its cached REKEY_ACK without ratcheting again." If the responder ratcheted again
on a duplicate, the initiator (which sees the first ACK as dropped and retransmits the
REQ) would receive an ACK sealed with epoch n+1 keys, which it cannot open (it expects
epoch n). The duplicate check is performed on raw bytes before the replay window so that a
retransmitted REKEY_REQ — which carries the same counter and would be rejected as a replay
— is recognised as a legitimate duplicate before the replay-window logic runs.

### Why grace period has two separate expiry conditions

§15 item 10: "ends at whichever comes first, 2 s or 64 records on the new epoch." A
time-only grace period could leave a congested path holding the old epoch key for a long
time under heavy load; a record-count-only condition could leave idle sessions holding the
old key indefinitely. Both conditions apply and `_grace_expired()` checks both. All
thresholds are configurable via `RekeyConfig` so tests can use `grace_period_records=2`
and `grace_period_s=0.0` to exercise expiry deterministically.

### Why AlertError is a distinct exception from RecordError

`RecordError` is a per-record failure: drop the record silently, increment a counter,
continue the session. `AlertError` is a session-fatal condition: the caller must send an
ALERT record and tear down the session. Keeping them as separate exception types forces
callers to handle the two cases differently and prevents a session-fatal condition from
being silently swallowed by code that only catches `RecordError`.

### Why epoch 255 is a hard guard rather than an automatic full rekey

The session manager raises `AlertError` when `epoch >= 255` rather than transparently
initiating a full rekey, because a full rekey requires a new handshake (§15 item 16),
which involves the calling layer, the link, and both peers. The session manager does not
own that orchestration in M4 (it is M5+ work). The guard ensures the epoch byte never
wraps back to 0 under the same session identity, which would reuse keys. CLAUDE.md §5.7:
"Force a full rekey before epoch 255."

### Why `promote_full_rekey()` is present but not exercised in M4 tests

The method signature is established here because `SessionKeys` is the right type to pass
at promotion time. Full rekey orchestration (running a parallel handshake while live
traffic continues) is M5+ scope (§15 item 16). The method moves the current RecordLayer
to the grace slot and installs fresh keys, which is the same state transition as light
rekey from the grace-period perspective; the tests for that mechanics are T8 and T10.

---

## Key results and test evidence

### Test summary
```
137 passed in 0.49s
```
19 new tests added in M4 (10 unit, 9 security). All 137 tests (cumulative from M0–M4) pass
with 0 failures and 0 errors.

### Ratchet correctness
Both sides of a completed handshake independently call `derive_rekey_epoch()` from their
respective `SessionKeys` and produce identical `k_i2r`, `k_r2i`, `salt_i2r`, `salt_r2i`
values (`test_ratchet_both_sides_agree`). This is the fundamental requirement: without a
network exchange, the ratchet must converge on the same keys.

### Key distinctness
Epoch-1 keys differ from epoch-0 keys on all five fields. Five chained epochs yield five
distinct `k_i2r` values with no collision (`test_ratchet_chained_epochs_distinct`). The
transcript hash `th` is unchanged through three successive ratchet steps
(`test_ratchet_th_preserved`).

### Key lengths across all suites
Parametrised over `classical`, `pqc`, and `hybrid` suites: `k_i2r` and `k_r2i` match
`suite.aead.key_len`; salts are always 4 bytes; `k_finished` and `rekey_sec0` are always
32 bytes (`test_ratchet_sizes_match_suite`).

### Grace-period behaviour (T8)
- Old-epoch records sealed before the rekey arrive and are accepted during the grace window
  (`test_t8_records_survive_grace_period`, grace_period_records=4).
- After `grace_period_records=2` new-epoch records have been opened, the next old-epoch
  record raises `RecordError` (`test_t8_old_epoch_rejected_after_grace_records`).
- With `grace_period_s=0.0`, the first old-epoch record after the rekey is rejected
  immediately (`test_t8_old_epoch_rejected_after_grace_time`).
- Two successive rekeys advance both sides to epoch 2 (`test_t8_multiple_rekeys_increase_epoch`).

### Duplicate REKEY_REQ (T8)
Sending the same REKEY_REQ bytes twice causes the responder to return a byte-identical
REKEY_ACK on both deliveries and remain on epoch 1, not epoch 2
(`test_t8_duplicate_rekey_req_resends_cached_ack`).

### Failed rekey alert (T8)
With `rekey_timeout_s=0.0` and `rekey_max_retries=0`, calling `check_rekey_timeout()`
after `initiate_light_rekey()` raises `AlertError`
(`test_t8_failed_rekey_raises_alert`).

### Counter exhaustion (T10)
With `counter_hard_limit=3`, the fourth `seal()` call returns a REKEY_REQ record (not a
DATA record). After completing the rekey exchange, the session continues normally on epoch
1 (`test_t10_counter_limit_triggers_rekey`). With `counter_hard_limit=1` and
`rekey_timeout_s=0.0`, the second `seal()` raises `AlertError`
(`test_t10_counter_limit_closes_on_failed_rekey`).

---

## Open issues resolved this milestone

No open issues from PROGRESS.md were assigned to M4. OI-1 (length validation) and OI-2
(SLH-DSA sizes) remain open from M1; they are pre-existing and do not affect M4 deliverables.

---

## Known limitations relevant to this milestone

1. **Light rekey does not evict an attacker holding the current secret.** The ratchet
   provides forward secrecy for past epochs (epoch-n+1 keys cannot be used to recover
   epoch-n keys) but an attacker who learned `rekey_sec_n` before epoch n+1 begins can
   compute all future ratchet secrets. A full rekey (new handshake) is required to close
   that window. Documented in `rekey.py` docstring and CLAUDE.md §5.7.

2. **Python cannot guarantee in-memory zeroization of discarded secrets.** The old
   `rekey_sec_{n-1}` is overwritten in the returned `SessionKeys` object, but CPython may
   keep a reference alive in bytecode temporaries. Documented in `rekey.py` docstring.
   This is a universal Python limitation, not specific to this implementation.

3. **Full rekey orchestration is M5+ scope.** `promote_full_rekey()` is scaffolded but
   the parallel-handshake machinery (§15 item 16) is not exercised until M5. The
   session manager cannot autonomously trigger a full rekey; it relies on the calling
   layer to do so before epoch 255 is reached.

4. **C0 cases for T8/T10 deferred.** T8/T10 on the passthrough path will be confirmed in
   M6 when the full security-test sweep across C0–C3 runs. Noted at the top of
   `test_t8_t10.py`.

---

## What an examiner should know

- **The ratchet is symmetric by construction.** Both sides possess identical `SessionKeys`
  after the handshake (the same `rekey_sec0`, the same `th`). `derive_rekey_epoch` takes
  only these inputs and the suite's KDF. There is no on-wire negotiation and no nonce
  exchange at rekey time; correctness rests entirely on both sides calling the same
  deterministic function at the same point in the protocol.

- **The transcript hash `th` in every ratchet expand call is cross-session domain
  separation.** It prevents an adversary from transplanting ratchet state from one session
  into another that happens to share `rekey_sec0`. The `SessionKeys.th` field added to
  `keyschedule.py` stores the epoch-0 transcript hash and passes it through every ratchet
  step unchanged.

- **Grace-period expiry is whichever comes first: time or record count.** Both conditions
  are tested independently (time=0 to force immediate expiry; records=N to exhaust by
  count). The implementation checks both on every `open()` call that routes to the
  previous epoch. When either condition fires, `_expire_grace()` nulls out `_rl_prev` and
  `_rw_prev` immediately; subsequent records with the old epoch number are rejected with
  `RecordError`.

- **Duplicate REKEY_REQ detection bypasses the replay window intentionally.** A
  retransmitted REKEY_REQ carries the same counter as the original. The replay window
  would reject it as a duplicate. The raw-bytes comparison runs before the replay-window
  check specifically to allow the legitimate retransmit path, in line with §15 item 21.
  An attacker cannot exploit this bypass because the REKEY_REQ is sealed under the current
  epoch key; forging a byte-identical record requires the session key.

- **`AlertError` versus `RecordError` is an intentional API contract.** Code that handles
  `RecordError` by dropping the record silently will not accidentally suppress an
  `AlertError` because they are unrelated exception classes. Every path that raises
  `AlertError` documents the required caller action: send an ALERT record and close the
  session.

- **Counter hard limit triggers a light rekey inside `seal()`.** The returned bytes from
  the triggering `seal()` call are the REKEY_REQ record, not the DATA record the caller
  expected. The caller must route those bytes to the peer and complete the exchange before
  calling `seal()` again. This design keeps the counter-exhaustion response within the
  session manager rather than leaking the trigger condition into the application layer.

---

*Generated by /milestone-log. Source of truth: git history, pytest output, PROGRESS.md.*
