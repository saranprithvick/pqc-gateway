# M4: Rekeying — light rekey, epochs, grace period, T8/T10

**Date completed:** 2026-11-04
**Branch:** m4-rekey
**Commits:** 1 (1ab4202 M4: rekeying — light rekey, epochs, grace period, T8/T10)
**Tests:** 164 passed, 0 failed (after m4-fixes; see post-M4 section below)

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

## Post-M4 fixes (m4-fixes branch)

**Commits:** `a56bff4` m4-fixes: pre-merge verification — closed state, no-backoff, grace docstring  
**Merged as:** `118e863` Merge m4-fixes: pre-M5 protocol hardening (OI-4 through OI-8 + pre-merge verification)  
**Tests after merge:** 164 passed, 0 failed (27 new tests added over M4 baseline of 137)

This branch resolved five open issues (OI-4 through OI-8) discovered during pre-merge review of the M4
implementation. No new features were added; every change is either a correctness fix or a regression test
that pins the fixed behaviour.

### OI-4: `seal()` now raises `CounterExhausted` instead of returning a REKEY_REQ record

**What was wrong.** The original M4 `seal()` returned the REKEY_REQ bytes to the caller when the counter
hard limit was reached, substituting a control record for the DATA record the caller expected. This broke
the caller API contract: the caller could not distinguish whether it had just sent data or triggered a
rekey without inspecting the returned bytes.

**What changed.** A new `CounterExhausted` exception class was added to `session.py`. When the counter
reaches `counter_hard_limit`, `seal()` now calls `initiate_light_rekey()` internally, appends the
REKEY_REQ to `_outbound_queue`, and raises `CounterExhausted`. The caller drains the queued record via
`take_outbound()` and must buffer the unsent frame (bounded queue, 64 max, drop-oldest per §15 item 20)
until the new epoch is active. The docstring on `CounterExhausted` states this caller obligation
explicitly so it cannot be missed.

**Why this matters.** A caller that only checked for exceptions and not record types would have silently
swallowed the control-record substitution, forwarding the REKEY_REQ bytes to the application layer.
Raising a distinct exception forces every call site to handle the counter-limit path explicitly.

**Regression tests** (`tests/unit/test_oi_regressions.py::TestOI4CounterExhausted`):
- `test_seal_raises_counter_exhausted_not_returns_rekey_req` — `seal()` with `counter_hard_limit=1`
  raises `CounterExhausted` on the second call, not a bytes return.
- `test_seal_queues_rekey_req_in_outbound` — after the exception, `take_outbound()` returns a record
  whose header has `rtype == RecordType.REKEY_REQ`.
- `test_rekey_completes_after_counter_exhausted` — session continues normally on epoch 1 after the
  full REKEY_REQ / REKEY_ACK exchange completes.

### OI-5: Duplicate REKEY_REQ bypass gated on rekey-in-progress state

**What was wrong.** The duplicate REKEY_REQ fast path in `open()` was checked against the raw bytes of
any incoming record whenever `_cached_rekey_req` was set, with no regard for whether a rekey was still
in progress. After the grace period expired and `_expire_grace()` set `_rekey_state = IDLE`, a delayed
or replayed REKEY_REQ from the previous rekey could still match the cache and cause the responder to
resend a stale cached ACK — bypassing the replay window and responding to a record that should be
rejected.

**What changed.** The duplicate-bypass check in `open()` is now guarded by:
```python
self._rekey_state in (RekeyState.ACK_SENT, RekeyState.GRACE)
```
`_expire_grace()` already set `_rekey_state = IDLE` when the grace period ended, so the guard
implicitly deactivates the duplicate-bypass path once grace expires. No additional state is required.

**Why this matters.** Without the gate, an attacker who captured a valid REKEY_REQ from a completed
rekey could replay it after grace expiry and receive a byte-identical REKEY_ACK sealed under the old
epoch key — an authenticated response generated from a session that should have been fully transitioned.

**Regression tests** (`tests/unit/test_oi_regressions.py::TestOI5DuplicateRekeyReqGate`):
- `test_duplicate_req_not_resent_after_grace_expires` — after `grace_period_records=1` exhausts the
  grace window, re-delivering the original REKEY_REQ raises `RecordError` (not a cached-ACK resend),
  and `take_outbound()` returns `None`.
- `test_duplicate_req_during_grace_resends_cached_ack` — during the active grace period (state
  `ACK_SENT`), a second delivery of the identical REKEY_REQ bytes returns a byte-identical ACK and
  leaves the responder on epoch 1, not epoch 2.

### OI-6: `RekeyConfig` timeout renamed to milliseconds with invariant validator

**What was wrong.** The field was named `rekey_timeout_s` (a float in seconds). CLAUDE.md §15 item 21
specifies the timeout as an integer in milliseconds with no backoff. The mismatch between the spec and
the implementation could lead to callers passing a float where an integer was expected, and nothing
enforced the invariant that the worst-case retry budget must fit inside the grace window.

**What changed.** The field was renamed `rekey_timeout_ms: int = 400`. A `__post_init__` validator was
added to `RekeyConfig`:

```python
budget_s = (self.rekey_timeout_ms / 1000) * (self.rekey_max_retries + 1)
if budget_s >= self.grace_period_s:
    raise ValueError(...)
```

With defaults: 0.4 × 4 = 1.6 s < 2.0 s. The validator is skipped when `grace_period_s == 0.0` (test
sentinel for instant-expiry tests). `check_rekey_timeout()` divides by 1000 to compare against elapsed
monotonic time — there is no exponential backoff; each retry resets the timer to `time.monotonic()`.

**Why this matters.** Without the invariant, it was possible to configure a retry budget longer than the
grace window, meaning the last retry's ACK could arrive after grace had expired and after the peer had
already discarded the previous epoch. The validator makes this misconfiguration a construction-time
`ValueError` rather than a silent correctness failure at runtime.

**Regression tests** (`tests/unit/test_oi_regressions.py`):
- `TestOI6ConfigValidator` (6 tests) — default config is valid; budget equal to grace raises; budget
  exceeding grace raises; `grace_period_s=0.0` bypasses the check; valid custom configs accepted.
- `TestRekeyTimeoutNoBackoff` (2 tests) — with `rekey_timeout_ms=0`, exactly `rekey_max_retries + 1`
  calls to `check_rekey_timeout()` are needed before `AlertError`; `_rekey_retries` increments by 1
  per call, confirming there is no doubling.

### OI-7: `hash_name` abstract property added to `KDF` interface; providers import removed from key schedule

**What was wrong.** `keyschedule.py` contained a direct import from `pqcgw.crypto.providers` to
determine the hash algorithm used by the KDF. This violated the architecture rule (CLAUDE.md §4, §2
rule 2): protocol code must import only the abstract interfaces, never concrete implementations.

**What changed.** A `hash_name: str` abstract property was added to the `KDF` ABC in
`src/pqcgw/crypto/interfaces.py`:

```python
@property
@abstractmethod
def hash_name(self) -> str:
    """Name of the underlying hash ('sha256' or 'sha384')."""
```

Both providers implement it: `HkdfSha256` returns `"sha256"` and `HkdfSha384` returns `"sha384"`. The
`suite_hash()` helper in `keyschedule.py` now calls `suite.kdf.hash_name` and dispatches on the
returned string instead of importing provider classes. The direct providers import was removed.

**Why this matters.** Protocol code that imports concrete provider classes becomes tightly coupled to
implementation details. If a provider is renamed or replaced via a config swap, the import breaks.
Making `hash_name` part of the interface contract ensures the protocol layer is insulated from any
future provider changes — exactly the agility guarantee the crypto abstraction layer is meant to provide.

**Regression tests** (`tests/unit/test_oi_regressions.py::TestOI7LayerBoundary`):
- Parametrised over every `.py` file in `src/pqcgw/protocol/`. Each test parses the module's AST and
  asserts that no `import` or `from ... import` node references `pqcgw.crypto.providers`. A violation
  fails the specific file's test with the offending line number.

### OI-8: T9 nonce-uniqueness extended across light-rekey boundaries

**What was added.** The existing T9 test verified nonce uniqueness within a single epoch. The gap was
that nonces were not checked across epoch boundaries: the concern is that a ratchet error could produce
identical salts or keys in different epochs, allowing nonce reuse in a different epoch under a different
(but coincidentally identical) key.

A new test file `tests/security/test_t9_rekey_spans.py` was added with two tests:

- `test_t9_nonce_uniqueness_spans_rekeys` — seals 500 records in each direction across epochs 0, 1, and
  2 (3000 (key, nonce) pairs total). Each pair is computed from `(salt || struct.pack(">Q", counter))`
  and inserted into a set before sealing. An assertion fires immediately on any duplicate. The test
  triggers two light rekeys to cover the epoch-0→1 and epoch-1→2 boundaries. Final assertion:
  `len(all_pairs) == 500 × 3 × 2 = 3000`.

- `test_t9_epoch_keys_differ_across_rekeys` — snapshots `(k_i2r, k_r2i, salt_i2r, salt_r2i)` at epochs
  0, 1, and 2 and asserts all three snapshots are pairwise distinct. This is the structural check that
  the ratchet produces genuinely different keying material at each epoch.

**Why this matters.** A bug in the `_info()` label encoding in `rekey.py` (for example, omitting `th`
or encoding `epoch` incorrectly) could produce identical expand outputs at different epochs without being
caught by within-epoch tests. The cross-epoch nonce check would catch such a regression immediately.

### Additional pre-merge hardening (commit `a56bff4`)

**Closed-state enforcement.** Tests in `TestSessionClosedState` (4 tests) confirm that after `AlertError`
is raised, `session.closed` is `True`, subsequent `seal()` raises `SessionError`, subsequent `open()`
raises `SessionError`, and the consecutive-auth-failure counter resets to 0 after any successfully
authenticated record. These behaviours existed in the M4 code but had no regression coverage.

**Grace docstring correction.** The `_expire_grace()` docstring was updated to document that it also
sets `_rekey_state = IDLE` when called from `_grace_expired()`, making the state transition visible to
readers who are auditing the duplicate-bypass gate.

---

*Generated by /milestone-log. Source of truth: git history, pytest output, PROGRESS.md.*
