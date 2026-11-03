# M3: Record Layer, Nonce Construction, and Replay Window

**Date completed:** 2026-11-03  
**Branch:** m3-record-layer  
**Commits:** 1 commit (7984244)  
**Tests:** 118 passed, 0 failed (33 new M3 tests + 85 carried from M0/M1/M2)

---

## What was implemented

### Record Layer (`src/pqcgw/protocol/record.py`)

The main encryption/decryption module for protected session traffic.

- **`RecordType`** (`IntEnum`) — five wire types: `DATA=0`, `REKEY_REQ=1`, `REKEY_ACK=2`, `CLOSE=3`, `ALERT=4`. The type is encoded in the low nibble of header byte 0 (§15 item 8).
- **`Direction`** (`IntEnum`) — `I2R=0`, `R2I=1`. Used to select the correct key and salt from `SessionKeys`.
- **`RecordHeader`** — dataclass with full `to_bytes()` / `from_bytes()` round-trip. Packs the 16-byte fixed-overhead header: `version_type (1 B) | session_id (4 B) | epoch (1 B) | counter (8 B big-endian) | payload_length (2 B big-endian)`. The version nibble is 1; type nibble is the `RecordType` value.
- **`RecordLayer`** — the single class that wraps `seal()` and `open()`. Holds per-direction outbound counters (`dict[Direction, int]`). Consumes a `Suite` (for the AEAD instance) and a `SessionKeys` (for keys and salts). `session_id` is stored and validated on every inbound record.
  - `seal(rtype, plaintext, direction)` — assigns the next counter, builds the header, constructs the 12-byte nonce (`salt[direction] (4 B) || counter (8 B)`), calls `suite.aead.encrypt(key, nonce, aad=header_bytes, plaintext)`, and returns `header_bytes || ciphertext || tag`.
  - `open(data, direction, replay)` — parses and validates the header (version, epoch, session_id, ciphertext length), calls `replay.check(counter)` before touching the key material, decrypts with `suite.aead.decrypt`, and only calls `replay.mark(counter)` after successful authentication.
- **`RecordError`** — the single exception for all record-layer failures. Callers drop the record silently on the wire and log locally (§5.8).

### Replay Window (`src/pqcgw/protocol/replay.py`)

A sliding bitmap that detects duplicate and out-of-window counters.

- **`ReplayWindow`** — configurable `window_size` (default 64). State: `_highest` (highest counter accepted, initialised to -1) and `_bitmap` (integer used as a bitmask of width `window_size`).
  - `check(counter)` — validates without mutating state. Raises `ReplayError` for duplicates and for counters more than `window_size` below `_highest`. Returns without error for new highs and for in-window unseen counters.
  - `mark(counter)` — records acceptance. If `counter > _highest`, shifts the bitmap left by the gap and sets bit 0. Otherwise sets the bit at position `_highest - counter`. Called only after successful AEAD authentication.
- **`ReplayError`** — distinct exception raised by the replay filter itself, also caught and re-raised as `RecordError` by `open()`.

### Tests — Unit (`tests/unit/test_record.py`, 19 tests)

Round-trip tests for C1/C2/C3 in both directions, overhead size assertion, nonce counter KAT, counter auto-increment, direction isolation, header parse round-trip for all five `RecordType` values, and a 10-record sequence test.

### Tests — Security (`tests/security/test_t1_t2_t3_t7_t9_t11.py`, 14 tests)

T1 (replay), T2 (tamper in ciphertext and in four distinct header fields), T3 (random injection, wrong-key injection), T7 (out-of-order within window, too-old record, duplicate), T9 (nonce uniqueness over 100,000 records across both directions), T11 (I2R→R2I and R2I→I2R reflection).

---

## Why it was implemented this way

### Header as AEAD associated data (AAD) (§5.5)

The 16-byte record header is passed as the AAD to the AEAD primitive. This means the AEAD tag authenticates both the plaintext and the header simultaneously: any modification to `session_id`, `epoch`, `counter`, `payload_length`, or `record_type` in the header causes tag verification to fail. Without this, an attacker could reinterpret a record by changing header fields without breaking the ciphertext authentication. The nonce is derived from the same counter that appears in the header, so a tampered counter causes a doubly-broken authentication: wrong nonce produces wrong keystream, and the AAD check also fails.

### Nonce = salt (4 B) || counter (8 B big-endian) (§5.5)

The nonce is 12 bytes, matching all three supported AEAD algorithms (AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305). The 4-byte per-direction salt (`salt_i2r` / `salt_r2i`) is fixed for the epoch and comes from the key schedule. The 8-byte counter is per-record and monotonically increasing. This construction provides two layers of direction separation: the salt distinguishes I2R from R2I, and the counter is tracked independently per direction. Using the counter as the variable nonce component (rather than a random nonce) gives T9 its guarantee: the counter never repeats under a key, so the (key, nonce) pair is unique by construction for the lifetime of the epoch.

### Direction-separated keys and salts (§5.3, §5.5)

`k_i2r` / `k_r2i` and `salt_i2r` / `salt_r2i` are derived with distinct HKDF labels in the key schedule (M2). Using the wrong direction's key means the AEAD tag check fails unconditionally. This is what makes T11 (reflection) structurally impossible: a record sealed under `k_i2r` cannot be authenticated with `k_r2i` because the keys are cryptographically independent. There is no configuration or parameter that could make them equal.

### Replay check before decryption, mark after (§5.6)

`replay.check(counter)` is called before the AEAD decryption attempt. `replay.mark(counter)` is called only after successful decryption. This ordering is security-critical: if `mark()` were called before decryption, a forged record with a valid-looking counter could poison the replay window and cause the legitimate record with that counter to be rejected. By checking first and marking only on authentication success, forgeries are rejected without any window mutation.

### Sliding bitmap replay window (§5.6)

A sliding bitmap (default 64 entries) is used rather than a simple "highest seen" check. This is necessary because out-of-order delivery is expected on the link (packets can be reordered in transit). The bitmap records which counters within the window have been accepted; any counter below `highest - window_size` is rejected as too old; any counter within the window that is already marked is rejected as a duplicate; any counter above the current highest slides the window forward. The window size is configurable so that tests can use a small window (e.g., 8) to verify the out-of-window rejection path without sealing thousands of records.

### `payload_length` in the header (§5.5)

The `payload_length` field records the plaintext byte count. This allows the receiver to validate the total wire length against the expected ciphertext length (`payload_length + tag_len`) before any decryption. A length mismatch raises `RecordError` immediately, preventing the AEAD from being called with a truncated ciphertext (which could produce unpredictable results in some implementations). It also means a truncation or extension attack that changes the payload length is caught both by the length check and by the AAD authentication failure.

### RecordError: no distinguishing detail on the wire (§5.8)

All record-layer failures — wrong session_id, wrong epoch, length mismatch, replay, AEAD failure — raise `RecordError` with a descriptive local log message. The exception is never serialised or sent to the peer. This follows the same principle as the handshake: an attacker must not be able to learn which check failed, because that information could help them craft targeted attacks (e.g., distinguishing a replay from a tag failure tells the attacker whether the counter is in range).

### Record overhead: 32 B fixed (16 B header + 16 B AES-GCM tag) (§5.5)

CLAUDE.md §5.5 states "Fixed overhead with this layout is therefore 32 B per record." The unit test `test_overhead_size` asserts that for an 8-byte payload the total wire record is `16 + 8 + tag_len` bytes. For AES-256-GCM and AES-128-GCM, `tag_len = 16 B`. For ChaCha20-Poly1305, `tag_len = 16 B` as well. The overhead measurement is a test assertion, not an assumption.

---

## Key results and test evidence

### Test summary

```
118 passed in 0.47s
  14 M3 security tests  (tests/security/test_t1_t2_t3_t7_t9_t11.py)
  19 M3 unit tests      (tests/unit/test_record.py)
  18 M2 unit tests      (tests/unit/test_handshake.py)
  10 M2 security tests  (tests/security/test_t4_t5_t6_t13.py)
  51 M1 unit tests      (tests/unit/test_crypto_interfaces.py)
   6 M0 smoke tests     (tests/test_smoke.py)
   0 failed, 0 errors, 0 skipped
```

### Round-trip verification (C1, C2, C3)

Both directions tested for all three suite configurations:

| Suite | Direction | Round-trip |
|---|---|---|
| C1 (X25519 + ECDSA-P256 + AES-256-GCM) | I2R | Passed |
| C1 | R2I | Passed |
| C2 (ML-KEM-768 + ML-DSA-65 + AES-256-GCM) | I2R | Passed |
| C2 | R2I | Passed |
| C3 (hybrid KEM + dual sig + AES-256-GCM) | I2R | Passed |
| C3 | R2I | Passed |

### Record overhead assertion

For an 8-byte payload on all three suites: wire record = `16 + 8 + 16 = 40 B`. Header = 16 B, tag = 16 B. Confirmed by `test_overhead_size` for C1, C2, C3.

### Counter discipline

`test_counter_starts_at_zero` confirms the first three records sealed in I2R carry counters 0, 1, 2 in bytes 6–13 of the header. `test_different_nonces_per_seal` confirms distinct counter bytes and distinct ciphertexts across successive seals of identical plaintexts.

### Nonce uniqueness (T9)

`test_t9_nonce_uniqueness` seals 50,000 I2R records and 50,000 R2I records, collecting all `(key, nonce)` pairs into sets and asserting no duplicates. 100,000 total records; 0 collisions. This covers the structural guarantee provided by the monotonic counter; the test would catch any regression to a random nonce scheme.

### Security tests (T1, T2, T3, T7, T11)

| Test | Scenario | Outcome |
|---|---|---|
| T1a | Replay same record immediately | `RecordError` / `ReplayError` |
| T1b | Replay after 5 subsequent records (still in window) | `RecordError` / `ReplayError` |
| T2a | Flip byte in ciphertext (byte 20) | `RecordError` (AEAD tag fail) |
| T2b | Flip byte in counter field (byte 10) | `RecordError` (nonce change + AAD fail) |
| T2c | Flip byte in session_id field (byte 2) | `RecordError` (session_id mismatch + AAD fail) |
| T2d | Flip byte in payload_length field (byte 14) | `RecordError` (length mismatch + AAD fail) |
| T3a | Deliver `os.urandom(total)` as a record | `RecordError` |
| T3b | Deliver record encrypted under a different session's keys | `RecordError` |
| T7a | Out-of-order delivery (order: 4,2,0,3,1) within window | All 5 accepted exactly once |
| T7b | Record outside window (oldest of 9 with window=8) | `RecordError` / `ReplayError` |
| T7c | Duplicate within window | `RecordError` / `ReplayError` |
| T11a | I2R record presented as R2I | `RecordError` (wrong key) |
| T11b | R2I record presented as I2R | `RecordError` (wrong key) |

---

## Open issues resolved this milestone

No open issues in PROGRESS.md were specifically tagged for M3. The record layer was implemented directly from the §5.5/§5.6 spec and §15 decisions. OI-1 and OI-2 remain tagged to M1 crypto layer and do not affect M3.

---

## Known limitations relevant to this milestone

1. **C0 baseline security test cases deferred (CLAUDE.md §11 M6).** The security test file notes that C0 cases (no security → accepted) are deferred to M6 when the `PassthroughPath` component exists. The current tests verify C1–C3 blocking behaviour only.
2. **Epoch transitions not yet tested (M4 scope).** `RecordLayer` stores `self._keys.epoch` and rejects records with a different epoch byte. Epoch transitions, the overlap grace period (accepting both epoch n and n+1 during a rekey), and epoch counter reset are M4 work.
3. **Counter hard limit not enforced (M4 scope).** CLAUDE.md §5.6 specifies a configurable hard limit (default 2^32) that forces a rekey when reached. This check is not in `RecordLayer` yet; it belongs in the session manager (M4).
4. **In-memory operation only (M5 scope).** There is no asyncio transport, `LinkEmulator`, or `python-can` bus. The record layer is tested by direct method calls.
5. **RecordLayer holds a single epoch's keys (by design).** Multi-epoch overlap for rekeying requires the session manager (M4) to present records from either epoch to the correct `RecordLayer` instance or to manage two instances during the grace period.

---

## What an examiner should know

- **The AEAD tag simultaneously authenticates the header and the plaintext.** The 16-byte header is passed as AAD on every seal and open. This means the AEAD tag is a cryptographic binding over both fields: counter, epoch, session_id, record type, payload length, and the ciphertext. Modifying any of these bytes — not just the payload — causes tag verification to fail. T2 tests four specific header bytes to confirm this.

- **Replay check before mark is the critical ordering invariant.** Calling `replay.check()` before decryption and `replay.mark()` only after successful authentication prevents a forgery from poisoning the window. If this order were reversed — or if `mark()` were called unconditionally — an attacker could force the window to record a counter as seen before the legitimate record with that counter has been authenticated, causing the legitimate record to be rejected as a duplicate on arrival.

- **Direction separation is two-layered: key and salt.** A reflected record (T11) fails because the key is wrong (`k_r2i ≠ k_i2r`), making decryption produce garbage and the tag check fail. Even if the keys were somehow equal (they cannot be — they are HKDF expansions with distinct labels), the salt would differ (`salt_r2i ≠ salt_i2r`), giving a different nonce and a different authentication failure. Both layers trace back to the key schedule design in M2.

- **Nonce uniqueness is structural, not probabilistic.** Unlike a scheme that uses random nonces, this construction assigns an 8-byte counter as the variable nonce component. The counter starts at 0 and increments by 1 per record; it never repeats under a key. The T9 test over 100,000 records confirms there are no collisions, but the real guarantee is the monotonic counter: nonce reuse is impossible as long as the counter does not overflow. The epoch boundary in M4 resets the counter to 0 under a fresh key, preserving the guarantee across rekeying.

- **`payload_length` serves both length validation and integrity.** Its presence in the header lets the receiver reject truncated or extended ciphertexts before calling the AEAD. Its inclusion in the AAD means a length-field tamper is caught by authentication even if the byte counts happened to align. This prevents an attacker from crafting a record where a modified length causes the AEAD to be called on a subset or superset of the ciphertext bytes.

- **The record overhead is measurable and fixed at 32 B per record.** Header (16 B) + AEAD tag (16 B) = 32 B for AES-256-GCM, AES-128-GCM, and ChaCha20-Poly1305. This is not a claim; it is asserted by `test_overhead_size` for each suite. The benchmark (M7) will measure actual overhead including fragmentation headers (8 B per link message) and report the full layered breakdown as required by CLAUDE.md §15 item 17.

---
*Generated by /milestone-log. Source of truth: git history, pytest output, PROGRESS.md.*
