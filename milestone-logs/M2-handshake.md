# M2: Handshake State Machines and Key Schedule

**Date completed:** 2026-11-03  
**Branch:** m2-handshake  
**Commits:** 1 commit (53b5ee9) + merge (bfd81a8)  
**Tests:** 85 passed, 0 failed (28 new M2 tests + 57 carried from M0/M1)

---

## What was implemented

### Protocol Messages (`src/pqcgw/protocol/messages.py`)
Dataclasses and deterministic wire serialization for the two handshake messages.

- **`HelloI`** — initiator's opening message. Fields: `version` (u8), `suite_id` (u8), `session_id` (4 B), `gateway_id` (u16-prefixed UTF-8), `peer_id` (u16-prefixed UTF-8), `nonce_i` (32 B), `kem_pk` (u16-prefixed), `sig` (u16-prefixed). Exposes `body_bytes()` (fields 1–7, for signing) and `to_bytes()` / `from_bytes()` for the full wire form.
- **`HelloR`** — responder's reply. Fields: `version`, `suite_id`, `session_id`, `nonce_r` (32 B), `kem_ct` (u16-prefixed), `sig` (u16-prefixed). Same `body_bytes()` / `to_bytes()` / `from_bytes()` API.
- **`FINISHED_I` / `FINISHED_R`** — plain 32-byte HMAC values; no wrapper class needed.
- `_pack_varlen` / `_unpack_varlen` — shared helpers for u16-length-prefixed field encoding.

### Key Schedule (`src/pqcgw/protocol/keyschedule.py`)
Derives all session keys from the handshake transcript.

- **`_info(label, suite_id, th, epoch)`** — builds the HKDF info field per §15 item 8: `u8(len(label)) || label_ascii || u8(suite_id) || th || u8(epoch)`.
- **`suite_hash(suite)`** — returns `hashlib.sha256` or `hashlib.sha384` by inspecting the suite's KDF type (§15 item 7).
- **`SessionKeys`** dataclass — holds `k_i2r`, `k_r2i`, `salt_i2r` (4 B), `salt_r2i` (4 B), `k_finished` (32 B), `rekey_sec0` (32 B), plus `suite_id` and `epoch`.
- **`derive_session_keys(suite, ss, nonce_i, nonce_r, th, epoch=0)`** — runs HKDF extract over `nonce_i || nonce_r` as salt and the combined shared secret as IKM, then derives all six values with distinct labels.

### Handshake State Machines (`src/pqcgw/protocol/handshake.py`)
Two explicit state machines communicating over an in-memory byte channel. No sockets or asyncio yet — those come in M5.

- **`IdentityContext`** dataclass — bundles `my_id`, `peer_id`, `my_sk`, `my_pk`, `peer_pk` (trust anchor), and `allowed_suite_ids` for one side.
- **`HandshakeInitiator`** (Gateway) — states: `IDLE → HELLO_SENT → KEYS_DERIVED → ESTABLISHED | FAILED`. Three public methods: `start()`, `process_hello_r()`, `process_finished_r()`.
- **`HandshakeResponder`** (Peer) — states: `IDLE → HELLO_RECEIVED → ESTABLISHED | FAILED`. Two public methods: `process_hello_i()`, `process_finished_i()`.
- **`HandshakeError`** — raised on any failure; detail logged locally only, nothing sent on the wire.
- **`_hmac_digest` / `_hmac_verify`** — HMAC helpers using `hmac.compare_digest` for constant-time verification.

### Tests — Unit (`tests/unit/test_handshake.py`, 18 tests)
Round-trips for C1/C2/C3, key schedule KAT, transcript binding, responder cache, and FINISHED cross-check.

### Tests — Security (`tests/security/test_t4_t5_t6_t13.py`, 10 tests)
T4, T5, T6, T13 across C1/C2/C3 handshake scenarios.

---

## Why it was implemented this way

### 4-message handshake: HELLO_I → HELLO_R → FINISHED_I → FINISHED_R (§15 items 11, 14)
The body text of §5.2 describes three messages. §15 item 11 resolves this: FINISHED_R is always sent, and the initiator treats the session as established only after verifying it. This means neither side commits to using session keys until both have authenticated the transcript. Without FINISHED_R, an active attacker who intercepts FINISHED_I and injects a forged response could make the responder accept a session that the initiator believes failed.

### FINISHED_R chains on FINISHED_I (§15 item 14)
`FINISHED_I = HMAC(k_finished, "I" || th)`  
`FINISHED_R = HMAC(k_finished, "R" || th || FINISHED_I_bytes)`

The chain means FINISHED_R is cryptographically dependent on what the responder actually received as FINISHED_I. This makes T13 (reflection attack) structurally impossible: a reflected FINISHED_I can never equal the expected FINISHED_R, and a reflected FINISHED_R cannot satisfy the responder's FINISHED_I check. The two values can never be equal by construction (different prefixes, different lengths).

### Constant-time HMAC comparison (`hmac.compare_digest`)
CLAUDE.md §2 requires MACs and tags to be compared only with constant-time functions. A timing-variable comparison (e.g. `==`) leaks how many bytes matched before the first mismatch, which can be exploited to forge MACs one byte at a time. `hmac.compare_digest` is used for both FINISHED_I and FINISHED_R verification.

### No distinguishing error detail on the wire (§5.8)
All verification failures — wrong signature, wrong suite_id, wrong session_id, HMAC mismatch — raise `HandshakeError` with a descriptive local log message but send nothing back to the peer. This prevents an attacker from learning which check failed (e.g. distinguishing "signature invalid" from "suite_id rejected"), which could help them craft targeted attacks. The `_fail()` helper enforces this consistently on both sides.

### Signature covers the full body including KEM public key and nonces (§5.2)
`sig_I = Sign(sk_I, "hs-v1-I" || H(body_bytes))` where `body_bytes` includes `suite_id`, both IDs, `nonce_i`, and `kem_pk_I`. Any MITM modification to any of these fields invalidates the signature (T5). The domain-separation prefix `"hs-v1-I"` / `"hs-v1-R"` prevents cross-message signature confusion even if a future message were to have the same hash as a body.

### `sig_R` covers HELLO_I || HELLO_R_body (§5.2)
`sig_R = Sign(sk_R, "hs-v1-R" || H(hello_i_bytes || hello_r_body))`. The responder's signature binds itself to the specific HELLO_I it received — including the initiator's KEM public key and nonce. If an attacker replays a different HELLO_I, the responder produces a different HELLO_R and a different sig_R, which the legitimate initiator will reject.

### Transcript hash `th = H(HELLO_I || HELLO_R)` (§5.3)
The transcript hash ties the FINISHED messages and all session keys to the exact bytes exchanged in the handshake. Even if an attacker can forge signatures (e.g. in a future post-quantum break of ECDSA-P256 alone), they cannot use a modified transcript because `th` would differ and the FINISHED HMAC would not verify. This is the handshake's transcript-binding property.

### HKDF info label encoding (§15 item 8)
`info = u8(len(label)) || label_ascii || u8(suite_id) || th || u8(epoch)`

Including `suite_id` inside the info field means keys derived from different suites are domain-separated even if the shared secret and nonces happened to be identical. Including `th` binds each key to the specific transcript. Including `epoch` ensures rekeyed sessions produce different keys from the initial epoch. The label length prefix prevents extension attacks where a short label could be a prefix of a longer one.

### Direction-separated keys (§5.3, §5.5)
`k_i2r` and `k_r2i` are derived with different labels. This means a record encrypted by the initiator cannot be decrypted or replayed by the responder as if it came from itself (T11 in the record layer, M3). The distinct salts `salt_i2r` / `salt_r2i` serve the same purpose for nonce construction.

### Responder cache keyed by `(session_id, H(HELLO_I))` (§15 item 9)
The responder stores its HELLO_R and resends it byte-identical when it receives a duplicate HELLO_I. Without this, a lost HELLO_R would cause the initiator to retransmit HELLO_I, and the responder would re-encapsulate (generating a different shared secret) and re-sign — producing a new HELLO_R that the initiator cannot use to finish the handshake. The cache is keyed on the hash of HELLO_I so a genuinely different HELLO_I (e.g. a new session attempt) starts fresh. After cache expiry a replayed HELLO_I is treated as a new session (documented DoS caveat, CLAUDE.md §5.9).

### Downgrade protection: allowed_suite_ids checked before signature verification (§5.4)
The responder checks `suite_id in allowed_suite_ids` before doing the expensive signature verification. This means a downgrade attempt with an unsupported suite_id is rejected immediately with no cryptographic work — protecting against DoS from crafted HELLO_I messages with valid signatures for suites the responder has disabled.

### In-memory link for M2
The state machines exchange bytes via direct method calls. No networking, no asyncio, no LinkEmulator. The "link" in M2 is just the caller passing `hello_i_bytes` from `initiator.start()` directly into `responder.process_hello_i()`. The real link (LinkEmulator with delay, loss, fragmentation, retransmission) is wired in M5. This keeps M2 focused on protocol correctness independent of transport.

---

## Key results and test evidence

### Test summary
```
85 passed in 0.28s
  18 M2 unit tests    (tests/unit/test_handshake.py)
  10 M2 security tests (tests/security/test_t4_t5_t6_t13.py)
  51 M1 unit tests    (tests/unit/test_crypto_interfaces.py)
   6 M0 smoke tests   (tests/test_smoke.py)
   0 failed, 0 errors, 0 skipped
```

### Handshake round-trips (C1, C2, C3)
All three suite configurations complete a full 4-message handshake and produce identical `SessionKeys` on both sides:

| Suite | Configuration | Keys match |
|---|---|---|
| C1 | X25519 + ECDSA-P256 | ✓ k_i2r, k_r2i, salts, k_finished, rekey_sec0 |
| C2 | ML-KEM-768 + ML-DSA-65 | ✓ all six values |
| C3 | Hybrid (X25519+ML-KEM-768, ECDSA+ML-DSA-65) | ✓ all six values |

### Key schedule verification
- **Deterministic:** same inputs → same outputs across multiple calls.
- **Direction-separated:** `k_i2r ≠ k_r2i`, `salt_i2r ≠ salt_r2i` in all suites.
- **All six values distinct:** `k_i2r`, `k_r2i`, `k_finished`, `rekey_sec0` are mutually distinct.
- **Transcript binding:** two handshakes with different `session_id`s produce different keys even with the same suite.

### Responder cache
Sending the same HELLO_I bytes twice to the same responder returns byte-identical HELLO_R both times — verified by direct byte comparison in the test.

### FINISHED cross-check
`FINISHED_I ≠ FINISHED_R` confirmed for C1, C2, C3 — structural impossibility by label construction.

### Security tests (T4, T5, T6, T13)

| Test | Attack | Result |
|---|---|---|
| T4a | Wrong peer_pk on responder | `HandshakeError` (sig_I fails) |
| T4b | Wrong peer_pk on initiator | `HandshakeError` (sig_R fails) |
| T5a | Flip byte in `kem_pk_I` | `HandshakeError` (sig_I fails) |
| T5b | Flip byte in `nonce_i` | `HandshakeError` (sig_I fails) |
| T5c | Flip byte in `kem_ct` | `HandshakeError` (sig_R fails) |
| T5d | Flip byte in `nonce_r` | `HandshakeError` (sig_R fails) |
| T6a | suite_id not in allowed list | `HandshakeError` (before sig check) |
| T6b | suite_id byte tampered in HELLO_I | `HandshakeError` (sig_I fails) |
| T13a | FINISHED_I reflected to initiator as FINISHED_R | `HandshakeError` |
| T13b | FINISHED_R fed to responder as FINISHED_I | `HandshakeError` |

---

## Open issues resolved this milestone

None from PROGRESS.md were specifically tagged for M2. The M2 protocol design followed §15 decisions directly with no new open issues raised.

---

## Known limitations relevant to this milestone

1. **In-memory link only (CLAUDE.md §11 M2 scope):** The state machines communicate via direct method calls. Network transport, fragmentation, retransmission, and loss handling are M5.
2. **Identity keys generated ephemerally in tests:** For M2, keypairs are generated at test time. The `gen_keys.py` script and file-loading infrastructure (`configs/keys/`) come in M5.
3. **Responder cache has no expiry:** The cache is an in-memory dict with no TTL. Expiry and the associated DoS caveat (replayed HELLO_I after expiry = new session) are documented in CLAUDE.md §5.9 and §15 item 9. A bounded LRU cache with TTL will be added in M5 when the full session lifecycle is wired up.
4. **No on-wire timestamps (CLAUDE.md §5.5):** Latency is measured out-of-band in M7; nothing is added to the handshake wire format.
5. **Record layer not yet wired (M3):** `SessionKeys` is returned from `process_finished_r()` but not yet used to protect any traffic.

---

## What an examiner should know

- **The transcript hash `th` is the anchor for all session keys.** Every key and FINISHED HMAC is derived from `H(HELLO_I || HELLO_R)`. This means the entire negotiated state — both nonces, both KEM artifacts, both identities, the suite — is cryptographically committed before any session traffic flows. An attacker who modifies any handshake byte produces a different `th` and therefore different keys, causing both FINISHED checks to fail.

- **FINISHED_R chains on FINISHED_I to eliminate reflection (§15 item 14, T13).** If FINISHED_R were simply `HMAC(k_finished, "R" || th)`, an attacker who observed one direction's FINISHED could replay it as the other's. The chain `HMAC(k_finished, "R" || th || FINISHED_I_bytes)` makes FINISHED_R dependent on what the responder actually received, which is verifiable by the initiator. The two values cannot collide by construction: different prefixes, different lengths.

- **Constant-time HMAC comparison prevents timing oracle attacks.** A timing-variable comparison of HMAC values allows an attacker to learn how many bytes matched, enabling byte-by-byte forgery in O(256n) queries rather than O(2^n). `hmac.compare_digest` eliminates this. This is mandated by CLAUDE.md §2 ("compare MACs/tags only with constant-time functions").

- **Downgrade protection is layered: allowed list + signed transcript.** The responder's `allowed_suite_ids` check rejects a disallowed suite before doing any cryptographic work (T6a). Even if this check were absent, tampering with `suite_id` in HELLO_I would invalidate `sig_I` because `suite_id` is included in the signed body (T6b). Both layers must hold for full downgrade resistance.

- **No distinguishing wire errors.** All failures — wrong key, wrong suite, replay, MITM — raise `HandshakeError` locally and send nothing to the peer. This prevents an attacker from using error responses to learn which check failed, which would help them probe for valid keys or suites.

- **The state machine enforces ordering.** Each method checks the current state before proceeding; calling methods out of order raises `HandshakeError`. This prevents an attacker from injecting messages at the wrong phase (e.g. sending FINISHED before HELLO_R).

---
*Generated by /milestone-log. Source of truth: git history, pytest output, PROGRESS.md.*
