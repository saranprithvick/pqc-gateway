# Threat Model

This document describes the security goals, adversary model, assumptions, and known
residual risks of the PQC gateway prototype.

---

## 1. Assets

| Asset | Why it matters |
|---|---|
| **Session keys** (`k_i2r`, `k_r2i`, salts, `k_finished`, `rekey_sec`) | Compromise allows decryption of past or future records (depending on epoch) and injection of forged records |
| **Long-term identity signing keys** | Compromise allows an attacker to impersonate the gateway or the peer in future handshakes |
| **CAN frame confidentiality** | CAN payloads (e.g. sensor readings, actuator commands) must not be readable by a link attacker |
| **CAN frame integrity and authenticity** | Frames delivered to the peer must be the same frames the legacy CAN bus emitted, without modification or injection |
| **Session establishment integrity** | Both endpoints must agree on the same session keys; a man-in-the-middle must not be able to substitute keys |

---

## 2. Adversaries

### 2.1 Link attacker

Fully controls the network link between the Gateway and the ModernPeer. Can:
- **Observe** all bytes in transit (passive eavesdropping).
- **Modify** any byte of any message.
- **Inject** arbitrary messages.
- **Replay** previously captured messages.
- **Drop** or delay messages.

The link attacker cannot access the CAN bus, the gateway's or peer's internal process
memory, or the identity key files.

### 2.2 CAN-bus attacker

Can inject frames onto the legacy CAN bus before they reach the CanAdapter. The gateway
does not authenticate CAN-bus senders: any injected frame is forwarded (protected) to
the peer. This is a **known non-prevention** (security test T12, limitation 1).

### 2.3 Future quantum adversary — harvest-now-decrypt-later (HNDL)

Records encrypted traffic today; decrypts it once a cryptographically relevant quantum
computer (CRQC) becomes available. X25519 (C1) is vulnerable to this attack; ML-KEM
(C2, C3) provides post-quantum confidentiality by design. Configuration C3 (hybrid) is
resistant to HNDL **provided** the ML-KEM component remains secure; the classical
X25519 component remains as a hedge against both implementation weaknesses in the
PQC library and unexpected cryptanalytic advances against ML-KEM.

---

## 3. Assumptions

| Assumption | Consequence if violated |
|---|---|
| Identity keys are pre-provisioned trust anchors (no PKI, no revocation) | A compromised identity key allows impersonation until manually replaced |
| OS CSPRNG (`os.urandom`) is trustworthy | Session IDs, nonces, and ephemeral key material become predictable |
| liboqs and `cryptography` library implementations are correct | Implementation bugs could bypass security goals. Known prior issue: GHSA-w696-4vrr-x6x3 (liboqs-python < 0.16.0.2 silently zero-padded short inputs); fixed in 0.16.0.2 and mitigated in this project's wrappers, which validate all input lengths before passing to liboqs. Library correctness is otherwise outside this prototype's scope. |
| Both endpoints are inside their respective trust boundaries | A compromised gateway endpoint breaks confidentiality and integrity |
| The system clock is not under attacker control | Only affects grace-period expiry; replays outside the window are still rejected by the counter |

---

## 4. Security goals and test coverage

Each row maps one security goal to the test(s) that verify it and the expected result on
C0 (baseline, no crypto) and C1–C3 (gateway configurations).

| ID | Threat / Goal | Test | C1–C3 | C0 |
|---|---|---|---|---|
| T1 | Replay of a captured valid record | Rejected by replay window | Rejected | Accepted |
| T2 | Modification of payload or any header field | Rejected (AEAD tag failure) | Rejected | Accepted |
| T3 | Injection of forged / random records | Rejected (AEAD tag failure) | Rejected | Accepted |
| T4 | Handshake with an unknown identity key | Handshake aborts (signature verification fails) | Aborts | n/a |
| T5 | MITM modifies KEM public key, ciphertext, or nonce | Handshake fails (signature or decapsulation fails) | Fails | n/a |
| T6 | Downgrade: change `suite_id` or force a weaker suite | Aborts (signed transcript + fixed allowed-suite list) | Aborts | n/a |
| T7 | Out-of-order and out-of-window counters | In-window unseen accepted once; older/duplicate rejected | Pass | n/a |
| T8 | Rekey boundary: in-flight records survive grace; old epoch rejected after grace | Records during grace accepted; old epoch rejected after | Pass | n/a |
| T9 | Nonce uniqueness across ≥ 10^5 records and across rekey boundaries | (key, nonce) never repeats | Pass | n/a |
| T10 | Counter exhaustion forces rekey or closes session | Light rekey triggered; session closes on failure | Pass | n/a |
| T11 | Reflection: send a record back to its sender | Rejected (per-direction keys; reflected record uses wrong key) | Rejected | n/a |
| T12 | Forged frame injected on the legacy CAN bus | **Forwarded (NOT prevented)** — known non-prevention, limitation 1 | Forwarded | Forwarded |
| T13 | Reflect a FINISHED message back to its sender | Handshake fails (HMAC inputs differ: "I" vs "R" label; FINISHED_R also commits FINISHED_I) | Fails | n/a |

Source: `tests/security/`, `results/tables/security_t1_t13.csv`, `results/tables/security_c0_c3.csv`.

---

## 5. Out of scope

### 5.1 DoS / rate limiting

A link attacker can replay a captured HELLO_I, forcing the responder to perform KEM
encapsulation and signing for each copy before the lack of the KEM secret key causes the
handshake to silently fail. This is a denial-of-service consideration; rate limiting is
outside the scope of this prototype (see CLAUDE.md §5.9).

### 5.2 Side-channel attacks

HMAC comparisons use `hmac.compare_digest` (constant-time). No claim is made about the
timing behaviour of liboqs KEM / signature operations or the `cryptography` package's
AEAD implementation. Timing side-channels on those operations are out of scope.

### 5.3 Unauthenticated type prefix

The 1-byte link message prefix (`0x01`–`0x10`) is not covered by any signature or AEAD.
Altering it can cause a message to be dropped — no worse than the attacker dropping it;
the receiver rejects it at the parse or AEAD step. The session_id is in the authenticated record header (AEAD AAD), so
altering the prefix cannot cause a record to be accepted under a different session.

### 5.4 CAN-bus forgery (T12)

The gateway does not authenticate CAN-bus senders. A forged CAN frame injected onto the
legacy bus will be forwarded (protected) to the peer. This is a known non-prevention
(limitation 1) and is asserted by security test T12. Addressing it would require
in-vehicle CAN authentication (e.g. AUTOSAR SecOC), which is future work.

### 5.5 Formal verification

The handshake is a custom protocol. It has not been modelled in ProVerif, Tamarin, or
any other formal tool. No formal security proofs are claimed.

### 5.6 PKI / certificate chains / revocation

Identity keys are pre-provisioned trust anchors. There is no certificate authority,
certificate chain, or revocation mechanism. Key compromise requires manual replacement.

---

## 6. Residual risks

| Risk | Detail |
|---|---|
| **Light rekey: forward secrecy only, not post-compromise security** | Light rekey (ratchet) provides forward secrecy for past epochs: an observer who later learns the current `rekey_sec_n` cannot decrypt records from epochs < n. However, it does **not** provide post-compromise security: an attacker who already holds `rekey_sec_n` can derive all future epoch keys. Only a full rekey (new handshake, new ephemeral KEM) achieves post-compromise security. |
| **Light-rekey forward secrecy depends on secret deletion** | Forward secrecy for past epochs requires that the previous `rekey_sec` is deleted after the grace period. Python cannot guarantee in-memory zeroization of overwritten values (see LIMITATIONS.md); copies of old secrets may remain in memory. |
| **No DoS protection** | A link attacker can replay captured HELLO_I messages to force the responder to perform KEM encapsulation and signing. Rate limiting is out of scope (§5.1). |
| **C1 authentication is not quantum-resistant** | HNDL threatens the **confidentiality** of C1 traffic (X25519). The ECDSA-P256 signatures used in the C1 handshake are also vulnerable to a live quantum adversary breaking authentication. C2 and C3 use ML-DSA-65 for quantum-resistant authentication. |
| **Identity-key compromise allows impersonation** | There is no revocation path. A compromised long-term signing key must be replaced out-of-band on both endpoints. |
| **HNDL threatens C1 confidentiality** | Traffic encrypted under C1 (X25519 only) is vulnerable to harvest-now-decrypt-later by a future CRQC. C2 (ML-KEM-768) and C3 (hybrid X25519+ML-KEM-768) are designed to resist this attack. |
| **CAN-bus trust boundary** | The gateway trusts every frame it receives from the CAN bus. Physical access to the CAN bus is an out-of-band concern. |
