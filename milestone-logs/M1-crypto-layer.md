# M1: Crypto Abstraction Layer

**Date completed:** 2026-11-03  
**Branch:** m1-crypto-layer  
**Commits:** 1 commit (6167cd5)  
**Tests:** 57 passed, 0 failed (51 M1 unit tests + 6 M0 smoke tests)

---

## What was implemented

### Crypto Interfaces (`src/pqcgw/crypto/interfaces.py`)
Four abstract base classes that define the entire cryptographic API used by the rest of the system. Protocol and session-manager code imports only these — never concrete implementations.

- `KEM` — `keygen()`, `encaps(pk)`, `decaps(sk, ct)`; exposes `pk_len`, `ct_len`, `ss_len`
- `Signature` — `keygen()`, `sign(sk, msg)`, `verify(pk, msg, sig)`; exposes `pk_len`, `sig_len`
- `KDF` — `extract(salt, ikm)`, `expand(prk, info, length)`
- `AEAD` — `encrypt(key, nonce, aad, pt)`, `decrypt(...)`; exposes `key_len`, `nonce_len`, `tag_len`

### Concrete Providers (`src/pqcgw/crypto/providers/`)

| File | Class(es) | Algorithms |
|---|---|---|
| `kem_x25519.py` | `X25519Kem` | X25519 wrapped as KEM-style interface |
| `kem_oqs.py` | `OqsKem` | ML-KEM-512, ML-KEM-768, ML-KEM-1024; HQC-* (experimental) |
| `sig_ecdsa.py` | `EcdsaP256` | ECDSA-P256, raw 64-byte r\|\|s wire format |
| `sig_oqs.py` | `OqsSig` | ML-DSA-44/65/87, SLH-DSA-PURE-SHA2-128F; Falcon/FN-DSA (experimental) |
| `kdf_hkdf.py` | `HkdfSha256`, `HkdfSha384` | HKDF with SHA-256 and SHA-384 |
| `aead_impl.py` | `AesGcm256`, `AesGcm128`, `ChaCha20Poly1305` | Three AEAD schemes |

### Hybrid Combiners (`src/pqcgw/crypto/hybrid.py`)

- `HybridKEM` — combines two or more KEMs (default: X25519 + ML-KEM-768). Both implement the `KEM` interface so the session manager sees a single KEM regardless of mode.
- `HybridSignature` — combines two signature schemes (default: ECDSA-P256 + ML-DSA-65). Both must verify independently for the combined verification to succeed.

### Registry and Suite Loader (`src/pqcgw/crypto/registry.py`)
Runtime algorithm discovery and factory functions. Maps friendly names (e.g. `"ml-kem-768"`) to concrete instances. Experimental algorithms are added to the registry only if `oqs.get_enabled_kem_mechanisms()` / `oqs.get_enabled_sig_mechanisms()` expose them. `load_suite(path)` reads a TOML file and returns a fully-resolved `Suite` dataclass.

### Suite TOML Files (`configs/suites/`)

| File | Suite ID | Configuration |
|---|---|---|
| `classical.toml` | 1 | X25519 + ECDSA-P256 + HKDF-SHA256 + AES-256-GCM (C1) |
| `pqc.toml` | 2 | ML-KEM-768 + ML-DSA-65 + HKDF-SHA256 + AES-256-GCM (C2) |
| `hybrid.toml` | 3 | X25519+ML-KEM-768 / ECDSA-P256+ML-DSA-65 + HKDF-SHA256 + AES-256-GCM (C3, default) |

### Tests (`tests/unit/test_crypto_interfaces.py`)
468 lines, 51 test functions covering: size assertions, round-trips, OI-1 regressions, hybrid combiners, registry lookups, and suite loading for all three configurations.

---

## Why it was implemented this way

### Abstract interfaces rather than direct imports
**CLAUDE.md §4**: "The session manager and protocol code must never import a concrete algorithm." This enforces algorithm agility — swapping a suite is a config change only, with no source edits. It also makes the protocol code testable with mock implementations and keeps the trust boundary clean: only the registry and providers touch liboqs or the cryptography package.

### Runtime algorithm discovery
**CLAUDE.md §15 item 4 / §2 rule 9**: liboqs mechanism names change between versions (e.g. `Kyber768` vs `ML-KEM-768`). The registry calls `oqs.get_enabled_kem_mechanisms()` and `oqs.get_enabled_sig_mechanisms()` at import time and normalises names by uppercasing and replacing hyphens/underscores. This makes the code portable across liboqs versions without hardcoded name lists.

### OI-1 length-validation guard (GHSA-w696-4vrr-x6x3)
**PROGRESS.md OI-1**: Earlier versions of liboqs silently zero-padded short inputs, meaning a 1-byte public key would not raise an error but would produce an incorrect result. Every wrapper (`OqsKem`, `OqsSig`, `X25519Kem`, `EcdsaP256`) validates input lengths against the algorithm's reported sizes before any call to the C library. A short or empty input raises `ValueError` at the Python layer. Eight regression tests verify this property.

### Hybrid KEM wire format (u16-length-prefix, fixed suite order)
**CLAUDE.md §4**: "concatenates public keys / ciphertexts (length-prefixed, fixed order from the suite file)." Each component field is prefixed with a 2-byte big-endian length (`struct.pack(">H", len(f))`). Fixed suite order ensures that the combined public key, ciphertext, and shared secret are always assembled in the same sequence, which is a prerequisite for the transcript-binding in the handshake (M2). Shared secrets are concatenated without prefixes before being passed to the KDF, consistent with draft-ietf-tls-hybrid-design.

### HybridSignature is NOT a standardised composite
**CLAUDE.md §4**: "This is a simple dual-signature scheme, not standardised composite." The scheme signs with each component independently and concatenates the signatures with length prefixes. Verification requires both components to pass independently. This is documented in the class docstring. A standardised composite (e.g. from NIST or IETF) would have different transcript-binding semantics; using our own simple scheme is acceptable for a research prototype and is clearly labelled.

### ECDSA-P256 raw r||s format
**CLAUDE.md §15 item 6**: "raw fixed 64-byte r||s (convert to/from DER with `cryptography`)". The `cryptography` package uses DER encoding internally; `sig_ecdsa.py` converts to/from DER using `encode_dss_signature` / `decode_dss_signature`. Each of r and s is zero-padded to 32 bytes. This gives a fixed 64-byte wire format regardless of the actual integer sizes, which simplifies framing in the hybrid combiner.

### ML-DSA empty context string
**CLAUDE.md §15 item 5**: "ML-DSA context string: empty." FIPS 204 allows an optional context string parameter; we pass `b""` throughout. This is documented in `sig_oqs.py` and is consistent across all ML-DSA variants. An examiner can verify this matches our FIPS 204 citations.

### KDF using HKDF extract-then-expand
**CLAUDE.md §5.3**: The key schedule uses `KDF.extract(salt=nonce_i||nonce_r, ikm=ss)` followed by `KDF.expand(prk, info, length)` with domain-separation labels. The `HkdfSha256` and `HkdfSha384` classes implement extract as HMAC(salt, ikm) and expand via `HKDFExpand` from the `cryptography` package. This is a standard RFC 5869 construction, not a custom primitive.

### Experimental algorithms
**CLAUDE.md §15 item 4**: HQC and Falcon/FN-DSA are labelled experimental and added to the registry only if the installed liboqs exposes them. If they are absent, `get_kem()` / `get_sig()` raise `KeyError` with a clear message. This satisfies CLAUDE.md §1 limitation 5 without failing on installations that don't include them.

---

## Key results and test evidence

### Test summary
```
57 passed in 0.25s
  51 M1 unit tests (tests/unit/test_crypto_interfaces.py)
   6 M0 smoke tests (tests/test_smoke.py)
   0 failed, 0 errors, 0 skipped
```

### Size assertions (FIPS 203/204 compliance)
All values confirmed by live liboqs 0.16.0 on Python 3.13.2 / arm64 macOS:

| Algorithm | pk (B) | ct or sig (B) | FIPS source |
|---|---|---|---|
| ML-KEM-512 | 800 | ct 768 | FIPS 203 |
| ML-KEM-768 | 1184 | ct 1088 | FIPS 203 |
| ML-KEM-1024 | 1568 | ct 1568 | FIPS 203 |
| ML-DSA-44 | 1312 | sig 2420 | FIPS 204 |
| ML-DSA-65 | 1952 | sig 3309 | FIPS 204 |
| ML-DSA-87 | 2592 | sig 4627 | FIPS 204 |
| X25519 | 32 | ss 32 | RFC 7748 |
| ECDSA-P256 | 65 | sig 64 | raw r\|\|s |
| SLH-DSA-PURE-SHA2-128F | 32 | sig 17088 | FIPS 205 |

### Round-trip verification
All KEMs and Signatures pass keygen→encaps/sign→decaps/verify round-trips with correct shared-secret or signature equality. HybridKEM (X25519 + ML-KEM-768) and HybridSignature (ECDSA-P256 + ML-DSA-65) also pass full round-trips.

### OI-1 regression coverage
8 tests verify that short/empty pk, ct, or sig inputs raise `ValueError` **before** reaching the liboqs C library for: ML-KEM-768 (encaps short pk, encaps empty pk, decaps short ct, decaps empty ct), ML-DSA-65 (verify short pk, verify empty pk), ECDSA-P256 (verify short pk), X25519 (encaps short pk).

### Suite loading
All three suite TOML files (C1/C2/C3) load successfully via `load_suite()`, resolve to correct `Suite` dataclass instances, and pass KEM + Signature + KDF + AEAD round-trips.

---

## Open issues resolved this milestone

| Issue | Resolution |
|---|---|
| **OI-1**: Validate lengths before calling liboqs (GHSA-w696-4vrr-x6x3) | Implemented in all six provider wrappers; 8 regression tests added. |
| **OI-2**: SLH-DSA-PURE-SHA2-128F sizes for size assertions | Confirmed pk=32, sig=17088 against live library; size assertion test added and passes. |

---

## Known limitations relevant to this milestone

1. **Algorithm agility scope** (CLAUDE.md §1 limitation 4): The abstraction layer covers only the four interfaces defined (KEM, Signature, KDF, AEAD). No claim is made about future algorithms that do not fit these interfaces.
2. **Experimental algorithms** (CLAUDE.md §1 limitation 5): FN-DSA and HQC are included only if the installed library exposes them. They are labelled experimental in the registry and are not benchmarked as primary configurations.
3. **HybridSignature is not standardised**: The dual-signature scheme used in C3 does not follow any NIST or IETF composite-signature standard. It is a simple research prototype construction, labelled as such in the code and docs.

---

## What an examiner should know

- **Interface isolation is the agility mechanism.** The session manager (M2+) will import only `KEM`, `Signature`, `KDF`, and `AEAD` from `interfaces.py`. Swapping from classical to hybrid to PQC-only is a TOML config change with zero source edits. This is verified by the suite-loading tests.

- **The OI-1 guard is a real security property, not just defensive programming.** GHSA-w696-4vrr-x6x3 documents that earlier liboqs versions silently accepted short inputs and zero-padded them, producing incorrect (but non-crashing) results. Our wrapper layer validates lengths independently so that this class of bug cannot resurface silently in a future liboqs update.

- **Hybrid KEM shared-secret concatenation order is fixed and security-relevant.** If the order were variable or negotiated, an attacker could swap component positions and produce a different session key while both sides believe they agreed. The suite file fixes the order; the order is the same on both sides because they load the same suite. This property carries through to the transcript binding in M2.

- **Both signatures in HybridSignature must independently verify.** If only one were checked, an attacker who breaks only the classical component could forge signatures under a hybrid suite. The `verify()` method returns `True` only when all components return `True`; any `False` or exception returns `False`.

- **All randomness is from the OS CSPRNG.** liboqs uses OpenSSL's `RAND_bytes` internally; the `cryptography` package uses the OS entropy pool. No seed is set; no test fixture generates deterministic keys used in benchmarks.

- **Python cannot guarantee secret zeroing.** The code does not attempt to zeroize key material after use because Python's garbage collector does not provide this guarantee. This is a documented limitation (CLAUDE.md §5.3) and is noted in the relevant docstrings.

---
*Generated by /milestone-log. Source of truth: git history, pytest output, PROGRESS.md.*
