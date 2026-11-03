"""M1 unit tests: KAT, round-trip, size assertions, OI-1 regression, hybrid.

Size constants are compared against FIPS 203/204 values AND verified live
against the installed liboqs.  A mismatch causes a hard fail with a clear
message (per OI-2, PROGRESS.md).
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import pytest

from pqcgw.crypto.providers.aead_impl import AesGcm128, AesGcm256, ChaCha20Poly1305
from pqcgw.crypto.providers.kdf_hkdf import HkdfSha256, HkdfSha384
from pqcgw.crypto.providers.kem_oqs import OqsKem
from pqcgw.crypto.providers.kem_x25519 import X25519Kem
from pqcgw.crypto.providers.sig_ecdsa import EcdsaP256
from pqcgw.crypto.providers.sig_oqs import OqsSig
from pqcgw.crypto.hybrid import HybridKEM, HybridSignature
from pqcgw.crypto.registry import get_kem, get_sig, get_kdf, get_aead, load_suite

SUITE_DIR = Path(__file__).parent.parent.parent / "configs" / "suites"

# ---------------------------------------------------------------------------
# Expected sizes from FIPS 203 / FIPS 204 — tests FAIL if library disagrees
# ---------------------------------------------------------------------------

EXPECTED_KEM_SIZES = {
    "ML-KEM-512":  {"pk": 800,  "ct": 768,  "ss": 32},
    "ML-KEM-768":  {"pk": 1184, "ct": 1088, "ss": 32},
    "ML-KEM-1024": {"pk": 1568, "ct": 1568, "ss": 32},
}

EXPECTED_SIG_SIZES = {
    "ML-DSA-44": {"pk": 1312, "sig": 2420},
    "ML-DSA-65": {"pk": 1952, "sig": 3309},
    "ML-DSA-87": {"pk": 2592, "sig": 4627},
    # OI-2: SLH-DSA exposed as SLH_DSA_PURE_SHA2_128F in liboqs 0.16.0
    "SLH_DSA_PURE_SHA2_128F": {"pk": 32, "sig": 17088},
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _kem_name_in_liboqs(friendly: str) -> str:
    """Resolve friendly name to what liboqs actually calls it."""
    import oqs
    available = oqs.get_enabled_kem_mechanisms()
    norm = friendly.upper().replace("-", "_").replace(" ", "_")
    for m in available:
        if m.upper().replace("-", "_").replace(" ", "_") == norm:
            return m
    pytest.skip(f"KEM '{friendly}' not enabled in installed liboqs")


def _sig_name_in_liboqs(friendly: str) -> str:
    import oqs
    available = oqs.get_enabled_sig_mechanisms()
    norm = friendly.upper().replace("-", "_").replace(" ", "_")
    for m in available:
        if m.upper().replace("-", "_").replace(" ", "_") == norm:
            return m
    pytest.skip(f"Signature '{friendly}' not enabled in installed liboqs")


# ===========================================================================
# 1. Size assertions (FIPS 203 / 204)
# ===========================================================================

@pytest.mark.parametrize("friendly,expected", [
    ("ML-KEM-512",  EXPECTED_KEM_SIZES["ML-KEM-512"]),
    ("ML-KEM-768",  EXPECTED_KEM_SIZES["ML-KEM-768"]),
    ("ML-KEM-1024", EXPECTED_KEM_SIZES["ML-KEM-1024"]),
])
def test_kem_sizes(friendly: str, expected: dict) -> None:
    oqs_name = _kem_name_in_liboqs(friendly)
    kem = OqsKem(oqs_name)
    assert kem.pk_len == expected["pk"], (
        f"{oqs_name} pk_len: library={kem.pk_len}, FIPS={expected['pk']}"
    )
    assert kem.ct_len == expected["ct"], (
        f"{oqs_name} ct_len: library={kem.ct_len}, FIPS={expected['ct']}"
    )
    assert kem.ss_len == expected["ss"], (
        f"{oqs_name} ss_len: library={kem.ss_len}, FIPS={expected['ss']}"
    )


@pytest.mark.parametrize("friendly,expected", [
    ("ML-DSA-44", EXPECTED_SIG_SIZES["ML-DSA-44"]),
    ("ML-DSA-65", EXPECTED_SIG_SIZES["ML-DSA-65"]),
    ("ML-DSA-87", EXPECTED_SIG_SIZES["ML-DSA-87"]),
    ("SLH_DSA_PURE_SHA2_128F", EXPECTED_SIG_SIZES["SLH_DSA_PURE_SHA2_128F"]),
])
def test_sig_sizes(friendly: str, expected: dict) -> None:
    oqs_name = _sig_name_in_liboqs(friendly)
    sig = OqsSig(oqs_name)
    assert sig.pk_len == expected["pk"], (
        f"{oqs_name} pk_len: library={sig.pk_len}, FIPS={expected['pk']}"
    )
    assert sig.sig_len == expected["sig"], (
        f"{oqs_name} sig_len: library={sig.sig_len}, FIPS={expected['sig']}"
    )


def test_x25519_sizes() -> None:
    kem = X25519Kem()
    assert kem.pk_len == 32
    assert kem.ct_len == 32
    assert kem.ss_len == 32


def test_ecdsa_p256_sizes() -> None:
    sig = EcdsaP256()
    assert sig.pk_len == 65
    assert sig.sig_len == 64


# ===========================================================================
# 2. KEM round-trip tests
# ===========================================================================

def test_x25519_roundtrip() -> None:
    kem = X25519Kem()
    pk, sk = kem.keygen()
    assert len(pk) == kem.pk_len
    assert len(sk) == 32
    ct, ss_enc = kem.encaps(pk)
    assert len(ct) == kem.ct_len
    ss_dec = kem.decaps(sk, ct)
    assert ss_enc == ss_dec


@pytest.mark.parametrize("friendly", ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
def test_mlkem_roundtrip(friendly: str) -> None:
    oqs_name = _kem_name_in_liboqs(friendly)
    kem = OqsKem(oqs_name)
    pk, sk = kem.keygen()
    assert len(pk) == kem.pk_len
    ct, ss_enc = kem.encaps(pk)
    assert len(ct) == kem.ct_len
    ss_dec = kem.decaps(sk, ct)
    assert ss_enc == ss_dec, f"{oqs_name}: shared secrets differ"


# ===========================================================================
# 3. Signature round-trip tests
# ===========================================================================

def test_ecdsa_roundtrip() -> None:
    sig = EcdsaP256()
    pk, sk = sig.keygen()
    assert len(pk) == sig.pk_len
    msg = b"test message for ecdsa"
    signature = sig.sign(sk, msg)
    assert len(signature) == sig.sig_len
    assert sig.verify(pk, msg, signature)
    assert not sig.verify(pk, msg + b"x", signature)


@pytest.mark.parametrize("friendly", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
def test_mldsa_roundtrip(friendly: str) -> None:
    oqs_name = _sig_name_in_liboqs(friendly)
    scheme = OqsSig(oqs_name)
    pk, sk = scheme.keygen()
    assert len(pk) == scheme.pk_len
    msg = b"test message for ml-dsa"
    signature = scheme.sign(sk, msg)
    assert len(signature) == scheme.sig_len
    assert scheme.verify(pk, msg, signature)
    assert not scheme.verify(pk, msg + b"x", signature)


def test_slh_dsa_roundtrip() -> None:
    oqs_name = _sig_name_in_liboqs("SLH_DSA_PURE_SHA2_128F")
    scheme = OqsSig(oqs_name)
    pk, sk = scheme.keygen()
    msg = b"test message for slh-dsa"
    signature = scheme.sign(sk, msg)
    assert scheme.verify(pk, msg, signature)
    assert not scheme.verify(pk, msg + b"x", signature)


# ===========================================================================
# 4. KDF round-trip tests
# ===========================================================================

@pytest.mark.parametrize("kdf_cls", [HkdfSha256, HkdfSha384])
def test_kdf_deterministic(kdf_cls) -> None:
    kdf = kdf_cls()
    salt = secrets.token_bytes(32)
    ikm = secrets.token_bytes(64)
    info = b"test-label"
    prk1 = kdf.extract(salt, ikm)
    prk2 = kdf.extract(salt, ikm)
    assert prk1 == prk2, "KDF extract must be deterministic"
    out1 = kdf.expand(prk1, info, 48)
    out2 = kdf.expand(prk2, info, 48)
    assert out1 == out2, "KDF expand must be deterministic"
    assert len(out1) == 48


def test_kdf_different_info_gives_different_output() -> None:
    kdf = HkdfSha256()
    prk = kdf.extract(b"salt", b"ikm")
    out1 = kdf.expand(prk, b"label-A", 32)
    out2 = kdf.expand(prk, b"label-B", 32)
    assert out1 != out2


# ===========================================================================
# 5. AEAD round-trip tests
# ===========================================================================

@pytest.mark.parametrize("aead_cls,key_len", [
    (AesGcm256, 32),
    (AesGcm128, 16),
    (ChaCha20Poly1305, 32),
])
def test_aead_roundtrip(aead_cls, key_len: int) -> None:
    aead = aead_cls()
    assert aead.key_len == key_len
    assert aead.nonce_len == 12
    assert aead.tag_len == 16
    key = secrets.token_bytes(key_len)
    nonce = secrets.token_bytes(12)
    aad = b"associated data"
    pt = b"hello world plaintext"
    ct = aead.encrypt(key, nonce, aad, pt)
    recovered = aead.decrypt(key, nonce, aad, ct)
    assert recovered == pt


@pytest.mark.parametrize("aead_cls,key_len", [
    (AesGcm256, 32),
    (AesGcm128, 16),
    (ChaCha20Poly1305, 32),
])
def test_aead_tampered_ct_raises(aead_cls, key_len: int) -> None:
    aead = aead_cls()
    key = secrets.token_bytes(key_len)
    nonce = secrets.token_bytes(12)
    ct = aead.encrypt(key, nonce, b"aad", b"plaintext")
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    with pytest.raises(ValueError):
        aead.decrypt(key, nonce, b"aad", bytes(tampered))


# ===========================================================================
# 6. OI-1 regression tests: short/empty inputs must raise ValueError at
#    wrapper layer, BEFORE reaching liboqs (GHSA-w696-4vrr-x6x3 guard).
# ===========================================================================

def test_oqs_kem_short_pk_raises_before_liboqs() -> None:
    oqs_name = _kem_name_in_liboqs("ML-KEM-768")
    kem = OqsKem(oqs_name)
    with pytest.raises(ValueError, match="expected pk"):
        kem.encaps(b"\x00")  # 1 byte, should be 1184


def test_oqs_kem_empty_pk_raises_before_liboqs() -> None:
    oqs_name = _kem_name_in_liboqs("ML-KEM-768")
    kem = OqsKem(oqs_name)
    with pytest.raises(ValueError, match="expected pk"):
        kem.encaps(b"")


def test_oqs_kem_short_ct_raises_before_liboqs() -> None:
    oqs_name = _kem_name_in_liboqs("ML-KEM-768")
    kem = OqsKem(oqs_name)
    pk, sk = kem.keygen()
    with pytest.raises(ValueError, match="expected ct"):
        kem.decaps(sk, b"\x00")  # 1 byte, should be 1088


def test_oqs_kem_empty_ct_raises_before_liboqs() -> None:
    oqs_name = _kem_name_in_liboqs("ML-KEM-768")
    kem = OqsKem(oqs_name)
    pk, sk = kem.keygen()
    with pytest.raises(ValueError, match="expected ct"):
        kem.decaps(sk, b"")


def test_oqs_sig_short_pk_raises_before_liboqs() -> None:
    oqs_name = _sig_name_in_liboqs("ML-DSA-65")
    scheme = OqsSig(oqs_name)
    with pytest.raises(ValueError, match="expected pk"):
        scheme.verify(b"\x00", b"msg", b"\x00" * scheme.sig_len)


def test_oqs_sig_empty_pk_raises_before_liboqs() -> None:
    oqs_name = _sig_name_in_liboqs("ML-DSA-65")
    scheme = OqsSig(oqs_name)
    with pytest.raises(ValueError, match="expected pk"):
        scheme.verify(b"", b"msg", b"\x00" * scheme.sig_len)


def test_ecdsa_short_pk_raises() -> None:
    sig = EcdsaP256()
    with pytest.raises(ValueError, match="expected pk"):
        sig.verify(b"\x04\x00", b"msg", b"\x00" * 64)


def test_x25519_short_pk_raises() -> None:
    kem = X25519Kem()
    with pytest.raises(ValueError, match="expected pk"):
        kem.encaps(b"\x00")


# ===========================================================================
# 7. Hybrid KEM round-trip
# ===========================================================================

def test_hybrid_kem_roundtrip() -> None:
    x25519 = X25519Kem()
    oqs_name = _kem_name_in_liboqs("ML-KEM-768")
    mlkem = OqsKem(oqs_name)
    hybrid = HybridKEM([x25519, mlkem])

    assert hybrid.pk_len == (2 + x25519.pk_len) + (2 + mlkem.pk_len)
    assert hybrid.ct_len == (2 + x25519.ct_len) + (2 + mlkem.ct_len)
    assert hybrid.ss_len == x25519.ss_len + mlkem.ss_len

    pk, sk = hybrid.keygen()
    assert len(pk) == hybrid.pk_len
    ct, ss_enc = hybrid.encaps(pk)
    assert len(ct) == hybrid.ct_len
    ss_dec = hybrid.decaps(sk, ct)
    assert ss_enc == ss_dec, "HybridKEM: shared secrets differ"


def test_hybrid_kem_different_keygens_give_different_ss() -> None:
    x25519 = X25519Kem()
    oqs_name = _kem_name_in_liboqs("ML-KEM-768")
    mlkem = OqsKem(oqs_name)
    hybrid = HybridKEM([x25519, mlkem])

    pk1, sk1 = hybrid.keygen()
    pk2, sk2 = hybrid.keygen()
    ct1, ss1 = hybrid.encaps(pk1)
    ct2, ss2 = hybrid.encaps(pk2)
    assert ss1 != ss2


# ===========================================================================
# 8. Hybrid Signature round-trip
# ===========================================================================

def test_hybrid_sig_roundtrip() -> None:
    ecdsa = EcdsaP256()
    oqs_name = _sig_name_in_liboqs("ML-DSA-65")
    mldsa = OqsSig(oqs_name)
    hybrid = HybridSignature([ecdsa, mldsa])

    pk, sk = hybrid.keygen()
    msg = b"test hybrid signature message"
    signature = hybrid.sign(sk, msg)
    assert hybrid.verify(pk, msg, signature)


def test_hybrid_sig_tampered_msg_fails() -> None:
    ecdsa = EcdsaP256()
    oqs_name = _sig_name_in_liboqs("ML-DSA-65")
    mldsa = OqsSig(oqs_name)
    hybrid = HybridSignature([ecdsa, mldsa])

    pk, sk = hybrid.keygen()
    msg = b"test hybrid signature message"
    signature = hybrid.sign(sk, msg)
    assert not hybrid.verify(pk, msg + b"x", signature)


def test_hybrid_sig_wrong_pk_fails() -> None:
    ecdsa = EcdsaP256()
    oqs_name = _sig_name_in_liboqs("ML-DSA-65")
    mldsa = OqsSig(oqs_name)
    hybrid = HybridSignature([ecdsa, mldsa])

    pk1, sk1 = hybrid.keygen()
    pk2, _sk2 = hybrid.keygen()
    msg = b"test message"
    signature = hybrid.sign(sk1, msg)
    assert not hybrid.verify(pk2, msg, signature)


# ===========================================================================
# 9. Registry tests
# ===========================================================================

def test_registry_get_kem_x25519() -> None:
    kem = get_kem("x25519")
    assert kem.pk_len == 32


def test_registry_get_kem_mlkem768() -> None:
    kem = get_kem("ml-kem-768")
    assert kem.pk_len == 1184


def test_registry_get_sig_ecdsa() -> None:
    sig = get_sig("ecdsa-p256")
    assert sig.pk_len == 65


def test_registry_get_sig_mldsa65() -> None:
    sig = get_sig("ml-dsa-65")
    assert sig.pk_len == 1952


def test_registry_unknown_kem_raises() -> None:
    with pytest.raises(KeyError, match="not available"):
        get_kem("no-such-kem")


def test_registry_unknown_sig_raises() -> None:
    with pytest.raises(KeyError, match="not available"):
        get_sig("no-such-sig")


def test_registry_get_kdf() -> None:
    kdf = get_kdf("hkdf-sha256")
    prk = kdf.extract(b"salt", b"ikm")
    assert len(prk) == 32


def test_registry_get_aead() -> None:
    aead = get_aead("aes-256-gcm")
    assert aead.key_len == 32


# ===========================================================================
# 10. Suite loading tests
# ===========================================================================

@pytest.mark.parametrize("suite_file,expected_id,expected_name", [
    ("classical.toml", 1, "classical"),
    ("pqc.toml",       2, "pqc"),
    ("hybrid.toml",    3, "hybrid"),
])
def test_load_suite(suite_file: str, expected_id: int, expected_name: str) -> None:
    suite = load_suite(SUITE_DIR / suite_file)
    assert suite.suite_id == expected_id
    assert suite.name == expected_name
    # Verify KEM round-trip
    pk, sk = suite.kem.keygen()
    ct, ss_enc = suite.kem.encaps(pk)
    ss_dec = suite.kem.decaps(sk, ct)
    assert ss_enc == ss_dec, f"Suite {suite_file}: KEM round-trip failed"
    # Verify Signature round-trip
    spk, ssk = suite.signature.keygen()
    msg = b"suite test message"
    sig = suite.signature.sign(ssk, msg)
    assert suite.signature.verify(spk, msg, sig), f"Suite {suite_file}: Sig verify failed"
    # Verify KDF
    prk = suite.kdf.extract(b"salt", b"ikm")
    out = suite.kdf.expand(prk, b"info", 32)
    assert len(out) == 32
    # Verify AEAD
    key = secrets.token_bytes(suite.aead.key_len)
    nonce = secrets.token_bytes(suite.aead.nonce_len)
    ct2 = suite.aead.encrypt(key, nonce, b"aad", b"plaintext")
    assert suite.aead.decrypt(key, nonce, b"aad", ct2) == b"plaintext"
