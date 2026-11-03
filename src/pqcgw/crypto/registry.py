"""Algorithm registry and suite loader.

Maps friendly algorithm names to concrete provider instances.  Algorithms are
discovered at import time from the installed liboqs; experimental algorithms
(HQC, Falcon/FN-DSA) are added only if the library exposes them.

Usage:
    from pqcgw.crypto.registry import get_kem, get_sig, get_kdf, get_aead, load_suite

All four interfaces are available only through get_* functions or load_suite().
Protocol code must never import concrete providers directly.
"""

from __future__ import annotations

import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import oqs

from pqcgw.crypto.hybrid import HybridKEM, HybridSignature
from pqcgw.crypto.interfaces import AEAD, KDF, KEM, Signature
from pqcgw.crypto.providers.aead_impl import AesGcm128, AesGcm256, ChaCha20Poly1305
from pqcgw.crypto.providers.kdf_hkdf import HkdfSha256, HkdfSha384
from pqcgw.crypto.providers.kem_oqs import OqsKem
from pqcgw.crypto.providers.kem_x25519 import X25519Kem
from pqcgw.crypto.providers.sig_ecdsa import EcdsaP256
from pqcgw.crypto.providers.sig_oqs import OqsSig


@dataclass
class Suite:
    """A fully-resolved crypto suite loaded from a TOML file."""

    suite_id: int
    name: str
    kem: KEM
    signature: Signature
    kdf: KDF
    aead: AEAD


# ---------------------------------------------------------------------------
# KEM registry
# ---------------------------------------------------------------------------

_KEM_REGISTRY: dict[str, Callable[[], KEM]] = {
    "x25519": X25519Kem,
}

_KEM_OQS_MAP = {
    "ml-kem-512": "ML-KEM-512",
    "ml-kem-768": "ML-KEM-768",
    "ml-kem-1024": "ML-KEM-1024",
}

_enabled_kems = oqs.get_enabled_kem_mechanisms()
_enabled_kems_upper = {m.upper().replace("-", "_").replace(" ", "_") for m in _enabled_kems}

for _friendly, _oqs_name in _KEM_OQS_MAP.items():
    _norm = _oqs_name.upper().replace("-", "_").replace(" ", "_")
    if _norm in _enabled_kems_upper:
        _name = _friendly  # capture for closure
        _oqs = _oqs_name
        _KEM_REGISTRY[_name] = lambda n=_oqs: OqsKem(n)

# Experimental HQC variants
for _mech in _enabled_kems:
    _upper = _mech.upper()
    if _upper.startswith("HQC"):
        _friendly_hqc = _mech.lower().replace("_", "-")
        _KEM_REGISTRY[_friendly_hqc] = lambda m=_mech: OqsKem(m, experimental=True)

# ---------------------------------------------------------------------------
# Signature registry
# ---------------------------------------------------------------------------

_SIG_REGISTRY: dict[str, Callable[[], Signature]] = {
    "ecdsa-p256": EcdsaP256,
}

_SIG_OQS_MAP = {
    "ml-dsa-44": "ML-DSA-44",
    "ml-dsa-65": "ML-DSA-65",
    "ml-dsa-87": "ML-DSA-87",
    "slh-dsa-sha2-128f": "SLH_DSA_PURE_SHA2_128F",
}

_enabled_sigs = oqs.get_enabled_sig_mechanisms()
_enabled_sigs_upper = {m.upper().replace("-", "_").replace(" ", "_") for m in _enabled_sigs}

for _friendly, _oqs_name in _SIG_OQS_MAP.items():
    _norm = _oqs_name.upper().replace("-", "_").replace(" ", "_")
    if _norm in _enabled_sigs_upper:
        _name = _friendly
        _oqs = _oqs_name
        _SIG_REGISTRY[_name] = lambda n=_oqs: OqsSig(n)

# Experimental: FN-DSA (only if library exposes that exact name prefix)
for _mech in _enabled_sigs:
    _upper = _mech.upper().replace("-", "_").replace(" ", "_")
    if _upper.startswith("FN_DSA"):
        _friendly_fndsa = _mech.lower().replace("_", "-")
        _SIG_REGISTRY[_friendly_fndsa] = lambda m=_mech: OqsSig(m, experimental=True)
    elif _upper.startswith("FALCON"):
        _friendly_falcon = _mech.lower().replace("_", "-")
        _SIG_REGISTRY[_friendly_falcon] = lambda m=_mech: OqsSig(m, experimental=True)

# ---------------------------------------------------------------------------
# KDF registry
# ---------------------------------------------------------------------------

_KDF_REGISTRY: dict[str, Callable[[], KDF]] = {
    "hkdf-sha256": HkdfSha256,
    "hkdf-sha384": HkdfSha384,
}

# ---------------------------------------------------------------------------
# AEAD registry
# ---------------------------------------------------------------------------

_AEAD_REGISTRY: dict[str, Callable[[], AEAD]] = {
    "aes-256-gcm": AesGcm256,
    "aes-128-gcm": AesGcm128,
    "chacha20-poly1305": ChaCha20Poly1305,
}

# ---------------------------------------------------------------------------
# Public accessors
# ---------------------------------------------------------------------------


def get_kem(name: str) -> KEM:
    """Instantiate a KEM by friendly name.  Raises KeyError if not available."""
    if name not in _KEM_REGISTRY:
        raise KeyError(
            f"KEM '{name}' is not available.  "
            f"Available: {sorted(_KEM_REGISTRY)}"
        )
    return _KEM_REGISTRY[name]()


def get_sig(name: str) -> Signature:
    """Instantiate a Signature scheme by friendly name."""
    if name not in _SIG_REGISTRY:
        raise KeyError(
            f"Signature scheme '{name}' is not available.  "
            f"Available: {sorted(_SIG_REGISTRY)}"
        )
    return _SIG_REGISTRY[name]()


def get_kdf(name: str) -> KDF:
    """Instantiate a KDF by friendly name."""
    if name not in _KDF_REGISTRY:
        raise KeyError(
            f"KDF '{name}' is not available.  "
            f"Available: {sorted(_KDF_REGISTRY)}"
        )
    return _KDF_REGISTRY[name]()


def get_aead(name: str) -> AEAD:
    """Instantiate an AEAD by friendly name."""
    if name not in _AEAD_REGISTRY:
        raise KeyError(
            f"AEAD '{name}' is not available.  "
            f"Available: {sorted(_AEAD_REGISTRY)}"
        )
    return _AEAD_REGISTRY[name]()


def load_suite(path: Path) -> Suite:
    """Load and validate a suite TOML file.

    Resolves all four algorithm components and wraps multi-component KEM/Sig
    lists in the appropriate hybrid combiner.
    """
    with open(path, "rb") as f:
        cfg = tomllib.load(f)

    suite_id: int = cfg["suite_id"]
    name: str = cfg["name"]

    kem_names: list[str] = cfg["kem"]
    sig_names: list[str] = cfg["signature"]
    kdf_name: str = cfg["kdf"]
    aead_name: str = cfg["aead"]

    kem_components = [get_kem(n) for n in kem_names]
    kem: KEM = kem_components[0] if len(kem_components) == 1 else HybridKEM(kem_components)

    sig_components = [get_sig(n) for n in sig_names]
    sig: Signature = (
        sig_components[0] if len(sig_components) == 1 else HybridSignature(sig_components)
    )

    return Suite(
        suite_id=suite_id,
        name=name,
        kem=kem,
        signature=sig,
        kdf=get_kdf(kdf_name),
        aead=get_aead(aead_name),
    )


def list_available() -> dict[str, list[str]]:
    """Return all registered algorithm names per category."""
    return {
        "kem": sorted(_KEM_REGISTRY),
        "signature": sorted(_SIG_REGISTRY),
        "kdf": sorted(_KDF_REGISTRY),
        "aead": sorted(_AEAD_REGISTRY),
    }
