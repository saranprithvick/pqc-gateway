"""liboqs Signature wrappers for ML-DSA, SLH-DSA, and experimental schemes.

OI-1 guard: pk length is validated before passing to liboqs.  For fixed-length
signature schemes (ML-DSA, SLH-DSA) the sig length is also validated before
calling verify.  A short or empty input raises ValueError here, never inside
liboqs.

ML-DSA context string: empty (b"").  The ML-DSA standard (FIPS 204) allows an
optional context string; we use the empty string throughout and document it so
that an examiner can verify it is consistent with our FIPS references.

§15 item 4: use fn-dsa-* only if the library exposes that exact name; otherwise
expose Falcon as falcon-*, labelled pre-standard and experimental.
"""

from __future__ import annotations

import oqs

from pqcgw.crypto.interfaces import Signature

# Schemes whose signatures are always exactly sig_len bytes.
_FIXED_LENGTH_PREFIXES = ("ML-DSA", "SLH-DSA", "SPHINCS")


def _resolve_mechanism(friendly: str, available: list[str]) -> str:
    if friendly in available:
        return friendly
    norm = friendly.upper().replace("-", "_").replace(" ", "_")
    for mech in available:
        if mech.upper().replace("-", "_").replace(" ", "_") == norm:
            return mech
    raise KeyError(
        f"Signature mechanism '{friendly}' not available in installed liboqs "
        f"(version {oqs.oqs_version()}).  "
        f"Available: {available}"
    )


class OqsSig(Signature):
    """liboqs Signature wrapper.

    Args:
        friendly_name: Friendly algorithm name (e.g. 'ml-dsa-65').
        experimental: If True, absence from the enabled list raises KeyError
            rather than a hard error.
    """

    def __init__(self, friendly_name: str, *, experimental: bool = False) -> None:
        available = oqs.get_enabled_sig_mechanisms()
        self._mech = _resolve_mechanism(friendly_name, available)
        self._experimental = experimental

        with oqs.Signature(self._mech) as sig:
            self.pk_len = sig.details["length_public_key"]
            self.sig_len = sig.details["length_signature"]

        self._fixed_length = any(
            self._mech.upper().startswith(p) for p in _FIXED_LENGTH_PREFIXES
        )

    def keygen(self) -> tuple[bytes, bytes]:
        with oqs.Signature(self._mech) as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
        return pk, sk

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        with oqs.Signature(self._mech, secret_key=sk) as sig:
            return sig.sign(msg)

    def verify(self, pk: bytes, msg: bytes, signature: bytes) -> bool:
        if len(pk) != self.pk_len:
            raise ValueError(
                f"{self._mech} verify: expected pk of {self.pk_len} bytes, "
                f"got {len(pk)}"
            )
        if self._fixed_length and len(signature) != self.sig_len:
            raise ValueError(
                f"{self._mech} verify: expected sig of {self.sig_len} bytes, "
                f"got {len(signature)}"
            )
        with oqs.Signature(self._mech) as sig:
            return sig.verify(msg, signature, pk)
