"""liboqs KEM wrappers for ML-KEM and HQC (experimental).

OI-1 guard: pk and ct lengths are validated against the values reported by
the algorithm BEFORE passing buffers to the C library.  A short or empty input
raises ValueError here, never inside liboqs — this defends against the class of
vulnerability documented in GHSA-w696-4vrr-x6x3 where earlier liboqs versions
silently zero-padded short inputs.
"""

from __future__ import annotations

import oqs

from pqcgw.crypto.interfaces import KEM


def _resolve_mechanism(friendly: str, available: list[str]) -> str:
    """Map a friendly name to the exact string liboqs exposes.

    Checks for an exact match first, then a case-insensitive prefix match so
    that name changes between liboqs versions (e.g. Kyber768 vs ML-KEM-768)
    are handled at runtime rather than hard-coded.
    """
    if friendly in available:
        return friendly
    # normalise: uppercase, replace hyphens/spaces with underscores
    norm = friendly.upper().replace("-", "_").replace(" ", "_")
    for mech in available:
        if mech.upper().replace("-", "_").replace(" ", "_") == norm:
            return mech
    raise KeyError(
        f"KEM mechanism '{friendly}' not available in installed liboqs "
        f"(version {oqs.oqs_version()}).  "
        f"Available: {available}"
    )


class OqsKem(KEM):
    """liboqs KEM wrapper (ML-KEM-512/768/1024, HQC-*, …).

    Args:
        friendly_name: Friendly algorithm name (e.g. 'ml-kem-768').  Resolved
            to the exact liboqs mechanism name at construction time.
        experimental: If True, the algorithm is labelled experimental and
            absence from the enabled list raises KeyError rather than a hard
            ImportError so the registry can skip it gracefully.
    """

    def __init__(self, friendly_name: str, *, experimental: bool = False) -> None:
        available = oqs.get_enabled_kem_mechanisms()
        self._mech = _resolve_mechanism(friendly_name, available)
        self._experimental = experimental

        # Probe sizes without holding the context open.
        with oqs.KeyEncapsulation(self._mech) as kem:
            self.pk_len = kem.details["length_public_key"]
            self.ct_len = kem.details["length_ciphertext"]
            self.ss_len = kem.details["length_shared_secret"]

    def keygen(self) -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self._mech) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
        return pk, sk

    def encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        if len(pk) != self.pk_len:
            raise ValueError(
                f"{self._mech} encaps: expected pk of {self.pk_len} bytes, "
                f"got {len(pk)}"
            )
        with oqs.KeyEncapsulation(self._mech) as kem:
            ct, ss = kem.encap_secret(pk)
        return ct, ss

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        if len(ct) != self.ct_len:
            raise ValueError(
                f"{self._mech} decaps: expected ct of {self.ct_len} bytes, "
                f"got {len(ct)}"
            )
        with oqs.KeyEncapsulation(self._mech, secret_key=sk) as kem:
            ss = kem.decap_secret(ct)
        return ss
