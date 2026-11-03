"""HKDF-SHA-256 and HKDF-SHA-384 KDF implementations."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.hmac import HMAC

from pqcgw.crypto.interfaces import KDF


class _HkdfBase(KDF):
    """HKDF parameterised by a hash algorithm."""

    def __init__(self, algorithm: hashes.HashAlgorithm) -> None:
        self._algorithm = algorithm
        self._hash_len = algorithm.digest_size

    def extract(self, salt: bytes, ikm: bytes) -> bytes:
        # HKDF-Extract: HMAC(salt, ikm)
        h = HMAC(salt if salt else bytes(self._hash_len), self._algorithm)
        h.update(ikm)
        return h.finalize()

    def expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        hkdf = HKDFExpand(algorithm=self._algorithm, length=length, info=info)
        return hkdf.derive(prk)


class HkdfSha256(_HkdfBase):
    """HKDF with SHA-256."""

    def __init__(self) -> None:
        super().__init__(hashes.SHA256())


class HkdfSha384(_HkdfBase):
    """HKDF with SHA-384."""

    def __init__(self) -> None:
        super().__init__(hashes.SHA384())
