"""AES-GCM-256, AES-GCM-128, and ChaCha20-Poly1305 AEAD implementations."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305 as _ChaCha,
)

from pqcgw.crypto.interfaces import AEAD


class _AesGcmBase(AEAD):
    nonce_len: int = 12
    tag_len: int = 16

    def __init__(self, key_len: int) -> None:
        self.key_len = key_len

    def encrypt(self, key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
        return AESGCM(key).encrypt(nonce, pt, aad)

    def decrypt(self, key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
        try:
            return AESGCM(key).decrypt(nonce, ct, aad)
        except InvalidTag as exc:
            raise ValueError("AEAD authentication failure") from exc


class AesGcm256(_AesGcmBase):
    key_len: int = 32
    nonce_len: int = 12
    tag_len: int = 16

    def __init__(self) -> None:
        super().__init__(32)


class AesGcm128(_AesGcmBase):
    key_len: int = 16
    nonce_len: int = 12
    tag_len: int = 16

    def __init__(self) -> None:
        super().__init__(16)


class ChaCha20Poly1305(AEAD):
    key_len: int = 32
    nonce_len: int = 12
    tag_len: int = 16

    def encrypt(self, key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
        return _ChaCha(key).encrypt(nonce, pt, aad)

    def decrypt(self, key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
        try:
            return _ChaCha(key).decrypt(nonce, ct, aad)
        except InvalidTag as exc:
            raise ValueError("AEAD authentication failure") from exc
