"""Abstract base classes for the crypto abstraction layer.

Protocol and session-manager code must import ONLY these interfaces, never
concrete implementations.  Algorithm selection is done exclusively via config
(suite TOML files) and the registry.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class KEM(ABC):
    """Key-Encapsulation Mechanism interface."""

    pk_len: int   # public-key length in bytes
    ct_len: int   # ciphertext length in bytes
    ss_len: int   # shared-secret length in bytes

    @abstractmethod
    def keygen(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""

    @abstractmethod
    def encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        """Encapsulate to pk.  Return (ciphertext, shared_secret)."""

    @abstractmethod
    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        """Decapsulate ct with sk.  Return shared_secret."""


class Signature(ABC):
    """Digital-signature interface."""

    pk_len: int   # public-key length in bytes
    sig_len: int  # signature length in bytes (fixed-length schemes only)

    @abstractmethod
    def keygen(self) -> tuple[bytes, bytes]:
        """Return (public_key, secret_key)."""

    @abstractmethod
    def sign(self, sk: bytes, msg: bytes) -> bytes:
        """Sign msg with sk.  Return signature bytes."""

    @abstractmethod
    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        """Verify sig over msg with pk.  Return True iff valid."""


class KDF(ABC):
    """Key-derivation function interface (HKDF-style extract-then-expand)."""

    @property
    @abstractmethod
    def hash_name(self) -> str:
        """Name of the underlying hash ('sha256' or 'sha384').
        Protocol code uses this instead of importing concrete provider classes.
        """

    @abstractmethod
    def extract(self, salt: bytes, ikm: bytes) -> bytes:
        """Extract a pseudorandom key from ikm using salt.  Return prk."""

    @abstractmethod
    def expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        """Expand prk with info to produce `length` output bytes."""


class AEAD(ABC):
    """Authenticated Encryption with Associated Data interface."""

    key_len: int    # symmetric key length in bytes
    nonce_len: int  # nonce length in bytes
    tag_len: int    # authentication-tag length in bytes

    @abstractmethod
    def encrypt(self, key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
        """Encrypt and authenticate pt.  Return ciphertext || tag."""

    @abstractmethod
    def decrypt(self, key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
        """Verify and decrypt ct (includes tag).  Raise ValueError on failure."""
