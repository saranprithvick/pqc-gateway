"""X25519 wrapped as a KEM-style interface.

Encaps generates an ephemeral key pair, computes DH, and returns the ephemeral
public key as the "ciphertext".  Decaps loads the static secret key and
computes DH against the ephemeral public key.

pk_len = ct_len = ss_len = 32 bytes.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from pqcgw.crypto.interfaces import KEM


class X25519Kem(KEM):
    """X25519 in a KEM-compatible interface."""

    pk_len: int = 32
    ct_len: int = 32   # ephemeral public key acts as "ciphertext"
    ss_len: int = 32

    def keygen(self) -> tuple[bytes, bytes]:
        sk = X25519PrivateKey.generate()
        pk = sk.public_key().public_bytes_raw()
        sk_bytes = sk.private_bytes_raw()
        return pk, sk_bytes

    def encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        if len(pk) != self.pk_len:
            raise ValueError(
                f"X25519 encaps: expected pk of {self.pk_len} bytes, got {len(pk)}"
            )
        peer_pk = X25519PublicKey.from_public_bytes(pk)
        eph_sk = X25519PrivateKey.generate()
        eph_pk = eph_sk.public_key().public_bytes_raw()
        ss = eph_sk.exchange(peer_pk)
        return eph_pk, ss

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        if len(sk) != self.pk_len:
            raise ValueError(
                f"X25519 decaps: expected sk of {self.pk_len} bytes, got {len(sk)}"
            )
        if len(ct) != self.ct_len:
            raise ValueError(
                f"X25519 decaps: expected ct of {self.ct_len} bytes, got {len(ct)}"
            )
        private_key = X25519PrivateKey.from_private_bytes(sk)
        eph_pk = X25519PublicKey.from_public_bytes(ct)
        return private_key.exchange(eph_pk)
