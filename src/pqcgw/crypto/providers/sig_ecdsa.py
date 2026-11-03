"""ECDSA-P256 signature implementation.

Signatures are raw 64-byte r || s (each 32 bytes, zero-padded to 32).
Public keys are uncompressed 65-byte points (0x04 prefix).
Internally converts to/from DER for the cryptography package.

§15 item 6: raw r||s; hybrid signature fields are length-prefixed.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from pqcgw.crypto.interfaces import Signature

_CURVE = ec.SECP256R1()


def _int_to_32(n: int) -> bytes:
    return n.to_bytes(32, "big")


class EcdsaP256(Signature):
    """ECDSA over P-256 with SHA-256, raw r||s wire format."""

    pk_len: int = 65   # uncompressed point
    sig_len: int = 64  # r || s, 32 bytes each

    def keygen(self) -> tuple[bytes, bytes]:
        sk = ec.generate_private_key(_CURVE)
        pk = sk.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        sk_bytes = sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return pk, sk_bytes

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        private_key = serialization.load_pem_private_key(sk, password=None)
        der_sig = private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        return _int_to_32(r) + _int_to_32(s)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        if len(pk) != self.pk_len:
            raise ValueError(
                f"ECDSA-P256 verify: expected pk of {self.pk_len} bytes, got {len(pk)}"
            )
        if len(sig) != self.sig_len:
            raise ValueError(
                f"ECDSA-P256 verify: expected sig of {self.sig_len} bytes, got {len(sig)}"
            )
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        der_sig = encode_dss_signature(r, s)
        try:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, pk)
            public_key.verify(der_sig, msg, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
