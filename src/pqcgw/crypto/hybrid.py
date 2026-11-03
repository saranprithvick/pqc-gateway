"""Hybrid KEM and Hybrid Signature combiners.

HybridKEM combines two or more KEM components (default: X25519 + ML-KEM-768).
HybridSignature combines two Signature components (default: ECDSA-P256 + ML-DSA-65).

Wire format for composite public keys / ciphertexts / signatures:
  Each field is length-prefixed: u16 (big-endian) || bytes.
  Fields are written in the fixed order determined by the suite file.

Shared secrets (HybridKEM) are concatenated WITHOUT length prefixes before
being passed to the KDF.  This is consistent with draft-ietf-tls-hybrid-design.

IMPORTANT: HybridSignature is NOT a standardised composite.  It is a simple
dual-signature scheme where both signatures must verify independently.  It does
NOT implement any NIST or IETF composite-signature standard.
"""

from __future__ import annotations

import struct

from pqcgw.crypto.interfaces import KEM, Signature


def _encode_fields(fields: list[bytes]) -> bytes:
    """Encode a list of byte-strings as u16-length-prefixed concatenation."""
    out = bytearray()
    for f in fields:
        out += struct.pack(">H", len(f))
        out += f
    return bytes(out)


def _decode_fields(data: bytes, count: int) -> list[bytes]:
    """Decode `count` u16-length-prefixed fields from data."""
    fields: list[bytes] = []
    offset = 0
    for _ in range(count):
        if offset + 2 > len(data):
            raise ValueError("Hybrid field decode: truncated length prefix")
        (length,) = struct.unpack_from(">H", data, offset)
        offset += 2
        if offset + length > len(data):
            raise ValueError("Hybrid field decode: truncated field body")
        fields.append(data[offset : offset + length])
        offset += length
    if offset != len(data):
        raise ValueError("Hybrid field decode: trailing bytes")
    return fields


class HybridKEM(KEM):
    """Hybrid KEM combining two or more component KEMs.

    Public keys, ciphertexts: u16-length-prefixed concatenation in suite order.
    Shared secrets: raw concatenation (no prefixes) for KDF input.
    """

    def __init__(self, components: list[KEM]) -> None:
        if len(components) < 2:
            raise ValueError("HybridKEM requires at least 2 components")
        self._components = components
        # Total lengths include 2-byte prefix per component
        self.pk_len = sum(2 + c.pk_len for c in components)
        self.ct_len = sum(2 + c.ct_len for c in components)
        self.ss_len = sum(c.ss_len for c in components)

    def keygen(self) -> tuple[bytes, bytes]:
        pks, sks = [], []
        for c in self._components:
            pk, sk = c.keygen()
            pks.append(pk)
            sks.append(sk)
        return _encode_fields(pks), _encode_fields(sks)

    def encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        pk_parts = _decode_fields(pk, len(self._components))
        cts, sses = [], []
        for c, pk_part in zip(self._components, pk_parts):
            ct, ss = c.encaps(pk_part)
            cts.append(ct)
            sses.append(ss)
        combined_ct = _encode_fields(cts)
        combined_ss = b"".join(sses)
        return combined_ct, combined_ss

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        sk_parts = _decode_fields(sk, len(self._components))
        ct_parts = _decode_fields(ct, len(self._components))
        sses = []
        for c, sk_part, ct_part in zip(self._components, sk_parts, ct_parts):
            sses.append(c.decaps(sk_part, ct_part))
        return b"".join(sses)


class HybridSignature(Signature):
    """Hybrid (dual) signature combining two component signature schemes.

    IMPORTANT: This is NOT a standardised composite-signature scheme.
    It is a simple dual-signature: both components sign independently and
    both must verify.  Wire format: u16-length-prefixed concatenation.

    pk_len includes the 2-byte prefix per component.
    sig_len is the sum of max component sig_lens + prefixes (informational only;
    actual length varies for non-fixed-length schemes).
    """

    def __init__(self, components: list[Signature]) -> None:
        if len(components) < 2:
            raise ValueError("HybridSignature requires at least 2 components")
        self._components = components
        self.pk_len = sum(2 + c.pk_len for c in components)
        self.sig_len = sum(2 + c.sig_len for c in components)

    def keygen(self) -> tuple[bytes, bytes]:
        pks, sks = [], []
        for c in self._components:
            pk, sk = c.keygen()
            pks.append(pk)
            sks.append(sk)
        return _encode_fields(pks), _encode_fields(sks)

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        sk_parts = _decode_fields(sk, len(self._components))
        sigs = [c.sign(sk_part, msg) for c, sk_part in zip(self._components, sk_parts)]
        return _encode_fields(sigs)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            pk_parts = _decode_fields(pk, len(self._components))
            sig_parts = _decode_fields(sig, len(self._components))
        except ValueError:
            return False
        return all(
            c.verify(pk_part, msg, sig_part)
            for c, pk_part, sig_part in zip(self._components, pk_parts, sig_parts)
        )
