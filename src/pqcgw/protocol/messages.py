"""Handshake message dataclasses and wire serialization.

Wire format: all variable-length fields are u16-length-prefixed (big-endian).
Fixed-length fields (version, suite_id, session_id, nonce_*) are written raw.

Transcript hash input is the raw wire bytes of HELLO_I || HELLO_R, so
serialization must be deterministic and stable across calls.

§15 item 8: suite_id is a single byte signed into every body.
§5.2: version byte = 1.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Low-level packing helpers
# ---------------------------------------------------------------------------

def _pack_varlen(data: bytes) -> bytes:
    """Encode bytes as u16-length-prefix || data."""
    if len(data) > 0xFFFF:
        raise ValueError(f"Field too long: {len(data)} bytes")
    return struct.pack(">H", len(data)) + data


def _unpack_varlen(buf: bytes, offset: int) -> tuple[bytes, int]:
    """Read a u16-length-prefixed field from buf at offset.
    Returns (field_bytes, new_offset).  Raises ValueError on truncation.
    """
    if offset + 2 > len(buf):
        raise ValueError("Truncated length prefix in message")
    (length,) = struct.unpack_from(">H", buf, offset)
    offset += 2
    if offset + length > len(buf):
        raise ValueError(f"Truncated field body: expected {length} bytes")
    return buf[offset : offset + length], offset + length


# ---------------------------------------------------------------------------
# HELLO_I
# ---------------------------------------------------------------------------

@dataclass
class HelloI:
    """HELLO_I — initiator → responder.

    Body (fields 1–7) is signed by the initiator.  The full message appends
    the signature as a u16-length-prefixed field.

    version    : u8 = 1
    suite_id   : u8
    session_id : 4 B (random)
    gateway_id : u16 || utf-8
    peer_id    : u16 || utf-8
    nonce_i    : 32 B
    kem_pk     : u16 || bytes
    sig        : u16 || bytes  (sig over "hs-v1-I" || H(body_bytes))
    """

    version: int
    suite_id: int
    session_id: bytes
    gateway_id: str
    peer_id: str
    nonce_i: bytes
    kem_pk: bytes
    sig: bytes = field(default=b"")

    def body_bytes(self) -> bytes:
        """Serialise fields 1–7 for signing.  Deterministic."""
        if len(self.session_id) != 4:
            raise ValueError("session_id must be 4 bytes")
        if len(self.nonce_i) != 32:
            raise ValueError("nonce_i must be 32 bytes")
        gw_b = self.gateway_id.encode("utf-8")
        peer_b = self.peer_id.encode("utf-8")
        return (
            bytes([self.version, self.suite_id])
            + self.session_id
            + _pack_varlen(gw_b)
            + _pack_varlen(peer_b)
            + self.nonce_i
            + _pack_varlen(self.kem_pk)
        )

    def to_bytes(self) -> bytes:
        """Full wire encoding including signature."""
        return self.body_bytes() + _pack_varlen(self.sig)

    @classmethod
    def from_bytes(cls, data: bytes) -> "HelloI":
        """Parse HELLO_I from wire bytes.  Raises ValueError on malformed input."""
        offset = 0

        if offset + 2 > len(data):
            raise ValueError("HELLO_I too short for version/suite_id")
        version = data[offset]
        suite_id = data[offset + 1]
        offset += 2

        if offset + 4 > len(data):
            raise ValueError("HELLO_I too short for session_id")
        session_id = data[offset : offset + 4]
        offset += 4

        gw_b, offset = _unpack_varlen(data, offset)
        peer_b, offset = _unpack_varlen(data, offset)

        if offset + 32 > len(data):
            raise ValueError("HELLO_I too short for nonce_i")
        nonce_i = data[offset : offset + 32]
        offset += 32

        kem_pk, offset = _unpack_varlen(data, offset)
        sig, offset = _unpack_varlen(data, offset)

        if offset != len(data):
            raise ValueError("HELLO_I has trailing bytes")

        return cls(
            version=version,
            suite_id=suite_id,
            session_id=session_id,
            gateway_id=gw_b.decode("utf-8"),
            peer_id=peer_b.decode("utf-8"),
            nonce_i=nonce_i,
            kem_pk=kem_pk,
            sig=sig,
        )


# ---------------------------------------------------------------------------
# HELLO_R
# ---------------------------------------------------------------------------

@dataclass
class HelloR:
    """HELLO_R — responder → initiator.

    Body (fields 1–5) is signed by the responder.

    version    : u8 = 1
    suite_id   : u8
    session_id : 4 B (echoed from HELLO_I)
    nonce_r    : 32 B
    kem_ct     : u16 || bytes
    sig        : u16 || bytes  (sig over "hs-v1-R" || H(hello_i_bytes || body_bytes))
    """

    version: int
    suite_id: int
    session_id: bytes
    nonce_r: bytes
    kem_ct: bytes
    sig: bytes = field(default=b"")

    def body_bytes(self) -> bytes:
        """Serialise fields 1–5 for signing."""
        if len(self.session_id) != 4:
            raise ValueError("session_id must be 4 bytes")
        if len(self.nonce_r) != 32:
            raise ValueError("nonce_r must be 32 bytes")
        return (
            bytes([self.version, self.suite_id])
            + self.session_id
            + self.nonce_r
            + _pack_varlen(self.kem_ct)
        )

    def to_bytes(self) -> bytes:
        return self.body_bytes() + _pack_varlen(self.sig)

    @classmethod
    def from_bytes(cls, data: bytes) -> "HelloR":
        offset = 0

        if offset + 2 > len(data):
            raise ValueError("HELLO_R too short for version/suite_id")
        version = data[offset]
        suite_id = data[offset + 1]
        offset += 2

        if offset + 4 > len(data):
            raise ValueError("HELLO_R too short for session_id")
        session_id = data[offset : offset + 4]
        offset += 4

        if offset + 32 > len(data):
            raise ValueError("HELLO_R too short for nonce_r")
        nonce_r = data[offset : offset + 32]
        offset += 32

        kem_ct, offset = _unpack_varlen(data, offset)
        sig, offset = _unpack_varlen(data, offset)

        if offset != len(data):
            raise ValueError("HELLO_R has trailing bytes")

        return cls(
            version=version,
            suite_id=suite_id,
            session_id=session_id,
            nonce_r=nonce_r,
            kem_ct=kem_ct,
            sig=sig,
        )
