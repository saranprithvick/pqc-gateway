"""Record layer: AEAD encryption/decryption of CAN-frame payloads.

Record format (§5.5):

  Header (16 B, also used as AEAD associated data):
    byte 0      : version_type  — high nibble = version (1), low nibble = type
                  DATA=0, REKEY_REQ=1, REKEY_ACK=2, CLOSE=3, ALERT=4  (§15 item 8)
    bytes 1–4   : session_id (4 B)
    byte 5      : epoch (1 B)
    bytes 6–13  : counter (8 B, big-endian)
    bytes 14–15 : payload_length (2 B, big-endian) — plaintext byte count

  Wire record = header (16 B) || AEAD ciphertext+tag

Nonce construction (§5.5):
  nonce = salt[direction] (4 B) || counter (8 B big-endian)  →  12 B
  All three AEAD algorithms use 12 B nonces.

Counter discipline:
  - Per direction, starts at 0, increments by 1 per record.
  - Never reused under a key.
  - check() is called before decryption; mark() is called after (so forgeries
    do not mutate the replay window).

RecordError is the single exception for all record-layer failures; callers
drop the record silently on the wire and log locally (§5.8).
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from enum import IntEnum

from pqcgw.crypto.registry import Suite
from pqcgw.protocol.keyschedule import SessionKeys
from pqcgw.protocol.replay import ReplayError, ReplayWindow

log = logging.getLogger(__name__)

_PROTOCOL_VERSION = 1
_HEADER_LEN = 16


class RecordType(IntEnum):
    DATA = 0
    REKEY_REQ = 1
    REKEY_ACK = 2
    CLOSE = 3
    ALERT = 4


class Direction(IntEnum):
    I2R = 0  # initiator → responder
    R2I = 1  # responder → initiator


class RecordError(Exception):
    """Raised on any record-layer failure.  Do not send detail on the wire."""


# ---------------------------------------------------------------------------
# Record header
# ---------------------------------------------------------------------------

@dataclass
class RecordHeader:
    version: int
    rtype: RecordType
    session_id: bytes    # 4 B
    epoch: int           # 1 B
    counter: int         # 8 B
    payload_length: int  # 2 B (plaintext byte count)

    def to_bytes(self) -> bytes:
        if len(self.session_id) != 4:
            raise ValueError("session_id must be 4 bytes")
        version_type = ((self.version & 0x0F) << 4) | (int(self.rtype) & 0x0F)
        return (
            bytes([version_type])
            + self.session_id
            + bytes([self.epoch])
            + struct.pack(">Q", self.counter)
            + struct.pack(">H", self.payload_length)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "RecordHeader":
        if len(data) < _HEADER_LEN:
            raise RecordError(f"Header too short: {len(data)} B")
        version_type = data[0]
        version = (version_type >> 4) & 0x0F
        try:
            rtype = RecordType(version_type & 0x0F)
        except ValueError:
            raise RecordError(f"Unknown record type nibble: {version_type & 0x0F}")
        session_id = data[1:5]
        epoch = data[5]
        (counter,) = struct.unpack_from(">Q", data, 6)
        (payload_length,) = struct.unpack_from(">H", data, 14)
        return cls(
            version=version,
            rtype=rtype,
            session_id=session_id,
            epoch=epoch,
            counter=counter,
            payload_length=payload_length,
        )


# ---------------------------------------------------------------------------
# Record layer
# ---------------------------------------------------------------------------

class RecordLayer:
    """Encrypts and decrypts records under a set of session keys.

    One instance is shared between both directions; per-direction counters
    are tracked internally.

    seal() always uses the key/salt for the given direction and post-increments
    the sender's counter.

    open() uses the key/salt for the given direction (the receiver's view) and
    validates via the replay window.
    """

    def __init__(self, suite: Suite, keys: SessionKeys, session_id: bytes) -> None:
        if len(session_id) != 4:
            raise ValueError("session_id must be 4 bytes")
        self._suite = suite
        self._keys = keys
        self._session_id = session_id
        # Outbound counter per direction (sender side)
        self._counters: dict[Direction, int] = {
            Direction.I2R: 0,
            Direction.R2I: 0,
        }

    def seal(
        self,
        rtype: RecordType,
        plaintext: bytes,
        direction: Direction,
    ) -> bytes:
        """Encrypt plaintext into a full wire record.

        Returns header (16 B) || ciphertext || tag.
        """
        counter = self._counters[direction]
        self._counters[direction] += 1

        header = RecordHeader(
            version=_PROTOCOL_VERSION,
            rtype=rtype,
            session_id=self._session_id,
            epoch=self._keys.epoch,
            counter=counter,
            payload_length=len(plaintext),
        )
        header_bytes = header.to_bytes()

        key, salt = self._key_and_salt(direction)
        nonce = salt + struct.pack(">Q", counter)  # 4 B + 8 B = 12 B

        ct_tag = self._suite.aead.encrypt(key, nonce, header_bytes, plaintext)
        return header_bytes + ct_tag

    def open(
        self,
        data: bytes,
        direction: Direction,
        replay: ReplayWindow,
    ) -> tuple[RecordType, bytes]:
        """Parse, authenticate, and decrypt a wire record.

        Returns (RecordType, plaintext).
        Raises RecordError on any failure (do not send detail on the wire).
        """
        if len(data) < _HEADER_LEN:
            raise RecordError("Record too short")

        header_bytes = data[:_HEADER_LEN]
        ct_tag = data[_HEADER_LEN:]

        try:
            header = RecordHeader.from_bytes(header_bytes)
        except RecordError:
            raise
        except Exception as exc:
            raise RecordError(f"Header parse error: {exc}") from exc

        # Validate header fields
        if header.version != _PROTOCOL_VERSION:
            log.warning("Record version mismatch: %d", header.version)
            raise RecordError("Record version mismatch")
        if header.epoch != self._keys.epoch:
            log.warning("Record epoch mismatch: got %d, expected %d", header.epoch, self._keys.epoch)
            raise RecordError("Record epoch mismatch")
        if header.session_id != self._session_id:
            log.warning("Record session_id mismatch")
            raise RecordError("Record session_id mismatch")

        expected_ct_len = header.payload_length + self._suite.aead.tag_len
        if len(ct_tag) != expected_ct_len:
            log.warning(
                "Record ct+tag length mismatch: got %d, expected %d",
                len(ct_tag), expected_ct_len,
            )
            raise RecordError("Record length mismatch")

        # Replay check BEFORE decryption (don't mutate window on forgery)
        try:
            replay.check(header.counter)
        except ReplayError as exc:
            log.warning("Replay check failed: %s", exc)
            raise RecordError(str(exc)) from exc

        key, salt = self._key_and_salt(direction)
        nonce = salt + struct.pack(">Q", header.counter)

        try:
            plaintext = self._suite.aead.decrypt(key, nonce, header_bytes, ct_tag)
        except ValueError as exc:
            log.warning("AEAD authentication failure: %s", exc)
            raise RecordError("AEAD authentication failure") from exc

        # Mark as seen AFTER successful decryption
        replay.mark(header.counter)
        return header.rtype, plaintext

    # -- internal ------------------------------------------------------------

    def _key_and_salt(self, direction: Direction) -> tuple[bytes, bytes]:
        if direction == Direction.I2R:
            return self._keys.k_i2r, self._keys.salt_i2r
        return self._keys.k_r2i, self._keys.salt_r2i
