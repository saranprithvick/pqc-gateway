"""MessageAdapter: convert CANFrame ↔ record plaintext.

Wire layout (CLAUDE.md §5.5): can_id (4 B incl. flags) || dlc (1 B) || data
The 4-byte can_id field encodes the arbitration ID plus:
  bit 31 (MSG_EFF_FLAG): extended 29-bit ID
  bit 29 (MSG_FD_FLAG):  CAN FD frame
so the receiver can reconstruct is_extended and is_fd without extra fields.

Minimum encoded length: 5 bytes (zero-payload frame).
"""

from __future__ import annotations

import struct

from pqcgw.legacy.can_model import (
    CANFrame,
    MSG_EFF_FLAG,
    MSG_FD_FLAG,
    MSG_ID_MASK,
    VALID_FD_LENGTHS,
)

# Struct for the 4-byte encoded can_id + 1-byte dlc prefix.
_HDR = struct.Struct(">IB")  # big-endian uint32, uint8
_HDR_LEN = _HDR.size  # 5


class MessageAdapter:
    """Encode/decode one CAN frame to/from record plaintext."""

    @staticmethod
    def encode(frame: CANFrame) -> bytes:
        """Encode a CANFrame to record plaintext bytes."""
        enc_id = frame.can_id & MSG_ID_MASK
        if frame.is_extended:
            enc_id |= MSG_EFF_FLAG
        if frame.is_fd:
            enc_id |= MSG_FD_FLAG
        return _HDR.pack(enc_id, frame.dlc) + frame.data

    @staticmethod
    def decode(data: bytes) -> CANFrame:
        """Decode record plaintext bytes to a CANFrame.

        Raises ValueError on truncated, malformed, or inconsistent input.
        Every field is validated before the CANFrame dataclass is constructed.
        """
        if len(data) < _HDR_LEN:
            raise ValueError(
                f"Encoded CAN frame too short: {len(data)} < {_HDR_LEN} bytes"
            )
        enc_id, dlc = _HDR.unpack(data[:_HDR_LEN])
        payload = data[_HDR_LEN:]

        is_extended = bool(enc_id & MSG_EFF_FLAG)
        is_fd = bool(enc_id & MSG_FD_FLAG)
        can_id = enc_id & MSG_ID_MASK

        # Validate dlc against frame type before constructing.
        if is_fd:
            if dlc not in VALID_FD_LENGTHS:
                raise ValueError(
                    f"Decoded CAN FD dlc {dlc} not in valid FD lengths"
                )
        else:
            if dlc > 8:
                raise ValueError(
                    f"Decoded CAN 2.0 dlc {dlc} exceeds maximum of 8"
                )

        if len(payload) != dlc:
            raise ValueError(
                f"Payload length {len(payload)} does not match decoded dlc {dlc}"
            )

        return CANFrame(
            can_id=can_id,
            dlc=dlc,
            data=payload,
            is_fd=is_fd,
            is_extended=is_extended,
        )
