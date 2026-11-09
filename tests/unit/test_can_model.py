"""Unit tests: CANFrame model and MessageAdapter encoding.

Tests cover construction validation, flag encoding, known-answer bytes,
round-trip for various payload sizes and flags, and error cases.
"""

from __future__ import annotations

import struct

import pytest

from pqcgw.legacy.can_model import (
    CANFrame,
    MSG_EFF_FLAG,
    MSG_FD_FLAG,
    MSG_ID_MASK,
    VALID_FD_LENGTHS,
)
from pqcgw.nodes.adapter import MessageAdapter


# ===========================================================================
# CANFrame construction
# ===========================================================================

class TestCANFrameConstruction:
    def test_valid_can20_min(self) -> None:
        f = CANFrame(can_id=0x100, dlc=0, data=b"")
        assert f.dlc == 0
        assert f.data == b""
        assert not f.is_fd
        assert not f.is_extended

    def test_valid_can20_max_dlc(self) -> None:
        f = CANFrame(can_id=0x7FF, dlc=8, data=b"\x00" * 8)
        assert f.dlc == 8

    def test_valid_can_fd_8_bytes(self) -> None:
        f = CANFrame(can_id=0x200, dlc=8, data=bytes(8), is_fd=True)
        assert f.is_fd

    def test_valid_can_fd_64_bytes(self) -> None:
        f = CANFrame(can_id=0x300, dlc=64, data=bytes(64), is_fd=True)
        assert f.dlc == 64

    def test_valid_extended_id(self) -> None:
        f = CANFrame(can_id=0x1FFFFFFF, dlc=4, data=bytes(4), is_extended=True)
        assert f.is_extended

    def test_dlc_data_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="does not match dlc"):
            CANFrame(can_id=0x100, dlc=4, data=b"\x01\x02")

    def test_can20_dlc_too_large_raises(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            CANFrame(can_id=0x100, dlc=9, data=bytes(9))

    def test_can_fd_invalid_dlc_raises(self) -> None:
        with pytest.raises(ValueError, match="not in valid FD lengths"):
            CANFrame(can_id=0x100, dlc=9, data=bytes(9), is_fd=True)

    def test_can_fd_valid_fd_lengths_all_accepted(self) -> None:
        for dlc in VALID_FD_LENGTHS:
            f = CANFrame(can_id=0x100, dlc=dlc, data=bytes(dlc), is_fd=True)
            assert f.dlc == dlc

    def test_standard_id_max_exceeded_raises(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            CANFrame(can_id=0x800, dlc=0, data=b"")  # 0x800 > 0x7FF

    def test_extended_id_max_accepted(self) -> None:
        f = CANFrame(can_id=0x1FFFFFFF, dlc=0, data=b"", is_extended=True)
        assert f.can_id == 0x1FFFFFFF


# ===========================================================================
# MessageAdapter known-answer
# ===========================================================================

class TestMessageAdapterKnownAnswer:
    def test_known_answer_standard_frame(self) -> None:
        # encode_id = 0x00000100 (no flags), dlc=3, data=\x01\x02\x03
        frame = CANFrame(can_id=0x100, dlc=3, data=b"\x01\x02\x03")
        encoded = MessageAdapter.encode(frame)
        assert encoded == b"\x00\x00\x01\x00\x03\x01\x02\x03"

    def test_known_answer_zero_payload(self) -> None:
        frame = CANFrame(can_id=0x000, dlc=0, data=b"")
        encoded = MessageAdapter.encode(frame)
        assert encoded == b"\x00\x00\x00\x00\x00"


# ===========================================================================
# MessageAdapter round-trips
# ===========================================================================

class TestMessageAdapterRoundTrip:
    def test_round_trip_0_bytes(self) -> None:
        f = CANFrame(can_id=0x100, dlc=0, data=b"")
        assert MessageAdapter.decode(MessageAdapter.encode(f)) == f

    def test_round_trip_4_bytes(self) -> None:
        f = CANFrame(can_id=0x200, dlc=4, data=b"\xDE\xAD\xBE\xEF")
        assert MessageAdapter.decode(MessageAdapter.encode(f)) == f

    def test_round_trip_8_bytes(self) -> None:
        f = CANFrame(can_id=0x7FF, dlc=8, data=bytes(range(8)))
        assert MessageAdapter.decode(MessageAdapter.encode(f)) == f

    def test_round_trip_fd_8_bytes(self) -> None:
        f = CANFrame(can_id=0x100, dlc=8, data=bytes(8), is_fd=True)
        decoded = MessageAdapter.decode(MessageAdapter.encode(f))
        assert decoded.is_fd is True
        assert decoded.data == bytes(8)

    def test_round_trip_fd_64_bytes(self) -> None:
        f = CANFrame(can_id=0x300, dlc=64, data=bytes(range(64)), is_fd=True)
        decoded = MessageAdapter.decode(MessageAdapter.encode(f))
        assert decoded.is_fd is True
        assert decoded.dlc == 64
        assert decoded.data == bytes(range(64))

    def test_round_trip_extended_id(self) -> None:
        f = CANFrame(can_id=0x1ABCDEF, dlc=3, data=b"\x01\x02\x03", is_extended=True)
        decoded = MessageAdapter.decode(MessageAdapter.encode(f))
        assert decoded.is_extended is True
        assert decoded.can_id == 0x1ABCDEF

    def test_round_trip_fd_extended(self) -> None:
        f = CANFrame(can_id=0x1FFFF00, dlc=12, data=bytes(12), is_fd=True, is_extended=True)
        decoded = MessageAdapter.decode(MessageAdapter.encode(f))
        assert decoded.is_fd is True
        assert decoded.is_extended is True
        assert decoded.dlc == 12


# ===========================================================================
# Flag encoding verification
# ===========================================================================

class TestFlagEncoding:
    def test_fd_flag_in_encoded_bytes(self) -> None:
        f = CANFrame(can_id=0x100, dlc=0, data=b"", is_fd=True)
        enc_id = struct.unpack(">I", MessageAdapter.encode(f)[:4])[0]
        assert enc_id & MSG_FD_FLAG

    def test_eff_flag_in_encoded_bytes(self) -> None:
        f = CANFrame(can_id=0x100, dlc=0, data=b"", is_extended=True)
        enc_id = struct.unpack(">I", MessageAdapter.encode(f)[:4])[0]
        assert enc_id & MSG_EFF_FLAG

    def test_no_flags_for_standard_frame(self) -> None:
        f = CANFrame(can_id=0x100, dlc=0, data=b"")
        enc_id = struct.unpack(">I", MessageAdapter.encode(f)[:4])[0]
        assert not (enc_id & MSG_EFF_FLAG)
        assert not (enc_id & MSG_FD_FLAG)


# ===========================================================================
# MessageAdapter error cases
# ===========================================================================

class TestMessageAdapterErrors:
    def test_decode_truncated_raises(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            MessageAdapter.decode(b"\x00\x01")

    def test_decode_dlc_data_mismatch_raises(self) -> None:
        # Header says dlc=5 but only 3 bytes of data follow
        bad = struct.pack(">IB", 0x100, 5) + b"\x01\x02\x03"
        with pytest.raises(ValueError, match="does not match decoded dlc"):
            MessageAdapter.decode(bad)

    def test_decode_invalid_fd_dlc_raises(self) -> None:
        # Mark as FD (bit 29 set) but dlc=9 which is invalid
        enc_id = 0x100 | MSG_FD_FLAG
        bad = struct.pack(">IB", enc_id, 9) + bytes(9)
        with pytest.raises(ValueError, match="not in valid FD lengths"):
            MessageAdapter.decode(bad)

    def test_decode_can20_dlc_too_large_raises(self) -> None:
        bad = struct.pack(">IB", 0x100, 9) + bytes(9)
        with pytest.raises(ValueError, match="exceeds maximum of 8"):
            MessageAdapter.decode(bad)
