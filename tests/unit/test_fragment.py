"""Unit tests: fragmentation and Reassembler (defensive bounds)."""

from __future__ import annotations

import struct
import time
from unittest.mock import patch

import pytest

from pqcgw.net.fragment import (
    FRAG_HEADER_LEN,
    MAX_FRAG_COUNT,
    MAX_MSG_BYTES,
    MAX_PENDING,
    STALE_TIMEOUT_S,
    Reassembler,
    fragment,
)

_HDR = struct.Struct(">IHH")


def _make_frag(msg_id: int, frag_idx: int, frag_count: int, payload: bytes) -> bytes:
    return _HDR.pack(msg_id, frag_idx, frag_count) + payload


# ===========================================================================
# fragment()
# ===========================================================================

class TestFragment:
    def test_small_payload_one_fragment(self) -> None:
        frags = fragment(1, b"hello", mtu=1500)
        assert len(frags) == 1
        assert frags[0] == _HDR.pack(1, 0, 1) + b"hello"

    def test_zero_payload_one_fragment(self) -> None:
        frags = fragment(0, b"", mtu=1500)
        assert len(frags) == 1
        assert frags[0] == _HDR.pack(0, 0, 1)

    def test_exact_fit_one_fragment(self) -> None:
        payload = bytes(1500 - FRAG_HEADER_LEN)
        frags = fragment(2, payload, mtu=1500)
        assert len(frags) == 1

    def test_3000_bytes_at_mtu_1500_gives_three_fragments(self) -> None:
        # chunk_size = 1500 - 8 = 1492; ceil(3000/1492) = 3
        payload = bytes(3000)
        frags = fragment(3, payload, mtu=1500)
        assert len(frags) == 3
        for f in frags:
            assert len(f) <= 1500

    def test_fragments_cover_full_payload(self) -> None:
        payload = bytes(range(256)) * 10
        frags = fragment(10, payload, mtu=100)
        # Reassemble and verify
        r = Reassembler()
        result = None
        for f in frags:
            result = r.feed(f)
        assert result == payload

    def test_mtu_too_small_raises(self) -> None:
        with pytest.raises(ValueError, match="mtu"):
            fragment(0, b"x", mtu=FRAG_HEADER_LEN)

    def test_mtu_exactly_header_plus_one(self) -> None:
        frags = fragment(0, b"x", mtu=FRAG_HEADER_LEN + 1)
        assert len(frags) == 1


# ===========================================================================
# Reassembler — normal cases
# ===========================================================================

class TestReassemblerNormal:
    def test_single_fragment_in_order(self) -> None:
        r = Reassembler()
        result = r.feed(_make_frag(1, 0, 1, b"complete"))
        assert result == b"complete"

    def test_two_fragments_in_order(self) -> None:
        r = Reassembler()
        assert r.feed(_make_frag(1, 0, 2, b"hel")) is None
        result = r.feed(_make_frag(1, 1, 2, b"lo"))
        assert result == b"hello"

    def test_two_fragments_out_of_order(self) -> None:
        r = Reassembler()
        assert r.feed(_make_frag(1, 1, 2, b"lo")) is None
        result = r.feed(_make_frag(1, 0, 2, b"hel"))
        assert result == b"hello"

    def test_multiple_messages_interleaved(self) -> None:
        r = Reassembler()
        r.feed(_make_frag(1, 0, 2, b"a"))
        r.feed(_make_frag(2, 0, 1, b"X"))   # msg 2 completes immediately
        result_msg2 = r.feed(_make_frag(2, 0, 1, b"X"))
        # msg 2 was already completed; feeding again is a duplicate → None
        # First delivery of msg 2 should have returned b"X"
        # Let's redo properly
        r2 = Reassembler()
        r2.feed(_make_frag(10, 0, 2, b"part1"))
        complete = r2.feed(_make_frag(20, 0, 1, b"msg2"))
        assert complete == b"msg2"
        complete2 = r2.feed(_make_frag(10, 1, 2, b"part2"))
        assert complete2 == b"part1part2"


# ===========================================================================
# Reassembler — bounds and error cases
# ===========================================================================

class TestReassemblerBounds:
    def test_frag_idx_gte_frag_count_raises(self) -> None:
        r = Reassembler()
        with pytest.raises(ValueError, match="frag_idx"):
            r.feed(_make_frag(1, 2, 2, b"bad"))  # frag_idx=2 >= frag_count=2

    def test_frag_count_exceeds_max_dropped(self) -> None:
        r = Reassembler()
        big_count = MAX_FRAG_COUNT + 1
        wire = _HDR.pack(1, 0, big_count) + b"data"
        result = r.feed(wire)
        assert result is None
        assert 1 not in r._pending  # not stored

    def test_duplicate_frag_idx_ignored(self) -> None:
        r = Reassembler()
        r.feed(_make_frag(1, 0, 2, b"first"))
        r.feed(_make_frag(1, 0, 2, b"duplicate"))  # duplicate; ignored
        result = r.feed(_make_frag(1, 1, 2, b"second"))
        # Result should use first delivery of frag 0
        assert result == b"firstsecond"

    def test_total_size_cap(self) -> None:
        # Create a scenario where total would exceed MAX_MSG_BYTES.
        # We set frag_count=2 and each chunk is MAX_MSG_BYTES/2+1 so total > MAX_MSG_BYTES.
        half = MAX_MSG_BYTES // 2 + 1
        r = Reassembler()
        r.feed(_make_frag(1, 0, 2, bytes(half)))
        result = r.feed(_make_frag(1, 1, 2, bytes(half)))
        assert result is None  # dropped due to size cap

    def test_pending_cap_evicts_oldest(self) -> None:
        r = Reassembler()
        # Fill to MAX_PENDING with incomplete 2-fragment messages
        for i in range(MAX_PENDING):
            r.feed(_make_frag(i, 0, 2, b"part"))
        assert len(r._pending) == MAX_PENDING
        # Adding one more should evict the oldest (msg_id=0)
        r.feed(_make_frag(MAX_PENDING, 0, 2, b"new"))
        assert 0 not in r._pending
        assert len(r._pending) == MAX_PENDING

    def test_stale_eviction(self) -> None:
        r = Reassembler()
        # Add an incomplete message
        r.feed(_make_frag(99, 0, 2, b"first"))
        assert 99 in r._pending
        # Advance time past stale timeout
        future = time.monotonic() + STALE_TIMEOUT_S + 1.0
        with patch("pqcgw.net.fragment.time") as mock_time:
            mock_time.monotonic.return_value = future
            # Feed another fragment to trigger eviction
            r.feed(_make_frag(200, 0, 1, b"trigger"))
        # msg 99 should have been evicted
        assert 99 not in r._pending

    def test_wire_too_short_returns_none(self) -> None:
        r = Reassembler()
        result = r.feed(b"\x00\x01")  # less than FRAG_HEADER_LEN
        assert result is None
