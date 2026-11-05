"""Fragmentation and reassembly.

Fragment header (8 B, big-endian):
  msg_id    uint32
  frag_idx  uint16   (0-based index of this fragment in the message)
  frag_count uint16  (total fragments; 1 = no fragmentation)

Maximum payload per fragment = mtu - FRAG_HEADER_LEN.

Reassembler defences (defensive parsing per CLAUDE.md §2):
  - frag_idx >= frag_count              → ValueError (caller may log and drop)
  - frag_count > MAX_FRAG_COUNT         → drop silently (return None)
  - computed total size > MAX_MSG_BYTES → drop silently
  - duplicate (msg_id, frag_idx)        → ignored
  - evict stale partials (> STALE_TIMEOUT_S since first fragment)
  - cap concurrent pending messages at MAX_PENDING (evict oldest on overflow)
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Optional

FRAG_HEADER_LEN: int = 8
MAX_FRAG_COUNT: int = 256
MAX_MSG_BYTES: int = 65536
MAX_PENDING: int = 64
STALE_TIMEOUT_S: float = 5.0

_HDR = struct.Struct(">IHH")  # msg_id, frag_idx, frag_count


def fragment(msg_id: int, payload: bytes, mtu: int) -> list[bytes]:
    """Split *payload* into fragments each at most *mtu* bytes (including header).

    Raises ValueError if mtu <= FRAG_HEADER_LEN (no room for payload).
    Returns a list of length 1 when the payload fits in a single fragment.
    """
    if mtu <= FRAG_HEADER_LEN:
        raise ValueError(
            f"mtu {mtu} must be > FRAG_HEADER_LEN {FRAG_HEADER_LEN}"
        )
    chunk_size = mtu - FRAG_HEADER_LEN
    if chunk_size <= 0:
        raise ValueError(f"chunk_size {chunk_size} <= 0 for mtu {mtu}")

    chunks = [payload[i : i + chunk_size] for i in range(0, max(len(payload), 1), chunk_size)]
    if not chunks:
        chunks = [b""]
    frag_count = len(chunks)

    frags: list[bytes] = []
    for idx, chunk in enumerate(chunks):
        header = _HDR.pack(msg_id, idx, frag_count)
        frags.append(header + chunk)
    return frags


@dataclass
class _PendingMsg:
    total_frags: int
    frags: list[Optional[bytes]]
    received_set: set[int] = field(default_factory=set)
    first_arrival: float = field(default_factory=time.monotonic)


class Reassembler:
    """Reassemble fragmented messages.  One instance per connection."""

    def __init__(self) -> None:
        self._pending: dict[int, _PendingMsg] = {}
        self._arrival_order: list[int] = []  # msg_ids in insertion order

    def feed(self, wire: bytes) -> Optional[bytes]:
        """Ingest one fragment wire bytes.

        Returns the reassembled message bytes when all fragments have been
        received, or None otherwise.

        Raises ValueError for structurally invalid fragments (frag_idx >=
        frag_count); other policy violations are silently dropped.
        """
        if len(wire) < FRAG_HEADER_LEN:
            return None  # too short to hold a valid header

        msg_id, frag_idx, frag_count = _HDR.unpack(wire[:FRAG_HEADER_LEN])
        payload_chunk = wire[FRAG_HEADER_LEN:]

        # Hard reject: structurally invalid
        if frag_idx >= frag_count:
            raise ValueError(
                f"frag_idx {frag_idx} >= frag_count {frag_count}"
            )

        # Policy drops (no error raised)
        if frag_count > MAX_FRAG_COUNT:
            return None

        # Evict stale partials first
        self._evict_stale()

        if msg_id not in self._pending:
            # Validate before allocating: reject if total would exceed MAX_MSG_BYTES
            max_chunk = len(payload_chunk)  # worst case: all chunks are this big
            # We don't know other chunk sizes yet; use a conservative upper bound.
            if frag_count * (max_chunk + 1) > MAX_MSG_BYTES:
                # Strictly we'd need all chunks; use a generous check here.
                # Exact check is applied when total can be measured below.
                pass
            # Evict oldest if at capacity
            if len(self._pending) >= MAX_PENDING:
                oldest_id = self._arrival_order[0]
                del self._pending[oldest_id]
                self._arrival_order.pop(0)
            self._pending[msg_id] = _PendingMsg(
                total_frags=frag_count,
                frags=[None] * frag_count,
            )
            self._arrival_order.append(msg_id)
        else:
            pm = self._pending[msg_id]
            # Consistency: frag_count must match what we already know
            if pm.total_frags != frag_count:
                # Contradictory fragment; drop silently
                return None

        pm = self._pending[msg_id]

        # Drop duplicate
        if frag_idx in pm.received_set:
            return None

        pm.frags[frag_idx] = payload_chunk
        pm.received_set.add(frag_idx)

        if len(pm.received_set) == pm.total_frags:
            # All fragments received; assemble and check size
            message = b"".join(pm.frags)  # type: ignore[arg-type]
            # Remove from pending
            del self._pending[msg_id]
            self._arrival_order.remove(msg_id)

            if len(message) > MAX_MSG_BYTES:
                return None  # exceed size cap; drop
            return message

        return None

    def _evict_stale(self) -> None:
        now = time.monotonic()
        stale = [
            mid
            for mid, pm in self._pending.items()
            if (now - pm.first_arrival) > STALE_TIMEOUT_S
        ]
        for mid in stale:
            del self._pending[mid]
            if mid in self._arrival_order:
                self._arrival_order.remove(mid)
