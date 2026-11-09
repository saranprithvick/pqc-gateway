"""LegacyNode: simulated ECU that emits CAN frames on demand.

Rate-driven timing and command forwarding are deferred to M7.  In M5a the
node generates frames only when explicitly called.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import List

from pqcgw.legacy.can_adapter import CanAdapter
from pqcgw.legacy.can_model import CANFrame, VALID_FD_LENGTHS


@dataclass
class TrafficProfile:
    """One CAN signal emitted by this node."""

    can_id: int
    rate_hz: float          # recorded for bus-time analysis; not enforced in M5a
    dlc: int
    payload_pattern: str    # "counter", "zeros", "random"
    is_fd: bool = False
    is_extended: bool = False

    def __post_init__(self) -> None:
        from pqcgw.legacy.can_model import VALID_FD_LENGTHS
        if self.is_fd and self.dlc not in VALID_FD_LENGTHS:
            raise ValueError(
                f"TrafficProfile dlc {self.dlc} not valid for CAN FD"
            )
        if not self.is_fd and not (0 <= self.dlc <= 8):
            raise ValueError(f"TrafficProfile dlc {self.dlc} out of range for CAN 2.0")
        if self.payload_pattern not in ("counter", "zeros", "random"):
            raise ValueError(f"Unknown payload_pattern: {self.payload_pattern!r}")


class LegacyNode:
    """Simulated ECU.  Generates deterministic CAN frames on demand."""

    def __init__(
        self,
        adapter: CanAdapter,
        profiles: list[TrafficProfile],
        seed: int = 0,
    ) -> None:
        self._adapter = adapter
        self._profiles = profiles
        # Per-profile counters (for "counter" pattern)
        self._counters: list[int] = [0] * len(profiles)
        # Per-profile seeded PRNGs (for "random" pattern)
        self._rngs: list[random.Random] = [
            random.Random(seed + i) for i in range(len(profiles))
        ]

    def inject(self, frame: CANFrame) -> None:
        """Write a frame directly to the CAN bus (use in attack/test scenarios)."""
        self._adapter.send(frame)

    def emit_one(self, profile_idx: int) -> CANFrame:
        """Generate and send one frame according to the given profile; return it."""
        if not (0 <= profile_idx < len(self._profiles)):
            raise IndexError(f"profile_idx {profile_idx} out of range")
        p = self._profiles[profile_idx]
        data = self._make_payload(profile_idx, p)
        frame = CANFrame(
            can_id=p.can_id,
            dlc=p.dlc,
            data=data,
            is_fd=p.is_fd,
            is_extended=p.is_extended,
        )
        self._adapter.send(frame)
        return frame

    # ------------------------------------------------------------------

    def _make_payload(self, idx: int, profile: TrafficProfile) -> bytes:
        if profile.payload_pattern == "counter":
            val = self._counters[idx] & 0xFF
            self._counters[idx] = (self._counters[idx] + 1) & 0xFF
            # Fill dlc bytes; counter in first byte, zeros elsewhere
            return bytes([val] + [0] * (profile.dlc - 1)) if profile.dlc > 0 else b""
        elif profile.payload_pattern == "zeros":
            return bytes(profile.dlc)
        else:  # "random"
            return bytes(self._rngs[idx].getrandbits(8) for _ in range(profile.dlc))
