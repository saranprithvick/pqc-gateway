"""Attacker: FOR TESTS ONLY.

Injects arbitrary frames onto a python-can virtual bus.  Used by T12 to demonstrate
that the Gateway forwards forged CAN frames (known limitation §1 item 1).
"""

from __future__ import annotations

import logging
import can

from pqcgw.legacy.can_model import CANFrame

log = logging.getLogger(__name__)


class Attacker:
    """Injects CAN frames onto a virtual bus channel.

    Uses the same 'virtual' interface as CanAdapter so frames appear on the same
    in-process bus.  FOR TESTS ONLY — not part of the production gateway path.
    """

    def __init__(self, channel: str = "vcan0") -> None:
        self._bus = can.Bus(interface="virtual", channel=channel)

    def inject_can_frame(self, frame: CANFrame) -> None:
        """Write a crafted frame to the CAN bus."""
        msg = can.Message(
            arbitration_id=frame.can_id,
            data=frame.data,
            is_extended_id=frame.is_extended,
            is_fd=frame.is_fd,
            check=True,
        )
        self._bus.send(msg)
        log.debug(
            "Attacker: injected frame can_id=0x%X dlc=%d data=%s",
            frame.can_id,
            frame.dlc,
            frame.data.hex(),
        )

    def close(self) -> None:
        self._bus.shutdown()

    def __enter__(self) -> "Attacker":
        return self

    def __exit__(self, *_) -> None:
        self.close()
