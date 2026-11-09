"""PassthroughPath: C0 baseline — no handshake, no crypto.

Wire framing (§15 item 17): can_id (4 B incl. flags) || dlc (1 B) || data
The 8 B fragment header is applied by the Link/Emulator layer (shared with C1–C3).
This matches the minimal overhead a real unsecured link would carry.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from pqcgw.legacy.can_adapter import CanAdapter
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.link import Link
from pqcgw.nodes.adapter import MessageAdapter


class PassthroughPath:
    """C0: frame and forward without any crypto or handshake."""

    async def run_gateway_side(
        self,
        can_adapter: CanAdapter,
        link: Link,
        n_frames: int,
    ) -> None:
        """Read n_frames from CAN, encode, and forward over the link."""
        loop = asyncio.get_event_loop()
        sent = 0
        while sent < n_frames:
            frame = await loop.run_in_executor(None, can_adapter.receive, 0.05)
            if frame is not None:
                encoded = MessageAdapter.encode(frame)
                await link.send(encoded)
                sent += 1

    async def run_peer_side(
        self,
        link: Link,
        sink: "asyncio.Queue[CANFrame]",
        n_frames: int,
    ) -> None:
        """Receive n_frames from the link, decode, and place in sink."""
        received = 0
        while received < n_frames:
            wire = await link.recv(timeout=5.0)
            if wire is None:
                continue
            try:
                frame = MessageAdapter.decode(wire)
            except ValueError:
                continue  # drop malformed
            await sink.put(frame)
            received += 1
