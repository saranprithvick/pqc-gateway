"""Link interface and LoopbackLink.

Link is the abstraction that Gateway and ModernPeer use to send and receive
raw message bytes.  LoopbackLink is an in-memory implementation backed by
asyncio.Queue pairs; it is used in unit and integration tests.  LinkEmulator
(emulator.py) is a Link that adds delay/loss/fragmentation.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Optional


class Link(ABC):
    """Abstract bidirectional message channel."""

    @abstractmethod
    async def send(self, msg: bytes) -> None:
        """Send *msg* to the other side."""

    @abstractmethod
    async def recv(self, timeout: float = 1.0) -> Optional[bytes]:
        """Return the next message, or None if *timeout* elapses."""

    async def recv_stream(self) -> bytes:
        """Await indefinitely until a message arrives; for use in reader tasks.

        Default implementation loops on recv(); subclasses should override
        with a direct queue.get() to avoid asyncio.wait_for overhead.
        """
        while True:
            msg = await self.recv(timeout=1.0)
            if msg is not None:
                return msg


class LoopbackLink(Link):
    """In-memory paired link.  Each half's send() feeds the other's recv()."""

    def __init__(self, tx: asyncio.Queue, rx: asyncio.Queue) -> None:
        self._tx = tx
        self._rx = rx

    @staticmethod
    def make_pair() -> tuple["LoopbackLink", "LoopbackLink"]:
        """Return (gateway_half, peer_half).

        gateway_half.send() → peer_half.recv()
        peer_half.send()    → gateway_half.recv()
        """
        a_to_b: asyncio.Queue[bytes] = asyncio.Queue()
        b_to_a: asyncio.Queue[bytes] = asyncio.Queue()
        gw_half = LoopbackLink(tx=a_to_b, rx=b_to_a)
        peer_half = LoopbackLink(tx=b_to_a, rx=a_to_b)
        return gw_half, peer_half

    async def send(self, msg: bytes) -> None:
        await self._tx.put(msg)

    async def recv(self, timeout: float = 1.0) -> Optional[bytes]:
        try:
            return await asyncio.wait_for(self._rx.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def recv_stream(self) -> bytes:
        """Direct queue.get() — no wait_for overhead; wakes immediately on arrival."""
        return await self._rx.get()
