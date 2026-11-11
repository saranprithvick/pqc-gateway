"""LinkAttacker: FOR TESTS ONLY.

Wraps any Link pair and allows an attacker to intercept, replay, tamper, and
inject messages on the emulated link between Gateway and Peer.

The attacker inserts two proxy Link objects between the gateway half and the peer
half.  Each proxy queues outbound messages so the attacker can inspect, hold,
replay, or drop them before forwarding.  The attacker also exposes an inject()
call to push fabricated bytes directly into either direction.

Usage in tests::

    gw_link_inner, peer_link_inner = LoopbackLink.make_pair()
    attacker, gw_link, peer_link = LinkAttacker.wrap(gw_link_inner, peer_link_inner)
    # Gateway uses gw_link; Peer uses peer_link.
    # attacker.replay(Direction.I2R, msg) re-delivers a captured message.
    # attacker.inject(Direction.I2R, payload) sends fabricated bytes toward the peer.
    # attacker.tamper_next(Direction.I2R, fn) transforms the next message in-flight.

This module is FOR TESTS ONLY and must never be imported in production gateway code.
"""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from pqcgw.net.link import Link
from pqcgw.protocol.record import Direction


class _AttackerProxy(Link):
    """One proxy Link half.  Outbound sends are routed through the attacker."""

    def __init__(self, inner: Link, outbound: "asyncio.Queue[bytes]") -> None:
        self._inner = inner
        self._outbound = outbound

    async def send(self, msg: bytes) -> None:
        await self._outbound.put(msg)

    async def recv(self, timeout: float = 1.0) -> Optional[bytes]:
        return await self._inner.recv(timeout=timeout)


class LinkAttacker:
    """Intercept, replay, tamper, and inject on a Link pair.

    After wrap(), the caller passes gw_link to the Gateway and peer_link to the
    Peer; both are proxies whose outbound traffic passes through this attacker
    before reaching the other side's inner Link.

    The attacker starts a background task (start() / stop()) that pumps messages
    from each proxy's outbound queue to the corresponding inner link, optionally
    applying a one-shot transform.

    FOR TESTS ONLY.
    """

    def __init__(
        self,
        gw_inner: Link,
        peer_inner: Link,
        gw_outbound: "asyncio.Queue[bytes]",
        peer_outbound: "asyncio.Queue[bytes]",
        gw_link: Link,
        peer_link: Link,
    ) -> None:
        self._gw_inner = gw_inner      # messages going TO gateway (from peer)
        self._peer_inner = peer_inner  # messages going TO peer (from gateway)
        self._gw_outbound = gw_outbound    # proxy queue: gateway → peer direction
        self._peer_outbound = peer_outbound  # proxy queue: peer → gateway direction
        self._gw_link = gw_link
        self._peer_link = peer_link

        # One-shot transforms: applied to the next message in that direction
        self._i2r_transform: Optional[Callable[[bytes], bytes]] = None
        self._r2i_transform: Optional[Callable[[bytes], bytes]] = None

        # Captured messages (most recently seen per direction)
        self._i2r_captured: list[bytes] = []
        self._r2i_captured: list[bytes] = []

        self._tasks: list[asyncio.Task] = []
        self._running = False

    @staticmethod
    def wrap(gw_inner: Link, peer_inner: Link) -> "tuple[LinkAttacker, Link, Link]":
        """Insert the attacker between two existing Link halves.

        Returns (attacker, gw_proxy_link, peer_proxy_link).
        Pass gw_proxy_link to the Gateway and peer_proxy_link to the Peer.

        The inner links remain usable for the other direction (recv calls are
        forwarded directly to the inner links).
        """
        # gateway sends → gw_outbound queue → attacker pump → gw_inner.send() → peer reads
        gw_outbound: asyncio.Queue[bytes] = asyncio.Queue()
        # peer sends → peer_outbound queue → attacker pump → peer_inner.send() → gateway reads
        peer_outbound: asyncio.Queue[bytes] = asyncio.Queue()

        gw_proxy = _AttackerProxy(gw_inner, gw_outbound)
        peer_proxy = _AttackerProxy(peer_inner, peer_outbound)

        attacker = LinkAttacker(
            gw_inner=gw_inner,
            peer_inner=peer_inner,
            gw_outbound=gw_outbound,
            peer_outbound=peer_outbound,
            gw_link=gw_proxy,
            peer_link=peer_proxy,
        )
        return attacker, gw_proxy, peer_proxy

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        """Start the background pump tasks.  Call inside an asyncio event loop."""
        if self._running:
            return
        self._running = True
        loop = asyncio.get_event_loop()
        self._tasks.append(loop.create_task(self._pump(Direction.I2R)))
        self._tasks.append(loop.create_task(self._pump(Direction.R2I)))

    async def stop(self) -> None:
        """Cancel and await the pump tasks."""
        self._running = False
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass
        self._tasks.clear()

    # ------------------------------------------------------------------ #
    # Attack operations (all safe to call from outside the pump tasks)
    # ------------------------------------------------------------------ #

    async def inject(self, direction: Direction, payload: bytes) -> None:
        """Push fabricated bytes directly into the channel.

        I2R → payload arrives at the peer's recv().
        R2I → payload arrives at the gateway's recv().

        For a LoopbackLink pair (gw_half, peer_half):
          gw_inner.send() → a_to_b → peer_half.recv()   ← I2R delivery
          peer_inner.send() → b_to_a → gw_half.recv()   ← R2I delivery
        """
        if direction == Direction.I2R:
            await self._gw_inner.send(payload)
        else:
            await self._peer_inner.send(payload)

    async def replay(self, direction: Direction, msg: bytes) -> None:
        """Re-deliver a previously captured (or supplied) message."""
        await self.inject(direction, msg)

    def tamper_next(
        self,
        direction: Direction,
        transform: Callable[[bytes], bytes],
    ) -> None:
        """Apply *transform* to the next message in *direction*.

        One-shot: cleared after the first message is transformed.
        """
        if direction == Direction.I2R:
            self._i2r_transform = transform
        else:
            self._r2i_transform = transform

    def captured_i2r(self) -> list[bytes]:
        """Return a copy of all I2R messages captured so far."""
        return list(self._i2r_captured)

    def captured_r2i(self) -> list[bytes]:
        """Return a copy of all R2I messages captured so far."""
        return list(self._r2i_captured)

    # ------------------------------------------------------------------ #
    # Internal pump
    # ------------------------------------------------------------------ #

    async def _pump(self, direction: Direction) -> None:
        """Forward messages from the proxy queue to the inner link.

        Applies one-shot transforms; captures every message seen.
        """
        if direction == Direction.I2R:
            # Gateway sends via gw_outbound → deliver to peer via gw_inner.send()
            # (gw_inner.send() puts into gw_half.tx = a_to_b, which peer_half.recv() reads)
            src_q = self._gw_outbound
            dst_link = self._gw_inner
            captured = self._i2r_captured
            get_transform = lambda: self._i2r_transform
            set_transform = lambda v: setattr(self, "_i2r_transform", v)
        else:
            # Peer sends via peer_outbound → deliver to gateway via peer_inner.send()
            # (peer_inner.send() puts into peer_half.tx = b_to_a, which gw_half.recv() reads)
            src_q = self._peer_outbound
            dst_link = self._peer_inner
            captured = self._r2i_captured
            get_transform = lambda: self._r2i_transform
            set_transform = lambda v: setattr(self, "_r2i_transform", v)

        while self._running:
            try:
                msg = await asyncio.wait_for(src_q.get(), timeout=0.1)
            except asyncio.TimeoutError:
                continue

            captured.append(msg)

            fn = get_transform()
            if fn is not None:
                set_transform(None)  # one-shot: clear before applying
                msg = fn(msg)

            await dst_link.send(msg)
