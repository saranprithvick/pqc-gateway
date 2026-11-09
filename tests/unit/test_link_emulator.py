"""Unit tests: LoopbackLink and LinkEmulator."""

from __future__ import annotations

import asyncio

import pytest

from pqcgw.net.emulator import LinkEmulator, NetworkConfig
from pqcgw.net.link import LoopbackLink


# ===========================================================================
# LoopbackLink
# ===========================================================================

class TestLoopbackLink:
    def test_send_recv_pair(self) -> None:
        async def _run() -> None:
            gw, peer = LoopbackLink.make_pair()
            await gw.send(b"hello")
            result = await peer.recv(timeout=1.0)
            assert result == b"hello"
            await peer.send(b"world")
            result2 = await gw.recv(timeout=1.0)
            assert result2 == b"world"

        asyncio.run(_run())

    def test_recv_timeout_returns_none(self) -> None:
        async def _run() -> None:
            gw, _peer = LoopbackLink.make_pair()
            result = await gw.recv(timeout=0.01)
            assert result is None

        asyncio.run(_run())

    def test_multiple_messages_in_order(self) -> None:
        async def _run() -> None:
            gw, peer = LoopbackLink.make_pair()
            for i in range(5):
                await gw.send(bytes([i]))
            for i in range(5):
                msg = await peer.recv(timeout=1.0)
                assert msg == bytes([i])

        asyncio.run(_run())


# ===========================================================================
# LinkEmulator — ideal
# ===========================================================================

class TestLinkEmulatorIdeal:
    def test_message_arrives_intact(self) -> None:
        async def _run() -> None:
            cfg = NetworkConfig(delay_ms=0, loss_pct=0)
            gw, peer = LinkEmulator.make_pair(cfg)
            payload = b"test message"
            await gw.send(payload)
            result = await peer.recv(timeout=2.0)
            assert result == payload

        asyncio.run(_run())

    def test_bidirectional(self) -> None:
        async def _run() -> None:
            cfg = NetworkConfig(delay_ms=0, loss_pct=0)
            gw, peer = LinkEmulator.make_pair(cfg)
            await gw.send(b"i2r")
            await peer.send(b"r2i")
            assert await peer.recv(timeout=2.0) == b"i2r"
            assert await gw.recv(timeout=2.0) == b"r2i"

        asyncio.run(_run())


# ===========================================================================
# LinkEmulator — loss
# ===========================================================================

class TestLinkEmulatorLoss:
    def test_100pct_loss_message_never_arrives(self) -> None:
        async def _run() -> None:
            cfg = NetworkConfig(loss_pct=100.0, mtu_bytes=1500)
            gw, peer = LinkEmulator.make_pair(cfg)
            await gw.send(b"lost")
            result = await peer.recv(timeout=0.3)
            assert result is None

        asyncio.run(_run())


# ===========================================================================
# LinkEmulator — fragmentation
# ===========================================================================

class TestLinkEmulatorFragmentation:
    def test_message_larger_than_mtu_reassembled(self) -> None:
        async def _run() -> None:
            # mtu=50 → each fragment carries 50-8=42 bytes of payload
            # 100-byte message → 3 fragments: 42 + 42 + 16
            cfg = NetworkConfig(mtu_bytes=50, delay_ms=0, loss_pct=0)
            gw, peer = LinkEmulator.make_pair(cfg)
            payload = bytes(range(100))
            await gw.send(payload)
            result = await peer.recv(timeout=2.0)
            assert result == payload

        asyncio.run(_run())

    def test_fragment_counter_incremented(self) -> None:
        async def _run() -> None:
            cfg = NetworkConfig(mtu_bytes=50, delay_ms=0, loss_pct=0)
            gw, peer = LinkEmulator.make_pair(cfg)
            # Access emulator via the attached reference
            emulator = gw._emulator  # type: ignore[attr-defined]
            payload = bytes(100)  # 3 fragments at mtu=50
            await gw.send(payload)
            await peer.recv(timeout=2.0)
            assert emulator.fragments_sent_i2r >= 2  # at least 2 (3 expected)

        asyncio.run(_run())
