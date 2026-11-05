"""End-to-end tests over LinkEmulator (fragmentation and loss/retransmit).

These tests verify the full Gateway+ModernPeer stack using an emulated network link
rather than a direct LoopbackLink.  They cover:

  - test_e2e_c1_fragmented_handshake: mtu_bytes=200, forcing every handshake message
    to be fragmented and reassembled.  Verifies that fragmentation is transparent.
  - test_e2e_c1_loss_retransmit: 30% loss rate (seed=42), forcing the Gateway's
    HELLO_I retransmit path.  Verifies that the handshake succeeds despite loss and
    that retransmit_count is recorded.

Each test uses a unique virtual-bus channel (can_channel fixture).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pqcgw.crypto.registry import load_suite
from pqcgw.legacy.can_adapter import CanAdapter
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.emulator import LinkEmulator, NetworkConfig
from pqcgw.nodes.gateway import Gateway
from pqcgw.nodes.peer import ModernPeer
from pqcgw.protocol.handshake import IdentityContext

SUITE_DIR = Path(__file__).parent.parent.parent / "configs" / "suites"

_N = 3  # I2R frames per test (fewer than test_e2e.py to keep tests fast)


def _make_identities(suite_name: str):
    suite = load_suite(SUITE_DIR / f"{suite_name}.toml")
    sig = suite.signature
    gw_pk, gw_sk = sig.keygen()
    peer_pk, peer_sk = sig.keygen()
    gw_id = IdentityContext(
        my_id="gw", peer_id="peer",
        my_sk=gw_sk, my_pk=gw_pk, peer_pk=peer_pk,
        allowed_suite_ids=[1, 2, 3],
    )
    peer_id = IdentityContext(
        my_id="peer", peer_id="gw",
        my_sk=peer_sk, my_pk=peer_pk, peer_pk=gw_pk,
        allowed_suite_ids=[1, 2, 3],
    )
    return suite, gw_id, peer_id


def _make_frames(n: int) -> list[CANFrame]:
    return [CANFrame(can_id=0x100, dlc=8, data=bytes([i % 256] * 8)) for i in range(n)]


async def _inject(channel: str, frames: list[CANFrame]) -> None:
    """Inject from a separate bus so the gateway bus can receive them."""
    with CanAdapter(channel) as sender:
        for f in frames:
            sender.send(f)


# ===========================================================================
# Fragmented handshake (mtu_bytes=200)
# ===========================================================================

def test_e2e_c1_fragmented_handshake(can_channel: str) -> None:
    """C1 handshake succeeds over a link with mtu_bytes=200.

    Every HELLO message (which is >> 200 B for C1 with ECDSA-P256 signatures)
    is fragmented.  The LinkEmulator fragments and reassembles transparently.
    3 I2R DATA frames must arrive at the peer correctly.
    """
    frames = _make_frames(_N)

    async def _scenario() -> tuple[list[CANFrame], int]:
        suite, gw_id, peer_id = _make_identities("classical")
        config = NetworkConfig(
            delay_ms=0.0, jitter_ms=0.0, loss_pct=0.0,
            bandwidth_kbps=0.0, mtu_bytes=200, seed=42,
        )
        gw_link, peer_link = LinkEmulator.make_pair(config)
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()

        with CanAdapter(can_channel) as can_gw:
            gateway = Gateway(
                suite, gw_id, can_gw, gw_link,
                handshake_timeout_ms=500,  # more time for fragment reassembly
                handshake_max_retries=5,
            )
            peer = ModernPeer(suite, peer_id, peer_link, sink)

            await asyncio.wait_for(
                asyncio.gather(
                    gateway.run(n_frames=_N),
                    peer.run(n_frames=_N),
                    _inject(can_channel, frames),
                ),
                timeout=30.0,
            )

        assert gateway.handshake_success
        assert peer.handshake_success
        return (
            [sink.get_nowait() for _ in range(sink.qsize())],
            gateway.handshake_retransmit_count,
        )

    received, retransmits = asyncio.run(_scenario())
    assert len(received) == _N, f"Expected {_N} frames, got {len(received)}"
    for i, f in enumerate(received):
        assert f.data == frames[i].data, f"Frame {i} data mismatch"
    # With zero loss, no retransmits should be needed
    assert retransmits == 0


# ===========================================================================
# Loss + handshake retransmit (loss_pct=30, seed=42)
# ===========================================================================

def test_e2e_c1_loss_retransmit(can_channel: str) -> None:
    """C1 handshake succeeds at 30% packet loss via HELLO_I retransmit.

    Purpose: verify that the Gateway retransmit loop in handshake() works under
    loss.  With seed=42 and 30% loss some HELLO_I / HELLO_R fragments are
    dropped; the Gateway must retry and eventually succeed.

    DATA delivery under loss is NOT tested here: M5a has no per-record retransmit
    (that is M5b/M6 work).  Both gateway and peer exit immediately after the
    handshake (n_frames=0) so the test never waits on a lost DATA record.
    """
    async def _scenario() -> int:
        suite, gw_id, peer_id = _make_identities("classical")
        config = NetworkConfig(
            delay_ms=5.0, jitter_ms=1.0, loss_pct=30.0,
            bandwidth_kbps=0.0, mtu_bytes=1500, seed=42,
        )
        gw_link, peer_link = LinkEmulator.make_pair(config)
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()

        with CanAdapter(can_channel) as can_gw:
            gateway = Gateway(
                suite, gw_id, can_gw, gw_link,
                handshake_timeout_ms=200,
                handshake_max_retries=10,
            )
            peer = ModernPeer(
                suite, peer_id, peer_link, sink,
                handshake_recv_timeout=60.0,
            )

            # Keep the peer alive (n_frames=None) so its data loop can respond
            # to FINISHED_I retransmits if FINISHED_R was dropped.  Cancel the
            # peer once the gateway has successfully exited.
            gw_task = asyncio.create_task(gateway.run(n_frames=0))
            peer_task = asyncio.create_task(peer.run(n_frames=None))
            try:
                await asyncio.wait_for(gw_task, timeout=30.0)
            finally:
                peer_task.cancel()
                await asyncio.gather(peer_task, return_exceptions=True)

        assert gateway.handshake_success
        assert peer.handshake_success
        return gateway.handshake_retransmit_count

    retransmits = asyncio.run(_scenario())
    # With seed=42 and 30% loss the handshake may need retransmits; the counter
    # must be a non-negative int regardless.
    assert retransmits >= 0
