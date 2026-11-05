"""End-to-end tests over LoopbackLink (C0–C3).

Tests verify the full stack — CAN adapter, Gateway, ModernPeer, C0 passthrough —
for all four configurations using an in-memory link (no link impairments).

IMPORTANT: python-can's virtual bus does NOT echo sends back to the sender.
To inject frames that the Gateway's bus will receive, we open a SEPARATE sender
bus on the same channel.  `gw_bus.send(f)` would not be readable by `gw_bus.recv()`;
`sender_bus.send(f)` IS readable by `gw_bus.recv()` because they share the channel.

Each test uses a unique virtual-bus channel (can_channel fixture) to prevent
cross-test contamination.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pqcgw.crypto.registry import load_suite
from pqcgw.legacy.can_adapter import CanAdapter
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.link import LoopbackLink
from pqcgw.nodes.adapter import MessageAdapter
from pqcgw.nodes.gateway import Gateway
from pqcgw.nodes.passthrough import PassthroughPath
from pqcgw.nodes.peer import ModernPeer
from pqcgw.protocol.handshake import IdentityContext

SUITE_DIR = Path(__file__).parent.parent.parent / "configs" / "suites"

_N = 5  # I2R frames per test


# ------------------------------------------------------------------
# Shared helpers
# ------------------------------------------------------------------

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
    """Inject frames from a separate bus so the gateway bus can receive them.

    python-can virtual bus: a sender does not receive its own echoes.  Opening a
    *separate* bus on the same channel and sending from that bus makes the frames
    readable on any other bus with the same channel name.
    """
    with CanAdapter(channel) as sender:
        for f in frames:
            sender.send(f)


# ===========================================================================
# C0 passthrough
# ===========================================================================

def test_e2e_c0_passthrough(can_channel: str) -> None:
    """C0: 5 frames forwarded through PassthroughPath without crypto."""
    frames = _make_frames(_N)

    async def _scenario() -> list[CANFrame]:
        gw_link, peer_link = LoopbackLink.make_pair()
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()

        with CanAdapter(can_channel) as can_gw:
            path = PassthroughPath()
            await asyncio.wait_for(
                asyncio.gather(
                    path.run_gateway_side(can_gw, gw_link, _N),
                    path.run_peer_side(peer_link, sink, _N),
                    _inject(can_channel, frames),  # separate sender bus
                ),
                timeout=10.0,
            )

        return [sink.get_nowait() for _ in range(sink.qsize())]

    received = asyncio.run(_scenario())
    assert len(received) == _N
    for i, frame in enumerate(received):
        assert frame.data == frames[i].data
        assert frame.can_id == 0x100


# ===========================================================================
# C1–C3 over LoopbackLink
# ===========================================================================

def _run_e2e(suite_name: str, can_channel: str) -> list[CANFrame]:
    frames = _make_frames(_N)

    async def _scenario() -> list[CANFrame]:
        suite, gw_id, peer_id = _make_identities(suite_name)
        gw_link, peer_link = LoopbackLink.make_pair()
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()

        with CanAdapter(can_channel) as can_gw:
            gateway = Gateway(suite, gw_id, can_gw, gw_link)
            peer = ModernPeer(suite, peer_id, peer_link, sink)

            await asyncio.wait_for(
                asyncio.gather(
                    gateway.run(n_frames=_N),
                    peer.run(n_frames=_N),
                    _inject(can_channel, frames),  # separate sender
                ),
                timeout=15.0,
            )

        assert gateway.handshake_success
        assert peer.handshake_success
        return [sink.get_nowait() for _ in range(sink.qsize())]

    return asyncio.run(_scenario())


def test_e2e_c1_classical(can_channel: str) -> None:
    """C1: Gateway+Peer handshake + 5 I2R frames, all received correctly."""
    frames = _make_frames(_N)
    received = _run_e2e("classical", can_channel)
    assert len(received) == _N
    for i, f in enumerate(received):
        assert f.data == frames[i].data


def test_e2e_c2_pqc(can_channel: str) -> None:
    """C2: PQC-only suite end-to-end."""
    frames = _make_frames(_N)
    received = _run_e2e("pqc", can_channel)
    assert len(received) == _N
    for i, f in enumerate(received):
        assert f.data == frames[i].data


def test_e2e_c3_hybrid(can_channel: str) -> None:
    """C3: Hybrid suite end-to-end."""
    frames = _make_frames(_N)
    received = _run_e2e("hybrid", can_channel)
    assert len(received) == _N
    for i, f in enumerate(received):
        assert f.data == frames[i].data


# ===========================================================================
# Reverse path: Peer → Gateway → CAN
# ===========================================================================

def test_e2e_reverse_path(can_channel: str) -> None:
    """Peer sends 2 R2I command frames; Gateway writes them to CAN.

    We use a third CAN adapter on the same channel to read back what the Gateway
    wrote (since the gateway's own bus cannot receive its own writes).
    """
    commands = [
        CANFrame(can_id=0x200, dlc=4, data=b"\xDE\xAD\xBE\xEF"),
        CANFrame(can_id=0x201, dlc=2, data=b"\xCA\xFE"),
    ]
    i2r_frames = [CANFrame(can_id=0x100, dlc=4, data=b"\x01\x02\x03\x04")]

    async def _scenario() -> list[CANFrame]:
        suite, gw_id, peer_id = _make_identities("classical")
        gw_link, peer_link = LoopbackLink.make_pair()
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        cmd_sink: asyncio.Queue[CANFrame] = asyncio.Queue()

        with CanAdapter(can_channel) as can_gw, \
             CanAdapter(can_channel) as can_rx:  # reads R2I frames from the bus

            # Filter to only the R2I command IDs; the injected I2R frame also
            # arrives on can_rx (virtual bus broadcasts to all adapters on channel).
            r2i_ids = {cmd.can_id for cmd in commands}

            async def _read_commands(n: int) -> None:
                loop = asyncio.get_running_loop()
                collected = 0
                while collected < n:
                    f = await loop.run_in_executor(None, can_rx.receive, 0.1)
                    if f is not None and f.can_id in r2i_ids:
                        await cmd_sink.put(f)
                        collected += 1

            gateway = Gateway(suite, gw_id, can_gw, gw_link)
            peer = ModernPeer(suite, peer_id, peer_link, sink)

            # Gateway runs indefinitely (n_frames=None) so it keeps processing
            # R2I commands after the single I2R frame is forwarded.
            # Cancel it once the other participants have all finished.
            gw_task = asyncio.create_task(gateway.run(n_frames=None))
            other_tasks = [
                asyncio.create_task(peer.run(n_frames=1, commands=commands)),
                asyncio.create_task(_inject(can_channel, i2r_frames)),
                asyncio.create_task(_read_commands(len(commands))),
            ]
            try:
                await asyncio.wait_for(
                    asyncio.gather(*other_tasks),
                    timeout=15.0,
                )
            finally:
                gw_task.cancel()
                await asyncio.gather(gw_task, return_exceptions=True)

        return [cmd_sink.get_nowait() for _ in range(cmd_sink.qsize())]

    received = asyncio.run(_scenario())
    assert len(received) == len(commands)
    for orig, got in zip(commands, received):
        assert got.can_id == orig.can_id
        assert got.data == orig.data


# ===========================================================================
# §15 item 20: pre-session CAN frame buffer
# ===========================================================================

def test_e2e_pre_session_buffer(can_channel: str) -> None:
    """CAN frames injected while Gateway awaits FINISHED_R arrive at peer.

    The separate sender bus injects 3 frames immediately.  By the time the
    Gateway starts its data loop, these frames have been buffered during the
    handshake (by _buffer_can) and are flushed after FINISHED_R is verified.
    """
    buffered_frames = [
        CANFrame(can_id=0x300, dlc=3, data=bytes([i, i + 1, i + 2]))
        for i in range(3)
    ]

    async def _scenario() -> list[CANFrame]:
        suite, gw_id, peer_id = _make_identities("classical")
        gw_link, peer_link = LoopbackLink.make_pair()
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()

        with CanAdapter(can_channel) as can_gw:
            gateway = Gateway(suite, gw_id, can_gw, gw_link)
            peer = ModernPeer(suite, peer_id, peer_link, sink)

            await asyncio.wait_for(
                asyncio.gather(
                    gateway.run(n_frames=3),
                    peer.run(n_frames=3),
                    _inject(can_channel, buffered_frames),  # injected during handshake
                ),
                timeout=15.0,
            )

        return [sink.get_nowait() for _ in range(sink.qsize())]

    received = asyncio.run(_scenario())
    assert len(received) == 3
    for i, f in enumerate(received):
        assert f.data == buffered_frames[i].data
