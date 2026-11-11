"""T12: Forged CAN frame is forwarded by the gateway — parametrized over C0–C3.

KNOWN LIMITATION (§1 item 1 / CLAUDE.md):
  The legacy CAN side is UNAUTHENTICATED.  The Gateway protects only the
  gateway↔peer link.  A forged frame injected onto the CAN bus is forwarded
  (sealed and transmitted) exactly as if it came from a legitimate ECU.

This test ASSERTS that the forged frame DOES arrive at the peer in every
configuration — the lack of CAN-side authentication is a documented design
constraint, not a bug.  Expected outcome per §9: "Forwarded" for C0–C3.

The Attacker class is FOR TESTS ONLY and must never appear in the
production gateway path.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pqcgw.attacks.attacker import Attacker
from pqcgw.legacy.can_adapter import CanAdapter
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.link import LoopbackLink
from pqcgw.nodes.passthrough import PassthroughPath
from pqcgw.nodes.gateway import Gateway
from pqcgw.nodes.peer import ModernPeer
from pqcgw.protocol.handshake import IdentityContext

from tests.suite_helpers import ALL_SUITE_IDS, suite_path
from pqcgw.crypto.registry import load_suite

_FORGED = CANFrame(can_id=0xDEAD, dlc=4, data=b"\xDE\xAD\xBE\xEF", is_extended=True)

# C0 uses PassthroughPath; C1/C2/C3 use Gateway+ModernPeer with the named suite.
_T12_CONFIGS = [
    pytest.param("c0", id="c0"),
    pytest.param("classical", id="c1"),
    pytest.param("pqc", id="c2"),
    pytest.param("hybrid", id="c3"),
]


async def _run_c0(channel: str) -> CANFrame:
    gw_link, peer_link = LoopbackLink.make_pair()
    sink: asyncio.Queue[CANFrame] = asyncio.Queue()

    with CanAdapter(channel) as can_gw, Attacker(channel=channel) as attacker:
        path = PassthroughPath()

        async def _inject():
            attacker.inject_can_frame(_FORGED)

        gw_task = asyncio.create_task(path.run_gateway_side(can_gw, gw_link, 1))
        peer_task = asyncio.create_task(path.run_peer_side(peer_link, sink, 1))
        inject_task = asyncio.create_task(_inject())

        await asyncio.wait_for(
            asyncio.gather(gw_task, peer_task, inject_task),
            timeout=10.0,
        )

    return sink.get_nowait()


async def _run_crypto(suite_name: str, channel: str) -> CANFrame:
    suite = load_suite(suite_path(suite_name))
    sig = suite.signature
    gw_pk, gw_sk = sig.keygen()
    peer_pk, peer_sk = sig.keygen()
    gw_id = IdentityContext(
        my_id="gw", peer_id="peer",
        my_sk=gw_sk, my_pk=gw_pk, peer_pk=peer_pk,
        allowed_suite_ids=ALL_SUITE_IDS,
    )
    peer_id = IdentityContext(
        my_id="peer", peer_id="gw",
        my_sk=peer_sk, my_pk=peer_pk, peer_pk=gw_pk,
        allowed_suite_ids=ALL_SUITE_IDS,
    )

    gw_link, peer_link = LoopbackLink.make_pair()
    sink: asyncio.Queue[CANFrame] = asyncio.Queue()

    with CanAdapter(channel) as can_gw, Attacker(channel=channel) as attacker:
        async def _inject():
            attacker.inject_can_frame(_FORGED)

        gateway = Gateway(suite, gw_id, can_gw, gw_link)
        peer = ModernPeer(suite, peer_id, peer_link, sink)

        gw_task = asyncio.create_task(gateway.run(n_frames=None))
        peer_task = asyncio.create_task(peer.run(n_frames=1))
        inject_task = asyncio.create_task(_inject())

        try:
            await asyncio.wait_for(
                asyncio.gather(peer_task, inject_task),
                timeout=15.0,
            )
        finally:
            gw_task.cancel()
            await asyncio.gather(gw_task, return_exceptions=True)

    return sink.get_nowait()


@pytest.mark.parametrize("config", _T12_CONFIGS)
def test_t12_forged_can_frame_forwarded(config: str, can_channel: str) -> None:
    """T12: A forged CAN frame injected onto the CAN bus reaches the peer.

    KNOWN LIMITATION: the gateway does NOT authenticate CAN frames.
    This test asserts the expected non-preventive behaviour across C0–C3.

    Security implication:
      An adversary with physical access to the legacy CAN bus can inject
      arbitrary frames that the gateway will forward.  CAN-layer MAC / CAN XL
      is out of scope; see docs/LIMITATIONS.md §1 and docs/THREAT_MODEL.md.
    """
    if config == "c0":
        received = asyncio.run(_run_c0(can_channel))
    else:
        received = asyncio.run(_run_crypto(config, can_channel))

    assert received.can_id == _FORGED.can_id, (
        f"KNOWN LIMITATION ({config}): Gateway forwarded a forged CAN frame unchanged.  "
        "CAN-side authentication is out of scope (see docs/LIMITATIONS.md §1)."
    )
    assert received.data == _FORGED.data
