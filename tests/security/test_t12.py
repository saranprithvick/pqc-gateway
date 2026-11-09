"""T12: Forged CAN frame is forwarded by the gateway.

KNOWN LIMITATION (§1 item 1 / CLAUDE.md):
  The legacy CAN side is UNAUTHENTICATED.  The Gateway protects only the
  gateway↔peer link.  A forged frame injected onto the CAN bus is forwarded
  (sealed and transmitted) exactly as if it came from a legitimate ECU.

This test ASSERTS that the forged frame DOES arrive at the peer — the lack of
CAN-side authentication is a documented design constraint, not a bug.

The Attacker class is FOR TESTS ONLY and must never appear in the
production gateway path.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pqcgw.attacks.attacker import Attacker
from pqcgw.crypto.registry import load_suite
from pqcgw.legacy.can_adapter import CanAdapter
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.link import LoopbackLink
from pqcgw.nodes.gateway import Gateway
from pqcgw.nodes.peer import ModernPeer
from pqcgw.protocol.handshake import IdentityContext

SUITE_DIR = Path(__file__).parent.parent.parent / "configs" / "suites"


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


def test_t12_forged_can_frame_forwarded(can_channel: str) -> None:
    """T12: A forged CAN frame injected by the Attacker reaches the peer.

    KNOWN LIMITATION: the gateway does NOT authenticate CAN frames.
    This test asserts the expected (non-preventive) behaviour.

    Security implication:
      An adversary with physical access to the legacy CAN bus can inject
      arbitrary frames that the gateway will forward under the PQC-protected
      session.  Mitigation (CAN-layer MAC or CAN XL) is out of scope for
      this prototype; see docs/LIMITATIONS.md item 1 and docs/THREAT_MODEL.md.
    """
    forged_frame = CANFrame(
        can_id=0xDEAD,
        dlc=4,
        data=b"\xDE\xAD\xBE\xEF",
        is_extended=True,  # 29-bit ID to reach 0xDEAD
    )

    async def _scenario() -> CANFrame:
        suite, gw_id, peer_id = _make_identities("classical")
        gw_link, peer_link = LoopbackLink.make_pair()
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()

        # Gateway + peer on the loopback link
        # Attacker injects forged frame using a SEPARATE bus on the same channel
        with CanAdapter(can_channel) as can_gw, \
             Attacker(channel=can_channel) as attacker:

            async def _inject_forged() -> None:
                attacker.inject_can_frame(forged_frame)

            gateway = Gateway(suite, gw_id, can_gw, gw_link)
            peer = ModernPeer(suite, peer_id, peer_link, sink)

            # Gateway runs for 1 frame; attacker injects the forged frame;
            # peer should receive it.
            gw_task = asyncio.create_task(gateway.run(n_frames=None))
            peer_task = asyncio.create_task(peer.run(n_frames=1))
            inject_task = asyncio.create_task(_inject_forged())

            try:
                await asyncio.wait_for(
                    asyncio.gather(peer_task, inject_task),
                    timeout=10.0,
                )
            finally:
                gw_task.cancel()
                await asyncio.gather(gw_task, return_exceptions=True)

        # KNOWN LIMITATION ASSERTION:
        # The forged frame MUST have arrived at the peer.
        assert sink.qsize() == 1, "Expected 1 forwarded frame (the forged one)"
        received = sink.get_nowait()
        assert received.can_id == forged_frame.can_id, (
            "KNOWN LIMITATION: Gateway forwarded a forged CAN frame unchanged.  "
            "CAN-side authentication is out of scope (see docs/LIMITATIONS.md §1)."
        )
        assert received.data == forged_frame.data
        return received

    asyncio.run(_scenario())
