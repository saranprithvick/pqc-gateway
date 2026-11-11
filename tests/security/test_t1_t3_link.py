"""T1–T3 E2E security tests via LinkAttacker, parametrized over C0–C3.

Each test runs a full Gateway ↔ Peer (or PassthroughPath for C0) over a
LinkAttacker-intercepted LoopbackLink.  Attack messages must:
  - Reach the peer (proving the attack was delivered to the right endpoint).
  - Be accepted on C0 (no security: vulnerability confirmed).
  - Be rejected on C1/C2/C3 (security: auth-failure counter incremented by 1).

T1 — Replay: captured record re-delivered.
       C0: second frame arrives (accepted); 2 frames at peer.
       C1–C3: replay silently dropped; peer._sm.consecutive_auth_failures == 1.

T2 — Tamper: byte-flip on a data record in transit.
       C0: tampered payload arrives undetected.
       C1–C3: AEAD failure; peer drops it; consecutive_auth_failures == 1.

T3 — Inject: attacker inserts a crafted minimal-framing (C0) or prefixed (C1–C3)
       payload directly into the link.
       C0: injected well-formed frame arrives.
       C1–C3: AEAD failure; peer drops it; consecutive_auth_failures == 1.

The existing unit-level T1–T3 tests (test_t1_t2_t3_t7_t9_t11.py) are unchanged.
"""

from __future__ import annotations

import asyncio
import os
import struct
from typing import Callable, Optional

import pytest

from pqcgw.attacks.link_attacker import LinkAttacker
from pqcgw.crypto.registry import load_suite
from pqcgw.legacy.can_adapter import CanAdapter
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.link import LoopbackLink
from pqcgw.nodes.gateway import Gateway
from pqcgw.nodes.passthrough import PassthroughPath
from pqcgw.nodes.peer import ModernPeer
from pqcgw.protocol.handshake import IdentityContext
from pqcgw.protocol.record import Direction

from tests.suite_helpers import ALL_SUITE_IDS, suite_path

_SUITE_FOR_CONFIG = {"c1": "classical", "c2": "pqc", "c3": "hybrid"}
_CONFIGS = ["c0", "c1", "c2", "c3"]
_FRAME = CANFrame(can_id=0x100, dlc=8, data=b"\x01" * 8)


# ---------------------------------------------------------------------------
# C0 passthrough helper
# ---------------------------------------------------------------------------

async def _c0_scenario(
    channel: str,
    gw_frames: int,
    peer_frames: int,
    setup_attack: Callable[[LinkAttacker], None] | None = None,
    inject_before_start: bool = False,
) -> list[CANFrame]:
    """Run PassthroughPath with a LinkAttacker.

    1. Inject gw_frames onto the CAN bus.
    2. Gateway forwards them through the attacker-intercepted link.
    3. If setup_attack is provided, call it after the first frame propagates.
    4. Peer collects peer_frames frames.
    Returns all frames from the peer sink.
    """
    gw_inner, peer_inner = LoopbackLink.make_pair()
    attacker, gw_link, peer_link = LinkAttacker.wrap(gw_inner, peer_inner)
    sink: asyncio.Queue[CANFrame] = asyncio.Queue()
    path = PassthroughPath()

    with CanAdapter(channel) as can_gw, CanAdapter(channel) as sender:
        await attacker.start()
        try:
            gw_task = asyncio.create_task(
                path.run_gateway_side(can_gw, gw_link, gw_frames)
            )
            peer_task = asyncio.create_task(
                path.run_peer_side(peer_link, sink, peer_frames)
            )

            async def _inject_and_attack():
                for _ in range(gw_frames):
                    sender.send(_FRAME)
                if setup_attack is not None:
                    await asyncio.sleep(0.1)  # let frame propagate through attacker
                    await setup_attack(attacker)

            await asyncio.wait_for(
                asyncio.gather(peer_task, _inject_and_attack()),
                timeout=8.0,
            )
        finally:
            gw_task.cancel()
            await asyncio.gather(gw_task, return_exceptions=True)
            await attacker.stop()

    received: list[CANFrame] = []
    while not sink.empty():
        received.append(sink.get_nowait())
    return received


# ---------------------------------------------------------------------------
# Crypto (C1–C3) helper
# ---------------------------------------------------------------------------

async def _crypto_scenario(
    suite_name: str,
    channel: str,
    setup_attack: Callable[[LinkAttacker], None],
    n_legit: int,
) -> tuple[list[CANFrame], ModernPeer]:
    """Run Gateway+Peer over LinkAttacker; inject attack after legitimate frames.

    Peer runs indefinitely so it is still alive to process (and reject) the
    attack message; both tasks are cancelled after setup_attack returns.

    Returns (received_frames, peer_instance).
    """
    suite = load_suite(suite_path(suite_name))
    sig = suite.signature
    gw_pk, gw_sk = sig.keygen()
    peer_pk, peer_sk = sig.keygen()
    gw_id = IdentityContext(
        my_id="gw", peer_id="peer",
        my_sk=gw_sk, my_pk=gw_pk, peer_pk=peer_pk,
        allowed_suite_ids=ALL_SUITE_IDS,
    )
    peer_id_ctx = IdentityContext(
        my_id="peer", peer_id="gw",
        my_sk=peer_sk, my_pk=peer_pk, peer_pk=gw_pk,
        allowed_suite_ids=ALL_SUITE_IDS,
    )
    gw_inner, peer_inner = LoopbackLink.make_pair()
    attacker, gw_link, peer_link = LinkAttacker.wrap(gw_inner, peer_inner)
    sink: asyncio.Queue[CANFrame] = asyncio.Queue()

    with CanAdapter(channel) as can_gw, CanAdapter(channel) as sender:
        gateway = Gateway(suite, gw_id, can_gw, gw_link)
        peer = ModernPeer(suite, peer_id_ctx, peer_link, sink)

        await attacker.start()
        gw_task = asyncio.create_task(gateway.run(n_frames=None))
        peer_task = asyncio.create_task(peer.run(n_frames=None))  # run until cancelled
        try:
            async def _inject_and_attack():
                await asyncio.sleep(0.1)  # handshake settle
                for _ in range(n_legit):
                    sender.send(_FRAME)
                await asyncio.sleep(0.3)  # let legit frames reach peer
                await setup_attack(attacker)
                await asyncio.sleep(0.15)  # give peer time to process attack

            await asyncio.wait_for(_inject_and_attack(), timeout=15.0)
        finally:
            peer_task.cancel()
            gw_task.cancel()
            await asyncio.gather(peer_task, gw_task, return_exceptions=True)
            await attacker.stop()

    received: list[CANFrame] = []
    while not sink.empty():
        received.append(sink.get_nowait())
    return received, peer


# ===========================================================================
# T1 — Replay
# ===========================================================================

@pytest.mark.parametrize("config", _CONFIGS)
def test_t1_link_replay(config: str, can_channel: str) -> None:
    """T1 (link level): replay a captured data record.

    C0 — accepted: peer receives 2 frames (original + replay).
    C1–C3 — rejected: peer receives 1 frame; auth-failure counter == 1.
    """
    if config == "c0":
        # Gateway sends 1 CAN frame; attacker captures and replays it; peer sees 2.
        async def _attack(attacker: LinkAttacker) -> None:
            captured = attacker.captured_i2r()
            assert captured, "No I2R messages captured before replay"
            await attacker.replay(Direction.I2R, captured[-1])

        received = asyncio.run(
            _c0_scenario(can_channel, gw_frames=1, peer_frames=2,
                         setup_attack=_attack)
        )
        assert len(received) == 2, (
            f"C0 T1: expected 2 frames (replay accepted), got {len(received)}"
        )
    else:
        async def _attack(attacker: LinkAttacker) -> None:
            captured = attacker.captured_i2r()
            # Find a DATA record (prefix byte 0x10 per §15 item 22)
            data_msgs = [m for m in captured if len(m) > 0 and m[0] == 0x10]
            assert data_msgs, "No DATA messages captured for replay"
            await attacker.replay(Direction.I2R, data_msgs[-1])

        received, peer = asyncio.run(
            _crypto_scenario(_SUITE_FOR_CONFIG[config], can_channel, _attack, n_legit=1)
        )
        assert len(received) == 1, (
            f"{config} T1: expected 1 legitimate frame, got {len(received)}"
        )
        assert peer._sm is not None
        assert peer._sm.consecutive_auth_failures == 1, (
            f"{config} T1: expected consecutive_auth_failures==1, "
            f"got {peer._sm.consecutive_auth_failures}"
        )


# ===========================================================================
# T2 — Tamper
# ===========================================================================

@pytest.mark.parametrize("config", _CONFIGS)
def test_t2_link_tamper(config: str, can_channel: str) -> None:
    """T2 (link level): byte-flip a data record in transit.

    C0 — accepted: tampered payload arrives at peer; first data byte is 0x01^0xFF.
    C1–C3 — rejected: AEAD failure; peer drops tampered record; auth_failures == 1.
    """
    if config == "c0":
        # Minimal framing: can_id(4B) | dlc(1B) | data
        # Flip the first payload byte at offset 5.
        def _tamper_fn(msg: bytes) -> bytes:
            if len(msg) > 5:
                buf = bytearray(msg)
                buf[5] ^= 0xFF
                return bytes(buf)
            return msg

        gw_inner, peer_inner = LoopbackLink.make_pair()
        attacker, gw_link, peer_link = LinkAttacker.wrap(gw_inner, peer_inner)
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        path = PassthroughPath()

        async def _run_tamper():
            with CanAdapter(can_channel) as can_gw, CanAdapter(can_channel) as sender:
                await attacker.start()
                try:
                    attacker.tamper_next(Direction.I2R, _tamper_fn)
                    sender.send(_FRAME)
                    gw_task = asyncio.create_task(
                        path.run_gateway_side(can_gw, gw_link, 1)
                    )
                    peer_task = asyncio.create_task(
                        path.run_peer_side(peer_link, sink, 1)
                    )
                    await asyncio.wait_for(
                        asyncio.gather(peer_task),
                        timeout=5.0,
                    )
                finally:
                    gw_task.cancel()
                    await asyncio.gather(gw_task, return_exceptions=True)
                    await attacker.stop()

        asyncio.run(_run_tamper())
        received = sink.get_nowait()
        # First data byte flipped: 0x01 → 0x01^0xFF = 0xFE
        assert received.data[0] == 0x01 ^ 0xFF, (
            f"C0 T2: expected tampered byte 0x{0x01^0xFF:02x}, "
            f"got 0x{received.data[0]:02x}"
        )
    else:
        def _tamper_fn(msg: bytes) -> bytes:
            # Flip a byte in the ciphertext portion (after type prefix + 16B header)
            if len(msg) > 20:
                buf = bytearray(msg)
                buf[20] ^= 0xFF
                return bytes(buf)
            return msg

        async def _attack(attacker: LinkAttacker) -> None:
            captured = attacker.captured_i2r()
            data_msgs = [m for m in captured if len(m) > 0 and m[0] == 0x10]
            assert data_msgs, "No DATA messages captured for tamper"
            tampered = _tamper_fn(data_msgs[-1])
            await attacker.inject(Direction.I2R, tampered)

        received, peer = asyncio.run(
            _crypto_scenario(_SUITE_FOR_CONFIG[config], can_channel, _attack, n_legit=1)
        )
        assert len(received) == 1, (
            f"{config} T2: expected 1 legitimate frame, got {len(received)}"
        )
        assert peer._sm is not None
        assert peer._sm.consecutive_auth_failures == 1, (
            f"{config} T2: expected consecutive_auth_failures==1, "
            f"got {peer._sm.consecutive_auth_failures}"
        )


# ===========================================================================
# T3 — Inject
# ===========================================================================

@pytest.mark.parametrize("config", _CONFIGS)
def test_t3_link_inject(config: str, can_channel: str) -> None:
    """T3 (link level): inject a crafted payload directly into the link.

    C0 — accepted: injected well-formed minimal-framing frame arrives at peer.
    C1–C3 — rejected: AEAD failure; peer drops it; auth_failures == 1.
    """
    # Craft a valid minimal-framing payload: can_id(4B big-endian) | dlc(1B) | data
    forged_can_id = 0x7FF
    forged_data = b"\xAB\xCD\xEF\x01\x02\x03\x04\x05"
    forged_frame_bytes = (
        struct.pack(">I", forged_can_id)
        + struct.pack("B", len(forged_data))
        + forged_data
    )

    if config == "c0":
        # Inject directly into the link (bypass gateway entirely).
        # PassthroughPath.run_peer_side() will decode the minimal framing.
        gw_inner, peer_inner = LoopbackLink.make_pair()
        attacker, gw_link, peer_link = LinkAttacker.wrap(gw_inner, peer_inner)
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        path = PassthroughPath()

        async def _run_inject():
            with CanAdapter(can_channel) as can_gw:
                await attacker.start()
                try:
                    peer_task = asyncio.create_task(
                        path.run_peer_side(peer_link, sink, 1)
                    )
                    # Inject directly (not via CAN/gateway)
                    await attacker.inject(Direction.I2R, forged_frame_bytes)
                    await asyncio.wait_for(peer_task, timeout=5.0)
                finally:
                    await attacker.stop()

        asyncio.run(_run_inject())
        received = sink.get_nowait()
        assert received.can_id == forged_can_id, (
            f"C0 T3: injected frame not delivered (can_id mismatch)"
        )
        assert received.data == forged_data
    else:
        # Inject a forged record with the correct session_id + epoch (copied from a
        # legitimate I2R message) but random ciphertext, so the AEAD check fails and
        # consecutive_auth_failures is incremented (not unknown_session_drops).
        # Record header layout (16 B): version/type(1) | session_id(4) | epoch(1) |
        #   counter(8) | payload_len(2). Body = header + ciphertext.
        # Wire message = 0x10 prefix + body.
        async def _attack(attacker: LinkAttacker) -> None:
            captured = attacker.captured_i2r()
            data_msgs = [m for m in captured if len(m) > 0 and m[0] == 0x10]
            assert data_msgs, "No DATA messages captured before inject"
            legit_body = data_msgs[-1][1:]  # strip 0x10 prefix → record body
            session_id = legit_body[1:5]    # bytes 1-4 of record header
            epoch = legit_body[5:6]         # byte 5 = epoch
            # Build forged body: correct session_id + epoch, everything else random
            forged_body = bytearray(os.urandom(32))  # header(16) + ciphertext(16)
            forged_body[1:5] = session_id
            forged_body[5:6] = epoch
            # Increment counter by a large amount to not collide with the replay window
            forged_body[6:14] = (0xFF_FF_FF_00).to_bytes(8, "big")
            await attacker.inject(Direction.I2R, bytes([0x10]) + bytes(forged_body))

        received, peer = asyncio.run(
            _crypto_scenario(_SUITE_FOR_CONFIG[config], can_channel, _attack, n_legit=1)
        )
        assert len(received) == 1, (
            f"{config} T3: expected 1 legitimate frame, got {len(received)}"
        )
        assert peer._sm is not None
        assert peer._sm.consecutive_auth_failures == 1, (
            f"{config} T3: expected consecutive_auth_failures==1, "
            f"got {peer._sm.consecutive_auth_failures}"
        )
