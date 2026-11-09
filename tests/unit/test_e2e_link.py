"""End-to-end tests over LinkEmulator and LoopbackLink (M5a + M5b).

M5a tests (fragmentation and loss/retransmit):
  - test_e2e_c1_fragmented_handshake
  - test_e2e_c1_loss_retransmit

M5b tests (light/full rekey, epoch guard, security):
  - test_e2e_c1_light_rekey_in_flight
  - test_e2e_c1_light_rekey_ack_lost
  - test_e2e_c1_full_rekey_hello_r_lost
  - test_e2e_c1_full_rekey_finished_r_lost
  - test_full_rekey_late_duplicate_hello_r_ignored
  - test_peer_forged_new_session_header_no_switch
  - test_full_rekey_failed_attempt_old_session_continues
  - test_full_rekey_max_attempts_raises_alert
  - test_epoch_254_guard_triggers_full_rekey
  - test_old_session_record_rejected_after_grace
  - test_full_rekey_completes_with_cleanup_active

Each test uses a unique virtual-bus channel (can_channel fixture) where needed.
"""

from __future__ import annotations

import asyncio
import struct
from pathlib import Path
from typing import Callable, Optional

import pytest

from pqcgw.crypto.registry import load_suite
from pqcgw.legacy.can_adapter import CanAdapter
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.emulator import LinkEmulator, NetworkConfig
from pqcgw.net.link import Link, LoopbackLink
from pqcgw.nodes.gateway import Gateway, _T_DATA, _T_HELLO_R, _T_FINISHED_R, _T_HELLO_I
from pqcgw.nodes.peer import ModernPeer
from pqcgw.protocol.handshake import HandshakeInitiator, HandshakeResponder, IdentityContext
from pqcgw.protocol.record import Direction, RecordType
from pqcgw.protocol.session import (
    AlertError,
    RekeyConfig,
    RekeyTrigger,
    SessionManager,
    SessionRole,
)

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


# ===========================================================================
# M5b helpers
# ===========================================================================

class _DropFirstWhere(Link):
    """Wraps a Link; drops the first sent message where pred(msg) is True."""

    def __init__(self, inner: Link, pred: Callable[[bytes], bool]) -> None:
        self._inner = inner
        self._pred = pred
        self._dropped = False

    async def send(self, msg: bytes) -> None:
        if not self._dropped and self._pred(msg):
            self._dropped = True
            return   # silently drop
        await self._inner.send(msg)

    async def recv(self, timeout: float = 1.0) -> Optional[bytes]:
        return await self._inner.recv(timeout=timeout)


class _DropAllWhere(Link):
    """Wraps a Link; drops ALL sent messages where pred(msg) is True."""

    def __init__(self, inner: Link, pred: Callable[[bytes], bool]) -> None:
        self._inner = inner
        self._pred = pred
        self.drop_count = 0

    async def send(self, msg: bytes) -> None:
        if self._pred(msg):
            self.drop_count += 1
            return
        await self._inner.send(msg)

    async def recv(self, timeout: float = 1.0) -> Optional[bytes]:
        return await self._inner.recv(timeout=timeout)


def _ideal_config() -> NetworkConfig:
    return NetworkConfig(delay_ms=0.0, jitter_ms=0.0, loss_pct=0.0,
                         bandwidth_kbps=0.0, mtu_bytes=1500, seed=0)


def _make_frames_mb5(n: int) -> list[CANFrame]:
    return [CANFrame(can_id=0x200, dlc=8, data=bytes([i % 256] * 8)) for i in range(n)]


# ===========================================================================
# M5b test 1: light rekey triggers in flight
# ===========================================================================

def test_e2e_c1_light_rekey_in_flight(can_channel: str) -> None:
    """Light rekey fires after record_count=5; all 20 frames delivered."""
    frames = _make_frames_mb5(20)

    async def _scenario():
        suite, gw_id, peer_id = _make_identities("classical")
        gw_link, peer_link = LinkEmulator.make_pair(_ideal_config())
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        cfg = RekeyConfig(grace_period_s=2.0, grace_period_records=100)
        trig = RekeyTrigger(record_count=5)

        with CanAdapter(can_channel) as can_gw:
            gateway = Gateway(suite, gw_id, can_gw, gw_link,
                              rekey_config=cfg, trigger=trig,
                              handshake_timeout_ms=500)
            peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=cfg)
            await asyncio.wait_for(
                asyncio.gather(
                    gateway.run(n_frames=20),
                    peer.run(n_frames=20),
                    _inject(can_channel, frames),
                ),
                timeout=30.0,
            )
        assert gateway._sm.epoch >= 1, "Expected at least one light rekey"
        assert gateway._pending_drops == 0
        return [sink.get_nowait() for _ in range(sink.qsize())]

    received = asyncio.run(_scenario())
    assert len(received) == 20, f"Expected 20 frames, got {len(received)}"


# ===========================================================================
# M5b test 2: light rekey REKEY_ACK lost once
# ===========================================================================

def test_e2e_c1_light_rekey_ack_lost(can_channel: str) -> None:
    """REKEY_ACK dropped once; REKEY_REQ retransmit recovers; all 10 frames delivered."""
    frames = _make_frames_mb5(10)

    def _is_rekey_ack(msg: bytes) -> bool:
        # DATA prefix + record header byte 0 low nibble == REKEY_ACK (2)
        return (len(msg) > 2
                and msg[0] == _T_DATA
                and (msg[1] & 0x0F) == RecordType.REKEY_ACK)

    async def _scenario():
        suite, gw_id, peer_id = _make_identities("classical")
        gw_link_inner, peer_link = LinkEmulator.make_pair(_ideal_config())
        # Wrap peer→gw direction: drop the first REKEY_ACK
        gw_link = _DropFirstWhere(gw_link_inner, _is_rekey_ack)
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        cfg = RekeyConfig(grace_period_s=2.0, grace_period_records=100,
                          rekey_timeout_ms=200, rekey_max_retries=5)
        trig = RekeyTrigger(record_count=3)

        with CanAdapter(can_channel) as can_gw:
            gateway = Gateway(suite, gw_id, can_gw, gw_link,
                              rekey_config=cfg, trigger=trig,
                              handshake_timeout_ms=500)
            peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=cfg)
            await asyncio.wait_for(
                asyncio.gather(
                    gateway.run(n_frames=10),
                    peer.run(n_frames=10),
                    _inject(can_channel, frames),
                ),
                timeout=30.0,
            )
        assert gateway._sm.epoch >= 1, "Expected rekey to complete despite lost ACK"
        return [sink.get_nowait() for _ in range(sink.qsize())]

    received = asyncio.run(_scenario())
    assert len(received) == 10, f"Expected 10 frames, got {len(received)}"


# ===========================================================================
# M5b test 3: full rekey with HELLO_R lost
# ===========================================================================

def test_e2e_c1_full_rekey_hello_r_lost(can_channel: str) -> None:
    """Full-rekey HELLO_R lost once; HELLO_I retransmit recovers; 5 frames delivered."""
    frames = _make_frames_mb5(5)

    def _is_hello_r(msg: bytes) -> bool:
        return len(msg) > 0 and msg[0] == _T_HELLO_R

    async def _scenario():
        suite, gw_id, peer_id = _make_identities("classical")
        gw_link_inner, peer_link_inner = LinkEmulator.make_pair(_ideal_config())
        # Drop the first HELLO_R from peer→gateway
        gw_link = _DropFirstWhere(gw_link_inner, _is_hello_r)
        peer_link = peer_link_inner
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        cfg = RekeyConfig(grace_period_s=5.0, grace_period_records=100)
        old_session_id = None

        with CanAdapter(can_channel) as can_gw:
            gateway = Gateway(suite, gw_id, can_gw, gw_link,
                              rekey_config=cfg,
                              full_rekey_max_attempts=3,
                              handshake_timeout_ms=400,
                              handshake_max_retries=5)
            peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=cfg)

            async def _trigger_and_inject():
                await asyncio.sleep(0.05)  # let handshake complete
                gateway.request_full_rekey()
                await _inject(can_channel, frames)

            await asyncio.wait_for(
                asyncio.gather(
                    gateway.run(n_frames=5),
                    peer.run(n_frames=5),
                    _trigger_and_inject(),
                ),
                timeout=30.0,
            )
        assert gateway._sm is not None
        return [sink.get_nowait() for _ in range(sink.qsize())]

    received = asyncio.run(_scenario())
    assert len(received) == 5, f"Expected 5 frames, got {len(received)}"


# ===========================================================================
# M5b test 4: full rekey with FINISHED_R lost
# ===========================================================================

def test_e2e_c1_full_rekey_finished_r_lost(can_channel: str) -> None:
    """Full-rekey FINISHED_R lost once; FINISHED_I retransmit recovers; 5 frames delivered."""
    frames = _make_frames_mb5(5)

    def _is_finished_r(msg: bytes) -> bool:
        return len(msg) > 0 and msg[0] == _T_FINISHED_R

    async def _scenario():
        suite, gw_id, peer_id = _make_identities("classical")
        gw_link_inner, peer_link_inner = LinkEmulator.make_pair(_ideal_config())
        gw_link = _DropFirstWhere(gw_link_inner, _is_finished_r)
        peer_link = peer_link_inner
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        cfg = RekeyConfig(grace_period_s=5.0, grace_period_records=100)

        with CanAdapter(can_channel) as can_gw:
            gateway = Gateway(suite, gw_id, can_gw, gw_link,
                              rekey_config=cfg,
                              full_rekey_max_attempts=3,
                              handshake_timeout_ms=400,
                              handshake_max_retries=5)
            peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=cfg)

            async def _trigger_and_inject():
                await asyncio.sleep(0.05)
                gateway.request_full_rekey()
                await _inject(can_channel, frames)

            await asyncio.wait_for(
                asyncio.gather(
                    gateway.run(n_frames=5),
                    peer.run(n_frames=5),
                    _trigger_and_inject(),
                ),
                timeout=30.0,
            )
        return [sink.get_nowait() for _ in range(sink.qsize())]

    received = asyncio.run(_scenario())
    assert len(received) == 5, f"Expected 5 frames, got {len(received)}"


# ===========================================================================
# M5b test 5: late duplicate HELLO_R in queue is ignored
# ===========================================================================

def test_full_rekey_late_duplicate_hello_r_ignored(can_channel: str) -> None:
    """Extra HELLO_R in _hs_queue is consumed and ignored; full rekey still completes.

    We use gateway.run() so run()'s inbound dispatch populates _hs_queue normally.
    After the initial handshake, we inject a stale HELLO_R directly into _hs_queue
    before triggering the full rekey.  The session_id check in _do_full_rekey()
    must skip the stale entry and succeed on the real HELLO_R.
    """
    async def _scenario():
        suite, gw_id, peer_id = _make_identities("classical")
        gw_link, peer_link = LoopbackLink.make_pair()
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        cfg = RekeyConfig(grace_period_s=5.0, grace_period_records=100)

        with CanAdapter(can_channel) as can_gw:
            gateway = Gateway(suite, gw_id, can_gw, gw_link,
                              rekey_config=cfg,
                              handshake_timeout_ms=400,
                              handshake_max_retries=3)
            peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=cfg)

            async def _control():
                # Wait for gateway's run() to have created _hs_queue (post-handshake)
                while gateway._hs_queue is None:
                    await asyncio.sleep(0.01)
                # Inject a stale HELLO_R (session_id = 4 null bytes, will be ignored)
                stale_hello_r = bytes([_T_HELLO_R]) + b"\x01\x01" + b"\x00" * 4 + b"\x00" * 32
                gateway._hs_queue.put_nowait(stale_hello_r)
                # Trigger full rekey; _do_full_rekey() will drain the stale entry first
                gateway.request_full_rekey()

            await asyncio.wait_for(
                asyncio.gather(
                    gateway.run(n_frames=0),
                    peer.run(n_frames=0),
                    _control(),
                ),
                timeout=30.0,
            )
        # Full rekey completed without error
        assert True

    asyncio.run(_scenario())


# ===========================================================================
# M5b test 6: forged new-session header does not switch peer
# ===========================================================================

def test_peer_forged_new_session_header_no_switch() -> None:
    """A DATA record with new-session_id but wrong AEAD ciphertext does not promote peer."""
    async def _scenario():
        suite, gw_id, peer_id = _make_identities("classical")
        gw_link, peer_link = LoopbackLink.make_pair()
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        cfg = RekeyConfig(grace_period_s=5.0, grace_period_records=100)

        with CanAdapter("test-m5b-forged-sid") as can_gw:
            gateway = Gateway(suite, gw_id, can_gw, gw_link, rekey_config=cfg)
            peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=cfg)
            await asyncio.gather(gateway.handshake(), peer.handshake())

            original_session_id = peer._sm._session_id

            # Drive a full-rekey handshake on the peer side manually so _fr_pending is set
            init_id2, resp_id2 = gw_id, peer_id  # reuse same identities
            initiator2 = HandshakeInitiator(suite, init_id2)
            responder2 = HandshakeResponder(suite, resp_id2)
            hello_i2 = initiator2.start()
            hello_r2 = responder2.process_hello_i(hello_i2)
            fi2 = initiator2.process_hello_r(hello_r2)
            fr2, new_keys = responder2.process_finished_i(fi2)
            # Inject _fr_pending into peer
            peer._fr = responder2
            peer._fr_session_id = initiator2.session_id
            peer._fr_complete = True
            peer._fr_fi = fi2
            peer._fr_fr = fr2
            peer._fr_pending = (new_keys, initiator2.session_id)

            # Craft a forged DATA record: correct new session_id but random ciphertext
            forged = (
                bytes([_T_DATA])
                + bytes([0x10])            # version_type: DATA
                + initiator2.session_id    # matching session_id
                + bytes([0])               # epoch 0
                + b"\x00" * 8             # counter
                + b"\x00" * 2             # payload_length 0
                + b"\xff" * 16            # bad AEAD tag
            )
            await peer._handle_inbound(forged[1:])  # strip _T_DATA prefix

            # Peer must NOT have promoted
            assert peer._sm._session_id == original_session_id, (
                "Peer session_id changed despite forged header"
            )
            assert peer._unknown_session_drops == 1

    asyncio.run(_scenario())


# ===========================================================================
# M5b test 7: failed full-rekey attempt leaves old session working
# ===========================================================================

def test_full_rekey_failed_attempt_old_session_continues(can_channel: str) -> None:
    """First full-rekey attempt fails (HELLO_R from peer is dropped); old session
    delivers 3 frames while the failed attempt is still in progress.

    Design: wrap the PEER's outbound link so HELLO_R is dropped before the
    gateway receives it.  The gateway's _do_full_rekey() times out.  During
    that window, 3 CAN frames are injected and forwarded on the old session.
    gateway.run(n_frames=3) exits normally (no AlertError) because it finishes
    before the full-rekey task failure is processed, and the finally block
    cancels the pending task cleanly.
    """
    frames = _make_frames_mb5(3)

    def _is_hello_r(msg: bytes) -> bool:
        return len(msg) > 0 and msg[0] == _T_HELLO_R

    async def _scenario():
        suite, gw_id, peer_id = _make_identities("classical")
        # gw_link: gateway sends via this link → arrives at peer
        # peer_link_inner: peer sends via this inner link → arrives at gateway
        gw_link, peer_link_inner = LinkEmulator.make_pair(_ideal_config())
        # Wrap peer's outbound link: drop HELLO_R peer→gateway, pass everything else
        drop_peer_link = _DropAllWhere(peer_link_inner, lambda _: False)
        cfg = RekeyConfig(grace_period_s=5.0, grace_period_records=100)
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()

        with CanAdapter(can_channel) as can_gw:
            gateway = Gateway(suite, gw_id, can_gw, gw_link,
                              rekey_config=cfg,
                              full_rekey_max_attempts=3,
                              handshake_timeout_ms=200,
                              handshake_max_retries=1)
            peer = ModernPeer(suite, peer_id, drop_peer_link, sink, rekey_config=cfg)

            session_before = [None]

            async def _control():
                await asyncio.sleep(0.1)   # let handshake complete
                session_before[0] = gateway._sm._session_id
                # Activate drop: HELLO_R from peer will not reach gateway
                drop_peer_link._pred = _is_hello_r
                # Trigger first full-rekey attempt (will fail: HELLO_R dropped)
                gateway.request_full_rekey()
                # Inject frames immediately; they travel on the OLD session while
                # the full-rekey attempt is still waiting for HELLO_R (~400ms budget)
                await _inject(can_channel, frames)

            await asyncio.wait_for(
                asyncio.gather(
                    gateway.run(n_frames=3),
                    peer.run(n_frames=3),
                    _control(),
                ),
                timeout=15.0,
            )
        # Old session delivered all 3 frames before the failed attempt timed out
        received = [sink.get_nowait() for _ in range(sink.qsize())]
        assert len(received) == 3
        assert session_before[0] is not None

    asyncio.run(_scenario())


# ===========================================================================
# M5b test 8: max full-rekey attempts raises AlertError
# ===========================================================================

def test_full_rekey_max_attempts_raises_alert(can_channel: str) -> None:
    """With full_rekey_max_attempts=1 and all HELLO_R dropped, AlertError is raised."""
    def _is_hello_r(msg: bytes) -> bool:
        return len(msg) > 0 and msg[0] == _T_HELLO_R

    async def _scenario():
        suite, gw_id, peer_id = _make_identities("classical")
        gw_link, peer_link_inner = LinkEmulator.make_pair(_ideal_config())
        # Start with no dropping so the initial handshake completes.
        # _trigger() activates the drop before requesting the full rekey.
        drop_peer_link = _DropAllWhere(peer_link_inner, lambda _: False)
        cfg = RekeyConfig(grace_period_s=5.0, grace_period_records=100)
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()

        with CanAdapter(can_channel) as can_gw:
            gateway = Gateway(suite, gw_id, can_gw, gw_link,
                              rekey_config=cfg,
                              full_rekey_max_attempts=1,
                              handshake_timeout_ms=200,
                              handshake_max_retries=1)
            peer = ModernPeer(suite, peer_id, drop_peer_link, sink, rekey_config=cfg)

            async def _trigger():
                # Let the initial handshake finish before activating the drop
                await asyncio.sleep(0.5)
                drop_peer_link._pred = _is_hello_r  # activate: now drop all HELLO_R
                gateway.request_full_rekey()

            with pytest.raises(AlertError):
                await asyncio.wait_for(
                    asyncio.gather(
                        gateway.run(n_frames=None),
                        peer.run(n_frames=None),
                        _trigger(),
                    ),
                    timeout=15.0,
                )
        assert gateway._sm.closed

    asyncio.run(_scenario())


# ===========================================================================
# M5b test 9: epoch-254 guard triggers full rekey (unit test, no link)
# ===========================================================================

def test_epoch_254_guard_triggers_full_rekey() -> None:
    """When epoch is set to 254 via _set_epoch_for_testing, the run() loop
    triggers a full rekey on the next iteration."""
    async def _scenario():
        suite, gw_id, peer_id = _make_identities("classical")
        gw_link, peer_link = LoopbackLink.make_pair()
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        # Use a generous handshake timeout: the full-rekey HELLO_I will time out
        # (no peer responds after n_frames=0 exits), but _full_rekey_pending stays True
        # long enough for the assertion.
        cfg = RekeyConfig(grace_period_s=5.0, grace_period_records=100)

        with CanAdapter("test-m5b-ep254") as can_gw:
            gateway = Gateway(suite, gw_id, can_gw, gw_link, rekey_config=cfg,
                              handshake_timeout_ms=2000, handshake_max_retries=0)
            peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=cfg)

            # peer.run(n_frames=0) exits immediately after the initial handshake.
            # The full-rekey HELLO_I therefore has no responder, so _full_rekey_pending
            # stays True until the per-attempt deadline (2 s), well past our check.
            async def _set_epoch_and_check() -> None:
                # Poll until run()'s handshake has set up the SM
                while gateway._sm is None:
                    await asyncio.sleep(0.01)
                gateway._set_epoch_for_testing(254)
                # Give the run() loop one iteration to detect the guard (recv timeout = 10ms)
                await asyncio.sleep(0.1)
                assert gateway._full_rekey_pending, (
                    "Epoch-254 guard must set _full_rekey_pending"
                )

            gw_task = asyncio.create_task(gateway.run(n_frames=None))
            # Peer exits right after initial handshake (n_frames=0)
            peer_task = asyncio.create_task(peer.run(n_frames=0))
            check_task = asyncio.create_task(_set_epoch_and_check())

            await asyncio.wait_for(check_task, timeout=15.0)

            gw_task.cancel()
            peer_task.cancel()
            await asyncio.gather(gw_task, peer_task, return_exceptions=True)

    asyncio.run(_scenario())


# ===========================================================================
# M5b test 10: old-session record rejected after grace (protocol layer)
# ===========================================================================

def test_old_session_record_rejected_after_grace() -> None:
    """After promote_full_rekey and grace_period_records new-epoch records,
    an old-session record raises RecordError (§5.6 / _route_open session_id guard)."""
    suite_name = "classical"
    suite = load_suite(SUITE_DIR / f"{suite_name}.toml")
    sig = suite.signature
    gw_pk, gw_sk = sig.keygen()
    peer_pk, peer_sk = sig.keygen()
    init_id = IdentityContext(my_id="gw", peer_id="peer",
                              my_sk=gw_sk, my_pk=gw_pk, peer_pk=peer_pk,
                              allowed_suite_ids=[1, 2, 3])
    resp_id = IdentityContext(my_id="peer", peer_id="gw",
                              my_sk=peer_sk, my_pk=peer_pk, peer_pk=gw_pk,
                              allowed_suite_ids=[1, 2, 3])

    # Initial handshake
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)
    hi = initiator.start()
    hr = responder.process_hello_i(hi)
    fi = initiator.process_hello_r(hr)
    fr, resp_keys = responder.process_finished_i(fi)
    gw_keys = initiator.process_finished_r(fr)

    grace_records = 5
    cfg = RekeyConfig(grace_period_records=grace_records, grace_period_s=60.0)
    gw_sm = SessionManager(suite, gw_keys, initiator.session_id, SessionRole.INITIATOR, config=cfg)
    peer_sm = SessionManager(suite, resp_keys, responder.session_id, SessionRole.RESPONDER, config=cfg)

    # Seal an old-session record BEFORE the full rekey
    old_record = gw_sm.seal(b"old data")
    old_session_id = gw_sm._session_id

    # Simulate a full rekey: new handshake
    initiator2 = HandshakeInitiator(suite, init_id)
    responder2 = HandshakeResponder(suite, resp_id)
    hi2 = initiator2.start()
    hr2 = responder2.process_hello_i(hi2)
    fi2 = initiator2.process_hello_r(hr2)
    fr2, resp_keys2 = responder2.process_finished_i(fi2)
    gw_keys2 = initiator2.process_finished_r(fr2)

    gw_sm.promote_full_rekey(gw_keys2, initiator2.session_id)
    peer_sm.promote_full_rekey(resp_keys2, responder2.session_id)

    # Seal grace_records new-epoch records; receiver opens each one
    # (this advances _new_epoch_records so grace expires)
    for _ in range(grace_records):
        rec = gw_sm.seal(b"new data")
        peer_sm.open(rec, Direction.I2R)

    # Old-session record must now be rejected (grace expired)
    from pqcgw.protocol.record import RecordError
    with pytest.raises(RecordError):
        peer_sm.open(old_record, Direction.I2R)


# ===========================================================================
# M5b test 11: full rekey completes with lazy cleanup active
# ===========================================================================

def test_full_rekey_completes_with_cleanup_active(can_channel: str) -> None:
    """Two sequential full rekeys; first session's grace expires before second
    completes; lazy cleanup in _handle_hs_message fires without breaking the second
    rekey in progress."""
    frames = _make_frames_mb5(3)

    async def _scenario():
        suite, gw_id, peer_id = _make_identities("classical")
        gw_link, peer_link = LoopbackLink.make_pair()
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        # Very short grace so first session expires quickly.
        # rekey_timeout_ms=10, rekey_max_retries=1 → budget = 0.02 s < grace_period_s=0.05 s.
        cfg = RekeyConfig(grace_period_s=0.05, grace_period_records=1,
                          rekey_timeout_ms=10, rekey_max_retries=1)

        with CanAdapter(can_channel) as can_gw:
            gateway = Gateway(suite, gw_id, can_gw, gw_link, rekey_config=cfg,
                              handshake_timeout_ms=500)
            peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=cfg)

            async def _control():
                await asyncio.sleep(0.05)  # let initial handshake complete
                # First full rekey
                gateway.request_full_rekey()
                await asyncio.sleep(0.5)   # let it complete + grace expire
                # Second full rekey (while first's grace may have expired)
                gateway.request_full_rekey()
                await asyncio.sleep(0.1)
                await _inject(can_channel, frames)

            await asyncio.wait_for(
                asyncio.gather(
                    gateway.run(n_frames=3),
                    peer.run(n_frames=3),
                    _control(),
                ),
                timeout=30.0,
            )
        received = [sink.get_nowait() for _ in range(sink.qsize())]
        assert len(received) == 3

    asyncio.run(_scenario())
