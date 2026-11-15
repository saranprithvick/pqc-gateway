"""Regression tests for three gateway run-loop bugs fixed in the M7 fix pass.

Bug 1 — Notifier thread-safety (can_adapter.py):
    can.Notifier without loop= calls on_message_received from its background
    thread without call_soon_threadsafe.  AsyncBufferedReader.put_nowait is
    therefore called from outside the event loop — unsafe.  Fix: pass
    loop=asyncio.get_running_loop() to Notifier so the background thread uses
    call_soon_threadsafe.

Bug 2 — Pre-session CAN frames bypassed trigger checks (gateway.py):
    Frames that arrived during the handshake were flushed from _pre_session_buf
    in a bare for-loop before the event-queue while-loop started.  Trigger
    checks only lived inside the while-loop, so a large pre-session flush with
    record_count trigger could sail past the threshold without firing a rekey.
    Fix: pre-seed _evt_q with the buffered frames so the main loop handles them
    (with trigger checks between frames).

Bug 3 — Early exit while REKEY_ACK was still in _evt_q (gateway.py):
    The while condition was `while frames_sent < n_frames`, so when n_frames was
    reached immediately after a trigger fired, the loop exited before the
    REKEY_ACK could be dequeued and processed.  Epoch stayed at 0.
    Fix: continue while _has_pending_work() (REQ_SENT, full-rekey, _pending, or
    outbound-queue non-empty).
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import pytest

from pqcgw.legacy.can_adapter import CanAdapter
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.emulator import LinkEmulator, NetworkConfig
from pqcgw.nodes.gateway import Gateway
from pqcgw.nodes.peer import ModernPeer
from pqcgw.protocol.handshake import IdentityContext
from pqcgw.protocol.session import RekeyConfig, RekeyTrigger

_SUITE_DIR = Path(__file__).resolve().parents[2] / "configs" / "suites"


def _load_classical():
    from pqcgw.crypto.registry import load_suite
    return load_suite(_SUITE_DIR / "classical.toml")


def _make_identities(suite):
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
    return gw_id, peer_id


def _ideal_nc(seed: int = 1) -> NetworkConfig:
    return NetworkConfig(delay_ms=0, jitter_ms=0, loss_pct=0.0,
                         bandwidth_kbps=0, seed=seed)


def _channel() -> str:
    return f"reg_{os.getpid()}_{int(time.monotonic_ns() % 10_000_000)}"


# ---------------------------------------------------------------------------
# Bug 1 regression: Notifier thread-safety (loop= required)
# ---------------------------------------------------------------------------

def test_notifier_loop_delivers_frames() -> None:
    """recv_async() on a CanAdapter delivers frames sent by a sender bus.

    With the fix (loop=asyncio.get_running_loop() passed to Notifier), the
    background rx-thread uses call_soon_threadsafe so put_nowait runs in the
    event loop — thread-safe.  Without the fix, frames are silently dropped.
    """
    chan = _channel()

    async def _scenario() -> int:
        delivered = 0
        with CanAdapter(chan) as receiver:
            # Send 5 frames from a separate bus on the same channel
            with CanAdapter(chan) as sender:
                for i in range(5):
                    sender.send(CANFrame(can_id=0x100, dlc=1, data=bytes([i])))

            # Receive all 5 — recv_async must wake up for each one
            async def _receive_all(n: int) -> int:
                count = 0
                for _ in range(n):
                    try:
                        frame = await asyncio.wait_for(receiver.recv_async(), timeout=2.0)
                        if frame is not None:
                            count += 1
                    except asyncio.TimeoutError:
                        break
                return count

            delivered = await _receive_all(5)
        return delivered

    count = asyncio.run(_scenario())
    assert count == 5, (
        f"recv_async() delivered only {count}/5 frames — "
        "Notifier thread-safety fix (loop= parameter) may be missing"
    )


# ---------------------------------------------------------------------------
# Bug 2 regression: pre-session frames go through trigger checks
# ---------------------------------------------------------------------------

def test_presession_frames_trigger_rekey() -> None:
    """Frames buffered during the handshake trigger a rekey in the data phase.

    10 frames are injected immediately (before the handshake completes), so
    they land in _pre_session_buf.  With record_count=5 they should trigger at
    least one light rekey once the data loop starts.  Bug 2 (bare for-loop
    flush) would leave epoch=0 because trigger checks were skipped.
    """
    chan = _channel()
    suite = _load_classical()
    gw_id, peer_id = _make_identities(suite)
    frames = [CANFrame(can_id=0x200, dlc=8, data=bytes([i % 256] * 8))
              for i in range(10)]

    async def _scenario() -> int:
        gw_link, peer_link = LinkEmulator.make_pair(_ideal_nc())
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        cfg = RekeyConfig(grace_period_s=2.0, grace_period_records=100)
        trig = RekeyTrigger(record_count=5)

        async def _inject_early():
            # Send before yielding so frames arrive during handshake
            with CanAdapter(chan) as s:
                for f in frames:
                    s.send(f)

        with CanAdapter(chan) as can_gw:
            gw = Gateway(suite, gw_id, can_gw, gw_link,
                         rekey_config=cfg, trigger=trig,
                         handshake_timeout_ms=500)
            peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=cfg)
            await asyncio.wait_for(
                asyncio.gather(
                    gw.run(n_frames=10),
                    peer.run(n_frames=10),
                    _inject_early(),
                ),
                timeout=15.0,
            )
        return gw._sm.epoch if gw._sm else 0

    epoch = asyncio.run(_scenario())
    assert epoch >= 1, (
        f"epoch={epoch}; expected ≥ 1 light rekey from pre-session frames — "
        "bug 2 (pre-session flush bypassing trigger) may have regressed"
    )


# ---------------------------------------------------------------------------
# Bug 3 regression: loop waits for REKEY_ACK after n_frames reached
# ---------------------------------------------------------------------------

def test_loop_waits_for_rekey_ack_after_n_frames() -> None:
    """gateway.run(n_frames=N) does not exit before REKEY_ACK is processed.

    With trigger at record_count=5 and n_frames=5, the trigger fires when
    records_sealed reaches the threshold after all n_frames are forwarded.
    REKEY_ACK arrives after n_frames are sent.  Bug 3 would exit the while-
    loop before dequeuing the ACK, leaving epoch=0.  _has_pending_work() fixes
    this by keeping the loop alive until rekey_state leaves REQ_SENT.

    The peer runs indefinitely (n_frames=None) so it can respond to REKEY_REQ;
    it is cancelled after the gateway finishes.
    """
    chan = _channel()
    suite = _load_classical()
    gw_id, peer_id = _make_identities(suite)
    frames = [CANFrame(can_id=0x300, dlc=4, data=bytes([i % 256] * 4))
              for i in range(5)]

    async def _scenario() -> int:
        gw_link, peer_link = LinkEmulator.make_pair(_ideal_nc())
        sink: asyncio.Queue[CANFrame] = asyncio.Queue()
        cfg = RekeyConfig(grace_period_s=2.0, grace_period_records=100)
        trig = RekeyTrigger(record_count=5)

        with CanAdapter(chan) as can_gw:
            gw = Gateway(suite, gw_id, can_gw, gw_link,
                         rekey_config=cfg, trigger=trig,
                         handshake_timeout_ms=500)
            peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=cfg)

            # Peer runs indefinitely so it can answer REKEY_REQ after
            # all n_frames are forwarded; cancelled once the gateway finishes.
            peer_task = asyncio.create_task(peer.run(n_frames=None))

            with CanAdapter(chan) as sender:
                for f in frames:
                    sender.send(f)

            try:
                await asyncio.wait_for(gw.run(n_frames=5), timeout=15.0)
            finally:
                peer_task.cancel()
                await asyncio.gather(peer_task, return_exceptions=True)

        return gw._sm.epoch if gw._sm else 0

    epoch = asyncio.run(_scenario())
    assert epoch >= 1, (
        f"epoch={epoch}; expected ≥ 1 after n_frames=trigger_count — "
        "bug 3 (early loop exit before REKEY_ACK) may have regressed"
    )
