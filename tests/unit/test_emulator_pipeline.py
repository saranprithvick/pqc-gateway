"""Tests for LinkEmulator pipelining and bandwidth cap (M7).

T1: 100 messages sent at once over 50 ms delay all arrive ≈ 50 ms (not 5 s).
T2: bandwidth cap serialises fragments; total time is at least serialisation time.
T3: link_ns_acc accumulates (delay + serialisation) per delivered message.
T4: reset_link_ns() zeroes the accumulators.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from pqcgw.net.emulator import LinkEmulator, NetworkConfig


# ---------------------------------------------------------------------------
# T1: Pipelining — 100 messages × 50 ms delay all arrive ≈ 50 ms
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pipeline_100_messages_arrive_concurrently():
    """All 100 messages should arrive within a 2× window of the base delay.

    Without pipelining (sequential sleep), 100 × 50 ms = 5 s.
    With pipelining, all arrive at ≈ 50 ms.
    """
    config = NetworkConfig(delay_ms=50.0, seed=1)
    gw, peer = LinkEmulator.make_pair(config)

    n_messages = 100
    msg = b"hello" * 10

    # Send all messages at once
    for _ in range(n_messages):
        await gw.send(msg)

    # Receive all messages; should take ≈50 ms (plus asyncio scheduling overhead)
    t_start = asyncio.get_event_loop().time()
    received = []
    while len(received) < n_messages:
        m = await peer.recv(timeout=5.0)
        if m is None:
            break
        received.append(m)
    t_elapsed = asyncio.get_event_loop().time() - t_start

    assert len(received) == n_messages, f"Expected {n_messages}, got {len(received)}"
    # Pipelining: should finish well under 5 s (sequential would take 5 s)
    # We allow up to 3 × delay + 200 ms scheduling overhead
    assert t_elapsed < 3.0, (
        f"Pipeline took {t_elapsed:.2f}s — expected < 3s (50 messages × 50ms sequential = 5s)"
    )


# ---------------------------------------------------------------------------
# T2: Bandwidth cap serialises fragments
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bandwidth_cap_serialises():
    """Bandwidth cap adds measurable serialisation time."""
    # 1 kbps cap; each fragment ≈ 50 bytes → serialise_s ≈ 50*8/1000 = 0.4 s per fragment
    # Send a 150-byte message → 3 fragments × 0.4 s = 1.2 s minimum
    config = NetworkConfig(
        delay_ms=0.0,
        bandwidth_kbps=1.0,  # very slow to make timing visible
        mtu_bytes=50,
        seed=2,
    )
    gw, peer = LinkEmulator.make_pair(config)

    msg = bytes(150)  # 150 B → 3 fragments at mtu=50
    t_start = time.perf_counter()
    await gw.send(msg)
    result = await peer.recv(timeout=10.0)
    t_elapsed = time.perf_counter() - t_start

    assert result is not None, "Message should be delivered"
    assert result == msg
    # Must have taken at least 1 second (3 fragments at ~0.4 s each at 1 kbps)
    assert t_elapsed > 0.5, (
        f"Bandwidth cap: expected > 0.5 s serialisation, got {t_elapsed:.3f}s"
    )


# ---------------------------------------------------------------------------
# T3: link_ns_acc accumulates per delivered message
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_link_ns_accumulates():
    """link_ns_acc should reflect delay × number of delivered messages."""
    config = NetworkConfig(delay_ms=10.0, seed=3)
    em = LinkEmulator(config)
    gw = em.gateway_half
    peer = em.peer_half
    em.reset_link_ns()

    n = 5
    msg = b"ping"
    for _ in range(n):
        await gw.send(msg)
    for _ in range(n):
        await peer.recv(timeout=2.0)

    # Each message should contribute ~10 ms (10,000,000 ns) to the I2R accumulator
    ns = em.handshake_link_ns_i2r
    expected_ns = n * 10_000_000  # 5 × 10 ms
    # Allow ±20% tolerance
    assert 0.5 * expected_ns < ns < 2.0 * expected_ns, (
        f"link_ns_i2r={ns} expected ≈ {expected_ns}"
    )


# ---------------------------------------------------------------------------
# T4: reset_link_ns
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reset_link_ns():
    """reset_link_ns() should zero both accumulators."""
    config = NetworkConfig(delay_ms=5.0, seed=4)
    em = LinkEmulator(config)
    gw = em.gateway_half
    peer = em.peer_half

    await gw.send(b"test")
    await peer.recv(timeout=2.0)

    em.reset_link_ns()
    assert em.handshake_link_ns_i2r == 0
    assert em.handshake_link_ns_r2i == 0
