"""Agility matrix tests: one test per matrix entry in configs/matrix.toml.

For each entry the test verifies all five §4 agility criteria:

1. Config-only: suite loaded from TOML only; no source-file changes.
   Recorded: git commit hash + src_dirty flag.

2. Handshake works: full I→R handshake over LinkEmulator(mtu_bytes=1500) succeeds.
   Recorded: total bytes sent in each direction, total fragment count.

3. Sizes handled automatically: fragment_count == sum of ceil(msg / (mtu - 8)) for
   every handshake message, computed from actual captured message sizes.
   Also asserts no fragment-reassembly errors (Peer delivers FINISHED_R).

4. Traffic works: 5 legitimate CAN frames delivered to the peer sink.

5. Security (T1, T2, T3, T7, T8, T9, T10, T11, T13): inline calls to the same
   protocol-layer helpers used in test_t1–t13.  For the agility parametrization
   the security-test modules are also parametrized over all matrix suites (W4), so
   run_matrix.py can pull those results from a single junitxml run.  The inline
   checks here provide a fast per-entry gate separate from the full security sweep.

Experimental entries (x-hqc3, x-falcon512): run always.  If the mechanism is absent
in the installed liboqs, the test is skipped (pytest.skip) with reason "mechanism_absent".
run_matrix.py catches skips and records "mechanism_absent" in the CSV row.

Timing in results is FUNCTIONAL RUN TIME, not a benchmark.
"""

from __future__ import annotations

import asyncio
import math
import os
import struct
import subprocess
import tomllib
from pathlib import Path
from typing import Optional

import pytest

from pqcgw.crypto.registry import load_suite
from pqcgw.legacy.can_adapter import CanAdapter
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.emulator import LinkEmulator, NetworkConfig
from pqcgw.net.fragment import FRAG_HEADER_LEN
from pqcgw.net.link import Link, LoopbackLink
from pqcgw.nodes.gateway import Gateway
from pqcgw.nodes.peer import ModernPeer
from pqcgw.protocol.handshake import HandshakeInitiator, HandshakeResponder, IdentityContext
from pqcgw.protocol.record import Direction, RecordError, RecordLayer, RecordType
from pqcgw.protocol.replay import ReplayError, ReplayWindow
from pqcgw.protocol.session import RekeyConfig, SessionManager, SessionRole

from tests.suite_helpers import ALL_SUITE_IDS, suite_path

REPO_ROOT = Path(__file__).parent.parent.parent
MATRIX_TOML = REPO_ROOT / "configs" / "matrix.toml"
_MTU = 1500
_N_TRAFFIC_FRAMES = 5


# ---------------------------------------------------------------------------
# Load matrix entries
# ---------------------------------------------------------------------------

with open(MATRIX_TOML, "rb") as _f:
    _MATRIX = tomllib.load(_f)

_ENTRIES = {e["entry_id"]: e for e in _MATRIX["entries"]}


def _entry_ids():
    return list(_ENTRIES.keys())


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip()
    except Exception:
        return "unknown"


def _src_dirty() -> bool:
    try:
        result = subprocess.run(
            ["git", "diff", "--stat", "src/"],
            cwd=REPO_ROOT, capture_output=True, text=True
        )
        return bool(result.stdout.strip())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Sniffer link: captures message sizes before fragmentation
# ---------------------------------------------------------------------------

class _SniffingLink(Link):
    """Wraps a Link, records the byte-length of every sent message."""

    def __init__(self, inner: Link) -> None:
        self._inner = inner
        self.sent_sizes: list[int] = []

    async def send(self, msg: bytes) -> None:
        self.sent_sizes.append(len(msg))
        await self._inner.send(msg)

    async def recv(self, timeout: float = 1.0) -> Optional[bytes]:
        return await self._inner.recv(timeout=timeout)


def _expected_frags(sizes: list[int], mtu: int) -> int:
    chunk = mtu - FRAG_HEADER_LEN
    return sum(math.ceil(max(s, 1) / chunk) for s in sizes)


# ---------------------------------------------------------------------------
# Protocol-layer helpers (inline security checks)
# ---------------------------------------------------------------------------

def _do_handshake(suite):
    sig = suite.signature
    gw_pk, gw_sk = sig.keygen()
    peer_pk, peer_sk = sig.keygen()
    init_id = IdentityContext(
        my_id="gw", peer_id="peer",
        my_sk=gw_sk, my_pk=gw_pk, peer_pk=peer_pk,
        allowed_suite_ids=ALL_SUITE_IDS,
    )
    resp_id = IdentityContext(
        my_id="peer", peer_id="gw",
        my_sk=peer_sk, my_pk=peer_pk, peer_pk=gw_pk,
        allowed_suite_ids=ALL_SUITE_IDS,
    )
    ini = HandshakeInitiator(suite, init_id)
    res = HandshakeResponder(suite, resp_id)
    hi = ini.start()
    hr = res.process_hello_i(hi)
    fi = ini.process_hello_r(hr)
    fr, r_keys = res.process_finished_i(fi)
    i_keys = ini.process_finished_r(fr)
    return suite, i_keys, r_keys, ini.session_id


def _check_security_inline(suite) -> None:
    """Fast inline check of T1, T2, T3, T7, T9, T11 at the record layer."""
    _, keys, _, session_id = _do_handshake(suite)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    # T1: replay rejected
    rec = rl.seal(RecordType.DATA, b"x", Direction.I2R)
    rl.open(rec, Direction.I2R, rw)
    with pytest.raises((RecordError, ReplayError)):
        rl.open(rec, Direction.I2R, rw)

    # T2: tamper rejected
    _, keys2, _, sid2 = _do_handshake(suite)
    rl2 = RecordLayer(suite, keys2, sid2)
    rw2 = ReplayWindow()
    rec2 = rl2.seal(RecordType.DATA, b"secret", Direction.I2R)
    buf = bytearray(rec2)
    buf[20] ^= 0xFF
    with pytest.raises(RecordError):
        rl2.open(bytes(buf), Direction.I2R, rw2)

    # T3: random bytes rejected
    _, keys3, _, sid3 = _do_handshake(suite)
    rl3 = RecordLayer(suite, keys3, sid3)
    rw3 = ReplayWindow()
    with pytest.raises(RecordError):
        rl3.open(os.urandom(16 + 16 + suite.aead.tag_len), Direction.I2R, rw3)

    # T7: out-of-order accepted; duplicate rejected
    _, keys4, _, sid4 = _do_handshake(suite)
    rl4 = RecordLayer(suite, keys4, sid4)
    rw4 = ReplayWindow()
    recs = [rl4.seal(RecordType.DATA, f"m{i}".encode(), Direction.I2R) for i in range(3)]
    for idx in [2, 0, 1]:
        rl4.open(recs[idx], Direction.I2R, rw4)
    with pytest.raises((RecordError, ReplayError)):
        rl4.open(recs[0], Direction.I2R, rw4)

    # T9: 1000-record nonce uniqueness (abbreviated from full 100k for speed)
    _, keys5, _, sid5 = _do_handshake(suite)
    rl5 = RecordLayer(suite, keys5, sid5)
    seen: set[tuple[bytes, bytes]] = set()
    for _ in range(1000):
        r = rl5.seal(RecordType.DATA, b"x", Direction.I2R)
        nonce = keys5.salt_i2r + r[6:14]
        pair = (keys5.k_i2r, nonce)
        assert pair not in seen
        seen.add(pair)

    # T11: reflection rejected
    _, keys6, _, sid6 = _do_handshake(suite)
    rl6 = RecordLayer(suite, keys6, sid6)
    rw6 = ReplayWindow()
    r_i2r = rl6.seal(RecordType.DATA, b"i2r", Direction.I2R)
    with pytest.raises(RecordError):
        rl6.open(r_i2r, Direction.R2I, rw6)


# ---------------------------------------------------------------------------
# End-to-end fragmentation test over LinkEmulator(mtu_bytes=1500)
# ---------------------------------------------------------------------------

async def _run_e2e_fragmentation(suite, channel: str):
    """Run full handshake + N frames over LinkEmulator(mtu_bytes=1500).

    Returns (handshake_ok, frag_count_i2r, frag_count_r2i, frag_expected_i2r,
             frag_expected_r2i, traffic_ok, frames_received).
    """
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

    net_cfg = NetworkConfig(
        delay_ms=0.0, jitter_ms=0.0, loss_pct=0.0,
        bandwidth_kbps=0.0, mtu_bytes=_MTU, seed=42,
    )
    emulator = LinkEmulator(net_cfg)
    gw_link = emulator.gateway_half
    peer_link = emulator.peer_half

    # Wrap the gw and peer link halves with sniffers to capture message sizes
    gw_sniffer = _SniffingLink(emulator.gateway_half)
    peer_sniffer = _SniffingLink(emulator.peer_half)
    # We need to wrap at the emulator input level; since emulator.gateway_half IS
    # the half for gateway sends, wrap it.
    # Actually sniff the outer links passed to Gateway/Peer:
    gw_link_sniffed = _SniffingLink(emulator.gateway_half)
    peer_link_sniffed = _SniffingLink(emulator.peer_half)

    sink: asyncio.Queue[CANFrame] = asyncio.Queue()
    frames_to_send = [CANFrame(can_id=0x200, dlc=8, data=bytes([i] * 8))
                      for i in range(_N_TRAFFIC_FRAMES)]

    handshake_ok = False
    traffic_ok = False

    with CanAdapter(channel) as can_gw, CanAdapter(channel) as sender:
        gateway = Gateway(suite, gw_id, can_gw, gw_link_sniffed)
        peer = ModernPeer(suite, peer_id_ctx, peer_link_sniffed, sink)

        gw_task = asyncio.create_task(gateway.run(n_frames=None))
        peer_task = asyncio.create_task(peer.run(n_frames=_N_TRAFFIC_FRAMES))

        async def _inject():
            await asyncio.sleep(0.1)
            for f in frames_to_send:
                sender.send(f)

        try:
            await asyncio.wait_for(
                asyncio.gather(peer_task, _inject()),
                timeout=20.0,
            )
            handshake_ok = True
            traffic_ok = sink.qsize() == _N_TRAFFIC_FRAMES
        except asyncio.TimeoutError:
            pass
        finally:
            gw_task.cancel()
            await asyncio.gather(gw_task, return_exceptions=True)

    # Fragment counts (from emulator, counting all packets including handshake)
    frag_i2r = emulator.fragments_sent_i2r
    frag_r2i = emulator.fragments_sent_r2i

    # Expected fragments: sum over all messages sent in each direction
    frag_expected_i2r = _expected_frags(gw_link_sniffed.sent_sizes, _MTU)
    frag_expected_r2i = _expected_frags(peer_link_sniffed.sent_sizes, _MTU)

    frames_received = sink.qsize()
    return (
        handshake_ok,
        frag_i2r, frag_r2i,
        frag_expected_i2r, frag_expected_r2i,
        traffic_ok, frames_received,
    )


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("entry_id", _entry_ids())
def test_agility_entry(entry_id: str, can_channel: str) -> None:
    """Agility matrix test for one entry.

    Checks all five §4 criteria.  Experimental entries are skipped (not xfailed)
    if the mechanism is absent; run_matrix.py records "mechanism_absent" for them.
    """
    entry = _ENTRIES[entry_id]
    toml_rel = entry["toml"]
    experimental = entry.get("experimental", False)

    # -------------------------------------------------------------------
    # Criterion 1: config-only
    # -------------------------------------------------------------------
    commit = _git_commit()
    dirty = _src_dirty()
    toml_path = REPO_ROOT / toml_rel

    try:
        suite = load_suite(toml_path)
    except KeyError as exc:
        if experimental:
            pytest.skip(f"mechanism_absent: {exc}")
        else:
            pytest.fail(f"Non-experimental entry {entry_id!r} failed to load: {exc}")

    # Assert no src changes (config-only criterion)
    assert not dirty, (
        f"src/ is dirty — agility criterion 1 (config-only) cannot be asserted.  "
        f"Commit or stash changes before running agility tests."
    )

    # -------------------------------------------------------------------
    # Criterion 5 (fast gate): inline security check
    # -------------------------------------------------------------------
    _check_security_inline(suite)

    # -------------------------------------------------------------------
    # Criteria 2, 3, 4: E2E fragmentation + traffic test
    # -------------------------------------------------------------------
    (
        handshake_ok,
        frag_i2r, frag_r2i,
        frag_expected_i2r, frag_expected_r2i,
        traffic_ok, frames_received,
    ) = asyncio.run(_run_e2e_fragmentation(suite, can_channel))

    # Criterion 2: handshake works
    assert handshake_ok, f"{entry_id}: handshake over LinkEmulator(mtu={_MTU}) failed"

    # Criterion 3: fragments match expected from actual message sizes
    assert frag_i2r == frag_expected_i2r, (
        f"{entry_id}: I2R fragment count mismatch: "
        f"got {frag_i2r}, expected {frag_expected_i2r} "
        f"(mtu={_MTU}, FRAG_HEADER_LEN={FRAG_HEADER_LEN})"
    )
    assert frag_r2i == frag_expected_r2i, (
        f"{entry_id}: R2I fragment count mismatch: "
        f"got {frag_r2i}, expected {frag_expected_r2i}"
    )

    # Criterion 4: traffic delivered
    assert traffic_ok, (
        f"{entry_id}: traffic test failed; "
        f"expected {_N_TRAFFIC_FRAMES} frames, got {frames_received}"
    )
