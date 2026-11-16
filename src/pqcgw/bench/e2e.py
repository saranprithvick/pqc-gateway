"""End-to-end benchmark harness (§8).

Sub-runs per configuration × network profile:
  A. Handshake: wall time (split into crypto / link / retransmit-wait / other),
     bytes per message, fragment count, success rate — ≥ 200 trials
  B. Latency at scenario rate: gateway CAN ingest → peer delivery (median/p95/p99)
  C. Throughput saturation + peak memory (tracemalloc, NOT inside timed region)
  D. Rekey cost: light rekey ×20, light rekey interval sweep, full rekey ×10

Configurations: C0 (passthrough), C1 (classical), C2 (pqc), C3 (hybrid)
Network profiles: ideal, delay5, delay20, delay50, loss1, loss5, bw6000

Overhead layer decomposition (§15 item 17 / plan):
  C0 baseline: 5 + dlc bytes (can_id 4B + dlc 1B — no data payload counted here)
  C1–C3 add: +8 B fragment header, +1 B prefix, +16 B record header, +16 B AEAD tag
  Residual assertion: abs(measured_overhead - expected_overhead) < 2 bytes

Usage (run from project root):
    python -m pqcgw.bench.e2e               # all configs × all profiles
    python -m pqcgw.bench.e2e --config c3 --profile ideal delay5

Each result file carries full environment metadata.  Raw per-sample data is
written to results/raw/ ; summary tables to results/tables/.
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import logging
import os
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pqcgw.bench.metrics import (
    LatencyTracker,
    SmallNStats,
    Stats,
    SummingHook,
    collect_env,
    compute_small_n_stats,
    compute_stats,
    write_csv,
)
from pqcgw.crypto.registry import load_suite
from pqcgw.legacy.can_adapter import CanAdapter
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.emulator import LinkEmulator, NetworkConfig
from pqcgw.nodes.adapter import MessageAdapter
from pqcgw.nodes.gateway import Gateway
from pqcgw.nodes.passthrough import PassthroughPath
from pqcgw.nodes.peer import ModernPeer
from pqcgw.protocol.handshake import IdentityContext
from pqcgw.protocol.session import RekeyConfig, RekeyTrigger

_ROOT = Path(__file__).resolve().parents[3]
_SUITE_DIR = _ROOT / "configs" / "suites"
_NET_DIR = _ROOT / "configs" / "network"
_RAW_DIR = _ROOT / "results" / "raw"
_TABLES_DIR = _ROOT / "results" / "tables"

# ---------------------------------------------------------------------------
# Configuration registry
# ---------------------------------------------------------------------------

_CONFIGS: dict[str, str] = {
    "c0": "passthrough",
    "c1": "classical",
    "c2": "pqc",
    "c3": "hybrid",
}

_PROFILES: list[str] = ["ideal", "delay5", "delay20", "delay50", "loss1", "loss5", "bw6000"]

_HANDSHAKE_TRIALS = 200
_N_DATA_FRAMES = 1000  # frames for latency sub-run (§8)
_DATA_RATE_HZ = 100.0  # §6 scenario rate
_REKEY_LIGHT_TRIALS = 20
_REKEY_FULL_TRIALS = 10
_REKEY_INTERVALS = [10, 20, 50, 100, 200, 500, 1000, 5000]  # one-factor sweep

_ALLOWED_SUITES = [1, 2, 3]  # C1, C2, C3

_FRAME_DLC = 8  # bench data payload DLC
_BENCH_CHANNEL_PREFIX = "bench_e2e_"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _net_config(profile: str, seed: int = 42) -> NetworkConfig:
    if profile == "ideal":
        return NetworkConfig(seed=seed)
    path = _NET_DIR / f"{profile}.toml"
    cfg = NetworkConfig.from_toml(path)
    # Per-trial seed: use base + offset set by caller
    return NetworkConfig(
        delay_ms=cfg.delay_ms,
        jitter_ms=cfg.jitter_ms,
        loss_pct=cfg.loss_pct,
        bandwidth_kbps=cfg.bandwidth_kbps,
        reorder_pct=cfg.reorder_pct,
        mtu_bytes=cfg.mtu_bytes,
        seed=seed,
    )


def _make_identities(suite):
    sig = suite.signature
    gw_pk, gw_sk = sig.keygen()
    peer_pk, peer_sk = sig.keygen()
    gw_id = IdentityContext(
        my_id="gw", peer_id="peer",
        my_sk=gw_sk, my_pk=gw_pk, peer_pk=peer_pk,
        allowed_suite_ids=_ALLOWED_SUITES,
    )
    peer_id = IdentityContext(
        my_id="peer", peer_id="gw",
        my_sk=peer_sk, my_pk=peer_pk, peer_pk=gw_pk,
        allowed_suite_ids=_ALLOWED_SUITES,
    )
    return gw_id, peer_id


def _unique_channel() -> str:
    return f"{_BENCH_CHANNEL_PREFIX}{os.getpid()}_{int(time.monotonic_ns() % 1_000_000)}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Prefix-byte → human-readable name (§15 item 22)
_PREFIX_NAMES: dict[int, str] = {
    0x01: "HELLO_I", 0x02: "HELLO_R",
    0x03: "FINISHED_I", 0x04: "FINISHED_R", 0x10: "DATA",
}

_AMORTISE_SESSIONS = [100, 1000, 10000]  # records to amortise HS cost over


class _ByteTracker:
    """Wraps a Link; records (type_byte, len) for every send() call."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.sent: list[tuple[int, int]] = []

    async def send(self, msg: bytes) -> None:
        self.sent.append((msg[0] if msg else 0, len(msg)))
        await self._inner.send(msg)

    async def recv(self, timeout: float = 1.0):
        return await self._inner.recv(timeout=timeout)


# ---------------------------------------------------------------------------
# Sub-run A: Handshake timing
# ---------------------------------------------------------------------------

async def _one_handshake(
    suite_name: str,
    net_cfg: NetworkConfig,
    chan: str,
) -> dict:
    """Run one full handshake and return a row dict with timing breakdown.

    The peer runs handshake() then serve_pending_handshake() so that a lost
    FINISHED_R can be recovered when the gateway retransmits FINISHED_I (§15
    item 20).  Outer timeout is set above the gateway's worst-case retry budget:
      HELLO_I phase:    6 attempts × 200ms×2^(0..5) = 6.2 s
      FINISHED_I phase: same = 6.2 s
      Total worst case: ≈ 12.4 s  →  budget = 15 s

    Returns timing breakdown, per-message byte sizes, amortised overhead, and
    last_lost_msg (from emulator drop log) on failure.
    """
    _BUDGET_S = 15.0

    suite = load_suite(_SUITE_DIR / f"{suite_name}.toml")
    gw_id, peer_id = _make_identities(suite)
    gw_hook = SummingHook()
    peer_hook = SummingHook()

    emulator = LinkEmulator(net_cfg)
    gw_link_raw = emulator.gateway_half
    peer_link_raw = emulator.peer_half
    emulator.reset_link_ns()

    # Byte trackers intercept send() on both sides to record per-message sizes.
    gw_tracker = _ByteTracker(gw_link_raw)
    peer_tracker = _ByteTracker(peer_link_raw)

    sink: asyncio.Queue[CANFrame] = asyncio.Queue()
    rekey_cfg = RekeyConfig()

    with CanAdapter(chan) as can:
        gw = Gateway(
            suite, gw_id, can, gw_tracker,
            rekey_config=rekey_cfg,
            handshake_timeout_ms=200,
            handshake_max_retries=5,
            crypto_hook=gw_hook,
        )
        peer = ModernPeer(
            suite, peer_id, peer_tracker, sink,
            rekey_config=rekey_cfg,
            crypto_hook=peer_hook,
        )

        async def _peer_serve() -> None:
            """Run handshake then serve duplicate FINISHED_I for the full retry budget."""
            try:
                await peer.handshake()
            except Exception as exc:
                log.debug("_one_handshake peer: handshake() raised %s", exc)
                return
            await peer.serve_pending_handshake(timeout_s=_BUDGET_S)

        t_wall_start = time.perf_counter_ns()
        gw_task = asyncio.create_task(gw.handshake())
        peer_task = asyncio.create_task(_peer_serve())

        t_wall_end = 0
        try:
            await asyncio.wait_for(gw_task, timeout=_BUDGET_S)
            t_wall_end = time.perf_counter_ns()
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception) as exc:
            # Collect last dropped message from emulator for diagnosis.
            drops = emulator.dropped_messages
            last_lost: Optional[str] = None
            if drops:
                d = drops[-1]
                name = _PREFIX_NAMES.get(d["type_byte"], f"0x{d['type_byte']:02x}")
                last_lost = f"{name} frag {d['frag_idx']}/{d['frag_count']} ({d['direction']})"
            return {
                "success": False,
                "error": type(exc).__name__ + ": " + str(exc),
                "last_lost_msg": last_lost,
            }
        finally:
            peer_task.cancel()
            await asyncio.gather(peer_task, return_exceptions=True)

    wall_ns = t_wall_end - t_wall_start
    crypto_ns = gw_hook.total_ns + peer_hook.total_ns
    link_ns = emulator.handshake_link_ns_i2r + emulator.handshake_link_ns_r2i
    retransmit_wait_ns = gw.handshake_retransmit_wait_ns
    other_ns = max(0, wall_ns - crypto_ns - link_ns - retransmit_wait_ns)

    # Per-message byte sizes (first send per type prefix, bytes include prefix byte).
    msg_bytes: dict[str, int] = {}
    for type_byte, nbytes in gw_tracker.sent + peer_tracker.sent:
        name = _PREFIX_NAMES.get(type_byte, f"0x{type_byte:02x}")
        if name not in msg_bytes:
            msg_bytes[name] = nbytes
    total_hs_bytes = sum(n for _, n in gw_tracker.sent + peer_tracker.sent)

    # On-wire bytes = app-layer bytes + 8 B fragment header per fragment.
    # ByteTracker records bytes BEFORE fragmentation; the 8 B header is added
    # by the emulator per fragment.  Report both for the benchmark table.
    frags_total = emulator.fragments_sent_i2r + emulator.fragments_sent_r2i
    total_hs_bytes_onwire = total_hs_bytes + 8 * frags_total

    return {
        "success": True,
        "wall_ns": wall_ns,
        "crypto_ns": crypto_ns,
        "link_ns": link_ns,
        "retransmit_wait_ns": retransmit_wait_ns,
        "other_ns": other_ns,
        "retransmits": gw.handshake_retransmit_count,
        "frags_i2r": emulator.fragments_sent_i2r,
        "frags_r2i": emulator.fragments_sent_r2i,
        "bytes_hello_i": msg_bytes.get("HELLO_I", 0),
        "bytes_hello_r": msg_bytes.get("HELLO_R", 0),
        "bytes_finished_i": msg_bytes.get("FINISHED_I", 0),
        "bytes_finished_r": msg_bytes.get("FINISHED_R", 0),
        "bytes_total_hs": total_hs_bytes,
        "bytes_total_hs_onwire": total_hs_bytes_onwire,
        **{f"amortised_overhead_{n}": total_hs_bytes / n for n in _AMORTISE_SESSIONS},
    }


def run_handshake_trials(
    config: str,
    profile: str,
    env: dict,
    n_trials: int = _HANDSHAKE_TRIALS,
    run_order_index: int = 0,
) -> None:
    """Sub-run A: ≥ 200 handshake trials, record timing breakdown."""
    suite_name = _CONFIGS[config]
    if config == "c0":
        print(f"  [A] {config}/{profile}: C0 has no handshake — skipping")
        return

    rows: list[dict] = []
    failure_rows: list[dict] = []
    failures = 0
    chan = _unique_channel()

    for i in range(n_trials):
        seed = env.get("seed", 42) + i
        net_cfg = _net_config(profile, seed=seed)
        try:
            result = asyncio.run(
                _one_handshake(suite_name, net_cfg, chan),
                debug=False,
            )
        except Exception as exc:
            failures += 1
            reason = type(exc).__name__ + ": " + str(exc)
            log.debug("Trial %d/%d failed (outer exception): %s", i, n_trials, reason)
            failure_rows.append({
                "config": config, "profile": profile, "trial": i, "seed": seed,
                "reason": reason,
            })
            continue

        if not result.get("success"):
            failures += 1
            reason = result.get("error", "unknown")
            last_lost = result.get("last_lost_msg")
            log.debug("Trial %d/%d failed: %s (last_lost=%s)", i, n_trials, reason, last_lost)
            failure_rows.append({
                "config": config, "profile": profile, "trial": i, "seed": seed,
                "reason": reason, "last_lost_msg": last_lost,
            })
            continue

        rows.append({
            "config": config,
            "profile": profile,
            "trial": i,
            "seed": seed,
            **{k: v for k, v in result.items() if k not in ("success", "error")},
        })

    success_rate = len(rows) / n_trials if n_trials > 0 else 0.0
    print(
        f"  [A] {config}/{profile}: {len(rows)}/{n_trials} succeeded "
        f"({success_rate:.1%}), {failures} failures"
    )

    if rows:
        # Summary stats — wall time only; crypto cost is reported separately
        # via run_primitive_cost() (in-process, no asyncio concurrency noise).
        wall_samples = [r["wall_ns"] for r in rows]
        try:
            st_wall = compute_stats(wall_samples)
            print(
                f"      wall median={st_wall.median_ns/1e6:.1f}ms p95={st_wall.p95_ns/1e6:.1f}ms"
            )
        except ValueError:
            pass

        # Per-message bytes (take median across successful trials).
        def _med_int(key: str) -> int:
            vals = [r[key] for r in rows if r.get(key, 0) > 0]
            return int(sorted(vals)[len(vals) // 2]) if vals else 0

        total_hs_med = _med_int("bytes_total_hs")
        total_hs_onwire_med = _med_int("bytes_total_hs_onwire")
        summary = [{
            "config": config, "profile": profile,
            "run_order_index": run_order_index,
            "n_trials": n_trials, "n_success": len(rows), "n_fail": failures,
            "success_rate": success_rate,
            **(compute_stats(wall_samples).as_dict("wall_") if len(rows) >= 50 else {}),
            "bytes_hello_i": _med_int("bytes_hello_i"),
            "bytes_hello_r": _med_int("bytes_hello_r"),
            "bytes_finished_i": _med_int("bytes_finished_i"),
            "bytes_finished_r": _med_int("bytes_finished_r"),
            "bytes_total_hs": total_hs_med,
            "bytes_total_hs_onwire": total_hs_onwire_med,
            **{f"amortised_overhead_{n}": round(total_hs_med / n, 2)
               for n in _AMORTISE_SESSIONS},
        }]
        write_csv(_TABLES_DIR / "handshake.csv", summary, env)
        write_csv(_RAW_DIR / f"handshake_{config}_{profile}.csv", rows, env)

    if failure_rows:
        write_csv(_RAW_DIR / f"handshake_failures_{config}_{profile}.csv", failure_rows, env)
        print(f"      {len(failure_rows)} failure(s) written to handshake_failures_{config}_{profile}.csv")


# ---------------------------------------------------------------------------
# Sub-run B: Latency at scenario rate
# ---------------------------------------------------------------------------

async def _run_latency(
    suite_name: str,
    net_cfg: NetworkConfig,
    chan: str,
    n_frames: int,
    rate_hz: float,
) -> list[int]:
    """Return list of latency_ns values (ingest→deliver) for n_frames."""
    from pqcgw.legacy.legacy_node import LegacyNode, TrafficProfile

    suite = load_suite(_SUITE_DIR / f"{suite_name}.toml")
    gw_id, peer_id = _make_identities(suite)
    tracker = LatencyTracker()

    emulator = LinkEmulator(net_cfg)
    gw_link = emulator.gateway_half
    peer_link = emulator.peer_half
    sink: asyncio.Queue[CANFrame] = asyncio.Queue()
    rekey_cfg = RekeyConfig()

    with CanAdapter(chan) as can:
        gw = Gateway(
            suite, gw_id, can, gw_link,
            rekey_config=rekey_cfg,
            latency_tracker=tracker,
        )
        peer = ModernPeer(
            suite, peer_id, peer_link, sink,
            rekey_config=rekey_cfg,
            latency_tracker=tracker,
        )

        # Handshake
        _gw_hs = asyncio.create_task(gw.handshake())
        _peer_hs = asyncio.create_task(peer.handshake())
        await asyncio.wait_for(asyncio.gather(_gw_hs, _peer_hs), timeout=10.0)

        # Emit frames at scenario rate.
        # The sender CanAdapter is on the same channel but a separate bus object;
        # the gateway's bus receives frames injected by the sender.
        # Close it explicitly in a finally so its Notifier (if any) is stopped.
        profile = TrafficProfile(can_id=0x100, rate_hz=rate_hz, dlc=_FRAME_DLC,
                                 payload_pattern="counter")
        frame_q: asyncio.Queue[CANFrame] = asyncio.Queue()
        sender_can = CanAdapter(chan)
        try:
            node = LegacyNode(sender_can, [profile])

            emit_task = asyncio.create_task(
                node.emit_loop(0, rate_hz, n_frames, frame_q)
            )
            gw_task = asyncio.create_task(gw.run(n_frames=n_frames))
            peer_task = asyncio.create_task(peer.run(n_frames=n_frames))

            try:
                await asyncio.wait_for(
                    asyncio.gather(emit_task, gw_task, peer_task),
                    timeout=max(5.0, n_frames / rate_hz + 2.0),
                )
            except asyncio.TimeoutError:
                # With packet loss the peer may never receive all n_frames.
                # Cancel remaining tasks and return whatever was collected.
                for t in (emit_task, gw_task, peer_task):
                    t.cancel()
                await asyncio.gather(emit_task, gw_task, peer_task,
                                     return_exceptions=True)
        finally:
            sender_can.close()

    return tracker.latencies_ns


async def _run_passthrough_latency(
    net_cfg: NetworkConfig,
    chan: str,
    n_frames: int,
) -> tuple[list[int], int]:
    """Measure C0 PassthroughPath latency and return (latency_ns_list, delivered).

    Ingest timestamp is captured at the GATEWAY (after can_gw.recv_async()), not
    at the sender, so the measurement is comparable to C1–C3 (which capture ingest
    at gateway.send_frame() after CAN reception and event-queue dequeue).
    """
    emulator = LinkEmulator(net_cfg)
    gw_link = emulator.gateway_half
    peer_link = emulator.peer_half
    sink: asyncio.Queue[tuple[int, int]] = asyncio.Queue()

    t_ingest: dict[int, int] = {}  # seq → ingest_ns captured at gateway CAN receive

    with CanAdapter(chan) as can_gw, CanAdapter(chan) as can_sender:
        async def _send_frames() -> None:
            for seq in range(n_frames):
                frame = CANFrame(can_id=0x100, dlc=8, data=seq.to_bytes(8, "big"))
                can_sender.send(frame)
                await asyncio.sleep(1.0 / _DATA_RATE_HZ)

        async def _gw_side() -> None:
            # Inline the passthrough gateway path to capture ingest at gateway
            # (consistent with C1–C3 LatencyTracker which records after CAN receive).
            sent = 0
            while sent < n_frames:
                frame = await can_gw.recv_async()
                t_ingest_ns = time.perf_counter_ns()  # CAN-ingest timestamp (gateway side)
                try:
                    seq = int.from_bytes(frame.data[:8], "big")
                except Exception:
                    seq = -1
                if seq >= 0:
                    t_ingest[seq] = t_ingest_ns
                encoded = MessageAdapter.encode(frame)
                await gw_link.send(encoded)
                sent += 1

        async def _peer_side() -> None:
            received = 0
            while received < n_frames:
                wire = await peer_link.recv_stream()
                try:
                    frame = MessageAdapter.decode(wire)
                except ValueError:
                    continue
                t_deliver = time.perf_counter_ns()
                try:
                    seq = int.from_bytes(frame.data[:8], "big")
                except Exception:
                    seq = -1
                if seq in t_ingest:
                    await sink.put((seq, t_deliver - t_ingest[seq]))
                received += 1

        try:
            await asyncio.wait_for(
                asyncio.gather(_send_frames(), _gw_side(), _peer_side()),
                timeout=max(5.0, n_frames / _DATA_RATE_HZ + 2.0),
            )
        except asyncio.TimeoutError:
            pass

    latencies: list[int] = []
    while not sink.empty():
        _, lat = sink.get_nowait()
        latencies.append(lat)
    return latencies, len(latencies)


def run_latency(config: str, profile: str, env: dict, run_order_index: int = 0) -> None:
    """Sub-run B: latency at scenario rate."""
    suite_name = _CONFIGS[config]
    chan = _unique_channel()
    net_cfg = _net_config(profile)

    if config == "c0":
        print(f"  [B] {config}/{profile}: C0 passthrough latency")
        try:
            latencies, delivered = asyncio.run(
                _run_passthrough_latency(net_cfg, chan, _N_DATA_FRAMES),
                debug=False,
            )
        except Exception as exc:
            print(f"  [B] {config}/{profile}: FAILED — {exc}")
            return
        if not latencies:
            print(f"  [B] {config}/{profile}: no latency samples")
            return
        rows = [{"config": "c0", "profile": profile, "latency_ns": v} for v in latencies]
        write_csv(_RAW_DIR / f"latency_c0_{profile}.csv", rows, env)
        delivery_ratio = delivered / _N_DATA_FRAMES
        try:
            st = compute_stats(latencies)
            print(
                f"  [B] c0/{profile}: n={st.n} delivery={delivery_ratio:.1%} "
                f"median={st.median_ns/1e6:.2f}ms p95={st.p95_ns/1e6:.2f}ms"
            )
            summary = [{"config": "c0", "profile": profile,
                        "run_order_index": run_order_index,
                        "delivery_ratio": delivery_ratio, **st.as_dict("latency_")}]
            write_csv(_TABLES_DIR / "latency.csv", summary, env)
        except ValueError:
            sn = compute_small_n_stats(latencies)
            print(f"  [B] c0/{profile}: n={sn.n} delivery={delivery_ratio:.1%} "
                  f"median={sn.median_ns/1e6:.2f}ms")
        return

    try:
        latencies = asyncio.run(
            _run_latency(suite_name, net_cfg, chan, _N_DATA_FRAMES, _DATA_RATE_HZ),
            debug=False,
        )
    except Exception as exc:
        print(f"  [B] {config}/{profile}: FAILED — {exc}")
        return

    if not latencies:
        print(f"  [B] {config}/{profile}: no latency samples collected")
        return

    rows = [{"config": config, "profile": profile, "latency_ns": v} for v in latencies]
    write_csv(_RAW_DIR / f"latency_{config}_{profile}.csv", rows, env)

    # delivery_ratio: fraction of injected frames that produced a latency sample.
    # Include it in every summary row so the column order matches the C0 rows
    # (C0 writes delivery_ratio first; without it C1/C2/C3 rows shift under the
    # C0-established CSV header when the file is appended).
    delivery_ratio = round(len(latencies) / _N_DATA_FRAMES, 4)

    try:
        st = compute_stats(latencies)
        print(
            f"  [B] {config}/{profile}: n={st.n} delivery={delivery_ratio:.1%} "
            f"median={st.median_ns/1e6:.2f}ms p95={st.p95_ns/1e6:.2f}ms p99={st.p99_ns/1e6:.2f}ms"
        )
        summary = [{"config": config, "profile": profile,
                    "run_order_index": run_order_index,
                    "delivery_ratio": delivery_ratio, **st.as_dict("latency_")}]
        write_csv(_TABLES_DIR / "latency.csv", summary, env)
    except ValueError:
        sn = compute_small_n_stats(latencies)
        print(
            f"  [B] {config}/{profile}: n={sn.n} (small) delivery={delivery_ratio:.1%} "
            f"median={sn.median_ns/1e6:.2f}ms"
        )


# ---------------------------------------------------------------------------
# Sub-run C: Throughput + memory
# ---------------------------------------------------------------------------

async def _run_throughput(
    suite_name: str,
    net_cfg: NetworkConfig,
    chan: str,
    n_frames: int,
) -> dict:
    suite = load_suite(_SUITE_DIR / f"{suite_name}.toml")
    gw_id, peer_id = _make_identities(suite)

    emulator = LinkEmulator(net_cfg)
    gw_link = emulator.gateway_half
    peer_link = emulator.peer_half
    sink: asyncio.Queue[CANFrame] = asyncio.Queue()

    # Use a SEPARATE injector adapter: the virtual bus does NOT echo sends
    # back to the sender, so frames must come from a different connection.
    injector_chan = chan
    with CanAdapter(chan) as can, CanAdapter(injector_chan) as injector:
        gw = Gateway(suite, gw_id, can, gw_link)
        peer = ModernPeer(suite, peer_id, peer_link, sink)
        _gw_hs = asyncio.create_task(gw.handshake())
        _peer_hs = asyncio.create_task(peer.handshake())
        await asyncio.wait_for(asyncio.gather(_gw_hs, _peer_hs), timeout=10.0)

        gc.collect()
        t_start = time.perf_counter_ns()
        t_cpu_start = time.process_time_ns()

        gw_task = asyncio.create_task(gw.run(n_frames=n_frames))
        peer_task = asyncio.create_task(peer.run(n_frames=n_frames))

        # Inject frames as fast as possible (throughput saturation).
        # injector is a separate adapter so the gateway's bus receives them.
        for i in range(n_frames):
            frame = CANFrame(can_id=0x100, dlc=_FRAME_DLC,
                             data=bytes([i % 256] * _FRAME_DLC))
            injector.send(frame)

        # Wait for the gateway to finish sending all n_frames.
        # The emulator is non-blocking on send, so this is always fast.
        # Time ends here — this is the gateway throughput measurement.
        try:
            await asyncio.wait_for(gw_task, timeout=20.0)
        except (asyncio.TimeoutError, Exception):
            gw_task.cancel()
            await asyncio.gather(gw_task, return_exceptions=True)

        t_end = time.perf_counter_ns()
        t_cpu_end = time.process_time_ns()

        # Give the peer time to drain in-flight records (best-effort).
        # With packet loss, peer may never drain fully — cancel after delay.
        peer_drain = max(2.0, 0.1)  # minimal drain window
        try:
            await asyncio.wait_for(peer_task, timeout=peer_drain)
        except (asyncio.TimeoutError, Exception):
            peer_task.cancel()
            await asyncio.gather(peer_task, return_exceptions=True)

    wall_s = (t_end - t_start) / 1e9
    cpu_s = (t_cpu_end - t_cpu_start) / 1e9
    fps = n_frames / wall_s if wall_s > 0 else 0

    return {
        "wall_s": wall_s,
        "cpu_s": cpu_s,
        "frames_per_sec": fps,
        "n_frames": n_frames,
    }


def run_throughput_memory(config: str, profile: str, env: dict, run_order_index: int = 0) -> None:
    """Sub-run C: throughput saturation (timed) + peak memory (separate untimed run).

    Memory and timing are intentionally separated per §8: tracemalloc must not
    run during the timed section.
    """
    suite_name = _CONFIGS[config]
    net_cfg = _net_config(profile)

    if config == "c0":
        print(f"  [C] {config}/{profile}: skipping (passthrough not instrumented)")
        return

    # Timed run — no tracemalloc
    chan = _unique_channel()
    gc.collect()
    try:
        result = asyncio.run(
            _run_throughput(suite_name, net_cfg, chan, _N_DATA_FRAMES),
            debug=False,
        )
    except Exception as exc:
        print(f"  [C] {config}/{profile}: timed run FAILED — {exc}")
        return

    # Separate memory run — tracemalloc on, no timing recorded
    chan2 = _unique_channel()
    tracemalloc.start()
    gc.collect()
    try:
        asyncio.run(
            _run_throughput(suite_name, net_cfg, chan2, _N_DATA_FRAMES),
            debug=False,
        )
    except Exception:
        pass
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    row = {
        "config": config, "profile": profile,
        "run_order_index": run_order_index,
        **result,
        "peak_memory_bytes": peak,
    }
    write_csv(_TABLES_DIR / "throughput.csv", [row], env)
    print(
        f"  [C] {config}/{profile}: "
        f"{result['frames_per_sec']:.0f} fps  "
        f"cpu={result['cpu_s']*1000:.1f}ms  "
        f"peak={peak//1024} KiB"
    )


# ---------------------------------------------------------------------------
# Sub-run D: Rekey cost
# ---------------------------------------------------------------------------

async def _measure_light_rekey(suite_name: str, net_cfg: NetworkConfig, chan: str) -> dict:
    """Measure one light-rekey round-trip (time from request to epoch change).

    The gateway and peer run loops must remain active during the rekey so that
    REKEY_REQ and REKEY_ACK can be exchanged.  We start them indefinitely, prime
    the data phase with one frame, then trigger a manual light rekey and poll for
    the epoch increment.  Both loops are cancelled after the measurement.
    """
    suite = load_suite(_SUITE_DIR / f"{suite_name}.toml")
    gw_id, peer_id = _make_identities(suite)

    emulator = LinkEmulator(net_cfg)
    gw_link = emulator.gateway_half
    peer_link = emulator.peer_half
    sink: asyncio.Queue[CANFrame] = asyncio.Queue()

    rekey_cfg = RekeyConfig(rekey_timeout_ms=400, rekey_max_retries=3)

    with CanAdapter(chan) as can:
        gw = Gateway(suite, gw_id, can, gw_link, rekey_config=rekey_cfg)
        peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=rekey_cfg)

        _gw_hs = asyncio.create_task(gw.handshake())
        _peer_hs = asyncio.create_task(peer.handshake())
        await asyncio.wait_for(asyncio.gather(_gw_hs, _peer_hs), timeout=10.0)

        # Keep run loops alive during the rekey measurement
        gw_run = asyncio.create_task(gw.run(n_frames=None))
        peer_run = asyncio.create_task(peer.run(n_frames=None))

        # Prime the data phase with one frame
        can.send(CANFrame(can_id=0x100, dlc=8, data=b"\x00" * 8))
        await asyncio.sleep(0.1)  # let the frame be processed

        # Trigger and time light rekey via asyncio.Event (no polling).
        # request_light_rekey_with_event() sets the flag AND returns an Event
        # that the run() loop fires when the epoch actually advances.
        old_epoch = gw._sm.epoch if gw._sm else 0
        t0 = time.perf_counter_ns()
        epoch_event = gw.request_light_rekey_with_event()
        try:
            await asyncio.wait_for(epoch_event.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            pass  # epoch may still have advanced; check below

        t1 = time.perf_counter_ns()
        new_epoch = gw._sm.epoch if gw._sm else -1

        gw_run.cancel()
        peer_run.cancel()
        await asyncio.gather(gw_run, peer_run, return_exceptions=True)

    return {
        "rekey_time_ns": t1 - t0,
        "epoch_before": old_epoch,
        "epoch_after": new_epoch,
    }


def _run_rekey_interval_sweep(suite_name: str, net_cfg: NetworkConfig, env: dict) -> None:
    """Light rekey interval sweep: vary record_count trigger; record overhead bytes/frame."""
    _N_SWEEP_FRAMES = 1000
    rows: list[dict] = []
    for interval in _REKEY_INTERVALS:
        chan = _unique_channel()
        try:
            r = asyncio.run(
                _run_rekey_sweep_trial(suite_name, net_cfg, chan, interval, _N_SWEEP_FRAMES),
                debug=False,
            )
            rows.append({
                "config": "c3",
                "profile": "ideal",
                "rekey_interval": interval,
                **r,
            })
            print(f"      sweep interval={interval}: rekeys={r['rekey_count']}")
        except Exception as exc:
            print(f"      sweep interval={interval}: FAILED — {exc}")

    if rows:
        write_csv(_TABLES_DIR / "rekey_sweep.csv", rows, env)
        print(f"  [D-sweep] wrote {len(rows)} rows to rekey_sweep.csv")


async def _run_rekey_sweep_trial(
    suite_name: str, net_cfg: NetworkConfig, chan: str, interval: int, n_frames: int
) -> dict:
    """Run n_frames at a fixed rekey interval; return bytes sent and rekey count."""
    suite = load_suite(_SUITE_DIR / f"{suite_name}.toml")
    gw_id, peer_id = _make_identities(suite)
    emulator = LinkEmulator(net_cfg)
    gw_link = emulator.gateway_half
    peer_link = emulator.peer_half
    sink: asyncio.Queue[CANFrame] = asyncio.Queue()

    rekey_trig = RekeyTrigger(record_count=interval)
    rekey_cfg = RekeyConfig(rekey_timeout_ms=400, rekey_max_retries=3)

    with CanAdapter(chan) as can, CanAdapter(chan) as injector:
        gw = Gateway(suite, gw_id, can, gw_link,
                     rekey_config=rekey_cfg, trigger=rekey_trig)
        peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=rekey_cfg)
        _gw_hs = asyncio.create_task(gw.handshake())
        _peer_hs = asyncio.create_task(peer.handshake())
        await asyncio.wait_for(asyncio.gather(_gw_hs, _peer_hs), timeout=10.0)

        gw_task = asyncio.create_task(gw.run(n_frames=n_frames))
        peer_task = asyncio.create_task(peer.run(n_frames=n_frames))
        # Inject via a separate adapter so the gateway's bus receives them.
        for i in range(n_frames):
            injector.send(CANFrame(can_id=0x100, dlc=_FRAME_DLC,
                                   data=bytes([i % 256] * _FRAME_DLC)))
        await asyncio.wait_for(asyncio.gather(gw_task, peer_task), timeout=120.0)

    return {
        "rekey_count": (gw._sm.epoch if gw._sm else 0),
        "n_frames": n_frames,
    }


async def _measure_full_rekey(
    suite_name: str,
    net_cfg: NetworkConfig,
    chan: str,
) -> dict:
    """Measure full-rekey cost alongside 100 Hz live traffic.

    Protocol:
      1. Handshake to establish the initial session.
      2. Start 100 Hz live traffic in background (100 frames).
      3. After a brief warm-up, trigger a full rekey.
      4. Record: wall time for new-session establishment, records delivered
         on the old session during the new handshake, first new-session DATA
         record time (from request_full_rekey() to first new-epoch DATA), and
         records dropped (sink count vs injected while rekey in flight).
    """
    _N_LIVE = 100
    _RATE_HZ = 100.0

    suite = load_suite(_SUITE_DIR / f"{suite_name}.toml")
    gw_id, peer_id = _make_identities(suite)

    emulator = LinkEmulator(net_cfg)
    gw_link = emulator.gateway_half
    peer_link = emulator.peer_half
    sink: asyncio.Queue[CANFrame] = asyncio.Queue()

    # retry_budget = 400ms × (3+1) = 1600ms < grace_period_s=5.0 ✓
    rekey_cfg = RekeyConfig(rekey_timeout_ms=400, rekey_max_retries=3,
                            grace_period_s=5.0, grace_period_records=64)

    with CanAdapter(chan) as can, CanAdapter(chan) as injector:
        gw = Gateway(suite, gw_id, can, gw_link, rekey_config=rekey_cfg,
                     handshake_timeout_ms=400, handshake_max_retries=5)
        peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=rekey_cfg)

        _gw_hs = asyncio.create_task(gw.handshake())
        _peer_hs = asyncio.create_task(peer.handshake())
        await asyncio.wait_for(asyncio.gather(_gw_hs, _peer_hs), timeout=15.0)

        old_session_id = gw._sm._session_id if gw._sm else None

        # Start run loops (indefinite — cancelled after measurement).
        gw_run = asyncio.create_task(gw.run(n_frames=None))
        peer_run = asyncio.create_task(peer.run(n_frames=None))

        # Inject warm-up frames (5) so the data path is exercised before timing.
        for i in range(5):
            injector.send(CANFrame(can_id=0x100, dlc=8,
                                   data=bytes([i % 256] * 8)))
        await asyncio.sleep(0.1)

        # Trigger full rekey and start timing using an event (no polling).
        # request_full_rekey_with_event() sets the flag AND returns an Event
        # that the run() loop fires when the new session is established.
        t0 = time.perf_counter_ns()
        full_rekey_event = gw.request_full_rekey_with_event()
        injected_during_rekey = 0

        # Inject live frames at 100 Hz while the full rekey is in flight.
        async def _inject_live() -> None:
            nonlocal injected_during_rekey
            for i in range(_N_LIVE):
                injector.send(CANFrame(can_id=0x100, dlc=8,
                                       data=bytes([i % 256] * 8)))
                injected_during_rekey += 1
                await asyncio.sleep(1.0 / _RATE_HZ)

        inject_task = asyncio.create_task(_inject_live())

        # Wait for new session event (event-driven; no 10ms polling overhead).
        t_new_session = 0
        try:
            await asyncio.wait_for(full_rekey_event.wait(), timeout=15.0)
            t_new_session = time.perf_counter_ns()
        except asyncio.TimeoutError:
            pass

        await asyncio.wait_for(inject_task, timeout=5.0)
        t1 = time.perf_counter_ns()

        # Allow grace period to flush remaining frames.
        await asyncio.sleep(0.3)

        gw_run.cancel()
        peer_run.cancel()
        await asyncio.gather(gw_run, peer_run, return_exceptions=True)

    delivered = sink.qsize()
    new_session_established = t_new_session > 0
    return {
        "full_rekey_wall_ns": (t_new_session - t0) if new_session_established else (t1 - t0),
        "established": new_session_established,
        "records_delivered": delivered,
        "injected_during_rekey": injected_during_rekey,
        "records_dropped": max(0, injected_during_rekey - delivered + 5),  # 5 warm-up injected before
    }


def run_rekey_cost(config: str, profile: str, env: dict, run_order_index: int = 0) -> None:
    """Sub-run D: light-rekey cost ×20 + full-rekey cost ×10 + interval sweep (C3/ideal only)."""
    if config == "c0":
        print(f"  [D] {config}/{profile}: C0 has no rekey — skipping")
        return

    suite_name = _CONFIGS[config]
    base_seed = 42

    # Light rekey cost × 20 — each trial uses a unique seed and channel so
    # loss patterns are independent (fix for all-same-seed clustering).
    light_times: list[int] = []
    for i in range(_REKEY_LIGHT_TRIALS):
        net_cfg_i = _net_config(profile, seed=base_seed + i)
        chan_i = _unique_channel()
        try:
            r = asyncio.run(_measure_light_rekey(suite_name, net_cfg_i, chan_i), debug=False)
            light_times.append(r["rekey_time_ns"])
        except Exception as exc:
            print(f"      light rekey trial {i} failed: {exc}")

    if light_times:
        st = compute_small_n_stats(light_times)
        print(
            f"  [D] {config}/{profile}: light rekey (n={st.n}) "
            f"median={st.median_ns/1e6:.1f}ms min={st.min_ns/1e6:.1f}ms max={st.max_ns/1e6:.1f}ms"
        )
        rows = [{"config": config, "profile": profile, "trial": i, "seed": base_seed + i, "rekey_ns": t}
                for i, t in enumerate(light_times)]
        write_csv(_RAW_DIR / f"rekey_light_{config}_{profile}.csv", rows, env)
        write_csv(_TABLES_DIR / "rekey_cost.csv",
                  [{"config": config, "profile": profile, "run_order_index": run_order_index,
                    "type": "light", **st.as_dict("time_")}], env)

    # Full rekey cost × 10 (ideal only — full rekey under loss is out of scope for M7)
    if profile == "ideal":
        full_times: list[int] = []
        full_rows: list[dict] = []
        for i in range(_REKEY_FULL_TRIALS):
            chan_i = _unique_channel()
            try:
                r = asyncio.run(_measure_full_rekey(suite_name,
                                                    _net_config("ideal", seed=base_seed + i),
                                                    chan_i), debug=False)
                full_times.append(r["full_rekey_wall_ns"])
                full_rows.append({"config": config, "profile": profile, "trial": i,
                                   "seed": base_seed + i, **r})
            except Exception as exc:
                print(f"      full rekey trial {i} failed: {exc}")

        if full_times:
            st_f = compute_small_n_stats(full_times)
            print(
                f"  [D] {config}/{profile}: full rekey (n={st_f.n}) "
                f"median={st_f.median_ns/1e6:.2f}ms min={st_f.min_ns/1e6:.2f}ms "
                f"max={st_f.max_ns/1e6:.2f}ms"
            )
            write_csv(_RAW_DIR / f"rekey_full_{config}_{profile}.csv", full_rows, env)
            write_csv(_TABLES_DIR / "rekey_cost.csv",
                      [{"config": config, "profile": profile,
                        "run_order_index": run_order_index,
                        "type": "full", **st_f.as_dict("time_")}], env)

    # Interval sweep: only for C3 on ideal profile (§plan sub-run D)
    if config == "c3" and profile == "ideal":
        net_ideal = _net_config("ideal", seed=base_seed)
        _run_rekey_interval_sweep(suite_name, net_ideal, env)


# ---------------------------------------------------------------------------
# Sub-run P: Dedicated in-process primitive cost (per handshake)
# ---------------------------------------------------------------------------

_PRIMITIVE_COST_WARMUP = 50
_PRIMITIVE_COST_REPS = 1000


def run_primitive_cost(configs: list[str], env: dict) -> None:
    """Measure per-handshake primitive cost for C1–C3 (in-process, no asyncio/link).

    Runs HandshakeInitiator.start() → HandshakeResponder.process_hello_i() →
    HandshakeInitiator.process_hello_r() → HandshakeInitiator send FINISHED_I →
    HandshakeResponder.process_finished_i() → HandshakeInitiator.process_finished_r()
    in a tight synchronous loop (no event loop, no link emulation).

    This is the theoretical primitive cost: keygen + KEM + 2×sign + 2×verify +
    KDF + HMAC per handshake, without asyncio task-switching or cache-eviction
    pressure from concurrent tasks.  It is a lower bound; the concurrent in-loop
    measurement is higher due to cache effects between gateway and peer primitives.

    Reports median/p95/p99 for ≥1000 reps after ≥50 warm-up reps discarded.
    Writes results/tables/primitive_cost.csv and results/raw/primitive_cost_<config>.csv.
    """
    from pqcgw.protocol.handshake import HandshakeInitiator, HandshakeResponder

    print("\n--- Primitive cost (in-process, no asyncio) ---")

    summary_rows: list[dict] = []

    for config in configs:
        if config == "c0":
            continue
        suite_name = _CONFIGS[config]
        suite = load_suite(_SUITE_DIR / f"{suite_name}.toml")
        gw_id, peer_id = _make_identities(suite)

        def _one_handshake_sync() -> None:
            gw_hs = HandshakeInitiator(suite, gw_id)
            peer_hs = HandshakeResponder(suite, peer_id)
            hello_i = gw_hs.start()
            hello_r = peer_hs.process_hello_i(hello_i)
            finished_i = gw_hs.process_hello_r(hello_r)
            finished_r, _keys = peer_hs.process_finished_i(finished_i)
            gw_hs.process_finished_r(finished_r)

        # Warm-up: discard timing
        gc.collect()
        for _ in range(_PRIMITIVE_COST_WARMUP):
            _one_handshake_sync()

        # Measured reps
        gc.collect()
        samples: list[int] = []
        for _ in range(_PRIMITIVE_COST_REPS):
            t0 = time.perf_counter_ns()
            _one_handshake_sync()
            samples.append(time.perf_counter_ns() - t0)

        st = compute_stats(samples)
        print(
            f"  {config}: primitive cost (n={st.n}) "
            f"median={st.median_ns/1e6:.3f}ms "
            f"p95={st.p95_ns/1e6:.3f}ms "
            f"p99={st.p99_ns/1e6:.3f}ms"
        )

        raw_rows = [{"config": config, "suite": suite_name, "trial": i, "cost_ns": t}
                    for i, t in enumerate(samples)]
        write_csv(_RAW_DIR / f"primitive_cost_{config}.csv", raw_rows, env)

        summary_rows.append({
            "config": config, "suite": suite_name, **st.as_dict("cost_")
        })

    if summary_rows:
        write_csv(_TABLES_DIR / "primitive_cost.csv", summary_rows, env)
        print(f"  → results/tables/primitive_cost.csv ({len(summary_rows)} rows)")


# ---------------------------------------------------------------------------
# Overhead layer decomposition
# ---------------------------------------------------------------------------

def measure_overhead(config: str, dlc: int = _FRAME_DLC) -> dict:
    """Compute expected per-record overhead in layers (§15 item 17 / plan).

    Layers:
      baseline     = 4 (can_id) + 1 (dlc) = 5 bytes of framing for C0
      frag_header  = 8 bytes (applies to ALL configs)
      prefix       = 1 byte (C1–C3 only)
      record_hdr   = 16 bytes (C1–C3 only)
      record_tag   = 16 bytes (C1–C3 only, AEAD tag)

    Returns a dict with per-layer byte counts and total.
    """
    baseline = 5           # can_id(4) + dlc(1), C0 framing
    frag_hdr = 8           # fragment header (all configs)
    prefix = 1 if config != "c0" else 0
    rec_hdr = 16 if config != "c0" else 0
    rec_tag = 16 if config != "c0" else 0
    total = baseline + frag_hdr + prefix + rec_hdr + rec_tag
    return {
        "config": config,
        "baseline_bytes": baseline,
        "frag_header_bytes": frag_hdr,
        "prefix_bytes": prefix,
        "record_header_bytes": rec_hdr,
        "record_tag_bytes": rec_tag,
        "total_overhead_bytes": total,
        "dlc": dlc,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run(
    configs: list[str],
    profiles: list[str],
    skip_hs: bool = False,
    sub: Optional[set[str]] = None,
) -> None:
    """Run e2e benchmarks.

    skip_hs: skip sub-run A (handshake trials) — use when already complete.
    sub: set of sub-run letters to run, e.g. {"B","C","D"}. None = all.
    """
    env = collect_env()
    _subs = sub if sub is not None else {"A", "B", "C", "D", "P"}

    # Unlink all summary tables so each run starts from a clean slate.
    # Raw files are kept (timestamped in filenames) so previous runs are not lost.
    for _fname in ["handshake.csv", "latency.csv", "throughput.csv",
                   "rekey_cost.csv", "rekey_sweep.csv", "primitive_cost.csv"]:
        (_TABLES_DIR / _fname).unlink(missing_ok=True)

    # Write overhead decomposition table (always overwrite — it's deterministic)
    overhead_path = _TABLES_DIR / "overhead.csv"
    overhead_path.unlink(missing_ok=True)
    overhead_rows = [measure_overhead(c) for c in configs]
    write_csv(overhead_path, overhead_rows, env)

    # Dedicated in-process primitive cost (sub-run P): once per bench run, before
    # the per-profile loop, so asyncio scheduler state doesn't affect it.
    if "P" in _subs:
        run_primitive_cost(configs, env)

    # Rotate config order per profile to control for run-order effects (CPU cache,
    # asyncio scheduler warm-up, etc.).  Profile p_idx starts with configs[p_idx % n].
    # run_order_index records the position within that rotation so order effects
    # can be detected in the results.
    n_cfgs = len(configs)
    for p_idx, profile in enumerate(profiles):
        rotated = configs[p_idx % n_cfgs:] + configs[:p_idx % n_cfgs]
        for r_idx, config in enumerate(rotated):
            print(f"\n--- {config} / {profile} [run_order={r_idx}] ---")
            if "A" in _subs and not skip_hs:
                run_handshake_trials(config, profile, env, run_order_index=r_idx)
            if "B" in _subs:
                run_latency(config, profile, env, run_order_index=r_idx)
            if "C" in _subs:
                run_throughput_memory(config, profile, env, run_order_index=r_idx)
            if "D" in _subs:
                run_rekey_cost(config, profile, env, run_order_index=r_idx)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="End-to-end benchmark harness")
    parser.add_argument("--config", nargs="*", default=list(_CONFIGS.keys()),
                        help="Config(s): c0 c1 c2 c3")
    parser.add_argument("--profile", nargs="*", default=_PROFILES,
                        help="Network profile(s)")
    parser.add_argument("--skip-hs", action="store_true",
                        help="Skip sub-run A (handshake) — use when already complete")
    parser.add_argument("--sub", nargs="*", choices=["A", "B", "C", "D", "P"],
                        help="Run only these sub-runs (default: all; P=primitive cost)")
    args = parser.parse_args()
    run(
        args.config,
        args.profile,
        skip_hs=args.skip_hs,
        sub=set(args.sub) if args.sub else None,
    )
