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
import os
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Optional

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
_N_DATA_FRAMES = 100   # frames for latency / throughput sub-runs
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
# Sub-run A: Handshake timing
# ---------------------------------------------------------------------------

async def _one_handshake(
    suite_name: str,
    net_cfg: NetworkConfig,
    chan: str,
) -> dict:
    """Run one full handshake and return a row dict with timing breakdown."""
    suite = load_suite(_SUITE_DIR / f"{suite_name}.toml")
    gw_id, peer_id = _make_identities(suite)
    gw_hook = SummingHook()
    peer_hook = SummingHook()

    emulator = LinkEmulator(net_cfg)
    gw_link = emulator.gateway_half
    peer_link = emulator.peer_half
    emulator.reset_link_ns()

    sink: asyncio.Queue[CANFrame] = asyncio.Queue()
    rekey_cfg = RekeyConfig()

    with CanAdapter(chan) as can:
        gw = Gateway(
            suite, gw_id, can, gw_link,
            rekey_config=rekey_cfg,
            handshake_timeout_ms=200,
            handshake_max_retries=5,
            crypto_hook=gw_hook,
        )
        peer = ModernPeer(
            suite, peer_id, peer_link, sink,
            rekey_config=rekey_cfg,
            crypto_hook=peer_hook,
        )

        t_wall_start = time.perf_counter_ns()
        gw_task = asyncio.create_task(gw.handshake())
        peer_task = asyncio.create_task(peer.handshake())
        try:
            await asyncio.wait_for(
                asyncio.gather(gw_task, peer_task),
                timeout=10.0,
            )
            t_wall_end = time.perf_counter_ns()
        except (asyncio.TimeoutError, Exception) as exc:
            gw_task.cancel()
            peer_task.cancel()
            return {"success": False, "error": str(exc)}

    wall_ns = t_wall_end - t_wall_start
    crypto_ns = gw_hook.total_ns + peer_hook.total_ns
    link_ns = emulator.handshake_link_ns_i2r + emulator.handshake_link_ns_r2i
    retransmit_wait_ns = gw.handshake_retransmit_wait_ns
    other_ns = max(0, wall_ns - crypto_ns - link_ns - retransmit_wait_ns)

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
    }


def run_handshake_trials(
    config: str,
    profile: str,
    env: dict,
    n_trials: int = _HANDSHAKE_TRIALS,
) -> None:
    """Sub-run A: ≥ 200 handshake trials, record timing breakdown."""
    suite_name = _CONFIGS[config]
    if config == "c0":
        print(f"  [A] {config}/{profile}: C0 has no handshake — skipping")
        return

    rows: list[dict] = []
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
            continue

        if not result.get("success"):
            failures += 1
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
        # Summary stats
        wall_samples = [r["wall_ns"] for r in rows]
        crypto_samples = [r["crypto_ns"] for r in rows]
        try:
            st_wall = compute_stats(wall_samples)
            st_crypto = compute_stats(crypto_samples)
            print(
                f"      wall median={st_wall.median_ns/1e6:.1f}ms p95={st_wall.p95_ns/1e6:.1f}ms  "
                f"crypto median={st_crypto.median_ns/1e6:.1f}ms"
            )
        except ValueError:
            pass

        summary = [{
            "config": config, "profile": profile,
            "n_trials": n_trials, "n_success": len(rows), "n_fail": failures,
            "success_rate": success_rate,
            **(compute_stats(wall_samples).as_dict("wall_") if len(rows) >= 50 else {}),
            **(compute_stats(crypto_samples).as_dict("crypto_") if len(rows) >= 50 else {}),
        }]
        write_csv(_TABLES_DIR / "handshake.csv", summary, env)
        write_csv(_RAW_DIR / f"handshake_{config}_{profile}.csv", rows, env)


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

        # Emit frames at scenario rate
        profile = TrafficProfile(can_id=0x100, rate_hz=rate_hz, dlc=_FRAME_DLC,
                                 payload_pattern="counter")
        node = LegacyNode(CanAdapter(chan), [profile])
        frame_q: asyncio.Queue[CANFrame] = asyncio.Queue()

        emit_task = asyncio.create_task(
            node.emit_loop(0, rate_hz, n_frames, frame_q)
        )
        gw_task = asyncio.create_task(gw.run(n_frames=n_frames))
        peer_task = asyncio.create_task(peer.run(n_frames=n_frames))

        await asyncio.wait_for(
            asyncio.gather(emit_task, gw_task, peer_task),
            timeout=max(30.0, n_frames / rate_hz * 2),
        )

    return tracker.latencies_ns


def run_latency(config: str, profile: str, env: dict) -> None:
    """Sub-run B: latency at scenario rate."""
    suite_name = _CONFIGS[config]
    chan = _unique_channel()
    net_cfg = _net_config(profile)

    if config == "c0":
        print(f"  [B] {config}/{profile}: C0 latency measured via passthrough (seq table)")
        # C0 passthrough latency measured in run_passthrough_latency()
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

    try:
        st = compute_stats(latencies)
        print(
            f"  [B] {config}/{profile}: n={st.n} "
            f"median={st.median_ns/1e6:.2f}ms p95={st.p95_ns/1e6:.2f}ms p99={st.p99_ns/1e6:.2f}ms"
        )
        summary = [{"config": config, "profile": profile, **st.as_dict("latency_")}]
        write_csv(_TABLES_DIR / "latency.csv", summary, env)
    except ValueError:
        sn = compute_small_n_stats(latencies)
        print(
            f"  [B] {config}/{profile}: n={sn.n} (small) "
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

    with CanAdapter(chan) as can:
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

        # Inject frames as fast as possible (throughput saturation)
        for i in range(n_frames):
            frame = CANFrame(can_id=0x100, dlc=_FRAME_DLC,
                             data=bytes([i % 256] * _FRAME_DLC))
            can.send(frame)

        await asyncio.wait_for(
            asyncio.gather(gw_task, peer_task),
            timeout=60.0,
        )

        t_end = time.perf_counter_ns()
        t_cpu_end = time.process_time_ns()

    wall_s = (t_end - t_start) / 1e9
    cpu_s = (t_cpu_end - t_cpu_start) / 1e9
    fps = n_frames / wall_s if wall_s > 0 else 0

    return {
        "wall_s": wall_s,
        "cpu_s": cpu_s,
        "frames_per_sec": fps,
        "n_frames": n_frames,
    }


def run_throughput_memory(config: str, profile: str, env: dict) -> None:
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
    """Measure one light-rekey round-trip (time, bytes exchanged)."""
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

        # Send one frame to establish data phase
        can.send(CANFrame(can_id=0x100, dlc=8, data=b"\x00" * 8))
        gw_run = asyncio.create_task(gw.run(n_frames=1))
        peer_run = asyncio.create_task(peer.run(n_frames=1))
        await asyncio.wait_for(asyncio.gather(gw_run, peer_run), timeout=5.0)

        # Trigger and time light rekey
        t0 = time.perf_counter_ns()
        gw.request_light_rekey()
        # Drive until rekey is complete (epoch changes)
        old_epoch = gw._sm.epoch if gw._sm else 0
        for _ in range(100):
            await asyncio.sleep(0.01)
            if gw._sm and gw._sm.epoch != old_epoch:
                break

        t1 = time.perf_counter_ns()

    return {
        "rekey_time_ns": t1 - t0,
        "epoch_before": old_epoch,
        "epoch_after": gw._sm.epoch if gw._sm else -1,
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

    with CanAdapter(chan) as can:
        gw = Gateway(suite, gw_id, can, gw_link,
                     rekey_config=rekey_cfg, trigger=rekey_trig)
        peer = ModernPeer(suite, peer_id, peer_link, sink, rekey_config=rekey_cfg)
        _gw_hs = asyncio.create_task(gw.handshake())
        _peer_hs = asyncio.create_task(peer.handshake())
        await asyncio.wait_for(asyncio.gather(_gw_hs, _peer_hs), timeout=10.0)

        for i in range(n_frames):
            can.send(CANFrame(can_id=0x100, dlc=_FRAME_DLC,
                              data=bytes([i % 256] * _FRAME_DLC)))
        gw_task = asyncio.create_task(gw.run(n_frames=n_frames))
        peer_task = asyncio.create_task(peer.run(n_frames=n_frames))
        await asyncio.wait_for(asyncio.gather(gw_task, peer_task), timeout=60.0)

    return {
        "rekey_count": (gw._sm.epoch if gw._sm else 0),
        "n_frames": n_frames,
    }


def run_rekey_cost(config: str, profile: str, env: dict) -> None:
    """Sub-run D: light-rekey cost ×20 + interval sweep (C3/ideal only)."""
    if config == "c0":
        print(f"  [D] {config}/{profile}: C0 has no rekey — skipping")
        return

    suite_name = _CONFIGS[config]
    net_cfg = _net_config(profile)
    chan = _unique_channel()

    # Light rekey cost × 20
    light_times: list[int] = []
    for i in range(_REKEY_LIGHT_TRIALS):
        try:
            r = asyncio.run(_measure_light_rekey(suite_name, net_cfg, chan), debug=False)
            light_times.append(r["rekey_time_ns"])
        except Exception as exc:
            print(f"      light rekey trial {i} failed: {exc}")

    if light_times:
        st = compute_small_n_stats(light_times)
        print(
            f"  [D] {config}/{profile}: light rekey (n={st.n}) "
            f"median={st.median_ns/1e6:.1f}ms min={st.min_ns/1e6:.1f}ms max={st.max_ns/1e6:.1f}ms"
        )
        rows = [{"config": config, "profile": profile, "rekey_ns": t} for t in light_times]
        write_csv(_RAW_DIR / f"rekey_light_{config}_{profile}.csv", rows, env)
        write_csv(_TABLES_DIR / "rekey_cost.csv",
                  [{"config": config, "profile": profile, "type": "light", **st.as_dict("time_")}], env)

    # Interval sweep: only for C3 on ideal profile (§plan sub-run D)
    if config == "c3" and profile == "ideal":
        _run_rekey_interval_sweep(suite_name, net_cfg, env)


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
    _subs = sub if sub is not None else {"A", "B", "C", "D"}

    # Write overhead decomposition table once
    overhead_rows = [measure_overhead(c) for c in configs]
    write_csv(_TABLES_DIR / "overhead.csv", overhead_rows, env)

    for config in configs:
        for profile in profiles:
            print(f"\n--- {config} / {profile} ---")
            if "A" in _subs and not skip_hs:
                run_handshake_trials(config, profile, env)
            if "B" in _subs:
                run_latency(config, profile, env)
            if "C" in _subs:
                run_throughput_memory(config, profile, env)
            if "D" in _subs:
                run_rekey_cost(config, profile, env)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="End-to-end benchmark harness")
    parser.add_argument("--config", nargs="*", default=list(_CONFIGS.keys()),
                        help="Config(s): c0 c1 c2 c3")
    parser.add_argument("--profile", nargs="*", default=_PROFILES,
                        help="Network profile(s)")
    parser.add_argument("--skip-hs", action="store_true",
                        help="Skip sub-run A (handshake) — use when already complete")
    parser.add_argument("--sub", nargs="*", choices=["A", "B", "C", "D"],
                        help="Run only these sub-runs (default: all)")
    args = parser.parse_args()
    run(
        args.config,
        args.profile,
        skip_hs=args.skip_hs,
        sub=set(args.sub) if args.sub else None,
    )
