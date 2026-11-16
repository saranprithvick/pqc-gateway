"""Smoke tests for bench infrastructure (M7).

Covers:
  - metrics.compute_stats / compute_small_n_stats
  - metrics.LatencyTracker: record_ingest + record_deliver round-trip
  - metrics.SummingHook: accumulates crypto time
  - metrics.collect_env: returns dict with expected keys
  - metrics.write_csv: creates file with header
  - analytical.bus_time: spot-check formulas
  - analytical.beacon_cost: runs without error
  - analytical.contact_window: contact_window_s formula
  - RekeyConfig.from_toml / RekeyTrigger.from_toml
  - emulator.NetworkConfig.from_toml
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_CONFIGS = _ROOT / "configs"
_SESSION_TOML = _CONFIGS / "sessions" / "default.toml"
_IDEAL_TOML = _CONFIGS / "network" / "ideal.toml"
_DELAY5_TOML = _CONFIGS / "network" / "delay5.toml"


# ---------------------------------------------------------------------------
# metrics module
# ---------------------------------------------------------------------------

class TestComputeStats:
    def test_median_sorted(self):
        from pqcgw.bench.metrics import compute_stats
        sample = list(range(1000))  # 0..999 ns
        st = compute_stats(sample)
        assert abs(st.median_ns - 499.5) < 1
        assert st.n == 1000

    def test_p95_p99_reasonable(self):
        from pqcgw.bench.metrics import compute_stats
        sample = list(range(100, 1100))  # 1000 values, 100..1099
        st = compute_stats(sample)
        assert st.p95_ns >= st.median_ns
        assert st.p99_ns >= st.p95_ns

    def test_requires_50(self):
        from pqcgw.bench.metrics import compute_stats
        with pytest.raises(ValueError, match="n ≥ 50"):
            compute_stats(list(range(10)))

    def test_small_n(self):
        from pqcgw.bench.metrics import compute_small_n_stats
        sample = [100, 200, 300, 400, 500]
        st = compute_small_n_stats(sample)
        assert st.min_ns == 100
        assert st.max_ns == 500
        assert st.n == 5


class TestLatencyTracker:
    def test_round_trip(self):
        from pqcgw.bench.metrics import LatencyTracker
        t = LatencyTracker()
        t.record_ingest(1, 0, 0, 1000)
        t.record_deliver(1, 0, 0, 2000)
        assert t.latencies_ns == [1000]
        assert t.unmatched_ingest == 0

    def test_unmatched_ingest(self):
        from pqcgw.bench.metrics import LatencyTracker
        t = LatencyTracker()
        t.record_ingest(1, 0, 0, 1000)
        # No deliver
        assert t.unmatched_ingest == 1

    def test_multiple_records(self):
        from pqcgw.bench.metrics import LatencyTracker
        t = LatencyTracker()
        for i in range(10):
            t.record_ingest(1, 0, i, i * 1000)
            t.record_deliver(1, 0, i, i * 1000 + 500)
        assert len(t.latencies_ns) == 10
        assert all(v == 500 for v in t.latencies_ns)

    def test_reset(self):
        from pqcgw.bench.metrics import LatencyTracker
        t = LatencyTracker()
        t.record_ingest(1, 0, 0, 100)
        t.reset()
        assert t.latencies_ns == []
        assert t.unmatched_ingest == 0


class TestSummingHook:
    def test_accumulates(self):
        from pqcgw.bench.metrics import SummingHook
        h = SummingHook()
        t0 = h.before_crypto("test")
        # Use a CPU-bound spin so thread_time_ns() records real execution time.
        # time.sleep() does NOT count as CPU time, so it cannot be used here.
        end = time.perf_counter_ns() + 1_000_000  # spin ≥ 1 ms wall
        while time.perf_counter_ns() < end:
            pass
        h.after_crypto("test", t0)
        # total_ns is thread CPU time — must be > 0 and < the wall elapsed.
        assert h.total_ns > 0
        # total_wall_ns is wall time — must be ≥ 1 ms.
        assert h.total_wall_ns >= 500_000
        assert h.counts["test"] == 1
        assert h.per_label_ns.get("test", 0) == h.total_ns

    def test_reset(self):
        from pqcgw.bench.metrics import SummingHook
        h = SummingHook()
        t0 = h.before_crypto("x")
        h.after_crypto("x", t0)
        h.reset()
        assert h.total_ns == 0
        assert h.total_wall_ns == 0


class TestCollectEnv:
    def test_keys_present(self):
        from pqcgw.bench.metrics import collect_env
        env = collect_env()
        for key in ("python_version", "os", "cpu", "liboqs_version",
                    "cryptography_version", "git_commit", "timestamp"):
            assert key in env

    def test_no_secrets_in_values(self):
        from pqcgw.bench.metrics import collect_env
        env = collect_env()
        for v in env.values():
            assert "password" not in str(v).lower()
            assert "secret" not in str(v).lower()


class TestWriteCsv:
    def test_creates_file_with_header(self, tmp_path):
        from pqcgw.bench.metrics import write_csv
        path = tmp_path / "test.csv"
        rows = [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
        write_csv(path, rows, {"env_key": "env_val"})
        content = path.read_text()
        assert "# env_key: env_val" in content
        assert "a,b" in content
        assert "1,2" in content

    def test_append_no_duplicate_header(self, tmp_path):
        from pqcgw.bench.metrics import write_csv
        path = tmp_path / "test.csv"
        rows = [{"x": 1}]
        write_csv(path, rows)
        write_csv(path, [{"x": 2}])
        lines = [l for l in path.read_text().splitlines() if not l.startswith("#")]
        headers = [l for l in lines if l.strip().startswith("x")]
        assert len(headers) == 1  # only one header row


# ---------------------------------------------------------------------------
# Analytical scripts
# ---------------------------------------------------------------------------

class TestBusTime:
    def test_can20_bits_dlc8(self):
        from pqcgw.bench.analytical.bus_time import _can20_frame_bits_worst
        bits = _can20_frame_bits_worst(8)
        # 47 + 64 + floor((34+64-1)/4) = 111 + 24 = 135 bits (worst case)
        assert bits == 47 + 64 + (34 + 64 - 1) // 4

    def test_can20_bits_dlc0(self):
        from pqcgw.bench.analytical.bus_time import _can20_frame_bits_worst
        bits = _can20_frame_bits_worst(0)
        assert bits == 47 + 0 + (34 - 1) // 4

    def test_can_fd_bits_dlc8(self):
        from pqcgw.bench.analytical.bus_time import _can_fd_frame_bits_worst
        bits = _can_fd_frame_bits_worst(8)
        # n_dyn = 22 + 64 = 86; dyn_stuff = 85//4 = 21; CRC-17 + 4 fixed = 21; tail=15; sc=4
        expected = 86 + (85 // 4) + 17 + 4 + 4 + 15
        assert bits == expected

    def test_can_fd_bits_dlc64(self):
        from pqcgw.bench.analytical.bus_time import _can_fd_frame_bits_worst
        bits = _can_fd_frame_bits_worst(64)
        # n_dyn = 22 + 512 = 534; dyn_stuff = 533//4 = 133; CRC-21 + 5 fixed = 26; sc=4; tail=15
        expected = 534 + (533 // 4) + 21 + 5 + 4 + 15
        assert bits == expected

    def test_run_no_error(self):
        from pqcgw.bench.analytical.bus_time import run
        run()  # should not raise


class TestBeaconCost:
    def test_run_no_error(self):
        from pqcgw.bench.analytical.beacon_cost import run
        run()  # should not raise

    def test_overhead_pct_mldsa65(self):
        # ML-DSA-65 sig = 3309 B on 200 B payload → 1654% overhead
        from pqcgw.bench.analytical.beacon_cost import _SCHEMES
        scheme = _SCHEMES["pqc"]
        pct = scheme["sig_bytes"] / 200 * 100
        assert pct > 1000  # more than 10× overhead


class TestContactWindow:
    def test_formula(self):
        from pqcgw.bench.analytical.contact_window import contact_window_s
        # §8: window_s = 2 × range_m / (relative_speed_kmh / 3.6)
        # 300 m at 120 km/h relative → 2×300 / (120/3.6) = 600/33.33 = 18 s
        w = contact_window_s(300, 120)
        assert abs(w - 18.0) < 0.01

    def test_zero_speed(self):
        from pqcgw.bench.analytical.contact_window import contact_window_s
        assert contact_window_s(100, 0) == float("inf")


# ---------------------------------------------------------------------------
# TOML from_toml round-trips
# ---------------------------------------------------------------------------

class TestRekeyFromToml:
    def test_rekey_config(self):
        from pqcgw.protocol.session import RekeyConfig
        cfg = RekeyConfig.from_toml(_SESSION_TOML)
        assert cfg.rekey_timeout_ms == 400
        assert cfg.rekey_max_retries == 3
        assert cfg.grace_period_s == 2.0
        assert cfg.grace_period_records == 64

    def test_rekey_trigger(self):
        from pqcgw.protocol.session import RekeyTrigger
        t = RekeyTrigger.from_toml(_SESSION_TOML)
        assert t.interval_s == 0.0
        assert t.record_count == 0
        assert t.byte_count == 0


class TestNetworkConfigFromToml:
    def test_delay5(self):
        from pqcgw.net.emulator import NetworkConfig
        cfg = NetworkConfig.from_toml(_DELAY5_TOML)
        assert cfg.delay_ms == 5.0
        assert cfg.loss_pct == 0.0

    @pytest.mark.skipif(not (_CONFIGS / "network" / "loss5.toml").exists(),
                        reason="loss5.toml not created")
    def test_loss5(self):
        from pqcgw.net.emulator import NetworkConfig
        cfg = NetworkConfig.from_toml(_CONFIGS / "network" / "loss5.toml")
        assert cfg.loss_pct == 5.0
        assert cfg.delay_ms == 5.0

    @pytest.mark.skipif(not (_CONFIGS / "network" / "bw6000.toml").exists(),
                        reason="bw6000.toml not created")
    def test_bw6000(self):
        from pqcgw.net.emulator import NetworkConfig
        cfg = NetworkConfig.from_toml(_CONFIGS / "network" / "bw6000.toml")
        assert cfg.bandwidth_kbps == 6000.0
