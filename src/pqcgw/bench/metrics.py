"""Benchmark measurement utilities.

Provides:
  - Stats / compute_stats: median/p95/p99 via linear interpolation on order statistics
  - SmallNStats / compute_small_n_stats: median/min/max/n for n < 50
  - write_csv: append rows to a CSV file with environment metadata header
  - collect_env: gather Python/OS/CPU/library version metadata
  - LatencyTracker: out-of-band latency correlation by (session_id, epoch, counter)
  - CryptoHook / NullCryptoHook / SummingHook: re-exported from protocol.hooks

Percentile method: linear interpolation on the sorted sample.
  For a sample of n values sorted ascending, the p-th percentile (0 ≤ p ≤ 1) is:
      h = p * (n - 1)
      result = sample[floor(h)] + (h - floor(h)) * (sample[ceil(h)] - sample[floor(h)])
  This matches numpy.percentile default ('linear' / 'interpolation').
  Documented here so results are reproducible without numpy.
"""

from __future__ import annotations

import csv
import gc
import math
import os
import platform
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Re-export hooks so bench code has a single import point
from pqcgw.protocol.hooks import CryptoHook, NullCryptoHook, SummingHook

__all__ = [
    "Stats",
    "SmallNStats",
    "compute_stats",
    "compute_small_n_stats",
    "write_csv",
    "collect_env",
    "LatencyTracker",
    "CryptoHook",
    "NullCryptoHook",
    "SummingHook",
]


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

@dataclass
class Stats:
    """Descriptive statistics for a sample of ≥ 50 values."""
    median_ns: float
    p95_ns: float
    p99_ns: float
    n: int

    def as_dict(self, prefix: str = "") -> dict:
        return {
            f"{prefix}median_ns": self.median_ns,
            f"{prefix}p95_ns": self.p95_ns,
            f"{prefix}p99_ns": self.p99_ns,
            f"{prefix}n": self.n,
        }


@dataclass
class SmallNStats:
    """Descriptive statistics for a sample of < 50 values."""
    median_ns: float
    min_ns: float
    max_ns: float
    n: int

    def as_dict(self, prefix: str = "") -> dict:
        return {
            f"{prefix}median_ns": self.median_ns,
            f"{prefix}min_ns": self.min_ns,
            f"{prefix}max_ns": self.max_ns,
            f"{prefix}n": self.n,
        }


def _percentile(sorted_sample: list[float], p: float) -> float:
    """Linear interpolation on order statistics (p ∈ [0, 1])."""
    n = len(sorted_sample)
    if n == 0:
        raise ValueError("empty sample")
    if n == 1:
        return sorted_sample[0]
    h = p * (n - 1)
    lo = int(math.floor(h))
    hi = int(math.ceil(h))
    frac = h - lo
    return sorted_sample[lo] + frac * (sorted_sample[hi] - sorted_sample[lo])


def compute_stats(sample_ns: list[int]) -> Stats:
    """Compute median/p95/p99 for a sample.  Sorts in-place copy."""
    if len(sample_ns) < 50:
        raise ValueError(
            f"compute_stats requires n ≥ 50 (got {len(sample_ns)}); "
            "use compute_small_n_stats for smaller samples"
        )
    s = sorted(float(x) for x in sample_ns)
    return Stats(
        median_ns=_percentile(s, 0.50),
        p95_ns=_percentile(s, 0.95),
        p99_ns=_percentile(s, 0.99),
        n=len(s),
    )


def compute_small_n_stats(sample_ns: list[int]) -> SmallNStats:
    """Compute median/min/max for a small sample (n < 50)."""
    if not sample_ns:
        raise ValueError("empty sample")
    s = sorted(float(x) for x in sample_ns)
    return SmallNStats(
        median_ns=_percentile(s, 0.50),
        min_ns=s[0],
        max_ns=s[-1],
        n=len(s),
    )


# ---------------------------------------------------------------------------
# Environment metadata
# ---------------------------------------------------------------------------

def collect_env(git_commit: str = "", seed: int = 0) -> dict:
    """Collect runtime environment metadata for result files."""
    import subprocess

    cpu = platform.processor() or platform.machine()
    try:
        # liboqs version via oqs module
        import oqs
        liboqs_ver = oqs.oqs_version()
    except Exception:
        liboqs_ver = "unavailable"

    try:
        import cryptography
        crypto_ver = cryptography.__version__
    except Exception:
        crypto_ver = "unavailable"

    if not git_commit:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, timeout=3,
            )
            git_commit = result.stdout.strip() if result.returncode == 0 else "unknown"
        except Exception:
            git_commit = "unknown"

    return {
        "python_version": sys.version.split()[0],
        "os": platform.system(),
        "os_version": platform.release(),
        "cpu": cpu,
        "liboqs_version": liboqs_ver,
        "cryptography_version": crypto_ver,
        "git_commit": git_commit,
        "seed": seed,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------

def write_csv(path: Path, rows: list[dict], env: Optional[dict] = None) -> None:
    """Write rows to a CSV file, prepending environment metadata as comments.

    If the file already exists it is appended (without re-writing the header
    unless it is empty).  The first row's keys become column headers.
    """
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not path.exists() or path.stat().st_size == 0
    with open(path, "a", newline="") as fh:
        if write_header and env:
            for k, v in env.items():
                fh.write(f"# {k}: {v}\n")
        fieldnames = list(rows[0].keys())
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Latency tracker
# ---------------------------------------------------------------------------

class LatencyTracker:
    """Out-of-band latency correlation by (session_id, epoch, counter).

    Gateway calls record_ingest() at CAN ingest time (before sealing).
    Peer calls record_deliver() at delivery time (after AEAD open, before sink.put).

    Timestamps are from time.perf_counter_ns().  The tracker is not thread-safe;
    use one instance per bench run.

    For C0 (no session), session_id = sequence number, epoch = 0, counter = 0.
    """

    def __init__(self) -> None:
        self._ingest: dict[tuple[int, int, int], int] = {}
        self._delivered: list[int] = []   # list of latency_ns values

    def record_ingest(self, session_id: int, epoch: int, counter: int, ts_ns: int) -> None:
        key = (session_id, epoch, counter)
        self._ingest[key] = ts_ns

    def record_deliver(self, session_id: int, epoch: int, counter: int, ts_ns: int) -> None:
        key = (session_id, epoch, counter)
        ingest = self._ingest.pop(key, None)
        if ingest is not None:
            self._delivered.append(ts_ns - ingest)

    @property
    def latencies_ns(self) -> list[int]:
        return list(self._delivered)

    @property
    def unmatched_ingest(self) -> int:
        return len(self._ingest)

    def reset(self) -> None:
        self._ingest.clear()
        self._delivered.clear()
