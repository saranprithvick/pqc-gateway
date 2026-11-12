"""Broadcast beacon overhead analytical script (§8).

ANALYTICAL ESTIMATE — NOT A SIMULATION.
Defaults are assumptions, not standards-derived values.

For each signature scheme, computes:
  - Added bytes per beacon: len(signature) + optional pubkey/cert bytes
  - Bytes per second per sender: added_bytes × rate_hz
  - Verification CPU load: neighbours × rate_hz × t_verify (from measured micro-bench)

Purpose: illustrate why per-message PQC signatures are expensive for broadcast safety
beacons compared to classical ECDSA-P256.

Reads verify timing from results/raw/micro_<suite>_sig.csv if available;
otherwise uses a placeholder and notes it.

Usage:
    python -m pqcgw.bench.analytical.beacon_cost
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[5]
_RAW_DIR = _ROOT / "results" / "raw"
_OUT_CSV = _ROOT / "results" / "tables" / "beacon_cost.csv"

# Default beacon parameters (§8 defaults: illustrative assumptions)
_PAYLOAD_BYTES = 200   # beacon payload bytes (e.g. BSM-like)
_RATE_HZ = 10.0        # beacons per second per vehicle
_N_NEIGHBOURS = 10     # number of nearby vehicles each receiver decodes

# Signature schemes to analyse (suite_name → friendly name, sig_len_bytes, pk_len_bytes)
# Sizes from FIPS 203/204 and §4 of CLAUDE.md; measured at runtime if micro CSVs are present
_SCHEMES = {
    "classical": {
        "name": "ECDSA-P256",
        "sig_bytes": 64,       # raw r||s
        "pk_bytes": 32,        # X25519 (not used for signing; ECDSA-P256 pk is 64B compressed)
        "sig_pk_bytes": 64,    # compressed P-256 public key
    },
    "pqc": {
        "name": "ML-DSA-65",
        "sig_bytes": 3309,
        "pk_bytes": 1952,
        "sig_pk_bytes": 1952,
    },
    "hybrid": {
        "name": "ECDSA-P256 + ML-DSA-65 (dual)",
        "sig_bytes": 64 + 3309,  # dual sig, length-prefixed
        "pk_bytes": 64 + 1952,
        "sig_pk_bytes": 64 + 1952,
    },
}


def _load_verify_time_ns(suite_name: str) -> float | None:
    """Load median verify time from micro-bench CSV if available."""
    path = _RAW_DIR / f"micro_{suite_name}_sig.csv"
    if not path.exists():
        return None
    try:
        with open(path, newline="") as fh:
            lines = [l for l in fh if not l.startswith("#")]
        reader = csv.DictReader(lines)
        for row in reader:
            if row.get("op") == "sig_verify":
                return float(row["median_ns"])
    except Exception:
        pass
    return None


def run(
    payload_bytes: int = _PAYLOAD_BYTES,
    rate_hz: float = _RATE_HZ,
    n_neighbours: int = _N_NEIGHBOURS,
    include_pk: bool = False,
) -> None:
    print("=" * 72)
    print("ANALYTICAL ESTIMATE — NOT A SIMULATION")
    print(f"Beacon payload={payload_bytes}B  rate={rate_hz}Hz  neighbours={n_neighbours}")
    print(f"include_pk_in_beacon={include_pk}")
    print("Defaults are assumptions, not standards-derived values.")
    print("=" * 72)

    rows = []

    for suite, info in _SCHEMES.items():
        sig_overhead = info["sig_bytes"]
        if include_pk:
            sig_overhead += info["sig_pk_bytes"]

        total_per_beacon = payload_bytes + sig_overhead
        bytes_per_sec = total_per_beacon * rate_hz
        overhead_pct = sig_overhead / payload_bytes * 100.0

        # Verify CPU load
        t_verify_ns = _load_verify_time_ns(suite)
        if t_verify_ns is not None:
            verify_load_ms_per_s = (n_neighbours * rate_hz * t_verify_ns) / 1e6
            verify_note = "measured"
        else:
            t_verify_ns = float("nan")
            verify_load_ms_per_s = float("nan")
            verify_note = "micro-bench not run; re-run after make bench"

        row = {
            "suite": suite,
            "scheme": info["name"],
            "payload_bytes": payload_bytes,
            "sig_bytes": info["sig_bytes"],
            "pk_bytes": info["sig_pk_bytes"] if include_pk else 0,
            "overhead_bytes": sig_overhead,
            "total_per_beacon": total_per_beacon,
            "overhead_pct": round(overhead_pct, 1),
            "bytes_per_sec": round(bytes_per_sec, 1),
            "rate_hz": rate_hz,
            "n_neighbours": n_neighbours,
            "verify_median_ns": round(t_verify_ns, 0) if t_verify_ns == t_verify_ns else "N/A",
            "verify_load_ms_per_s": round(verify_load_ms_per_s, 2) if verify_load_ms_per_s == verify_load_ms_per_s else "N/A",
            "verify_timing_source": verify_note,
        }
        rows.append(row)

        print(
            f"\n  {info['name']}:\n"
            f"    sig overhead: {sig_overhead:5d} B/beacon ({overhead_pct:.0f}% of payload)\n"
            f"    bytes/s:      {bytes_per_sec:8.0f} B/s per sender\n"
            f"    verify load:  {verify_load_ms_per_s:.2f} ms/s per receiver "
            f"({n_neighbours} neighbours × {rate_hz} Hz × verify)\n"
            f"    verify time:  {t_verify_ns/1e3:.1f} µs  [{verify_note}]"
            if t_verify_ns == t_verify_ns
            else
            f"\n  {info['name']}:\n"
            f"    sig overhead: {sig_overhead:5d} B/beacon ({overhead_pct:.0f}% of payload)\n"
            f"    bytes/s:      {bytes_per_sec:8.0f} B/s per sender\n"
            f"    verify timing: [{verify_note}]"
        )

    _OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(_OUT_CSV, "w", newline="") as fh:
        fh.write("# ANALYTICAL ESTIMATE — NOT A SIMULATION\n")
        fh.write(f"# payload_bytes={payload_bytes}  rate_hz={rate_hz}  n_neighbours={n_neighbours}\n")
        fh.write("# Defaults are assumptions, not standards-derived values.\n")
        if rows:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    print(f"\n→ {_OUT_CSV}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Beacon cost analytical estimate")
    parser.add_argument("--payload", type=int, default=_PAYLOAD_BYTES)
    parser.add_argument("--rate", type=float, default=_RATE_HZ)
    parser.add_argument("--neighbours", type=int, default=_N_NEIGHBOURS)
    parser.add_argument("--include-pk", action="store_true")
    args = parser.parse_args()
    run(payload_bytes=args.payload, rate_hz=args.rate,
        n_neighbours=args.neighbours, include_pk=args.include_pk)
