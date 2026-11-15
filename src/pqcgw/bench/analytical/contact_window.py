"""Contact-window vs handshake-time comparison (analytical).

ANALYTICAL ESTIMATE — NOT A SIMULATION.

Contact window formula (§8):
    window_s = 2 × range_m / (relative_speed_kmh / 3.6)

For each (range_m, relative_speed_kmh) pair and each network profile,
compare the contact window against the measured handshake p95 time and
print the ratio.  Also includes handshake success rate per profile.

The contact window is a simple geometry calculation; actual V2V contact
depends on road geometry, traffic, and radio range, none of which are
modelled here.

Usage:
    python -m pqcgw.bench.analytical.contact_window

Reads handshake timing from results/tables/handshake.csv (produced by e2e.py).
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[4]
_HANDSHAKE_CSV = _ROOT / "results" / "tables" / "handshake.csv"
_OUT_CSV = _ROOT / "results" / "tables" / "contact_window.csv"

# Default parameter grid (§8: illustrative, not standards-derived)
_RANGES_M = [100, 200, 300]            # communication range metres
_SPEEDS_KMPH = [50, 100, 150, 200]     # relative speed km/h
_CONFIGS = ["c1", "c2", "c3"]
_PROFILES = ["ideal", "delay5", "delay20", "delay50", "loss1", "loss5", "bw6000"]


def contact_window_s(range_m: float, relative_speed_kmh: float) -> float:
    """Return contact-window duration in seconds."""
    if relative_speed_kmh <= 0:
        return float("inf")
    speed_mps = relative_speed_kmh / 3.6
    return 2.0 * range_m / speed_mps


def load_handshake_table(path: Path) -> list[dict]:
    """Load results/tables/handshake.csv; skip comment lines."""
    rows = []
    if not path.exists():
        return rows
    with open(path, newline="") as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            break
        # Rewind and use DictReader ignoring comment lines
    with open(path, newline="") as fh:
        lines = [l for l in fh if not l.startswith("#")]
    if not lines:
        return rows
    reader = csv.DictReader(lines)
    return list(reader)


def run(
    ranges_m: list[float] = None,
    speeds_kmh: list[float] = None,
    configs: list[str] = None,
    profiles: list[str] = None,
) -> None:
    if ranges_m is None:
        ranges_m = _RANGES_M
    if speeds_kmh is None:
        speeds_kmh = _SPEEDS_KMPH
    if configs is None:
        configs = _CONFIGS
    if profiles is None:
        profiles = _PROFILES

    print("=" * 72)
    print("ANALYTICAL ESTIMATE — NOT A SIMULATION")
    print("Contact window vs handshake time")
    print("=" * 72)

    hs_data = load_handshake_table(_HANDSHAKE_CSV)
    # Index by (config, profile)
    hs_index: dict[tuple[str, str], dict] = {}
    for row in hs_data:
        key = (row.get("config", ""), row.get("profile", ""))
        hs_index[key] = row

    out_rows = []

    for range_m in ranges_m:
        for speed in speeds_kmh:
            w = contact_window_s(range_m, speed)
            for config in configs:
                for profile in profiles:
                    hs_row = hs_index.get((config, profile), {})
                    hs_p95_s = None
                    ratio = None
                    success_rate = None
                    try:
                        p95_ns = float(hs_row.get("wall_p95_ns") or hs_row.get("p95_ns") or "nan")
                        hs_p95_s = p95_ns / 1e9
                        ratio = w / hs_p95_s if hs_p95_s and hs_p95_s > 0 else None
                        success_rate = float(hs_row.get("success_rate") or "nan")
                    except (ValueError, TypeError, KeyError):
                        pass

                    row = {
                        "range_m": range_m,
                        "relative_speed_kmh": speed,
                        "contact_window_s": round(w, 4),
                        "config": config,
                        "profile": profile,
                        "hs_p95_s": round(hs_p95_s, 4) if hs_p95_s is not None else "N/A",
                        "window_to_hs_ratio": round(ratio, 2) if ratio is not None else "N/A",
                        "hs_success_rate": round(success_rate, 4) if success_rate and not (success_rate != success_rate) else "N/A",
                    }
                    out_rows.append(row)

                    if hs_p95_s is not None:
                        print(
                            f"  range={range_m:4.0f}m speed={speed:5.0f}km/h "
                            f"window={w:.3f}s  "
                            f"{config}/{profile:10s} hs_p95={hs_p95_s*1000:.1f}ms "
                            f"ratio={ratio:.1f}x  success={success_rate:.1%}"
                            if success_rate and success_rate == success_rate
                            else
                            f"  range={range_m:4.0f}m speed={speed:5.0f}km/h "
                            f"window={w:.3f}s  "
                            f"{config}/{profile:10s} hs_p95={hs_p95_s*1000:.1f}ms ratio={ratio:.1f}x"
                        )
                    else:
                        print(
                            f"  range={range_m:4.0f}m speed={speed:5.0f}km/h "
                            f"window={w:.3f}s  "
                            f"{config}/{profile}: no handshake data"
                        )

    _OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(_OUT_CSV, "w", newline="") as fh:
        fh.write("# ANALYTICAL ESTIMATE — NOT A SIMULATION\n")
        fh.write("# Contact window = 2 * range_m / (relative_speed_kmh / 3.6)\n")
        if out_rows:
            writer = csv.DictWriter(fh, fieldnames=list(out_rows[0].keys()))
            writer.writeheader()
            writer.writerows(out_rows)
    print(f"\n→ {_OUT_CSV}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Contact window vs handshake time (analytical)")
    parser.add_argument("--range", nargs="*", type=float, default=_RANGES_M)
    parser.add_argument("--speed", nargs="*", type=float, default=_SPEEDS_KMPH)
    parser.add_argument("--config", nargs="*", default=_CONFIGS)
    parser.add_argument("--profile", nargs="*", default=_PROFILES)
    args = parser.parse_args()
    run(ranges_m=args.range, speeds_kmh=args.speed,
        configs=args.config, profiles=args.profile)
