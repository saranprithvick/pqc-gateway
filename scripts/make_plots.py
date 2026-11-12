"""Generate matplotlib figures from benchmark results.

Figures produced:
  1. micro_latency_cdf.png  — per-algorithm AEAD encrypt latency empirical CDF
                              (one line per suite), log y-axis for micro timings
  2. handshake_bars.png     — median handshake wall time per config × profile,
                              stacked bars: crypto / link / retransmit-wait / other
  3. latency_cdf.png        — empirical CDF of per-record latency for C1–C3 × ideal
  4. contact_window_heat.png — heatmap of window/handshake ratio:
                               rows = (range_m, speed_kmh), cols = config×profile
                               for profiles {ideal, delay50, loss5}

Reads from: results/raw/ and results/tables/
Writes to:  results/figures/

Usage: python scripts/make_plots.py [--show]
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_RAW = _ROOT / "results" / "raw"
_TABLES = _ROOT / "results" / "tables"
_FIGURES = _ROOT / "results" / "figures"

_CONFIGS = ["c1", "c2", "c3"]
_PROFILES_HEAT = ["ideal", "delay50", "loss5"]


def _load_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, newline="") as fh:
        lines = [l for l in fh if not l.startswith("#")]
    if not lines:
        return []
    return list(csv.DictReader(lines))


def _ensure_matplotlib():
    try:
        import matplotlib
        matplotlib.use("Agg")  # non-interactive backend
        import matplotlib.pyplot as plt
        return plt
    except ImportError:
        print("matplotlib not installed — skipping plots")
        sys.exit(0)


# ---------------------------------------------------------------------------
# Figure 1: micro AEAD encrypt CDF (log y-axis)
# ---------------------------------------------------------------------------

def plot_micro_aead_cdf(plt, show: bool) -> None:
    _FIGURES.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8, 5))

    suites = ["classical", "pqc", "hybrid"]
    colors = {"classical": "#2196F3", "pqc": "#F44336", "hybrid": "#4CAF50"}

    any_data = False
    for suite in suites:
        path = _RAW / f"micro_{suite}_aead.csv"
        rows = _load_csv(path)
        rows = [r for r in rows if r.get("op") == "aead_encrypt" and r.get("payload_bytes") == "64"]
        if not rows:
            continue
        try:
            vals_ns = sorted(float(r.get("median_ns", 0)) for r in rows[:1])
            # For CDF we need raw per-sample data; micro.py writes stats not samples
            # Use median as a point estimate with a note
            ax.axvline(vals_ns[0] / 1000, color=colors.get(suite, "gray"),
                       linestyle="--", label=f"{suite} (median only)", alpha=0.7)
            any_data = True
        except (ValueError, IndexError):
            pass

    # Also try to load raw latency files for latency CDF (from e2e raw)
    for config in _CONFIGS:
        path = _RAW / f"latency_{config}_ideal.csv"
        rows = _load_csv(path)
        if not rows:
            continue
        try:
            vals = sorted(float(r["latency_ns"]) / 1e6 for r in rows)
            n = len(vals)
            cdf = [(i + 1) / n for i in range(n)]
            ax.plot(vals, cdf, label=f"{config}/ideal", linewidth=1.5)
            any_data = True
        except (ValueError, KeyError):
            pass

    if not any_data:
        ax.text(0.5, 0.5, "No data yet — run make bench first",
                ha="center", va="center", transform=ax.transAxes, fontsize=10)

    ax.set_xlabel("Latency (ms)")
    ax.set_ylabel("CDF")
    ax.set_title("Per-record latency empirical CDF (ideal network)")
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)
    out = _FIGURES / "latency_cdf.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print(f"→ {out}")
    if show:
        plt.show()
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 2: handshake stacked bars (crypto / link / retransmit-wait / other)
# ---------------------------------------------------------------------------

def plot_handshake_bars(plt, show: bool) -> None:
    _FIGURES.mkdir(parents=True, exist_ok=True)
    rows = _load_csv(_TABLES / "handshake.csv")
    if not rows:
        print("  No handshake data yet — skipping handshake_bars.png")
        return

    import matplotlib.pyplot as mplt
    configs = sorted({r["config"] for r in rows if r["config"] != "c0"})
    profiles = sorted({r["profile"] for r in rows})

    fig, ax = plt.subplots(figsize=(12, 5))
    x_labels = []
    bottoms = None

    for config in configs:
        for profile in profiles:
            matches = [r for r in rows if r["config"] == config and r["profile"] == profile]
            if not matches:
                continue
            r = matches[0]
            x_labels.append(f"{config}/{profile}")

    if not x_labels:
        plt.close(fig)
        return

    x = list(range(len(x_labels)))
    components = ["crypto", "link", "retransmit_wait", "other"]
    colors_comp = {"crypto": "#F44336", "link": "#2196F3",
                   "retransmit_wait": "#FF9800", "other": "#9E9E9E"}

    vals: dict[str, list[float]] = {c: [] for c in components}
    for label in x_labels:
        cfg, prof = label.split("/")
        matches = [r for r in rows if r["config"] == cfg and r["profile"] == prof]
        if not matches:
            for c in components:
                vals[c].append(0.0)
            continue
        r = matches[0]
        for c in components:
            key = f"{c}_median_ns" if f"{c}_median_ns" in r else f"wall_median_ns"
            try:
                vals[c].append(float(r.get(f"{c}_median_ns", 0)) / 1e6)
            except (ValueError, TypeError):
                vals[c].append(0.0)

    bottom = [0.0] * len(x)
    for c in components:
        ax.bar(x, vals[c], bottom=bottom, label=c,
               color=colors_comp[c], alpha=0.85)
        bottom = [b + v for b, v in zip(bottom, vals[c])]

    ax.set_xticks(x)
    ax.set_xticklabels(x_labels, rotation=45, ha="right", fontsize=7)
    ax.set_ylabel("Time (ms)")
    ax.set_title("Handshake time breakdown (median)")
    ax.legend(fontsize=8)
    ax.grid(True, axis="y", alpha=0.3)
    out = _FIGURES / "handshake_bars.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print(f"→ {out}")
    if show:
        plt.show()
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 3: contact-window heatmap
# ---------------------------------------------------------------------------

def plot_contact_window_heatmap(plt, show: bool) -> None:
    _FIGURES.mkdir(parents=True, exist_ok=True)
    rows = _load_csv(_TABLES / "contact_window.csv")
    if not rows:
        print("  No contact_window data yet — skipping contact_window_heat.png")
        return

    import numpy as np
    import matplotlib.pyplot as mplt
    import matplotlib.colors as mcolors

    # Filter to target profiles
    rows = [r for r in rows
            if r.get("profile") in _PROFILES_HEAT and r.get("config") in _CONFIGS]

    if not rows:
        print("  No matching contact_window data for selected configs/profiles")
        return

    # Build pivot: row = (range_m, speed), col = (config, profile)
    row_keys = sorted({(r["range_m"], r["relative_speed_kmh"]) for r in rows})
    col_keys = [(c, p) for c in _CONFIGS for p in _PROFILES_HEAT]

    idx: dict = {}
    for r in rows:
        k = (r["range_m"], r["relative_speed_kmh"])
        c = (r["config"], r["profile"])
        v = r.get("window_to_hs_ratio", "N/A")
        try:
            idx[(k, c)] = float(v)
        except (ValueError, TypeError):
            idx[(k, c)] = float("nan")

    data = [[idx.get((rk, ck), float("nan")) for ck in col_keys] for rk in row_keys]
    data_arr = np.array(data)

    fig, ax = plt.subplots(figsize=(12, max(4, len(row_keys) * 0.5 + 1)))
    im = ax.imshow(data_arr, aspect="auto", cmap="RdYlGn",
                   norm=mcolors.LogNorm(vmin=0.1, vmax=max(100, float(np.nanmax(data_arr)) if data_arr.size else 100)))
    fig.colorbar(im, ax=ax, label="Window / Handshake p95 ratio (log scale)")

    ax.set_xticks(range(len(col_keys)))
    ax.set_xticklabels([f"{c}/{p}" for c, p in col_keys], rotation=45, ha="right", fontsize=7)
    ax.set_yticks(range(len(row_keys)))
    ax.set_yticklabels([f"{r}m {s}km/h" for r, s in row_keys], fontsize=7)
    ax.set_title("Contact window / handshake p95 ratio\n(> 1 = window sufficient)")

    # Annotate cells
    for i, rk in enumerate(row_keys):
        for j, ck in enumerate(col_keys):
            v = idx.get((rk, ck), float("nan"))
            if v == v:  # not NaN
                ax.text(j, i, f"{v:.1f}", ha="center", va="center", fontsize=6,
                        color="black" if 0.5 < v < 50 else "white")

    out = _FIGURES / "contact_window_heat.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print(f"→ {out}")
    if show:
        plt.show()
    plt.close(fig)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate benchmark plots")
    parser.add_argument("--show", action="store_true", help="Display plots interactively")
    args = parser.parse_args()

    plt = _ensure_matplotlib()
    _FIGURES.mkdir(parents=True, exist_ok=True)

    print("Generating plots…")
    plot_micro_aead_cdf(plt, args.show)
    plot_handshake_bars(plt, args.show)
    plot_contact_window_heatmap(plt, args.show)
    print("Done.")


if __name__ == "__main__":
    main()
