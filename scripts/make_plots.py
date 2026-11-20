"""Generate matplotlib figures from benchmark results.

Figures produced:
  1. micro_keygen.png       — keygen times by algorithm (grouped bar, log y)
  2. micro_ops.png          — encaps/decaps/sign/verify median µs (grouped bar, log y)
  3. micro_aead.png         — AEAD encrypt/decrypt µs vs payload size (line, log y)
  4. handshake_bars.png     — median handshake wall time per config × profile,
                              stacked bars: crypto / link / retransmit-wait / other
  5. latency_cdf.png        — empirical CDF of per-record latency for C1–C3 × ideal
  6. e2e_overhead.png       — per-layer bytes/record for C0–C3 (stacked bar)
  7. rekey_sweep.png        — overhead bytes/frame vs rekey interval (line, log x)
  8. contact_window_heat.png — heatmap of window/handshake ratio:
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
# Figure: micro keygen times (grouped bar, log y)
# ---------------------------------------------------------------------------

def plot_micro_keygen(plt, show: bool) -> None:
    _FIGURES.mkdir(parents=True, exist_ok=True)
    micro_rows = _load_csv(_TABLES / "micro.csv")
    keygen_rows = [r for r in micro_rows if r.get("op") in ("kem_keygen", "sig_keygen")]
    if not keygen_rows:
        print("  No micro keygen data — skipping micro_keygen.png")
        return

    algos = list({r["alg"] for r in keygen_rows})
    ops = ["kem_keygen", "sig_keygen"]
    colors = {"kem_keygen": "#2196F3", "sig_keygen": "#F44336"}
    x = list(range(len(algos)))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 5))
    for i, op in enumerate(ops):
        vals = []
        for alg in algos:
            matches = [r for r in keygen_rows if r["alg"] == alg and r["op"] == op]
            vals.append(float(matches[0]["median_ns"]) / 1e3 if matches else 0.0)
        offset = (i - len(ops) / 2 + 0.5) * width
        ax.bar([xi + offset for xi in x], vals, width, label=op, color=colors[op], alpha=0.85)

    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(algos, rotation=30, ha="right", fontsize=8)
    ax.set_ylabel("Median time (µs, log scale)")
    ax.set_title("Keygen times by algorithm")
    ax.legend(fontsize=9)
    ax.grid(True, axis="y", alpha=0.3)
    out = _FIGURES / "micro_keygen.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print(f"→ {out}")
    if show:
        plt.show()
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure: micro KEM/SIG ops (grouped bar, log y)
# ---------------------------------------------------------------------------

def plot_micro_ops(plt, show: bool) -> None:
    _FIGURES.mkdir(parents=True, exist_ok=True)
    micro_rows = _load_csv(_TABLES / "micro.csv")
    ops_of_interest = ["kem_encaps", "kem_decaps", "sig_sign", "sig_verify"]
    op_rows = [r for r in micro_rows if r.get("op") in ops_of_interest]
    if not op_rows:
        print("  No micro ops data — skipping micro_ops.png")
        return

    algos = list({r["alg"] for r in op_rows})
    colors = {
        "kem_encaps": "#2196F3", "kem_decaps": "#03A9F4",
        "sig_sign": "#F44336", "sig_verify": "#FF7043",
    }
    x = list(range(len(algos)))
    width = 0.2

    fig, ax = plt.subplots(figsize=(12, 5))
    for i, op in enumerate(ops_of_interest):
        vals = []
        for alg in algos:
            matches = [r for r in op_rows if r["alg"] == alg and r["op"] == op]
            vals.append(float(matches[0]["median_ns"]) / 1e3 if matches else 0.0)
        offset = (i - len(ops_of_interest) / 2 + 0.5) * width
        ax.bar([xi + offset for xi in x], vals, width,
               label=op, color=colors[op], alpha=0.85)

    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(algos, rotation=30, ha="right", fontsize=8)
    ax.set_ylabel("Median time (µs, log scale)")
    ax.set_title("KEM / Signature operation times by algorithm")
    ax.legend(fontsize=8, loc="upper left")
    ax.grid(True, axis="y", alpha=0.3)
    out = _FIGURES / "micro_ops.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print(f"→ {out}")
    if show:
        plt.show()
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure: AEAD encrypt/decrypt vs payload size (line, log y)
# ---------------------------------------------------------------------------

def plot_micro_aead(plt, show: bool) -> None:
    _FIGURES.mkdir(parents=True, exist_ok=True)
    micro_rows = _load_csv(_TABLES / "micro.csv")
    aead_rows = [r for r in micro_rows if r.get("op") in ("aead_encrypt", "aead_decrypt")]
    if not aead_rows:
        print("  No micro AEAD data — skipping micro_aead.png")
        return

    suites = ["classical", "pqc", "hybrid"]
    ops = ["aead_encrypt", "aead_decrypt"]
    suite_colors = {"classical": "#2196F3", "pqc": "#F44336", "hybrid": "#4CAF50"}
    linestyles = {"aead_encrypt": "-", "aead_decrypt": "--"}

    fig, ax = plt.subplots(figsize=(8, 5))
    for suite in suites:
        for op in ops:
            rows = [r for r in aead_rows if r.get("alg") == suite and r.get("op") == op]
            if not rows:
                continue
            try:
                xs = [int(r["payload_bytes"]) for r in rows]
                ys = [float(r["median_ns"]) / 1e3 for r in rows]
                xs, ys = zip(*sorted(zip(xs, ys)))
                ax.plot(xs, ys, marker="o", linestyle=linestyles[op],
                        color=suite_colors[suite],
                        label=f"{suite} {op.split('_')[1]}", linewidth=1.5)
            except (ValueError, KeyError):
                pass

    ax.set_yscale("log")
    ax.set_xscale("log")
    ax.set_xlabel("Payload size (bytes)")
    ax.set_ylabel("Median time (µs, log scale)")
    ax.set_title("AEAD encrypt/decrypt vs payload size")
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)
    out = _FIGURES / "micro_aead.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print(f"→ {out}")
    if show:
        plt.show()
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure: per-layer overhead stacked bar (C0–C3)
# ---------------------------------------------------------------------------

def plot_overhead_bars(plt, show: bool) -> None:
    _FIGURES.mkdir(parents=True, exist_ok=True)
    rows = _load_csv(_TABLES / "overhead.csv")
    if not rows:
        print("  No overhead data — skipping e2e_overhead.png")
        return

    configs = [r["config"] for r in rows]
    layers = ["baseline_bytes", "frag_header_bytes", "prefix_bytes",
              "record_header_bytes", "record_tag_bytes"]
    labels = ["Baseline (5B)", "Frag header (8B)", "Type prefix (1B)",
              "Record header (16B)", "AEAD tag (16B)"]
    colors = ["#9E9E9E", "#FF9800", "#03A9F4", "#2196F3", "#F44336"]

    x = list(range(len(configs)))
    fig, ax = plt.subplots(figsize=(8, 5))
    bottoms = [0.0] * len(configs)
    for layer, label, color in zip(layers, labels, colors):
        vals = []
        for r in rows:
            try:
                vals.append(float(r.get(layer, 0)))
            except (ValueError, TypeError):
                vals.append(0.0)
        ax.bar(x, vals, bottom=bottoms, label=label, color=color, alpha=0.85)
        bottoms = [b + v for b, v in zip(bottoms, vals)]

    ax.set_xticks(x)
    ax.set_xticklabels(configs)
    ax.set_ylabel("Bytes per record")
    ax.set_title("Per-record overhead layer decomposition (C0–C3)")
    ax.legend(fontsize=8, loc="upper left")
    ax.grid(True, axis="y", alpha=0.3)
    out = _FIGURES / "e2e_overhead.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print(f"→ {out}")
    if show:
        plt.show()
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure: rekey sweep (line, log x)
# ---------------------------------------------------------------------------

def plot_rekey_sweep(plt, show: bool) -> None:
    _FIGURES.mkdir(parents=True, exist_ok=True)
    rows = _load_csv(_TABLES / "rekey_sweep.csv")
    if not rows:
        print("  No rekey_sweep data — skipping rekey_sweep.png")
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    try:
        intervals = [int(r["rekey_interval"]) for r in rows]
        rekey_counts = [int(r["rekey_count"]) for r in rows]
        ax.plot(intervals, rekey_counts, marker="o", linewidth=2, color="#F44336")
        ax.set_xscale("log")
        ax.set_xlabel("Rekey interval (records, log scale)")
        ax.set_ylabel("Rekey count per 1000 frames")
        ax.set_title("C3 light rekey frequency vs interval setting")
        ax.grid(True, alpha=0.3)
    except (ValueError, KeyError) as exc:
        ax.text(0.5, 0.5, f"Data error: {exc}",
                ha="center", va="center", transform=ax.transAxes)

    out = _FIGURES / "rekey_sweep.png"
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
    plot_micro_keygen(plt, args.show)
    plot_micro_ops(plt, args.show)
    plot_micro_aead(plt, args.show)
    plot_micro_aead_cdf(plt, args.show)
    plot_handshake_bars(plt, args.show)
    plot_overhead_bars(plt, args.show)
    _sweep_csv = Path("results/tables/rekey_sweep.csv")
    if _sweep_csv.exists():
        plot_rekey_sweep(plt, args.show)
    else:
        print("Skipping rekey_sweep plot: rekey_sweep.csv not present (removed as future work)")
    plot_contact_window_heatmap(plt, args.show)
    print("Done.")


if __name__ == "__main__":
    main()
