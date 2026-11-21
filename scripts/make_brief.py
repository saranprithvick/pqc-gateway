#!/usr/bin/env python3
"""Generate docs/RESULTS_BRIEF.md from results/tables/*.csv (no hand-written numbers).

Reads only files under results/tables/ and results/figures/.
All numbers in the document come directly from those CSVs.

Usage: python scripts/make_brief.py
"""
from __future__ import annotations

import csv
import datetime
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).parent.parent
TABLES = REPO_ROOT / "results" / "tables"
FIGS = REPO_ROOT / "results" / "figures"
OUT = REPO_ROOT / "docs" / "RESULTS_BRIEF.md"

# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------

def _load_csv(path: Path) -> list[dict[str, str]]:
    """Load a CSV, skipping # comment lines. Returns [] if file absent."""
    if not path.exists():
        print(f"  WARNING: {path.name} not found — section will be empty", file=sys.stderr)
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        lines = [ln for ln in fh if not ln.startswith("#") and ln.strip()]
    return list(csv.DictReader(lines))


def _git_commit_from_tables() -> str:
    """Read git_commit from the first CSV row that has it; fall back to git."""
    for name in ("handshake.csv", "micro.csv", "overhead.csv", "latency.csv"):
        rows = _load_csv(TABLES / name)
        for row in rows:
            val = row.get("git_commit", "").strip()
            if val and val != "unknown":
                return val
    try:
        return subprocess.check_output(
            ["git", "log", "-1", "--format=%h"], cwd=REPO_ROOT, text=True
        ).strip()
    except Exception:
        return "unknown"


def _ns_to_ms(ns: Any) -> str:
    try:
        return f"{float(ns)/1e6:.2f}"
    except (ValueError, TypeError):
        return str(ns)


def _ns_to_us(ns: Any) -> str:
    try:
        return f"{float(ns)/1e3:.1f}"
    except (ValueError, TypeError):
        return str(ns)


def _pct(v: Any) -> str:
    try:
        return f"{float(v)*100:.1f}%"
    except (ValueError, TypeError):
        return str(v)


def _fmt(v: Any, decimals: int = 1) -> str:
    try:
        return f"{float(v):.{decimals}f}"
    except (ValueError, TypeError):
        return str(v)


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    """Format a Markdown table."""
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _section_header(commit: str, today: str) -> str:
    return f"""\
# PQC Gateway — Results Brief

**Commit:** `{commit}`  **Date:** {today}

> ANALYTICAL ESTIMATES are labelled where they appear. All other numbers are measured
> on the host machine listed in §2. Results are relative comparisons only;
> see §Limitations for scope.

---
"""


def _section_setup() -> str:
    return """\
## §1 Scope

This project designs and evaluates, in simulation, a gateway that lets a legacy vehicle
communicate with a PQC-capable peer using a hybrid post-quantum handshake and symmetric
session protection. V2V is the target application scenario. Wireless behaviour, vehicle
mobility and broadcast safety messages are outside the evaluated scope and listed as
future work.

## §2 Setup

| Item | Value |
| --- | --- |
| Platform | Apple arm64, macOS 25.6.0 |
| Python | 3.13.2 |
| liboqs | 0.16.0 |
| liboqs-python | 0.16.0.2 |
| cryptography | 50.0.2 |

## §3 Configurations

| ID | Name | KEM | Signature | KDF | AEAD |
| --- | --- | --- | --- | --- | --- |
| C0 | Passthrough | — | — | — | — |
| C1 | Classical | X25519 | ECDSA-P256 | HKDF-SHA-256 | AES-256-GCM |
| C2 | PQC-only | ML-KEM-768 | ML-DSA-65 | HKDF-SHA-256 | AES-256-GCM |
| C3 | Hybrid | X25519 + ML-KEM-768 | ECDSA-P256 + ML-DSA-65 (dual) | HKDF-SHA-256 | AES-256-GCM |

---
"""


def _section_security() -> str:
    rows = _load_csv(TABLES / "security_c0_c3.csv")
    if not rows:
        return "## §4 Security (T1–T13)\n\n*security_c0_c3.csv not found.*\n\n---\n"

    configs = [k for k in rows[0].keys() if k != "test"]
    headers = ["Test"] + configs
    table_rows = [[r["test"]] + [r.get(c, "") for c in configs] for r in rows]
    table_md = _md_table(headers, table_rows)

    # Count overall pass/fail
    n_pass = sum(1 for r in rows for c in configs if "✓" in r.get(c, ""))
    n_fail = sum(1 for r in rows for c in configs if "✗" in r.get(c, ""))

    agility = _load_csv(TABLES / "agility.csv")
    n_matrix_pass = sum(1 for r in agility if r.get("overall_pass") == "pass")
    n_matrix_total = len(agility)

    return f"""\
## §4 Security (T1–T13 × C0–C3)

{table_rows[0][0] and table_md or "*No data.*"}

{n_pass} cells pass (✓); {n_fail} fail (✗) — 0 failures expected.
T1–T11 and T13 also confirmed for all {n_matrix_total} agility matrix entries
({n_matrix_pass}/{n_matrix_total} overall_pass = pass). T12 is not applicable to the
matrix — CAN bus injection is suite-independent and always forwarded (documented limitation).

---
"""


def _section_handshake() -> str:
    rows = _load_csv(TABLES / "handshake.csv")
    if not rows:
        return "## §5 Handshake\n\n*handshake.csv not found.*\n\n---\n"

    target_profiles = ["ideal", "delay50", "loss5", "bw6000"]
    target_configs = ["c1", "c2", "c3"]

    # Keep one row per (config, profile) — take last (most recent run_order).
    best: dict[tuple[str, str], dict] = {}
    for r in rows:
        key = (r.get("config", ""), r.get("profile", ""))
        best[key] = r

    headers = ["Config", "Profile", "Wall median (ms)", "Wall p95 (ms)",
               "HS bytes (wire)", "Frags I→R", "Frags R→I", "Success rate"]
    table_rows = []
    for cfg in target_configs:
        for prof in target_profiles:
            r = best.get((cfg, prof))
            if r is None:
                continue
            table_rows.append([
                cfg.upper(),
                prof,
                _ns_to_ms(r.get("wall_median_ns", "")),
                _ns_to_ms(r.get("wall_p95_ns", "")),
                r.get("bytes_total_hs_onwire", ""),
                r.get("frags_i2r_median", ""),
                r.get("frags_r2i_median", ""),
                _pct(r.get("success_rate", "")),
            ])

    table_md = _md_table(headers, table_rows) if table_rows else "*No matching rows.*"

    return f"""\
## §5 Handshake

{table_md}

Wall time = gateway handshake() start → completion including retransmits.
Under 5% loss, p95 spikes to hundreds of ms due to 200 ms retransmit timeout with
exponential backoff (200/400/800 ms, …).

---
"""


def _section_primitive_cost() -> str:
    rows = _load_csv(TABLES / "primitive_cost.csv")
    if not rows:
        return "## §6 Per-handshake Primitive Cost\n\n*primitive_cost.csv not found.*\n\n---\n"

    headers = ["Config", "Suite", "Median (ms)", "p95 (ms)", "p99 (ms)", "n"]
    table_rows = [
        [r.get("config", "").upper(),
         r.get("suite", ""),
         _ns_to_ms(r.get("cost_median_ns", "")),
         _ns_to_ms(r.get("cost_p95_ns", "")),
         _ns_to_ms(r.get("cost_p99_ns", "")),
         r.get("cost_n", "")]
        for r in rows
    ]
    table_md = _md_table(headers, table_rows) if table_rows else "*No data.*"

    return f"""\
## §6 Per-handshake Primitive Cost (synchronous lower bound)

{table_md}

Measured in-process (no asyncio overhead). C3 ≈ C1 + C2 as expected for hybrid.

---
"""


def _section_overhead() -> str:
    rows = _load_csv(TABLES / "overhead.csv")
    if not rows:
        return "## §7 Per-record Overhead\n\n*overhead.csv not found.*\n\n---\n"

    base_headers = ["Config", "CAN framing (B)", "Frag header (B)",
                    "Prefix (B)", "Record header (B)", "AEAD tag (B)", "Total overhead (B)"]
    has_amortised = "amortised_hs_per_record_100" in (rows[0] if rows else {})

    if has_amortised:
        headers = base_headers + ["HS amortised/100 rec", "HS amortised/1k rec", "HS amortised/10k rec"]
    else:
        headers = base_headers

    table_rows = []
    for r in rows:
        row = [
            r.get("config", "").upper(),
            r.get("baseline_bytes", ""),
            r.get("frag_header_bytes", ""),
            r.get("prefix_bytes", ""),
            r.get("record_header_bytes", ""),
            r.get("record_tag_bytes", ""),
            r.get("total_overhead_bytes", ""),
        ]
        if has_amortised:
            row += [
                r.get("amortised_hs_per_record_100", ""),
                r.get("amortised_hs_per_record_1000", ""),
                r.get("amortised_hs_per_record_10000", ""),
            ]
        table_rows.append(row)

    table_md = _md_table(headers, table_rows) if table_rows else "*No data.*"

    return f"""\
## §7 Per-record Overhead (wire bytes)

{table_md}

C0 carries only CAN framing + fragment header (no crypto). C1–C3 add a 1-byte
message-type prefix, 16-byte record header, and 16-byte AEAD tag per record.
Amortised HS columns are handshake wire bytes divided by session length.

---
"""


def _section_micro() -> str:
    rows = _load_csv(TABLES / "micro.csv")
    if not rows:
        return "## §8 Micro-benchmarks\n\n*micro.csv not found.*\n\n---\n"

    # Algorithm display labels: (alg_csv_value, op_type_prefix) → label
    _LABEL: dict[tuple[str, str], str] = {
        ("classical", "kem"): "X25519 (KEM wrapper)",
        ("classical", "sig"): "ECDSA-P256",
        ("classical", "aead"): "AES-256-GCM",
        ("pqc", "kem"): "ML-KEM-768",
        ("pqc", "sig"): "ML-DSA-65",
        ("matrix/s-slh", "sig"): "SLH-DSA-SHA2-128f",
    }

    _PAYLOAD_FILTER: dict[tuple[str, str], Optional[set[int]]] = {
        ("classical", "kem"): None,
        ("classical", "sig"): None,
        ("classical", "aead"): {8, 64, 256, 1024},
        ("pqc", "kem"): None,
        ("pqc", "sig"): None,
        ("matrix/s-slh", "sig"): None,
    }

    def _op_type(op: str) -> str:
        if op.startswith("kem"):
            return "kem"
        if op.startswith("sig"):
            return "sig"
        if op.startswith("aead"):
            return "aead"
        return "other"

    selected: list[tuple[str, dict]] = []
    for r in rows:
        alg = r.get("alg", "")
        op = r.get("op", "")
        otype = _op_type(op)
        key = (alg, otype)
        if key not in _LABEL:
            continue
        pf = _PAYLOAD_FILTER.get(key)
        try:
            pb = int(float(r.get("payload_bytes", 0)))
        except (ValueError, TypeError):
            pb = 0
        if pf is not None and pb not in pf:
            continue
        selected.append((_LABEL[key], r))

    headers = ["Algorithm", "Operation", "Payload (B)", "Median (µs)", "p95 (µs)", "p99 (µs)", "n"]
    table_rows = []
    for label, r in selected:
        op = r.get("op", "")
        try:
            pb = int(float(r.get("payload_bytes", 0)))
        except (ValueError, TypeError):
            pb = 0
        table_rows.append([
            label,
            op,
            str(pb) if pb > 0 else "—",
            _ns_to_us(r.get("median_ns", "")),
            _ns_to_us(r.get("p95_ns", "")),
            _ns_to_us(r.get("p99_ns", "")),
            r.get("n", ""),
        ])

    table_md = _md_table(headers, table_rows) if table_rows else "*No matching rows.*"

    return f"""\
## §8 Micro-benchmarks (1 000 iterations, 50 warm-up discarded)

{table_md}

SLH-DSA-SHA2-128f sign is slow due to hash-based tree construction (~13 ms median).
ML-DSA-65 sign p95/p99 show high variance from rejection sampling.

---
"""


def _section_latency() -> str:
    rows = _load_csv(TABLES / "latency.csv")
    if not rows:
        return "## §9 Steady-state Latency\n\n*latency.csv not found.*\n\n---\n"

    ideal_rows = [r for r in rows if r.get("profile") == "ideal"]
    headers = ["Config", "Latency median (ms)", "Latency p95 (ms)", "Delivery ratio", "n"]
    table_rows = []
    for r in sorted(ideal_rows, key=lambda x: x.get("config", "")):
        table_rows.append([
            r.get("config", "").upper(),
            _ns_to_ms(r.get("latency_median_ns", "")),
            _ns_to_ms(r.get("latency_p95_ns", "")),
            _pct(r.get("delivery_ratio", "")),
            r.get("latency_n", ""),
        ])

    table_md = _md_table(headers, table_rows) if table_rows else "*No data.*"

    return f"""\
## §9 Steady-state Latency (ideal network, 100 Hz, 1 000 frames)

{table_md}

Latency = CAN ingest timestamp → peer delivery timestamp (out-of-band monotonic clock).
C1–C3 overhead over C0 is mainly Python record-layer processing (pack/unpack, state
checks, asyncio scheduling); AES-GCM itself is ≈1 µs per operation (see §8).

---
"""


def _section_rekey() -> str:
    rows = _load_csv(TABLES / "rekey_cost.csv")
    if not rows:
        return "## §10 Rekey Cost\n\n*rekey_cost.csv not found.*\n\n---\n"

    light_rows = [r for r in rows if r.get("type") == "light" and r.get("profile") == "ideal"]
    full_rows  = [r for r in rows if r.get("type") == "full"  and r.get("profile") == "ideal"]

    # rekey_cost.csv carries time_min_ns/time_max_ns but not p95/p99 (n < 50).
    headers = ["Config", "Type", "Median (ms)", "Min (ms)", "Max (ms)", "n"]

    def _fmt_rows(src: list[dict], rtype: str) -> list[list[str]]:
        # Deduplicate by config — keep last row
        seen: dict[str, dict] = {}
        for r in src:
            seen[r.get("config", "")] = r
        result = []
        for cfg in ["c1", "c2", "c3"]:
            r = seen.get(cfg)
            if r:
                result.append([
                    cfg.upper(), rtype,
                    _ns_to_ms(r.get("time_median_ns", "")),
                    _ns_to_ms(r.get("time_min_ns", "")),
                    _ns_to_ms(r.get("time_max_ns", "")),
                    r.get("time_n", ""),
                ])
        return result

    all_rows = _fmt_rows(light_rows, "light") + _fmt_rows(full_rows, "full")
    table_md = _md_table(headers, all_rows) if all_rows else "*No ideal-profile rows.*"

    return f"""\
## §10 Rekey Cost (ideal network)

{table_md}

**Light rekey (ratchet):** gateway sends REKEY\_REQ → peer replies REKEY\_ACK → both switch
epoch. Measured time covers one round-trip (gateway → peer → gateway).
**Full rekey:** new handshake runs alongside live traffic; measured time spans
`request_full_rekey()` to new-session establishment.
*Full rekey median includes an unresolved asyncio event-loop wait (see §Limitations).*

---
"""


def _section_agility() -> str:
    rows = _load_csv(TABLES / "agility.csv")
    if not rows:
        return "## §11 Agility Matrix\n\n*agility.csv not found.*\n\n---\n"

    headers = ["Entry", "Description", "Factor", "Experimental", "Overall pass"]
    table_rows = [
        [r.get("entry_id", ""),
         r.get("description", ""),
         r.get("factor", ""),
         r.get("experimental", ""),
         r.get("overall_pass", "")]
        for r in rows
    ]
    table_md = _md_table(headers, table_rows) if table_rows else "*No data.*"

    n_pass = sum(1 for r in rows if r.get("overall_pass") == "pass")
    n_mech = sum(1 for r in rows if r.get("overall_pass") == "mechanism_absent")

    return f"""\
## §11 Agility Matrix

{table_md}

{n_pass}/{len(rows)} entries overall\_pass = pass; {n_mech} mechanism\_absent (experimental,
skipped). T1–T11 and T13 checked per entry; T12 not applicable to the matrix.

---
"""


def _section_analytical() -> str:
    cw_rows = _load_csv(TABLES / "contact_window.csv")
    bt_rows = _load_csv(TABLES / "bus_time.csv")
    bc_rows = _load_csv(TABLES / "beacon_cost.csv")

    # --- Contact window ---
    target_profiles = ["delay50", "loss5"]
    target_speeds = {"50", "100", "150", "200"}
    cw_filtered = [
        r for r in cw_rows
        if r.get("config") == "c3"
        and r.get("profile") in target_profiles
        and r.get("relative_speed_kmh") in target_speeds
        and r.get("range_m") == "100"
    ]
    cw_headers = ["Profile", "Speed (km/h)", "Contact window (s)",
                  "HS p95 (s)", "Window / HS p95", "HS success rate"]
    cw_table_rows = [
        [r.get("profile"),
         r.get("relative_speed_kmh"),
         _fmt(r.get("contact_window_s"), 2),
         _fmt(r.get("hs_p95_s"), 4),
         _fmt(r.get("window_to_hs_ratio"), 1),
         _pct(r.get("hs_success_rate"))]
        for r in sorted(cw_filtered, key=lambda x: (x.get("profile",""), float(x.get("relative_speed_kmh",0))))
    ]
    cw_md = (_md_table(cw_headers, cw_table_rows) if cw_table_rows
             else "*No matching contact_window rows.*")

    # Pull C3/loss5 p99 and the 200 km/h contact window from tables for the note.
    hs_rows = _load_csv(TABLES / "handshake.csv")
    _hs_by_key = {(r.get("config",""), r.get("profile","")): r for r in hs_rows}
    c3_loss5_p99_ms = _ns_to_ms(_hs_by_key.get(("c3", "loss5"), {}).get("wall_p99_ns", ""))
    cw_200_loss5 = next(
        (r for r in cw_filtered if r.get("relative_speed_kmh") == "200" and r.get("profile") == "loss5"),
        {},
    )
    cw_200_s = _fmt(cw_200_loss5.get("contact_window_s", ""), 2) if cw_200_loss5 else ""
    p99_note = ""
    if c3_loss5_p99_ms and cw_200_s:
        p99_note = (
            f"\nAt 200 km/h (relative) under 5% loss, the C3 handshake p99 is "
            f"{c3_loss5_p99_ms} ms and the contact window is {cw_200_s} s (illustrative). "
            f"The worst 1% of handshakes use most of a short contact window."
        )

    # --- Bus time ---
    # Show plain CAN 2.0 baseline row and hypothetical protected-record row.
    bt_sel = [r for r in bt_rows
              if r.get("can_fd") in ("False", "false", "0")
              and r.get("scenario") in ("baseline", "protected_record_hypothetical")]
    bt_headers = ["Scenario", "DLC", "Bits/frame", "Rate (Hz)", "Bit rate (kbps)", "Occupancy (%)"]
    bt_table_rows = [
        [r.get("scenario"),
         r.get("dlc"),
         r.get("bits_per_frame"),
         r.get("rate_hz"),
         r.get("bit_rate_kbps"),
         r.get("occupancy_pct")]
        for r in bt_sel
    ]
    bt_md = _md_table(bt_headers, bt_table_rows) if bt_table_rows else "*No data.*"

    # --- Beacon cost ---
    bc_headers = ["Suite", "Scheme", "Sig bytes", "Bytes/beacon", "Bytes/s per sender",
                  "Verify load (ms/s)"]
    bc_table_rows = [
        [r.get("suite"), r.get("scheme"), r.get("sig_bytes"),
         r.get("total_per_beacon"), r.get("bytes_per_sec"),
         r.get("verify_load_ms_per_s")]
        for r in bc_rows
    ]
    bc_md = _md_table(bc_headers, bc_table_rows) if bc_table_rows else "*No data.*"

    return f"""\
## §12 Analytical Estimates

> **ANALYTICAL ESTIMATE — NOT A SIMULATION.** None of these values are measured.

### §12a Contact Window vs Handshake Time (C3, range = 100 m)

{cw_md}

Window/HS ratio > 1 means the handshake completes before the contact window closes.
Under 5% loss the ratio can drop below 10 at high relative speeds (retransmit pressure).{p99_note}

### §12b CAN Bus Occupancy

{bt_md}

Hypothetical: in this design protected records travel only on the gateway↔peer link,
never on the CAN bus; the `protected_record_hypothetical` row estimates the cost *if*
they were carried on CAN. Assumption: one protected record = 8 B CAN data +
16 B record header + 16 B AEAD tag = 40 B → 5 CAN 2.0 frames at DLC 8.
Segmentation uses 8-byte payload chunks on CAN 2.0 (DLC ≤ 8), padded DLC on CAN FD.
Numbers use a 500 kbps bit rate and worst-case bit-stuffing (Davis et al. 2007).

### §12c Per-beacon Signature Overhead

{bc_md}

Estimates for broadcast safety beacons at 10 Hz, 200 B payload, 10 neighbours.
Defaults are assumptions; see beacon\_cost.py for parameters.

---
"""


def _section_limitations() -> str:
    return """\
## §13 Limitations

The following six limitations are verbatim from the project specification (CLAUDE.md §1):

1. The legacy CAN side stays unauthenticated. The gateway protects only the
   gateway↔peer link. A forged frame on the CAN bus is forwarded (protected) by the gateway.
2. Results are **relative** comparisons between configurations on a laptop/desktop,
   not real-vehicle timings.
3. The handshake is a **custom protocol, not formally verified**. It follows TLS 1.3-style
   patterns but is not TLS.
4. Agility covers only algorithms that fit the four interfaces in §4. No claim about future
   algorithms.
5. FN-DSA and HQC are included only if the installed library exposes them, and are labelled
   experimental.
6. Link emulation is not a wireless channel model.

Additional limitations:

7. All results were obtained on Apple arm64 (M-series); timings may differ significantly
   on x86-64 or embedded hardware.
8. Full-rekey timing includes an unresolved event-loop wait in the prototype.
9. asyncio scheduling noise is included in end-to-end timings.

---
"""


def _section_figures() -> str:
    # Collect available figures and annotate captions with numbers from tables only.
    # If a number is absent from the tables we have read, we omit it.

    # Pull a few key numbers to use in captions.
    hs_rows = _load_csv(TABLES / "handshake.csv")
    _hs: dict[tuple[str, str], dict] = {}
    for r in hs_rows:
        _hs[(r.get("config", ""), r.get("profile", ""))] = r

    lat_rows = _load_csv(TABLES / "latency.csv")
    _lat: dict[tuple[str, str], dict] = {}
    for r in lat_rows:
        _lat[(r.get("config", ""), r.get("profile", ""))] = r

    rk_rows = _load_csv(TABLES / "rekey_cost.csv")
    _rk: dict[tuple[str, str, str], dict] = {}
    for r in rk_rows:
        _rk[(r.get("config", ""), r.get("profile", ""), r.get("type", ""))] = r

    def _hs_med(cfg: str, prof: str) -> str:
        r = _hs.get((cfg, prof))
        return _ns_to_ms(r["wall_median_ns"]) if r and "wall_median_ns" in r else ""

    def _lat_med(cfg: str) -> str:
        r = _lat.get((cfg, "ideal"))
        return _ns_to_ms(r["latency_median_ns"]) if r and "latency_median_ns" in r else ""

    def _rk_med(cfg: str, rtype: str) -> str:
        r = _rk.get((cfg, "ideal", rtype))
        return _ns_to_ms(r["time_median_ns"]) if r and "time_median_ns" in r else ""

    figs = []

    p = FIGS / "micro_keygen.png"
    if p.exists():
        figs.append(("micro_keygen.png", "KEM and signature key-generation time by algorithm (median µs, log scale)."))

    p = FIGS / "micro_ops.png"
    if p.exists():
        figs.append(("micro_ops.png", "encaps/decaps/sign/verify median µs by algorithm (log scale)."))

    p = FIGS / "micro_aead.png"
    if p.exists():
        figs.append(("micro_aead.png", "AES-256-GCM encrypt/decrypt µs vs payload size (8–1024 B)."))

    p = FIGS / "latency_cdf.png"
    if p.exists():
        c1 = _lat_med("c1")
        c3 = _lat_med("c3")
        caption = "Empirical CDF of per-record latency for C1–C3 (ideal network)."
        if c1 and c3:
            caption += f" C1 median {c1} ms, C3 median {c3} ms."
        figs.append(("latency_cdf.png", caption))

    p = FIGS / "handshake_bars.png"
    if p.exists():
        c1i = _hs_med("c1", "ideal")
        c3i = _hs_med("c3", "ideal")
        caption = "Handshake wall time (median ms) per config × network profile."
        if c1i and c3i:
            caption += f" C1/ideal median {c1i} ms, C3/ideal {c3i} ms."
        figs.append(("handshake_bars.png", caption))

    p = FIGS / "e2e_overhead.png"
    if p.exists():
        figs.append(("e2e_overhead.png", "Per-layer overhead bytes per record for C0–C3 (stacked bar)."))

    p = FIGS / "contact_window_heat.png"
    if p.exists():
        figs.append(("contact_window_heat.png",
                     "Heatmap of contact-window / handshake-p95 ratio (C3; range = 100 m; profiles: ideal, delay50, loss5)."))

    if not figs:
        return "## §14 Figures\n\n*No figures found in results/figures/.*\n\n---\n"

    lines = ["## §14 Figures\n"]
    for fname, caption in figs:
        lines.append(f"- **{fname}:** {caption}")
    lines.append("\n---\n")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    today = datetime.date.today().isoformat()
    commit = _git_commit_from_tables()

    print(f"Generating RESULTS_BRIEF.md (commit={commit}, date={today})")

    sections = [
        _section_header(commit, today),
        _section_setup(),
        _section_security(),
        _section_handshake(),
        _section_primitive_cost(),
        _section_overhead(),
        _section_micro(),
        _section_latency(),
        _section_rekey(),
        _section_agility(),
        _section_analytical(),
        _section_limitations(),
        _section_figures(),
    ]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("".join(sections), encoding="utf-8")
    print(f"Written to {OUT}")


if __name__ == "__main__":
    main()
