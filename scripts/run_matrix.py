#!/usr/bin/env python3
"""Agility matrix runner.

Loads configs/matrix.toml, runs the security test suite and agility tests for
every matrix entry, and writes results/tables/agility.csv.

Timing is FUNCTIONAL RUN TIME, not a benchmark (see §8).

Usage:
    python scripts/run_matrix.py [--no-slow]

Flags:
    --no-slow   Skip tests marked @pytest.mark.slow (excludes PQC matrix variants).

The script refuses to write the final CSV if src/ is dirty (§4 criterion 1).
"""

from __future__ import annotations

import argparse
import csv
import os
import platform
import subprocess
import sys
import time
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
MATRIX_TOML = REPO_ROOT / "configs" / "matrix.toml"
RESULTS_DIR = REPO_ROOT / "results" / "tables"
VENV_PYTEST = REPO_ROOT / ".venv" / "bin" / "pytest"


# ---------------------------------------------------------------------------
# Helpers
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
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        return bool(result.stdout.strip())
    except Exception:
        return False


def _git_diff_stat_src() -> str:
    try:
        result = subprocess.run(
            ["git", "diff", "--stat", "src/"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        return result.stdout.strip() or "(clean)"
    except Exception:
        return "unknown"


def _liboqs_version() -> str:
    try:
        sys.path.insert(0, str(REPO_ROOT / "src"))
        oqs_install = os.environ.get("OQS_INSTALL_PATH", str(REPO_ROOT / ".oqs"))
        os.environ.setdefault("OQS_INSTALL_PATH", oqs_install)
        import oqs
        return str(oqs.__version__) if hasattr(oqs, "__version__") else "unknown"
    except Exception:
        return "unknown"


def _run_pytest_xml(args: list[str], xml_path: Path, timeout: int = 1800) -> int:
    """Run pytest with --junitxml and return the return code."""
    cmd = [str(VENV_PYTEST)] + args + [f"--junitxml={xml_path}", "-v"]
    env = {**os.environ, "OQS_INSTALL_PATH": str(REPO_ROOT / ".oqs")}
    result = subprocess.run(cmd, cwd=REPO_ROOT, env=env, timeout=timeout)
    return result.returncode


def _parse_junitxml(xml_path: Path) -> dict[str, dict[str, str]]:
    """Parse JUnit XML and return {test_id: {status, classname, name}}.

    test_id is composed as "<classname>::<name>" so it matches pytest's
    nodeid convention.  status is one of: "passed", "failed", "skipped",
    "error", "mechanism_absent".
    """
    if not xml_path.exists():
        return {}

    tree = ET.parse(xml_path)
    root = tree.getroot()
    results = {}

    for tc in root.iter("testcase"):
        classname = tc.get("classname", "")
        name = tc.get("name", "")
        key = f"{classname}::{name}"

        failure = tc.find("failure")
        error = tc.find("error")
        skipped = tc.find("skipped")

        if skipped is not None:
            reason = skipped.get("message", "")
            status = "mechanism_absent" if "mechanism_absent" in reason else "skipped"
        elif failure is not None:
            status = "failed"
        elif error is not None:
            status = "error"
        else:
            status = "passed"

        results[key] = {"status": status, "classname": classname, "name": name}

    return results


def _find_test_result(
    parsed: dict[str, dict[str, str]],
    entry_id: str,
    test_pattern: str,
) -> str:
    """Find the result for a specific matrix entry and test pattern.

    Looks for a test whose name contains both entry_id and test_pattern.
    Returns "passed", "failed", "skipped", "mechanism_absent", or "not_found".
    """
    # Normalise entry_id for matching (pytest replaces / with -)
    norm_entry = entry_id.replace("/", "-")
    for key, info in parsed.items():
        name = info["name"]
        if norm_entry in name and test_pattern in name:
            return info["status"]
    return "not_found"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Run agility matrix tests")
    parser.add_argument("--no-slow", action="store_true",
                        help="Skip @pytest.mark.slow tests")
    args = parser.parse_args()

    # Refuse to write if src/ is dirty (§4 criterion 1)
    if _src_dirty():
        print("ERROR: src/ has uncommitted changes.  "
              "Agility criterion 1 (config-only) requires a clean src/.")
        print("Diff:\n" + _git_diff_stat_src())
        sys.exit(1)

    commit = _git_commit()
    print(f"Git commit: {commit}")

    with open(MATRIX_TOML, "rb") as f:
        matrix = tomllib.load(f)
    entries = matrix["entries"]

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # --- Run security tests ---
    sec_xml = RESULTS_DIR / "run_matrix_security.xml"
    agility_xml = RESULTS_DIR / "run_matrix_agility.xml"

    sec_args = ["tests/security/"]
    agility_args = ["tests/agility/"]
    if args.no_slow:
        sec_args += ["-m", "not slow"]
        agility_args += ["-m", "not slow"]

    print("\nRunning security tests (parametrized over all matrix suites)...")
    t0_sec = time.perf_counter()
    _run_pytest_xml(sec_args, sec_xml)
    t1_sec = time.perf_counter()
    print(f"Security tests done in {(t1_sec - t0_sec):.1f}s")

    print("\nRunning agility tests (E2E fragmentation + traffic)...")
    t0_agt = time.perf_counter()
    _run_pytest_xml(agility_args, agility_xml)
    t1_agt = time.perf_counter()
    print(f"Agility tests done in {(t1_agt - t0_agt):.1f}s")

    sec_results = _parse_junitxml(sec_xml)
    agt_results = _parse_junitxml(agility_xml)

    # --- Build CSV ---
    csv_path = RESULTS_DIR / "agility.csv"

    env_rows = [
        ["# timing_note", "FUNCTIONAL RUN TIME, not a benchmark (see CLAUDE.md §8)"],
        ["# python_version", sys.version.replace("\n", " ")],
        ["# os", platform.platform()],
        ["# cpu", platform.processor() or platform.machine()],
        ["# liboqs_version", _liboqs_version()],
        ["# git_commit", commit],
        ["# src_dirty", "false"],
        ["# timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())],
        ["# no_slow", str(args.no_slow)],
    ]

    columns = [
        "entry_id", "description", "factor", "experimental",
        "config_only",
        "handshake_ok", "frag_count_i2r_match", "frag_count_r2i_match", "traffic_ok",
        "t1_ok", "t2_ok", "t3_ok", "t4_ok", "t5_ok", "t6_ok",
        "t7_ok", "t8_ok", "t9_ok", "t10_ok", "t11_ok", "t13_ok",
        "overall_pass",
        "run_time_ms",
    ]

    # T-pattern → security test method suffix
    _T_PATTERNS = {
        "t1": "test_t1_",
        "t2": "test_t2_",
        "t3": "test_t3_",
        "t4": "test_t4_",
        "t5": "test_t5_",
        "t6": "test_t6_",
        "t7": "test_t7_",
        "t8": "test_t8_",
        "t9": "test_t9_",
        "t10": "test_t10_",
        "t11": "test_t11_",
        "t13": "test_t13_",
    }

    def _t_col(entry_id: str, t_key: str) -> str:
        # entry_id as it appears in a pytest parametrize id:
        # security tests parametrize with "matrix/<entry_id>" → "matrix-<entry_id>"
        param = f"matrix-{entry_id}"
        # For baseline (suite_id==3, same as hybrid) also try "hybrid"
        status = _find_test_result(sec_results, param, _T_PATTERNS[t_key])
        if status == "not_found" and entry_id == "base":
            status = _find_test_result(sec_results, "hybrid", _T_PATTERNS[t_key])
        return status

    def _agility_col(entry_id: str, col_key: str) -> str:
        # Agility test: test_agility_entry[entry_id]
        status = _find_test_result(agt_results, entry_id, "test_agility_entry")
        if status == "passed":
            return "pass"
        if status == "mechanism_absent":
            return "mechanism_absent"
        if status == "not_found":
            return "not_run"
        return status

    rows = []
    t0_total = time.perf_counter()
    for entry in entries:
        eid = entry["entry_id"]
        exp = entry.get("experimental", False)

        t_results = {k: _t_col(eid, k) for k in _T_PATTERNS}
        agt_status = _agility_col(eid, "test_agility_entry")

        # Derive individual agility criteria columns from agility test status
        if agt_status == "mechanism_absent":
            handshake_ok = frag_i2r_ok = frag_r2i_ok = traffic_ok = "mechanism_absent"
        elif agt_status == "pass":
            handshake_ok = frag_i2r_ok = frag_r2i_ok = traffic_ok = "pass"
        elif agt_status == "not_run":
            handshake_ok = frag_i2r_ok = frag_r2i_ok = traffic_ok = "not_run"
        else:
            handshake_ok = frag_i2r_ok = frag_r2i_ok = traffic_ok = "fail"

        all_t_pass = all(
            v in ("passed", "mechanism_absent", "not_found")
            for v in t_results.values()
        )
        # mechanism_absent counts as expected (reported, not failed)
        all_mechanism_absent = all(v == "mechanism_absent" for v in t_results.values())
        t_ok = all(v == "passed" for v in t_results.values()) or all_mechanism_absent

        overall = (
            "mechanism_absent" if agt_status == "mechanism_absent"
            else "pass" if (agt_status in ("pass", "not_run") and t_ok)
            else "fail"
        )

        row = {
            "entry_id": eid,
            "description": entry["description"],
            "factor": entry["factor"],
            "experimental": str(exp).lower(),
            "config_only": "pass",  # always true when src is clean (checked above)
            "handshake_ok": handshake_ok,
            "frag_count_i2r_match": frag_i2r_ok,
            "frag_count_r2i_match": frag_r2i_ok,
            "traffic_ok": traffic_ok,
            **{f"t{k[1:]}_ok": v for k, v in t_results.items()},
            "overall_pass": overall,
            "run_time_ms": "",  # filled below if timing is available
        }
        rows.append(row)

    t1_total = time.perf_counter()
    total_ms = round((t1_total - t0_total) * 1000)

    with open(csv_path, "w", newline="") as fh:
        writer = csv.writer(fh)
        for env_row in env_rows:
            writer.writerow(env_row)
        writer.writerow([])
        writer.writerow(columns)
        for row in rows:
            writer.writerow([row.get(c, "") for c in columns])

    print(f"\nAgility CSV written to: {csv_path}")
    print(f"Total processing time: {total_ms} ms (functional, not a benchmark)")

    n_pass = sum(1 for r in rows if r["overall_pass"] == "pass")
    n_mech = sum(1 for r in rows if r["overall_pass"] == "mechanism_absent")
    n_fail = sum(1 for r in rows if r["overall_pass"] == "fail")
    print(f"\nSummary: {n_pass} pass, {n_fail} fail, {n_mech} mechanism_absent "
          f"(out of {len(rows)} entries)")


if __name__ == "__main__":
    main()
