#!/usr/bin/env python3
"""Generate results/tables/security_t1_t13.csv from the security test suite.

Runs pytest tests/security/ --junitxml, parses the XML with xml.etree.ElementTree,
and writes a table where each cell shows "expected ✓", "unexpected ✗", "n/a", or
"mechanism_absent".

Expected outcomes per §9 of CLAUDE.md:

  Test  C0            C1 / C2 / C3
  T1    accepted ✓    rejected ✓
  T2    accepted ✓    rejected ✓
  T3    accepted ✓    rejected ✓
  T4    n/a           aborts ✓
  T5    n/a           fails ✓
  T6    n/a           aborts ✓
  T7    n/a           accepted/rejected ✓
  T8    n/a           survives/rejects ✓
  T9    n/a           no reuse ✓
  T10   n/a           rekey/close ✓
  T11   n/a           rejected ✓
  T12   forwarded ✓   forwarded ✓
  T13   n/a           fails ✓

"accepted ✓" means the test asserts the attack SUCCEEDS (confirmed vulnerability);
the test passes on C0 by asserting that outcome.

Usage:
    python scripts/make_security_table.py [--no-slow]
"""

from __future__ import annotations

import argparse
import csv
import os
import platform
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
RESULTS_DIR = REPO_ROOT / "results" / "tables"
VENV_PYTEST = REPO_ROOT / ".venv" / "bin" / "pytest"


# ---------------------------------------------------------------------------
# §9 expected outcome map
# ---------------------------------------------------------------------------

# T_ID → (c0_expected_description, c1_c2_c3_expected_description, c0_na)
# c0_na=True means T is "n/a" for C0 per §9.
_EXPECTED = {
    "T1":  ("accepted",   "rejected",  False),
    "T2":  ("accepted",   "rejected",  False),
    "T3":  ("accepted",   "rejected",  False),
    "T4":  ("n/a",        "aborts",    True),
    "T5":  ("n/a",        "fails",     True),
    "T6":  ("n/a",        "aborts",    True),
    "T7":  ("n/a",        "rejects",   True),
    "T8":  ("n/a",        "survives",  True),
    "T9":  ("n/a",        "no-reuse",  True),
    "T10": ("n/a",        "rekeys",    True),
    "T11": ("n/a",        "rejected",  True),
    "T12": ("forwarded",  "forwarded", False),
    "T13": ("n/a",        "fails",     True),
}

# Map test method name prefixes → T-IDs
_METHOD_TO_T: dict[str, str] = {
    "test_t1_": "T1",
    "test_t2_": "T2",
    "test_t3_": "T3",
    "test_t4_": "T4",
    "test_t5_": "T5",
    "test_t6_": "T6",
    "test_t7_": "T7",
    "test_t8_": "T8",
    "test_t9_": "T9",
    "test_t10_": "T10",
    "test_t11_": "T11",
    "test_t12_": "T12",
    "test_t13_": "T13",
}

# Map pytest parametrize suite names → config column
_SUITE_TO_CONFIG: dict[str, str] = {
    "classical": "C1",
    "pqc": "C2",
    "hybrid": "C3",
    # matrix/base has suite_id==3 (same as C3) but is a separate parametrize variant
    "matrix-base": "matrix-base",
    "c0": "C0",
    "c1": "C1",
    "c2": "C2",
    "c3": "C3",
}


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


def _liboqs_version() -> str:
    try:
        sys.path.insert(0, str(REPO_ROOT / "src"))
        oqs_install = os.environ.get("OQS_INSTALL_PATH", str(REPO_ROOT / ".oqs"))
        os.environ.setdefault("OQS_INSTALL_PATH", oqs_install)
        import oqs
        return str(oqs.__version__) if hasattr(oqs, "__version__") else "unknown"
    except Exception:
        return "unknown"


def _run_security_tests(xml_path: Path, no_slow: bool) -> int:
    cmd = [str(VENV_PYTEST), "tests/security/", f"--junitxml={xml_path}", "-v"]
    if no_slow:
        cmd += ["-m", "not slow"]
    env = {**os.environ, "OQS_INSTALL_PATH": str(REPO_ROOT / ".oqs")}
    result = subprocess.run(cmd, cwd=REPO_ROOT, env=env, timeout=3600)
    return result.returncode


def _parse_xml(xml_path: Path):
    """Parse JUnit XML → list of (classname, name, status, suite_name, t_id)."""
    if not xml_path.exists():
        return []

    tree = ET.parse(xml_path)
    root = tree.getroot()
    parsed = []

    for tc in root.iter("testcase"):
        classname = tc.get("classname", "")
        name = tc.get("name", "")

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

        # Identify T-ID from method name
        t_id = None
        for prefix, tid in _METHOD_TO_T.items():
            if prefix in name:
                t_id = tid
                break

        # Identify config from parametrize suffix
        # e.g. "test_t1_replay_rejected[classical]" → suite_name = "classical"
        suite_name = None
        if "[" in name and name.endswith("]"):
            param = name[name.rfind("[") + 1:-1]
            # matrix entry params look like "matrix/k-512" → "matrix-k-512"
            param = param.replace("/", "-")
            suite_name = param

        parsed.append({
            "classname": classname,
            "name": name,
            "status": status,
            "t_id": t_id,
            "suite_name": suite_name,
        })

    return parsed


def _config_from_suite(suite_name: Optional[str]) -> str:
    if suite_name is None:
        return "unknown"
    return _SUITE_TO_CONFIG.get(suite_name, suite_name)


# ---------------------------------------------------------------------------
# Build the summary table
# ---------------------------------------------------------------------------

def _cell(
    t_id: str,
    config: str,
    status: str,
) -> str:
    """Return the table cell content."""
    if status == "mechanism_absent":
        return "mechanism_absent"
    if status == "skipped":
        return "skipped"

    if config == "C0":
        c0_expected, _, c0_na = _EXPECTED.get(t_id, ("?", "?", False))
        if c0_na:
            return "n/a"
        # C0 test passes when the attack is confirmed accepted/forwarded
        expected_desc = c0_expected
        return f"{expected_desc} ✓" if status == "passed" else f"{expected_desc} ✗"
    else:
        _, c1_expected, _ = _EXPECTED.get(t_id, ("?", "?", False))
        return f"{c1_expected} ✓" if status == "passed" else f"{c1_expected} ✗"


def _build_table(parsed: list[dict]) -> dict:
    """Build {(t_id, config): [cell_values]} from parsed test cases."""
    table: dict[tuple[str, str], list[str]] = {}

    for tc in parsed:
        t_id = tc["t_id"]
        if t_id is None:
            continue
        suite_name = tc["suite_name"]
        config = _config_from_suite(suite_name)
        status = tc["status"]

        key = (t_id, config)
        cell = _cell(t_id, config, status)
        table.setdefault(key, []).append(cell)

    # Collapse multiple tests per (t_id, config) to a single cell
    collapsed: dict[tuple[str, str], str] = {}
    for key, cells in table.items():
        # If all cells agree, use the common value; else report any failure
        unique = set(cells)
        if len(unique) == 1:
            collapsed[key] = unique.pop()
        elif any("✗" in c for c in cells):
            collapsed[key] = next(c for c in cells if "✗" in c)
        else:
            collapsed[key] = cells[0]

    return collapsed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

from typing import Optional


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate security T1–T13 table")
    parser.add_argument("--no-slow", action="store_true",
                        help="Skip @pytest.mark.slow tests")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    xml_path = RESULTS_DIR / "security_tests.xml"

    print("Running security tests...")
    t0 = time.perf_counter()
    _run_security_tests(xml_path, args.no_slow)
    t1 = time.perf_counter()
    print(f"Done in {t1 - t0:.1f}s")

    parsed = _parse_xml(xml_path)

    # Determine all configs seen
    configs_seen = sorted({
        _config_from_suite(tc["suite_name"])
        for tc in parsed
        if tc["t_id"] is not None
    }, key=lambda c: (
        ["C0", "C1", "C2", "C3"].index(c) if c in ["C0", "C1", "C2", "C3"] else 99,
        c,
    ))

    table = _build_table(parsed)

    # Write CSV
    csv_path = RESULTS_DIR / "security_t1_t13.csv"

    env_rows = [
        ["# python_version", sys.version.replace("\n", " ")],
        ["# os", platform.platform()],
        ["# cpu", platform.processor() or platform.machine()],
        ["# liboqs_version", _liboqs_version()],
        ["# git_commit", _git_commit()],
        ["# timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())],
        ["# no_slow", str(args.no_slow)],
        ["#"],
        ["# Legend: 'expected ✓' = test passed with expected outcome;",
         "'expected ✗' = test failed or unexpected outcome;",
         "'n/a' = test not applicable for this config (see §9);",
         "'mechanism_absent' = mechanism not in installed liboqs."],
        ["# C0 tests for T1/T2/T3/T12: 'accepted ✓' means attack succeeded",
         "(vulnerability confirmed, not a failure — expected per §9)"],
        ["#"],
    ]

    t_ids = list(_EXPECTED.keys())
    header = ["test"] + configs_seen

    with open(csv_path, "w", newline="") as fh:
        writer = csv.writer(fh)
        for row in env_rows:
            writer.writerow(row)
        writer.writerow(header)
        for t_id in t_ids:
            row = [t_id]
            for config in configs_seen:
                cell = table.get((t_id, config), "not_run")
                row.append(cell)
            writer.writerow(row)

    print(f"\nSecurity table written to: {csv_path}")

    # Print a human-readable preview
    print(f"\n{'Test':<6}", end="")
    for c in configs_seen:
        print(f"  {c:<22}", end="")
    print()
    print("-" * (6 + 24 * len(configs_seen)))
    for t_id in t_ids:
        print(f"{t_id:<6}", end="")
        for config in configs_seen:
            cell = table.get((t_id, config), "not_run")
            print(f"  {cell:<22}", end="")
        print()


if __name__ == "__main__":
    main()
