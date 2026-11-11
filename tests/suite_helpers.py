"""Shared suite-name constants and path helpers used by security and agility tests."""

from __future__ import annotations

from pathlib import Path

SUITE_DIR = Path(__file__).parent.parent / "configs" / "suites"

STANDARD_SUITES = ["classical", "pqc", "hybrid"]

MATRIX_NON_EXP = [
    "matrix/base",
    "matrix/k-512",
    "matrix/k-768",
    "matrix/k-1024",
    "matrix/s-44",
    "matrix/s-87",
    "matrix/s-slh",
    "matrix/s-ecdsa",
    "matrix/d-384",
    "matrix/a-128",
    "matrix/a-cha",
]

MATRIX_EXPERIMENTAL = [
    "matrix/x-hqc3",
    "matrix/x-falcon512",
]

ALL_MATRIX_SUITES = MATRIX_NON_EXP + MATRIX_EXPERIMENTAL

ALL_SUITES_FOR_SECURITY = STANDARD_SUITES + MATRIX_NON_EXP + MATRIX_EXPERIMENTAL

ALL_SUITE_IDS = [1, 2, 3, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]


def suite_path(name: str) -> Path:
    """Resolve a suite short-name to its TOML path.

    "classical"     → configs/suites/classical.toml
    "matrix/k-512"  → configs/suites/matrix/k-512.toml
    """
    if name.startswith("matrix/"):
        entry_id = name[len("matrix/"):]
        return SUITE_DIR / "matrix" / f"{entry_id}.toml"
    return SUITE_DIR / f"{name}.toml"
