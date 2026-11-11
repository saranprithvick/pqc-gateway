"""Top-level pytest fixtures shared across all test directories."""

from __future__ import annotations

import uuid

import pytest

# Re-export suite helpers so tests can also do `from conftest import …` if needed.
from tests.suite_helpers import (  # noqa: F401
    ALL_MATRIX_SUITES,
    ALL_SUITE_IDS,
    ALL_SUITES_FOR_SECURITY,
    MATRIX_EXPERIMENTAL,
    MATRIX_NON_EXP,
    STANDARD_SUITES,
    SUITE_DIR,
    suite_path,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def can_channel() -> str:
    """Return a unique python-can virtual bus channel name per test.

    Using a UUID prefix ensures no cross-test bus contamination.
    """
    return f"m5_{uuid.uuid4().hex[:8]}"
