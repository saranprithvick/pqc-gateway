"""Top-level pytest fixtures shared across all test directories."""

from __future__ import annotations

import uuid

import pytest


@pytest.fixture
def can_channel() -> str:
    """Return a unique python-can virtual bus channel name per test.

    Using a UUID prefix ensures no cross-test bus contamination.
    """
    return f"m5_{uuid.uuid4().hex[:8]}"
