"""CryptoHook: optional measurement instrumentation for crypto operations.

A NullCryptoHook (default) has zero overhead on the hot path.
A SummingHook accumulates total crypto time for benchmarking.

Usage:
    hook = SummingHook()
    initiator = HandshakeInitiator(suite, identity, crypto_hook=hook)
    # ... run handshake ...
    total_ns = hook.total_ns
"""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class CryptoHook(Protocol):
    """Interface for timing crypto operations."""

    def before_crypto(self, label: str) -> int:
        """Called immediately before a crypto operation; returns start timestamp (ns)."""
        ...

    def after_crypto(self, label: str, start_ns: int) -> None:
        """Called immediately after a crypto operation with the start timestamp."""
        ...


class NullCryptoHook:
    """No-op hook; zero measurement overhead on hot paths."""

    def before_crypto(self, label: str) -> int:
        return 0

    def after_crypto(self, label: str, start_ns: int) -> None:
        pass


class SummingHook:
    """Accumulates total crypto time across all labelled operations.

    Thread-safety: not thread-safe; use one instance per session.
    Measurement overhead: ~100 ns per call pair on modern hardware; document
    in docs/LIMITATIONS.md as a known measurement artefact.
    """

    def __init__(self) -> None:
        self._total_ns: int = 0
        self._counts: dict[str, int] = {}

    def before_crypto(self, label: str) -> int:
        return time.perf_counter_ns()

    def after_crypto(self, label: str, start_ns: int) -> None:
        elapsed = time.perf_counter_ns() - start_ns
        self._total_ns += elapsed
        self._counts[label] = self._counts.get(label, 0) + 1

    @property
    def total_ns(self) -> int:
        return self._total_ns

    @property
    def counts(self) -> dict[str, int]:
        return dict(self._counts)

    def reset(self) -> None:
        self._total_ns = 0
        self._counts.clear()
