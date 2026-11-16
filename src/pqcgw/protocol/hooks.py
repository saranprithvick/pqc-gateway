"""CryptoHook: optional measurement instrumentation for crypto operations.

A NullCryptoHook (default) has zero overhead on the hot path.
A SummingHook accumulates total crypto time for benchmarking.

Usage:
    hook = SummingHook()
    initiator = HandshakeInitiator(suite, identity, crypto_hook=hook)
    # ... run handshake ...
    total_ns = hook.total_ns  # CPU thread-time (not inflated by OS preemption)
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
    """Accumulates total crypto CPU time across all labelled operations.

    Uses time.thread_time_ns() so OS preemption of the event-loop thread
    does not inflate the measurement (wall-clock perf_counter_ns() was
    inflated by ~2 ms per handshake by scheduler preemption in asyncio
    context even though no await spans the before/after brackets).

    Thread-safety: not thread-safe; use one instance per session.
    Measurement overhead: ~100 ns per call pair on modern hardware.
    """

    def __init__(self) -> None:
        self._total_ns: int = 0           # CPU thread-time accumulated
        self._total_wall_ns: int = 0      # wall-clock accumulated (for reference)
        self._wall_start: int = 0
        self._counts: dict[str, int] = {}
        self._per_label_ns: dict[str, int] = {}

    def before_crypto(self, label: str) -> int:
        self._wall_start = time.perf_counter_ns()
        return time.thread_time_ns()

    def after_crypto(self, label: str, start_ns: int) -> None:
        thread_elapsed = time.thread_time_ns() - start_ns
        wall_elapsed = time.perf_counter_ns() - self._wall_start
        self._total_ns += thread_elapsed
        self._total_wall_ns += wall_elapsed
        self._counts[label] = self._counts.get(label, 0) + 1
        self._per_label_ns[label] = self._per_label_ns.get(label, 0) + thread_elapsed

    @property
    def total_ns(self) -> int:
        """Total CPU thread-time across all hooked operations (ns)."""
        return self._total_ns

    @property
    def total_wall_ns(self) -> int:
        """Total wall-clock time across all hooked operations (ns).

        Included for reference; inflated by OS scheduler preemption in asyncio
        context.  Use total_ns (thread-time) for fair crypto comparisons.
        """
        return self._total_wall_ns

    @property
    def counts(self) -> dict[str, int]:
        return dict(self._counts)

    @property
    def per_label_ns(self) -> dict[str, int]:
        """CPU thread-time per label (ns)."""
        return dict(self._per_label_ns)

    def reset(self) -> None:
        self._total_ns = 0
        self._total_wall_ns = 0
        self._counts.clear()
        self._per_label_ns.clear()
