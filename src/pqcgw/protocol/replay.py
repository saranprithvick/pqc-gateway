"""Sliding-window replay filter for the record layer.

One ReplayWindow instance is used per (direction, epoch).  It tracks which
counters have been accepted and rejects duplicates and out-of-window counters.

Algorithm (§5.6):
  - highest_seen: the largest counter accepted so far (-1 initially).
  - bitmap: a bitmask of width `window_size`.  Bit i is set if
    counter (highest_seen - i) has been accepted.
  - counter > highest_seen: new high-water mark — slide the window and accept.
  - counter <= highest_seen - window_size: too old — ReplayError.
  - Otherwise: check bit; accept if not yet seen, else ReplayError.

check(counter) validates without mutating state.
mark(counter) records acceptance; MUST be called only after successful
  decryption to avoid mutating state on a forgery.
"""

from __future__ import annotations


class ReplayError(Exception):
    """Raised when a counter is a duplicate or outside the replay window."""


class ReplayWindow:
    """Sliding bitmap replay window (default width 64)."""

    def __init__(self, window_size: int = 64) -> None:
        if window_size < 1:
            raise ValueError("window_size must be >= 1")
        self._size = window_size
        self._highest: int = -1   # highest counter seen so far
        self._bitmap: int = 0     # bit i set means (highest - i) was seen

    # -- public API ----------------------------------------------------------

    def check(self, counter: int) -> None:
        """Validate counter without mutating state.

        Raises ReplayError if the counter is a duplicate or too old.
        Does NOT mark the counter as seen.
        """
        if counter < 0:
            raise ReplayError(f"Negative counter: {counter}")
        if self._highest == -1:
            return  # first record ever — always accept
        if counter > self._highest:
            return  # new highest — accept
        diff = self._highest - counter
        if diff >= self._size:
            raise ReplayError(
                f"Counter {counter} is outside the replay window "
                f"(highest={self._highest}, window={self._size})"
            )
        if (self._bitmap >> diff) & 1:
            raise ReplayError(f"Duplicate counter {counter}")

    def mark(self, counter: int) -> None:
        """Record counter as accepted.  Call only after successful decryption.

        check() must have been called (and passed) for this counter before mark().
        """
        if counter > self._highest:
            # Slide the bitmap to account for the new high-water mark
            shift = counter - self._highest
            self._bitmap = (self._bitmap << shift) & ((1 << self._size) - 1)
            self._highest = counter
            # Mark bit 0 (the current highest)
            self._bitmap |= 1
        else:
            diff = self._highest - counter
            self._bitmap |= (1 << diff)
