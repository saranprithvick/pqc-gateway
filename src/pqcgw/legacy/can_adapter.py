"""CanAdapter: thin wrapper around a python-can virtual bus.

Uses the python-can 'virtual' interface (pure-Python, no OS setup) so tests
run on any platform.  Pass a unique channel string per test to avoid
cross-test contamination.
"""

from __future__ import annotations

import asyncio
import logging
from types import TracebackType
from typing import Optional

import can

from pqcgw.legacy.can_model import CANFrame, MSG_EFF_FLAG, MSG_FD_FLAG

log = logging.getLogger(__name__)


class CanAdapter:
    """Read and write CANFrames on a python-can virtual bus."""

    def __init__(self, channel: str = "vcan0", is_fd: bool = False) -> None:
        self._channel = channel
        self._is_fd = is_fd
        self._bus = can.Bus(interface="virtual", channel=channel, fd=is_fd)
        self._async_reader: Optional[can.AsyncBufferedReader] = None
        self._notifier: Optional[can.Notifier] = None

    # ------------------------------------------------------------------
    # Conversion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_msg(frame: CANFrame) -> can.Message:
        return can.Message(
            arbitration_id=frame.can_id,
            data=frame.data,
            is_extended_id=frame.is_extended,
            is_fd=frame.is_fd,
            check=True,
        )

    @staticmethod
    def _from_msg(msg: can.Message) -> CANFrame:
        from pqcgw.legacy.can_model import VALID_FD_LENGTHS

        is_fd = bool(msg.is_fd)
        dlc = len(msg.data) if msg.data is not None else 0
        data = bytes(msg.data) if msg.data is not None else b""

        # Validate on receive; malformed frames are dropped
        if is_fd and dlc not in VALID_FD_LENGTHS:
            raise ValueError(f"Received CAN FD frame with invalid dlc {dlc}")
        if not is_fd and dlc > 8:
            raise ValueError(f"Received CAN 2.0 frame with dlc {dlc} > 8")

        return CANFrame(
            can_id=msg.arbitration_id,
            dlc=dlc,
            data=data,
            is_fd=is_fd,
            is_extended=bool(msg.is_extended_id),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send(self, frame: CANFrame) -> None:
        """Send a CAN frame onto the bus."""
        msg = self._to_msg(frame)
        self._bus.send(msg)

    def receive(self, timeout: float = 0.1) -> Optional[CANFrame]:
        """Block for up to *timeout* seconds; return a frame or None."""
        msg = self._bus.recv(timeout=timeout)
        if msg is None:
            return None
        try:
            return self._from_msg(msg)
        except ValueError as exc:
            log.warning("Dropping malformed CAN message: %s", exc)
            return None

    def _ensure_async_reader(self) -> None:
        """Lazy-init the AsyncBufferedReader + Notifier for async receive.

        Must be called from within a running asyncio event loop.  Passing the
        running loop to Notifier causes _rx_thread to use call_soon_threadsafe,
        so AsyncBufferedReader.on_message_received (which calls put_nowait) runs
        in the asyncio thread rather than the Notifier background thread.
        """
        if self._async_reader is None:
            loop = asyncio.get_running_loop()
            self._async_reader = can.AsyncBufferedReader()
            self._notifier = can.Notifier(self._bus, [self._async_reader], timeout=0.1, loop=loop)

    async def recv_async(self) -> Optional[CANFrame]:
        """Return next CAN frame, waiting until one arrives (cancellation-safe).

        Lazy-inits the Notifier on first call.  Drops malformed frames and waits
        for the next one.  Respects asyncio task cancellation via the underlying
        asyncio.Queue.get() await.
        """
        self._ensure_async_reader()
        while True:
            msg = await self._async_reader.get_message()
            try:
                return self._from_msg(msg)
            except ValueError as exc:
                log.warning("Dropping malformed CAN message: %s", exc)

    def close(self) -> None:
        if self._notifier is not None:
            self._notifier.stop()
            self._notifier = None
        # Reset reader so a stale handle is not used if close() is called mid-use.
        self._async_reader = None
        self._bus.shutdown()

    # Context-manager support
    def __enter__(self) -> "CanAdapter":
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()
