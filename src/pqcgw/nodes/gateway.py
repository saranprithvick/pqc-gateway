"""Gateway: async session initiator.

Drives the full lifecycle:
  1. Handshake (HELLO_I / HELLO_R / FINISHED_I / FINISHED_R)
     with HELLO_I exponential-backoff retransmit and FINISHED_I retransmit.
  2. §15 item 20: CAN frames are buffered into _pre_session_buf while awaiting
     FINISHED_R; flushed after the session is established; discarded on failure.
  3. Bidirectional data forwarding:
     I2R: read CAN frame → seal → send over link
     R2I: receive from link → open → write decoded frame to CAN
  4. CounterExhausted: frame buffered in _pending (bounded queue, §15 item 20);
     REKEY_REQ queued by SessionManager and sent.  Flush path added in M5b.

M5a does NOT wire rekey triggers or the REKEY_ACK flush path; those are added in M5b.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Iterable, Optional

from pqcgw.crypto.registry import Suite
from pqcgw.legacy.can_adapter import CanAdapter
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.link import Link
from pqcgw.nodes.adapter import MessageAdapter
from pqcgw.protocol.handshake import HandshakeError, HandshakeInitiator, IdentityContext
from pqcgw.protocol.record import Direction, RecordType
from pqcgw.protocol.session import (
    AlertError,
    CounterExhausted,
    RekeyConfig,
    SessionError,
    SessionManager,
    SessionRole,
)

log = logging.getLogger(__name__)

_PRE_SESSION_BUF_SIZE = 64  # §15 item 20
_PENDING_BUF_SIZE = 64       # CounterExhausted buffer (§15 item 20)


class Gateway:
    """Async handshake initiator and bidirectional CAN↔link forwarder."""

    def __init__(
        self,
        suite: Suite,
        identity: IdentityContext,
        can_adapter: CanAdapter,
        link: Link,
        rekey_config: Optional[RekeyConfig] = None,
        handshake_timeout_ms: int = 200,
        handshake_max_retries: int = 5,
    ) -> None:
        self._suite = suite
        self._identity = identity
        self._can = can_adapter
        self._link = link
        self._rekey_config = rekey_config
        self._hs_timeout_ms = handshake_timeout_ms
        self._hs_max_retries = handshake_max_retries

        self._sm: Optional[SessionManager] = None

        # §15 item 20 — pre-session CAN frame buffer
        self._pre_session_buf: deque[CANFrame] = deque(maxlen=_PRE_SESSION_BUF_SIZE)
        self._pre_session_drops: int = 0
        self._buffering: bool = False

        # CounterExhausted buffer (flushed in M5b after REKEY_ACK)
        self._pending: deque[CANFrame] = deque(maxlen=_PENDING_BUF_SIZE)
        self._pending_drops: int = 0

        # Instrumentation (item 18)
        self._hs_success: bool = False
        self._hs_retransmits: int = 0
        self._hs_start_ns: int = 0
        self._hs_end_ns: int = 0

    # ------------------------------------------------------------------
    # Properties (item 18)
    # ------------------------------------------------------------------

    @property
    def handshake_success(self) -> bool:
        return self._hs_success

    @property
    def handshake_retransmit_count(self) -> int:
        return self._hs_retransmits

    @property
    def handshake_duration_ns(self) -> int:
        return self._hs_end_ns - self._hs_start_ns

    @property
    def pre_session_drops(self) -> int:
        return self._pre_session_drops

    @property
    def pending_drops(self) -> int:
        return self._pending_drops

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------

    async def handshake(self) -> None:
        """Drive the 4-message handshake with exponential-backoff retransmit."""
        self._hs_start_ns = time.perf_counter_ns()
        initiator = HandshakeInitiator(self._suite, self._identity)
        hello_i = initiator.start()
        loop = asyncio.get_running_loop()

        # --- HELLO_I retransmit loop ---
        hello_r: Optional[bytes] = None
        for attempt in range(self._hs_max_retries + 1):
            await self._link.send(hello_i)
            if attempt > 0:
                self._hs_retransmits += 1
                log.debug("Gateway: retransmit HELLO_I attempt %d", attempt)
            timeout_s = (self._hs_timeout_ms / 1000.0) * (2 ** attempt)
            hello_r = await self._link.recv(timeout=timeout_s)
            if hello_r is not None:
                break
        else:
            raise HandshakeError("HELLO_R timeout after retransmits")

        finished_i = initiator.process_hello_r(hello_r)

        # --- §15 item 20: start buffering CAN frames ---
        self._buffering = True
        buf_task = loop.create_task(self._buffer_can())

        # --- FINISHED_I retransmit loop ---
        finished_r: Optional[bytes] = None
        try:
            for attempt in range(self._hs_max_retries + 1):
                await self._link.send(finished_i)
                if attempt > 0:
                    self._hs_retransmits += 1
                    log.debug("Gateway: retransmit FINISHED_I attempt %d", attempt)
                timeout_s = (self._hs_timeout_ms / 1000.0) * (2 ** attempt)
                finished_r = await self._link.recv(timeout=timeout_s)
                if finished_r is not None:
                    break
            else:
                raise HandshakeError("FINISHED_R timeout after retransmits")

            gw_keys = initiator.process_finished_r(finished_r)
            self._sm = SessionManager(
                self._suite,
                gw_keys,
                initiator.session_id,
                SessionRole.INITIATOR,
                config=self._rekey_config,
            )
            self._hs_success = True
            self._hs_end_ns = time.perf_counter_ns()
            log.debug(
                "Gateway: session established session_id=%s",
                initiator.session_id.hex(),
            )
        except Exception:
            self._pre_session_buf.clear()
            raise
        finally:
            self._buffering = False
            # Wait for the buffering task to finish its current recv() call naturally.
            # Cancelling immediately can cause the thread to consume a CAN frame from
            # the virtual bus without storing it in _pre_session_buf (the Future gets
            # cancelled but the thread already called bus.recv() and consumed the frame).
            # The task will exit within one receive timeout (0.05 s) once _buffering=False.
            if not buf_task.done():
                done, _ = await asyncio.wait({buf_task}, timeout=0.15)
                if not done:
                    buf_task.cancel()
                    try:
                        await buf_task
                    except (asyncio.CancelledError, Exception):
                        pass

    async def _buffer_can(self) -> None:
        """Read CAN frames into the pre-session buffer while _buffering is True."""
        loop = asyncio.get_running_loop()
        while self._buffering:
            frame = await loop.run_in_executor(None, self._can.receive, 0.05)
            if frame is not None:
                if len(self._pre_session_buf) == self._pre_session_buf.maxlen:
                    self._pre_session_drops += 1
                self._pre_session_buf.append(frame)

    # ------------------------------------------------------------------
    # Data-path helpers
    # ------------------------------------------------------------------

    async def send_frame(self, frame: CANFrame) -> None:
        """Encode → seal → send.  On CounterExhausted: buffer + send REKEY_REQ."""
        assert self._sm is not None
        encoded = MessageAdapter.encode(frame)
        try:
            wire = self._sm.seal(encoded)
        except CounterExhausted:
            if len(self._pending) == self._pending.maxlen:
                self._pending_drops += 1
            self._pending.append(frame)
            req = self._sm.take_outbound()
            if req is not None:
                await self._link.send(req)
            log.debug("Gateway: CounterExhausted — frame buffered (%d pending)", len(self._pending))
            return
        except AlertError as exc:
            log.error("Gateway: AlertError sealing frame: %s", exc)
            raise
        await self._link.send(wire)

    async def _handle_inbound(self, wire: bytes) -> None:
        """Open one inbound record; write DATA records to CAN; drain take_outbound()."""
        assert self._sm is not None
        try:
            rtype, payload = self._sm.open(wire, Direction.R2I)
        except Exception as exc:
            log.debug("Gateway: inbound record rejected: %s", exc)
            return
        if rtype == RecordType.DATA:
            try:
                frame = MessageAdapter.decode(payload)
                self._can.send(frame)
            except ValueError as exc:
                log.warning("Gateway: malformed reverse-path payload: %s", exc)
        # Drain any outbound control records (e.g. REKEY_ACK in M5b)
        while (out := self._sm.take_outbound()) is not None:
            await self._link.send(out)

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, n_frames: Optional[int] = None) -> None:
        """Handshake then bidirectionally forward frames.

        n_frames: stop after forwarding this many I2R frames (for tests).
        Pass None to run indefinitely (until error).
        """
        await self.handshake()

        # Flush pre-session buffer (§15 item 20); counts toward n_frames
        loop = asyncio.get_running_loop()
        frames_sent = 0
        for frame in list(self._pre_session_buf):
            await self.send_frame(frame)
            frames_sent += 1
        self._pre_session_buf.clear()

        while n_frames is None or frames_sent < n_frames:
            # I2R: CAN → peer
            frame = await loop.run_in_executor(None, self._can.receive, 0.01)
            if frame is not None:
                await self.send_frame(frame)
                frames_sent += 1

            # R2I: peer → CAN
            wire = await self._link.recv(timeout=0.01)
            if wire is not None:
                await self._handle_inbound(wire)
