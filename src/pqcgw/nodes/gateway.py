"""Gateway: async session initiator.

Drives the full lifecycle:
  1. Handshake (HELLO_I / HELLO_R / FINISHED_I / FINISHED_R)
     with HELLO_I exponential-backoff retransmit and FINISHED_I retransmit.
     All handshake messages carry a 1-byte type prefix (§15 item 22).
  2. §15 item 20: CAN frames are buffered into _pre_session_buf while awaiting
     FINISHED_R; flushed after the session is established; discarded on failure.
  3. Bidirectional data forwarding:
     I2R: read CAN frame → seal → send over link (prefixed with _T_DATA)
     R2I: receive from link → dispatch by prefix → open → write to CAN
  4. Light rekey triggers (time, record count, byte count), REKEY_REQ retransmit,
     and _pending flush after REKEY_ACK.
  5. Full rekey (§15 item 16): parallel session while old session carries traffic.
     Epoch-254 guard triggers full rekey before epoch limit is reached.

Prefix bytes (C1–C3 only; §15 item 22):
  _T_HELLO_I    = 0x01
  _T_HELLO_R    = 0x02
  _T_FINISHED_I = 0x03
  _T_FINISHED_R = 0x04
  _T_DATA       = 0x10

Drop counters:
  _malformed_drops       — message shorter than minimum or unknown type byte
  _unknown_session_drops — DATA record for unknown/expired session_id
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import replace
from typing import Optional

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
    RekeyState,
    RekeyTrigger,
    SessionError,
    SessionManager,
    SessionRole,
)

log = logging.getLogger(__name__)

# 1-byte type prefix (§15 item 22)
_T_HELLO_I    = 0x01
_T_HELLO_R    = 0x02
_T_FINISHED_I = 0x03
_T_FINISHED_R = 0x04
_T_DATA       = 0x10

# Minimum body lengths after prefix byte
_MIN_HS_BODY  = 6    # version + suite_id + session_id = 1+1+4
_MIN_DATA_BODY = 16  # record header

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
        trigger: Optional[RekeyTrigger] = None,
        full_rekey_max_attempts: int = 3,
        handshake_timeout_ms: int = 200,
        handshake_max_retries: int = 5,
    ) -> None:
        self._suite = suite
        self._identity = identity
        self._can = can_adapter
        self._link = link
        self._rekey_config = rekey_config
        self._trigger = trigger or RekeyTrigger()
        self._full_rekey_max_attempts = full_rekey_max_attempts
        self._hs_timeout_ms = handshake_timeout_ms
        self._hs_max_retries = handshake_max_retries

        self._sm: Optional[SessionManager] = None

        # §15 item 20 — pre-session CAN frame buffer
        self._pre_session_buf: deque[CANFrame] = deque(maxlen=_PRE_SESSION_BUF_SIZE)
        self._pre_session_drops: int = 0
        self._buffering: bool = False

        # CounterExhausted buffer (flushed after REKEY_ACK or full-rekey promote)
        self._pending: deque[CANFrame] = deque(maxlen=_PENDING_BUF_SIZE)
        self._pending_drops: int = 0

        # Full-rekey task state
        self._full_rekey_pending: bool = False
        self._full_rekey_task: Optional[asyncio.Task] = None
        self._full_rekey_attempts: int = 0

        # Manual trigger flags (set from outside; consumed in run())
        self._manual_light_rekey: bool = False
        self._manual_full_rekey: bool = False

        # Trigger counters (reset after each rekey)
        self._records_sealed: int = 0
        self._bytes_sealed: int = 0
        self._session_start: float = 0.0

        # Drop counters
        self._malformed_drops: int = 0
        self._unknown_session_drops: int = 0

        # Instrumentation (item 18)
        self._hs_success: bool = False
        self._hs_retransmits: int = 0
        self._hs_start_ns: int = 0
        self._hs_end_ns: int = 0

        # Created in run() (needs event loop)
        self._hs_queue: Optional[asyncio.Queue] = None

    # ------------------------------------------------------------------
    # Properties
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

    @property
    def malformed_drops(self) -> int:
        return self._malformed_drops

    @property
    def unknown_session_drops(self) -> int:
        return self._unknown_session_drops

    @property
    def rekey_state(self) -> str:
        if self._full_rekey_pending:
            return "full_rekey"
        if self._sm and self._sm.rekey_state != RekeyState.IDLE:
            return "light_rekey"
        return "idle"

    # ------------------------------------------------------------------
    # Public control API
    # ------------------------------------------------------------------

    def request_light_rekey(self) -> None:
        """Schedule a light rekey on the next run-loop iteration."""
        self._manual_light_rekey = True

    def request_full_rekey(self) -> None:
        """Schedule a full rekey on the next run-loop iteration."""
        self._manual_full_rekey = True

    def _set_epoch_for_testing(self, epoch: int) -> None:
        """Test-only: force the current SM epoch to trigger the epoch-254 guard."""
        assert self._sm is not None, "_set_epoch_for_testing requires an active session"
        old_keys = self._sm._rl_current._keys
        self._sm._rl_current._keys = replace(old_keys, epoch=epoch)

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------

    async def handshake(self) -> None:
        """Drive the 4-message handshake with exponential-backoff retransmit.

        All messages carry a 1-byte type prefix (§15 item 22).
        Unexpected HS type bytes received while waiting for HELLO_R or FINISHED_R
        are ignored and not fatal (§15 item 22: duplicates/unexpected ignored).
        """
        self._hs_start_ns = time.perf_counter_ns()
        initiator = HandshakeInitiator(self._suite, self._identity)
        hello_i = initiator.start()
        loop = asyncio.get_running_loop()

        # --- HELLO_I retransmit loop (wait for HELLO_R) ---
        hello_r_body: Optional[bytes] = None
        for attempt in range(self._hs_max_retries + 1):
            await self._link.send(bytes([_T_HELLO_I]) + hello_i)
            if attempt > 0:
                self._hs_retransmits += 1
                log.debug("Gateway: retransmit HELLO_I attempt %d", attempt)
            timeout_s = (self._hs_timeout_ms / 1000.0) * (2 ** attempt)
            deadline = loop.time() + timeout_s
            # Inner loop: drain unexpected HS messages until we get HELLO_R or deadline
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    raw = await asyncio.wait_for(
                        self._link.recv(timeout=remaining), timeout=remaining + 0.1
                    )
                except asyncio.TimeoutError:
                    break
                if raw is None:
                    break
                if len(raw) < 1:
                    self._malformed_drops += 1
                    continue
                t = raw[0]
                if t == _T_HELLO_R:
                    body = raw[1:]
                    if len(body) < _MIN_HS_BODY:
                        self._malformed_drops += 1
                        continue
                    hello_r_body = body
                    break
                # Other HS type: ignore (§15 item 22)
                log.debug("Gateway: ignoring unexpected type 0x%02x while waiting for HELLO_R", t)
            if hello_r_body is not None:
                break
        else:
            raise HandshakeError("HELLO_R timeout after retransmits")

        finished_i = initiator.process_hello_r(hello_r_body)

        # --- §15 item 20: start buffering CAN frames ---
        self._buffering = True
        buf_task = loop.create_task(self._buffer_can())

        # --- FINISHED_I retransmit loop (wait for FINISHED_R) ---
        finished_r_body: Optional[bytes] = None
        try:
            for attempt in range(self._hs_max_retries + 1):
                await self._link.send(bytes([_T_FINISHED_I]) + finished_i)
                if attempt > 0:
                    self._hs_retransmits += 1
                    log.debug("Gateway: retransmit FINISHED_I attempt %d", attempt)
                timeout_s = (self._hs_timeout_ms / 1000.0) * (2 ** attempt)
                deadline = loop.time() + timeout_s
                while True:
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        break
                    try:
                        raw = await asyncio.wait_for(
                            self._link.recv(timeout=remaining), timeout=remaining + 0.1
                        )
                    except asyncio.TimeoutError:
                        break
                    if raw is None:
                        break
                    if len(raw) < 1:
                        self._malformed_drops += 1
                        continue
                    t = raw[0]
                    if t == _T_FINISHED_R:
                        body = raw[1:]
                        finished_r_body = body
                        break
                    log.debug("Gateway: ignoring unexpected type 0x%02x while waiting for FINISHED_R", t)
                if finished_r_body is not None:
                    break
            else:
                raise HandshakeError("FINISHED_R timeout after retransmits")

            gw_keys = initiator.process_finished_r(finished_r_body)
            self._sm = SessionManager(
                self._suite,
                gw_keys,
                initiator.session_id,
                SessionRole.INITIATOR,
                config=self._rekey_config,
            )
            self._hs_success = True
            self._hs_end_ns = time.perf_counter_ns()
            log.debug("Gateway: session established session_id=%s", initiator.session_id.hex())
        except Exception:
            self._pre_session_buf.clear()
            raise
        finally:
            self._buffering = False
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
                await self._link.send(bytes([_T_DATA]) + req)
            log.debug("Gateway: CounterExhausted — frame buffered (%d pending)", len(self._pending))
            return
        except AlertError as exc:
            log.error("Gateway: AlertError sealing frame: %s", exc)
            raise
        await self._link.send(bytes([_T_DATA]) + wire)
        self._records_sealed += 1
        self._bytes_sealed += len(encoded)

    def _flush_pending(self) -> list[CANFrame]:
        """Return and clear the pending buffer."""
        frames = list(self._pending)
        self._pending.clear()
        return frames

    async def _handle_inbound(self, body: bytes) -> None:
        """Open one inbound DATA record (body has _T_DATA prefix stripped).

        Unknown session_id is silently dropped (no auth failure increment).
        """
        assert self._sm is not None
        if len(body) < _MIN_DATA_BODY:
            self._malformed_drops += 1
            return
        # session_id is at bytes 1-4 of the record header
        record_session_id = body[1:5]
        if record_session_id not in self._sm.known_session_ids:
            self._unknown_session_drops += 1
            return
        try:
            rtype, payload = self._sm.open(body, Direction.R2I)
        except Exception as exc:
            log.debug("Gateway: inbound record rejected: %s", exc)
            return
        if rtype == RecordType.DATA:
            try:
                frame = MessageAdapter.decode(payload)
                self._can.send(frame)
            except ValueError as exc:
                log.warning("Gateway: malformed reverse-path payload: %s", exc)
        elif rtype == RecordType.REKEY_ACK:
            # Flush CounterExhausted pending buffer now that epoch switched
            for frame in self._flush_pending():
                await self.send_frame(frame)
        # Drain any outbound control records
        while (out := self._sm.take_outbound()) is not None:
            await self._link.send(bytes([_T_DATA]) + out)

    # ------------------------------------------------------------------
    # Full-rekey coroutine
    # ------------------------------------------------------------------

    async def _do_full_rekey(self) -> None:
        """Run a new handshake in parallel while old session carries traffic.

        Uses per-attempt deadlines so stale HS messages do not consume retry budget.
        A FINISHED_R that fails verification is ignored until the deadline, then
        FINISHED_I is retransmitted.

        Raises HandshakeError on timeout (run() handles retry/ALERT).
        """
        from pqcgw.protocol.handshake import HandshakeInitiator
        loop = asyncio.get_running_loop()
        initiator = HandshakeInitiator(self._suite, self._identity)
        hello_i = initiator.start()
        await self._link.send(bytes([_T_HELLO_I]) + hello_i)

        # --- Wait for HELLO_R with per-attempt deadline ---
        hello_r_body: Optional[bytes] = None
        for attempt in range(self._hs_max_retries + 1):
            timeout_s = (self._hs_timeout_ms / 1000.0) * (2 ** attempt)
            deadline = loop.time() + timeout_s
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    raw = await asyncio.wait_for(self._hs_queue.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                t, body = raw[0], raw[1:]
                if t != _T_HELLO_R:
                    log.debug("_do_full_rekey: ignoring type 0x%02x while waiting for HELLO_R", t)
                    continue
                if len(body) < _MIN_HS_BODY:
                    log.debug("_do_full_rekey: HELLO_R too short, ignoring")
                    continue
                try:
                    from pqcgw.protocol.messages import HelloR
                    sid = HelloR.from_bytes(body).session_id
                except (ValueError, Exception):
                    log.debug("_do_full_rekey: HELLO_R parse failed, ignoring")
                    continue
                if sid != initiator.session_id:
                    log.debug("_do_full_rekey: HELLO_R session_id mismatch, ignoring")
                    continue
                hello_r_body = body
                break
            if hello_r_body is not None:
                break
            if attempt < self._hs_max_retries:
                log.debug("_do_full_rekey: HELLO_R timeout, retransmitting HELLO_I (attempt %d)", attempt + 1)
                await self._link.send(bytes([_T_HELLO_I]) + hello_i)
        if hello_r_body is None:
            raise HandshakeError("full rekey: HELLO_R timeout after retransmits")

        finished_i = initiator.process_hello_r(hello_r_body)
        await self._link.send(bytes([_T_FINISHED_I]) + finished_i)

        # --- Wait for FINISHED_R with per-attempt deadline ---
        new_keys = None
        for attempt in range(self._hs_max_retries + 1):
            timeout_s = (self._hs_timeout_ms / 1000.0) * (2 ** attempt)
            deadline = loop.time() + timeout_s
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    raw = await asyncio.wait_for(self._hs_queue.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                t, body = raw[0], raw[1:]
                if t != _T_FINISHED_R:
                    log.debug("_do_full_rekey: ignoring type 0x%02x while waiting for FINISHED_R", t)
                    continue
                try:
                    new_keys = initiator.process_finished_r(body)
                    break
                except Exception as exc:
                    log.warning("_do_full_rekey: FINISHED_R verify failed (%s), ignoring until deadline", exc)
                    continue
            if new_keys is not None:
                break
            if attempt < self._hs_max_retries:
                log.debug("_do_full_rekey: FINISHED_R timeout, retransmitting FINISHED_I (attempt %d)", attempt + 1)
                await self._link.send(bytes([_T_FINISHED_I]) + finished_i)
        if new_keys is None:
            raise HandshakeError("full rekey: FINISHED_R timeout after retransmits")

        self._sm.promote_full_rekey(new_keys, initiator.session_id)
        log.info("Gateway: full rekey promoted session_id=%s", initiator.session_id.hex())
        # run() resets trigger counters and flushes _pending on task success

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(self, n_frames: Optional[int] = None) -> None:
        """Handshake then bidirectionally forward frames.

        n_frames: stop after forwarding this many I2R frames (for tests).
        Pass None to run indefinitely (until error).
        """
        await self.handshake()

        self._hs_queue = asyncio.Queue()
        self._session_start = time.monotonic()
        self._records_sealed = 0
        self._bytes_sealed = 0
        self._full_rekey_attempts = 0

        loop = asyncio.get_running_loop()

        # Flush pre-session buffer (§15 item 20)
        frames_sent = 0
        for frame in list(self._pre_session_buf):
            await self.send_frame(frame)
            frames_sent += 1
        self._pre_session_buf.clear()

        try:
            while n_frames is None or frames_sent < n_frames:
                # -- 1. Manual rekey requests --
                if (self._manual_light_rekey
                        and not self._full_rekey_pending
                        and self._sm.rekey_state == RekeyState.IDLE):
                    self._manual_light_rekey = False
                    req = self._sm.initiate_light_rekey()
                    await self._link.send(bytes([_T_DATA]) + req)
                    self._records_sealed = self._bytes_sealed = 0
                    self._session_start = time.monotonic()

                if self._manual_full_rekey and not self._full_rekey_pending:
                    self._manual_full_rekey = False
                    self._trigger_full_rekey()

                # -- 2. Automatic light-rekey triggers --
                if (not self._full_rekey_pending
                        and self._sm.rekey_state == RekeyState.IDLE
                        and self._triggers_fire()):
                    req = self._sm.initiate_light_rekey()
                    await self._link.send(bytes([_T_DATA]) + req)
                    self._records_sealed = self._bytes_sealed = 0
                    self._session_start = time.monotonic()

                # -- 3. Epoch-254 guard: trigger full rekey before limit --
                if not self._full_rekey_pending and self._sm.epoch >= 254:
                    log.info("Gateway: epoch %d reached; triggering full rekey", self._sm.epoch)
                    self._trigger_full_rekey()

                # -- 4. Light-rekey timeout + retransmit drain --
                try:
                    self._sm.check_rekey_timeout()
                except AlertError:
                    raise
                while (ctrl := self._sm.take_outbound()) is not None:
                    await self._link.send(bytes([_T_DATA]) + ctrl)

                # -- 5. Full-rekey task completion --
                if self._full_rekey_task is not None and self._full_rekey_task.done():
                    exc = self._full_rekey_task.exception()
                    self._full_rekey_task = None
                    if exc is not None:
                        log.warning("Gateway: full rekey attempt failed: %s", exc)
                        self._full_rekey_attempts += 1
                        if self._full_rekey_attempts >= self._full_rekey_max_attempts:
                            # Send ALERT and close
                            try:
                                alert = self._sm.seal(b"", RecordType.ALERT, Direction.I2R)
                                await self._link.send(bytes([_T_DATA]) + alert)
                            except Exception:
                                pass
                            self._sm._close()
                            raise AlertError(
                                f"full rekey failed after {self._full_rekey_attempts} attempts; session closed"
                            )
                        self._trigger_full_rekey()
                    else:
                        # Success
                        self._full_rekey_attempts = 0
                        self._full_rekey_pending = False
                        # Reset trigger counters for new session
                        self._records_sealed = self._bytes_sealed = 0
                        self._session_start = time.monotonic()
                        # Flush CounterExhausted pending buffer
                        for frame in self._flush_pending():
                            await self.send_frame(frame)

                # -- 6. I2R: CAN → peer --
                frame = await loop.run_in_executor(None, self._can.receive, 0.01)
                if frame is not None:
                    await self.send_frame(frame)
                    frames_sent += 1

                # -- 7. R2I: peer → CAN --
                raw = await self._link.recv(timeout=0.01)
                if raw is not None:
                    if len(raw) < 1:
                        self._malformed_drops += 1
                    else:
                        t, body = raw[0], raw[1:]
                        if t in (_T_HELLO_I, _T_HELLO_R, _T_FINISHED_I, _T_FINISHED_R):
                            if len(body) >= _MIN_HS_BODY:
                                self._hs_queue.put_nowait(raw)
                            else:
                                self._malformed_drops += 1
                        elif t == _T_DATA:
                            await self._handle_inbound(body)
                        else:
                            self._malformed_drops += 1
        finally:
            if self._full_rekey_task is not None and not self._full_rekey_task.done():
                self._full_rekey_task.cancel()
                try:
                    await self._full_rekey_task
                except (asyncio.CancelledError, Exception):
                    pass

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _triggers_fire(self) -> bool:
        t = self._trigger
        if t.interval_s and (time.monotonic() - self._session_start) >= t.interval_s:
            return True
        if t.record_count and self._records_sealed >= t.record_count:
            return True
        if t.byte_count and self._bytes_sealed >= t.byte_count:
            return True
        return False

    def _trigger_full_rekey(self) -> None:
        """Start a full-rekey task; drain stale HS messages from prior attempt."""
        self._full_rekey_pending = True
        # Drain stale messages from any previous full-rekey attempt
        if self._hs_queue is not None:
            while not self._hs_queue.empty():
                try:
                    self._hs_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
        self._full_rekey_task = asyncio.ensure_future(self._do_full_rekey())
