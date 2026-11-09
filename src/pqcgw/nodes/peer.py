"""ModernPeer: async session responder.

Drives the responder side of the handshake:
  HELLO_I → HELLO_R → FINISHED_I → FINISHED_R

All handshake messages carry a 1-byte type prefix (§15 item 22).
Dispatch is always on the prefix byte, never on protocol state.

§15 item 20:
  - DATA records received before FINISHED_I is verified are dropped.
  - A byte-identical duplicate FINISHED_I causes a byte-identical FINISHED_R resend.
  - Any other second FINISHED_I is dropped.

Full-rekey (§15 item 16):
  Incoming HELLO_I messages are routed to _handle_hs_message(), which manages a
  single in-progress HandshakeResponder (_fr).  After FINISHED_I is processed the
  keys are stored in _fr_pending; the peer does NOT promote until it receives a DATA
  record for the new session that authenticates with the pending keys (trial open).
  _fr is kept alive to serve cached HELLO_R on retransmit.

Lazy cleanup:
  _fr state is cleared only when the promoted session's grace has expired AND the
  session has left _sm.known_session_ids (_fr_complete AND _fr_pending is None).

Drop counters:
  _malformed_drops       — message shorter than minimum or unknown type byte
  _unknown_session_drops — DATA record for unknown/expired session_id or failed trial open
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import asyncio

from pqcgw.crypto.registry import Suite
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.link import Link
from pqcgw.nodes.adapter import MessageAdapter
from pqcgw.protocol.handshake import HandshakeError, HandshakeResponder, IdentityContext
from pqcgw.protocol.messages import HelloI
from pqcgw.protocol.record import Direction, RecordError, RecordLayer, RecordType
from pqcgw.protocol.replay import ReplayWindow
from pqcgw.protocol.session import (
    AlertError,
    RekeyConfig,
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

_MIN_HS_BODY  = 6    # version + suite_id + session_id
_MIN_DATA_BODY = 16  # record header


class ModernPeer:
    """Async handshake responder and bidirectional peer."""

    def __init__(
        self,
        suite: Suite,
        identity: IdentityContext,
        link: Link,
        sink: "asyncio.Queue[CANFrame]",
        rekey_config: Optional[RekeyConfig] = None,
        handshake_recv_timeout: float = 30.0,
    ) -> None:
        self._suite = suite
        self._identity = identity
        self._link = link
        self._sink = sink
        self._rekey_config = rekey_config
        self._hs_recv_timeout = handshake_recv_timeout

        self._sm: Optional[SessionManager] = None

        # §15 item 20 — FINISHED cache for initial handshake
        self._cached_finished_i: Optional[bytes] = None
        self._cached_finished_r: Optional[bytes] = None

        # Full-rekey responder state (one in-progress session at a time)
        self._fr: Optional[HandshakeResponder] = None
        self._fr_session_id: Optional[bytes] = None   # new-session id of _fr
        self._fr_complete: bool = False                # True after FINISHED_I processed
        self._fr_fi: Optional[bytes] = None            # cached FINISHED_I for retransmit check
        self._fr_fr: Optional[bytes] = None            # cached FINISHED_R to resend
        self._fr_pending: Optional[tuple] = None       # (SessionKeys, session_id) pre-promote

        # Drop counters
        self._malformed_drops: int = 0
        self._unknown_session_drops: int = 0

        # Instrumentation
        self._hs_success: bool = False
        self._hs_start_ns: int = 0
        self._hs_end_ns: int = 0

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def handshake_success(self) -> bool:
        return self._hs_success

    @property
    def handshake_duration_ns(self) -> int:
        return self._hs_end_ns - self._hs_start_ns

    @property
    def malformed_drops(self) -> int:
        return self._malformed_drops

    @property
    def unknown_session_drops(self) -> int:
        return self._unknown_session_drops

    # ------------------------------------------------------------------
    # Handshake (initial)
    # ------------------------------------------------------------------

    async def handshake(self) -> None:
        """Await and process the 4-message initial handshake.

        Dispatches on the 1-byte prefix (§15 item 22).  Unexpected types are
        silently ignored (not fatal) until timeout.
        """
        self._hs_start_ns = time.perf_counter_ns()
        responder = HandshakeResponder(self._suite, self._identity)

        # --- HELLO_I: loop until correct type or timeout (§15 item 22) ---
        hello_i_body: Optional[bytes] = None
        while True:
            raw = await self._link.recv(timeout=self._hs_recv_timeout)
            if raw is None:
                raise HandshakeError("Peer: HELLO_I timeout")
            if len(raw) < 2:
                self._malformed_drops += 1
                continue
            t, body = raw[0], raw[1:]
            if t == _T_HELLO_I:
                hello_i_body = body
                break
            self._malformed_drops += 1   # unexpected type: drop and count

        hello_r = responder.process_hello_i(hello_i_body)
        await self._link.send(bytes([_T_HELLO_R]) + hello_r)

        # --- FINISHED_I: loop, resend HELLO_R on HELLO_I retransmit (§15 items 9, 22) ---
        finished_i_body: Optional[bytes] = None
        while True:
            raw = await self._link.recv(timeout=self._hs_recv_timeout)
            if raw is None:
                raise HandshakeError("Peer: FINISHED_I timeout")
            if len(raw) < 2:
                self._malformed_drops += 1
                continue
            t, body = raw[0], raw[1:]
            if t == _T_HELLO_I:
                new_hr = responder.process_hello_i(body)
                await self._link.send(bytes([_T_HELLO_R]) + new_hr)
                continue
            if t == _T_FINISHED_I:
                finished_i_body = body
                break
            # Other HS type: ignore (§15 item 22)
            log.debug("Peer: ignoring type 0x%02x while waiting for FINISHED_I", t)

        # §15 item 20 — handle duplicate FINISHED_I
        if self._cached_finished_i is not None:
            if finished_i_body == self._cached_finished_i:
                log.debug("Peer: duplicate FINISHED_I; resending cached FINISHED_R")
                await self._link.send(bytes([_T_FINISHED_R]) + self._cached_finished_r)
                return
            else:
                log.debug("Peer: different FINISHED_I received; dropping")
                return

        finished_r, peer_keys = responder.process_finished_i(finished_i_body)
        self._cached_finished_i = finished_i_body
        self._cached_finished_r = finished_r
        await self._link.send(bytes([_T_FINISHED_R]) + finished_r)

        self._sm = SessionManager(
            self._suite,
            peer_keys,
            responder.session_id,
            SessionRole.RESPONDER,
            config=self._rekey_config,
        )
        self._hs_success = True
        self._hs_end_ns = time.perf_counter_ns()
        log.debug("Peer: session established session_id=%s", responder.session_id.hex())

    # ------------------------------------------------------------------
    # Data-path helpers
    # ------------------------------------------------------------------

    async def send_command(self, frame: CANFrame) -> None:
        """Seal and send one R2I frame to the Gateway."""
        assert self._sm is not None
        encoded = MessageAdapter.encode(frame)
        wire = self._sm.seal(encoded, direction=Direction.R2I)
        await self._link.send(bytes([_T_DATA]) + wire)

    async def _handle_inbound(self, wire: bytes) -> None:
        """Open one I2R DATA record (wire has _T_DATA prefix stripped).

        Full-rekey switch-over: if wire's session_id matches a pending full-rekey,
        trial-open with pending keys first; promote only on successful authentication.
        """
        if self._sm is None:
            return

        if len(wire) < 5:
            self._malformed_drops += 1
            return

        record_session_id = wire[1:5]

        # --- Full-rekey switch-over (§15 item 16) ---
        if self._fr_pending is not None and record_session_id == self._fr_pending[1]:
            pending_keys, pending_sid = self._fr_pending
            # Trial open with pending keys — authenticate before promoting
            trial_rl = RecordLayer(self._suite, pending_keys, pending_sid)
            trial_rw = ReplayWindow()
            try:
                trial_rl.open(wire, Direction.I2R, trial_rw)
            except RecordError:
                log.warning("Peer: new-session header present but authentication failed; dropping")
                self._unknown_session_drops += 1
                return
            # Authenticated: promote and re-open via SM (SM's replay window is updated)
            self._sm.promote_full_rekey(pending_keys, pending_sid)
            self._fr_pending = None
            log.info("Peer: promoted full rekey session_id=%s", pending_sid.hex())
            # fall through: SM now uses new session, re-open below

        elif record_session_id not in self._sm.known_session_ids:
            log.debug("Peer: drop record for unknown session %s", record_session_id.hex())
            self._unknown_session_drops += 1
            return

        try:
            rtype, payload = self._sm.open(wire, Direction.I2R)
        except Exception as exc:
            log.debug("Peer: inbound record rejected: %s", exc)
            return

        if rtype == RecordType.DATA:
            try:
                frame = MessageAdapter.decode(payload)
                await self._sink.put(frame)
            except ValueError as exc:
                log.warning("Peer: malformed I2R payload: %s", exc)

        # Drain any control records (REKEY_ACK etc.)
        while (out := self._sm.take_outbound()) is not None:
            await self._link.send(bytes([_T_DATA]) + out)

    async def _handle_hs_message(self, type_byte: int, body: bytes) -> None:
        """Route an in-data-phase HS message (full-rekey HELLO_I / FINISHED_I).

        Dispatches on type_byte.  Lazy cleanup of _fr state happens here when
        the promoted session has fully left _sm.known_session_ids.
        """
        if self._sm is None:
            return

        # --- Lazy cleanup: only for promoted sessions whose grace has expired ---
        # Condition: _fr was completed AND promoted (_fr_pending is None) AND
        # the new session_id has since left known_session_ids (pushed out by a later full rekey).
        if (self._fr_session_id is not None
                and self._fr_complete
                and self._fr_pending is None
                and self._fr_session_id not in self._sm.known_session_ids):
            log.debug("Peer: clearing stale full-rekey state for session %s", self._fr_session_id.hex())
            self._fr = None
            self._fr_session_id = None
            self._fr_complete = False
            self._fr_fi = None
            self._fr_fr = None

        if type_byte == _T_HELLO_I:
            # Parse session_id via the proper parser (fix 4)
            try:
                attempt_session_id = HelloI.from_bytes(body).session_id
            except (ValueError, Exception) as exc:
                log.debug("Peer: HELLO_I parse failed (%s), dropping", exc)
                self._malformed_drops += 1
                return

            if attempt_session_id == self._fr_session_id:
                # Same session: existing responder handles retransmit via its _cache
                if self._fr is None:
                    log.warning("Peer: HELLO_I retransmit for session %s but responder cleared",
                                attempt_session_id.hex())
                    return
                hello_r = self._fr.process_hello_i(body)
                await self._link.send(bytes([_T_HELLO_R]) + hello_r)
            else:
                # New session_id: replace any stale _fr
                # If _fr_pending refers to the stale session, discard it too
                if (self._fr_pending is not None
                        and self._fr_pending[1] == self._fr_session_id):
                    log.debug("Peer: discarding _fr_pending for replaced session %s",
                              self._fr_session_id.hex() if self._fr_session_id else "None")
                    self._fr_pending = None
                self._fr = HandshakeResponder(self._suite, self._identity)
                self._fr_session_id = attempt_session_id
                self._fr_complete = False
                self._fr_fi = None
                self._fr_fr = None
                hello_r = self._fr.process_hello_i(body)
                await self._link.send(bytes([_T_HELLO_R]) + hello_r)

        elif type_byte == _T_FINISHED_I:
            # §15 item 20: initial-handshake FINISHED_I retransmit in the data phase
            if self._cached_finished_i is not None and body == self._cached_finished_i:
                log.debug("Peer: retransmitted initial FINISHED_I; resending cached FINISHED_R")
                await self._link.send(bytes([_T_FINISHED_R]) + self._cached_finished_r)
                return

            # Retransmit check: byte-identical FINISHED_I for a completed full rekey
            if self._fr_complete and self._fr_fi == body:
                await self._link.send(bytes([_T_FINISHED_R]) + self._fr_fr)
                return

            if self._fr is None or self._fr.state != "HELLO_RECEIVED":
                log.warning("Peer: unexpected FINISHED_I (fr state=%s)",
                            self._fr.state if self._fr else "none")
                return

            finished_r, new_keys = self._fr.process_finished_i(body)
            self._fr_complete = True
            self._fr_fi = body
            self._fr_fr = finished_r
            await self._link.send(bytes([_T_FINISHED_R]) + finished_r)

            # Store pending; do NOT promote yet.
            # Peer promotes only when a DATA record on the new session authenticates
            # (trial open in _handle_inbound; §15 item 16 switch-over).
            self._fr_pending = (new_keys, self._fr.session_id)
            log.debug("Peer: full-rekey keys ready for session %s; awaiting first DATA",
                      self._fr.session_id.hex())

        else:
            log.debug("Peer: ignoring HS type 0x%02x in data phase", type_byte)

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------

    async def run(
        self,
        n_frames: Optional[int] = None,
        commands: Optional[list[CANFrame]] = None,
    ) -> None:
        """Handshake then receive n_frames into sink; optionally send commands.

        commands: R2I frames sent to the Gateway after the session is established.
        n_frames: how many I2R DATA frames to receive before returning.
                  None means run indefinitely (until cancelled).
        """
        await self.handshake()

        if commands:
            for cmd in commands:
                await self.send_command(cmd)

        received = 0
        while n_frames is None or received < n_frames:
            raw = await self._link.recv(timeout=5.0)
            if raw is None:
                continue
            if len(raw) < 1:
                self._malformed_drops += 1
                continue
            t, body = raw[0], raw[1:]

            if t in (_T_HELLO_I, _T_HELLO_R, _T_FINISHED_I, _T_FINISHED_R):
                if len(body) >= _MIN_HS_BODY:
                    await self._handle_hs_message(t, body)
                else:
                    self._malformed_drops += 1
            elif t == _T_DATA:
                prev_size = self._sink.qsize()
                await self._handle_inbound(body)
                if self._sink.qsize() > prev_size:
                    received += 1
            else:
                self._malformed_drops += 1
