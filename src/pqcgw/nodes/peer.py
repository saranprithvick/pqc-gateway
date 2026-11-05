"""ModernPeer: async session responder.

Drives the responder side of the handshake:
  HELLO_I → HELLO_R → FINISHED_I → FINISHED_R

§15 item 20:
  - DATA records received before FINISHED_I is verified are dropped.
  - A byte-identical duplicate FINISHED_I causes a byte-identical FINISHED_R resend
    (cached; no re-ratcheting, no new SessionManager).
  - Any other second FINISHED_I is dropped.

Reverse path:
  After the session is established, send_command(frame) seals and sends an R2I record.
  Inbound I2R records are decoded and placed in the sink queue.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from pqcgw.crypto.registry import Suite
from pqcgw.legacy.can_model import CANFrame
from pqcgw.net.link import Link
from pqcgw.nodes.adapter import MessageAdapter
from pqcgw.protocol.handshake import HandshakeError, HandshakeResponder, IdentityContext
from pqcgw.protocol.record import Direction, RecordType
from pqcgw.protocol.session import (
    AlertError,
    RekeyConfig,
    SessionManager,
    SessionRole,
)

log = logging.getLogger(__name__)


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

        # §15 item 20 — FINISHED cache
        self._cached_finished_i: Optional[bytes] = None
        self._cached_finished_r: Optional[bytes] = None

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

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------

    async def handshake(self) -> None:
        """Await and process the 4-message handshake."""
        self._hs_start_ns = time.perf_counter_ns()
        responder = HandshakeResponder(self._suite, self._identity)

        # HELLO_I
        hello_i = await self._link.recv(timeout=self._hs_recv_timeout)
        if hello_i is None:
            raise HandshakeError("Peer: HELLO_I timeout")
        hello_r = responder.process_hello_i(hello_i)
        await self._link.send(hello_r)
        # Cache for §15 item 9: byte-identical retransmit → resend cached HELLO_R
        _cached_hello_i = hello_i
        _cached_hello_r = hello_r

        # FINISHED_I — with retransmit handling (§15 item 9)
        finished_i: Optional[bytes] = None
        while True:
            msg = await self._link.recv(timeout=self._hs_recv_timeout)
            if msg is None:
                raise HandshakeError("Peer: FINISHED_I timeout")
            if msg == _cached_hello_i:
                # Byte-identical HELLO_I retransmit: resend cached HELLO_R (§15 item 9)
                log.debug("Peer: retransmitted HELLO_I; resending cached HELLO_R")
                await self._link.send(_cached_hello_r)
                continue
            finished_i = msg
            break

        # §15 item 20 — handle duplicate or alien FINISHED_I
        if self._cached_finished_i is not None:
            if finished_i == self._cached_finished_i:
                log.debug("Peer: duplicate FINISHED_I; resending cached FINISHED_R")
                await self._link.send(self._cached_finished_r)
                return  # session already established
            else:
                log.debug("Peer: different FINISHED_I received; dropping")
                return  # keep existing session

        finished_r, peer_keys = responder.process_finished_i(finished_i)
        self._cached_finished_i = finished_i
        self._cached_finished_r = finished_r
        await self._link.send(finished_r)

        self._sm = SessionManager(
            self._suite,
            peer_keys,
            responder.session_id,
            SessionRole.RESPONDER,
            config=self._rekey_config,
        )
        self._hs_success = True
        self._hs_end_ns = time.perf_counter_ns()
        log.debug(
            "Peer: session established session_id=%s",
            responder.session_id.hex(),
        )

    # ------------------------------------------------------------------
    # Data-path helpers
    # ------------------------------------------------------------------

    async def send_command(self, frame: CANFrame) -> None:
        """Seal and send one R2I frame to the Gateway."""
        assert self._sm is not None
        encoded = MessageAdapter.encode(frame)
        wire = self._sm.seal(encoded, direction=Direction.R2I)
        await self._link.send(wire)

    async def _handle_inbound(self, wire: bytes) -> None:
        """Open one I2R record; drop DATA before session; drain take_outbound()."""
        # §15 item 20: respond to FINISHED_I retransmits even in the data phase
        # (FINISHED_R may have been lost; the initiator retransmits FINISHED_I).
        if self._cached_finished_i is not None and wire == self._cached_finished_i:
            log.debug("Peer: retransmitted FINISHED_I in data phase; resending FINISHED_R")
            await self._link.send(self._cached_finished_r)
            return

        if self._sm is None:
            # §15 item 20: drop DATA records before FINISHED_I is verified
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
        # Drain any control records (e.g. REKEY_ACK in M5b)
        while (out := self._sm.take_outbound()) is not None:
            await self._link.send(out)

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

        # Send any reverse-path commands
        if commands:
            for cmd in commands:
                await self.send_command(cmd)

        # Receive n_frames of I2R data (or run forever if n_frames is None)
        received = 0
        while n_frames is None or received < n_frames:
            wire = await self._link.recv(timeout=5.0)
            if wire is None:
                continue
            prev_size = self._sink.qsize()
            await self._handle_inbound(wire)
            if self._sink.qsize() > prev_size:
                received += 1
