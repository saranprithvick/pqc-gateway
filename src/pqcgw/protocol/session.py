"""Session manager: epoch tracking, light rekey, full rekey, grace period.

The SessionManager wraps two RecordLayer instances (current and previous epoch)
and drives the light-rekey state machine (REKEY_REQ / REKEY_ACK exchange).

Light rekey wire sequence (§15 item 15):
  1. Initiator calls initiate_light_rekey() → REKEY_REQ record (sealed under epoch n).
  2. Responder open()s the REKEY_REQ, ratchets keys, queues REKEY_ACK under epoch n,
     switches to epoch n+1 for new sends.  Caller drains ACK via take_outbound().
  3. Initiator open()s the REKEY_ACK, switches to epoch n+1.
  4. Both sides accept epoch-n records for the grace period (2 s or 64 new-epoch records,
     whichever comes first).

Full rekey (§15 item 16): run a new HandshakeInitiator/Responder as a separate session
with a new session_id while the old session keeps carrying traffic.  The caller drives
the handshake externally and calls promote_full_rekey() when the new session is established.

Epoch 255: before sealing on epoch 255, seal() raises AlertError; callers must do a full
rekey before that point.

Counter hard limit: when the outbound counter for a direction reaches counter_hard_limit,
seal() automatically triggers a light rekey and returns the REKEY_REQ bytes.  If a rekey
is already in progress or the timeout has expired, AlertError is raised.

Duplicate REKEY_REQ (§15 item 21): a second identical REKEY_REQ during the grace period
makes the responder resend the cached ACK byte-for-byte without ratcheting again.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum

from pqcgw.crypto.registry import Suite
from pqcgw.protocol.keyschedule import SessionKeys
from pqcgw.protocol.record import (
    Direction,
    RecordError,
    RecordHeader,
    RecordLayer,
    RecordType,
)
from pqcgw.protocol.rekey import derive_rekey_epoch
from pqcgw.protocol.replay import ReplayWindow

log = logging.getLogger(__name__)

_HEADER_LEN = 16


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class RekeyConfig:
    """Configurable limits and timeouts for the session manager."""

    counter_hard_limit: int = 2 ** 32
    max_consecutive_auth_failures: int = 10
    grace_period_s: float = 2.0
    grace_period_records: int = 64
    rekey_timeout_s: float = 0.5
    rekey_max_retries: int = 3


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SessionRole(Enum):
    INITIATOR = "initiator"   # gateway (light-rekey initiator)
    RESPONDER = "responder"   # peer    (light-rekey responder)


class RekeyState(Enum):
    IDLE = "idle"
    REQ_SENT = "req_sent"      # initiator: sent REKEY_REQ, awaiting ACK
    ACK_SENT = "ack_sent"      # responder: sent REKEY_ACK, epoch switched
    GRACE = "grace"            # either side: epoch switched, old epoch in grace window


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SessionError(Exception):
    """Base class for session-layer errors."""


class AlertError(SessionError):
    """Fatal session error; the caller must send an ALERT record and close."""


# ---------------------------------------------------------------------------
# SessionManager
# ---------------------------------------------------------------------------

class SessionManager:
    """Manages record sealing/opening with epoch-based key rotation.

    One SessionManager instance per session side (initiator or responder).
    The caller is responsible for delivering outbound bytes to the network and
    providing inbound bytes from the network.

    For the responder side, control messages (REKEY_ACK) are queued internally
    and must be drained via take_outbound() after each call to open().
    """

    def __init__(
        self,
        suite: Suite,
        keys: SessionKeys,
        session_id: bytes,
        role: SessionRole,
        config: RekeyConfig | None = None,
    ) -> None:
        self._suite = suite
        self._session_id = session_id
        self._role = role
        self._config = config or RekeyConfig()

        # Current-epoch record layer and replay windows (one per direction)
        self._rl_current = RecordLayer(suite, keys, session_id)
        self._rw_current: dict[Direction, ReplayWindow] = {
            Direction.I2R: ReplayWindow(),
            Direction.R2I: ReplayWindow(),
        }

        # Previous-epoch record layer (grace period only)
        self._rl_prev: RecordLayer | None = None
        self._rw_prev: dict[Direction, ReplayWindow] | None = None

        # Grace period tracking
        self._grace_start: float = 0.0
        self._new_epoch_records: int = 0

        # Rekey state
        self._rekey_state: RekeyState = RekeyState.IDLE
        self._pending_next_keys: SessionKeys | None = None
        self._cached_rekey_req: bytes | None = None     # for dup-detection on responder
        self._cached_rekey_ack: bytes | None = None     # cached ACK to resend on dup
        self._rekey_timer_start: float = 0.0
        self._rekey_retries: int = 0

        # Consecutive auth-failure counter
        self._auth_failures: int = 0

        # Outbound message queue (control messages queued by open())
        self._outbound_queue: list[bytes] = []

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    @property
    def epoch(self) -> int:
        return self._rl_current._keys.epoch

    @property
    def rekey_state(self) -> RekeyState:
        return self._rekey_state

    @property
    def consecutive_auth_failures(self) -> int:
        return self._auth_failures

    def seal(
        self,
        plaintext: bytes,
        rtype: RecordType = RecordType.DATA,
        direction: Direction = Direction.I2R,
    ) -> bytes:
        """Encrypt plaintext into a wire record under the current epoch.

        If the outbound counter has reached counter_hard_limit, initiates a light
        rekey and returns the REKEY_REQ record instead of a DATA record.

        Raises AlertError if the epoch is 255 (full rekey required) or if a rekey
        was triggered but has already timed out.
        """
        # Epoch 255 guard: full rekey must be done before wrapping (§5.7)
        if self._rl_current._keys.epoch >= 255:
            raise AlertError("epoch limit reached; full rekey required before epoch 255")

        # Check for a pending rekey timeout before sealing data
        if self._rekey_state == RekeyState.REQ_SENT:
            self.check_rekey_timeout()

        # Counter hard-limit trigger
        current_counter = self._rl_current._counters[direction]
        if current_counter >= self._config.counter_hard_limit:
            if self._role != SessionRole.INITIATOR:
                raise AlertError("counter hard limit reached on responder; initiator must trigger rekey")
            if self._rekey_state == RekeyState.REQ_SENT:
                # Rekey already in progress; check timeout
                self.check_rekey_timeout()
                raise AlertError("counter hard limit reached and rekey did not complete")
            log.info("Counter hard limit %d reached; triggering light rekey", self._config.counter_hard_limit)
            req = self.initiate_light_rekey()
            # Immediately check timeout for zero-timeout configs (e.g. in tests)
            self.check_rekey_timeout()
            return req

        return self._rl_current.seal(rtype, plaintext, direction)

    def open(
        self,
        data: bytes,
        direction: Direction,
    ) -> tuple[RecordType, bytes]:
        """Parse, authenticate, and decrypt a wire record.

        Routes the record to the current or previous epoch's RecordLayer based on
        the epoch byte in the header.  Handles REKEY_REQ and REKEY_ACK as control
        messages, updating state internally.

        Returns (RecordType, plaintext).  For REKEY_REQ / REKEY_ACK the plaintext
        is always b"".  The caller must call take_outbound() after this returns to
        drain any queued response (e.g. the REKEY_ACK that the responder queued).

        Raises RecordError on authentication/epoch/replay failure (drop silently on wire).
        Raises AlertError on too many consecutive auth failures.
        """
        if len(data) < _HEADER_LEN:
            raise RecordError("Record too short")

        # Duplicate REKEY_REQ check (§15 item 21): perform raw-bytes comparison
        # BEFORE going through the replay window, since a retransmitted REKEY_REQ
        # would otherwise be rejected as a duplicate counter.
        if (
            self._role == SessionRole.RESPONDER
            and self._cached_rekey_req is not None
            and data == self._cached_rekey_req
            and self._cached_rekey_ack is not None
        ):
            log.debug("Duplicate REKEY_REQ; resending cached ACK")
            self._outbound_queue.append(self._cached_rekey_ack)
            return RecordType.REKEY_REQ, b""

        # Parse epoch from header without decrypting
        try:
            hdr = RecordHeader.from_bytes(data[:_HEADER_LEN])
        except RecordError:
            self._on_auth_failure()
            raise

        rtype, plaintext = self._route_open(data, hdr, direction)

        # Reset auth-failure counter on success
        self._auth_failures = 0

        # Handle control records
        if rtype == RecordType.REKEY_REQ:
            self._handle_rekey_req(data)
        elif rtype == RecordType.REKEY_ACK:
            self._handle_rekey_ack()

        # Track new-epoch records for grace-period expiry
        if self._rekey_state in (RekeyState.GRACE, RekeyState.ACK_SENT):
            if hdr.epoch == self._rl_current._keys.epoch:
                self._new_epoch_records += 1

        return rtype, plaintext

    def take_outbound(self) -> bytes | None:
        """Return and remove the next queued outbound control record, or None."""
        if self._outbound_queue:
            return self._outbound_queue.pop(0)
        return None

    def initiate_light_rekey(self) -> bytes:
        """Initiator only: derive epoch+1 keys and send REKEY_REQ.

        Returns the REKEY_REQ record bytes to be sent to the peer.

        Raises SessionError if called on the responder side.
        Raises AlertError if epoch == 255.
        """
        if self._role != SessionRole.INITIATOR:
            raise SessionError("only the initiator may initiate a light rekey")
        if self._rl_current._keys.epoch >= 255:
            raise AlertError("epoch limit reached; use full rekey")

        # Derive next-epoch keys but do NOT switch yet
        self._pending_next_keys = derive_rekey_epoch(self._suite, self._rl_current._keys)
        self._rekey_state = RekeyState.REQ_SENT
        self._rekey_timer_start = time.monotonic()

        req = self._rl_current.seal(RecordType.REKEY_REQ, b"", Direction.I2R)
        log.info("Light rekey initiated: epoch %d → %d", self.epoch, self.epoch + 1)
        return req

    def check_rekey_timeout(self) -> None:
        """Raise AlertError if a rekey is in progress and has timed out.

        Respects rekey_max_retries; each call after a timeout increments the retry
        counter until max_retries is reached, at which point AlertError is raised.
        (In a networked context the caller would retransmit before calling this.)
        """
        if self._rekey_state != RekeyState.REQ_SENT:
            return
        elapsed = time.monotonic() - self._rekey_timer_start
        if elapsed >= self._config.rekey_timeout_s:
            if self._rekey_retries >= self._config.rekey_max_retries:
                self._rekey_state = RekeyState.IDLE
                raise AlertError(
                    f"rekey timed out after {self._rekey_retries} retries; closing session"
                )
            self._rekey_retries += 1
            self._rekey_timer_start = time.monotonic()

    def promote_full_rekey(self, new_keys: SessionKeys, new_session_id: bytes) -> None:
        """Swap in a freshly completed full-rekey session (§15 item 16).

        The old session enters the grace period; the caller must continue to handle
        inbound records with the old session_id until the grace period expires.
        (Full rekey management is exercised in M5+.)
        """
        self._start_grace()
        self._rl_current = RecordLayer(self._suite, new_keys, new_session_id)
        self._rw_current = {Direction.I2R: ReplayWindow(), Direction.R2I: ReplayWindow()}
        self._session_id = new_session_id
        self._rekey_state = RekeyState.GRACE

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _route_open(
        self,
        data: bytes,
        hdr: RecordHeader,
        direction: Direction,
    ) -> tuple[RecordType, bytes]:
        """Route a record to the right RecordLayer by epoch."""
        cur_epoch = self._rl_current._keys.epoch

        if hdr.epoch == cur_epoch:
            try:
                return self._rl_current.open(data, direction, self._rw_current[direction])
            except RecordError:
                self._on_auth_failure()
                raise

        # Try previous epoch during grace period
        if (
            self._rl_prev is not None
            and hdr.epoch == self._rl_prev._keys.epoch
            and not self._grace_expired()
        ):
            try:
                return self._rl_prev.open(data, direction, self._rw_prev[direction])
            except RecordError:
                self._on_auth_failure()
                raise

        self._on_auth_failure()
        raise RecordError(
            f"Record epoch {hdr.epoch} not accepted "
            f"(current={cur_epoch}, grace={'active' if self._rl_prev else 'none'})"
        )

    def _handle_rekey_req(self, raw_req: bytes) -> None:
        """Responder: process an incoming REKEY_REQ.

        If this is a duplicate of the cached REKEY_REQ, resend the cached ACK.
        Otherwise ratchet keys, queue a REKEY_ACK, and switch to the new epoch.
        """
        if self._role != SessionRole.RESPONDER:
            log.warning("Initiator received REKEY_REQ; ignoring")
            return

        # Duplicate detection (§15 item 21)
        if raw_req == self._cached_rekey_req and self._cached_rekey_ack is not None:
            log.debug("Duplicate REKEY_REQ; resending cached ACK")
            self._outbound_queue.append(self._cached_rekey_ack)
            return

        # Derive next-epoch keys and switch
        next_keys = derive_rekey_epoch(self._suite, self._rl_current._keys)
        # Seal REKEY_ACK under the CURRENT epoch before switching
        ack = self._rl_current.seal(RecordType.REKEY_ACK, b"", Direction.R2I)

        # Cache for duplicate handling
        self._cached_rekey_req = raw_req
        self._cached_rekey_ack = ack

        # Switch epoch
        self._start_grace()
        self._rl_current = RecordLayer(self._suite, next_keys, self._session_id)
        self._rw_current = {Direction.I2R: ReplayWindow(), Direction.R2I: ReplayWindow()}
        self._rekey_state = RekeyState.ACK_SENT

        self._outbound_queue.append(ack)
        log.info("Light rekey: responder switched to epoch %d", self.epoch)

    def _handle_rekey_ack(self) -> None:
        """Initiator: process an incoming REKEY_ACK and switch to the pending epoch."""
        if self._role != SessionRole.INITIATOR:
            log.warning("Responder received REKEY_ACK; ignoring")
            return
        if self._pending_next_keys is None or self._rekey_state != RekeyState.REQ_SENT:
            log.warning("Unexpected REKEY_ACK; ignoring")
            return

        self._start_grace()
        self._rl_current = RecordLayer(self._suite, self._pending_next_keys, self._session_id)
        self._rw_current = {Direction.I2R: ReplayWindow(), Direction.R2I: ReplayWindow()}
        self._pending_next_keys = None
        self._rekey_state = RekeyState.GRACE
        self._rekey_retries = 0
        log.info("Light rekey: initiator switched to epoch %d", self.epoch)

    def _start_grace(self) -> None:
        """Move current RecordLayer to previous slot, start the grace clock."""
        self._rl_prev = self._rl_current
        self._rw_prev = dict(self._rw_current)
        self._grace_start = time.monotonic()
        self._new_epoch_records = 0

    def _grace_expired(self) -> bool:
        """True if the grace period has ended (time or record count)."""
        if self._rl_prev is None:
            return True
        if time.monotonic() - self._grace_start >= self._config.grace_period_s:
            self._expire_grace()
            return True
        if self._new_epoch_records >= self._config.grace_period_records:
            self._expire_grace()
            return True
        return False

    def _expire_grace(self) -> None:
        """Discard the previous-epoch state."""
        self._rl_prev = None
        self._rw_prev = None
        if self._rekey_state in (RekeyState.GRACE, RekeyState.ACK_SENT):
            self._rekey_state = RekeyState.IDLE

    def _on_auth_failure(self) -> None:
        self._auth_failures += 1
        if self._auth_failures >= self._config.max_consecutive_auth_failures:
            self._auth_failures = 0
            raise AlertError(
                f"too many consecutive authentication failures "
                f"({self._config.max_consecutive_auth_failures})"
            )
