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
seal() triggers a light rekey, queues the REKEY_REQ via take_outbound(), and raises
CounterExhausted.  The caller buffers the unsent frame and flushes after the new epoch is
active.  If a rekey is already in progress or the timeout has expired, AlertError is raised.

Duplicate REKEY_REQ (§15 item 21): a second identical REKEY_REQ during the grace period
makes the responder resend the cached ACK byte-for-byte without ratcheting again.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
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
class RekeyTrigger:
    """Config for automatic rekey triggers in the Gateway run loop.

    All fields default to 0 (disabled).  Values are loadable from TOML config
    by M7 (e.g. configs/sessions/default.toml).
    """

    interval_s: float = 0.0    # trigger after this many seconds (0 = off)
    record_count: int = 0       # trigger after this many records sealed (0 = off)
    byte_count: int = 0         # trigger after this many payload bytes sealed (0 = off)


@dataclass
class RekeyConfig:
    """Configurable limits and timeouts for the session manager.

    Validation invariant (§15 item 21, OI-6):
        rekey_timeout_ms / 1000 * (rekey_max_retries + 1) < grace_period_s
    With defaults: 0.4 × 4 = 1.6 s < 2.0 s — the worst-case retry budget
    is strictly inside the grace window so the last ACK cannot arrive after
    grace has already expired.
    """

    counter_hard_limit: int = 2 ** 32
    max_consecutive_auth_failures: int = 10
    # grace_period_s: seconds after epoch switch before old-epoch records are rejected.
    # 0.0 = no grace period (test-only sentinel): old-epoch records are rejected
    # immediately; a lost REKEY_ACK closes the session via AlertError.
    # Validator check is skipped when grace_period_s == 0.0.
    grace_period_s: float = 2.0
    grace_period_records: int = 64
    rekey_timeout_ms: int = 400   # fixed per retry, no backoff (§15 item 21 / OI-6)
    rekey_max_retries: int = 3

    def __post_init__(self) -> None:
        # grace_period_s=0.0 is a test-only sentinel for instant expiry; skip budget check.
        if self.grace_period_s > 0:
            budget_s = (self.rekey_timeout_ms / 1000) * (self.rekey_max_retries + 1)
            if budget_s >= self.grace_period_s:
                raise ValueError(
                    f"RekeyConfig: retry budget {budget_s:.3f} s "
                    f"(rekey_timeout_ms={self.rekey_timeout_ms} × "
                    f"(rekey_max_retries+1)={self.rekey_max_retries + 1}) "
                    f"must be strictly less than grace_period_s={self.grace_period_s}. "
                    f"Increase grace_period_s or reduce rekey_timeout_ms/rekey_max_retries."
                )


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


class CounterExhausted(SessionError):
    """Outbound counter reached the hard limit; a light rekey was triggered.

    The caller must buffer the unsent frame (bounded queue, 64 max, drop-oldest)
    and flush it once the new epoch is active.  On rekey failure the session will
    be closed via AlertError and buffered frames are counted as lost (§15 item 20).
    The REKEY_REQ record is queued in outbound; drain it via take_outbound().
    """


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

        # Closed flag: set to True on AlertError; subsequent seal/open raise SessionError
        self._closed: bool = False

        # Outbound message queue (control messages queued by open())
        self._outbound_queue: list[bytes] = []

        # Cached REKEY_REQ bytes for retransmit on timeout (initiator only)
        self._cached_initiator_req: bytes | None = None

        # Previous session_id during grace (for _route_open session_id guard)
        self._prev_session_id: bytes | None = None

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    @property
    def epoch(self) -> int:
        return self._rl_current._keys.epoch

    @property
    def closed(self) -> bool:
        """True after a fatal AlertError; subsequent seal/open raise SessionError."""
        return self._closed

    @property
    def rekey_state(self) -> RekeyState:
        return self._rekey_state

    @property
    def consecutive_auth_failures(self) -> int:
        return self._auth_failures

    @property
    def known_session_ids(self) -> frozenset[bytes]:
        """Current and previous (grace-period) session ids."""
        ids: set[bytes] = {self._session_id}
        if self._prev_session_id is not None:
            ids.add(self._prev_session_id)
        return frozenset(ids)

    def seal(
        self,
        plaintext: bytes,
        rtype: RecordType = RecordType.DATA,
        direction: Direction = Direction.I2R,
    ) -> bytes:
        """Encrypt plaintext into a wire record under the current epoch.

        Raises CounterExhausted if the outbound counter has reached counter_hard_limit.
        In that case a light rekey is triggered and the REKEY_REQ is queued in the
        outbound queue (drain via take_outbound()).  The caller must buffer the unsent
        plaintext frame until the new epoch is active (§15 item 20 / OI-4).

        Raises AlertError if epoch == 255 (full rekey required), or if a rekey was
        already in progress and timed out.
        Raises SessionError if the session has been closed by a prior AlertError.
        """
        if self._closed:
            raise SessionError("session is closed")
        # Epoch 255 guard: full rekey must be done before wrapping (§5.7)
        if self._rl_current._keys.epoch >= 255:
            self._close()
            raise AlertError("epoch limit reached; full rekey required before epoch 255")

        # Check for a pending rekey timeout before sealing data
        if self._rekey_state == RekeyState.REQ_SENT:
            self.check_rekey_timeout()

        # Counter hard-limit trigger (OI-4)
        current_counter = self._rl_current._counters[direction]
        if current_counter >= self._config.counter_hard_limit:
            if self._role != SessionRole.INITIATOR:
                self._close()
                raise AlertError("counter hard limit reached on responder; initiator must trigger rekey")
            if self._rekey_state == RekeyState.REQ_SENT:
                # Rekey already in progress; check timeout
                self.check_rekey_timeout()
                self._close()
                raise AlertError("counter hard limit reached and rekey did not complete")
            log.info("Counter hard limit %d reached; triggering light rekey", self._config.counter_hard_limit)
            req = self.initiate_light_rekey()
            self._outbound_queue.append(req)   # caller drains via take_outbound()
            raise CounterExhausted(
                f"counter hard limit {self._config.counter_hard_limit} reached; "
                "light rekey triggered — buffer this frame and flush after epoch switch"
            )

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
        Raises SessionError if the session has been closed by a prior AlertError.
        """
        if self._closed:
            raise SessionError("session is closed")
        if len(data) < _HEADER_LEN:
            raise RecordError("Record too short")

        # Duplicate REKEY_REQ check (§15 item 21 / OI-5): perform raw-bytes comparison
        # BEFORE going through the replay window, since a retransmitted REKEY_REQ
        # would otherwise be rejected as a duplicate counter.
        # Gate: only while a rekey is in progress (ACK_SENT or GRACE); after grace
        # the duplicate check is not active and the REKEY_REQ goes through normally
        # (which will fail replay-window validation, as expected).
        if (
            self._role == SessionRole.RESPONDER
            and self._rekey_state in (RekeyState.ACK_SENT, RekeyState.GRACE)
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
            if hdr.session_id == self._session_id and hdr.epoch == self._rl_current._keys.epoch:
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
            self._close()
            raise AlertError("epoch limit reached; use full rekey")

        # Derive next-epoch keys but do NOT switch yet
        self._pending_next_keys = derive_rekey_epoch(self._suite, self._rl_current._keys)
        self._rekey_state = RekeyState.REQ_SENT
        self._rekey_timer_start = time.monotonic()

        req = self._rl_current.seal(RecordType.REKEY_REQ, b"", Direction.I2R)
        self._cached_initiator_req = req   # stored for retransmit on timeout
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
        if elapsed >= self._config.rekey_timeout_ms / 1000:
            if self._rekey_retries >= self._config.rekey_max_retries:
                self._rekey_state = RekeyState.IDLE
                self._close()
                raise AlertError(
                    f"rekey timed out after {self._rekey_retries} retries; closing session"
                )
            self._rekey_retries += 1
            self._rekey_timer_start = time.monotonic()
            if self._cached_initiator_req is not None:
                self._outbound_queue.append(self._cached_initiator_req)

    def promote_full_rekey(self, new_keys: SessionKeys, new_session_id: bytes) -> None:
        """Swap in a freshly completed full-rekey session (§15 item 16).

        The old session enters the grace period; the caller must continue to handle
        inbound records with the old session_id until the grace period expires.
        """
        self._prev_session_id = self._session_id   # captured before _start_grace
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
        """Route a record to the right RecordLayer by session_id and epoch.

        Guarding by session_id prevents the edge case where a full-rekey new session
        and the old session's first epoch share epoch==0.
        """
        cur_epoch = self._rl_current._keys.epoch

        if hdr.session_id == self._session_id and hdr.epoch == cur_epoch:
            try:
                return self._rl_current.open(data, direction, self._rw_current[direction])
            except RecordError:
                self._on_auth_failure()
                raise

        # Try previous session/epoch during grace period
        if (
            self._rl_prev is not None
            and hdr.session_id == self._prev_session_id
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
            f"Record session/epoch ({hdr.session_id.hex()}/{hdr.epoch}) not accepted "
            f"(current={self._session_id.hex()}/{cur_epoch}, "
            f"grace={'active' if self._rl_prev else 'none'})"
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
        # For light rekey old == new session_id; for full rekey caller sets _prev_session_id first.
        if self._prev_session_id is None:
            self._prev_session_id = self._session_id
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
        self._prev_session_id = None
        if self._rekey_state in (RekeyState.GRACE, RekeyState.ACK_SENT):
            self._rekey_state = RekeyState.IDLE

    def _close(self) -> None:
        """Mark the session permanently closed; subsequent seal/open raise SessionError."""
        self._closed = True
        log.info("Session closed (session_id=%s)", self._session_id.hex())

    def _on_auth_failure(self) -> None:
        self._auth_failures += 1
        if self._auth_failures >= self._config.max_consecutive_auth_failures:
            self._auth_failures = 0
            self._close()
            raise AlertError(
                f"too many consecutive authentication failures "
                f"({self._config.max_consecutive_auth_failures})"
            )
