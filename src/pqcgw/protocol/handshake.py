"""Handshake state machines: initiator (gateway) and responder (peer).

3-message handshake + FINISHED_R (§5.2, §15 items 9, 11, 14):

  I → R : HELLO_I
  R → I : HELLO_R
  I → R : FINISHED_I   = HMAC(k_finished, "I" || th)
  R → I : FINISHED_R   = HMAC(k_finished, "R" || th || finished_i_bytes)

The initiator treats the session as established only after verifying FINISHED_R.
The responder may send DATA after verifying FINISHED_I (implemented in M3+).

Abort behaviour: any verification failure raises HandshakeError with a local
log message.  No distinguishing error detail is sent on the wire.

HMAC verification uses hmac.compare_digest to prevent timing side-channels.

Identity keys are loaded externally and passed as IdentityContext; the
handshake state machines do not load files.  Ephemeral KEM keys are generated
inside start() / process_hello_i() using the OS CSPRNG via the KEM provider.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac_module
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from pqcgw.crypto.registry import Suite
from pqcgw.protocol.keyschedule import SessionKeys, derive_session_keys, suite_hash
from pqcgw.protocol.messages import HelloI, HelloR

log = logging.getLogger(__name__)

_PROTOCOL_VERSION = 1


class HandshakeError(Exception):
    """Raised on any handshake failure.  Detail is logged locally; not sent on wire."""


@dataclass
class IdentityContext:
    """Long-term identity material for one side of the handshake."""

    my_id: str
    peer_id: str
    my_sk: bytes          # signing secret key
    my_pk: bytes          # signing public key
    peer_pk: bytes        # peer's signing public key (pre-provisioned trust anchor)
    allowed_suite_ids: list[int]


# ---------------------------------------------------------------------------
# HMAC helpers (constant-time comparison per CLAUDE.md §2)
# ---------------------------------------------------------------------------

def _hmac_digest(key: bytes, msg: bytes, hash_fn) -> bytes:
    return _hmac_module.new(key, msg, hash_fn).digest()


def _hmac_verify(key: bytes, msg: bytes, expected: bytes, hash_fn) -> bool:
    actual = _hmac_digest(key, msg, hash_fn)
    return _hmac_module.compare_digest(actual, expected)


# ---------------------------------------------------------------------------
# HandshakeInitiator  (Gateway = initiator, §3)
# ---------------------------------------------------------------------------

class HandshakeInitiator:
    """Handshake initiator state machine.

    States: IDLE → HELLO_SENT → KEYS_DERIVED → ESTABLISHED | FAILED
    """

    def __init__(self, suite: Suite, identity: IdentityContext) -> None:
        self._suite = suite
        self._identity = identity
        self._state = "IDLE"
        self._session_id: Optional[bytes] = None
        self._kem_sk: Optional[bytes] = None
        self._nonce_i: Optional[bytes] = None
        self._hello_i_bytes: Optional[bytes] = None
        self._keys: Optional[SessionKeys] = None
        self._finished_i: Optional[bytes] = None
        self._th: Optional[bytes] = None
        self._hash_fn = suite_hash(suite)

    # -- public API ----------------------------------------------------------

    @property
    def state(self) -> str:
        return self._state

    @property
    def session_id(self) -> Optional[bytes]:
        return self._session_id

    def start(self) -> bytes:
        """Generate HELLO_I and return its wire bytes."""
        if self._state != "IDLE":
            raise HandshakeError(f"start() called in state {self._state}")

        session_id = os.urandom(4)
        nonce_i = os.urandom(32)
        kem_pk, kem_sk = self._suite.kem.keygen()

        msg = HelloI(
            version=_PROTOCOL_VERSION,
            suite_id=self._suite.suite_id,
            session_id=session_id,
            gateway_id=self._identity.my_id,
            peer_id=self._identity.peer_id,
            nonce_i=nonce_i,
            kem_pk=kem_pk,
        )
        body = msg.body_bytes()
        sig = self._suite.signature.sign(
            self._identity.my_sk,
            b"hs-v1-I" + self._hash_fn(body).digest(),
        )
        msg.sig = sig
        hello_i_bytes = msg.to_bytes()

        self._session_id = session_id
        self._kem_sk = kem_sk
        self._nonce_i = nonce_i
        self._hello_i_bytes = hello_i_bytes
        self._state = "HELLO_SENT"
        return hello_i_bytes

    def process_hello_r(self, data: bytes) -> bytes:
        """Parse HELLO_R, verify, decapsulate, derive keys; return FINISHED_I bytes."""
        if self._state != "HELLO_SENT":
            raise HandshakeError(f"process_hello_r() called in state {self._state}")
        try:
            msg = HelloR.from_bytes(data)
        except ValueError as exc:
            self._fail(f"HELLO_R parse error: {exc}")

        # Validate fields
        if msg.version != _PROTOCOL_VERSION:
            self._fail(f"HELLO_R version mismatch: {msg.version}")
        if msg.suite_id != self._suite.suite_id:
            self._fail(f"HELLO_R suite_id mismatch: {msg.suite_id}")
        if msg.session_id != self._session_id:
            self._fail("HELLO_R session_id mismatch")

        # Verify sig_R: Sign(sk_peer, "hs-v1-R" || H(hello_i || hello_r_body))
        hello_r_body = msg.body_bytes()
        expected_sig_input = (
            b"hs-v1-R"
            + self._hash_fn(self._hello_i_bytes + hello_r_body).digest()
        )
        if not self._suite.signature.verify(
            self._identity.peer_pk, expected_sig_input, msg.sig
        ):
            self._fail("HELLO_R signature verification failed")

        # Decapsulate
        try:
            ss = self._suite.kem.decaps(self._kem_sk, msg.kem_ct)
        except Exception as exc:
            self._fail(f"KEM decapsulation failed: {exc}")

        # Transcript hash and key derivation
        hello_r_bytes = data
        th = self._hash_fn(self._hello_i_bytes + hello_r_bytes).digest()
        self._th = th
        self._keys = derive_session_keys(
            self._suite, ss, self._nonce_i, msg.nonce_r, th
        )

        # FINISHED_I = HMAC(k_finished, "I" || th)  §15 item 14
        finished_i = _hmac_digest(
            self._keys.k_finished, b"I" + th, self._hash_fn
        )
        self._finished_i = finished_i
        self._state = "KEYS_DERIVED"
        return finished_i

    def process_finished_r(self, data: bytes) -> SessionKeys:
        """Verify FINISHED_R and return session keys."""
        if self._state != "KEYS_DERIVED":
            raise HandshakeError(f"process_finished_r() called in state {self._state}")

        # FINISHED_R = HMAC(k_finished, "R" || th || finished_i_bytes)  §15 item 14
        expected = _hmac_digest(
            self._keys.k_finished,
            b"R" + self._th + self._finished_i,
            self._hash_fn,
        )
        if not _hmac_module.compare_digest(expected, data):
            self._fail("FINISHED_R verification failed")

        self._state = "ESTABLISHED"
        log.debug("Initiator: session established, session_id=%s", self._session_id.hex())
        return self._keys

    # -- internal ------------------------------------------------------------

    def _fail(self, reason: str):
        log.warning("Handshake initiator failure: %s", reason)
        self._state = "FAILED"
        raise HandshakeError(reason)


# ---------------------------------------------------------------------------
# HandshakeResponder  (ModernPeer = responder, §3)
# ---------------------------------------------------------------------------

class HandshakeResponder:
    """Handshake responder state machine.

    States: IDLE → HELLO_RECEIVED → ESTABLISHED | FAILED

    Responder cache (§15 item 9): HELLO_R is cached keyed by
    (session_id, H(hello_i_bytes)) and resent byte-identical on duplicate
    HELLO_I without re-encapsulation or re-signing.
    """

    def __init__(self, suite: Suite, identity: IdentityContext) -> None:
        self._suite = suite
        self._identity = identity
        self._state = "IDLE"
        self._session_id: Optional[bytes] = None
        self._ss: Optional[bytes] = None
        self._hello_i_bytes: Optional[bytes] = None
        self._hello_r_bytes: Optional[bytes] = None
        self._nonce_r: Optional[bytes] = None
        self._hash_fn = suite_hash(suite)
        # cache: (session_id_hex, hello_i_hash_hex) → hello_r_bytes
        self._cache: dict[tuple[str, str], bytes] = {}

    @property
    def state(self) -> str:
        return self._state

    @property
    def session_id(self) -> Optional[bytes]:
        return self._session_id

    def process_hello_i(self, data: bytes) -> bytes:
        """Parse HELLO_I, verify, encapsulate, return HELLO_R bytes."""
        try:
            msg = HelloI.from_bytes(data)
        except ValueError as exc:
            self._fail(f"HELLO_I parse error: {exc}")

        # Downgrade protection: suite_id must be in allowed list (§5.4)
        if msg.suite_id not in self._identity.allowed_suite_ids:
            self._fail(
                f"suite_id {msg.suite_id} not in allowed list "
                f"{self._identity.allowed_suite_ids}"
            )

        # Check peer_id is us
        if msg.peer_id != self._identity.my_id:
            self._fail(f"peer_id mismatch: expected {self._identity.my_id!r}, got {msg.peer_id!r}")

        if msg.version != _PROTOCOL_VERSION:
            self._fail(f"HELLO_I version mismatch: {msg.version}")

        # Verify sig_I: Sign(sk_gateway, "hs-v1-I" || H(body_bytes))
        body = msg.body_bytes()
        expected_sig_input = b"hs-v1-I" + self._hash_fn(body).digest()
        if not self._suite.signature.verify(
            self._identity.peer_pk, expected_sig_input, msg.sig
        ):
            self._fail("HELLO_I signature verification failed")

        # Cache check (§15 item 9): resend byte-identical HELLO_R on duplicate
        hello_i_hash = self._hash_fn(data).hexdigest()
        cache_key = (msg.session_id.hex(), hello_i_hash)
        if cache_key in self._cache:
            log.debug("Responder: cache hit for session_id=%s", msg.session_id.hex())
            return self._cache[cache_key]

        # Encapsulate to initiator's KEM public key
        try:
            kem_ct, ss = self._suite.kem.encaps(msg.kem_pk)
        except Exception as exc:
            self._fail(f"KEM encapsulation failed: {exc}")

        nonce_r = os.urandom(32)

        hello_r_msg = HelloR(
            version=_PROTOCOL_VERSION,
            suite_id=msg.suite_id,
            session_id=msg.session_id,
            nonce_r=nonce_r,
            kem_ct=kem_ct,
        )
        hello_r_body = hello_r_msg.body_bytes()
        sig_r = self._suite.signature.sign(
            self._identity.my_sk,
            b"hs-v1-R" + self._hash_fn(data + hello_r_body).digest(),
        )
        hello_r_msg.sig = sig_r
        hello_r_bytes = hello_r_msg.to_bytes()

        # Store state for FINISHED processing
        self._session_id = msg.session_id
        self._ss = ss
        self._nonce_i = msg.nonce_i
        self._nonce_r = nonce_r
        self._hello_i_bytes = data
        self._hello_r_bytes = hello_r_bytes

        self._cache[cache_key] = hello_r_bytes
        self._state = "HELLO_RECEIVED"
        return hello_r_bytes

    def process_finished_i(self, data: bytes) -> tuple[bytes, SessionKeys]:
        """Verify FINISHED_I, derive keys, return (FINISHED_R bytes, SessionKeys)."""
        if self._state != "HELLO_RECEIVED":
            raise HandshakeError(f"process_finished_i() called in state {self._state}")

        th = self._hash_fn(self._hello_i_bytes + self._hello_r_bytes).digest()
        keys = derive_session_keys(
            self._suite, self._ss, self._nonce_i, self._nonce_r, th
        )

        # Verify FINISHED_I = HMAC(k_finished, "I" || th)  §15 item 14
        if not _hmac_verify(keys.k_finished, b"I" + th, data, self._hash_fn):
            self._fail("FINISHED_I verification failed")

        # Produce FINISHED_R = HMAC(k_finished, "R" || th || finished_i_bytes)
        finished_r = _hmac_digest(
            keys.k_finished, b"R" + th + data, self._hash_fn
        )

        self._state = "ESTABLISHED"
        log.debug("Responder: session established, session_id=%s", self._session_id.hex())
        return finished_r, keys

    def _fail(self, reason: str):
        log.warning("Handshake responder failure: %s", reason)
        self._state = "FAILED"
        raise HandshakeError(reason)
