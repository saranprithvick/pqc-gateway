"""Regression tests for OI-4, OI-5, OI-6, OI-7 (m4-fixes branch).

OI-4  — seal() raises CounterExhausted (never substitutes record types) and queues REKEY_REQ.
OI-5  — duplicate REKEY_REQ bypass is gated on rekey-in-progress state; expired after grace.
OI-6  — RekeyConfig.__post_init__ validates that retry budget < grace_period_s.
OI-7  — src/pqcgw/protocol/ never imports from src/pqcgw/crypto/providers/.
"""

from __future__ import annotations

import ast
import pathlib
from pathlib import Path

import pytest

from pqcgw.crypto.registry import load_suite
from pqcgw.protocol.handshake import HandshakeInitiator, HandshakeResponder, IdentityContext
from pqcgw.protocol.record import Direction, RecordError, RecordType
from pqcgw.protocol.session import (
    AlertError,
    CounterExhausted,
    RekeyConfig,
    SessionManager,
    SessionRole,
)

SUITE_DIR = Path(__file__).parent.parent.parent / "configs" / "suites"
PROTOCOL_DIR = Path(__file__).parent.parent.parent / "src" / "pqcgw" / "protocol"


# ---------------------------------------------------------------------------
# Shared helper (duplicated from test_t8_t10 to keep test isolation)
# ---------------------------------------------------------------------------

def _handshake_both_sides(suite_name: str = "classical"):
    suite = load_suite(SUITE_DIR / f"{suite_name}.toml")
    sig = suite.signature
    gw_pk, gw_sk = sig.keygen()
    peer_pk, peer_sk = sig.keygen()
    init_id = IdentityContext(
        my_id="gw", peer_id="peer",
        my_sk=gw_sk, my_pk=gw_pk, peer_pk=peer_pk,
        allowed_suite_ids=[1, 2, 3],
    )
    resp_id = IdentityContext(
        my_id="peer", peer_id="gw",
        my_sk=peer_sk, my_pk=peer_pk, peer_pk=gw_pk,
        allowed_suite_ids=[1, 2, 3],
    )
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)
    hi = initiator.start()
    hr = responder.process_hello_i(hi)
    fi = initiator.process_hello_r(hr)
    fr, resp_keys = responder.process_finished_i(fi)
    gw_keys = initiator.process_finished_r(fr)
    return suite, gw_keys, resp_keys, initiator.session_id


def _make_managers(suite_name: str = "classical", config: RekeyConfig | None = None):
    suite, gw_keys, peer_keys, session_id = _handshake_both_sides(suite_name)
    cfg = config or RekeyConfig()
    gw_sm = SessionManager(suite, gw_keys, session_id, SessionRole.INITIATOR, config=cfg)
    peer_sm = SessionManager(suite, peer_keys, session_id, SessionRole.RESPONDER, config=cfg)
    return gw_sm, peer_sm


# ===========================================================================
# OI-4: seal() must never substitute record types
# ===========================================================================

class TestOI4CounterExhausted:
    """seal() raises CounterExhausted at the hard limit and queues the REKEY_REQ."""

    def test_seal_raises_counter_exhausted_not_returns_rekey_req(self):
        """seal() must NOT return REKEY_REQ bytes at counter limit; must raise."""
        cfg = RekeyConfig(counter_hard_limit=1)
        gw_sm, _ = _make_managers(config=cfg)
        gw_sm.seal(b"first")           # counter 0 → 1; next seal hits limit
        with pytest.raises(CounterExhausted):
            gw_sm.seal(b"second")       # counter == hard limit → CounterExhausted

    def test_seal_queues_rekey_req_in_outbound(self):
        """REKEY_REQ is queued in the outbound queue, not silently dropped."""
        cfg = RekeyConfig(counter_hard_limit=1)
        gw_sm, _ = _make_managers(config=cfg)
        gw_sm.seal(b"first")
        try:
            gw_sm.seal(b"second")
        except CounterExhausted:
            pass
        req = gw_sm.take_outbound()
        assert req is not None, "REKEY_REQ must be in outbound queue after CounterExhausted"
        # Verify it is actually a REKEY_REQ record
        from pqcgw.protocol.record import RecordHeader
        hdr = RecordHeader.from_bytes(req[:16])
        assert hdr.rtype == RecordType.REKEY_REQ

    def test_rekey_completes_after_counter_exhausted(self):
        """Session can continue after CounterExhausted + completed rekey."""
        cfg = RekeyConfig(counter_hard_limit=2)
        gw_sm, peer_sm = _make_managers(config=cfg)

        gw_sm.seal(b"a")   # counter 0
        gw_sm.seal(b"b")   # counter 1; next hits limit

        try:
            gw_sm.seal(b"c")
        except CounterExhausted:
            pass

        req = gw_sm.take_outbound()
        rtype, _ = peer_sm.open(req, Direction.I2R)
        assert rtype == RecordType.REKEY_REQ
        ack = peer_sm.take_outbound()
        rtype, _ = gw_sm.open(ack, Direction.R2I)
        assert rtype == RecordType.REKEY_ACK

        assert gw_sm.epoch == 1
        new_rec = gw_sm.seal(b"after")
        rtype, pt = peer_sm.open(new_rec, Direction.I2R)
        assert rtype == RecordType.DATA
        assert pt == b"after"


# ===========================================================================
# OI-5: duplicate REKEY_REQ bypass gated on rekey-in-progress state
# ===========================================================================

class TestOI5DuplicateRekeyReqGate:
    """Duplicate REKEY_REQ resend is only active while rekey is in progress."""

    def test_duplicate_req_not_resent_after_grace_expires(self):
        """OI-5 regression: after grace expires (state=IDLE), cached REKEY_REQ/ACK is
        NOT resent — the state guard prevents the bypass path from firing."""
        # grace_period_records=1: one new-epoch record exhausts the record-count window
        cfg = RekeyConfig(grace_period_records=1, grace_period_s=60.0)
        gw_sm, peer_sm = _make_managers(config=cfg)

        # Seal an epoch-0 record before the rekey (we'll use it to trigger grace expiry)
        old_rec = gw_sm.seal(b"epoch0")

        req = gw_sm.initiate_light_rekey()
        peer_sm.open(req, Direction.I2R)   # peer: IDLE → ACK_SENT
        ack1 = peer_sm.take_outbound()
        gw_sm.open(ack1, Direction.R2I)    # gw: switches to epoch 1

        # Send 1 new-epoch record → _new_epoch_records=1 == grace_period_records=1
        new_rec = gw_sm.seal(b"epoch1")
        peer_sm.open(new_rec, Direction.I2R)

        # Routing the old epoch-0 record calls _grace_expired(), which now detects
        # _new_epoch_records >= grace_period_records → calls _expire_grace()
        # → _rekey_state = IDLE, _rl_prev = None.  The old record is then rejected.
        with pytest.raises(RecordError):
            peer_sm.open(old_rec, Direction.I2R)

        # OI-5 assertion: re-delivering the original REKEY_REQ now falls through the
        # state guard (IDLE is not in ACK_SENT|GRACE) and is rejected by epoch routing,
        # NOT resent as a stale ACK.
        with pytest.raises(RecordError):
            peer_sm.open(req, Direction.I2R)

        # No spurious ACK must be in the outbound queue
        assert peer_sm.take_outbound() is None

    def test_duplicate_req_during_grace_resends_cached_ack(self):
        """During grace period (ACK_SENT / GRACE), duplicate REKEY_REQ resends cached ACK."""
        gw_sm, peer_sm = _make_managers()
        req = gw_sm.initiate_light_rekey()

        peer_sm.open(req, Direction.I2R)
        ack1 = peer_sm.take_outbound()
        assert ack1 is not None

        # Second delivery while state is ACK_SENT → resend cached ACK
        peer_sm.open(req, Direction.I2R)
        ack2 = peer_sm.take_outbound()
        assert ack2 is not None

        assert ack1 == ack2, "Cached ACK must be byte-identical"
        assert peer_sm.epoch == 1, "Must NOT have ratcheted again (still epoch 1)"


# ===========================================================================
# OI-6: RekeyConfig validator
# ===========================================================================

class TestOI6ConfigValidator:
    """RekeyConfig.__post_init__ rejects an invalid retry-budget / grace combination."""

    def test_default_config_is_valid(self):
        """Default config: 0.4 × 4 = 1.6 s < 2.0 s — must not raise."""
        cfg = RekeyConfig()   # rekey_timeout_ms=400, rekey_max_retries=3, grace_period_s=2.0
        assert cfg.rekey_timeout_ms == 400
        assert cfg.rekey_max_retries == 3
        assert cfg.grace_period_s == 2.0

    def test_budget_equal_to_grace_raises(self):
        """Budget exactly equal to grace_period_s is rejected."""
        with pytest.raises(ValueError, match="retry budget"):
            # 500 ms × 4 = 2.0 s = grace_period_s → invalid (must be strictly less)
            RekeyConfig(rekey_timeout_ms=500, rekey_max_retries=3, grace_period_s=2.0)

    def test_budget_exceeds_grace_raises(self):
        """Budget exceeding grace_period_s is rejected."""
        with pytest.raises(ValueError, match="retry budget"):
            # 600 ms × 4 = 2.4 s > 2.0 s → invalid
            RekeyConfig(rekey_timeout_ms=600, rekey_max_retries=3, grace_period_s=2.0)

    def test_grace_zero_bypasses_check(self):
        """grace_period_s=0.0 is a test sentinel; validator is skipped."""
        # With any rekey_timeout_ms, budget > 0 >= 0 would fail without the bypass
        cfg = RekeyConfig(grace_period_s=0.0)
        assert cfg.grace_period_s == 0.0

    def test_valid_custom_config(self):
        """A valid custom config: budget=0.3×4=1.2 s < 5.0 s grace."""
        cfg = RekeyConfig(rekey_timeout_ms=300, rekey_max_retries=3, grace_period_s=5.0)
        assert cfg.rekey_timeout_ms == 300

    def test_zero_timeout_valid(self):
        """rekey_timeout_ms=0 produces budget=0.0 < any positive grace_period_s."""
        cfg = RekeyConfig(rekey_timeout_ms=0, rekey_max_retries=0, grace_period_s=2.0)
        assert cfg.rekey_timeout_ms == 0


# ===========================================================================
# OI-7: protocol/ never imports from crypto/providers/
# ===========================================================================

class TestOI7LayerBoundary:
    """No module in src/pqcgw/protocol/ may import from pqcgw.crypto.providers."""

    @pytest.mark.parametrize("py_file", list(PROTOCOL_DIR.glob("*.py")))
    def test_no_providers_import(self, py_file: pathlib.Path):
        """Scan each protocol module's AST for direct providers imports."""
        source = py_file.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py_file))
        violations: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if "crypto.providers" in node.module:
                    violations.append(
                        f"Line {node.lineno}: 'from {node.module} import ...'"
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if "crypto.providers" in alias.name:
                        violations.append(
                            f"Line {node.lineno}: 'import {alias.name}'"
                        )
        assert not violations, (
            f"{py_file.name} imports from crypto.providers (layer violation):\n"
            + "\n".join(violations)
        )
