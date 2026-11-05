"""Security tests T8 and T10 (M4 — rekeying).

T8  — Rekey: records across the epoch boundary survive during grace; old epoch rejected
       after grace period; failed rekey raises ALERT; duplicate REKEY_REQ resends cached ACK.
T10 — Counter exhaustion: low hard limit forces light rekey; failed rekey closes session.

C0 cases deferred to M6 (passthrough not yet implemented).
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from pqcgw.crypto.registry import load_suite
from pqcgw.protocol.handshake import HandshakeInitiator, HandshakeResponder, IdentityContext
from pqcgw.protocol.record import Direction, RecordError, RecordType
from pqcgw.protocol.session import AlertError, CounterExhausted, RekeyConfig, SessionManager, SessionRole

SUITE_DIR = Path(__file__).parent.parent.parent / "configs" / "suites"


# ---------------------------------------------------------------------------
# Shared helper
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
    """Return (gw_sm, peer_sm) with matched SessionManagers."""
    suite, gw_keys, peer_keys, session_id = _handshake_both_sides(suite_name)
    cfg = config or RekeyConfig()
    gw_sm = SessionManager(suite, gw_keys, session_id, SessionRole.INITIATOR, config=cfg)
    peer_sm = SessionManager(suite, peer_keys, session_id, SessionRole.RESPONDER, config=cfg)
    return gw_sm, peer_sm


def _do_light_rekey(gw_sm: SessionManager, peer_sm: SessionManager) -> None:
    """Drive a complete light-rekey exchange between two SessionManagers."""
    req = gw_sm.initiate_light_rekey()
    rtype, _ = peer_sm.open(req, Direction.I2R)
    assert rtype == RecordType.REKEY_REQ
    ack = peer_sm.take_outbound()
    assert ack is not None
    rtype, _ = gw_sm.open(ack, Direction.R2I)
    assert rtype == RecordType.REKEY_ACK


# ===========================================================================
# T8 — Rekey boundary and grace period
# ===========================================================================

def test_t8_records_survive_grace_period() -> None:
    """Old-epoch records delivered before the grace period expires are accepted."""
    cfg = RekeyConfig(grace_period_records=4, grace_period_s=60.0)
    gw_sm, peer_sm = _make_managers(config=cfg)

    # Seal 3 records before the rekey
    old_records = [gw_sm.seal(b"payload" + bytes([i])) for i in range(3)]

    # Execute light rekey
    _do_light_rekey(gw_sm, peer_sm)

    # Both sides should now be on epoch 1
    assert gw_sm.epoch == 1
    assert peer_sm.epoch == 1

    # Old-epoch records must still be accepted (grace window not exhausted)
    for rec in old_records:
        rtype, plaintext = peer_sm.open(rec, Direction.I2R)
        assert rtype == RecordType.DATA
        assert plaintext[0:7] == b"payload"


def test_t8_old_epoch_rejected_after_grace_records() -> None:
    """Old-epoch records are rejected once the grace-record count is exhausted."""
    cfg = RekeyConfig(grace_period_records=2, grace_period_s=60.0)
    gw_sm, peer_sm = _make_managers(config=cfg)

    old_record = gw_sm.seal(b"old")
    _do_light_rekey(gw_sm, peer_sm)

    # Exhaust the grace window (send grace_period_records new-epoch records)
    for i in range(cfg.grace_period_records):
        new_rec = gw_sm.seal(b"new" + bytes([i]))
        peer_sm.open(new_rec, Direction.I2R)

    # Old-epoch record must now be rejected
    with pytest.raises(RecordError):
        peer_sm.open(old_record, Direction.I2R)


def test_t8_old_epoch_rejected_after_grace_time() -> None:
    """Old-epoch records are rejected immediately when grace_period_s=0."""
    cfg = RekeyConfig(grace_period_records=64, grace_period_s=0.0)
    gw_sm, peer_sm = _make_managers(config=cfg)

    old_record = gw_sm.seal(b"old")
    _do_light_rekey(gw_sm, peer_sm)

    # grace_period_s=0 means grace has already expired
    with pytest.raises(RecordError):
        peer_sm.open(old_record, Direction.I2R)


def test_t8_new_epoch_records_work_after_rekey() -> None:
    """Data records sealed after rekey are accepted on the new epoch."""
    gw_sm, peer_sm = _make_managers()
    _do_light_rekey(gw_sm, peer_sm)

    new_rec = gw_sm.seal(b"hello epoch 1")
    rtype, pt = peer_sm.open(new_rec, Direction.I2R)
    assert rtype == RecordType.DATA
    assert pt == b"hello epoch 1"


def test_t8_duplicate_rekey_req_resends_cached_ack() -> None:
    """A second identical REKEY_REQ makes the responder resend a byte-identical ACK."""
    gw_sm, peer_sm = _make_managers()

    req = gw_sm.initiate_light_rekey()

    # First delivery
    peer_sm.open(req, Direction.I2R)
    ack1 = peer_sm.take_outbound()
    assert ack1 is not None

    # Second delivery of the same REKEY_REQ (simulate retransmit)
    peer_sm.open(req, Direction.I2R)
    ack2 = peer_sm.take_outbound()
    assert ack2 is not None

    # Both ACKs must be byte-identical (cached, not re-ratcheted)
    assert ack1 == ack2

    # Peer must still be on epoch 1 (not epoch 2)
    assert peer_sm.epoch == 1


def test_t8_failed_rekey_raises_alert() -> None:
    """If REKEY_ACK never arrives and the timeout expires, AlertError is raised."""
    cfg = RekeyConfig(rekey_timeout_ms=0, rekey_max_retries=0)
    gw_sm, peer_sm = _make_managers(config=cfg)

    gw_sm.initiate_light_rekey()
    # Timeout has already expired (rekey_timeout_ms=0)
    with pytest.raises(AlertError):
        gw_sm.check_rekey_timeout()


def test_t8_multiple_rekeys_increase_epoch() -> None:
    """Running two successive light rekeys advances epoch by 2."""
    cfg = RekeyConfig(grace_period_records=1, grace_period_s=60.0)
    gw_sm, peer_sm = _make_managers(config=cfg)

    _do_light_rekey(gw_sm, peer_sm)
    assert gw_sm.epoch == 1

    _do_light_rekey(gw_sm, peer_sm)
    assert gw_sm.epoch == 2
    assert peer_sm.epoch == 2


# ===========================================================================
# T10 — Counter exhaustion
# ===========================================================================

def test_t10_counter_limit_triggers_rekey() -> None:
    """Reaching the counter hard limit causes the initiator to raise CounterExhausted
    and queue the REKEY_REQ; after completing the rekey the session continues."""
    # counter_hard_limit=3: after sealing counters 0,1,2, the next seal fires the trigger
    cfg = RekeyConfig(counter_hard_limit=3, grace_period_records=1, grace_period_s=60.0)
    gw_sm, peer_sm = _make_managers(config=cfg)

    # Seal records with counters 0, 1, 2 — all succeed
    for i in range(3):
        rec = gw_sm.seal(b"frame" + bytes([i]))
        peer_sm.open(rec, Direction.I2R)

    # The 4th seal hits counter == hard limit → CounterExhausted; REKEY_REQ queued
    with pytest.raises(CounterExhausted):
        gw_sm.seal(b"trigger")

    # Retrieve the REKEY_REQ from the outbound queue
    req = gw_sm.take_outbound()
    assert req is not None, "REKEY_REQ should be in the outbound queue"

    # Verify the queued record is a REKEY_REQ
    from pqcgw.protocol.record import RecordHeader
    hdr = RecordHeader.from_bytes(req[:16])
    assert hdr.rtype == RecordType.REKEY_REQ

    # Complete the rekey
    rtype, _ = peer_sm.open(req, Direction.I2R)
    assert rtype == RecordType.REKEY_REQ
    ack = peer_sm.take_outbound()
    rtype, _ = gw_sm.open(ack, Direction.R2I)
    assert rtype == RecordType.REKEY_ACK

    assert gw_sm.epoch == 1

    # Session continues on epoch 1
    new_rec = gw_sm.seal(b"after rekey")
    rtype, pt = peer_sm.open(new_rec, Direction.I2R)
    assert rtype == RecordType.DATA
    assert pt == b"after rekey"


def test_t10_counter_limit_closes_on_failed_rekey() -> None:
    """Counter exhaustion raises CounterExhausted; with zero timeout the subsequent
    check_rekey_timeout call raises AlertError (session closes)."""
    # counter_hard_limit=1: after sealing counter 0, next seal fires the trigger
    cfg = RekeyConfig(counter_hard_limit=1, rekey_timeout_ms=0, rekey_max_retries=0)
    gw_sm, _ = _make_managers(config=cfg)

    # First seal uses counter 0; counter becomes 1 (== hard limit)
    gw_sm.seal(b"a")

    # Second seal hits the counter limit → CounterExhausted + REKEY_REQ queued
    with pytest.raises(CounterExhausted):
        gw_sm.seal(b"b")

    # Rekey is in progress (REQ_SENT), timeout is 0ms → AlertError on next check
    with pytest.raises(AlertError):
        gw_sm.check_rekey_timeout()
