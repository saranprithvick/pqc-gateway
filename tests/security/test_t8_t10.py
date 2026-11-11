"""Security tests T8 and T10 (rekeying).

T8  — Rekey: records across the epoch boundary survive during grace; old epoch rejected
       after grace period; failed rekey raises ALERT; duplicate REKEY_REQ resends cached ACK.
T10 — Counter exhaustion: low hard limit forces light rekey; failed rekey closes session.

T8/T10 are n/a for C0 (no session manager).
Parametrized over standard suites (C1 classical, C2 pqc, C3 hybrid) and all
matrix agility entries per §4 agility criterion 3.

PQC-heavy matrix variants are marked @pytest.mark.slow.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from pqcgw.crypto.registry import load_suite
from pqcgw.protocol.handshake import HandshakeInitiator, HandshakeResponder, IdentityContext
from pqcgw.protocol.record import Direction, RecordError, RecordType
from pqcgw.protocol.session import AlertError, CounterExhausted, RekeyConfig, SessionManager, SessionRole

from tests.suite_helpers import ALL_SUITE_IDS, MATRIX_EXPERIMENTAL, suite_path

_STANDARD = ["classical", "pqc", "hybrid"]
_MATRIX_NON_EXP = [
    "matrix/base", "matrix/k-512", "matrix/k-768", "matrix/k-1024",
    "matrix/s-44", "matrix/s-87", "matrix/s-slh", "matrix/s-ecdsa",
    "matrix/d-384", "matrix/a-128", "matrix/a-cha",
]

_ALL_SUITE_PARAMS = (
    [pytest.param(s) for s in _STANDARD]
    + [pytest.param(s, marks=pytest.mark.slow) for s in _MATRIX_NON_EXP]
    + [pytest.param(s, marks=pytest.mark.slow) for s in MATRIX_EXPERIMENTAL]
)


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _handshake_both_sides(suite_name: str = "classical"):
    try:
        suite = load_suite(suite_path(suite_name))
    except KeyError as exc:
        pytest.skip(f"mechanism not available in installed liboqs: {exc}")
    sig = suite.signature
    gw_pk, gw_sk = sig.keygen()
    peer_pk, peer_sk = sig.keygen()
    init_id = IdentityContext(
        my_id="gw", peer_id="peer",
        my_sk=gw_sk, my_pk=gw_pk, peer_pk=peer_pk,
        allowed_suite_ids=ALL_SUITE_IDS,
    )
    resp_id = IdentityContext(
        my_id="peer", peer_id="gw",
        my_sk=peer_sk, my_pk=peer_pk, peer_pk=gw_pk,
        allowed_suite_ids=ALL_SUITE_IDS,
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


def _do_light_rekey(gw_sm: SessionManager, peer_sm: SessionManager) -> None:
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

@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t8_records_survive_grace_period(suite_name: str) -> None:
    """Old-epoch records delivered before the grace period expires are accepted."""
    cfg = RekeyConfig(grace_period_records=4, grace_period_s=60.0)
    gw_sm, peer_sm = _make_managers(suite_name, config=cfg)

    old_records = [gw_sm.seal(b"payload" + bytes([i])) for i in range(3)]
    _do_light_rekey(gw_sm, peer_sm)
    assert gw_sm.epoch == 1
    assert peer_sm.epoch == 1

    for rec in old_records:
        rtype, plaintext = peer_sm.open(rec, Direction.I2R)
        assert rtype == RecordType.DATA
        assert plaintext[0:7] == b"payload"


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t8_old_epoch_rejected_after_grace_records(suite_name: str) -> None:
    """Old-epoch records are rejected once the grace-record count is exhausted."""
    cfg = RekeyConfig(grace_period_records=2, grace_period_s=60.0)
    gw_sm, peer_sm = _make_managers(suite_name, config=cfg)

    old_record = gw_sm.seal(b"old")
    _do_light_rekey(gw_sm, peer_sm)

    for i in range(cfg.grace_period_records):
        new_rec = gw_sm.seal(b"new" + bytes([i]))
        peer_sm.open(new_rec, Direction.I2R)

    with pytest.raises(RecordError):
        peer_sm.open(old_record, Direction.I2R)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t8_old_epoch_rejected_after_grace_time(suite_name: str) -> None:
    """Old-epoch records are rejected immediately when grace_period_s=0."""
    cfg = RekeyConfig(grace_period_records=64, grace_period_s=0.0)
    gw_sm, peer_sm = _make_managers(suite_name, config=cfg)

    old_record = gw_sm.seal(b"old")
    _do_light_rekey(gw_sm, peer_sm)

    with pytest.raises(RecordError):
        peer_sm.open(old_record, Direction.I2R)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t8_new_epoch_records_work_after_rekey(suite_name: str) -> None:
    gw_sm, peer_sm = _make_managers(suite_name)
    _do_light_rekey(gw_sm, peer_sm)

    new_rec = gw_sm.seal(b"hello epoch 1")
    rtype, pt = peer_sm.open(new_rec, Direction.I2R)
    assert rtype == RecordType.DATA
    assert pt == b"hello epoch 1"


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t8_duplicate_rekey_req_resends_cached_ack(suite_name: str) -> None:
    gw_sm, peer_sm = _make_managers(suite_name)

    req = gw_sm.initiate_light_rekey()
    peer_sm.open(req, Direction.I2R)
    ack1 = peer_sm.take_outbound()
    assert ack1 is not None

    peer_sm.open(req, Direction.I2R)
    ack2 = peer_sm.take_outbound()
    assert ack2 is not None
    assert ack1 == ack2
    assert peer_sm.epoch == 1


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t8_failed_rekey_raises_alert(suite_name: str) -> None:
    cfg = RekeyConfig(rekey_timeout_ms=0, rekey_max_retries=0)
    gw_sm, peer_sm = _make_managers(suite_name, config=cfg)

    gw_sm.initiate_light_rekey()
    with pytest.raises(AlertError):
        gw_sm.check_rekey_timeout()


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t8_multiple_rekeys_increase_epoch(suite_name: str) -> None:
    cfg = RekeyConfig(grace_period_records=1, grace_period_s=60.0)
    gw_sm, peer_sm = _make_managers(suite_name, config=cfg)

    _do_light_rekey(gw_sm, peer_sm)
    assert gw_sm.epoch == 1
    _do_light_rekey(gw_sm, peer_sm)
    assert gw_sm.epoch == 2
    assert peer_sm.epoch == 2


# ===========================================================================
# T10 — Counter exhaustion
# ===========================================================================

@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t10_counter_limit_triggers_rekey(suite_name: str) -> None:
    """Reaching the counter hard limit causes the initiator to raise CounterExhausted
    and queue the REKEY_REQ; after completing the rekey the session continues."""
    cfg = RekeyConfig(counter_hard_limit=3, grace_period_records=1, grace_period_s=60.0)
    gw_sm, peer_sm = _make_managers(suite_name, config=cfg)

    for i in range(3):
        rec = gw_sm.seal(b"frame" + bytes([i]))
        peer_sm.open(rec, Direction.I2R)

    with pytest.raises(CounterExhausted):
        gw_sm.seal(b"trigger")

    req = gw_sm.take_outbound()
    assert req is not None

    from pqcgw.protocol.record import RecordHeader
    hdr = RecordHeader.from_bytes(req[:16])
    assert hdr.rtype == RecordType.REKEY_REQ

    rtype, _ = peer_sm.open(req, Direction.I2R)
    assert rtype == RecordType.REKEY_REQ
    ack = peer_sm.take_outbound()
    rtype, _ = gw_sm.open(ack, Direction.R2I)
    assert rtype == RecordType.REKEY_ACK
    assert gw_sm.epoch == 1

    new_rec = gw_sm.seal(b"after rekey")
    rtype, pt = peer_sm.open(new_rec, Direction.I2R)
    assert rtype == RecordType.DATA
    assert pt == b"after rekey"


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t10_counter_limit_closes_on_failed_rekey(suite_name: str) -> None:
    cfg = RekeyConfig(counter_hard_limit=1, rekey_timeout_ms=0, rekey_max_retries=0)
    gw_sm, _ = _make_managers(suite_name, config=cfg)

    gw_sm.seal(b"a")
    with pytest.raises(CounterExhausted):
        gw_sm.seal(b"b")
    with pytest.raises(AlertError):
        gw_sm.check_rekey_timeout()
