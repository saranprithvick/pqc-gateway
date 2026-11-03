"""M3 unit tests: record layer round-trips, overhead size, nonce KAT,
direction isolation, header parse round-trip.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from pqcgw.crypto.registry import load_suite
from pqcgw.protocol.handshake import (
    HandshakeInitiator,
    HandshakeResponder,
    IdentityContext,
)
from pqcgw.protocol.record import (
    Direction,
    RecordError,
    RecordHeader,
    RecordLayer,
    RecordType,
)
from pqcgw.protocol.replay import ReplayWindow

SUITE_DIR = Path(__file__).parent.parent.parent / "configs" / "suites"


# ---------------------------------------------------------------------------
# Helper: run a full handshake and return (initiator_keys, session_id, suite)
# ---------------------------------------------------------------------------

def _handshake(suite_name: str):
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

    hello_i = initiator.start()
    hello_r = responder.process_hello_i(hello_i)
    fin_i = initiator.process_hello_r(hello_r)
    fin_r, resp_keys = responder.process_finished_i(fin_i)
    init_keys = initiator.process_finished_r(fin_r)

    session_id = initiator.session_id
    return suite, init_keys, session_id


# ===========================================================================
# 1. Round-trip for C1, C2, C3
# ===========================================================================

@pytest.mark.parametrize("suite_name", ["classical", "pqc", "hybrid"])
def test_roundtrip(suite_name: str) -> None:
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    pt = b"hello world"
    record = rl.seal(RecordType.DATA, pt, Direction.I2R)
    rtype, recovered = rl.open(record, Direction.I2R, rw)
    assert rtype == RecordType.DATA
    assert recovered == pt


@pytest.mark.parametrize("suite_name", ["classical", "pqc", "hybrid"])
def test_roundtrip_r2i(suite_name: str) -> None:
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    pt = b"response payload"
    record = rl.seal(RecordType.DATA, pt, Direction.R2I)
    rtype, recovered = rl.open(record, Direction.R2I, rw)
    assert rtype == RecordType.DATA
    assert recovered == pt


# ===========================================================================
# 2. Overhead size: header (16 B) + ciphertext + tag
# ===========================================================================

@pytest.mark.parametrize("suite_name", ["classical", "pqc", "hybrid"])
def test_overhead_size(suite_name: str) -> None:
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)

    pt = b"A" * 8  # 8-byte payload
    record = rl.seal(RecordType.DATA, pt, Direction.I2R)
    expected = 16 + len(pt) + suite.aead.tag_len
    assert len(record) == expected, (
        f"{suite_name}: expected {expected} B, got {len(record)} B"
    )


# ===========================================================================
# 3. Nonce KAT: first three seals use counters 0, 1, 2
# ===========================================================================

def test_counter_starts_at_zero() -> None:
    suite, keys, session_id = _handshake("classical")
    rl = RecordLayer(suite, keys, session_id)

    records = [rl.seal(RecordType.DATA, b"x", Direction.I2R) for _ in range(3)]
    # Counter is bytes 6–13 of the 16-byte header
    for i, rec in enumerate(records):
        counter = struct.unpack(">Q", rec[6:14])[0]
        assert counter == i, f"Expected counter {i}, got {counter}"


# ===========================================================================
# 4. Counter auto-increments → different nonces per record
# ===========================================================================

def test_different_nonces_per_seal() -> None:
    suite, keys, session_id = _handshake("classical")
    rl = RecordLayer(suite, keys, session_id)

    r1 = rl.seal(RecordType.DATA, b"a", Direction.I2R)
    r2 = rl.seal(RecordType.DATA, b"a", Direction.I2R)
    # Counter bytes differ
    assert r1[6:14] != r2[6:14]
    # Ciphertext also differs (different nonce)
    assert r1[16:] != r2[16:]


# ===========================================================================
# 5. Direction isolation: I2R record cannot be opened as R2I (wrong key)
# ===========================================================================

def test_direction_isolation() -> None:
    suite, keys, session_id = _handshake("classical")
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"secret", Direction.I2R)
    with pytest.raises(RecordError):
        rl.open(record, Direction.R2I, rw)


# ===========================================================================
# 6. Header parse round-trip
# ===========================================================================

def test_header_parse_roundtrip() -> None:
    h = RecordHeader(
        version=1,
        rtype=RecordType.DATA,
        session_id=b"\x01\x02\x03\x04",
        epoch=0,
        counter=12345,
        payload_length=64,
    )
    assert RecordHeader.from_bytes(h.to_bytes()) == h


@pytest.mark.parametrize("rtype", list(RecordType))
def test_header_all_record_types(rtype: RecordType) -> None:
    h = RecordHeader(
        version=1, rtype=rtype,
        session_id=b"\xde\xad\xbe\xef",
        epoch=2, counter=0, payload_length=0,
    )
    assert RecordHeader.from_bytes(h.to_bytes()) == h


# ===========================================================================
# 7. Multiple records in sequence all decrypt correctly
# ===========================================================================

def test_sequence_of_records() -> None:
    suite, keys, session_id = _handshake("classical")
    rl_sender = RecordLayer(suite, keys, session_id)
    rl_receiver = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    payloads = [f"message {i}".encode() for i in range(10)]
    records = [rl_sender.seal(RecordType.DATA, p, Direction.I2R) for p in payloads]

    for p, rec in zip(payloads, records):
        _, recovered = rl_receiver.open(rec, Direction.I2R, rw)
        assert recovered == p
