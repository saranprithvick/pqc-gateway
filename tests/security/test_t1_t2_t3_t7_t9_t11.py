"""Security tests T1, T2, T3, T7, T9, T11 for the record layer.

T1  — Replay: valid record replayed → rejected by replay window
T2  — Tamper: modified payload or header field → authentication failure
T3  — Inject: random bytes → authentication failure
T7  — Out-of-order: in-window unseen accepted; out-of-window or duplicate rejected
T9  — Nonce uniqueness: (key, nonce) never repeats over ≥ 100,000 records
T11 — Reflection: I2R record cannot be opened as R2I (per-direction keys)

Parametrized over standard suites (C1 classical, C2 pqc, C3 hybrid) and all
matrix agility entries (suite_ids 10–21) per §4 agility criterion 3.

PQC-heavy matrix variants are marked @pytest.mark.slow.
Link-level C0 vulnerability tests are in test_t1_t3_link.py.
"""

from __future__ import annotations

import os
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
    RecordLayer,
    RecordType,
)
from pqcgw.protocol.replay import ReplayError, ReplayWindow

# Import constants from conftest (available via pytest's sys.path injection)
from tests.suite_helpers import ALL_SUITES_FOR_SECURITY, MATRIX_EXPERIMENTAL, suite_path

# Standard suites only — cheap enough for unrestricted parametrize
_STANDARD = ["classical", "pqc", "hybrid"]

# Matrix non-experimental: mark slow (PQC key gen per test)
_MATRIX_NON_EXP = [
    "matrix/base", "matrix/k-512", "matrix/k-768", "matrix/k-1024",
    "matrix/s-44", "matrix/s-87", "matrix/s-slh", "matrix/s-ecdsa",
    "matrix/d-384", "matrix/a-128", "matrix/a-cha",
]

# All suites used for the main parametrize (excluding T9 which has its own)
_ALL_SUITE_PARAMS = (
    [pytest.param(s) for s in _STANDARD]
    + [pytest.param(s, marks=pytest.mark.slow) for s in _MATRIX_NON_EXP]
    + [pytest.param(s, marks=pytest.mark.slow) for s in MATRIX_EXPERIMENTAL]
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _handshake(suite_name: str):
    try:
        suite = load_suite(suite_path(suite_name))
    except KeyError as exc:
        pytest.skip(f"mechanism not available in installed liboqs: {exc}")
    sig = suite.signature
    gw_pk, gw_sk = sig.keygen()
    peer_pk, peer_sk = sig.keygen()
    from tests.suite_helpers import ALL_SUITE_IDS
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
    fr, _ = responder.process_finished_i(fi)
    keys = initiator.process_finished_r(fr)
    return suite, keys, initiator.session_id


def _flip_byte(data: bytes, offset: int) -> bytes:
    buf = bytearray(data)
    buf[offset % len(buf)] ^= 0xFF
    return bytes(buf)


# ===========================================================================
# T1 — Replay: second delivery of the same record must be rejected
# ===========================================================================

@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t1_replay_rejected(suite_name: str) -> None:
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"payload", Direction.I2R)
    rl.open(record, Direction.I2R, rw)
    with pytest.raises((RecordError, ReplayError)):
        rl.open(record, Direction.I2R, rw)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t1_replay_after_gap(suite_name: str) -> None:
    """Replay after several more records are received is still rejected."""
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    first = rl.seal(RecordType.DATA, b"first", Direction.I2R)
    rl.open(first, Direction.I2R, rw)
    for _ in range(5):
        r = rl.seal(RecordType.DATA, b"x", Direction.I2R)
        rl.open(r, Direction.I2R, rw)
    with pytest.raises((RecordError, ReplayError)):
        rl.open(first, Direction.I2R, rw)


# ===========================================================================
# T2 — Tamper: modified bytes invalidate authentication
# ===========================================================================

@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t2_tampered_ciphertext(suite_name: str) -> None:
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"secret", Direction.I2R)
    tampered = _flip_byte(record, 20)
    with pytest.raises(RecordError):
        rl.open(tampered, Direction.I2R, rw)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t2_tampered_counter_in_header(suite_name: str) -> None:
    """Flipping a counter byte in the header changes the nonce → tag failure."""
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"secret", Direction.I2R)
    tampered = _flip_byte(record, 10)
    with pytest.raises(RecordError):
        rl.open(tampered, Direction.I2R, rw)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t2_tampered_session_id_in_header(suite_name: str) -> None:
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"secret", Direction.I2R)
    tampered = _flip_byte(record, 2)
    with pytest.raises(RecordError):
        rl.open(tampered, Direction.I2R, rw)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t2_tampered_payload_length_in_header(suite_name: str) -> None:
    """Changing the payload_length field invalidates AAD → tag failure."""
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"secret", Direction.I2R)
    tampered = _flip_byte(record, 14)
    with pytest.raises(RecordError):
        rl.open(tampered, Direction.I2R, rw)


# ===========================================================================
# T3 — Inject: random bytes → authentication failure
# ===========================================================================

@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t3_random_record_rejected(suite_name: str) -> None:
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    pt_len = 16
    total = 16 + pt_len + suite.aead.tag_len
    random_record = os.urandom(total)
    with pytest.raises(RecordError):
        rl.open(random_record, Direction.I2R, rw)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t3_wrong_key_record_rejected(suite_name: str) -> None:
    """Record encrypted under a different key → tag failure."""
    suite, keys1, sid1 = _handshake(suite_name)
    _, keys2, sid2 = _handshake(suite_name)

    rl1 = RecordLayer(suite, keys1, sid1)
    rl2 = RecordLayer(suite, keys2, sid2)
    rw = ReplayWindow()

    record = rl1.seal(RecordType.DATA, b"payload", Direction.I2R)
    with pytest.raises(RecordError):
        rl2.open(record, Direction.I2R, rw)


# ===========================================================================
# T7 — Out-of-order and sliding window
# ===========================================================================

@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t7_out_of_order_within_window(suite_name: str) -> None:
    """Records delivered out of order but within the window are all accepted once."""
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    records = [rl.seal(RecordType.DATA, f"m{i}".encode(), Direction.I2R) for i in range(5)]
    for idx in [4, 2, 0, 3, 1]:
        _, pt = rl.open(records[idx], Direction.I2R, rw)
        assert pt == f"m{idx}".encode()


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t7_out_of_window_too_old(suite_name: str) -> None:
    """A record older than the window size is rejected."""
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow(window_size=8)

    records = [rl.seal(RecordType.DATA, b"x", Direction.I2R) for _ in range(9)]
    for rec in records[1:]:
        rl.open(rec, Direction.I2R, rw)
    with pytest.raises((RecordError, ReplayError)):
        rl.open(records[0], Direction.I2R, rw)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t7_duplicate_within_window(suite_name: str) -> None:
    """A duplicate record within the window is rejected."""
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"dup", Direction.I2R)
    rl.open(record, Direction.I2R, rw)
    with pytest.raises((RecordError, ReplayError)):
        rl.open(record, Direction.I2R, rw)


# ===========================================================================
# T9 — Nonce uniqueness: (key, nonce) never repeats over ≥ 100,000 records
# ===========================================================================

# T9 runs for ALL suites; parametrize as slow for PQC/matrix variants.
@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t9_nonce_uniqueness(suite_name: str) -> None:
    """Property test: no (key, nonce) pair is reused across 100,000 records."""
    suite, keys, session_id = _handshake(suite_name)

    rl = RecordLayer(suite, keys, session_id)
    seen_i2r: set[tuple[bytes, bytes]] = set()
    seen_r2i: set[tuple[bytes, bytes]] = set()

    for _ in range(50_000):
        rec = rl.seal(RecordType.DATA, b"x", Direction.I2R)
        counter_bytes = rec[6:14]
        nonce = keys.salt_i2r + counter_bytes
        pair = (keys.k_i2r, nonce)
        assert pair not in seen_i2r, "Nonce reuse detected in I2R direction"
        seen_i2r.add(pair)

    rl2 = RecordLayer(suite, keys, session_id)
    for _ in range(50_000):
        rec = rl2.seal(RecordType.DATA, b"x", Direction.R2I)
        counter_bytes = rec[6:14]
        nonce = keys.salt_r2i + counter_bytes
        pair = (keys.k_r2i, nonce)
        assert pair not in seen_r2i, "Nonce reuse detected in R2I direction"
        seen_r2i.add(pair)


# ===========================================================================
# T11 — Reflection: I2R record cannot be opened as R2I
# ===========================================================================

@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t11_reflection_rejected(suite_name: str) -> None:
    """A record sent in I2R direction is rejected if presented as R2I."""
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"i2r payload", Direction.I2R)
    with pytest.raises(RecordError):
        rl.open(record, Direction.R2I, rw)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t11_reflection_r2i_to_i2r(suite_name: str) -> None:
    """A record sent in R2I direction is rejected if presented as I2R."""
    suite, keys, session_id = _handshake(suite_name)
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"r2i payload", Direction.R2I)
    with pytest.raises(RecordError):
        rl.open(record, Direction.I2R, rw)
