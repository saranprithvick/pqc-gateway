"""Security tests T1, T2, T3, T7, T9, T11 for the record layer.

T1  — Replay: valid record replayed → rejected by replay window
T2  — Tamper: modified payload or header field → authentication failure
T3  — Inject: random bytes → authentication failure
T7  — Out-of-order: in-window unseen accepted; out-of-window or duplicate rejected
T9  — Nonce uniqueness: (key, nonce) never repeats over ≥ 100,000 records
T11 — Reflection: I2R record cannot be opened as R2I (per-direction keys)

C0 cases (no security → accepted) deferred to M6 when passthrough exists.
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

SUITE_DIR = Path(__file__).parent.parent.parent / "configs" / "suites"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _handshake(suite_name: str = "classical"):
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

def test_t1_replay_rejected() -> None:
    suite, keys, session_id = _handshake()
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"payload", Direction.I2R)
    # First delivery: accepted
    rl.open(record, Direction.I2R, rw)
    # Second delivery: replay window rejects it
    with pytest.raises((RecordError, ReplayError)):
        rl.open(record, Direction.I2R, rw)


def test_t1_replay_after_gap() -> None:
    """Replay after several more records are received is still rejected."""
    suite, keys, session_id = _handshake()
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    first = rl.seal(RecordType.DATA, b"first", Direction.I2R)
    rl.open(first, Direction.I2R, rw)

    # Seal and open 5 more records
    for _ in range(5):
        r = rl.seal(RecordType.DATA, b"x", Direction.I2R)
        rl.open(r, Direction.I2R, rw)

    # Replay the first record — still within window (window=64)
    with pytest.raises((RecordError, ReplayError)):
        rl.open(first, Direction.I2R, rw)


# ===========================================================================
# T2 — Tamper: modified bytes invalidate authentication
# ===========================================================================

def test_t2_tampered_ciphertext() -> None:
    suite, keys, session_id = _handshake()
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"secret", Direction.I2R)
    # Flip a byte in the ciphertext portion (after the 16-byte header)
    tampered = _flip_byte(record, 20)
    with pytest.raises(RecordError):
        rl.open(tampered, Direction.I2R, rw)


def test_t2_tampered_counter_in_header() -> None:
    """Flipping a counter byte in the header changes the nonce → tag failure."""
    suite, keys, session_id = _handshake()
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"secret", Direction.I2R)
    # Counter is bytes 6–13; flip byte 10
    tampered = _flip_byte(record, 10)
    with pytest.raises(RecordError):
        rl.open(tampered, Direction.I2R, rw)


def test_t2_tampered_session_id_in_header() -> None:
    suite, keys, session_id = _handshake()
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"secret", Direction.I2R)
    # session_id is bytes 1–4; flip byte 2
    tampered = _flip_byte(record, 2)
    with pytest.raises(RecordError):
        rl.open(tampered, Direction.I2R, rw)


def test_t2_tampered_payload_length_in_header() -> None:
    """Changing the payload_length field invalidates AAD → tag failure."""
    suite, keys, session_id = _handshake()
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"secret", Direction.I2R)
    # payload_length is bytes 14–15; flip byte 14
    tampered = _flip_byte(record, 14)
    with pytest.raises(RecordError):
        rl.open(tampered, Direction.I2R, rw)


# ===========================================================================
# T3 — Inject: random bytes → authentication failure
# ===========================================================================

def test_t3_random_record_rejected() -> None:
    suite, keys, session_id = _handshake()
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    # A record sealed by a legitimate sender is 16+len(pt)+tag_len bytes;
    # fabricate a random blob of the same length
    pt_len = 16
    total = 16 + pt_len + suite.aead.tag_len
    random_record = os.urandom(total)
    with pytest.raises(RecordError):
        rl.open(random_record, Direction.I2R, rw)


def test_t3_wrong_key_record_rejected() -> None:
    """Record encrypted under a different key → tag failure."""
    suite, keys1, sid1 = _handshake()
    _, keys2, sid2 = _handshake()

    rl1 = RecordLayer(suite, keys1, sid1)
    rl2 = RecordLayer(suite, keys2, sid2)
    rw = ReplayWindow()

    record = rl1.seal(RecordType.DATA, b"payload", Direction.I2R)
    with pytest.raises(RecordError):
        rl2.open(record, Direction.I2R, rw)


# ===========================================================================
# T7 — Out-of-order and sliding window
# ===========================================================================

def test_t7_out_of_order_within_window() -> None:
    """Records delivered out of order but within the window are all accepted once."""
    suite, keys, session_id = _handshake()
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    # Seal 5 records in order
    records = [rl.seal(RecordType.DATA, f"m{i}".encode(), Direction.I2R) for i in range(5)]

    # Deliver them out of order: 4, 2, 0, 3, 1
    for idx in [4, 2, 0, 3, 1]:
        _, pt = rl.open(records[idx], Direction.I2R, rw)
        assert pt == f"m{idx}".encode()


def test_t7_out_of_window_too_old() -> None:
    """A record older than the window size is rejected."""
    suite, keys, session_id = _handshake()
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow(window_size=8)

    # Seal and deliver 9 records so the first one is outside the window
    records = [rl.seal(RecordType.DATA, b"x", Direction.I2R) for _ in range(9)]
    for rec in records[1:]:  # deliver records 1–8 first
        rl.open(rec, Direction.I2R, rw)

    # Record 0 is now older than the window (highest=8, window=8 → min=0, which is at the boundary)
    # With window_size=8: highest_seen=8, anything with counter <= 8-8=0 is at boundary.
    # Record 0 counter=0, highest=8 → 8-0=8 >= window_size=8 → rejected
    with pytest.raises((RecordError, ReplayError)):
        rl.open(records[0], Direction.I2R, rw)


def test_t7_duplicate_within_window() -> None:
    """A duplicate record within the window is rejected."""
    suite, keys, session_id = _handshake()
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"dup", Direction.I2R)
    rl.open(record, Direction.I2R, rw)  # first delivery: ok
    with pytest.raises((RecordError, ReplayError)):
        rl.open(record, Direction.I2R, rw)  # duplicate: rejected


# ===========================================================================
# T9 — Nonce uniqueness: (key, nonce) never repeats over ≥ 100,000 records
# ===========================================================================

def test_t9_nonce_uniqueness() -> None:
    """Property test: no (key, nonce) pair is reused across 100,000 records."""
    suite, keys, session_id = _handshake("classical")

    # Use two RecordLayer instances to generate I2R and R2I records independently
    rl = RecordLayer(suite, keys, session_id)

    seen_i2r: set[tuple[bytes, bytes]] = set()
    seen_r2i: set[tuple[bytes, bytes]] = set()

    for _ in range(50_000):
        rec = rl.seal(RecordType.DATA, b"x", Direction.I2R)
        # Nonce = salt_i2r (4B) || counter (8B big-endian) from the header
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

def test_t11_reflection_rejected() -> None:
    """A record sent in I2R direction is rejected if presented as R2I."""
    suite, keys, session_id = _handshake()
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"i2r payload", Direction.I2R)
    # Present it as if it were an R2I record → wrong key and salt → tag failure
    with pytest.raises(RecordError):
        rl.open(record, Direction.R2I, rw)


def test_t11_reflection_r2i_to_i2r() -> None:
    """A record sent in R2I direction is rejected if presented as I2R."""
    suite, keys, session_id = _handshake()
    rl = RecordLayer(suite, keys, session_id)
    rw = ReplayWindow()

    record = rl.seal(RecordType.DATA, b"r2i payload", Direction.R2I)
    with pytest.raises(RecordError):
        rl.open(record, Direction.I2R, rw)
