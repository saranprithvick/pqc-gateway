"""T9 nonce-uniqueness extended across light rekeys and full rekeys.

Verifies that (key, nonce) pairs do not repeat across epoch 0, 1, and 2 in both
the I2R and R2I directions, and across a full-rekey boundary (new session_id).
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from pqcgw.crypto.registry import load_suite
from pqcgw.protocol.handshake import HandshakeInitiator, HandshakeResponder, IdentityContext
from pqcgw.protocol.record import Direction, RecordType
from pqcgw.protocol.session import RekeyConfig, SessionManager, SessionRole

N_PER_SESSION = 100  # records per direction for full-rekey test

SUITE_DIR = Path(__file__).parent.parent.parent / "configs" / "suites"

N_PER_EPOCH = 500   # records per direction per epoch; 500×3×2=3000 pairs checked


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


def _do_light_rekey(gw_sm: SessionManager, peer_sm: SessionManager) -> None:
    req = gw_sm.initiate_light_rekey()
    rtype, _ = peer_sm.open(req, Direction.I2R)
    ack = peer_sm.take_outbound()
    assert ack is not None
    rtype, _ = gw_sm.open(ack, Direction.R2I)


def _collect_epoch(
    gw_sm: SessionManager,
    peer_sm: SessionManager,
    n: int,
    all_pairs: set[tuple[bytes, bytes]],
) -> None:
    """Seal n I2R records and n R2I records; assert no (key, nonce) pair in all_pairs."""
    for _ in range(n):
        # Capture key + nonce BEFORE sealing
        keys = gw_sm._rl_current._keys
        counter = gw_sm._rl_current._counters[Direction.I2R]
        nonce = keys.salt_i2r + struct.pack(">Q", counter)
        pair_i2r = (keys.k_i2r, nonce)
        assert pair_i2r not in all_pairs, (
            f"I2R nonce reuse at epoch {keys.epoch} counter {counter}"
        )
        all_pairs.add(pair_i2r)
        rec = gw_sm.seal(b"ping")
        peer_sm.open(rec, Direction.I2R)

    for _ in range(n):
        # peer_sm seals R2I records
        keys = peer_sm._rl_current._keys
        counter = peer_sm._rl_current._counters[Direction.R2I]
        nonce = keys.salt_r2i + struct.pack(">Q", counter)
        pair_r2i = (keys.k_r2i, nonce)
        assert pair_r2i not in all_pairs, (
            f"R2I nonce reuse at epoch {keys.epoch} counter {counter}"
        )
        all_pairs.add(pair_r2i)
        rec = peer_sm.seal(b"pong", direction=Direction.R2I)
        gw_sm.open(rec, Direction.R2I)


def test_t9_nonce_uniqueness_spans_rekeys() -> None:
    """No (key, nonce) pair repeats across epoch 0, 1, and 2 in both directions."""
    # Large enough grace window so old-epoch records don't expire during this test
    cfg = RekeyConfig(grace_period_records=N_PER_EPOCH * 10, grace_period_s=60.0)
    suite, gw_keys, peer_keys, session_id = _handshake_both_sides("classical")
    gw_sm = SessionManager(suite, gw_keys, session_id, SessionRole.INITIATOR, config=cfg)
    peer_sm = SessionManager(suite, peer_keys, session_id, SessionRole.RESPONDER, config=cfg)

    all_pairs: set[tuple[bytes, bytes]] = set()

    # Epoch 0
    _collect_epoch(gw_sm, peer_sm, N_PER_EPOCH, all_pairs)
    assert gw_sm.epoch == 0

    # Rekey → epoch 1
    _do_light_rekey(gw_sm, peer_sm)
    assert gw_sm.epoch == 1

    # Epoch 1 — also checks cross-epoch uniqueness (keys differ → nonces differ)
    _collect_epoch(gw_sm, peer_sm, N_PER_EPOCH, all_pairs)

    # Rekey → epoch 2
    _do_light_rekey(gw_sm, peer_sm)
    assert gw_sm.epoch == 2

    # Epoch 2
    _collect_epoch(gw_sm, peer_sm, N_PER_EPOCH, all_pairs)

    # Totals: N_PER_EPOCH × 3 epochs × 2 directions
    assert len(all_pairs) == N_PER_EPOCH * 3 * 2


def test_t9_epoch_keys_differ_across_rekeys() -> None:
    """Epoch 0, 1, 2 produce distinct k_i2r, k_r2i, salt_i2r, salt_r2i values."""
    suite, gw_keys, peer_keys, session_id = _handshake_both_sides("classical")
    cfg = RekeyConfig(grace_period_records=100, grace_period_s=60.0)
    gw_sm = SessionManager(suite, gw_keys, session_id, SessionRole.INITIATOR, config=cfg)
    peer_sm = SessionManager(suite, peer_keys, session_id, SessionRole.RESPONDER, config=cfg)

    def _snap(sm: SessionManager) -> tuple:
        k = sm._rl_current._keys
        return (k.k_i2r, k.k_r2i, k.salt_i2r, k.salt_r2i)

    snap0 = _snap(gw_sm)
    _do_light_rekey(gw_sm, peer_sm)
    snap1 = _snap(gw_sm)
    _do_light_rekey(gw_sm, peer_sm)
    snap2 = _snap(gw_sm)

    assert snap0 != snap1, "Epoch 0 and 1 keys must differ"
    assert snap1 != snap2, "Epoch 1 and 2 keys must differ"
    assert snap0 != snap2, "Epoch 0 and 2 keys must differ"


def test_t9_nonce_uniqueness_spans_full_rekey() -> None:
    """No (key, nonce) pair repeats across a full-rekey boundary (new session_id)."""
    cfg = RekeyConfig(grace_period_records=N_PER_SESSION * 10, grace_period_s=60.0)
    suite, gw_keys, peer_keys, session_id = _handshake_both_sides("classical")
    gw_sm = SessionManager(suite, gw_keys, session_id, SessionRole.INITIATOR, config=cfg)
    peer_sm = SessionManager(suite, peer_keys, session_id, SessionRole.RESPONDER, config=cfg)

    all_pairs: set[tuple[bytes, bytes]] = set()

    # Collect pairs from initial session (epoch 0)
    old_k_i2r = gw_sm._rl_current._keys.k_i2r
    _collect_epoch(gw_sm, peer_sm, N_PER_SESSION, all_pairs)
    assert gw_sm.epoch == 0

    # Run a fresh handshake to simulate full rekey (new session_id)
    suite2, new_gw_keys, new_peer_keys, new_session_id = _handshake_both_sides("classical")
    assert new_session_id != session_id, "New handshake must produce a different session_id"

    # Promote both sides
    gw_sm.promote_full_rekey(new_gw_keys, new_session_id)
    peer_sm.promote_full_rekey(new_peer_keys, new_session_id)

    # Collect pairs from new session (epoch 0 on new session_id)
    assert gw_sm.epoch == 0
    assert gw_sm._session_id == new_session_id
    _collect_epoch(gw_sm, peer_sm, N_PER_SESSION, all_pairs)

    # All pairs must be unique (key differs between sessions → no nonce collision)
    assert len(all_pairs) == N_PER_SESSION * 2 * 2  # 2 sessions × 2 directions
    assert new_gw_keys.k_i2r != old_k_i2r, "Full rekey must produce different k_i2r"
