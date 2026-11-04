"""Unit tests for the light-rekey key-derivation ratchet (M4).

Tests verify:
- Determinism: same inputs → same output
- Distinctness from epoch 0 and between consecutive epochs
- Correct key/salt lengths for each suite
- Chain chaining across multiple epochs
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pqcgw.crypto.registry import load_suite
from pqcgw.protocol.handshake import HandshakeInitiator, HandshakeResponder, IdentityContext
from pqcgw.protocol.rekey import derive_rekey_epoch

SUITE_DIR = Path(__file__).parent.parent.parent / "configs" / "suites"


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


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_ratchet_deterministic() -> None:
    suite, gw_keys, _, _ = _handshake_both_sides()
    epoch1_a = derive_rekey_epoch(suite, gw_keys)
    epoch1_b = derive_rekey_epoch(suite, gw_keys)
    assert epoch1_a.k_i2r == epoch1_b.k_i2r
    assert epoch1_a.k_r2i == epoch1_b.k_r2i
    assert epoch1_a.salt_i2r == epoch1_b.salt_i2r
    assert epoch1_a.salt_r2i == epoch1_b.salt_r2i
    assert epoch1_a.k_finished == epoch1_b.k_finished
    assert epoch1_a.rekey_sec0 == epoch1_b.rekey_sec0


# ---------------------------------------------------------------------------
# Distinctness from epoch 0
# ---------------------------------------------------------------------------

def test_ratchet_keys_differ_from_epoch0() -> None:
    suite, gw_keys, _, _ = _handshake_both_sides()
    epoch1 = derive_rekey_epoch(suite, gw_keys)
    assert epoch1.k_i2r != gw_keys.k_i2r
    assert epoch1.k_r2i != gw_keys.k_r2i
    assert epoch1.salt_i2r != gw_keys.salt_i2r
    assert epoch1.rekey_sec0 != gw_keys.rekey_sec0
    assert epoch1.epoch == 1


# ---------------------------------------------------------------------------
# Both sides produce the same epoch-1 keys
# ---------------------------------------------------------------------------

def test_ratchet_both_sides_agree() -> None:
    suite, gw_keys, peer_keys, _ = _handshake_both_sides()
    gw_epoch1 = derive_rekey_epoch(suite, gw_keys)
    peer_epoch1 = derive_rekey_epoch(suite, peer_keys)
    assert gw_epoch1.k_i2r == peer_epoch1.k_i2r
    assert gw_epoch1.k_r2i == peer_epoch1.k_r2i
    assert gw_epoch1.salt_i2r == peer_epoch1.salt_i2r
    assert gw_epoch1.salt_r2i == peer_epoch1.salt_r2i


# ---------------------------------------------------------------------------
# Epoch chaining: each epoch distinct
# ---------------------------------------------------------------------------

def test_ratchet_chained_epochs_distinct() -> None:
    suite, gw_keys, _, _ = _handshake_both_sides()
    all_k_i2r = {gw_keys.k_i2r}
    keys = gw_keys
    for _ in range(5):
        keys = derive_rekey_epoch(suite, keys)
        assert keys.k_i2r not in all_k_i2r, "epoch key collision"
        all_k_i2r.add(keys.k_i2r)


def test_ratchet_epoch_counter_increments() -> None:
    suite, gw_keys, _, _ = _handshake_both_sides()
    assert gw_keys.epoch == 0
    k1 = derive_rekey_epoch(suite, gw_keys)
    assert k1.epoch == 1
    k2 = derive_rekey_epoch(suite, k1)
    assert k2.epoch == 2


# ---------------------------------------------------------------------------
# Key/salt lengths match suite
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("suite_name", ["classical", "pqc", "hybrid"])
def test_ratchet_sizes_match_suite(suite_name: str) -> None:
    suite, gw_keys, _, _ = _handshake_both_sides(suite_name)
    epoch1 = derive_rekey_epoch(suite, gw_keys)
    key_len = suite.aead.key_len
    assert len(epoch1.k_i2r) == key_len
    assert len(epoch1.k_r2i) == key_len
    assert len(epoch1.salt_i2r) == 4
    assert len(epoch1.salt_r2i) == 4
    assert len(epoch1.k_finished) == 32
    assert len(epoch1.rekey_sec0) == 32


# ---------------------------------------------------------------------------
# th is preserved through the chain
# ---------------------------------------------------------------------------

def test_ratchet_th_preserved() -> None:
    suite, gw_keys, _, _ = _handshake_both_sides()
    original_th = gw_keys.th
    keys = gw_keys
    for _ in range(3):
        keys = derive_rekey_epoch(suite, keys)
        assert keys.th == original_th


# ---------------------------------------------------------------------------
# suite_id preserved
# ---------------------------------------------------------------------------

def test_ratchet_suite_id_preserved() -> None:
    suite, gw_keys, _, _ = _handshake_both_sides()
    epoch1 = derive_rekey_epoch(suite, gw_keys)
    assert epoch1.suite_id == gw_keys.suite_id
