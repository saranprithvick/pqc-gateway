"""M2 unit tests: handshake round-trips (C1/C2/C3), key schedule KAT,
transcript binding, responder cache, and FINISHED cross-check.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pqcgw.crypto.registry import load_suite, get_sig
from pqcgw.protocol.handshake import (
    HandshakeInitiator,
    HandshakeResponder,
    HandshakeError,
    IdentityContext,
)
from pqcgw.protocol.keyschedule import SessionKeys, derive_session_keys, _info

SUITE_DIR = Path(__file__).parent.parent.parent / "configs" / "suites"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_identities(suite_name: str) -> tuple[IdentityContext, IdentityContext]:
    """Generate ephemeral identity keypairs for a test handshake."""
    suite = load_suite(SUITE_DIR / f"{suite_name}.toml")
    sig = suite.signature

    gw_pk, gw_sk = sig.keygen()
    peer_pk, peer_sk = sig.keygen()

    initiator_id = IdentityContext(
        my_id="gateway-1",
        peer_id="peer-1",
        my_sk=gw_sk,
        my_pk=gw_pk,
        peer_pk=peer_pk,
        allowed_suite_ids=[1, 2, 3],
    )
    responder_id = IdentityContext(
        my_id="peer-1",
        peer_id="gateway-1",
        my_sk=peer_sk,
        my_pk=peer_pk,
        peer_pk=gw_pk,
        allowed_suite_ids=[1, 2, 3],
    )
    return initiator_id, responder_id


def _run_handshake(suite_name: str) -> tuple[SessionKeys, SessionKeys]:
    """Run a complete 4-message handshake and return (initiator_keys, responder_keys)."""
    suite = load_suite(SUITE_DIR / f"{suite_name}.toml")
    init_id, resp_id = _make_identities(suite_name)

    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    hello_r = responder.process_hello_i(hello_i)
    finished_i = initiator.process_hello_r(hello_r)
    finished_r, resp_keys = responder.process_finished_i(finished_i)
    init_keys = initiator.process_finished_r(finished_r)

    return init_keys, resp_keys


# ===========================================================================
# 1. Round-trip tests for C1, C2, C3
# ===========================================================================

@pytest.mark.parametrize("suite_name", ["classical", "pqc", "hybrid"])
def test_handshake_roundtrip(suite_name: str) -> None:
    init_keys, resp_keys = _run_handshake(suite_name)
    assert init_keys.k_i2r == resp_keys.k_i2r, f"{suite_name}: k_i2r mismatch"
    assert init_keys.k_r2i == resp_keys.k_r2i, f"{suite_name}: k_r2i mismatch"
    assert init_keys.salt_i2r == resp_keys.salt_i2r, f"{suite_name}: salt_i2r mismatch"
    assert init_keys.salt_r2i == resp_keys.salt_r2i, f"{suite_name}: salt_r2i mismatch"
    assert init_keys.k_finished == resp_keys.k_finished, f"{suite_name}: k_finished mismatch"
    assert init_keys.rekey_sec0 == resp_keys.rekey_sec0, f"{suite_name}: rekey_sec0 mismatch"


@pytest.mark.parametrize("suite_name", ["classical", "pqc", "hybrid"])
def test_handshake_state_established(suite_name: str) -> None:
    suite = load_suite(SUITE_DIR / f"{suite_name}.toml")
    init_id, resp_id = _make_identities(suite_name)
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    assert initiator.state == "HELLO_SENT"

    hello_r = responder.process_hello_i(hello_i)
    assert responder.state == "HELLO_RECEIVED"

    finished_i = initiator.process_hello_r(hello_r)
    finished_r, _ = responder.process_finished_i(finished_i)
    assert responder.state == "ESTABLISHED"

    initiator.process_finished_r(finished_r)
    assert initiator.state == "ESTABLISHED"


# ===========================================================================
# 2. Key schedule KAT — deterministic, direction-separated, all values distinct
# ===========================================================================

def test_key_schedule_deterministic() -> None:
    suite = load_suite(SUITE_DIR / "classical.toml")
    ss = bytes(32)
    nonce_i = bytes(32)
    nonce_r = b"\x01" * 32
    th = bytes(32)

    keys1 = derive_session_keys(suite, ss, nonce_i, nonce_r, th)
    keys2 = derive_session_keys(suite, ss, nonce_i, nonce_r, th)
    assert keys1.k_i2r == keys2.k_i2r
    assert keys1.k_r2i == keys2.k_r2i
    assert keys1.rekey_sec0 == keys2.rekey_sec0


def test_key_schedule_direction_separation() -> None:
    suite = load_suite(SUITE_DIR / "classical.toml")
    ss = bytes(32)
    nonce_i = bytes(32)
    nonce_r = b"\x01" * 32
    th = bytes(32)

    keys = derive_session_keys(suite, ss, nonce_i, nonce_r, th)
    assert keys.k_i2r != keys.k_r2i, "i2r and r2i keys must differ"
    assert keys.salt_i2r != keys.salt_r2i, "i2r and r2i salts must differ"


def test_key_schedule_all_values_distinct() -> None:
    suite = load_suite(SUITE_DIR / "classical.toml")
    ss = bytes(32)
    nonce_i = bytes(32)
    nonce_r = b"\x01" * 32
    th = bytes(32)

    keys = derive_session_keys(suite, ss, nonce_i, nonce_r, th)
    values = [keys.k_i2r, keys.k_r2i, keys.k_finished, keys.rekey_sec0]
    assert len(set(values)) == len(values), "All derived key values must be distinct"


def test_info_encoding() -> None:
    """_info() must produce deterministic, distinct outputs for different labels."""
    th = bytes(32)
    info1 = _info("key i2r", 3, th, 0)
    info2 = _info("key r2i", 3, th, 0)
    info3 = _info("key i2r", 3, th, 1)  # different epoch

    assert info1 != info2
    assert info1 != info3
    assert info2 != info3
    # Check structure: first byte is label length
    assert info1[0] == len("key i2r")


# ===========================================================================
# 3. Transcript binding
# ===========================================================================

def test_different_sessions_give_different_keys() -> None:
    keys1, _ = _run_handshake("classical")
    keys2, _ = _run_handshake("classical")
    # Different session_ids and nonces → different keys
    assert keys1.k_i2r != keys2.k_i2r


@pytest.mark.parametrize("suite_name", ["classical", "pqc", "hybrid"])
def test_both_sides_see_same_session_id(suite_name: str) -> None:
    suite = load_suite(SUITE_DIR / f"{suite_name}.toml")
    init_id, resp_id = _make_identities(suite_name)
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    hello_r = responder.process_hello_i(hello_i)
    finished_i = initiator.process_hello_r(hello_r)
    finished_r, _ = responder.process_finished_i(finished_i)
    initiator.process_finished_r(finished_r)

    assert initiator.session_id == responder.session_id


# ===========================================================================
# 4. Responder cache — byte-identical HELLO_R on duplicate HELLO_I (§15 item 9)
# ===========================================================================

def test_responder_cache_returns_identical_hello_r() -> None:
    suite = load_suite(SUITE_DIR / "classical.toml")
    init_id, resp_id = _make_identities("classical")
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    hello_r_1 = responder.process_hello_i(hello_i)
    hello_r_2 = responder.process_hello_i(hello_i)  # duplicate

    assert hello_r_1 == hello_r_2, "Duplicate HELLO_I must produce byte-identical HELLO_R"


# ===========================================================================
# 5. FINISHED cross-check — FINISHED_I ≠ FINISHED_R (§15 item 14)
# ===========================================================================

@pytest.mark.parametrize("suite_name", ["classical", "pqc", "hybrid"])
def test_finished_i_not_equal_finished_r(suite_name: str) -> None:
    suite = load_suite(SUITE_DIR / f"{suite_name}.toml")
    init_id, resp_id = _make_identities(suite_name)
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    hello_r = responder.process_hello_i(hello_i)
    finished_i = initiator.process_hello_r(hello_r)
    finished_r, _ = responder.process_finished_i(finished_i)

    assert finished_i != finished_r, "FINISHED_I and FINISHED_R must never be equal"
