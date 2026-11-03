"""Security tests T4, T5, T6, T13 for the handshake protocol.

T4  — Unknown identity key: handshake aborts
T5  — MITM modifies KEM pk, ct, or nonce: handshake fails
T6  — Downgrade: suite_id changed or not in allowed list: aborts
T13 — Reflected FINISHED: handshake fails

C0 cases (no security → accepted) are deferred to M6 when the passthrough
path exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pqcgw.crypto.registry import load_suite
from pqcgw.protocol.handshake import (
    HandshakeError,
    HandshakeInitiator,
    HandshakeResponder,
    IdentityContext,
)
from pqcgw.protocol.messages import HelloI, HelloR

SUITE_DIR = Path(__file__).parent.parent.parent / "configs" / "suites"


def _make_identities(suite_name: str = "hybrid"):
    suite = load_suite(SUITE_DIR / f"{suite_name}.toml")
    sig = suite.signature
    gw_pk, gw_sk = sig.keygen()
    peer_pk, peer_sk = sig.keygen()
    init_id = IdentityContext(
        my_id="gateway-1", peer_id="peer-1",
        my_sk=gw_sk, my_pk=gw_pk, peer_pk=peer_pk,
        allowed_suite_ids=[1, 2, 3],
    )
    resp_id = IdentityContext(
        my_id="peer-1", peer_id="gateway-1",
        my_sk=peer_sk, my_pk=peer_pk, peer_pk=gw_pk,
        allowed_suite_ids=[1, 2, 3],
    )
    return suite, init_id, resp_id


def _flip_byte(data: bytes, offset: int) -> bytes:
    """Flip one byte at offset (wraps if negative)."""
    buf = bytearray(data)
    buf[offset % len(buf)] ^= 0xFF
    return bytes(buf)


# ===========================================================================
# T4 — Wrong identity key
# ===========================================================================

def test_t4_wrong_peer_pk_on_responder() -> None:
    """Responder has a wrong pk_peer → sig_I verification fails."""
    suite, init_id, resp_id = _make_identities()
    # Give responder a random wrong public key for the initiator
    wrong_pk, _ = suite.signature.keygen()
    bad_resp_id = IdentityContext(
        my_id=resp_id.my_id, peer_id=resp_id.peer_id,
        my_sk=resp_id.my_sk, my_pk=resp_id.my_pk,
        peer_pk=wrong_pk,           # wrong!
        allowed_suite_ids=resp_id.allowed_suite_ids,
    )
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, bad_resp_id)

    hello_i = initiator.start()
    with pytest.raises(HandshakeError):
        responder.process_hello_i(hello_i)


def test_t4_wrong_peer_pk_on_initiator() -> None:
    """Initiator has a wrong pk_peer → sig_R verification fails."""
    suite, init_id, resp_id = _make_identities()
    wrong_pk, _ = suite.signature.keygen()
    bad_init_id = IdentityContext(
        my_id=init_id.my_id, peer_id=init_id.peer_id,
        my_sk=init_id.my_sk, my_pk=init_id.my_pk,
        peer_pk=wrong_pk,           # wrong!
        allowed_suite_ids=init_id.allowed_suite_ids,
    )
    initiator = HandshakeInitiator(suite, bad_init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    hello_r = responder.process_hello_i(hello_i)
    with pytest.raises(HandshakeError):
        initiator.process_hello_r(hello_r)


# ===========================================================================
# T5 — MITM modifies KEM pk, ct, or nonce
# ===========================================================================

def test_t5_tampered_kem_pk_in_hello_i() -> None:
    """Flip a byte in kem_pk_I → sig_I fails on responder."""
    suite, init_id, resp_id = _make_identities()
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i_bytes = initiator.start()
    # Parse, tamper, re-serialise
    msg = HelloI.from_bytes(hello_i_bytes)
    msg.kem_pk = _flip_byte(msg.kem_pk, 10)
    tampered = msg.to_bytes()

    with pytest.raises(HandshakeError):
        responder.process_hello_i(tampered)


def test_t5_tampered_nonce_i_in_hello_i() -> None:
    """Flip a byte in nonce_i → sig_I fails on responder."""
    suite, init_id, resp_id = _make_identities()
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i_bytes = initiator.start()
    msg = HelloI.from_bytes(hello_i_bytes)
    msg.nonce_i = _flip_byte(msg.nonce_i, 5)
    tampered = msg.to_bytes()

    with pytest.raises(HandshakeError):
        responder.process_hello_i(tampered)


def test_t5_tampered_kem_ct_in_hello_r() -> None:
    """Flip a byte in kem_ct → sig_R fails on initiator."""
    suite, init_id, resp_id = _make_identities()
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    hello_r_bytes = responder.process_hello_i(hello_i)
    msg = HelloR.from_bytes(hello_r_bytes)
    msg.kem_ct = _flip_byte(msg.kem_ct, 10)
    tampered = msg.to_bytes()

    with pytest.raises(HandshakeError):
        initiator.process_hello_r(tampered)


def test_t5_tampered_nonce_r_in_hello_r() -> None:
    """Flip a byte in nonce_r → sig_R fails on initiator."""
    suite, init_id, resp_id = _make_identities()
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    hello_r_bytes = responder.process_hello_i(hello_i)
    msg = HelloR.from_bytes(hello_r_bytes)
    msg.nonce_r = _flip_byte(msg.nonce_r, 5)
    tampered = msg.to_bytes()

    with pytest.raises(HandshakeError):
        initiator.process_hello_r(tampered)


# ===========================================================================
# T6 — Downgrade: suite_id changed or not in allowed list
# ===========================================================================

def test_t6_suite_id_not_in_allowed_list() -> None:
    """Responder's allowed_suite_ids excludes initiator's suite → abort."""
    suite, init_id, resp_id = _make_identities(suite_name="hybrid")  # suite_id = 3
    bad_resp_id = IdentityContext(
        my_id=resp_id.my_id, peer_id=resp_id.peer_id,
        my_sk=resp_id.my_sk, my_pk=resp_id.my_pk, peer_pk=resp_id.peer_pk,
        allowed_suite_ids=[1, 2],   # excludes 3
    )
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, bad_resp_id)

    hello_i = initiator.start()
    with pytest.raises(HandshakeError):
        responder.process_hello_i(hello_i)


def test_t6_tampered_suite_id_in_hello_i() -> None:
    """MITM changes suite_id in HELLO_I → sig_I fails (suite_id is in signed body)."""
    suite, init_id, resp_id = _make_identities(suite_name="classical")  # suite_id = 1
    # Responder allows only suite_id=1 so a change to 2 would also fail allowed check first,
    # but we test with an allowed-list that permits both to isolate the sig check.
    resp_id_permissive = IdentityContext(
        my_id=resp_id.my_id, peer_id=resp_id.peer_id,
        my_sk=resp_id.my_sk, my_pk=resp_id.my_pk, peer_pk=resp_id.peer_pk,
        allowed_suite_ids=[1, 2, 3],
    )
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id_permissive)

    hello_i_bytes = initiator.start()
    msg = HelloI.from_bytes(hello_i_bytes)
    msg.suite_id = 2   # tamper
    tampered = msg.to_bytes()

    with pytest.raises(HandshakeError):
        responder.process_hello_i(tampered)


# ===========================================================================
# T13 — Reflected FINISHED
# ===========================================================================

def test_t13_finished_i_reflected_to_initiator() -> None:
    """Reflect FINISHED_I back to initiator as if it were FINISHED_R → HandshakeError."""
    suite, init_id, resp_id = _make_identities()
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    hello_r = responder.process_hello_i(hello_i)
    finished_i = initiator.process_hello_r(hello_r)

    # Relay FINISHED_I back to initiator instead of FINISHED_R
    with pytest.raises(HandshakeError):
        initiator.process_finished_r(finished_i)


def test_t13_finished_r_replayed_to_responder_as_finished_i() -> None:
    """Relay FINISHED_R to responder as if it were FINISHED_I → HandshakeError."""
    suite, init_id, resp_id = _make_identities()
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    hello_r = responder.process_hello_i(hello_i)
    finished_i = initiator.process_hello_r(hello_r)
    finished_r, _ = responder.process_finished_i(finished_i)

    # New responder (same identity) — try to feed FINISHED_R as FINISHED_I
    responder2 = HandshakeResponder(suite, resp_id)
    hello_r2 = responder2.process_hello_i(hello_i)   # re-use same HELLO_I
    initiator2 = HandshakeInitiator(suite, init_id)
    initiator2.start()   # consume, discard
    # Feed FINISHED_R (from first run) to responder2 as FINISHED_I
    with pytest.raises(HandshakeError):
        responder2.process_finished_i(finished_r)
