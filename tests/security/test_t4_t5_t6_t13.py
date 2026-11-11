"""Security tests T4, T5, T6, T13 for the handshake protocol.

T4  — Unknown identity key: handshake aborts
T5  — MITM modifies KEM pk, ct, or nonce: handshake fails
T6  — Downgrade: suite_id changed or not in allowed list: aborts
T13 — Reflected FINISHED: handshake fails

T4/T5/T6/T13 are n/a for C0 (no handshake).
Parametrized over standard suites (C1 classical, C2 pqc, C3 hybrid) and all
matrix agility entries per §4 agility criterion 3.

PQC-heavy matrix variants are marked @pytest.mark.slow.
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


def _make_identities(suite_name: str = "hybrid"):
    try:
        suite = load_suite(suite_path(suite_name))
    except KeyError as exc:
        pytest.skip(f"mechanism not available in installed liboqs: {exc}")
    sig = suite.signature
    gw_pk, gw_sk = sig.keygen()
    peer_pk, peer_sk = sig.keygen()
    init_id = IdentityContext(
        my_id="gateway-1", peer_id="peer-1",
        my_sk=gw_sk, my_pk=gw_pk, peer_pk=peer_pk,
        allowed_suite_ids=ALL_SUITE_IDS,
    )
    resp_id = IdentityContext(
        my_id="peer-1", peer_id="gateway-1",
        my_sk=peer_sk, my_pk=peer_pk, peer_pk=gw_pk,
        allowed_suite_ids=ALL_SUITE_IDS,
    )
    return suite, init_id, resp_id


def _flip_byte(data: bytes, offset: int) -> bytes:
    buf = bytearray(data)
    buf[offset % len(buf)] ^= 0xFF
    return bytes(buf)


# ===========================================================================
# T4 — Wrong identity key
# ===========================================================================

@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t4_wrong_peer_pk_on_responder(suite_name: str) -> None:
    """Responder has a wrong pk_peer → sig_I verification fails."""
    suite, init_id, resp_id = _make_identities(suite_name)
    wrong_pk, _ = suite.signature.keygen()
    bad_resp_id = IdentityContext(
        my_id=resp_id.my_id, peer_id=resp_id.peer_id,
        my_sk=resp_id.my_sk, my_pk=resp_id.my_pk,
        peer_pk=wrong_pk,
        allowed_suite_ids=resp_id.allowed_suite_ids,
    )
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, bad_resp_id)

    hello_i = initiator.start()
    with pytest.raises(HandshakeError):
        responder.process_hello_i(hello_i)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t4_wrong_peer_pk_on_initiator(suite_name: str) -> None:
    """Initiator has a wrong pk_peer → sig_R verification fails."""
    suite, init_id, resp_id = _make_identities(suite_name)
    wrong_pk, _ = suite.signature.keygen()
    bad_init_id = IdentityContext(
        my_id=init_id.my_id, peer_id=init_id.peer_id,
        my_sk=init_id.my_sk, my_pk=init_id.my_pk,
        peer_pk=wrong_pk,
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

@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t5_tampered_kem_pk_in_hello_i(suite_name: str) -> None:
    """Flip a byte in kem_pk_I → sig_I fails on responder."""
    suite, init_id, resp_id = _make_identities(suite_name)
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i_bytes = initiator.start()
    msg = HelloI.from_bytes(hello_i_bytes)
    msg.kem_pk = _flip_byte(msg.kem_pk, 10)
    tampered = msg.to_bytes()

    with pytest.raises(HandshakeError):
        responder.process_hello_i(tampered)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t5_tampered_nonce_i_in_hello_i(suite_name: str) -> None:
    """Flip a byte in nonce_i → sig_I fails on responder."""
    suite, init_id, resp_id = _make_identities(suite_name)
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i_bytes = initiator.start()
    msg = HelloI.from_bytes(hello_i_bytes)
    msg.nonce_i = _flip_byte(msg.nonce_i, 5)
    tampered = msg.to_bytes()

    with pytest.raises(HandshakeError):
        responder.process_hello_i(tampered)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t5_tampered_kem_ct_in_hello_r(suite_name: str) -> None:
    """Flip a byte in kem_ct → sig_R fails on initiator."""
    suite, init_id, resp_id = _make_identities(suite_name)
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    hello_r_bytes = responder.process_hello_i(hello_i)
    msg = HelloR.from_bytes(hello_r_bytes)
    msg.kem_ct = _flip_byte(msg.kem_ct, 10)
    tampered = msg.to_bytes()

    with pytest.raises(HandshakeError):
        initiator.process_hello_r(tampered)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t5_tampered_nonce_r_in_hello_r(suite_name: str) -> None:
    """Flip a byte in nonce_r → sig_R fails on initiator."""
    suite, init_id, resp_id = _make_identities(suite_name)
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

@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t6_suite_id_not_in_allowed_list(suite_name: str) -> None:
    """Responder's allowed_suite_ids excludes initiator's suite → abort."""
    suite, init_id, resp_id = _make_identities(suite_name)
    sid = suite.suite_id
    # Exclude this suite's ID from the responder's allowed list
    excluded = [i for i in ALL_SUITE_IDS if i != sid]
    bad_resp_id = IdentityContext(
        my_id=resp_id.my_id, peer_id=resp_id.peer_id,
        my_sk=resp_id.my_sk, my_pk=resp_id.my_pk, peer_pk=resp_id.peer_pk,
        allowed_suite_ids=excluded,
    )
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, bad_resp_id)

    hello_i = initiator.start()
    with pytest.raises(HandshakeError):
        responder.process_hello_i(hello_i)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t6_tampered_suite_id_in_hello_i(suite_name: str) -> None:
    """MITM changes suite_id in HELLO_I → sig_I fails (suite_id is in signed body)."""
    suite, init_id, resp_id = _make_identities(suite_name)
    # Responder allows all suite IDs so we isolate the signature check
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i_bytes = initiator.start()
    msg = HelloI.from_bytes(hello_i_bytes)
    # Tamper to a different (but still listed) suite_id
    tampered_sid = 1 if msg.suite_id != 1 else 2
    msg.suite_id = tampered_sid
    tampered = msg.to_bytes()

    with pytest.raises(HandshakeError):
        responder.process_hello_i(tampered)


# ===========================================================================
# T13 — Reflected FINISHED
# ===========================================================================

@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t13_finished_i_reflected_to_initiator(suite_name: str) -> None:
    """Reflect FINISHED_I back to initiator as if it were FINISHED_R → HandshakeError."""
    suite, init_id, resp_id = _make_identities(suite_name)
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    hello_r = responder.process_hello_i(hello_i)
    finished_i = initiator.process_hello_r(hello_r)

    with pytest.raises(HandshakeError):
        initiator.process_finished_r(finished_i)


@pytest.mark.parametrize("suite_name", _ALL_SUITE_PARAMS)
def test_t13_finished_r_replayed_to_responder_as_finished_i(suite_name: str) -> None:
    """Relay FINISHED_R to responder as if it were FINISHED_I → HandshakeError."""
    suite, init_id, resp_id = _make_identities(suite_name)
    initiator = HandshakeInitiator(suite, init_id)
    responder = HandshakeResponder(suite, resp_id)

    hello_i = initiator.start()
    hello_r = responder.process_hello_i(hello_i)
    finished_i = initiator.process_hello_r(hello_r)
    finished_r, _ = responder.process_finished_i(finished_i)

    responder2 = HandshakeResponder(suite, resp_id)
    responder2.process_hello_i(hello_i)
    with pytest.raises(HandshakeError):
        responder2.process_finished_i(finished_r)
