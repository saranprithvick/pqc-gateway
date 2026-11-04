"""Handshake key schedule.

Derives all session keys from the combined shared secret, the transcript hash,
and the two nonces, following §5.3 and §15 items 7 and 8.

Label encoding (§15 item 8):
    info = u8(len(label_ascii)) || label_ascii || u8(suite_id) || th || u8(epoch)

All six derived values use distinct labels so they are cryptographically
independent.  Epoch 0 is used for the initial handshake keys; rekeying (M4)
uses epoch > 0.

The hash function H is determined by the suite's KDF:
  hkdf-sha256 → hashlib.sha256
  hkdf-sha384 → hashlib.sha384
(§15 item 7)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from pqcgw.crypto.registry import Suite
from pqcgw.crypto.providers.kdf_hkdf import HkdfSha256, HkdfSha384


@dataclass
class SessionKeys:
    """All keys and salts derived from one completed handshake epoch."""

    k_i2r: bytes       # AEAD key, initiator → responder direction
    k_r2i: bytes       # AEAD key, responder → initiator direction
    salt_i2r: bytes    # 4-byte nonce prefix, i2r
    salt_r2i: bytes    # 4-byte nonce prefix, r2i
    k_finished: bytes  # 32-byte key for FINISHED HMAC
    rekey_sec0: bytes  # current ratchet secret; updated each light rekey
    suite_id: int
    th: bytes          # original handshake transcript hash; fixed for session lifetime
    epoch: int = 0


def suite_hash(suite: "Suite"):
    """Return the hashlib constructor matching the suite's KDF (§15 item 7)."""
    if isinstance(suite.kdf, HkdfSha256):
        return hashlib.sha256
    if isinstance(suite.kdf, HkdfSha384):
        return hashlib.sha384
    # Fallback: inspect the KDF's algorithm name if it exists
    raise TypeError(f"Cannot determine hash for KDF type {type(suite.kdf)}")


def _info(label: str, suite_id: int, th: bytes, epoch: int) -> bytes:
    """Build the HKDF info field per §15 item 8.

    info = u8(len(label)) || label_ascii || u8(suite_id) || th || u8(epoch)
    """
    lb = label.encode("ascii")
    if len(lb) > 255:
        raise ValueError(f"Label too long: {label!r}")
    if suite_id > 255 or epoch > 255:
        raise ValueError("suite_id and epoch must fit in u8")
    return bytes([len(lb)]) + lb + bytes([suite_id]) + th + bytes([epoch])


def derive_session_keys(
    suite: "Suite",
    ss: bytes,
    nonce_i: bytes,
    nonce_r: bytes,
    th: bytes,
    epoch: int = 0,
) -> SessionKeys:
    """Derive all session keys from the combined shared secret.

    Args:
        suite:   Fully resolved Suite (kdf and aead used here).
        ss:      Combined shared secret: ss_comp1 || ss_comp2 || … (raw concat).
        nonce_i: 32-byte initiator nonce from HELLO_I.
        nonce_r: 32-byte responder nonce from HELLO_R.
        th:      Transcript hash H(HELLO_I || HELLO_R).
        epoch:   Key epoch; 0 for the initial handshake.

    Returns:
        SessionKeys with six derived values.
    """
    sid = suite.suite_id
    key_len = suite.aead.key_len

    prk = suite.kdf.extract(salt=nonce_i + nonce_r, ikm=ss)

    def expand(label: str, length: int) -> bytes:
        return suite.kdf.expand(prk, _info(label, sid, th, epoch), length)

    return SessionKeys(
        k_i2r=expand("key i2r", key_len),
        k_r2i=expand("key r2i", key_len),
        salt_i2r=expand("salt i2r", 4),
        salt_r2i=expand("salt r2i", 4),
        k_finished=expand("finished", 32),
        rekey_sec0=expand("rekey0", 32),
        suite_id=sid,
        th=th,
        epoch=epoch,
    )
