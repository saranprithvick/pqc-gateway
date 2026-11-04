"""Light-rekey (ratchet) key derivation for the PQC gateway session layer.

The ratchet advances the session one epoch forward without a new handshake.

Security properties:
  - Forward secrecy for past epochs: epoch-n+1 keys are derived from rekey_sec_n, which
    is deleted (overwritten in the returned SessionKeys) after the new epoch is established.
    An observer who learns rekey_sec_n cannot recover keys for epochs < n.
  - Limitation (documented in §5.7 and LIMITATIONS.md): the ratchet does NOT evict an
    attacker who already holds the current session secret.  A full rekey (new handshake)
    is required to achieve that.

Formula (§15 item 8):
    n = current_epoch + 1
    rekey_sec_n = KDF.expand(rekey_sec_{n-1}, _info("rekey",    sid, th, n), 32)
    k_i2r       = KDF.expand(rekey_sec_n,     _info("key i2r",  sid, th, n), key_len)
    k_r2i       = KDF.expand(rekey_sec_n,     _info("key r2i",  sid, th, n), key_len)
    salt_i2r    = KDF.expand(rekey_sec_n,     _info("salt i2r", sid, th, n), 4)
    salt_r2i    = KDF.expand(rekey_sec_n,     _info("salt r2i", sid, th, n), 4)
    k_finished  = KDF.expand(rekey_sec_n,     _info("finished", sid, th, n), 32)

The transcript hash `th` is the original handshake transcript hash stored in SessionKeys;
it is fixed for the lifetime of the session and bound to every expand call to prevent
cross-session key confusion.

Python cannot guarantee in-memory zeroization of the previous rekey_sec; this is a
documented limitation.
"""

from __future__ import annotations

from pqcgw.crypto.registry import Suite
from pqcgw.protocol.keyschedule import SessionKeys, _info


def derive_rekey_epoch(suite: Suite, keys: SessionKeys) -> SessionKeys:
    """Ratchet SessionKeys forward by one epoch.

    Args:
        suite: Fully resolved Suite (kdf and aead used here).
        keys:  Current-epoch SessionKeys. keys.rekey_sec0 is the current ratchet secret;
               keys.th is the original transcript hash.

    Returns:
        New SessionKeys with epoch = keys.epoch + 1. The returned rekey_sec0 is the
        new ratchet secret (rekey_sec_n); callers should discard the old one.
    """
    n = keys.epoch + 1
    sid = keys.suite_id
    th = keys.th
    kdf = suite.kdf
    key_len = suite.aead.key_len

    rekey_sec_n = kdf.expand(keys.rekey_sec0, _info("rekey",    sid, th, n), 32)

    return SessionKeys(
        k_i2r=kdf.expand(rekey_sec_n,     _info("key i2r",  sid, th, n), key_len),
        k_r2i=kdf.expand(rekey_sec_n,     _info("key r2i",  sid, th, n), key_len),
        salt_i2r=kdf.expand(rekey_sec_n,  _info("salt i2r", sid, th, n), 4),
        salt_r2i=kdf.expand(rekey_sec_n,  _info("salt r2i", sid, th, n), 4),
        k_finished=kdf.expand(rekey_sec_n, _info("finished", sid, th, n), 32),
        rekey_sec0=rekey_sec_n,
        suite_id=sid,
        th=th,
        epoch=n,
    )
