"""CAN frame model and wire-encoding constants.

CLAUDE.md §5.5: "can_id (4 B incl. flags)" — the 4-byte field encodes the
arbitration ID plus two flag bits so the receiver can reconstruct is_extended
and is_fd without side-channel fields.
"""

from __future__ import annotations

from dataclasses import dataclass

# Valid CAN FD payload byte counts (DLC codes 0–15 → these lengths).
VALID_FD_LENGTHS: frozenset[int] = frozenset(
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64]
)

# 4-byte can_id encoding flags.
MSG_EFF_FLAG: int = 0x80000000  # extended 29-bit arbitration ID
MSG_FD_FLAG: int = 0x20000000   # CAN FD frame
MSG_ID_MASK: int = 0x1FFFFFFF   # arbitration-ID bits 28:0

# Standard-frame ID upper bound (11-bit).
_STD_ID_MAX: int = 0x7FF


@dataclass
class CANFrame:
    """One CAN 2.0 or CAN FD data frame.

    dlc is the actual byte count (not a DLC code).  For CAN FD frames, dlc must
    be one of VALID_FD_LENGTHS; for CAN 2.0, dlc must be 0–8.
    """

    can_id: int           # arbitration ID
    dlc: int              # actual payload byte count
    data: bytes           # len(data) must equal dlc
    is_fd: bool = False
    is_extended: bool = False  # 29-bit extended ID?

    def __post_init__(self) -> None:
        id_max = MSG_ID_MASK if self.is_extended else _STD_ID_MAX
        if not (0 <= self.can_id <= id_max):
            raise ValueError(
                f"can_id 0x{self.can_id:X} out of range for "
                f"{'extended' if self.is_extended else 'standard'} frame"
            )
        if self.is_fd:
            if self.dlc not in VALID_FD_LENGTHS:
                raise ValueError(
                    f"CAN FD dlc {self.dlc} not in valid FD lengths {sorted(VALID_FD_LENGTHS)}"
                )
        else:
            if not (0 <= self.dlc <= 8):
                raise ValueError(f"CAN 2.0 dlc {self.dlc} out of range 0–8")
        if len(self.data) != self.dlc:
            raise ValueError(
                f"data length {len(self.data)} does not match dlc {self.dlc}"
            )
