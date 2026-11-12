"""Analytical CAN/CAN FD bus occupancy script.

ANALYTICAL ESTIMATE — NOT A SIMULATION.
Virtual CAN has no real timing; this computes theoretical bus occupancy.

CAN 2.0A frame bits (worst-case bit stuffing):
  Overhead = 44 bits (without IFS) or 47 bits (with 3-bit IFS)
  Data bits = 8 × DLC
  Dynamic stuff bits (Davis et al. 2007, worst case):
      ⌊(34 + 8 × DLC - 1) / 4⌋   [from SOF through CRC, excluding EOF/IFS]
  Total (with IFS, worst case):
      47 + 8 × DLC + ⌊(34 + 8 × DLC - 1) / 4⌋

  Reference: Davis R.I., Burns A., Bril R.J., Lukkien J.J. (2007).
  "Controller Area Network (CAN) schedulability analysis: Refuted, revisited
  and revised." Real-Time Systems 35(3).

CAN FD frame bits (worst-case):
  Arbitration field (bit-stuffed, nominal rate): SOF + 11-bit ID + RTR + IDE +
  res + DLC = 15 bits; control field includes BRS, ESI, r0.
  Dynamic stuffing applies from SOF up to (not including) the CRC field:
      n_dyn bits → ⌊(n_dyn - 1) / 4⌋ dynamic stuff bits (worst case)
  CRC field uses FIXED stuff bits:
      CRC-17 (DLC ≤ 16 B, i.e. CAN FD ≤ 16 B payload): 4 fixed stuff bits
      CRC-21 (DLC > 16 B, i.e. CAN FD 20–64 B payload): 5 fixed stuff bits
  Stuff Count = 3-bit Gray-coded count + 1 parity bit = 4 bits total.
  References:
    Bosch GmbH. "CAN with Flexible Data-Rate Specification Version 1.0."
    April 17, 2012.
    Davis et al. 2007 (above) for worst-case dynamic stuffing bound.

Protected records on CAN: HYPOTHETICAL calculation showing overhead if the
gateway-to-gateway link ran over CAN 2.0 / CAN FD (it does not in this
prototype — the link uses a virtual emulated network).  The gateway actually
communicates over the emulated IP/UDP-like link.  The fragment header (8 B)
and 1-byte prefix are NOT counted here (they are link-layer, not CAN-layer).
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[5]
_RESULTS = _ROOT / "results" / "tables"


def _can20_frame_bits_worst(dlc: int) -> int:
    """CAN 2.0A worst-case frame bits including IFS.

    Formula: 47 + 8*dlc + floor((34 + 8*dlc - 1) / 4)
    The 47 accounts for SOF(1) + 11-ID + RTR + IDE + r0 + DLC(4) + 15-CRC +
    CRC-del + ACK + ACK-del + EOF(7) + IFS(3) = 47 non-data bits.
    The stuffable region (SOF…CRC excl. delimiters) = 34 bits + data.
    Worst-case stuff count per Davis et al. 2007.
    """
    if not (0 <= dlc <= 8):
        raise ValueError(f"CAN 2.0 DLC must be 0–8, got {dlc}")
    data_bits = 8 * dlc
    # Stuffable region: SOF(1) + ID(11) + RTR(1) + IDE(1) + r0(1) + DLC(4) + data + CRC(15) = 34 + data_bits
    stuffable = 34 + data_bits
    stuff_bits = (stuffable - 1) // 4   # worst case: Davis et al. 2007
    return 47 + data_bits + stuff_bits


def _can_fd_frame_bits_worst(dlc_bytes: int) -> int:
    """CAN FD worst-case frame bits.

    CAN FD frame structure (nominal-rate arbitration + data-rate data):
      SOF(1) + ID(11) + RRS(1) + IDE(1) + EDL(1) + r0(1) + BRS(1) + ESI(1) +
      DLC(4) = 22 bits before data, all in the stuffable dynamic region.
      After DLC: data (8*dlc_bytes bits) in the stuffable dynamic region.
      CRC field: CRC value + fixed stuff bits + Stuff Count (4 bits).
        CRC-17 for payload ≤ 16 B: 17-bit CRC + 4 fixed stuff bits = 21 bits
        CRC-21 for payload > 16 B: 21-bit CRC + 5 fixed stuff bits = 26 bits
      CRC delimiters, ACK, ACK-del, EOF(10 bits), IFS(2 bits) ≈ 15 bits.

    Dynamic stuffable region (from SOF to end of data before CRC):
      22 + 8*dlc_bytes bits

    Stuff Count = 3-bit Gray code + 1 parity = 4 bits (Bosch CAN FD Spec v1.0, 2012)
    """
    valid_fd = {0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64}
    if dlc_bytes not in valid_fd:
        raise ValueError(f"CAN FD DLC {dlc_bytes} not in valid set {sorted(valid_fd)}")

    data_bits = 8 * dlc_bytes
    # Stuffable region before CRC: header(22) + data
    n_dyn = 22 + data_bits
    dyn_stuff_bits = (n_dyn - 1) // 4   # worst case

    # CRC field (fixed stuff bits from Bosch CAN FD Spec v1.0, 2012)
    if dlc_bytes <= 16:
        crc_bits = 17
        crc_fixed_stuff = 4   # CRC-17: 4 fixed stuff bits
    else:
        crc_bits = 21
        crc_fixed_stuff = 5   # CRC-21: 5 fixed stuff bits

    stuff_count_bits = 4  # 3-bit Gray + 1 parity (Bosch CAN FD Spec v1.0)

    # Fixed overhead: CRC delimiters(1) + ACK(1) + ACK-del(1) + EOF(10) + IFS(2) = 15
    fixed_tail = 15

    total = n_dyn + dyn_stuff_bits + crc_bits + crc_fixed_stuff + stuff_count_bits + fixed_tail
    return total


def _bytes_to_can_frames(total_bytes: int, dlc: int) -> int:
    """Number of CAN 2.0 frames needed for total_bytes payload."""
    if dlc == 0:
        return 0
    return math.ceil(total_bytes / dlc)


def compute_bus_occupancy(
    *,
    bit_rate_kbps: float = 500.0,
    can_fd: bool = False,
    dlc: int = 8,
    rate_hz: float = 100.0,
    n_senders: int = 1,
    record_overhead_bytes: int = 32,  # 16 hdr + 16 tag
    frag_overhead_bytes: int = 0,     # fragment header NOT counted (link-layer only)
) -> dict:
    """Compute bus occupancy for one sender at given rate.

    Returns a dict with bits_per_frame, bits_per_second, occupancy_pct.
    record_overhead_bytes: added to payload for protected-record hypothetical.
    Set to 0 for baseline CAN-only.
    """
    payload_per_frame = dlc + record_overhead_bytes  # hypothetical bytes per send
    if not can_fd and payload_per_frame > 8:
        # Must segment into multiple CAN 2.0 frames
        n_frames = math.ceil(payload_per_frame / dlc)
        bits_per_send = n_frames * _can20_frame_bits_worst(dlc)
    elif can_fd:
        bits_per_send = _can_fd_frame_bits_worst(payload_per_frame)
    else:
        bits_per_send = _can20_frame_bits_worst(dlc)

    bits_per_second = bits_per_send * rate_hz * n_senders
    occupancy_pct = bits_per_second / (bit_rate_kbps * 1000.0) * 100.0

    return {
        "can_fd": can_fd,
        "dlc": dlc,
        "rate_hz": rate_hz,
        "n_senders": n_senders,
        "payload_bytes": dlc,
        "record_overhead_bytes": record_overhead_bytes,
        "bits_per_frame": bits_per_send,
        "bits_per_second": bits_per_second,
        "bit_rate_kbps": bit_rate_kbps,
        "occupancy_pct": occupancy_pct,
    }


def run(
    bit_rate_kbps: float = 500.0,
    fd_data_rate_kbps: float = 2000.0,
    dlcs: list[int] = None,
    fd_dlcs: list[int] = None,
    rate_hz: float = 100.0,
    n_senders: int = 1,
) -> None:
    if dlcs is None:
        dlcs = [8]
    if fd_dlcs is None:
        fd_dlcs = [8, 64]

    print("=" * 72)
    print("ANALYTICAL ESTIMATE — NOT A SIMULATION")
    print("CAN bus occupancy: worst-case bit stuffing (Davis et al. 2007)")
    print("=" * 72)

    rows = []

    for dlc in dlcs:
        # Baseline (no overhead)
        r = compute_bus_occupancy(
            bit_rate_kbps=bit_rate_kbps, can_fd=False, dlc=dlc,
            rate_hz=rate_hz, n_senders=n_senders, record_overhead_bytes=0,
        )
        rows.append({"scenario": "baseline", **r})
        print(
            f"CAN2.0 DLC={dlc} baseline   : {r['bits_per_frame']:4d} bits/frame  "
            f"{r['occupancy_pct']:.2f}% @ {bit_rate_kbps} kbps"
        )

        # Protected record hypothetical (16B hdr + 16B tag, segmented over CAN 2.0)
        r2 = compute_bus_occupancy(
            bit_rate_kbps=bit_rate_kbps, can_fd=False, dlc=dlc,
            rate_hz=rate_hz, n_senders=n_senders, record_overhead_bytes=32,
        )
        rows.append({"scenario": "protected_record_hypothetical", **r2})
        print(
            f"CAN2.0 DLC={dlc} +32B record: {r2['bits_per_frame']:4d} bits/frame  "
            f"{r2['occupancy_pct']:.2f}% @ {bit_rate_kbps} kbps  "
            f"[hypothetical — gateway link does not run over CAN]"
        )

    for fd_dlc in fd_dlcs:
        r = compute_bus_occupancy(
            bit_rate_kbps=fd_data_rate_kbps, can_fd=True, dlc=fd_dlc,
            rate_hz=rate_hz, n_senders=n_senders, record_overhead_bytes=0,
        )
        rows.append({"scenario": "baseline", **r})
        print(
            f"CAN FD DLC={fd_dlc:2d} baseline  : {r['bits_per_frame']:5d} bits/frame  "
            f"{r['occupancy_pct']:.3f}% @ {fd_data_rate_kbps} kbps"
        )

    _RESULTS.mkdir(parents=True, exist_ok=True)
    import csv
    out_path = _RESULTS / "bus_time.csv"
    with open(out_path, "w", newline="") as fh:
        fh.write("# ANALYTICAL ESTIMATE — NOT A SIMULATION\n")
        fh.write(f"# bit_rate_kbps: {bit_rate_kbps}\n")
        fh.write(f"# fd_data_rate_kbps: {fd_data_rate_kbps}\n")
        fh.write(f"# rate_hz: {rate_hz}  n_senders: {n_senders}\n")
        fh.write("# Davis R.I. et al. 2007; Bosch CAN FD Spec v1.0 (2012)\n")
        if rows:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    print(f"\n→ {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CAN bus occupancy (analytical)")
    parser.add_argument("--bit-rate", type=float, default=500.0, help="CAN 2.0 bit rate kbps")
    parser.add_argument("--fd-rate", type=float, default=2000.0, help="CAN FD data bit rate kbps")
    parser.add_argument("--rate-hz", type=float, default=100.0, help="Frame emission rate Hz")
    parser.add_argument("--senders", type=int, default=1, help="Number of senders")
    args = parser.parse_args()
    run(bit_rate_kbps=args.bit_rate, fd_data_rate_kbps=args.fd_rate,
        rate_hz=args.rate_hz, n_senders=args.senders)
