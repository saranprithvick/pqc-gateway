"""LinkEmulator: bidirectional asyncio link with configurable impairments.

Each direction (I2R and R2I) is an independent asyncio Task that:
  1. Accepts a message from the sender's queue.
  2. Fragments it to mtu_bytes.
  3. For each fragment: applies bandwidth serialisation (synchronous, keeps wire order),
     then loss, then feeds to the reassembler.
  4. When a message is fully reassembled, its propagation delay is applied via an
     asyncio task (pipelined: all messages in a direction experience delay
     concurrently, so 100 messages sent at once all arrive ≈ delay_ms later).
  5. link_ns_acc accumulates (delay + serialisation) per DELIVERED message for
     benchmark crypto/link time decomposition.

Handshake retransmission is NOT handled here; the Gateway/Peer retransmit on timeout.

Each make_pair() call gets its own seeded random.Random, so simulations are
reproducible (all non-cryptographic randomness takes a seed from config, per CLAUDE.md §2.7).
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from pqcgw.net.fragment import Reassembler, fragment
from pqcgw.net.link import Link

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class NetworkConfig:
    delay_ms: float = 0.0
    jitter_ms: float = 0.0
    loss_pct: float = 0.0        # 0.0–100.0
    bandwidth_kbps: float = 0.0  # 0 = unlimited (bandwidth cap deferred to M7)
    reorder_pct: float = 0.0     # reorder deferred to M7
    mtu_bytes: int = 1500
    seed: int = 42

    @classmethod
    def from_toml(cls, path: Path) -> "NetworkConfig":
        with open(path, "rb") as fh:
            d = tomllib.load(fh)
        return cls(
            delay_ms=float(d.get("delay_ms", 0.0)),
            jitter_ms=float(d.get("jitter_ms", 0.0)),
            loss_pct=float(d.get("loss_pct", 0.0)),
            bandwidth_kbps=float(d.get("bandwidth_kbps", 0.0)),
            reorder_pct=float(d.get("reorder_pct", 0.0)),
            mtu_bytes=int(d.get("mtu_bytes", 1500)),
            seed=int(d.get("seed", 42)),
        )


class _EmulatedHalf(Link):
    """One side of a LinkEmulator pair.

    send() pushes to the shared input queue; recv() pops from the output queue
    after the impairment task has processed and delivered fragments.
    """

    def __init__(
        self,
        in_queue: asyncio.Queue,
        out_queue: asyncio.Queue,
        frag_counter_ref: list[int],
    ) -> None:
        self._in = in_queue
        self._out = out_queue
        self._frag_counter = frag_counter_ref  # mutable list[int] shared with emulator

    async def send(self, msg: bytes) -> None:
        await self._in.put(msg)

    async def recv(self, timeout: float = 1.0) -> Optional[bytes]:
        try:
            return await asyncio.wait_for(self._out.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None


class LinkEmulator:
    """Bidirectional emulated link.  Use make_pair() to create."""

    def __init__(self, config: NetworkConfig) -> None:
        self._config = config
        self._rng = random.Random(config.seed)
        # Fragment counters (mutable list so tasks can share the ref)
        self._frags_i2r: list[int] = [0]
        self._frags_r2i: list[int] = [0]
        # Link-delay accumulators (ns per delivered message, for benchmark decomposition)
        self._link_ns_i2r: list[int] = [0]
        self._link_ns_r2i: list[int] = [0]
        # Drop log: each entry is {"direction", "msg_id", "frag_idx", "frag_count",
        # "type_byte"} where type_byte is the C1–C3 prefix byte from the first
        # fragment's payload (None for C0/unknown).
        self._drop_log: list[dict] = []
        # Queues: gw_send → impair_i2r → peer_recv; peer_send → impair_r2i → gw_recv
        self._gw_send: asyncio.Queue[bytes] = asyncio.Queue()
        self._peer_recv: asyncio.Queue[bytes] = asyncio.Queue()
        self._peer_send: asyncio.Queue[bytes] = asyncio.Queue()
        self._gw_recv: asyncio.Queue[bytes] = asyncio.Queue()
        # Halves
        self._gw_half = _EmulatedHalf(self._gw_send, self._gw_recv, self._frags_r2i)
        self._peer_half = _EmulatedHalf(self._peer_send, self._peer_recv, self._frags_i2r)
        # Tasks started lazily
        self._tasks: list[asyncio.Task] = []
        self._started = False

    @property
    def fragments_sent_i2r(self) -> int:
        return self._frags_i2r[0]

    @property
    def fragments_sent_r2i(self) -> int:
        return self._frags_r2i[0]

    @property
    def handshake_link_ns_i2r(self) -> int:
        """Accumulated (delay + serialisation) ns for all delivered I2R messages."""
        return self._link_ns_i2r[0]

    @property
    def handshake_link_ns_r2i(self) -> int:
        """Accumulated (delay + serialisation) ns for all delivered R2I messages."""
        return self._link_ns_r2i[0]

    def reset_link_ns(self) -> None:
        """Zero the link-ns accumulators (call before the phase you want to measure)."""
        self._link_ns_i2r[0] = 0
        self._link_ns_r2i[0] = 0

    @property
    def dropped_messages(self) -> list[dict]:
        """Log of dropped fragments: [{direction, msg_id, frag_idx, frag_count, type_byte}]."""
        return self._drop_log

    @property
    def gateway_half(self) -> Link:
        self._start()  # ensure impairment tasks are running before first use
        return self._gw_half

    @property
    def peer_half(self) -> Link:
        self._start()
        return self._peer_half

    def _start(self) -> None:
        if self._started:
            return
        self._started = True
        loop = asyncio.get_event_loop()
        self._tasks.append(loop.create_task(
            self._impair_direction(
                in_q=self._gw_send,
                out_q=self._peer_recv,
                counter=self._frags_i2r,
                link_ns_acc=self._link_ns_i2r,
                direction="i2r",
            )
        ))
        self._tasks.append(loop.create_task(
            self._impair_direction(
                in_q=self._peer_send,
                out_q=self._gw_recv,
                counter=self._frags_r2i,
                link_ns_acc=self._link_ns_r2i,
                direction="r2i",
            )
        ))

    async def _impair_direction(
        self,
        in_q: asyncio.Queue,
        out_q: asyncio.Queue,
        counter: list[int],
        link_ns_acc: list[int],
        direction: str = "unknown",
    ) -> None:
        reassembler = Reassembler()
        rng = random.Random(self._rng.random())  # per-direction seeded sub-RNG
        msg_id_gen = 0
        while True:
            msg = await in_q.get()
            frags = fragment(msg_id_gen & 0xFFFFFFFF, msg, self._config.mtu_bytes)
            msg_id_gen += 1
            counter[0] += len(frags)
            msg_serialise_ns = 0
            for frag_bytes in frags:
                # Bandwidth serialisation (synchronous — keeps wire ordering for this direction)
                if self._config.bandwidth_kbps > 0:
                    serialise_s = len(frag_bytes) * 8 / (self._config.bandwidth_kbps * 1000.0)
                    msg_serialise_ns += int(serialise_s * 1e9)
                    await asyncio.sleep(serialise_s)
                # Loss
                if self._config.loss_pct > 0 and rng.random() * 100 < self._config.loss_pct:
                    # Parse fragment header to record type_byte for drop log.
                    frag_idx = int.from_bytes(frag_bytes[4:6], "big") if len(frag_bytes) >= 6 else 0
                    frag_count = int.from_bytes(frag_bytes[6:8], "big") if len(frag_bytes) >= 8 else 1
                    type_byte: Optional[int] = (
                        frag_bytes[8] if frag_idx == 0 and len(frag_bytes) > 8 else None
                    )
                    self._drop_log.append({
                        "direction": direction,
                        "msg_id": int.from_bytes(frag_bytes[0:4], "big") if len(frag_bytes) >= 4 else 0,
                        "frag_idx": frag_idx,
                        "frag_count": frag_count,
                        "type_byte": type_byte,
                    })
                    continue  # drop this fragment
                # Feed to reassembler; deliver when complete
                result = reassembler.feed(frag_bytes)
                if result is not None:
                    # Propagation delay (pipelined — does not block this loop)
                    delay_s = self._config.delay_ms / 1000.0
                    if self._config.jitter_ms > 0:
                        delay_s += rng.uniform(
                            -self._config.jitter_ms, self._config.jitter_ms
                        ) / 1000.0
                    delay_s = max(0.0, delay_s)
                    link_ns_acc[0] += int(delay_s * 1e9) + msg_serialise_ns
                    if delay_s > 0:
                        loop = asyncio.get_running_loop()
                        # Capture loop-locals by default-arg to avoid closure-over-loop issues
                        async def _deliver(d: float = delay_s, m: bytes = result, q: asyncio.Queue = out_q) -> None:
                            await asyncio.sleep(d)
                            await q.put(m)
                        loop.create_task(_deliver())
                    else:
                        await out_q.put(result)
                    msg_serialise_ns = 0  # reset per message

    async def _send_gw(self, msg: bytes) -> None:
        self._start()
        await self._gw_send.put(msg)

    async def _recv_gw(self, timeout: float) -> Optional[bytes]:
        self._start()
        try:
            return await asyncio.wait_for(self._gw_recv.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def _send_peer(self, msg: bytes) -> None:
        self._start()
        await self._peer_send.put(msg)

    async def _recv_peer(self, timeout: float) -> Optional[bytes]:
        self._start()
        try:
            return await asyncio.wait_for(self._peer_recv.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    @staticmethod
    def make_pair(config: NetworkConfig) -> tuple[Link, Link]:
        """Return (gateway_link, peer_link).

        gateway_link.send() → (fragmented + impaired) → peer_link.recv()
        peer_link.send()    → (fragmented + impaired) → gateway_link.recv()
        """
        emulator = LinkEmulator(config)

        class _GwLink(Link):
            async def send(self, msg: bytes) -> None:
                await emulator._send_gw(msg)

            async def recv(self, timeout: float = 1.0) -> Optional[bytes]:
                return await emulator._recv_gw(timeout)

        class _PeerLink(Link):
            async def send(self, msg: bytes) -> None:
                await emulator._send_peer(msg)

            async def recv(self, timeout: float = 1.0) -> Optional[bytes]:
                return await emulator._recv_peer(timeout)

        # Attach the emulator so callers can inspect counters
        gw = _GwLink()
        peer = _PeerLink()
        gw._emulator = emulator   # type: ignore[attr-defined]
        peer._emulator = emulator  # type: ignore[attr-defined]
        return gw, peer
