"""LinkEmulator: bidirectional asyncio link with configurable impairments.

Each direction (I2R and R2I) is an independent asyncio Task that:
  1. Accepts a message from the sender's queue.
  2. Fragments it to mtu_bytes.
  3. For each fragment: applies loss, then delay (delay_ms ± jitter_ms, clamped ≥ 0).
  4. Pushes surviving fragments to the receiver's reassembler queue.
  5. Receiver reassembles fragments before making messages available via recv().

Handshake retransmission is NOT handled here; the Gateway/Peer retransmit on timeout.
Reorder and bandwidth cap are deferred to M7.

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
        # I2R counters
        self._frags_i2r: list[int] = [0]
        self._frags_r2i: list[int] = [0]
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
        self._msg_counter = 0  # global message-id counter

    @property
    def fragments_sent_i2r(self) -> int:
        return self._frags_i2r[0]

    @property
    def fragments_sent_r2i(self) -> int:
        return self._frags_r2i[0]

    def _start(self) -> None:
        if self._started:
            return
        self._started = True
        self._tasks.append(asyncio.get_event_loop().create_task(
            self._impair_direction(
                in_q=self._gw_send,
                out_q=self._peer_recv,
                counter=self._frags_i2r,
                direction="I2R",
            )
        ))
        self._tasks.append(asyncio.get_event_loop().create_task(
            self._impair_direction(
                in_q=self._peer_send,
                out_q=self._gw_recv,
                counter=self._frags_r2i,
                direction="R2I",
            )
        ))

    async def _impair_direction(
        self,
        in_q: asyncio.Queue,
        out_q: asyncio.Queue,
        counter: list[int],
        direction: str,
    ) -> None:
        reassembler = Reassembler()
        rng = random.Random(self._rng.random())  # per-direction seeded sub-RNG
        msg_id_gen = 0
        while True:
            msg = await in_q.get()
            frags = fragment(msg_id_gen & 0xFFFFFFFF, msg, self._config.mtu_bytes)
            msg_id_gen += 1
            counter[0] += len(frags)
            for frag_bytes in frags:
                # Loss
                if self._config.loss_pct > 0 and rng.random() * 100 < self._config.loss_pct:
                    continue  # drop this fragment
                # Delay
                delay_s = self._config.delay_ms / 1000.0
                if self._config.jitter_ms > 0:
                    delay_s += rng.uniform(-self._config.jitter_ms, self._config.jitter_ms) / 1000.0
                delay_s = max(0.0, delay_s)
                if delay_s > 0:
                    await asyncio.sleep(delay_s)
                # Feed to reassembler; deliver when complete
                result = reassembler.feed(frag_bytes)
                if result is not None:
                    await out_q.put(result)

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
