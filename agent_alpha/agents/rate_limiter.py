# agent_alpha/agents/rate_limiter.py
"""Per-engagement egress rate limiter (Rules-of-Engagement control).

`policy.yaml` declares `rate_limiting_enabled` + per-OPSEC-profile `rate_limit_rps`
(quiet=2 / normal=10 / loud=50), but nothing enforced it — recon fired requests as
fast as the network allowed (anti-Lyndon #2: declared-not-wired; a real RoE risk
once probing live client targets). This is the enforcement: a blocking min-interval
limiter at the single HTTP egress chokepoint (`HttpClient.get`).

Design:
- DELAYS, never DROPS — `acquire()` blocks until the next slot, so no request is
  silently discarded (anti-Lyndon #3). Throughput is bounded, requests are not lost.
- Injectable clock + sleep → fully deterministic tests (no real wall-clock waiting).
- Thread-safe — Celery workers may share a client across threads.
- The FIRST request is immediate; subsequent requests are spaced by >= 1/rps.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class RateLimiter:
    """Guarantee >= 1/rps seconds between successive `acquire()` calls."""

    def __init__(
        self,
        rps: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rps <= 0:
            raise ValueError(f"rps must be > 0, got {rps}")
        self._min_interval = 1.0 / rps
        self._monotonic = monotonic
        self._sleep = sleep
        self._next_allowed: float | None = None  # None → first request is immediate
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until a request slot is available, then reserve the next slot."""
        with self._lock:
            now = self._monotonic()
            if self._next_allowed is not None and now < self._next_allowed:
                self._sleep(self._next_allowed - now)
                now = self._next_allowed
            self._next_allowed = now + self._min_interval
