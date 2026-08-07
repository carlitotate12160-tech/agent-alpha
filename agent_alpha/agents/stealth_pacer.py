# agent_alpha/agents/stealth_pacer.py
"""§12.50 — human-like burst-and-pause egress pacer (stealth OPSEC profile).

Duck-types ``RateLimiter.acquire()`` so ``HttpClient`` uses it in place of the
fixed-interval limiter, plus an optional ``notify(status_code)`` hook for
adaptive backoff.

Human-likeness comes from a MULTI-MODAL timing shape, NOT from maximal
randomness (uniform noise is itself a bot tell):

  BURST:       3-5 requests spaced by short intra-burst gaps (50-200ms) — a
               browser fetching a page + its assets.
  READ pause:  2-8s after each burst — user reading the page.
  THINK pause: 10-30s every 3-5 bursts — user thinking / typing.
  IDLE pause:  60-120s every 10-15 bursts — tab switch / away.
  DISTRACTION: ~10% chance per request of an extra long pause (mimicry-derived).

All phase durations are drawn from a GAUSSIAN centred on the range midpoint
(ADR §12.50 amended: uniform ±20% → Gaussian, per human reaction-time studies),
clamped >= 0. The multi-modal phase structure — not the intra-phase noise — is
what makes the signal human; the "every N bursts" thresholds are re-randomised
each time so there is no fixed periodicity (anti-Lyndon #11).

BACKOFF (RoE-protective, from the Slice review): ``notify(429|503)`` doubles the
next pause AND ends the current burst early (server signalled overload → slow
down promptly); a 2xx resets the multiplier. Capped to avoid runaway.

Sustained rate stays under the stealth rps by CONSTRUCTION: a 3-5 request burst
(<1s) followed by a 2-8s+ pause averages well under 2 rps over any 10s window,
so no per-request min-interval floor is wrapped (which would kill the burst).

The RNG is seeded per-engagement → deterministic replay in tests, unpredictable
in production. ``monotonic``/``sleep`` are injectable for hermetic tests.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from urllib.parse import urlparse

from agent_alpha.config import constants

_BACKOFF_STATUSES = frozenset({429, 503})


class StealthPacer:
    """Human burst-and-pause pacer. Satisfies the ``Pacer`` protocol."""

    def __init__(
        self,
        *,
        seed: int | str | bytes | None = None,
        rng: random.Random | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._rng = rng if rng is not None else random.Random(seed)  # nosec B311
        self._sleep = sleep
        self._monotonic = monotonic
        self._started = False
        self._in_burst = 0
        self._last_host: str | None = None
        self._burst_size = self._pick_burst_size()
        self._bursts_until_think = self._rng.randint(*constants.STEALTH_THINK_EVERY_N_BURSTS)
        self._bursts_until_idle = self._rng.randint(*constants.STEALTH_IDLE_EVERY_N_BURSTS)
        self._backoff = 1.0

    # ── internals ──────────────────────────────────────────────────
    def _pick_burst_size(self) -> int:
        return self._rng.randint(constants.STEALTH_BURST_MIN, constants.STEALTH_BURST_MAX)

    def _gauss_in(self, lo: float, hi: float) -> float:
        """A Gaussian draw centred on the [lo, hi] midpoint (std = (hi-lo)/4 →
        ~95% of draws land in range), clamped >= 0."""
        mean = (lo + hi) / 2.0
        std = (hi - lo) / 4.0
        return max(0.0, self._rng.gauss(mean, std))

    def _maybe_distraction(self) -> None:
        if self._rng.random() < constants.STEALTH_DISTRACTION_CHANCE:
            self._sleep(self._gauss_in(*constants.STEALTH_DISTRACTION_PAUSE_S))

    def _between_page_pause(self) -> float:
        """A read / think / idle pause (Gaussian), scaled by any active backoff.
        Think/idle thresholds are re-randomised each time → no fixed periodicity."""
        self._bursts_until_think -= 1
        self._bursts_until_idle -= 1
        if self._bursts_until_idle <= 0:
            pause = self._gauss_in(*constants.STEALTH_IDLE_PAUSE_S)
            self._bursts_until_idle = self._rng.randint(*constants.STEALTH_IDLE_EVERY_N_BURSTS)
        elif self._bursts_until_think <= 0:
            pause = self._gauss_in(*constants.STEALTH_THINK_PAUSE_S)
            self._bursts_until_think = self._rng.randint(*constants.STEALTH_THINK_EVERY_N_BURSTS)
        else:
            pause = self._gauss_in(*constants.STEALTH_READ_PAUSE_S)
        pause *= self._backoff
        self._backoff = 1.0  # backoff is consumed by the pause it slows
        return pause

    # ── Pacer contract ─────────────────────────────────────────────
    def acquire(self, url: str | None = None) -> None:
        """Block for a human-like interval, then reserve this request's slot.

        §12.50 slice-2 — context-adaptive burst (ADR §12.50 point 2): a request to
        a NEW host is a NAVIGATION (single request, preceded by a read/think/idle
        pause — the user finished the previous page and clicked away). Follow-up
        requests to the SAME host are the browser fetching that page's assets — a
        fast burst. When ``url`` is None (context-less caller) the pacer falls back
        to fixed burst-and-pause. WAFs correlate request-count-per-navigation, so
        this is not cosmetic (anti-Lyndon #11: adapts to context, not a fixed loop).
        """
        host = urlparse(url).hostname if url else None

        if not self._started:
            self._started = True
            self._in_burst = 1
            self._last_host = host
            self._maybe_distraction()
            return

        # NAVIGATION to a new host → a between-page pause, then a single request.
        if host is not None and host != self._last_host:
            self._sleep(self._between_page_pause())
            self._last_host = host
            self._burst_size = self._pick_burst_size()
            self._in_burst = 1
            self._maybe_distraction()
            return

        # SAME host (or unknown) → an asset fetch within the current page.
        if self._in_burst < self._burst_size:
            lo, hi = constants.STEALTH_BURST_INTERVAL_MS
            self._sleep(self._gauss_in(lo / 1000.0, hi / 1000.0))
            self._in_burst += 1
        else:
            # page's asset budget spent → a read pause, then a fresh burst.
            self._sleep(self._between_page_pause())
            self._burst_size = self._pick_burst_size()
            self._in_burst = 1
        self._maybe_distraction()

    def notify(self, status_code: int) -> None:
        """Adaptive backoff hook (HttpClient calls this after each response).

        429/503 (rate-limited / overloaded) → double the next pause AND end the
        current burst early so the very next request pauses. A 2xx resets the
        multiplier. Capped to avoid runaway.
        """
        if status_code in _BACKOFF_STATUSES:
            self._backoff = min(
                self._backoff * constants.STEALTH_BACKOFF_FACTOR,
                constants.STEALTH_BACKOFF_CAP,
            )
            self._in_burst = self._burst_size  # force the next acquire() to pause
        elif 200 <= status_code < 300:
            self._backoff = 1.0
