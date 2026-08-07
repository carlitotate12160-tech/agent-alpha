# tests/phase_2/test_stealth_pacer.py
"""§12.50 StealthPacer — human burst-and-pause pacing + adaptive backoff.

Deterministic: sleeps are captured (never real wall-clock), and either a seeded
Random (shape tests) or a fully-controlled fake RNG (exact backoff tests) drives
the pacer.
"""

from __future__ import annotations

import pytest

from agent_alpha.agents.stealth_pacer import StealthPacer
from agent_alpha.config import constants


class _Rec:
    """Records every sleep duration instead of blocking."""

    def __init__(self) -> None:
        self.sleeps: list[float] = []

    def __call__(self, d: float) -> None:
        self.sleeps.append(d)


class _FakeRng:
    """Deterministic RNG: gauss → mean, randint → low, random → 1.0 (no distraction)."""

    def randint(self, a: int, b: int) -> int:
        return a

    def gauss(self, mean: float, std: float) -> float:
        return mean

    def random(self) -> float:
        return 1.0  # >= STEALTH_DISTRACTION_CHANCE → never distract


# ── shape (seeded real RNG) ─────────────────────────────────────────


def test_multimodal_shape_short_bursts_and_long_pauses() -> None:
    rec = _Rec()
    pacer = StealthPacer(seed=12345, sleep=rec)
    for _ in range(12):
        pacer.acquire()
    assert rec.sleeps, "pacer never slept"
    short = [d for d in rec.sleeps if d < 1.0]  # intra-burst gaps
    long = [d for d in rec.sleeps if d >= 1.0]  # between-burst pauses
    assert short, "no short intra-burst gaps — burst not modelled"
    assert long, "no long between-burst pause — pacing not human"


def test_first_request_is_not_delayed_by_a_pause() -> None:
    rec = _Rec()
    pacer = StealthPacer(rng=_FakeRng(), sleep=rec)
    pacer.acquire()  # very first request
    # no read/think/idle pause on the first request (fake rng → no distraction)
    assert rec.sleeps == [], "first request incurred a pause — should start immediately"


# ── exact structure (fake RNG) ──────────────────────────────────────


def test_burst_then_read_pause_exact() -> None:
    rec = _Rec()
    pacer = StealthPacer(rng=_FakeRng(), sleep=rec)
    burst = constants.STEALTH_BURST_MIN  # fake randint → low
    gap = sum(constants.STEALTH_BURST_INTERVAL_MS) / 2 / 1000.0  # midpoint, ms→s
    read = sum(constants.STEALTH_READ_PAUSE_S) / 2  # midpoint

    for _ in range(burst):  # complete one burst
        pacer.acquire()
    assert rec.sleeps == [gap] * (burst - 1), "intra-burst gaps wrong"

    pacer.acquire()  # burst full → a read pause
    assert rec.sleeps[-1] == pytest.approx(read), "between-burst pause not a read pause"


# ── backoff ─────────────────────────────────────────────────────────


def test_notify_429_doubles_next_pause_and_ends_burst() -> None:
    rec = _Rec()
    pacer = StealthPacer(rng=_FakeRng(), sleep=rec)
    read = sum(constants.STEALTH_READ_PAUSE_S) / 2

    pacer.acquire()  # first (no sleep)
    pacer.acquire()  # burst gap
    pacer.notify(429)  # backoff ×2 + force burst end
    pacer.acquire()  # next request → a doubled pause immediately
    assert rec.sleeps[-1] == pytest.approx(read * constants.STEALTH_BACKOFF_FACTOR)


def test_backoff_is_consumed_then_resets() -> None:
    rec = _Rec()
    pacer = StealthPacer(rng=_FakeRng(), sleep=rec)
    read = sum(constants.STEALTH_READ_PAUSE_S) / 2

    pacer.acquire()
    pacer.notify(429)
    pacer.acquire()  # doubled pause
    pacer.acquire()  # burst gap after the forced pause
    pacer.acquire()
    # after the doubled pause was consumed, the NEXT between-burst pause is normal
    burst = constants.STEALTH_BURST_MIN
    for _ in range(burst):
        pacer.acquire()
    normal_pauses = [d for d in rec.sleeps if d == pytest.approx(read)]
    assert normal_pauses, "backoff not consumed — pauses never returned to baseline"


def test_notify_2xx_resets_backoff() -> None:
    rec = _Rec()
    pacer = StealthPacer(rng=_FakeRng(), sleep=rec)
    read = sum(constants.STEALTH_READ_PAUSE_S) / 2

    pacer.acquire()
    pacer.notify(429)
    pacer.notify(200)  # success clears the backoff before it is applied
    pacer.notify(429)  # one 429 again → single doubling
    pacer.acquire()
    assert rec.sleeps[-1] == pytest.approx(read * constants.STEALTH_BACKOFF_FACTOR)


def test_backoff_capped() -> None:
    pacer = StealthPacer(rng=_FakeRng(), sleep=_Rec())
    for _ in range(20):
        pacer.notify(503)
    assert pacer._backoff <= constants.STEALTH_BACKOFF_CAP


def test_distraction_fires_on_low_random() -> None:
    class _DistractRng(_FakeRng):
        def random(self) -> float:
            return 0.0  # < STEALTH_DISTRACTION_CHANCE → always distract

    rec = _Rec()
    pacer = StealthPacer(rng=_DistractRng(), sleep=rec)
    pacer.acquire()  # first request + distraction pause
    distract_mid = sum(constants.STEALTH_DISTRACTION_PAUSE_S) / 2
    assert any(d == pytest.approx(distract_mid) for d in rec.sleeps), "distraction never fired"
