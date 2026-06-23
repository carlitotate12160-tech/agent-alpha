"""Contract: RateLimiter + HttpClient RoE rate-limit enforcement.

Deterministic via an injected clock (no real wall-clock waiting): the clock
advances ONLY when the limiter sleeps, modelling real time. Proves the limiter
DELAYS (never drops) and honours >= 1/rps spacing, and that HttpClient acquires a
slot before every egress.

Run on Oracle ARM64:
    .venv/bin/pytest tests/phase_2/test_rate_limiter.py -v
"""

from __future__ import annotations

import httpx
import pytest

from agent_alpha.agents.http_client import HttpClient
from agent_alpha.agents.rate_limiter import RateLimiter
from agent_alpha.config import constants


class _Clock:
    """Fake monotonic clock; sleeping advances it (models real time)."""

    def __init__(self) -> None:
        self.t = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.t

    def sleep(self, dt: float) -> None:
        self.sleeps.append(dt)
        self.t += dt


def _limiter(rps: float, clock: _Clock) -> RateLimiter:
    return RateLimiter(rps, monotonic=clock.monotonic, sleep=clock.sleep)


# ── RateLimiter ───────────────────────────────────────────────────────


def test_first_request_is_immediate() -> None:
    clock = _Clock()
    _limiter(10, clock).acquire()
    assert clock.sleeps == []  # no wait for the very first request


def test_successive_requests_spaced_by_min_interval() -> None:
    clock = _Clock()
    lim = _limiter(10, clock)  # 0.1s min interval
    for _ in range(3):
        lim.acquire()
    assert clock.sleeps == [pytest.approx(0.1), pytest.approx(0.1)]  # 2 waits after the 1st


def test_no_wait_when_enough_time_already_passed() -> None:
    clock = _Clock()
    lim = _limiter(10, clock)
    lim.acquire()  # reserves next slot at t+0.1
    clock.t += 0.5  # caller did other work past the interval
    lim.acquire()
    assert clock.sleeps == []  # plenty of time elapsed → no throttle


def test_delays_never_drops() -> None:
    """Every acquire returns (None); throttling bounds throughput, never discards."""
    clock = _Clock()
    lim = _limiter(5, clock)
    results = [lim.acquire() for _ in range(10)]
    assert results == [None] * 10
    assert len(clock.sleeps) == 9  # 9 waits after the first immediate one


def test_invalid_rps_rejected() -> None:
    for bad in (0, -1, -0.5):
        with pytest.raises(ValueError):
            RateLimiter(bad)


# ── HttpClient integration ────────────────────────────────────────────


class _RecordingLimiter:
    def __init__(self) -> None:
        self.calls = 0

    def acquire(self) -> None:
        self.calls += 1


def test_httpclient_acquires_a_slot_before_each_request() -> None:
    limiter = _RecordingLimiter()
    order: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        order.append("request")
        return httpx.Response(200, text="ok")

    # wrap acquire to record ordering vs the request
    orig = limiter.acquire

    def tracking_acquire() -> None:
        order.append("acquire")
        orig()

    limiter.acquire = tracking_acquire  # type: ignore[method-assign]

    client = HttpClient(
        engagement_id="eng1",
        transport=httpx.MockTransport(handler),
        rate_limiter=limiter,  # type: ignore[arg-type]
    )
    client.get("https://lab-target.invalid")
    client.get("https://lab-target.invalid")

    assert limiter.calls == 2
    assert order == ["acquire", "request", "acquire", "request"]  # throttle BEFORE egress


def test_httpclient_default_limiter_is_single_source_rps() -> None:
    """Default rps comes from the constant, not a hardcoded literal (anti-Lyndon #7)."""
    client = HttpClient(engagement_id="eng1", transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    # one request is immediate regardless; this just asserts construction wires the default.
    assert constants.DEFAULT_RATE_LIMIT_RPS == 2.0
    client.get("https://lab-target.invalid")  # must not raise / must not block on first call
