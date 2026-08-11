# tests/phase_4/test_soft404_calibration.py
# GAP-044 — Soft-404 (catch-all) suppression — Tier-1 contract tests.
# Reuses the GAP-029 _build_alpha/_StubProvider harness.
#   * test_no_catch_all_not_calibrated — CARDINAL (fail-safe): a host that PROPERLY
#     404s a random path stores NO signature -> real content is never suppressed.
# Run on Oracle ARM64 / .venv312.
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from agent_alpha.events.event_types import EventType
from tests.phase_4.test_dead_host_skip import FakeResponse, _StubProvider, _build_alpha

_HOST = "catchall.example"
_PAD = "X" * 93800  # match the ingco 93858-byte catch-all shape


class CatchAllHttpClient:
    """UNKNOWN paths all return 200 + a generic error page echoing the requested path
    (reflected). Designated `real` paths return distinct 200 content. proper_404=True
    models a NORMAL host (missing path -> 404) for the fail-safe cardinal test."""

    def __init__(self, real: dict[str, FakeResponse] | None = None,
                 proper_404: bool = False) -> None:
        self.real = real or {}
        self.proper_404 = proper_404
        self.calls: list[str] = []

    def get(self, url: str, **kw: Any) -> FakeResponse:
        self.calls.append(url)
        path = urlparse(url).path
        if path in self.real:
            return self.real[path]
        if self.proper_404:
            return FakeResponse(404, f"<html>404 {path}</html>", {})
        return FakeResponse(200, f"<html>ERROR: {path} not found</html>{_PAD}",
                            {"content-type": "text/html"})


def _soft404_events(store, eid):
    return [
        e for e in store.get_events(eid)
        if e.event_type == EventType.PASSIVE_DISCOVERY
        and getattr(e, "payload", {}).get("reason") == "soft_404_catch_all"
    ]


def test_catch_all_calibrated_and_suppressed() -> None:
    real = {"/": FakeResponse(200, "<html>real homepage, distinct body</html>", {})}
    http = CatchAllHttpClient(real=real)
    alpha, eid, store = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    alpha.run_recon(eid, f"https://{_HOST}/")
    assert _HOST in alpha._soft404_sig, "catch-all host must be calibrated"
    assert _soft404_events(store, eid), "seeded soft-404 paths must be suppressed + audited"


def test_no_catch_all_not_calibrated() -> None:
    """CARDINAL fail-safe: a proper-404 host stores NO signature."""
    real = {"/": FakeResponse(200, "<html>real homepage</html>", {})}
    http = CatchAllHttpClient(real=real, proper_404=True)
    alpha, eid, store = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    alpha.run_recon(eid, f"https://{_HOST}/")
    assert _HOST not in alpha._soft404_sig
    assert _soft404_events(store, eid) == []


def test_real_page_not_suppressed_on_catch_all_host() -> None:
    real = {"/": FakeResponse(200, "<html>UNIQUE real content 12345</html>", {})}
    http = CatchAllHttpClient(real=real)
    alpha, eid, _ = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    alpha.run_recon(eid, f"https://{_HOST}/")
    home = FakeResponse(200, "<html>UNIQUE real content 12345</html>", {})
    assert alpha._is_soft404(_HOST, f"https://{_HOST}/", home) is False


def test_calibration_probe_is_once_per_host() -> None:
    real = {"/": FakeResponse(200, "<html>home</html>", {})}
    http = CatchAllHttpClient(real=real)
    alpha, eid, _ = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    probe_seg = alpha._soft404_probe_path(_HOST)
    alpha.run_recon(eid, f"https://{_HOST}/")
    assert len([u for u in http.calls if probe_seg in u]) == 1
