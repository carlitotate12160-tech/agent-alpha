# tests/phase_4/test_soft404_calibration.py
# GAP-044 + GAP-048 — soft-404 catch-all suppression via two-probe DIFFERENTIAL
# calibration (format-agnostic). Reuses the GAP-029 _build_alpha/_StubProvider harness.
#   * test_no_catch_all_not_calibrated — CARDINAL fail-safe.
#   * test_real_page_not_suppressed_on_catch_all_host — CARDINAL false-negative guard
#     (real content on a CALIBRATED catch-all host must NOT be suppressed).
# Run on Oracle ARM64 / .venv312.
from __future__ import annotations

import itertools
from typing import Any
from urllib.parse import urlparse

from agent_alpha.events.event_types import EventType
from tests.phase_4.test_dead_host_skip import FakeResponse, _StubProvider, _build_alpha

_HOST = "catchall.example"
_PAD = "X" * 4000


class CatchAllHttpClient:
    """UNKNOWN paths return 200 + a catch-all echoing the path AND carrying a per-request
    token (varies every call — simulates CSRF/session so the two-probe diff has volatile
    positions to find). `real` paths return distinct content. proper_404=True models a
    normal host (missing -> 404) for the fail-safe cardinal test."""

    def __init__(self, real: dict[str, FakeResponse] | None = None,
                 proper_404: bool = False, token_fmt: str = "hex") -> None:
        self.real = real or {}
        self.proper_404 = proper_404
        self.token_fmt = token_fmt
        self._ctr = itertools.count()
        self.calls: list[str] = []

    def _token(self) -> str:
        n = next(self._ctr)
        if self.token_fmt == "uuid":
            h = f"{n:032x}"
            return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
        return f"{n:032x}"  # 32-hex

    def get(self, url: str, **kw: Any) -> FakeResponse:
        self.calls.append(url)
        path = urlparse(url).path
        if path in self.real:
            return self.real[path]
        if self.proper_404:
            return FakeResponse(404, f"<html>404 {path}</html>", {})
        body = (f'<meta name="csrf" content="{self._token()}">'
                f"<title>404 {path} not found</title>{_PAD}")
        return FakeResponse(200, body, {"content-type": "text/html"})


def _soft404_events(store, eid):
    return [e for e in store.get_events(eid)
            if e.event_type == EventType.PASSIVE_DISCOVERY
            and getattr(e, "payload", {}).get("reason") == "soft_404_catch_all"]


def test_catch_all_calibrated_and_suppressed_hex() -> None:
    real = {"/": FakeResponse(200, "<html>real homepage, distinct</html>", {})}
    http = CatchAllHttpClient(real=real, token_fmt="hex")
    alpha, eid, store = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    alpha.run_recon(eid, f"https://{_HOST}/")
    assert _HOST in alpha._soft404_sig
    assert _soft404_events(store, eid)


def test_catch_all_suppressed_uuid_format() -> None:
    """Format-agnostic: a UUID token (dashes — the regex whack-a-mole missed this) is
    still neutralised by the differential diff."""
    real = {"/": FakeResponse(200, "<html>real homepage, distinct</html>", {})}
    http = CatchAllHttpClient(real=real, token_fmt="uuid")
    alpha, eid, store = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    alpha.run_recon(eid, f"https://{_HOST}/")
    assert _HOST in alpha._soft404_sig
    assert _soft404_events(store, eid)


def test_no_catch_all_not_calibrated() -> None:
    """CARDINAL fail-safe: a proper-404 host stores NO signature."""
    real = {"/": FakeResponse(200, "<html>real homepage</html>", {})}
    http = CatchAllHttpClient(real=real, proper_404=True)
    alpha, eid, store = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    alpha.run_recon(eid, f"https://{_HOST}/")
    assert _HOST not in alpha._soft404_sig
    assert _soft404_events(store, eid) == []


def test_real_page_not_suppressed_on_catch_all_host() -> None:
    """CARDINAL false-negative guard: a REAL page on a CALIBRATED catch-all host must NOT
    be suppressed. The calibrated signature exists (host IS catch-all), but a page with
    distinct content must fail the match — either different token count (structural
    mismatch) or different masked hash (skeleton mismatch). Without this test, a future
    regression where masked-hash collision suppresses real content goes undetected (anti-#3)."""
    real = {"/": FakeResponse(200, "<html>UNIQUE real content 12345</html>", {})}
    http = CatchAllHttpClient(real=real)
    alpha, eid, _ = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    alpha.run_recon(eid, f"https://{_HOST}/")
    # Host IS calibrated (catch-all active)...
    assert _HOST in alpha._soft404_sig
    # ...but the real homepage must NOT be suppressed.
    home = FakeResponse(200, "<html>UNIQUE real content 12345</html>", {})
    assert alpha._is_soft404(_HOST, f"https://{_HOST}/", home) is False


def test_two_probes_per_host() -> None:
    """Differential calibration issues exactly TWO deterministic probes per host."""
    real = {"/": FakeResponse(200, "<html>home</html>", {})}
    http = CatchAllHttpClient(real=real)
    alpha, eid, _ = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    alpha.run_recon(eid, f"https://{_HOST}/")
    # Compute segs AFTER run_recon — _engagement_id is set during run_recon,
    # so probe paths computed before would differ from the actual probes used.
    segs = {alpha._soft404_probe_path(_HOST, "a"), alpha._soft404_probe_path(_HOST, "b")}
    hits = [u for u in http.calls if any(seg in u for seg in segs)]
    assert len(hits) == 2, hits


class _UnstableTokenClient:
    """Two probes return DIFFERENT token structures (hex then UUID) → unstable token
    count → fail-safe: NO signature stored. Exercises the len(t1) != len(t2) branch.

    The first unknown-path GET returns a hex token (no dashes); the second returns a
    UUID token (with dashes). Since the homepage is fetched BEFORE calibration, we
    use a call counter that starts at the first CATCH-ALL response (not the homepage)."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self._catchall_ctr = itertools.count()

    def get(self, url: str, **kw: Any) -> FakeResponse:
        self.calls.append(url)
        path = urlparse(url).path
        # Homepage (path="/") gets a stable hex token — it's not a probe.
        if path == "/":
            return FakeResponse(200, "<html>real homepage</html>", {})
        n = next(self._catchall_ctr)
        if n == 0:
            token = f"{n:032x}"  # hex (no dashes) — probe a
        else:
            h = f"{n:032x}"
            token = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"  # UUID — probe b
        body = f'<meta name="csrf" content="{token}"><title>404 {path}</title>{_PAD}'
        return FakeResponse(200, body, {"content-type": "text/html"})


def test_unstable_token_count_stores_no_signature() -> None:
    """Fail-safe: two probes with DIFFERENT token structures (hex vs UUID) produce
    different token counts → no signature stored → real content never suppressed.
    Exercises the len(t1) != len(t2) early-return branch in _calibrate_soft404."""
    http = _UnstableTokenClient()
    alpha, eid, store = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    alpha.run_recon(eid, f"https://{_HOST}/")
    assert _HOST not in alpha._soft404_sig
    assert _soft404_events(store, eid) == []


def test_same_token_count_different_skeleton_not_suppressed() -> None:
    """CARDINAL false-negative guard (same-structure variant): a body with the SAME
    token count as the catch-all but DIFFERENT non-volatile content must NOT be
    suppressed. The masked hash must differ because the skeleton differs — not just
    because the structure differs. Without this, a masked-hash collision that
    suppresses structurally-similar real content goes undetected (anti-#3)."""
    # Build a catch-all host, then construct a same-token-count body with different
    # non-volatile content and assert _is_soft404 returns False.
    real = {"/": FakeResponse(200, "<html>real homepage, distinct</html>", {})}
    http = CatchAllHttpClient(real=real, token_fmt="hex")
    alpha, eid, _ = _build_alpha(http, domains=[_HOST], provider=_StubProvider())
    alpha.run_recon(eid, f"https://{_HOST}/")
    assert _HOST in alpha._soft404_sig

    # Construct a body with the SAME structural shape (same token count) but different
    # non-volatile content. The catch-all body is:
    #   <meta name="csrf" content="<32hex>"><title>404 /<path> not found</title><PAD>
    # Replace "404" with "500" and "not found" with "server error" — same token count,
    # different non-volatile values → masked hash MUST differ.
    ntok, volatile, _ = alpha._soft404_sig[_HOST]
    fake_token = "deadbeef" * 4  # 32-hex, same length as catch-all token
    same_struct_body = (
        f'<meta name="csrf" content="{fake_token}">'
        f"<title>500 /test server error</title>{_PAD}"
    )
    fake_resp = FakeResponse(200, same_struct_body, {"content-type": "text/html"})
    assert alpha._is_soft404(_HOST, f"https://{_HOST}/test", fake_resp) is False
