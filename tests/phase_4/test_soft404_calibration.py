# tests/phase_4/test_soft404_calibration.py
# GAP-044 + GAP-048 — soft-404 catch-all suppression via two-probe DIFFERENTIAL
# calibration (format-agnostic). Reuses the GAP-029 _build_alpha/_StubProvider harness.
#   * test_no_catch_all_not_calibrated — CARDINAL fail-safe.
#   * test_real_page_not_suppressed_on_catch_all_host — CARDINAL false-negative guard
#     (real content on a CALIBRATED catch-all host must NOT be suppressed).
# GAP-028 — origin-aware soft-404 calibration (transport parity).
#   * test_origin_direct_calibrates_via_origin — CARDINAL RED.
#   * test_origin_direct_real_content_not_suppressed — anti-false-negative guard.
#   * test_origin_probe_failure_no_signature — fail-safe.
#   * test_origin_direct_calls_origin_probe_not_http_client — wiring.
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
    """Two probes return DIFFERENT token structures (hex then UUID) -> unstable token
    count -> fail-safe: NO signature stored. Exercises the len(t1) != len(t2) branch.

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
    different token counts -> no signature stored -> real content never suppressed.
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
    # different non-volatile values -> masked hash MUST differ.
    ntok, volatile, _ = alpha._soft404_sig[_HOST]
    fake_token = "deadbeef" * 4  # 32-hex, same length as catch-all token
    same_struct_body = (
        f'<meta name="csrf" content="{fake_token}">'
        f"<title>500 /test server error</title>{_PAD}"
    )
    fake_resp = FakeResponse(200, same_struct_body, {"content-type": "text/html"})
    assert alpha._is_soft404(_HOST, f"https://{_HOST}/test", fake_resp) is False


# =============================================================================
# GAP-028 — origin-aware soft-404 calibration (transport parity)
#
# When a host is origin-bound (_bound_origin[host] non-empty), calibration
# probes go through origin_direct_probe (same transport as the real probe),
# not the front-door http_client.get (which is WAF-blocked -> no signature).
#
# Tests exercise _calibrate_soft404 directly (after _reset_target_state +
# manual _bound_origin injection), because run_recon resets _bound_origin
# and the full origin-discovery plumbing is not needed to verify the
# transport-selection logic in _calibration_fetch.
# =============================================================================

_ORIGIN_HOST = "spa-origin.example"
_ORIGIN_IP = "10.0.0.1"
_ORIGIN_PAD = "X" * 4000


def _spa_body(path: str, token: str) -> str:
    """Build a SPA catch-all body echoing the path + per-request token."""
    return (
        f'<meta name="csrf" content="{token}">'
        f"<title>404 {path} not found</title>{_ORIGIN_PAD}"
    )


def _build_origin_alpha():
    """Build an Alpha with _bound_origin manually set for the origin-direct path.

    Returns (alpha, eid, store). The caller must patch origin_direct_probe at
    'agent_alpha.agents.alpha.scout.origin_direct_probe' before calling
    _calibrate_soft404.
    """
    http = CatchAllHttpClient(real={"/": FakeResponse(200, "<html>home</html>", {})})
    alpha, eid, store = _build_alpha(http, domains=[_ORIGIN_HOST], provider=_StubProvider())
    # _reset_target_state sets _engagement_id (needed by _soft404_probe_path) and
    # clears per-target state. We set _bound_origin AFTER this reset.
    alpha._reset_target_state(eid, f"https://{_ORIGIN_HOST}/")
    alpha._bound_origin[_ORIGIN_HOST] = [_ORIGIN_IP]
    return alpha, eid, store


def test_origin_direct_calibrates_via_origin() -> None:
    """CARDINAL RED (GAP-028): origin-direct host, front door WAF-blocked, origin
    returns the SAME SPA for two random missing paths -> _soft404_sig[host] IS stored
    (origin baseline) and _is_soft404 returns True on a third SPA-junk response.

    BEFORE fix: http_client.get -> HttpClientError -> no signature -> _is_soft404 False.
    """
    from unittest.mock import MagicMock, patch

    from agent_alpha.recon.origin_reach import _ReachResponse

    alpha, _eid, _store = _build_origin_alpha()

    call_counter = itertools.count()

    def _fake_origin_probe(alpha_obj, url, host, origins_list):
        n = next(call_counter)
        return _ReachResponse(
            status_code=200,
            body=_spa_body(urlparse(url).path, f"{n:032x}"),
            headers={"content-type": "text/html"},
        )

    mock_probe = MagicMock(side_effect=_fake_origin_probe)

    with patch("agent_alpha.agents.alpha.scout.origin_direct_probe", mock_probe):
        alpha._calibrate_soft404(_ORIGIN_HOST, urlparse(f"https://{_ORIGIN_HOST}/"))

    # Signature MUST be stored (origin-direct calibration worked).
    assert _ORIGIN_HOST in alpha._soft404_sig, (
        f"GAP-028: _soft404_sig should contain {_ORIGIN_HOST} after origin-direct "
        f"calibration; got keys={list(alpha._soft404_sig.keys())}"
    )

    # A third SPA-junk body MUST match the signature (suppressed).
    junk_resp = _ReachResponse(
        status_code=200,
        body=_spa_body("/junk-path", "aaaa" * 8),
        headers={"content-type": "text/html"},
    )
    assert alpha._is_soft404(
        _ORIGIN_HOST, f"https://{_ORIGIN_HOST}/junk-path", junk_resp
    ) is True


def test_origin_direct_real_content_not_suppressed() -> None:
    """Anti-false-negative guard (GAP-028): a planted origin response that DIFFERS
    from the SPA skeleton (a real /.git/config body) -> _is_soft404 returns False
    (distinguishable, not over-suppressed)."""
    from unittest.mock import MagicMock, patch

    from agent_alpha.recon.origin_reach import _ReachResponse

    alpha, _eid, _store = _build_origin_alpha()

    call_counter = itertools.count()

    def _fake_origin_probe(alpha_obj, url, host, origins_list):
        n = next(call_counter)
        return _ReachResponse(
            status_code=200,
            body=_spa_body(urlparse(url).path, f"{n:032x}"),
            headers={"content-type": "text/html"},
        )

    mock_probe = MagicMock(side_effect=_fake_origin_probe)

    with patch("agent_alpha.agents.alpha.scout.origin_direct_probe", mock_probe):
        alpha._calibrate_soft404(_ORIGIN_HOST, urlparse(f"https://{_ORIGIN_HOST}/"))

    assert _ORIGIN_HOST in alpha._soft404_sig

    # A REAL body with completely different structure must NOT be suppressed.
    real_body = (
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
    )
    real_resp = _ReachResponse(
        status_code=200,
        body=real_body,
        headers={"content-type": "text/plain"},
    )
    assert (
        alpha._is_soft404(
            _ORIGIN_HOST, f"https://{_ORIGIN_HOST}/.git/config", real_resp
        )
        is False
    )


def test_origin_probe_failure_no_signature() -> None:
    """Fail-safe (GAP-028): origin_direct_probe returns None (block) for calibration
    probes -> NO signature stored, _is_soft404 stays False (no crash, no false
    suppression)."""
    from unittest.mock import MagicMock, patch

    from agent_alpha.recon.origin_reach import _ReachResponse

    alpha, _eid, _store = _build_origin_alpha()

    # origin_direct_probe returns None (blocked / no useful response).
    mock_probe = MagicMock(return_value=None)

    with patch("agent_alpha.agents.alpha.scout.origin_direct_probe", mock_probe):
        alpha._calibrate_soft404(_ORIGIN_HOST, urlparse(f"https://{_ORIGIN_HOST}/"))

    # No signature stored (fail-closed).
    assert _ORIGIN_HOST not in alpha._soft404_sig, (
        "Fail-safe: origin_direct_probe returning None should NOT store a signature"
    )
    # _is_soft404 must return False (no suppression).
    junk = _ReachResponse(status_code=200, body="anything", headers={})
    assert alpha._is_soft404(_ORIGIN_HOST, f"https://{_ORIGIN_HOST}/x", junk) is False


def test_origin_direct_calls_origin_probe_not_http_client() -> None:
    """Wiring (GAP-028): the origin-direct branch calls origin_direct_probe with
    _bound_origin[host] (not http_client.get) — proves transport parity on the live
    path (anti-island)."""
    from unittest.mock import MagicMock, patch

    from agent_alpha.recon.origin_reach import _ReachResponse

    alpha, _eid, _store = _build_origin_alpha()

    call_counter = itertools.count()

    def _fake_origin_probe(alpha_obj, url, host, origins_list):
        n = next(call_counter)
        return _ReachResponse(
            status_code=200,
            body=_spa_body(urlparse(url).path, f"{n:032x}"),
            headers={"content-type": "text/html"},
        )

    mock_probe = MagicMock(side_effect=_fake_origin_probe)

    # Record http_client.get calls to verify NO calibration probe goes front-door.
    http_calls_before = len(alpha.http_client.calls)

    with patch("agent_alpha.agents.alpha.scout.origin_direct_probe", mock_probe):
        alpha._calibrate_soft404(_ORIGIN_HOST, urlparse(f"https://{_ORIGIN_HOST}/"))

    # origin_direct_probe MUST have been called exactly twice (2 calibration probes).
    assert mock_probe.call_count == 2, (
        f"origin_direct_probe should be called exactly twice (2 calibration probes); "
        f"got {mock_probe.call_count} calls"
    )
    # Every call must pass the bound origin list.
    for call in mock_probe.call_args_list:
        args = call[0]
        assert args[3] == [_ORIGIN_IP], (
            f"origin_direct_probe called with origins={args[3]}, expected [{_ORIGIN_IP}]"
        )

    # http_client.get must NOT have been called for calibration probes.
    http_calls_after = len(alpha.http_client.calls)
    assert http_calls_after == http_calls_before, (
        f"http_client.get was called {http_calls_after - http_calls_before} times during "
        f"calibration (transport parity broken — should use origin_direct_probe)"
    )
