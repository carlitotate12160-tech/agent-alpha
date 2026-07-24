# tests/phase_2_5/test_alpha_autonomous_reach.py
"""Phase 2.5 — Alpha autonomously reaches past WAF/CDN blocks.

The A1 "reach seal" proved the mechanism via a1_validation_runner (a hardcoded
lab script). These tests prove reach lives in Alpha's AUTONOMOUS cognitive loop
(scout OBSERVE -> _attempt_reach -> re-OBSERVE), NOT in the runner.

Test contract:
  1. test_alpha_autonomous_reach_origin_direct — Alpha.run_recon (the
     autonomous loop) against a CHALLENGE'd target with an authorized origin
     injected -> Alpha classifies mitigation, chooses ORIGIN_DIRECT, fetches
     via origin, and reaches the content. Proves reach in Alpha's loop.
  2. test_alpha_reach_refused_without_authorization — SAME target but NO
     authorized origin -> Alpha does NOT origin-direct; records honest
     WAF-blocked outcome, does not fabricate reach (anti-#3).
  3. test_reach_is_differential — different mitigation classes drive different
     reach strategies (not a fixed pipeline, anti-#11).
  4. test_reach_bounded — Alpha does not loop reach strategies indefinitely
     on a persistently blocked resource.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2_5/test_alpha_autonomous_reach.py -v
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.engagement_profile import EngagementProfile
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire import a1_validation_runner
from agent_alpha.recon.origin_discovery import StaticOriginDiscovery
from agent_alpha.recon.reach_strategy import ReachStrategy
from agent_alpha.recon.transport_resilience import MitigationClass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LAB_HOST = "alpha-ai.web.id"  # in LAB_TARGET_ALLOWLIST
_ORIGIN_IP = "203.0.113.42"
_ENGAGEMENT = "eng-reach-test"

# Challenge body — contains a CHALLENGE_STRONG_MARKER so classify_response
# returns CHALLENGE even at status 200.  At status 403 it returns BLOCKED
# (status code checked before body markers — _BLOCK_STATUS_CODES precedence).
_CHALLENGE_BODY = "<html><body>cf-browser-verification</body></html>"
_BLOCKED_BODY = "<html><body>Forbidden</body></html>"
_OK_BODY = '<html><body><a href="/secret">Secret</a> api_key=AKIA-test-key</body></html>'

# ---------------------------------------------------------------------------
# Minimal test doubles
# ---------------------------------------------------------------------------


class _FakeAuth:
    def can_agent_proceed(self, *_: Any, **__: Any) -> bool:
        return True

    def is_in_scope(self, engagement_id: str, host: str) -> bool:
        return host == _LAB_HOST or host.endswith(f".{_LAB_HOST}")

    def get_state(self, engagement_id: str) -> int:
        from agent_alpha.a2a.a2a_pb2 import RECON_ONLY

        return RECON_ONLY


@dataclass
class _FakeResp:
    text: str
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)


class _FakeHttpClient:
    """Returns a CHALLENGE response for blocked URLs, OK for others."""

    def __init__(
        self,
        challenge_urls: set[str] | None = None,
        ok_body: str = _OK_BODY,
        challenge_all: bool = False,
    ) -> None:
        self._challenge_urls = challenge_urls or set()
        self._ok_body = ok_body
        self._challenge_all = challenge_all
        self.requests: list[str] = []

    def get(self, url: str, **kwargs: Any) -> _FakeResp:
        self.requests.append(url)
        if self._challenge_all or url in self._challenge_urls:
            return _FakeResp(
                text=_CHALLENGE_BODY,
                status_code=200,
                headers={"server": "cloudflare", "cf-ray": "abc123"},
            )
        return _FakeResp(text=self._ok_body, status_code=200, headers={})


@dataclass
class _FakeDecision:
    tool: str = "js_secret_probe"
    tier: str = "rule"
    reasoning: str = "test stub"
    cost_usd: float = 0.0


class _FakeOrchestrator:
    def decide(self, observation: dict[str, Any]) -> _FakeDecision:
        return _FakeDecision()


class _StubOriginDirectResult:
    """Mimics _OriginDirectResult from a1_validation_runner."""

    def __init__(self, body: str, status_code: int = 200) -> None:
        self.body = body
        self.status_code = status_code
        self.headers: dict[str, str] = {}
        self.challenge_encountered = False
        self.challenge_solved = False


class _StubBrowserSolveResult:
    """Mimics BrowserSolveResponse."""

    def __init__(self, body: str, solved: bool = True) -> None:
        self.body = body
        self.status_code = 200
        self.headers: dict[str, str] = {}
        self.cleared_cookies: dict[str, str] = {}
        self.challenge_encountered = True
        self.challenge_solved = solved


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_profile(
    authorized_origins: frozenset[str] | None = None,
    allow_evasion: bool = False,
) -> EngagementProfile:
    return EngagementProfile(
        engagement_id=_ENGAGEMENT,
        client_id="lab",
        targets=frozenset({_LAB_HOST}),
        authorized_origins=authorized_origins or frozenset(),
        allow_evasion=allow_evasion,
    )


def _make_alpha(
    event_store: InMemoryEventStore | None = None,
    origin_discovery: Any = None,
    browser_solve: Any = None,
    engagement_profile: Any = None,
    browser_solve_viable: bool = False,
    challenge_urls: set[str] | None = None,
    ok_body: str = _OK_BODY,
    challenge_all: bool = False,
) -> Alpha:
    """Alpha wired with reach deps, ready for run_recon."""
    store = event_store or InMemoryEventStore()
    http_client = _FakeHttpClient(
        challenge_urls=challenge_urls,
        ok_body=ok_body,
        challenge_all=challenge_all,
    )
    return Alpha(
        authorization=_FakeAuth(),
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=_FakeOrchestrator(),
        http_client=http_client,
        secrets_manager=MagicMock(),
        origin_discovery=origin_discovery,
        browser_solve=browser_solve,
        engagement_profile=engagement_profile,
        browser_solve_viable=browser_solve_viable,
    )


# ---------------------------------------------------------------------------
# Test 1: Alpha autonomously reaches via ORIGIN_DIRECT
# ---------------------------------------------------------------------------


def test_alpha_autonomous_reach_origin_direct(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drive Alpha.run_recon (the autonomous loop, NOT a1_validation_runner)
    against a CHALLENGE'd target with an authorized origin injected.

    Alpha autonomously classifies mitigation, chooses ORIGIN_DIRECT, fetches
    via origin, and reaches the content. Proves reach lives in Alpha's loop.
    """
    front_door = f"https://{_LAB_HOST}"
    store = InMemoryEventStore()

    # Stub origin_direct_fetch to return the real content
    def _fake_origin_fetch(
        host: str, origin_ip: str, path: str = "/", **kw: Any
    ) -> _StubOriginDirectResult:
        return _StubOriginDirectResult(body=_OK_BODY)

    from agent_alpha.recon import reach_transport
    monkeypatch.setattr(reach_transport, "origin_direct_fetch", _fake_origin_fetch)

    profile = _make_profile(authorized_origins=frozenset({_ORIGIN_IP}))
    origin_discovery = StaticOriginDiscovery([_ORIGIN_IP])

    alpha = _make_alpha(
        event_store=store,
        origin_discovery=origin_discovery,
        engagement_profile=profile,
        challenge_urls={front_door},
    )

    # Run the autonomous loop
    alpha.run_recon(_ENGAGEMENT, front_door)

    # Verify ORIGIN_DIRECT_ATTEMPT event was emitted
    events = store.get_events(_ENGAGEMENT)
    event_types = [e.event_type for e in events]
    assert EventType.ORIGIN_DIRECT_ATTEMPT in event_types, (
        "Alpha did not emit ORIGIN_DIRECT_ATTEMPT — reach was not attempted autonomously"
    )

    # Verify the origin-direct event carries the authorized origin
    od_events = [e for e in events if e.event_type == EventType.ORIGIN_DIRECT_ATTEMPT]
    assert od_events[0].payload["origin_ip"] == _ORIGIN_IP
    assert od_events[0].payload["authorized"] is True

    # Verify Alpha reached the content (analyzable_probes > 0 means it got past the block)
    assert alpha._analyzable_probes > 0, (
        "Alpha never reached the content — origin-direct did not flow into OBSERVE"
    )


# ---------------------------------------------------------------------------
# Test 2: Alpha refuses reach without authorization (anti-#3)
# ---------------------------------------------------------------------------


def test_alpha_reach_refused_without_authorization() -> None:
    """SAME CHALLENGE'd target but NO authorized origin / evasion not permitted.

    Alpha does NOT origin-direct; it records an honest WAF-blocked outcome
    and does not fabricate reach (anti-#3).
    """
    front_door = f"https://{_LAB_HOST}"
    store = InMemoryEventStore()

    # No authorized origins, no evasion
    profile = _make_profile(authorized_origins=frozenset(), allow_evasion=False)
    origin_discovery = StaticOriginDiscovery([_ORIGIN_IP])

    alpha = _make_alpha(
        event_store=store,
        origin_discovery=origin_discovery,
        engagement_profile=profile,
        challenge_all=True,
    )

    # Run the autonomous loop
    alpha.run_recon(_ENGAGEMENT, front_door)

    events = store.get_events(_ENGAGEMENT)
    event_types = [e.event_type for e in events]

    # Must NOT have origin-direct attempt
    assert EventType.ORIGIN_DIRECT_ATTEMPT not in event_types, (
        "Alpha attempted origin-direct WITHOUT authorization — capability gate failed"
    )

    # Must have WAF_BLOCKED (honest outcome)
    assert EventType.WAF_BLOCKED in event_types, (
        "Alpha did not record WAF_BLOCKED — the honest block was not recorded (anti-#3)"
    )

    # Alpha never reached the content (all URLs challenged, no reach)
    assert alpha._analyzable_probes == 0, (
        "Alpha recorded analyzable probes despite no authorized reach — reach was fabricated"
    )


# ---------------------------------------------------------------------------
# Test 3: Reach is differential (mitigation class drives strategy)
# ---------------------------------------------------------------------------


def test_reach_is_differential() -> None:
    """Different mitigation classes drive different reach strategies.

    CHALLENGE + browser_solve_viable + allow_evasion -> EVASION
    CHALLENGE + no viable solve + authorized origin -> ORIGIN_DIRECT
    FINGERPRINT (403) + authorized origin -> ORIGIN_DIRECT
    No mitigation -> DIRECT (no reach needed)
    """
    # We test the decision function directly since _attempt_reach uses it.
    from agent_alpha.recon.reach_strategy import choose_reach

    # CHALLENGE + viable -> EVASION
    assert (
        choose_reach(
            MitigationClass.CHALLENGE,
            browser_solve_viable=True,
            authorized_origin=None,
        )
        is ReachStrategy.EVASION
    )

    # CHALLENGE + not viable + origin -> ORIGIN_DIRECT
    assert (
        choose_reach(
            MitigationClass.CHALLENGE,
            browser_solve_viable=False,
            authorized_origin=_ORIGIN_IP,
        )
        is ReachStrategy.ORIGIN_DIRECT
    )

    # FINGERPRINT + origin -> ORIGIN_DIRECT
    assert (
        choose_reach(
            MitigationClass.FINGERPRINT,
            browser_solve_viable=False,
            authorized_origin=_ORIGIN_IP,
        )
        is ReachStrategy.ORIGIN_DIRECT
    )

    # No mitigation -> DIRECT
    assert (
        choose_reach(
            None,
            browser_solve_viable=False,
            authorized_origin=None,
        )
        is ReachStrategy.DIRECT
    )

    # CHALLENGE + not viable + no origin -> DIRECT (honest block)
    assert (
        choose_reach(
            MitigationClass.CHALLENGE,
            browser_solve_viable=False,
            authorized_origin=None,
        )
        is ReachStrategy.DIRECT
    )


# ---------------------------------------------------------------------------
# Test 4: Reach is bounded (no infinite loop)
# ---------------------------------------------------------------------------


def test_reach_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Alpha does not loop reach strategies indefinitely on a persistently
    blocked resource.

    Setup: origin-direct returns a CHALLENGE body too (still blocked after
    reach). Alpha should attempt reach at most once per URL, then record
    WAF_BLOCKED and continue — not loop forever.
    """
    front_door = f"https://{_LAB_HOST}"
    store = InMemoryEventStore()

    calls_per_url: dict[str, int] = {}

    def _fake_origin_fetch(
        host: str, origin_ip: str, path: str = "/", **kw: Any
    ) -> _StubOriginDirectResult:
        url_key = f"{host}{path}"
        calls_per_url[url_key] = calls_per_url.get(url_key, 0) + 1
        # Return a challenge body — still blocked after origin-direct
        return _StubOriginDirectResult(body=_CHALLENGE_BODY, status_code=403)

    from agent_alpha.recon import reach_transport
    monkeypatch.setattr(reach_transport, "origin_direct_fetch", _fake_origin_fetch)

    profile = _make_profile(authorized_origins=frozenset({_ORIGIN_IP}))
    origin_discovery = StaticOriginDiscovery([_ORIGIN_IP])

    alpha = _make_alpha(
        event_store=store,
        origin_discovery=origin_discovery,
        engagement_profile=profile,
        challenge_all=True,
    )

    # Run the autonomous loop — must terminate (not hang)
    alpha.run_recon(_ENGAGEMENT, front_door)

    # Each URL should get at most 1 reach attempt (bounded per resource)
    repeated = {url: n for url, n in calls_per_url.items() if n > 1}
    assert not repeated, (
        f"origin_direct_fetch called >1 times for these URLs — reach is not bounded "
        f"(should be at most 1 attempt per blocked resource): {repeated}"
    )

    # WAF_BLOCKED must be recorded (honest outcome after reach failed)
    events = store.get_events(_ENGAGEMENT)
    event_types = [e.event_type for e in events]
    assert EventType.WAF_BLOCKED in event_types, (
        "Alpha did not record WAF_BLOCKED after reach failed — honest block missing"
    )

    # Alpha never reached the content (still blocked after reach attempt)
    assert alpha._analyzable_probes == 0, (
        "Alpha recorded analyzable probes despite persistent block — reach was fabricated"
    )
