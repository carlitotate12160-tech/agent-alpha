# ADR §12.27 slice — Cloudflare/WAF CHALLENGE verdict must skip RULE and LLM tiers.
#
# A 200 response whose body is a CDN/WAF interstitial (Cloudflare "Just a moment...",
# cf-browser-verification, challenge-platform, Turnstile) must be classified as
# Verdict.CHALLENGE. Like Verdict.UNSUPPORTED_MEDIA_TYPE it is non-analyzable:
# no token burn, no frontier expansion, no asset persist, but a WAF/CF audit
# event IS recorded.
#
# Mirrors the harness of test_empty_body_header_signal.py:
# real PlaybookEngine + real LLMOrchestrator + stub provider that counts calls.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_cf_challenge_no_llm.py -v

from __future__ import annotations

import dataclasses
import pathlib
from typing import Any

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.recon.response_classifier import Verdict, classify_response
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")
_FIXTURE_DIR = pathlib.Path("tests/fixtures/cassettes")
_HOST = "target.example"
_SEED = f"https://{_HOST}/"
_CF_HEADERS = {"Server": "cloudflare", "CF-Ray": "0000000000000000-TEST"}

# Expected URL set: seed + well-known leak paths + surface discovery paths.
# These are seeded by run_recon() itself, NOT by frontier expansion.
_ROOT = _SEED.rstrip("/")
_EXPECTED_SEeded_URLS: set[str] = {_SEED}
for _p in getattr(constants, "WELL_KNOWN_LEAK_PATHS", ()):
    _EXPECTED_SEeded_URLS.add(f"{_ROOT}{_p}")
for _p in getattr(constants, "SURFACE_DISCOVERY_PATHS", ()):
    _EXPECTED_SEeded_URLS.add(f"{_ROOT}{_p}")


@dataclasses.dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = dataclasses.field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, routes: dict[str, FakeResponse]) -> None:
        self._routes = routes
        self.calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.calls.append(url)
        # Any unmatched path returns a 404 with a body (NOT_FOUND, non-analyzable).
        return self._routes.get(url, FakeResponse(404, "not found"))


class _SpyProvider:
    """Stub LLM provider that counts complete() calls and sums usage_cost_usd."""

    model = "stub"

    def __init__(
        self, response_text: str = '{"tool": "generic_http_probe"}', usage_cost_usd: float = 0.0001
    ) -> None:
        self._text = response_text
        self._cost = usage_cost_usd
        self.calls: list[dict[str, Any]] = []
        self.total_cost_usd = 0.0

    def complete(self, *args: object, **kwargs: object) -> object:
        self.calls.append({"args": args, "kwargs": kwargs})
        self.total_cost_usd += self._cost
        return type(
            "R",
            (),
            {
                "text": self._text,
                "usage_cost_usd": self._cost,
                "model": "stub",
                "reasoning": "",
            },
        )()


def _load_fixture(name: str) -> str:
    return (_FIXTURE_DIR / name).read_text(encoding="utf-8")


def _alpha(http: FakeHttpClient, provider: _SpyProvider) -> tuple[Alpha, str, InMemoryEventStore]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="cf_lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    orch = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(_PLAYBOOK_DIR),
        provider=provider,
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=store,
        orchestrator=orch,
        http_client=http,
        secrets_manager=SecretsManager(),
    )
    return alpha, rec.engagement_id, store


def _waf_events(store: InMemoryEventStore, engagement_id: str) -> list[Any]:
    return [e for e in store.get_events(engagement_id) if e.event_type == EventType.WAF_BLOCKED]


# ---------------------------------------------------------------------------
# t1 — CHALLENGE verdict from body + headers
# ---------------------------------------------------------------------------


def test_cf_challenge_200_body_is_challenge() -> None:
    """A 200 carrying a Cloudflare challenge interstitial must be Verdict.CHALLENGE."""
    body = _load_fixture("cf_challenge_body.txt")
    assert classify_response(status_code=200, body=body, headers=_CF_HEADERS) is Verdict.CHALLENGE


# ---------------------------------------------------------------------------
# t1b — live path: no LLM tokens, no frontier, no asset, WAF event recorded
# ---------------------------------------------------------------------------


def test_cf_challenge_200_never_burns_llm_tokens() -> None:
    """A real run_recon over a CF challenge 200 must not call the provider,
    must not persist an ASSET, must not expand the frontier, and must record
    a WAF/CF audit event."""
    body = _load_fixture("cf_challenge_body.txt")
    provider = _SpyProvider()
    http = FakeHttpClient({_SEED: FakeResponse(200, body, _CF_HEADERS)})
    alpha, eid, store = _alpha(http, provider)

    alpha.run_recon(eid, _SEED)

    assert len(provider.calls) == 0, (
        "Cloudflare challenge 200 was escalated to the LLM provider — "
        f"provider.complete() called {len(provider.calls)}x"
    )
    assert provider.total_cost_usd == 0.0, "Cloudflare challenge 200 incurred non-zero LLM cost"
    assert list(alpha.graph_store.nodes_by_type(NodeType.ASSET)) == [], (
        "Cloudflare challenge 200 persisted an ASSET node"
    )
    # Frontier expansion only fires on Verdict.OK. The fixture body now contains
    # a same-origin <a href="/x"> anchor — if CHALLENGE is working correctly,
    # that href must NOT be enqueued.
    _challenge_href = f"{_ROOT}/x"
    assert _challenge_href not in http.calls, (
        "challenge-page href /x was fetched — frontier expanded on a CHALLENGE verdict"
    )
    extra = set(http.calls) - _EXPECTED_SEeded_URLS
    assert not extra, f"challenge-page hrefs were fetched beyond seed + well-known paths: {extra}"
    assert len(_waf_events(store, eid)) >= 1, (
        "Cloudflare challenge 200 did not record a WAF/CF audit event"
    )


# ---------------------------------------------------------------------------
# t2 — FP guard: CF headers alone must NOT trigger CHALLENGE
# ---------------------------------------------------------------------------


def test_cf_headers_alone_do_not_trigger_challenge() -> None:
    """A real 200 page served behind Cloudflare must stay Verdict.OK.
    Headers (Server: cloudflare, CF-Ray) are not enough to call it a challenge."""
    body = _load_fixture("cf_legit_200_body.txt")
    verdict = classify_response(status_code=200, body=body, headers=_CF_HEADERS)
    assert verdict is Verdict.OK


# ---------------------------------------------------------------------------
# t3 — backward compat: omitting headers keeps every existing verdict pinned
# ---------------------------------------------------------------------------


def test_classify_response_without_headers_unchanged() -> None:
    """headers is an optional parameter; existing status-only callers are pinned."""
    assert classify_response(status_code=200, body="<html>ok</html>") is Verdict.OK
    assert classify_response(status_code=403, body="Forbidden") is Verdict.BLOCKED
    assert classify_response(status_code=404, body="not found") is Verdict.NOT_FOUND
    assert (
        classify_response(status_code=415, body="unsupported media type")
        is Verdict.UNSUPPORTED_MEDIA_TYPE
    )


# ---------------------------------------------------------------------------
# #3/#4 — Marker tiering: STRONG markers fire alone; WEAK markers need header
# ---------------------------------------------------------------------------
# CodeRabbit #3: "access denied" and "reference #" are generic phrases that
# appear in legitimate pages. At HTTP 200 they false-CHALLENGE without a
# corroborating vendor header. R2 splits CHALLENGE_BODY_MARKERS into STRONG
# (fire alone) and WEAK (need header hint). These tests pin the contract.
#
# t_strong            — GREEN (strong marker fires without header)
# t_weak_no_header    — GREEN (weak marker without header is OK)
# t_weak_with_header  — GREEN (weak marker + Akamai header → CHALLENGE)
# t_reflection_guard  — GREEN (legit article text with "access denied" is OK)


def test_strong_marker_alone_is_challenge() -> None:
    """A body with ONLY a STRONG marker (e.g. cf-browser-verification) and NO
    vendor header must be Verdict.CHALLENGE."""
    body = '<html><body><div id="cf-browser-verification">Loading...</div></body></html>'
    assert classify_response(status_code=200, body=body) is Verdict.CHALLENGE


def test_weak_marker_without_header_is_ok() -> None:
    """A 200 body with ONLY weak markers ("access denied", "reference #") and NO
    Akamai/WAF header must be Verdict.OK — weak markers need corroboration."""
    body = (
        "<html><body>"
        "<h1>Access denied</h1>"
        "<p>Reference #12345. Please contact support.</p>"
        "</body></html>"
    )
    assert classify_response(status_code=200, body=body) is Verdict.OK


def test_weak_marker_with_corroborating_header_is_challenge() -> None:
    """A 200 body with weak markers + a corroborating Akamai header
    (Server: AkamaiGHost) must be Verdict.CHALLENGE."""
    body = (
        "<html><body>"
        "<h1>Access denied</h1>"
        "<p>Reference #12345. Please contact support.</p>"
        "</body></html>"
    )
    headers = {"Server": "AkamaiGHost"}
    assert classify_response(status_code=200, body=body, headers=headers) is Verdict.CHALLENGE


def test_reflection_guard_legit_page_with_access_denied_text_is_ok() -> None:
    """A legit 200 page whose body merely echoes "access denied" in article text
    (no vendor header) must be Verdict.OK — attacker/self-DoS guard (#4)."""
    body = (
        "<html><body><article>"
        "<h1>When to use access denied responses</h1>"
        "<p>In HTTP, a 403 status means access denied to the resource.</p>"
        "</article></body></html>"
    )
    assert classify_response(status_code=200, body=body) is Verdict.OK
