# ADR §12.27 D2 — per-engagement OK-body SHA-256 dedup.
#
# Scout hashes each OK body per engagement. A repeat hash short-circuits before
# the RULE and LLM tiers, so identical pages are analyzed once. The second page
# still records an audit event (dedup, not silent skip) and the graph is not
# double-processed.
#
# Mirrors the harness of test_empty_body_header_signal.py:
# real PlaybookEngine + real LLMOrchestrator + stub provider that counts calls.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_identical_body_dedup.py -v

from __future__ import annotations

import dataclasses
import pathlib
from typing import Any

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.recon.response_classifier import VOLATILE_HEADERS
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")
_HOST = "target.example"
_SEED = f"https://{_HOST}/"
_SECOND = f"https://{_HOST}/second-page"


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


def _alpha(http: FakeHttpClient, provider: _SpyProvider) -> tuple[Alpha, str]:
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="dedup_lab", target=_HOST)
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
    return alpha, rec.engagement_id


def _dedup_events(store: InMemoryEventStore, engagement_id: str) -> list[Any]:
    """Audit events that explicitly record a body-dedup short-circuit."""
    return [
        e for e in store.get_events(engagement_id) if e.payload.get("reason") == "identical_body"
    ]


# ---------------------------------------------------------------------------
# t4 — identical OK body is analyzed once; second is short-circuited
# ---------------------------------------------------------------------------


def test_identical_ok_body_is_analyzed_once() -> None:
    """Two in-scope URLs returning the same OK body: first analyzed, second
    short-circuited before RULE/LLM. An audit event is recorded for the second
    and the graph is not double-processed."""
    same_body = (
        "<!DOCTYPE html><html><head><title>Same</title></head>"
        "<body><h1>Same page</h1><p>Identical body for dedup test.</p>"
        '<a href="/second-page">next</a></body></html>'
    )
    provider = _SpyProvider()
    http = FakeHttpClient(
        {
            _SEED: FakeResponse(200, same_body, {"Server": "nginx"}),
            _SECOND: FakeResponse(200, same_body, {"Server": "nginx"}),
        }
    )
    alpha, eid = _alpha(http, provider)

    alpha.run_recon(eid, _SEED)

    assert len(provider.calls) == 1, (
        "identical OK body was analyzed more than once; "
        f"provider.complete() called {len(provider.calls)}x"
    )
    assert alpha._analyzable_probes == 1, (
        f"graph was double-processed; _analyzable_probes = {alpha._analyzable_probes}"
    )
    assert len(_dedup_events(alpha.event_store, eid)) == 1, (
        "second identical-body fetch did not record a dedup audit event"
    )


# ---------------------------------------------------------------------------
# t5 — different OK bodies are both analyzed (dedup must not over-collapse)
# ---------------------------------------------------------------------------


def test_different_ok_bodies_are_both_analyzed() -> None:
    """Two different OK bodies must both be analyzed; dedup must not collapse them."""
    body_a = (
        "<!DOCTYPE html><html><head><title>Page A</title></head>"
        "<body><h1>Welcome to Page A</h1><a href='/second-page'>next</a></body></html>"
    )
    body_b = (
        "<!DOCTYPE html><html><head><title>Page B</title></head>"
        "<body><h1>Welcome to Page B</h1><p>Different content.</p></body></html>"
    )
    provider = _SpyProvider()
    http = FakeHttpClient(
        {
            _SEED: FakeResponse(200, body_a, {"Server": "nginx"}),
            _SECOND: FakeResponse(200, body_b, {"Server": "nginx"}),
        }
    )
    alpha, eid = _alpha(http, provider)

    alpha.run_recon(eid, _SEED)

    assert len(provider.calls) == 2, (
        "two different OK bodies were not both analyzed; "
        f"provider.complete() called {len(provider.calls)}x"
    )
    assert alpha._analyzable_probes == 2, (
        f"different bodies collapsed; _analyzable_probes = {alpha._analyzable_probes}"
    )
    assert len(_dedup_events(alpha.event_store, eid)) == 0, (
        "different bodies incorrectly recorded as dedup"
    )


# ---------------------------------------------------------------------------
# #2 — Curated-header dedup key: non-volatile security headers enter the key;
#      volatile headers (CF-Ray, Date, Set-Cookie, Age, X-Request-Id) do NOT.
# ---------------------------------------------------------------------------
# CodeRabbit #2: dedup currently hashes only resp.text. Two URLs with identical
# bodies but different WWW-Authenticate headers are wrongly deduped. R2 will
# include curated (non-volatile) headers in the hash key.
#
# t_same_body_diff_auth       — RED until R2 (different auth header, same body →
#                               currently deduped, test expects both analyzed)
# t_same_body_volatile_headers — GREEN now (volatile-only difference → deduped;
#                               stays GREEN after R2 because volatile headers
#                               must not enter the key)


def test_same_body_diff_auth_header_both_analyzed() -> None:
    """Two in-scope 200 URLs with IDENTICAL body but DIFFERENT WWW-Authenticate
    header must both be analyzed — the auth header is security-relevant and
    must enter the dedup key.

    RED until R2 implements curated-header dedup."""
    same_body = (
        "<!DOCTYPE html><html><head><title>Protected</title></head>"
        "<body><h1>Protected Resource</h1>"
        '<a href="/second-page">next</a></body></html>'
    )
    provider = _SpyProvider()
    http = FakeHttpClient(
        {
            _SEED: FakeResponse(
                200,
                same_body,
                {"Server": "nginx", "WWW-Authenticate": 'Digest realm="a"'},
            ),
            _SECOND: FakeResponse(
                200,
                same_body,
                {"Server": "nginx", "WWW-Authenticate": 'Bearer realm="b"'},
            ),
        }
    )
    alpha, eid = _alpha(http, provider)

    alpha.run_recon(eid, _SEED)

    assert alpha._analyzable_probes == 2, (
        "identical body with different WWW-Authenticate was deduped — "
        f"_analyzable_probes = {alpha._analyzable_probes} (expected 2)"
    )
    assert len(_dedup_events(alpha.event_store, eid)) == 0, (
        "identical body with different WWW-Authenticate incorrectly recorded as dedup"
    )


def test_same_body_volatile_headers_second_is_deduped() -> None:
    """Two in-scope 200 URLs with identical body, differing ONLY in volatile
    headers (CF-Ray, Date) — the second MUST still be deduped. Volatile headers
    must never enter the dedup key (Bug #20)."""
    same_body = (
        "<!DOCTYPE html><html><head><title>Same</title></head>"
        "<body><h1>Same page</h1><p>Identical body for volatile dedup test.</p>"
        '<a href="/second-page">next</a></body></html>'
    )
    provider = _SpyProvider()
    http = FakeHttpClient(
        {
            _SEED: FakeResponse(
                200,
                same_body,
                {"Server": "nginx", "CF-Ray": "aaa-AAA", "Date": "Thu, 17 Jul 2026 10:00:00 GMT"},
            ),
            _SECOND: FakeResponse(
                200,
                same_body,
                {"Server": "nginx", "CF-Ray": "bbb-BBB", "Date": "Thu, 17 Jul 2026 10:00:01 GMT"},
            ),
        }
    )
    alpha, eid = _alpha(http, provider)

    alpha.run_recon(eid, _SEED)

    assert len(provider.calls) == 1, (
        "identical body with only volatile-header differences was NOT deduped — "
        f"provider.complete() called {len(provider.calls)}x (expected 1). "
        f"Volatile headers must not enter the dedup key (Bug #20). "
        f"VOLATILE_HEADERS = {VOLATILE_HEADERS}"
    )
    assert len(_dedup_events(alpha.event_store, eid)) == 1, (
        "second identical-body (volatile-only diff) did not record a dedup audit event"
    )
