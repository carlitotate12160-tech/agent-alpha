# RED tests for JS-bundle secret + API-endpoint recon — generic, SYNTHETIC fixtures.
#
# TARGET PATH:  tests/phase_3/test_js_secret_probe.py
# AUTHORED BY:  Claude (test/gate lane).
#
# PINS (the contract the bodies MUST honour):
#   T1  discover_js_bundles returns same-origin only (CDN scripts filtered out).
#   T2  Real-looking provider keys (AWS, Stripe) are hits.
#   T3  Placeholders and low-entropy strings are NOT hits (anti-#3 core).
#   T4  Secret value never returned raw (masked preview only).
#   T5  verify_js_secret_leak persists validated secret as CREDENTIAL node + vaults raw.
#   T6  WAF block (403) on bundle → WAF_BLOCKED event, NOT treated as clean.
#   T7  Out-of-scope target → never fetched (scope gate).

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.recon.js_secret_probe import (
    discover_js_bundles,
    extract_api_endpoints,
    scan_js_for_secrets,
    verify_js_secret_leak,
)
from agent_alpha.security.secrets import SecretsManager

_HOST = "app.example.com"


# ── T1: discover_js_bundles — same-origin only ──────────────────────────────


def test_discover_bundles_same_origin_only():
    html = (
        '<script src="/assets/index-abc.js"></script>'
        '<script src="https://cdn.other.com/x.js">'
        '<link rel="modulepreload" href="/assets/vendor-def.js">'
    )
    result = discover_js_bundles(html, f"https://{_HOST}/")
    assert result == [
        f"https://{_HOST}/assets/index-abc.js",
        f"https://{_HOST}/assets/vendor-def.js",
    ]


# ── T2: real-looking keys are hits ──────────────────────────────────────────


def test_real_looking_key_is_a_hit():
    _stripe = "sk_live_" + "abcd1234efgh5678ijkl9012"
    body = f'const k="AKIA1234567890ABCDEF"; const s="{_stripe}";'
    hits = scan_js_for_secrets(body)
    kinds = {h.kind for h in hits}
    assert "aws_access_key" in kinds
    assert "stripe_live" in kinds


# ── T3: placeholders and low-entropy are NOT hits (anti-#3 core) ────────────


def test_placeholder_and_low_entropy_are_not_hits():
    assert scan_js_for_secrets('apiKey: "YOUR_API_KEY_HERE"') == []
    assert scan_js_for_secrets('token = "xxxxxxxxxxxxxxxx"') == []
    assert scan_js_for_secrets('const password = "";') == []
    assert scan_js_for_secrets('secret: "placeholder_value123"') == []


# ── T4: secret value never returned raw ─────────────────────────────────────


def test_secret_value_never_returned_raw():
    [hit] = scan_js_for_secrets('aws="AKIA1234567890ABCDEF"')
    assert "AKIA1234567890ABCDEF" not in str(hit)
    assert "AKIA1234567890ABCDEF" not in hit.value_preview
    assert "****" in hit.value_preview


# ── Test fixtures for verify_js_secret_leak ─────────────────────────────────


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""


class FakeHttpClient:
    """Records every URL probed; returns canned responses."""

    def __init__(self, responses: dict[str, FakeResponse | Exception] | None = None) -> None:
        self._responses = responses or {}
        self.get_calls: list[str] = []

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> FakeResponse:
        self.get_calls.append(url)
        r = self._responses.get(url)
        if isinstance(r, Exception):
            raise r
        if r is None:
            return FakeResponse(status_code=404, text="")
        return r


class JsTestContext:
    """Bundle of stores + auth + fake HTTP for verify_js_secret_leak tests."""

    def __init__(self, *, domains: list[str] | None = None) -> None:
        self.events = InMemoryEventStore()
        self.auth = AuthorizationStateMachine(event_store=self.events)
        self.graph = NetworkXGraphStore()
        self.secrets = SecretsManager()
        self.http = FakeHttpClient()

        target = (domains or [_HOST])[0]
        rec = self.auth.create_engagement(client_id="js_lab", target=target)
        self.auth.enable_recon(
            rec.engagement_id,
            Scope(
                ip_ranges=["10.0.0.1/32"],
                domains=domains or [_HOST],
                exclusions=[],
            ),
        )
        self.engagement_id = rec.engagement_id

        self.args: dict[str, Any] = {
            "engagement_id": self.engagement_id,
            "auth": self.auth,
            "http_client": self.http,
            "scope_targets": domains or [_HOST],
            "graph_store": self.graph,
            "event_store": self.events,
            "secrets_manager": self.secrets,
        }

    def serve_page(self, html: str) -> None:
        self.http._responses[f"https://{_HOST}/"] = FakeResponse(status_code=200, text=html)

    def serve_bundle(self, body: str, path: str = "/assets/app.js") -> None:
        self.http._responses[f"https://{_HOST}{path}"] = FakeResponse(status_code=200, text=body)

    def serve_bundle_status(self, status: int, path: str = "/assets/app.js") -> None:
        self.http._responses[f"https://{_HOST}{path}"] = FakeResponse(
            status_code=status, text="blocked"
        )

    def events_list(self) -> list[Any]:
        return list(self.events.get_events(self.engagement_id))


@pytest.fixture()
def js_ctx() -> JsTestContext:
    return JsTestContext()


# ── T5: verify persists validated secret as credential + vaults raw ─────────


def test_verify_persists_validated_secret_as_credential(js_ctx: JsTestContext) -> None:
    js_ctx.serve_page('<script src="/assets/app.js"></script>')
    js_ctx.serve_bundle('const k="AKIA1234567890ABCDEF";')

    n = verify_js_secret_leak(**js_ctx.args)
    assert n == 1

    cred = [
        c for c in js_ctx.graph.nodes_by_type(NodeType.CREDENTIAL) if c.properties.service == "aws"
    ]
    assert cred
    assert js_ctx.secrets.retrieve(cred[0].properties.secret_ref) == "AKIA1234567890ABCDEF"


# ── T6: WAF block on bundle is INCONCLUSIVE, not clean ──────────────────────


def test_waf_block_on_bundle_is_inconclusive_not_clean(js_ctx: JsTestContext) -> None:
    js_ctx.serve_page('<script src="/assets/app.js"></script>')
    js_ctx.serve_bundle_status(403)

    verify_js_secret_leak(**js_ctx.args)

    assert any(
        getattr(e, "event_type", None) == EventType.WAF_BLOCKED for e in js_ctx.events_list()
    )


# ── T7: out-of-scope target never fetched ───────────────────────────────────


def test_out_of_scope_target_never_fetched(js_ctx: JsTestContext) -> None:
    js_ctx.args["scope_targets"] = ["not-in-scope.example"]
    verify_js_secret_leak(**js_ctx.args)
    assert js_ctx.http.get_calls == []


# ── T8: API endpoint extraction ─────────────────────────────────────────────


def test_extract_api_endpoints():
    body = 'fetch("/api/users"); axios.post("/api/login"); baseURL="/api/v2";'
    endpoints = extract_api_endpoints(body)
    assert "/api/users" in endpoints
    assert "/api/login" in endpoints
    assert "/api/v2" in endpoints


# ── T9: below RECON_ONLY tier → fail-closed ─────────────────────────────────


def test_below_recon_tier_fail_closed() -> None:
    # Drop engagement back to PLANNING by creating a fresh one without enabling recon
    ctx2 = JsTestContext()
    rec = ctx2.auth.create_engagement(client_id="js_lab2", target=_HOST)
    ctx2.args["engagement_id"] = rec.engagement_id
    ctx2.args["auth"] = ctx2.auth
    # Don't enable recon — state is PLANNING
    n = verify_js_secret_leak(**ctx2.args)
    assert n == 0
    assert ctx2.http.get_calls == []
