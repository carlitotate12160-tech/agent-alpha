"""FROZEN contract (architect-authored — IDE implements Option A; do NOT edit assertions).

Closes the dead-integration gap (Lyndon #2): the proven recon vectors
(recon.wp_config_probe.verify_wp_config_leak, recon.js_secret_probe.verify_js_secret_leak)
are invoked ONLY by bespoke live-fire chain runners, never by Alpha's cognitive loop. So
an autonomous Conductor-driven engagement, Alpha (SCOUT) produces ONLY Laravel-debug
findings — one stack. The WP/JS capability is real but integration-dead.

DESIGN = Option A (chosen 2026-07-03): Alpha is a fingerprint-DISPATCHER that invokes the
existing standalone vectors INTACT — no rewrite; they keep their own tier/scope/WAF gates
as defense-in-depth. step() maps decision.tool to the matching vector via a small registry
{tool_name: handler}; unknown tools fall through to the generic asset-only handler.

Contract the IDE implements in agent_alpha/agents/alpha/scout.py:
  * A dispatch registry (built in __init__): {"laravel_debug_probe": ..., "wp_config_probe":
    self._handle_wp_config_probe, "js_secret_probe": self._handle_js_secret_probe}.
  * In-scope hosts come from the ENGAGEMENT SCOPE (self.authorization.get_record(
    self._engagement_id).scope.domains) — NEVER the probed URL host, NEVER caller free-form.
    NOTE the vector kwarg names DIFFER: wp uses `scope_hosts=`, js uses `scope_targets=`.
  * Findings accounting: a campaign that returns creds_added > 0 increments self._findings by
    EXACTLY 1 (one finding = one exposure), mirroring _handle_laravel_debug — NOT by
    creds_added (a credential count is not a finding count; += count inflates, anti-#3).
  * IDEMPOTENCY GUARD (required, even though latent today): the vectors are ENGAGEMENT-level
    campaigns (they iterate all scope_hosts internally) but step() runs PER-URL. Today the
    work queue holds a single URL so no re-run happens — but Alpha's own output spec includes
    api_endpoints; the moment endpoint-discovery enqueues URLs, each same-tool step would
    re-run the full campaign (redundant probes + duplicate nodes/events). Guard it now:
    reset `self._ran_campaigns: set[str] = set()` in run_recon; each campaign handler returns
    0 early if its tool is already in the set, else adds it. (A behavioural test for this is
    deferred until endpoint-discovery lands — the path that makes it active — rather than
    contorting a white-box test against a currently-unreachable branch.)
  * Unknown / greenfield tools STILL route to the generic asset-only handler (no fabricated
    finding, #3). The vectors' WAF discriminator + scope/tier gates must be PRESERVED.

Vector internals are pinned by tests/phase_3/test_wp_config_leak.py &
test_js_secret_probe.py; these tests pin OUTCOMES + wiring at Alpha's boundary only.
RED until the dispatch exists (today scout.step() handles only "laravel_debug_probe").

Authoritative run: Oracle ARM64 (`.venv/bin/python3 -m pytest`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType

_HOST = "wp-lab.invalid"
_HOST_B = "wp-lab-b.invalid"
_ROOT_URL = f"https://{_HOST}/"
_WP_CONFIG_BODY = (
    "<?php\n"
    "define('DB_NAME', 'wp_lab');\n"
    "define('DB_USER', 'wpuser');\n"
    "define('DB_PASSWORD', 's3cret');\n"
    "define('DB_HOST', 'localhost');\n"
)


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class FakeHttpClient:
    """Serves canned responses per-URL; records every URL requested."""

    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> FakeResponse:
        self.calls.append(url)
        return self._responses.get(url, FakeResponse(status_code=404, text="Not Found"))


class _StubOrchestrator:
    """Stands in for ORIENT: forces a fixed tool selection so the ACT/dispatch seam
    (the thing under test) is isolated from LLM/playbook tool-selection."""

    def __init__(self, tool: str) -> None:
        self._tool = tool

    def decide(self, observation: dict[str, object]) -> SimpleNamespace:
        return SimpleNamespace(
            tool=self._tool,
            tier="rule",
            reasoning="fingerprint",
            cost_usd=0.0,
            technique_id="T1552.001",
        )


def _recon_engagement(
    event_store: InMemoryEventStore, *, domains: list[str] | None = None
) -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="wp_lab", target=_HOST)
    auth.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=["10.0.0.1/32"], domains=domains or [_HOST], exclusions=[], db_endpoints=[]
        ),
    )
    return auth, rec.engagement_id


def _make_alpha(
    auth: AuthorizationStateMachine,
    event_store: InMemoryEventStore,
    http: FakeHttpClient,
    tool: str,
) -> Alpha:
    return Alpha(
        authorization=auth,
        graph_store=NetworkXGraphStore(),
        event_store=event_store,
        orchestrator=_StubOrchestrator(tool),
        http_client=http,
    )


def _handoff(msg: a2a_pb2.A2AMessage) -> a2a_pb2.HandoffPayload:
    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)
    return payload


# ── Behavioural: the real vector runs through Alpha and a real finding lands ─────


def test_alpha_dispatches_wp_tool_to_real_vector_and_finds_credential() -> None:
    """decision.tool='wp_config_probe' + a leaking backup path -> a CREDENTIAL finding.

    RED today: Alpha routes any non-laravel tool to the generic asset-only handler,
    so zero credential nodes are persisted.
    """
    event_store = InMemoryEventStore()
    auth, eng_id = _recon_engagement(event_store)
    http = FakeHttpClient(
        {
            _ROOT_URL: FakeResponse(200, "<html>wp-content wp-includes</html>"),
            f"https://{_HOST}/wp-config.php.bak": FakeResponse(200, _WP_CONFIG_BODY),
        }
    )
    alpha = _make_alpha(auth, event_store, http, "wp_config_probe")

    alpha.run_recon(eng_id, _ROOT_URL)

    creds = alpha.graph_store.nodes_by_type(NodeType.CREDENTIAL)
    assert creds, (
        "Alpha selected wp_config_probe but produced no CREDENTIAL node: the WP vector "
        "was not dispatched (fell through to the generic asset-only handler)."
    )
    assert f"https://{_HOST}/wp-config.php.bak" in http.calls


def test_alpha_wp_dispatch_preserves_waf_discriminator() -> None:
    """A 403 on the backup path -> WAF_BLOCKED event, NO credential, NOT a false 'clean'."""
    event_store = InMemoryEventStore()
    auth, eng_id = _recon_engagement(event_store)
    http = FakeHttpClient(
        {
            _ROOT_URL: FakeResponse(200, "<html>wp-content</html>"),
            f"https://{_HOST}/wp-config.php.bak": FakeResponse(
                403, "Access Denied", {"cf-ray": "deadbeef-SIN"}
            ),
        }
    )
    alpha = _make_alpha(auth, event_store, http, "wp_config_probe")

    alpha.run_recon(eng_id, _ROOT_URL)

    assert not alpha.graph_store.nodes_by_type(NodeType.CREDENTIAL)
    waf = [e for e in event_store.get_events(eng_id) if e.event_type == EventType.WAF_BLOCKED]
    assert waf, "A 403 backup path was treated as clean — WAF discriminator lost in the wiring."


def test_alpha_unknown_tool_stays_generic_asset_only() -> None:
    """Regression guard: an unrecognised tool must NOT fabricate a finding (#3)."""
    event_store = InMemoryEventStore()
    auth, eng_id = _recon_engagement(event_store)
    http = FakeHttpClient({_ROOT_URL: FakeResponse(200, "<html>hello</html>")})
    alpha = _make_alpha(auth, event_store, http, "mystery_probe_v9")

    alpha.run_recon(eng_id, _ROOT_URL)

    assert not alpha.graph_store.nodes_by_type(NodeType.CREDENTIAL)
    assert not alpha.graph_store.nodes_by_type(NodeType.VULNERABILITY)


# ── Wiring (monkeypatch): scope source + findings accounting ─────────────────────
# Patched at BOTH the source module and Alpha's namespace so the spy is hit whether
# the IDE imports the vector at module top-level or lazily inside the handler.


class _Spy:
    def __init__(self, returns: int) -> None:
        self.returns = returns
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> int:
        self.calls.append(kwargs)
        return self.returns


def _install(monkeypatch: pytest.MonkeyPatch, name: str, spy: _Spy) -> None:
    monkeypatch.setattr(f"agent_alpha.recon.wp_config_probe.{name}", spy, raising=False)
    monkeypatch.setattr(f"agent_alpha.recon.js_secret_probe.{name}", spy, raising=False)
    monkeypatch.setattr(f"agent_alpha.agents.alpha.scout.{name}", spy, raising=False)


def test_wp_vector_receives_scope_hosts_from_scope_not_probed_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scope_hosts must be the engagement's FULL verified scope, not just the probed host.

    Two domains in scope, only one probed -> the vector must still receive BOTH (proves the
    hosts come from auth scope, not from the URL under probe).
    """
    spy = _Spy(returns=1)
    _install(monkeypatch, "verify_wp_config_leak", spy)
    event_store = InMemoryEventStore()
    auth, eng_id = _recon_engagement(event_store, domains=[_HOST, _HOST_B])
    http = FakeHttpClient({_ROOT_URL: FakeResponse(200, "<html>wp-content</html>")})
    alpha = _make_alpha(auth, event_store, http, "wp_config_probe")

    alpha.run_recon(eng_id, _ROOT_URL)

    assert spy.calls, "wp_config_probe handler did not call verify_wp_config_leak."
    assert sorted(spy.calls[0]["scope_hosts"]) == sorted([_HOST, _HOST_B])


def test_js_vector_receives_scope_targets_kwarg(monkeypatch: pytest.MonkeyPatch) -> None:
    """js vector uses scope_targets= (NOT scope_hosts=) — pin the correct kwarg name."""
    spy = _Spy(returns=1)
    _install(monkeypatch, "verify_js_secret_leak", spy)
    event_store = InMemoryEventStore()
    auth, eng_id = _recon_engagement(event_store, domains=[_HOST, _HOST_B])
    http = FakeHttpClient(
        {_ROOT_URL: FakeResponse(200, "<html><script src=/app.js></script></html>")}
    )
    alpha = _make_alpha(auth, event_store, http, "js_secret_probe")

    alpha.run_recon(eng_id, _ROOT_URL)

    assert spy.calls, "js_secret_probe handler did not call verify_js_secret_leak."
    assert sorted(spy.calls[0]["scope_targets"]) == sorted([_HOST, _HOST_B])


def test_finding_count_is_one_per_vector_hit_not_per_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A vector returning 3 credentials is ONE finding, not three (anti-#3 inflation)."""
    spy = _Spy(returns=3)
    _install(monkeypatch, "verify_wp_config_leak", spy)
    event_store = InMemoryEventStore()
    auth, eng_id = _recon_engagement(event_store)
    http = FakeHttpClient({_ROOT_URL: FakeResponse(200, "<html>wp-content</html>")})
    alpha = _make_alpha(auth, event_store, http, "wp_config_probe")

    msg = alpha.run_recon(eng_id, _ROOT_URL)

    assert _handoff(msg).findings_count == 1


# ── Idempotency guard (regression lock) ──────────────────────────────────────────
# The guard's skip branch is unreachable via the public loop TODAY (the work queue
# holds a single URL, nothing appends), so it is driven at the handler boundary. This
# pins the SAFETY control — a campaign must probe a client at most once per engagement.
# If the early-return is ever removed, redundant client probing returns and this fails.
# (When endpoint-discovery enqueues multiple URLs, the guard also gains black-box
# coverage; until then this is the honest pin.)


@pytest.mark.parametrize(
    "handler_attr,vector_name,tool",
    [
        ("_handle_wp_config_probe", "verify_wp_config_leak", "wp_config_probe"),
        ("_handle_js_secret_probe", "verify_js_secret_leak", "js_secret_probe"),
    ],
)
def test_campaign_runs_at_most_once_per_engagement(
    monkeypatch: pytest.MonkeyPatch, handler_attr: str, vector_name: str, tool: str
) -> None:
    spy = _Spy(returns=2)
    _install(monkeypatch, vector_name, spy)
    event_store = InMemoryEventStore()
    auth, eng_id = _recon_engagement(event_store)
    http = FakeHttpClient({_ROOT_URL: FakeResponse(200, "<html>wp-content</html>")})
    alpha = _make_alpha(auth, event_store, http, tool)

    # Mirror the per-run state run_recon() sets before the cognitive loop.
    alpha._engagement_id = eng_id
    alpha._ran_campaigns = set()
    alpha._findings = 0

    decision = _StubOrchestrator(tool).decide({})
    resp = FakeResponse(200, "<html>wp-content</html>")
    handler = getattr(alpha, handler_attr)

    first = handler(resp, decision, _ROOT_URL)
    second = handler(resp, decision, _ROOT_URL)

    assert first == 2, "first dispatch should return the vector's credential count"
    assert second == 0, "second dispatch of the same campaign must be guarded (no re-probe)"
    assert len(spy.calls) == 1, "the campaign vector must be invoked exactly once per engagement"
    assert alpha._findings == 1, "findings must increment once, not once per dispatch attempt"
