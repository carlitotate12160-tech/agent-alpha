"""FROZEN contract (architect-authored — IDE implements Option A; do NOT edit assertions).

Alpha is a fingerprint-DISPATCHER: step() maps decision.tool to the proven recon
vectors (verify_wp_config_leak / verify_js_secret_leak), unknown tools fall through
to the generic asset-only handler.

DESIGN CORRECTION 2026-07-03 (found by the live FP-run — the original Option-A framing
was wrong): the campaign vectors must scan ONLY the CURRENT TARGET HOST, not all
scope hosts. Rationale: Alpha's caller loop (run_live_fire / recon_runner) ALREADY
iterates one host per run_recon, so a campaign that sweeps every scope host both (a)
duplicates work (N× redundant probes) and (b) MISATTRIBUTES findings — probing the
`spa-hardened` target while the campaign also scans an in-scope `spa-vuln` sibling
credits the sibling's leak to the hardened target's findings_count → a false positive
(predicted_vulnerable via `findings_count > 0`). Breadth comes from the caller loop,
NOT from the campaign. The fix passes `[current_host]` (from the URL under probe, which
Alpha has already validated in-scope, and which the vector re-checks via is_in_scope).

Impl this pins:
  * WP handler -> verify_wp_config_leak(..., scope_hosts=[<current target host>])
  * JS handler -> verify_js_secret_leak(..., scope_targets=[<current target host>])
    (note the differing kwarg names: scope_hosts vs scope_targets)
  * `_get_scope_hosts()` (the old all-scope accessor) becomes unused -> DELETE it (no
    dead code, anti-#2).
  * Findings: creds_added > 0 -> self._findings += 1 (one finding = one exposure, not
    per-credential, anti-#3).
  * Idempotency guard (self._ran_campaigns) still runs each campaign at most once per
    run_recon.
  * Unknown tools -> generic asset-only (no fabricated finding).

Vector internals are pinned by tests/phase_3/test_wp_config_leak.py &
test_js_secret_probe.py; these tests pin OUTCOMES + wiring at Alpha's boundary only.
Authoritative run: Oracle ARM64.
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

_HOST = "wp-lab.invalid"           # the host actually probed in each test
_HOST_B = "sibling-lab.invalid"    # an in-scope SIBLING that must NOT be scanned
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
        Scope(ip_ranges=["10.0.0.1/32"], domains=domains or [_HOST], exclusions=[], db_endpoints=[]),
    )
    return auth, rec.engagement_id


def _make_alpha(
    auth: AuthorizationStateMachine, event_store: InMemoryEventStore, http: FakeHttpClient, tool: str
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
    """decision.tool='wp_config_probe' + a leaking backup path -> a CREDENTIAL finding."""
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


# ── Wiring: the campaign scans ONLY the current target host (not the whole scope) ──
# These INVERT the earlier "receives full scope" contract, which the live FP-run proved
# wrong (it cross-contaminated hardened targets with vulnerable siblings' findings).


class _Spy:
    def __init__(self, returns: int) -> None:
        self.returns = returns
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> int:
        self.calls.append(kwargs)
        return self.returns


def _install(monkeypatch: pytest.MonkeyPatch, name: str, spy: Any) -> None:
    monkeypatch.setattr(f"agent_alpha.recon.wp_config_probe.{name}", spy, raising=False)
    monkeypatch.setattr(f"agent_alpha.recon.js_secret_probe.{name}", spy, raising=False)
    monkeypatch.setattr(f"agent_alpha.agents.alpha.scout.{name}", spy, raising=False)


def test_wp_vector_receives_only_current_target_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two hosts in scope, one probed -> the WP vector receives ONLY the probed host.

    Passing the full scope makes the campaign scan in-scope siblings and misattribute
    their leaks to this target's findings_count (the FP the FP-run surfaced).
    """
    spy = _Spy(returns=1)
    _install(monkeypatch, "verify_wp_config_leak", spy)
    event_store = InMemoryEventStore()
    auth, eng_id = _recon_engagement(event_store, domains=[_HOST, _HOST_B])
    http = FakeHttpClient({_ROOT_URL: FakeResponse(200, "<html>wp-content</html>")})
    alpha = _make_alpha(auth, event_store, http, "wp_config_probe")

    alpha.run_recon(eng_id, _ROOT_URL)

    assert spy.calls, "wp_config_probe handler did not call verify_wp_config_leak."
    assert spy.calls[0]["scope_hosts"] == [_HOST], (
        f"WP campaign must scan only the current host {[_HOST]}, got "
        f"{spy.calls[0]['scope_hosts']} — scanning the in-scope sibling causes FP."
    )


def test_js_vector_receives_only_current_target_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same for JS — and pin the differing kwarg name (scope_targets, not scope_hosts)."""
    spy = _Spy(returns=1)
    _install(monkeypatch, "verify_js_secret_leak", spy)
    event_store = InMemoryEventStore()
    auth, eng_id = _recon_engagement(event_store, domains=[_HOST, _HOST_B])
    http = FakeHttpClient({_ROOT_URL: FakeResponse(200, '<html><div id="root"></div></html>')})
    alpha = _make_alpha(auth, event_store, http, "js_secret_probe")

    alpha.run_recon(eng_id, _ROOT_URL)

    assert spy.calls, "js_secret_probe handler did not call verify_js_secret_leak."
    assert spy.calls[0]["scope_targets"] == [_HOST], (
        f"JS campaign must scan only the current host {[_HOST]}, got "
        f"{spy.calls[0]['scope_targets']}."
    )


def test_hardened_target_not_contaminated_by_vulnerable_sibling_in_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FP LOCK (the exact bug the FP-run hit): probing a hardened host must report NO
    finding even when a vulnerable sibling is in scope.

    The stub 'finds' a secret only if the vulnerable sibling (_HOST_B) is in the scanned
    set. With the fix (current-host only) the hardened run never scans _HOST_B, so
    findings_count stays 0. RED today (full scope includes _HOST_B -> false positive).
    """

    def fake_verify(**kwargs: Any) -> int:
        scanned = kwargs.get("scope_targets") or kwargs.get("scope_hosts") or []
        return 1 if _HOST_B in scanned else 0

    _install(monkeypatch, "verify_js_secret_leak", fake_verify)
    event_store = InMemoryEventStore()
    auth, eng_id = _recon_engagement(event_store, domains=[_HOST, _HOST_B])  # _HOST probed, _HOST_B vuln sibling
    http = FakeHttpClient({_ROOT_URL: FakeResponse(200, '<html><div id="root"></div></html>')})
    alpha = _make_alpha(auth, event_store, http, "js_secret_probe")

    msg = alpha.run_recon(eng_id, _ROOT_URL)

    assert _handoff(msg).findings_count == 0, (
        "Probing the hardened target reported a finding because the campaign scanned the "
        "in-scope vulnerable sibling — the cross-contamination false positive."
    )


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
