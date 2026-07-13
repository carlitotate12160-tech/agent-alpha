# RED tests — Header-matcher slice-1. Two tiers:
#
#   UNIT (U*)  : PlaybookRule.matches() now reads response HEADERS (was body-only).
#   WIRING (W*): the header-fingerprint capability is REACHABLE in the LIVE recon
#                path (Alpha.run_recon), not an island (anti-Lyndon #2).
#
# TARGET PATH:  tests/phase_4/test_header_matcher.py
# AUTHORED BY:  Claude (test/gate lane). Bodies (PlaybookRule.matches header
#               branches, capability_probe catalog, 3 YAML rules, scout
#               _handle_capability_fingerprint + dispatch registration) are the
#               IDE lane.
#
# DESIGN (why these pins):
#   * observation already carries {"body", "headers"} (scout._step_once); the RULE
#     tier was body-only, so Tomcat (Server: Apache-Coyote), Basic-Auth
#     (WWW-Authenticate: Basic) and S3 (Server: AmazonS3) fell to the LLM tier or
#     leaked past. header_contains/header_regex close that (NOT a new engine).
#   * DETECT only: a match persists a LABELED ASSET node + seeds the frontier via
#     the existing in-scope guard; it NEVER mints a credential and NEVER increments
#     findings (fingerprint != finding, anti-#3). ACT stays gated Gamma (§12.26).
#
# Run on Oracle ARM64 only (system python 3.10 fails StrEnum):
#   .venv312/bin/python3 -m pytest tests/phase_4/test_header_matcher.py -v

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")

_HOST = "vuln.example"
_ROOT = f"https://{_HOST}/"
_MANAGER_URL = f"https://{_HOST}/manager/html"

_TOMCAT_HEADERS = {"Server": "Apache-Coyote/1.1"}
_BASIC_HEADERS = {"WWW-Authenticate": 'Basic realm="Restricted"'}
_S3_HEADERS = {"Server": "AmazonS3"}


# ── UNIT: PlaybookRule.matches() now reads headers ──────────────────────────


def test_u1_header_regex_matches_tomcat_server() -> None:
    from agent_alpha.tools.playbook import PlaybookEngine

    engine = PlaybookEngine.from_directory(_PLAYBOOK_DIR)
    decision = engine.match({"body": "<html>hi</html>", "headers": _TOMCAT_HEADERS})
    assert decision is not None
    assert decision.tool == "tomcat_fingerprint"
    assert decision.tier == "rule"


def test_u2_header_case_insensitive_and_negative() -> None:
    from agent_alpha.tools.playbook import PlaybookEngine

    engine = PlaybookEngine.from_directory(_PLAYBOOK_DIR)
    # Lower-cased header name (as an HTTP/2 origin or a proxy might emit) still hits.
    assert engine.match({"body": "", "headers": {"server": "apache-coyote"}}) is not None
    # A plain nginx origin must NOT fingerprint as any capability.
    assert engine.match({"body": "<html>ok</html>", "headers": {"Server": "nginx"}}) is None


def test_u3_basic_auth_and_s3_select_their_tools() -> None:
    from agent_alpha.tools.playbook import PlaybookEngine

    engine = PlaybookEngine.from_directory(_PLAYBOOK_DIR)
    assert engine.match({"body": "401", "headers": _BASIC_HEADERS}).tool == (
        "http_basic_auth_fingerprint"
    )
    assert engine.match({"body": "<Error/>", "headers": _S3_HEADERS}).tool == (
        "s3_bucket_fingerprint"
    )


def test_u4_body_only_rule_unaffected_by_header_change() -> None:
    # Regression: a body rule (git config) still fires, and a missing "headers"
    # key does not crash the header branches.
    from agent_alpha.tools.playbook import PlaybookEngine

    engine = PlaybookEngine.from_directory(_PLAYBOOK_DIR)
    git_body = "[core]\n\trepositoryformatversion = 0\n"
    assert engine.match({"body": git_body}).tool == "git_exposure_probe"


# ── WIRING: reachable via Alpha.run_recon (Oracle / py3.12) ─────────────────


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)


class FakeHttpClient:
    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self._responses = responses
        self.get_calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.get_calls.append(url)
        return self._responses.get(url, FakeResponse(404, "not found"))


class _StubProvider:
    """Rule tier is deterministic for header signals; provider must never be the
    path that fingerprints. Returns inert JSON so a non-rule observation is a no-op."""

    model = "stub"

    def complete(self, *a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "stub"})()


def _alpha(graph, store, http):
    from agent_alpha.agents.alpha.scout import Alpha
    from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
    from agent_alpha.llm.orchestrator import LLMOrchestrator
    from agent_alpha.security.secrets import SecretsManager
    from agent_alpha.tools.playbook import PlaybookEngine

    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="header_lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    orch = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(_PLAYBOOK_DIR), provider=_StubProvider()
    )
    alpha = Alpha(
        authorization=auth,
        graph_store=graph,
        event_store=store,
        orchestrator=orch,
        http_client=http,
        secrets_manager=SecretsManager(),
    )
    return alpha, rec.engagement_id


def test_w1_capability_tools_registered_in_dispatch() -> None:
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    store = InMemoryEventStore()
    alpha, _ = _alpha(NetworkXGraphStore(), store, FakeHttpClient({}))
    for tool in ("tomcat_fingerprint", "http_basic_auth_fingerprint", "s3_bucket_fingerprint"):
        assert tool in alpha._dispatch_registry


def test_w3_run_recon_fingerprints_tomcat_and_seeds_manager() -> None:
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore
    from agent_alpha.graph.nodes import NodeType

    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient(
        {
            _ROOT: FakeResponse(200, "<html>root</html>", dict(_TOMCAT_HEADERS)),
            _MANAGER_URL: FakeResponse(401, "login", dict(_BASIC_HEADERS)),
        }
    )
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    assets = list(graph.nodes_by_type(NodeType.ASSET))
    labels = {label for a in assets for label in a.properties.tech_stack}
    assert "tomcat" in labels  # labeled ASSET minted via the LIVE loop -> not an island
    assert "http_basic_auth" in labels  # merge: /manager/html 401 → basic_auth fingerprint
    assert _MANAGER_URL in http.get_calls  # seeded surface was enqueued + probed


def test_w4_fingerprint_is_not_a_payable_finding() -> None:
    # anti-Lyndon #3: a header fingerprint enriches the graph but is NOT a finding.
    from agent_alpha.events.store import InMemoryEventStore
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    http = FakeHttpClient({_ROOT: FakeResponse(200, "<html>root</html>", dict(_TOMCAT_HEADERS))})
    alpha, eid = _alpha(graph, store, http)

    alpha.run_recon(eid, _ROOT)

    assert alpha._findings == 0
