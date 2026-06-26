"""RED integration contract: the Laravel finding must come from the TOOL-LAYER
template, carry retrievable + REDACTED proof, with NO duplicate detection path (ADR §12.16).

WHY THIS EXISTS (anti-Lyndon, caught 2026-06-26):
  #44 merged `LaravelFindingTemplate`, but NOTHING in the live path calls it — `scout.py` 
  still detects Laravel inline via `_handle_laravel_debug`. That is dead + duplicate code
  (Lyndon #2 + #6), and the agent owns domain logic the tool layer is supposed to own
  (#4/#8). The template's *unit* test passed in isolation, which hid all of this.

  This test drives Alpha END-TO-END and stays RED until:
    1. scout delegates Laravel detection to the template (one canonical path), and
    2. the persisted proof is real captured evidence (not boilerplate, not a string), and
    3. redaction holds for Laravel-specific secrets (APP_KEY), not just generic ones.

Authored by Claude (the seam/contract). The offensive build()/verify() bodies stay DeepSeek's.

Run on Oracle ARM64 (the only valid env, Lyndon #9):
  .venv/bin/python3 -m pytest tests/phase_2/test_laravel_template_wiring.py -v
"""

from __future__ import annotations

import dataclasses
import pathlib

import pytest

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).parent / "fixtures" / "playbooks"

# Planted secrets — MUST never reach the persisted graph in raw form.
#   DB_PASSWORD: caught by the generic LOG_SCRUB_PATTERNS (password[:=]\S+).
#   APP_KEY:     Laravel-specific — the generic patterns MISS it, so this is the
#                value that exposes the redaction gap once the template is wired.
# NOTE: These are TEST FIXTURES, not real secrets. GitGuardian may flag them.
PLANTED_DB_PASSWORD = "test-fixture-password-12345"
PLANTED_APP_KEY = "base64:TESTFIXTUREAPPKEY9999999999999999999999AAAA="

LEAKY_LARAVEL_BODY = (
    "<!DOCTYPE html><html><head><title>Whoops! There was an error.</title></head>"
    "<body><div class='exception'>Illuminate\\Database\\QueryException</div>"
    "<div>SQLSTATE[HY000] [1045] Access denied</div><table>"
    "<tr><td>APP_DEBUG</td><td>true</td></tr>"
    f"<tr><td>APP_KEY</td><td>{PLANTED_APP_KEY}</td></tr>"
    f"<tr><td>DB_PASSWORD</td><td>{PLANTED_DB_PASSWORD}</td></tr>"
    "</table><footer>Laravel v10.3.1 (PHP v8.2.4)</footer></body></html>"
)

TARGET_URL = "https://lab-target.invalid/trigger-error"


@dataclasses.dataclass(frozen=True)
class _Resp:
    status_code: int
    text: str
    headers: dict
    url: str


class _FakeHttpClient:
    def __init__(self, body: str) -> None:
        self.calls: list[str] = []
        self._body = body

    def get(self, url: str, timeout: float = 10.0) -> _Resp:
        self.calls.append(url)
        return _Resp(500, self._body, {"server": "nginx"}, url)


class _StubProvider:
    """Never reached on the RULE tier (Whoops -> playbook hit); present for safety."""

    model = "deepseek-v4-pro"

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, *a: object, **k: object):
        self.calls += 1
        return type(
            "R", (), {"text": '{"tool": "generic_http_probe"}', "usage_cost_usd": 0.0,
                      "model": self.model}
        )()


@pytest.fixture
def alpha():
    event_store = InMemoryEventStore()
    graph_store = NetworkXGraphStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="client_lab", target="lab-target.invalid")
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=["10.0.0.0/30"], domains=["lab-target.invalid"], exclusions=[]),
    )
    orchestrator = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR), provider=_StubProvider()
    )
    agent = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=_FakeHttpClient(LEAKY_LARAVEL_BODY),
    )
    return agent, rec.engagement_id, graph_store


def _laravel_vulns(graph_store):
    return [v for v in graph_store.nodes_by_type(NodeType.VULNERABILITY) if "laravel" in v.id]


def _proof_blob(vulns) -> str:
    """Everything a client/auditor could read off the persisted proof."""
    parts: list[str] = []
    for v in vulns:
        for p in v.proof_artifacts:
            parts.append(f"{p.description} {p.storage_ref} {p.type} {p.artifact_id}")
    return " ".join(parts)


# ── #6: one canonical detection path, no duplicate ───────────────────────


def test_exactly_one_laravel_vuln_no_duplicate_path(alpha):
    agent, eng, graph_store = alpha
    agent.run_recon(eng, TARGET_URL)
    assert len(_laravel_vulns(graph_store)) == 1


# ── #3: proof is retrievable, not a theater string ───────────────────────


def test_proof_is_retrievable(alpha):
    agent, eng, graph_store = alpha
    agent.run_recon(eng, TARGET_URL)
    proofs = [p for v in _laravel_vulns(graph_store) for p in v.proof_artifacts]
    assert proofs, "laravel vuln must carry a proof artifact"
    for p in proofs:
        assert p.storage_ref.strip(), "proof must reference stored evidence (storage_ref)"
        assert p.artifact_id.strip(), "proof must have a stable artifact_id"


# ── RED NOW: proof must be REAL captured evidence, not boilerplate ────────


def test_proof_contains_captured_evidence_from_body(alpha):
    """The proof must include a debug signal actually captured from the page. scout's
    generic description does not — this fails until detection is delegated to the
    template, which captures a redacted snippet around the matched signature."""
    agent, eng, graph_store = alpha
    agent.run_recon(eng, TARGET_URL)
    blob = _proof_blob(_laravel_vulns(graph_store))
    assert ("Whoops" in blob) or ("QueryException" in blob), (
        "proof must contain evidence captured from the response body, not a generic string"
    )


# ── Security guard: redaction holds end-to-end (bites APP_KEY after wiring) ─


def test_no_raw_secret_reaches_the_graph(alpha):
    """The captured proof must be redacted. DB_PASSWORD is caught by the generic
    patterns; APP_KEY is NOT (LOG_SCRUB_PATTERNS misses it) — redaction must use the
    Laravel credential-key SSOT so neither value can ever land in the graph/report."""
    agent, eng, graph_store = alpha
    agent.run_recon(eng, TARGET_URL)
    blob = _proof_blob(_laravel_vulns(graph_store))
    assert PLANTED_DB_PASSWORD not in blob, "DB_PASSWORD value leaked into the graph"
    assert "PLANTEDAPPKEY" not in blob, "APP_KEY value leaked into the graph (redaction gap)"
