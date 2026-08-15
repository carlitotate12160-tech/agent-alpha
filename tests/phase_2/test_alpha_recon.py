"""Contract: Alpha (SCOUT) recon on the first target — Laravel APP_DEBUG.

This is the test that proves the project's headline claim for Phase 2:
Alpha *reads* an HTTP response and reaches a conclusion that DIFFERS by target,
rather than replaying a hardcoded sequence. Four guarantees:

  1. Auth gate: Alpha refuses to act unless the Conductor's state machine
     says it may (anti-bypass — Alpha never reads/writes auth state itself).
  2. Real read: the target URL appears in the http client's call log; the
     conclusion is derived from the body, not fabricated (anti-Lyndon #3).
  3. Distinct conclusion: Laravel-debug target -> laravel asset + debug-
     exposure vulnerability node; hardened target -> neither.
  4. No silent success: an empty/unreachable target yields status FAILED,
     never COMPLETE-with-zero-findings dressed up as success.
"""

from __future__ import annotations

import pathlib

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.graph.nodes import NodeType
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).parent / "fixtures" / "playbooks"


class _StubProvider:
    def __init__(self) -> None:
        self.calls = 0
        self.model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object):
        self.calls += 1
        return type(
            "R",
            (),
            {
                "text": '{"tool": "generic_http_probe"}',
                "usage_cost_usd": 0.0,
                "model": "deepseek-v4-pro",
            },
        )()


@pytest.fixture
def alpha_factory(graph_store, event_store):
    def _make(auth, http_client):
        provider = _StubProvider()
        orchestrator = LLMOrchestrator(
            playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR), provider=provider
        )
        agent = Alpha(
            authorization=auth,
            graph_store=graph_store,
            event_store=event_store,
            orchestrator=orchestrator,
            http_client=http_client,
        )
        return agent, provider

    return _make


def _handoff(msg: a2a_pb2.A2AMessage) -> a2a_pb2.HandoffPayload:
    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)
    return payload


# ── 1. Authorization gate ─────────────────────────────────────────────


def test_alpha_refuses_without_authorization(alpha_factory, http_client):
    from agent_alpha.conductor.authorization import AuthorizationStateMachine
    from agent_alpha.events.store import InMemoryEventStore

    auth = AuthorizationStateMachine(event_store=InMemoryEventStore())
    rec = auth.create_engagement(client_id="c", target="lab-target.invalid")
    # State is CREATED, not RECON_ONLY -> Alpha may NOT proceed.
    agent, _ = alpha_factory(auth, http_client)

    msg = agent.run_recon(rec.engagement_id, "https://lab-target.invalid/trigger-error")
    assert _handoff(msg).status == a2a_pb2.BLOCKED
    assert http_client.calls == []  # never even reached out


def test_alpha_refuses_out_of_scope_target(alpha_factory, recon_engagement, http_client):
    """Authorized state (RECON_ONLY) is NOT enough — the target host must also
    be inside the engagement scope. Scanning out of scope violates the SOW, so
    Alpha must BLOCK and never send a request (anti-bypass; auth gate must not
    be softened for convenience)."""
    auth, engagement_id = recon_engagement  # scope: lab-target.invalid, hardened.invalid

    agent, _ = alpha_factory(auth, http_client)

    msg = agent.run_recon(engagement_id, "https://out-of-scope.invalid/trigger-error")
    assert _handoff(msg).status == a2a_pb2.BLOCKED
    assert http_client.calls == []  # scope violation -> never fetched


# ── 2 + 3. Real read, distinct conclusion ─────────────────────────────


def test_alpha_detects_laravel_debug_and_writes_graph(
    alpha_factory, recon_engagement, http_client, graph_store, laravel_target_url
):
    auth, engagement_id = recon_engagement
    agent, provider = alpha_factory(auth, http_client)

    msg = agent.run_recon(engagement_id, laravel_target_url)

    assert laravel_target_url in http_client.calls  # actually fetched
    assert provider.calls == 0  # RULE tier, no LLM

    assets = graph_store.nodes_by_type(NodeType.ASSET)
    vulns = graph_store.nodes_by_type(NodeType.VULNERABILITY)
    assert any("laravel" in a.properties.tech_stack for a in assets)
    assert len(vulns) >= 1
    # Exploitability proof must be attached, not merely asserted.
    assert any(v.proof_artifacts for v in vulns)

    handoff = _handoff(msg)
    assert msg.from_agent == a2a_pb2.ALPHA
    assert msg.to_agent == a2a_pb2.CONDUCTOR
    assert msg.message_type == a2a_pb2.HANDOFF_READY
    assert handoff.status == a2a_pb2.COMPLETE
    assert handoff.findings_count >= 1
    assert handoff.next_recommended == a2a_pb2.CONDUCTOR


def test_alpha_reaches_different_conclusion_on_hardened_target(
    alpha_factory, recon_engagement, http_client, graph_store, hardened_target_url
):
    auth, engagement_id = recon_engagement
    agent, _ = alpha_factory(auth, http_client)

    msg = agent.run_recon(engagement_id, hardened_target_url)

    assets = graph_store.nodes_by_type(NodeType.ASSET)
    # The hardened target leaks nothing -> no laravel tech-stack conclusion.
    assert not any("laravel" in a.properties.tech_stack for a in assets)

    # Reachable + analysed + zero findings is a COMPLETED recon, NOT "running".
    # A terminal handoff must never report RUNNING (the Conductor would think
    # Alpha is still working). findings_count conveys that nothing was found.
    handoff = _handoff(msg)
    assert handoff.status == a2a_pb2.COMPLETE
    assert handoff.findings_count == 0


# ── 4. No silent success ──────────────────────────────────────────────


def test_empty_target_is_failure_not_silent_success(alpha_factory, recon_engagement, http_client):
    auth, engagement_id = recon_engagement
    agent, _ = alpha_factory(auth, http_client)

    # URL not in the fake routes -> 404 empty body.
    msg = agent.run_recon(engagement_id, "https://nothing-here.invalid/")
    handoff = _handoff(msg)
    assert handoff.status == a2a_pb2.FAILED
    assert handoff.findings_count == 0


# ── Bug #34: engagement-scoped state persists across targets, resets per engagement ──
#
# On the autonomous path (conductor/recon_runner.run_recon_for_engagement) ONE Alpha
# instance scans EVERY target of an engagement in sequence — `for url in targets:
# pipeline.alpha.run_recon(engagement_id, url)`. Dedup/health state that is scoped to
# the whole engagement (already-probed URLs, dead hosts, an egress that was found
# blocked, duplicate-body hashes) MUST survive across those targets. Wiping it every
# call made the agent re-probe a blocked egress and re-analyse the same WAF wall on
# every sibling target — burns HTTP + LLM tokens, never converges. It must still RESET
# when a genuinely new engagement (fresh engagement_id) begins (no cross-engagement leak).


def test_engagement_scoped_state_persists_across_targets(
    alpha_factory, recon_engagement, http_client, hardened_target_url
):
    """Bug #34 CARDINAL: two targets in the SAME engagement on a reused Alpha — the
    engagement's learned dedup/health state carries over to the second target instead of
    being wiped (the old behaviour = re-probe a blocked egress / re-analyse the same
    wall on every sibling → thrash)."""
    auth, engagement_id = recon_engagement
    agent, _ = alpha_factory(auth, http_client)

    # First target of the engagement.
    agent.run_recon(engagement_id, hardened_target_url)

    # What the FIRST target learned that the engagement as a whole must remember:
    # a URL already probed, a host proven dead, the same-wall body hash, and — the
    # cardinal one — that the egress IP is blocked.
    agent._probed.add("https://hardened.invalid/_sentinel_probed")
    agent._dead_hosts.add("dead.invalid")
    agent._body_hashes.add("sentinel-body-hash")
    agent._egress_blocked = True
    agent._consecutive_transport_fail = 3

    # Second target, SAME engagement, SAME reused instance.
    agent.run_recon(engagement_id, hardened_target_url)

    assert "https://hardened.invalid/_sentinel_probed" in agent._probed
    assert "dead.invalid" in agent._dead_hosts
    assert "sentinel-body-hash" in agent._body_hashes
    assert agent._egress_blocked is True
    assert agent._consecutive_transport_fail == 3


def test_new_engagement_id_resets_engagement_state(
    alpha_factory, recon_engagement, http_client, hardened_target_url
):
    """Bug #34 boundary: a genuinely NEW engagement (fresh engagement_id) on a reused
    Alpha MUST wipe the prior engagement's dedup/health state — otherwise stale
    'egress blocked' / 'already probed' from engagement A silently starves engagement B
    (cross-engagement leak, the opposite failure)."""
    from agent_alpha.conductor.authorization import Scope

    auth, eng1 = recon_engagement
    agent, _ = alpha_factory(auth, http_client)

    agent.run_recon(eng1, hardened_target_url)
    agent._probed.add("https://hardened.invalid/_stale_from_eng1")
    agent._egress_blocked = True

    # A SECOND engagement on the same reused Alpha, scoped to the same host.
    rec2 = auth.create_engagement(client_id="client_lab2", target="hardened.invalid")
    auth.enable_recon(
        rec2.engagement_id,
        Scope(ip_ranges=["10.0.0.0/30"], domains=["hardened.invalid"], exclusions=[]),
    )

    agent.run_recon(rec2.engagement_id, hardened_target_url)

    assert "https://hardened.invalid/_stale_from_eng1" not in agent._probed
    assert agent._egress_blocked is False
