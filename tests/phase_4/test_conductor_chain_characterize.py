# tests/phase_4/test_conductor_chain_characterize.py
"""Characterization test — drives the alpha-ai Odoo cred-reuse chain through the REAL
Conductor Celery path (eager) instead of live_fire/odoo_chain_runner.py, to MAP which
autonomous-delta (if any) exists between the RUNNER ISLAND and the AUTONOMOUS-WIRED path.

This closes the exact debt tracked in docs/BUGS_AND_GAPS.md ("OdooAccessTool — WIRING
now gate-protected ... but AUTONOMOUS-WIN PROOF still owed: no non-island test drives
OdooAccessTool to WIN via run_strike/run_beta"). READ BEFORE re-deriving: do not rebuild
this test, extend it.

NOT a green-target test. RED at J1b and/or J4 is an EXPECTED, USEFUL outcome — it means
the runner hand-feeds a step the autonomous loop does not yet decide on its own, or the
tool-ranking picks a different tool than odoo_access when cred_applicators are bound.
Do NOT "fix to green" by mocking Beta/OdooAccessTool/the orchestrator/the network — that
defeats the measurement (Lyndon #3/#9). If a juncture is RED, open ONE tracked item in
docs/BUGS_AND_GAPS.md (update the existing OdooAccessTool entry, do not duplicate it) and
register it in tests/governance/test_wiring_gate.py so CI enforces the gap until closed.

Deliberate deviation from a literal J1..J5 step-by-step breakpoint script: Celery is
configured eager (task_always_eager=True), so a single call to `run_engagement_task`
cascades Alpha -> advance -> Beta -> advance(+verify) -> Omega SYNCHRONOUSLY in one shot
(same behavior test_autonomous_wp_chain_e2e.py relies on for the WP chain). That means the
human-tier-approval gate (enable_active) must be granted BEFORE the trigger, not staged
mid-run --- there is no in-process pause point between Alpha-complete and Beta-dispatch to
inject it later without either mocking the dispatcher (defeats the test) or running real
Celery workers (out of scope here). Each juncture is therefore reconstructed POST-HOC from
the durable, event-sourced log the autonomous path itself produced --- this is still an
honest measurement (the events are the source of truth, per authorization.py's own
doctrine), not a staged fake.

SAFETY: hits a REAL self-owned lab target over the network and makes REAL LLM calls.
Gated behind AGENT_ALPHA_LIVE_FIRE=1 + DEEPSEEK_API_KEY so it never runs by accident in a
normal `pytest tests/` sweep. Oracle ARM64 + .venv312 only (system py3.10 fails StrEnum):

    AGENT_ALPHA_LIVE_FIRE=1 .venv312/bin/python3 -m pytest \
        tests/phase_4/test_conductor_chain_characterize.py -v -s
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AGENT_ALPHA_LIVE_FIRE") != "1" or not os.environ.get("DEEPSEEK_API_KEY"),
    reason=(
        "live-fire characterization test: requires AGENT_ALPHA_LIVE_FIRE=1 and a real "
        "DEEPSEEK_API_KEY (real network + real LLM calls against a self-owned lab target). "
        "Run explicitly on Oracle ARM64 — never as part of a default pytest sweep."
    ),
)

from typing import Any  # noqa: E402

from agent_alpha.a2a import a2a_pb2  # noqa: E402
from agent_alpha.conductor import main as m  # noqa: E402
from agent_alpha.conductor.applicator_factory import beta_web_applicators  # noqa: E402
from agent_alpha.conductor.authorization import (  # noqa: E402
    AuthorizationStateMachine,
    Scope,
    authorize_engagement,
)
from agent_alpha.conductor.engagement_profile import dump_signed_profile  # noqa: E402
from agent_alpha.conductor.execute_agent import rebuild_graph_from_events  # noqa: E402
from agent_alpha.events.event_types import EventType  # noqa: E402
from agent_alpha.events.store import InMemoryEventStore  # noqa: E402
from agent_alpha.graph.nodes import NodeType  # noqa: E402
from agent_alpha.live_fire import odoo_chain_runner as ocr  # noqa: E402
from agent_alpha.live_fire.lab_guard import assert_lab_only_target  # noqa: E402
from agent_alpha.security.secrets import get_profile_signing_key  # noqa: E402
from agent_alpha.tools.internal.access.applicator import CredentialApplicator  # noqa: E402


def _proof_request_method(payload: object) -> str | None:
    """Narrow an event payload down to proof_request.method, or None. Isolated so mypy
    can track the dict narrowing cleanly (nested isinstance chains in a generator
    expression don't narrow reliably across two dict accesses)."""
    if not isinstance(payload, dict):
        return None
    proof_request = payload.get("proof_request")
    if not isinstance(proof_request, dict):
        return None
    method = proof_request.get("method")
    return method if isinstance(method, str) else None

# Self-owned alpha-ai.web.id siblings (see live_fire/lab_guard.py _LAB_HOSTS). Override via
# env if the live vulnerable Odoo stack moves to a different self-owned host --- the
# lab_guard allowlist is the enforced source of truth, not this default.
_LEAK_HOST = os.environ.get("ODOO_CHAIN_LEAK_HOST", "wp.alpha-ai.web.id")
_ENTRY_HOST = os.environ.get("ODOO_CHAIN_ENTRY_HOST", "odoo.alpha-ai.web.id")
_RECON_URL = f"https://{_LEAK_HOST}/"
_ENTRY_POINT = f"https://{_ENTRY_HOST}/"

_TENANT_ID = "tenant_odoo_characterize"


@pytest.mark.timeout(600)
def test_conductor_autonomous_chain_characterization(
    celery_eager_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Fail-closed target guard --- mirrors odoo_chain_runner.main(); refuses anything not
    # in the self-owned lab allowlist even though this test never touches that runner.
    assert_lab_only_target(_RECON_URL)
    assert_lab_only_target(_ENTRY_POINT)

    findings: list[str] = []

    # ── Seed engagement + auth (human tier-approval SIMULATED upfront --- see module
    #    docstring for why; this does NOT prove "no human needed", only what the
    #    autonomous CODE PATH does once approval is granted) ──────────────────────
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("odoo-characterize", _RECON_URL, tenant_id=_TENANT_ID)
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=[], domains=[_LEAK_HOST, _ENTRY_HOST], exclusions=[]),
    )
    auth.enable_active(rec.engagement_id)  # J3 (simulated) --- Beta gate = ACTIVE_APPROVED
    m.store_provider._stores[_TENANT_ID] = store  # route the worker's tenant store

    # ── Signed EngagementProfile (§12.36) --- REQUIRED for the Conductor path to build
    #    origin-discovery and reach the origin DIRECTLY (bypassing CF). Without this,
    #    run_engagement_task degrades to engagement_profile=None → no origin discovery →
    #    Alpha hits the CF edge → 403 on everything → Beta never dispatches.
    #    The runner (odoo_chain_runner) doesn't need this because it constructs Alpha directly;
    #    the Conductor path REQUIRES the signed profile event.
    #
    #    authorized_origins (cooperative path) → StaticOriginDiscovery: pre-signed origin IP
    #    168.110.192.62 (the Oracle box itself, self-owned). Faster + more reliable than
    #    LiveOriginDiscovery (CT/DNS lookup) which timed out in the first run.
    #    Lab mode: skip_domain_verification=True (ownership proven by lab_guard allowlist).
    #    opsec_stealth DISABLED for this test — StealthPacer Gaussian jitter adds ~5s between
    #    each of ~24 probes, exceeding the pytest timeout. Stealth is proven separately (PR #353).
    lab_token = "dns-txt:agentalpha-lab-proof=bc90b41d578cbf3c66512495d2e9aaaa"
    signing_key = get_profile_signing_key()
    profile = authorize_engagement(
        engagement_id=rec.engagement_id,
        client_id="odoo-characterize",
        targets=[_LEAK_HOST, _ENTRY_HOST],
        scope_mode="multi",
        authorized_origins=frozenset({"168.110.192.62"}),
        allow_origin_discovery=True,
        authorization_level="ACTIVE_APPROVED",
        consent_items=frozenset({"origin_direct", "active_approved"}),
        signed_by="natanael",
        signed_at="2026-08-08T00:00:00Z",
        ownership_tokens={_LEAK_HOST: lab_token, _ENTRY_HOST: lab_token},
        skip_domain_verification=True,
        event_store=store,
        key=signing_key,
    )
    envelope = dump_signed_profile(profile, key=signing_key)
    store.append(
        event_type=EventType.ENGAGEMENT_PROFILE_SIGNED,
        engagement_id=rec.engagement_id,
        agent="CONDUCTOR",
        payload=envelope,
    )

    # Spy (not a mock) on the REAL applicator factory: records whether Beta actually
    # bound web cred_applicators this run, without altering their behavior. Confirms the
    # "applicators BOUND" precondition instead of asserting it blind.
    applicator_calls: list[int] = []

    def _spy_beta_web_applicators(http_client: object) -> list[CredentialApplicator]:
        candidates = beta_web_applicators(http_client)
        applicator_calls.append(len(candidates))
        return candidates

    monkeypatch.setattr(m, "beta_web_applicators", _spy_beta_web_applicators)

    # ── ONE TRIGGER --- real network, real LLM, real Beta, real OdooAccessTool.
    #    Eager Celery cascades Alpha -> advance -> Beta -> advance(+verify) -> Omega. ──
    result: dict[str, Any] = m.run_engagement_task(rec.engagement_id, _TENANT_ID)

    assert result.get("status") == "completed", (
        f"run_engagement_task did not complete: {result} --- recon leg failed before Beta "
        "could even be reached; this is a precondition failure, not a J1b/J4 finding."
    )

    graph = rebuild_graph_from_events(store, rec.engagement_id)
    events = store.get_events(rec.engagement_id)

    # ── J1a: wp-config CREDENTIAL node vaulted (secret_ref resolves) ────────────
    edge_from_harvested_cred = ocr._edge_from_harvested_cred(
        graph, m.secrets_provider.for_tenant(_TENANT_ID)
    )
    if not edge_from_harvested_cred:
        findings.append(
            "J1a WIRING GAP: no ACCESS_LEVEL ENABLES-edge traced back to a vaulted "
            "(secret_ref-resolving) CREDENTIAL node on the autonomous path."
        )

    # ── J1b CARDINAL RED: did the autonomous loop DECIDE wp_config_probe on its own?
    #    Unlike odoo_chain_runner.run_odoo_chain_live_fire (which hand-calls
    #    verify_wp_config_leak after Alpha.run_recon regardless of what Alpha decided),
    #    THIS test never calls verify_wp_config_leak directly --- the only path to a
    #    leaked CREDENTIAL node is scout.py's autonomous dispatch_registry picking
    #    "wp_config_probe" (see agents/alpha/scout.py _dispatch_registry). ──────────
    creds = list(graph.nodes_by_type(NodeType.CREDENTIAL))
    if not creds:
        findings.append(
            "J1b CARDINAL RED: the autonomous Alpha loop did NOT select wp_config_probe "
            f"on {_LEAK_HOST} without being hand-fed --- zero CREDENTIAL nodes in the "
            "graph. odoo_chain_runner's chain_proven relies on a manual "
            "verify_wp_config_leak() call this path never makes."
        )

    # ── J2 (guard, expect PASS): did advance_engagement dispatch BETA? ──────────
    dispatched_beta = any(
        e.event_type == EventType.AGENT_DISPATCHED
        and isinstance(e.payload, dict)
        and e.payload.get("dispatched_agent") == a2a_pb2.BETA
        for e in events
    )
    if not dispatched_beta:
        findings.append(
            "J2 GUARD FAILED (separately-logged delta): advance_engagement never "
            "dispatched BETA after Alpha COMPLETE --- routing regression, not the "
            "expected J1b/J4 characterization finding."
        )

    # ── J4 CARDINAL RED: did OdooAccessTool WIN the ranked tool selection despite
    #    bound web cred_applicators (WpLoginApplicator/HttpFormApplicator)? Proof
    #    request shape ("method": "authenticate") uniquely discriminates odoo_access
    #    from cred_reuse/default_creds/user_derived_creds (see
    #    agents/beta/strike.py `candidates` + tools/internal/access/odoo_access.py). ──
    assert applicator_calls and applicator_calls[0] > 0, (
        "J4 precondition failed: beta_web_applicators was never called with candidates "
        "--- Beta did not run with applicators bound at all; re-check auth/scope wiring "
        "before trusting any J4 verdict."
    )
    winning_tool_is_odoo_access = any(
        _proof_request_method(e.payload) == "authenticate" for e in events
    )
    access_level = ocr._web_access_level(graph)
    if not winning_tool_is_odoo_access or access_level not in ("user", "admin"):
        findings.append(
            "J4 CARDINAL RED: OdooAccessTool did not win ToolRegistry(candidates).ranked(ctx) "
            f"on the autonomous path (access_level={access_level!r}, "
            f"odoo_access_proof_seen={winning_tool_is_odoo_access}). A bound web "
            "cred_applicator (or another tool) won first, or Odoo was never reached."
        )

    # ── J5 (guard, expect PASS): CredReuseAttestor promoted CROSS_VERIFIED ───────
    cross_verified = ocr._web_cross_verified(graph)
    if not cross_verified:
        findings.append(
            "J5 GUARD FAILED (separately-logged delta): ACCESS_LEVEL node never reached "
            "CROSS_VERIFIED --- verify_access_nodes did not fire/promote on the autonomous "
            "run_beta() COMPLETE path (conductor/main.py run_agent_task)."
        )

    if findings:
        pytest.fail(
            "Conductor-vs-runner delta map (this IS the deliverable --- do not chase "
            "green by mocking):\n  - " + "\n  - ".join(findings)
        )
