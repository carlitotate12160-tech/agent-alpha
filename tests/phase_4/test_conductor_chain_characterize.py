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
    os.environ.get("AGENT_ALPHA_LIVE_FIRE") != "1"
    or not os.environ.get("DEEPSEEK_API_KEY")
    or not os.environ.get("PROFILE_SIGNING_KEY"),
    reason=(
        "live-fire characterization test: requires AGENT_ALPHA_LIVE_FIRE=1, a real "
        "DEEPSEEK_API_KEY (real network + real LLM calls against a self-owned lab target), "
        "and a PROFILE_SIGNING_KEY (EngagementProfile HMAC signing — get_profile_signing_key "
        "raises ValueError without it). Run explicitly on Oracle ARM64 — never as part of a "
        "default pytest sweep."
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
    # Route the worker's tenant store. monkeypatch.setitem auto-restores on teardown —
    # direct dict mutation would persist across tests (isolation correctness, not style).
    monkeypatch.setitem(m.store_provider._stores, _TENANT_ID, store)

    # ── Signed EngagementProfile (§12.36) --- REQUIRED for the Conductor path to build
    #    origin-discovery and reach the origin DIRECTLY (bypassing CF). Without this,
    #    run_engagement_task degrades to engagement_profile=None → no origin discovery →
    #    Alpha hits the CF edge → 403 on everything → Beta never dispatches.
    #    The runner (odoo_chain_runner) doesn't need this because it constructs Alpha directly;
    #    the Conductor path REQUIRES the signed profile event.
    #
    #    authorized_origins=frozenset() (EMPTY) — forces the §12.46 BINDING path:
    #    run_engagement_task sees empty authorized_origins → wires LiveOriginDiscovery
    #    (not Static). CompositeOriginDiscovery unions the seeded PASSIVE_INTEL_GATHERED
    #    events below with LiveOriginDiscovery's candidates. resolve_and_bind_origin then
    #    PROVES binding via the real well-known token canary on the origin. NO pre-signed
    #    origin IP = the ONLY authorization path is ORIGIN_BINDING_PROVEN (§12.46).
    #
    #    Lab mode: skip_domain_verification=True (ownership proven by lab_guard allowlist).
    #    opsec_stealth DISABLED for this test — StealthPacer Gaussian jitter adds ~5s between
    #    each of ~24 probes, exceeding the pytest timeout. Stealth is proven separately (PR #353).
    #
    #    PRECONDITION (lab setup): 168.110.192.62 MUST serve the well-known canary file:
    #      /.well-known/agent-alpha-<token>.txt  (echoing <token> in the body)
    #    for BOTH vhosts (wp.alpha-ai.web.id, odoo.alpha-ai.web.id). <token> is the
    #    ownership_tokens value below. Without this, binding fail-closes (expected/honest).
    #    Nginx: /var/www/alpha-ai-bait/.well-known/ on the origin box.
    # Token matches the DEPLOYED canary on 168.110.192.62 (see
    # alpha_ai_integrated.example.yaml ownership_tokens for wp.alpha-ai.web.id).
    # Nginx on the origin serves /var/www/alpha-ai-bait/.well-known/ for all vhosts,
    # so the same file works regardless of Host header (wp or odoo).
    lab_token = "5fd127953896afcb6bc19b0cfc434786"
    signing_key = get_profile_signing_key()
    profile = authorize_engagement(
        engagement_id=rec.engagement_id,
        client_id="odoo-characterize",
        targets=[_LEAK_HOST, _ENTRY_HOST],
        scope_mode="multi",
        authorized_origins=frozenset(),
        allow_origin_discovery=True,
        authorization_level="ACTIVE_APPROVED",
        consent_items=frozenset({"origin_direct", "active_approved", "origin_discovery"}),
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

    # ── Seed origin-IP candidates via PASSIVE_INTEL_GATHERED (GAP-017 consumer path).
    #    With authorized_origins=frozenset(), run_engagement_task wires LiveOriginDiscovery
    #    (real CT/DNS). CompositeOriginDiscovery unions these event-sourced IPs into the
    #    candidate list — same mechanism OTX slice-5 uses. This is NOT a mock: the BINDING
    #    verification (verify_origin_binding → real fetch to origin) is still live. We seed
    #    the candidate to avoid dependence on crt.sh availability (which timed out before).
    _ORIGIN_IP = "168.110.192.62"
    for host in (_LEAK_HOST, _ENTRY_HOST):
        store.append(
            event_type=EventType.PASSIVE_INTEL_GATHERED,
            engagement_id=rec.engagement_id,
            agent="alpha",
            payload={
                "domain": host,
                "origin_ip_candidates": [_ORIGIN_IP],
                "subdomains": [],
                "in_scope_subdomains": [],
            },
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

    # ── J0: ORIGIN_BINDING_PROVEN — the BOUND leg was exercised (§12.46) ────────
    #    With authorized_origins=frozenset(), the ONLY way an origin IP gets
    #    authorized is via ORIGIN_BINDING_PROVEN events (proven_origins in
    #    assert_origin_authorized_or_bound). This is the cardinal gate: if binding
    #    did NOT fire for _LEAK_HOST, the wp-config reach path cannot succeed (no
    #    origin authorized → choose_reach ≠ ORIGIN_DIRECT → CF blocks everything).
    binding_events = [
        e for e in events
        if e.event_type == EventType.ORIGIN_BINDING_PROVEN
    ]
    leak_host_bound = any(
        isinstance(e.payload, dict) and e.payload.get("fronted_host") == _LEAK_HOST
        for e in binding_events
    )
    entry_host_bound = any(
        isinstance(e.payload, dict) and e.payload.get("fronted_host") == _ENTRY_HOST
        for e in binding_events
    )

    # Hard gate: _LEAK_HOST binding is on the critical path. Without it, the
    # wp-config probe cannot reach the origin and the chain dies at CF 403.
    assert leak_host_bound, (
        f"J0 BINDING GATE FAILED: no ORIGIN_BINDING_PROVEN event for {_LEAK_HOST!r}. "
        f"With authorized_origins=frozenset() the bound leg is the ONLY authorization "
        f"path. Verify the canary is deployed: the origin (168.110.192.62) must serve "
        f"/.well-known/agent-alpha-<token>.txt echoing the ownership_token for {_LEAK_HOST}. "
        f"Binding events found: {[(e.payload.get('fronted_host'), e.payload.get('origin_ip')) for e in binding_events if isinstance(e.payload, dict)]}"
    )

    # Soft finding: _ENTRY_HOST binding depends on Alpha probing odoo during recon.
    # Beta's OdooAccessTool uses XML-RPC (not origin-direct reach), so binding for
    # odoo is not on the cred-reuse critical path — it's a recon-completeness signal.
    if not entry_host_bound:
        findings.append(
            f"J0b CHARACTERIZATION: no ORIGIN_BINDING_PROVEN for {_ENTRY_HOST!r}. "
            f"Alpha did not trigger reach on this host during recon (expected if "
            f"Alpha's cognitive loop focused on {_LEAK_HOST} and did not probe odoo "
            f"resources behind CF). Beta reaches odoo via XML-RPC (not origin-direct)."
        )

    # Meta-assertion: profile.authorized_origins is EMPTY — proves the signed-origin
    # cooperative path is structurally impossible. Any successful origin-direct reach
    # (including the wp-config probe) MUST have gone through the BOUND leg.
    assert not profile.authorized_origins, (
        f"INTEGRITY CHECK: profile.authorized_origins should be empty but got "
        f"{profile.authorized_origins!r} — the test is NOT exercising the binding path."
    )

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
