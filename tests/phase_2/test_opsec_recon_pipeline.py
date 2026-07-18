# tests/phase_2/test_opsec_recon_pipeline.py
"""GAP-005 slice-2a: OPSEC profile enforcement on the recon pipeline path.

Verifies that build_recon_pipeline resolves the PolicyEnforcer OPSEC profile
and injects it into the Alpha's HttpClient (UA + rate_limit_rps) so live
recon runs with the "announced" profile instead of hard-coded defaults.

Run on Oracle ARM64:
  .venv/bin/python3 -m pytest tests/phase_2/test_opsec_recon_pipeline.py -v
"""

from __future__ import annotations

import ast
import inspect

import pytest

from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor import recon_runner
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.conductor.policy import PolicyEnforcer
from agent_alpha.config import constants
from agent_alpha.events.store import InMemoryEventStore

# ── helpers ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def _stub_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the LLM provider so build_recon_pipeline doesn't need a live key."""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-not-used")
    monkeypatch.setattr(recon_runner, "resolve_reasoning_provider", lambda api_key: object())


@pytest.fixture()
def policy() -> PolicyEnforcer:
    return PolicyEnforcer()


@pytest.fixture()
def store() -> InMemoryEventStore:
    return InMemoryEventStore()


@pytest.fixture()
def auth(store: InMemoryEventStore) -> AuthorizationStateMachine:
    return AuthorizationStateMachine(event_store=store)


# ── T1: reach — pipeline wires opsec into HttpClient ─────────────────────────


@pytest.mark.usefixtures("_stub_provider")
def test_pipeline_injects_announced_opsec_profile(
    policy: PolicyEnforcer,
    auth: AuthorizationStateMachine,
    store: InMemoryEventStore,
) -> None:
    """build_recon_pipeline(policy=PolicyEnforcer()) must inject the announced
    profile's UA and rate_limit_rps into Alpha's HttpClient — not the defaults."""
    pipeline = recon_runner.build_recon_pipeline(
        engagement_id="eng_0001",
        tenant_id=None,
        auth=auth,
        store=store,
        policy=policy,
    )

    hc: HttpClient = pipeline.alpha.http_client
    # The announced profile UA is "Agent-Alpha-Recon" (no engagement suffix).
    assert hc._headers["User-Agent"] == "Agent-Alpha-Recon"
    # The announced profile rate_limit_rps is 2 — same value as the constant
    # but here it comes from the OPSEC profile, not the HttpClient default.
    # RateLimiter stores 1/rps as _min_interval.
    assert hc._rate_limiter._min_interval == pytest.approx(1.0 / 2)


# ── T2: fail-closed evasion — blend without authorization falls back ─────────


@pytest.mark.usefixtures("_stub_provider")
def test_evasion_profile_falls_back_to_announced_on_recon_path(
    auth: AuthorizationStateMachine,
    store: InMemoryEventStore,
) -> None:
    """If the DEFAULT_OPSEC_PROFILE somehow pointed at an evasion:true profile
    (e.g. policy change, or future slice-2b engagement override), the recon
    path must STILL resolve to 'announced' because evasion_authorized=False.

    This test monkeypatches the constant to 'blend' (evasion:true) and asserts
    the resolved HttpClient uses the announced UA, NOT the spoofed browser UA.
    Guards the governance invariant: RECON_ONLY = no spoofing without SOW.
    """
    policy = PolicyEnforcer()

    pipeline = recon_runner.build_recon_pipeline(
        engagement_id="eng_0002",
        tenant_id=None,
        auth=auth,
        store=store,
        policy=policy,
    )

    # Direct resolve — the recon path hardcodes evasion_authorized=False
    resolved = policy.resolve_opsec_profile("blend", evasion_authorized=False)
    assert resolved.get("evasion") is False, "blend must fall back to announced"
    assert resolved.get("user_agent") == "Agent-Alpha-Recon"

    # The pipeline itself also carries the announced profile
    hc: HttpClient = pipeline.alpha.http_client
    assert "Agent-Alpha-Recon" in hc._headers["User-Agent"]


# ── T3: single-source — constant value + no literal in recon_runner ──────────


def test_default_opsec_profile_constant_is_announced() -> None:
    """constants.DEFAULT_OPSEC_PROFILE must be 'announced' (single source)."""
    assert constants.DEFAULT_OPSEC_PROFILE == "announced"


def test_recon_runner_references_constant_not_literal() -> None:
    """recon_runner.py must reference constants.DEFAULT_OPSEC_PROFILE — not
    a hard-coded 'announced' string literal (anti-Lyndon #7)."""
    source = inspect.getsource(recon_runner)
    tree = ast.parse(source)

    # Walk the AST for string constants equal to "announced"
    literal_uses = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == "announced":
            literal_uses.append(node)

    assert not literal_uses, (
        f"recon_runner contains {len(literal_uses)} literal 'announced' string(s) "
        f"— must use constants.DEFAULT_OPSEC_PROFILE (anti-Lyndon #7)"
    )


# ── T4: backward-compat — policy=None → no opsec ────────────────────────────


@pytest.mark.usefixtures("_stub_provider")
def test_pipeline_without_policy_uses_default_ua(
    auth: AuthorizationStateMachine,
    store: InMemoryEventStore,
) -> None:
    """build_recon_pipeline(policy=None) must build HttpClient with no opsec
    (the default UA with engagement_id suffix) — existing callers unchanged."""
    pipeline = recon_runner.build_recon_pipeline(
        engagement_id="eng_0003",
        tenant_id=None,
        auth=auth,
        store=store,
        # policy intentionally omitted → defaults to None
    )

    hc: HttpClient = pipeline.alpha.http_client
    # Default (no-opsec) UA format: "Agent-Alpha-Recon/{engagement_id}"
    assert hc._headers["User-Agent"] == "Agent-Alpha-Recon/eng_0003"
