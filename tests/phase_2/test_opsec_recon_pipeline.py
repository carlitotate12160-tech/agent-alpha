# tests/phase_2/test_opsec_recon_pipeline.py

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


@pytest.fixture()
def _stub_provider(monkeypatch: pytest.MonkeyPatch) -> None:
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


@pytest.mark.usefixtures("_stub_provider")
def test_pipeline_injects_stealth_opsec_profile(
    policy: PolicyEnforcer,
    auth: AuthorizationStateMachine,
    store: InMemoryEventStore,
) -> None:
    pipeline = recon_runner.build_recon_pipeline(
        engagement_id="eng_0001",
        tenant_id=None,
        auth=auth,
        store=store,
        policy=policy,
    )

    from agent_alpha.agents.stealth_pacer import StealthPacer

    hc: HttpClient = pipeline.alpha.http_client
    assert hc._headers["User-Agent"] == constants.STEALTH_BROWSER["user_agent"]
    assert isinstance(hc._rate_limiter, StealthPacer)


def test_evasion_profile_falls_back_to_baseline_stealth(policy: PolicyEnforcer) -> None:
    resolved = policy.resolve_opsec_profile("blend", evasion_authorized=False)
    assert resolved == policy.get_opsec_profile(constants.DEFAULT_OPSEC_PROFILE)


def test_default_opsec_profile_constant_is_stealth() -> None:
    assert constants.DEFAULT_OPSEC_PROFILE == "stealth"


def test_recon_runner_references_constant_not_literal() -> None:
    source = inspect.getsource(recon_runner)
    tree = ast.parse(source)

    literal_uses = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == "stealth":
            literal_uses.append(node)

    assert not literal_uses, (
        f"recon_runner contains {len(literal_uses)} literal 'stealth' string(s) "
        f"— must use constants.DEFAULT_OPSEC_PROFILE"
    )


@pytest.mark.usefixtures("_stub_provider")
def test_pipeline_without_policy_uses_stealth_defaults(
    auth: AuthorizationStateMachine,
    store: InMemoryEventStore,
) -> None:
    pipeline = recon_runner.build_recon_pipeline(
        engagement_id="eng_0003",
        tenant_id=None,
        auth=auth,
        store=store,
    )

    hc: HttpClient = pipeline.alpha.http_client
    assert hc._headers["User-Agent"] == constants.STEALTH_BROWSER["user_agent"]


@pytest.mark.usefixtures("_stub_provider")
def test_pipeline_injects_stealth_pacer_when_opsec_stealth_consented(
    policy: PolicyEnforcer,
    auth: AuthorizationStateMachine,
    store: InMemoryEventStore,
) -> None:
    """§12.50 WIRED-PROOF: a signed profile with opsec_stealth=True → the live
    recon HttpClient is paced by a StealthPacer (human burst-and-pause), not the
    fixed-interval RateLimiter."""
    from agent_alpha.agents.stealth_pacer import StealthPacer

    profile = type("P", (), {"opsec_stealth": True})()
    pipeline = recon_runner.build_recon_pipeline(
        engagement_id="eng_stealth",
        tenant_id=None,
        auth=auth,
        store=store,
        policy=policy,
        engagement_profile=profile,
    )
    assert isinstance(pipeline.alpha.http_client._rate_limiter, StealthPacer)


@pytest.mark.usefixtures("_stub_provider")
def test_pipeline_uses_fixed_limiter_without_opsec_stealth(
    policy: PolicyEnforcer,
    auth: AuthorizationStateMachine,
    store: InMemoryEventStore,
) -> None:
    """No opsec_stealth consent → the plain fixed-interval RateLimiter (anti
    behaviour-change without consent)."""
    from agent_alpha.agents.rate_limiter import RateLimiter

    profile = type("P", (), {"opsec_stealth": False})()
    pipeline = recon_runner.build_recon_pipeline(
        engagement_id="eng_plain",
        tenant_id=None,
        auth=auth,
        store=store,
        policy=policy,
        engagement_profile=profile,
    )
    assert isinstance(pipeline.alpha.http_client._rate_limiter, RateLimiter)
