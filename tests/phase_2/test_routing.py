"""Contract: llm/routing.py — LLM role -> provider chokepoint (ADR §12.15, C2).

The routing module is the SINGLE place that maps the role/provider/transport
CONSTANTS onto a concrete provider. These tests pin the invariants:

  * reasoning role follows LLM_REASONING_PROVIDER and is NOT NEVER-guarded
    (reasoning may legitimately be a Claude/GPT-class model in production);
  * payload role is gated BEFORE a provider is built: direct-transport only,
    allowlist only, no forbidden (reasoning-class) token;
  * the transport gate precedes the model gate (egress risk dominates);
  * provider identity is config-only — swapping a constant swaps the provider
    with zero code change (ADR §12.15: "provider swap = config-only").

All hermetic: a recording builder stands in for any real backend, so no network
and no provider construction is required to exercise the policy.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from agent_alpha.config import constants
from agent_alpha.llm.routing import (
    PayloadProviderError,
    PayloadTransportError,
    ProviderPolicyError,
    assert_payload_policy,
    resolve_payload_provider,
    resolve_reasoning_provider,
)


class _RecordingBuilder:
    """Captures the model the resolver asked for; returns an inert stand-in.

    Satisfies routing.ProviderBuilder (keyword-only api_key + model)."""

    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def __call__(self, *, api_key: str, model: str) -> Any:
        self.calls.append({"api_key": api_key, "model": model})
        return SimpleNamespace(model=model)


def _config(
    *,
    reasoning: str = "deepseek-v4-pro",
    payload: str = "deepseek-v4-pro",
    transport: str = "direct",
    allowed: tuple[str, ...] = ("deepseek-v4-pro", "kimi-2.6"),
    never: tuple[str, ...] = ("claude", "sonnet", "opus", "gpt"),
) -> SimpleNamespace:
    """A drop-in stand-in for the constants module (no global mutation)."""
    return SimpleNamespace(
        LLM_REASONING_PROVIDER=reasoning,
        LLM_PAYLOAD_PROVIDER=payload,
        LLM_PAYLOAD_TRANSPORT=transport,
        LLM_PAYLOAD_ALLOWED=list(allowed),
        LLM_PAYLOAD_NEVER=list(never),
    )


# ── reasoning role ────────────────────────────────────────────────────


def test_reasoning_resolves_to_configured_provider() -> None:
    builder = _RecordingBuilder()
    provider = resolve_reasoning_provider(
        api_key="noop", config=_config(reasoning="deepseek-v4-pro"), build=builder
    )
    assert builder.calls == [{"api_key": "noop", "model": "deepseek-v4-pro"}]
    assert provider.model == "deepseek-v4-pro"


def test_reasoning_is_not_never_guarded() -> None:
    """The role split's whole point: reasoning MAY be a Claude/GPT-class model in
    production. A NEVER token on the reasoning provider must NOT raise."""
    builder = _RecordingBuilder()
    provider = resolve_reasoning_provider(
        api_key="noop", config=_config(reasoning="claude-opus-4"), build=builder
    )
    assert provider.model == "claude-opus-4"


def test_reasoning_provider_swap_is_config_only() -> None:
    builder = _RecordingBuilder()
    resolve_reasoning_provider(
        api_key="noop", config=_config(reasoning="gpt-5-thinking"), build=builder
    )
    assert builder.calls[0]["model"] == "gpt-5-thinking"


def test_reasoning_default_build_uses_real_backend_hermetically() -> None:
    """With the default builder, the reasoning role yields a real provider whose
    model is the single-source-of-truth constant — constructor is network-free."""
    provider = resolve_reasoning_provider(api_key="unit-test-noop")
    assert provider.model == constants.LLM_REASONING_PROVIDER == "deepseek-v4-pro"


# ── payload role: accept path ─────────────────────────────────────────


def test_payload_resolves_when_policy_satisfied() -> None:
    builder = _RecordingBuilder()
    provider = resolve_payload_provider(
        api_key="noop", config=_config(payload="deepseek-v4-pro"), build=builder
    )
    assert provider.model == "deepseek-v4-pro"
    assert builder.calls == [{"api_key": "noop", "model": "deepseek-v4-pro"}]


@pytest.mark.parametrize("model", ["deepseek-v4-pro", "kimi-2.6"])
def test_assert_payload_policy_accepts_allowlisted_direct(model: str) -> None:
    # Must not raise; returns None on success.
    assert_payload_policy(model, transport="direct", config=_config())


def test_payload_policy_reads_canonical_constants() -> None:
    """The real constants must satisfy their own payload policy — guards against a
    future edit that sets an out-of-policy default (transport drift, etc.)."""
    assert_payload_policy(
        constants.LLM_PAYLOAD_PROVIDER,
        transport=constants.LLM_PAYLOAD_TRANSPORT,
        config=constants,
    )


# ── payload role: reject paths ────────────────────────────────────────


def test_payload_rejects_gateway_transport() -> None:
    builder = _RecordingBuilder()
    with pytest.raises(PayloadTransportError):
        resolve_payload_provider(
            api_key="noop", config=_config(transport="gateway"), build=builder
        )
    assert builder.calls == []  # gate runs BEFORE any provider is built


def test_payload_rejects_forbidden_reasoning_class_model() -> None:
    """A model on ALLOWED that nonetheless carries a NEVER token is rejected by the
    NEVER branch — isolate it by putting the model in ALLOWED too."""
    cfg = _config(payload="gpt-5-payload", allowed=("gpt-5-payload", "deepseek-v4-pro"))
    with pytest.raises(PayloadProviderError):
        resolve_payload_provider(api_key="noop", config=cfg, build=_RecordingBuilder())


def test_payload_rejects_non_allowlisted_model() -> None:
    cfg = _config(payload="llama-3-70b")  # not NEVER, not ALLOWED
    with pytest.raises(PayloadProviderError):
        resolve_payload_provider(api_key="noop", config=cfg, build=_RecordingBuilder())


def test_transport_gate_precedes_model_gate() -> None:
    """Forbidden model AND gateway transport -> the transport breach is reported
    first: egress of the payload prompt is the dominant risk."""
    cfg = _config(payload="gpt-5", transport="gateway", allowed=("gpt-5",))
    with pytest.raises(PayloadTransportError):
        resolve_payload_provider(api_key="noop", config=cfg, build=_RecordingBuilder())


def test_policy_errors_share_a_base() -> None:
    """Callers may catch the family with one except (anti-Lyndon #3: one domain
    error, no silent downgrade)."""
    assert issubclass(PayloadTransportError, ProviderPolicyError)
    assert issubclass(PayloadProviderError, ProviderPolicyError)
    assert issubclass(ProviderPolicyError, ValueError)
