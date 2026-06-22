"""LLM role -> provider routing (ADR §12.15).

ROLE is the architectural invariant; the PROVIDER behind each role is config.
Two roles, two policies:

  reasoning : ORIENT / PLAN / narrative. The provider MAY egress via a
              gateway/aggregator *iff* that gateway is zero-retention (Bedrock /
              Vertex in our own cloud, or a public router under a zero-retention
              contract). The current testing provider is LLM_REASONING_PROVIDER;
              the production target is a Claude/GPT-class model. A reasoning
              model is therefore explicitly NOT subject to the payload NEVER-list.

  payload   : offensive tool & exploit-body generation. The provider MUST egress
              via a DIRECT vendor API (LLM_PAYLOAD_TRANSPORT == "direct") -- NEVER
              an aggregator/router, NEVER a reasoning-class model (Claude/GPT).
              Strongest posture: self-hosted open-weight in our own infra so the
              payload prompt never leaves the perimeter.

This module is the SINGLE place that turns the role/provider/transport CONSTANTS
into a live provider object. It is the chokepoint, not a feature:

  * ``resolve_reasoning_provider`` is wired live into ``live_fire/runner.py``.
  * ``resolve_payload_provider`` is the guarded factory every future payload
    caller (Gamma / Phase 4) MUST pass through. It enforces the transport +
    allowlist policy that was previously declared-but-dead config, and reuses the
    one canonical forbidden-model list (``constants.LLM_PAYLOAD_NEVER``).

No payload GENERATION lives here: that body is authored by the payload model in
Phase 4. This module only decides *which* provider may be used and *how* it may
egress. Swapping a provider is therefore a constants edit, never a code edit
(ADR §12.15: "provider swap = config-only").

Relationship to ``DeepSeekProvider.__init__``'s NEVER-guard: that guard protects
the *concrete class* from being instantiated with a reasoning-class model and
applies to either role of DeepSeek. ``assert_payload_policy`` enforces the
broader *payload-role* policy (transport + allowlist + never). Both read the same
``constants`` source of truth, so this is defense-in-depth, not duplicated config
(anti-Lyndon #6/#7).
"""

from __future__ import annotations

from typing import Any, Protocol

from agent_alpha.config import constants
from agent_alpha.llm.providers.deepseek import DeepSeekProvider


class ProviderPolicyError(ValueError):
    """A requested role/provider/transport combination violates ADR §12.15.

    Subclassed (transport vs provider) so callers and tests can assert the
    specific policy breach. A loud, catchable failure -- a payload provider is
    never silently downgraded or substituted (anti-Lyndon #3)."""


class PayloadTransportError(ProviderPolicyError):
    """Payload role was asked to egress via a non-direct transport (gateway/
    aggregator). Payload prompts must never traverse a third-party router."""


class PayloadProviderError(ProviderPolicyError):
    """Payload role was asked to use a model that is not on the payload
    allowlist, or that carries a forbidden (reasoning-class) token."""


class CompletionProvider(Protocol):
    """Structural type every provider must satisfy: a ``complete(**kw)`` returning
    an object exposing ``.text`` (the orchestrator depends on exactly this)."""

    def complete(self, messages: list[dict[str, Any]], max_tokens: int) -> Any: ...


# A builder turns (api_key, model) into a concrete provider. Injected so tests
# stay hermetic and so a future provider backend is a one-line swap here.
class ProviderBuilder(Protocol):
    def __call__(self, *, api_key: str, model: str) -> CompletionProvider: ...


def _default_build(*, api_key: str, model: str) -> CompletionProvider:
    """Default builder: the DeepSeek backend (current testing provider)."""
    return DeepSeekProvider(api_key=api_key, model=model)


def assert_payload_policy(
    model: str,
    *,
    transport: str,
    config: Any = constants,
) -> None:
    """Enforce the ADR §12.15 payload-role policy or raise.

    Order matters: transport is the outermost gate (a forbidden model over a
    forbidden transport is reported as the transport breach first, because the
    transport decision is what risks egress of the payload prompt).
    """
    if transport != "direct":
        raise PayloadTransportError(
            f"payload role requires direct transport, got {transport!r}; "
            "payload prompts must never traverse an aggregator/router (ADR §12.15)"
        )

    model_lower = model.lower()
    for forbidden in config.LLM_PAYLOAD_NEVER:
        if forbidden in model_lower:
            raise PayloadProviderError(
                f"forbidden payload model {model!r}: contains reasoning-class "
                f"token {forbidden!r} (ADR §12.10/§12.15)"
            )

    if model not in config.LLM_PAYLOAD_ALLOWED:
        raise PayloadProviderError(
            f"payload model {model!r} is not on the allowlist "
            f"{list(config.LLM_PAYLOAD_ALLOWED)!r} (ADR §12.15)"
        )


def resolve_reasoning_provider(
    *,
    api_key: str,
    config: Any = constants,
    build: ProviderBuilder = _default_build,
) -> CompletionProvider:
    """Return the provider for the REASONING role (ORIENT / PLAN / narrative).

    Provider identity is config-only: ``constants.LLM_REASONING_PROVIDER``. No
    NEVER-guard here by design -- reasoning may legitimately be a Claude/GPT-class
    model in production (the role split's entire point).
    """
    return build(api_key=api_key, model=config.LLM_REASONING_PROVIDER)


def resolve_payload_provider(
    *,
    api_key: str,
    config: Any = constants,
    build: ProviderBuilder = _default_build,
) -> CompletionProvider:
    """Return the provider for the PAYLOAD role, or raise on policy breach.

    The guarded chokepoint: ``assert_payload_policy`` runs BEFORE any provider is
    built, so a misconfiguration fails loudly at resolution time rather than at
    first offensive call. Generation itself is authored downstream (Phase 4).
    """
    model = config.LLM_PAYLOAD_PROVIDER
    assert_payload_policy(model, transport=config.LLM_PAYLOAD_TRANSPORT, config=config)
    return build(api_key=api_key, model=model)
