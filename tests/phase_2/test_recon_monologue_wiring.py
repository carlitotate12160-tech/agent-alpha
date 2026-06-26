"""RED: build_recon_pipeline must wire a tenant-scoped RedisMonologueSink into Alpha.

Without this, the worker builds Alpha with the default NullMonologueSink and every
ThoughtFrame is DISCARDED — the inner monologue never reaches the user. This is the
gap that made the Phase-2 "streamed to user in real time" criterion only LOOK done
(sink abstraction + unit tests green, but no live wiring — anti-Lyndon #2).

Hermetic: the heavy LLM provider is stubbed; a fake publisher captures what the
wired sink emits. RED until build_recon_pipeline accepts a publisher seam and
constructs Alpha(monologue=RedisMonologueSink(...)).

Run on Oracle ARM64:
  .venv/bin/python3 -m pytest tests/phase_2/test_recon_monologue_wiring.py -v
"""

from __future__ import annotations

from agent_alpha.agents.monologue import ThoughtFrame
from agent_alpha.agents.monologue_stream import channel_for
from agent_alpha.conductor import recon_runner
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.events.store import InMemoryEventStore


class _FakePublisher:
    def __init__(self) -> None:
        self.published: list[tuple[str, str]] = []

    def publish(self, channel: str, payload: str) -> None:
        self.published.append((channel, payload))


def test_build_recon_pipeline_wires_tenant_scoped_monologue_sink(monkeypatch) -> None:
    # Stub the only live dependency so the pipeline builds hermetically.
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-not-used")
    monkeypatch.setattr(recon_runner, "resolve_reasoning_provider", lambda api_key: object())

    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    pub = _FakePublisher()

    pipeline = recon_runner.build_recon_pipeline(
        engagement_id="eng_1",
        tenant_id="t1",
        auth=auth,
        store=store,
        publisher=pub,
    )

    # The Alpha the worker actually runs must carry a sink that publishes to the
    # tenant+engagement channel — not the default NullMonologueSink.
    pipeline.alpha.monologue.emit(
        ThoughtFrame(
            engagement_id="eng_1",
            agent="alpha",
            phase="ACT",
            message="probing target",
            timestamp_utc="2026-06-26T00:00:00Z",
        )
    )

    assert pub.published, "Alpha emitted nothing — sink not wired (still NullMonologueSink)"
    channel, _payload = pub.published[0]
    assert channel == channel_for("t1", "eng_1")
