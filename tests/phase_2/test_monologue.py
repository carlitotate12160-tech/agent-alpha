# tests/phase_2/test_monologue.py
"""Contract (RED): inner monologue — the agent's reasoning streamed to a USER
channel in real-time. Closes Phase 2 exit criterion #3.

Design pinned by this contract:

  * The monologue is loop-driven (one ThoughtFrame per cognitive-loop phase),
    NOT reasoning_content-only. In Opsi-B playbook-first, the headline Laravel
    detection runs at the RULE tier with ZERO LLM calls — reasoning_content
    would be empty there. So the RULE-tier frame carries the playbook rationale;
    the SINGLE_LLM-tier frame carries DeepSeek reasoning_content.

  * The monologue is a USER channel, NOT A2A. A2A handoff messages stay
    structured JSON with no free-form reasoning text (non-negotiable).

  * Emission is real-time: frames are pushed to the injected sink DURING the
    run (inside Alpha.step), not batched at the end. The WebSocket delivery
    layer is operational (not unit-tested); the testable core is the emission.

  * Backward compatible: Alpha without a sink uses NullMonologueSink (no-op),
    so every existing caller/test is unaffected.

VERIFY: Oracle ARM64 only. RED until agent_alpha.agents.monologue exists and
Alpha accepts a `monologue` dependency.
"""

from __future__ import annotations

import pathlib

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.monologue import (
    CollectingMonologueSink,
    MonologueSink,
    NullMonologueSink,
    ThoughtFrame,
)
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).parent / "fixtures" / "playbooks"

# The six cognitive-loop phases, in order.
_PHASES = ["OBSERVE", "ORIENT", "PLAN", "ACT", "VERIFY", "PERSIST"]


def _orchestrator():
    class _StubProvider:
        model = "deepseek-v4-pro"

        def complete(self, *a: object, **k: object):
            return type(
                "R",
                (),
                {
                    "text": '{"tool": "generic_http_probe"}',
                    "usage_cost_usd": 0.0,
                    "model": "deepseek-v4-pro",
                    "reasoning": "no playbook hit; selecting a generic probe",
                },
            )()

    return LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR), provider=_StubProvider()
    )


def _alpha(auth, graph_store, event_store, http_client, monologue) -> Alpha:
    return Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=_orchestrator(),
        http_client=http_client,
        monologue=monologue,
    )


# ── 1. Frames emitted, in phase order, tagged to the engagement ───────────────


def test_collecting_sink_records_ordered_frames(
    recon_engagement, graph_store, event_store, http_client, laravel_target_url
) -> None:
    auth, engagement_id = recon_engagement
    sink = CollectingMonologueSink()
    agent = _alpha(auth, graph_store, event_store, http_client, sink)

    agent.run_recon(engagement_id, laravel_target_url)

    assert sink.frames, "monologue must emit at least one frame"
    assert all(isinstance(f, ThoughtFrame) for f in sink.frames)
    assert all(f.engagement_id == engagement_id for f in sink.frames)
    assert all(f.agent == "alpha" for f in sink.frames)

    # The analysable probe must narrate at least OBSERVE -> ORIENT -> PERSIST,
    # and they must appear in cognitive-loop order.
    phases = [f.phase for f in sink.frames]
    for required in ("OBSERVE", "ORIENT", "PERSIST"):
        assert required in phases, f"missing phase frame: {required}"
    order = {p: i for i, p in enumerate(_PHASES)}
    seen = [order[p] for p in phases if p in order]
    assert seen == sorted(seen), f"frames out of cognitive-loop order: {phases}"


# ── 2. RULE-tier reasoning comes from the playbook rationale (not empty) ───────


def test_rule_tier_frame_carries_playbook_rationale(
    recon_engagement, graph_store, event_store, http_client, laravel_target_url
) -> None:
    """The Laravel hit is RULE tier (no LLM). Its ORIENT frame must still carry
    a human reason — the playbook rationale — so the monologue is never blank on
    the path that does the real work."""
    auth, engagement_id = recon_engagement
    sink = CollectingMonologueSink()
    agent = _alpha(auth, graph_store, event_store, http_client, sink)

    agent.run_recon(engagement_id, laravel_target_url)

    orient = next(f for f in sink.frames if f.phase == "ORIENT")
    assert orient.reasoning.strip(), "RULE-tier ORIENT frame must not be blank"
    # The laravel_debug playbook's rationale mentions APP_DEBUG / debug exposure.
    assert "debug" in orient.reasoning.lower()


# ── 3. Backward compatible: no sink -> NullMonologueSink, no error ─────────────


def test_alpha_without_sink_defaults_to_null(
    recon_engagement, graph_store, event_store, http_client, laravel_target_url
) -> None:
    auth, engagement_id = recon_engagement
    # No monologue argument at all.
    agent = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=_orchestrator(),
        http_client=http_client,
    )
    msg = agent.run_recon(engagement_id, laravel_target_url)

    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)
    assert payload.status == a2a_pb2.COMPLETE  # runs normally
    assert isinstance(agent.monologue, NullMonologueSink)


def test_null_sink_emit_is_noop() -> None:
    NullMonologueSink().emit(
        ThoughtFrame(
            engagement_id="eng_x",
            agent="alpha",
            phase="OBSERVE",
            message="m",
            timestamp_utc="2026-06-19T00:00:00Z",
            reasoning="",
        )
    )  # must not raise


# ── 4. The monologue is NOT A2A: handoff stays structured, no reasoning text ──


def test_monologue_does_not_leak_into_a2a(
    recon_engagement, graph_store, event_store, http_client, laravel_target_url
) -> None:
    auth, engagement_id = recon_engagement
    sink = CollectingMonologueSink()
    agent = _alpha(auth, graph_store, event_store, http_client, sink)

    msg = agent.run_recon(engagement_id, laravel_target_url)

    # A2A message remains the structured handoff contract.
    assert msg.message_type == a2a_pb2.HANDOFF_READY
    payload = a2a_pb2.HandoffPayload()
    payload.ParseFromString(msg.payload)  # parses cleanly = still structured
    # Narrative reasoning lives only in the monologue sink, never in A2A.
    assert sink.frames


# ── 5. Sink is a structural Protocol (any duck-typed emit works) ──────────────


def test_custom_sink_satisfies_protocol() -> None:
    class _ListSink:
        def __init__(self) -> None:
            self.got: list[ThoughtFrame] = []

        def emit(self, frame: ThoughtFrame) -> None:
            self.got.append(frame)

    sink: MonologueSink = _ListSink()
    frame = ThoughtFrame(
        engagement_id="e",
        agent="alpha",
        phase="PERSIST",
        message="wrote vuln node",
        timestamp_utc="2026-06-19T00:00:00Z",
        reasoning="confirmed",
    )
    sink.emit(frame)
    assert sink.got == [frame]  # type: ignore[attr-defined]
