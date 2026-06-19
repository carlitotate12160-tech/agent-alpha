# agent_alpha/agents/monologue.py
"""Inner monologue — the agent's reasoning streamed to a USER channel.

A USER-facing narrative channel, DISTINCT from A2A (which stays structured
JSON). One :class:`ThoughtFrame` per cognitive-loop phase is emitted to an
injected :class:`MonologueSink` in real time during a run. The WebSocket
delivery layer is operational (not unit-tested); this module is the testable
emission core.
"""

from __future__ import annotations

import dataclasses
import typing


@dataclasses.dataclass(frozen=True)
class ThoughtFrame:
    """One human-readable step of an agent's reasoning.

    ``phase`` is one of OBSERVE | ORIENT | PLAN | ACT | VERIFY | PERSIST.
    ``reasoning`` carries the *why* — the playbook rationale on the RULE tier,
    the LLM ``reasoning_content`` on the SINGLE_LLM tier (empty otherwise).
    """

    engagement_id: str
    agent: str
    phase: str
    message: str
    timestamp_utc: str
    reasoning: str = ""


class MonologueSink(typing.Protocol):
    """Anything that can receive ThoughtFrames in real time."""

    def emit(self, frame: ThoughtFrame) -> None: ...


class NullMonologueSink:
    """Default no-op sink — an agent runs identically with no observer."""

    def emit(self, frame: ThoughtFrame) -> None:
        return None


class CollectingMonologueSink:
    """In-memory sink: keeps every frame in arrival order (tests, replay)."""

    def __init__(self) -> None:
        self.frames: list[ThoughtFrame] = []

    def emit(self, frame: ThoughtFrame) -> None:
        self.frames.append(frame)
