# agent_alpha/agents/monologue_stream.py
"""Cross-process delivery of the inner monologue to a USER channel.

Engagements run in a Celery worker; the user connects to the FastAPI conductor in
ANOTHER process. Frames cross that boundary via Redis pub/sub on a per-engagement,
per-tenant channel. This module is the TESTABLE core (publish/subscribe seam +
channel SSOT + redaction). The real redis-py adapters and the WebSocket endpoint are
the operational layer (built in conductor, verified on Oracle).

SECURITY:
  * Frames are USER-facing narrative, NOT A2A — but they may echo target content, so
    every text field is REDACTED before it leaves the process (reuse redact_secrets).
  * The channel is tenant-scoped. The WS endpoint MUST verify the caller's JWT tenant
    == the engagement's tenant before subscribing (auth gate — never softened).
"""

from __future__ import annotations

import json
import typing

from agent_alpha.agents.monologue import ThoughtFrame
from agent_alpha.llm.redaction import redact_secrets


def channel_for(tenant_id: str, engagement_id: str) -> str:
    """Single source of truth for the per-tenant, per-engagement monologue channel."""
    return f"monologue:{tenant_id}:{engagement_id}"


class MonologuePublisher(typing.Protocol):
    """Thin seam over redis-py PUBLISH (so the core is hermetically testable)."""

    def publish(self, channel: str, payload: str) -> None: ...


class MonologueSubscriber(typing.Protocol):
    """Thin seam over redis-py SUBSCRIBE/listen."""

    def listen(self, channel: str) -> typing.Iterator[str]: ...


class RedisMonologueSink:
    """A MonologueSink (structurally conforms to agents.monologue.MonologueSink) that
    publishes REDACTED frames to a tenant-scoped channel. Publisher is injected."""

    def __init__(self, publisher: MonologuePublisher, tenant_id: str, engagement_id: str) -> None:
        self._publisher = publisher
        self._tenant_id = tenant_id
        self._engagement_id = engagement_id

    def emit(self, frame: ThoughtFrame) -> None:
        """Redact the human-readable fields, serialize, and publish to the scoped
        channel. message/reasoning may echo target content, so both are redacted; the
        structural fields (ids, phase, timestamp) are not secret."""
        payload = json.dumps(
            {
                "engagement_id": frame.engagement_id,
                "agent": frame.agent,
                "phase": frame.phase,
                "message": redact_secrets(frame.message),
                "timestamp_utc": frame.timestamp_utc,
                "reasoning": redact_secrets(frame.reasoning),
            }
        )
        self._publisher.publish(channel_for(self._tenant_id, self._engagement_id), payload)


def stream_monologue(
    subscriber: MonologueSubscriber, tenant_id: str, engagement_id: str
) -> typing.Iterator[ThoughtFrame]:
    """Subscribe to the scoped channel, parse each JSON payload back into a
    ThoughtFrame, and yield in arrival order. A subscriber for a different
    tenant/engagement listens on a different channel and receives nothing — tenant
    isolation by construction."""
    for raw in subscriber.listen(channel_for(tenant_id, engagement_id)):
        data = json.loads(raw)
        yield ThoughtFrame(
            engagement_id=data["engagement_id"],
            agent=data["agent"],
            phase=data["phase"],
            message=data["message"],
            timestamp_utc=data["timestamp_utc"],
            reasoning=data.get("reasoning", ""),
        )
