# agent_alpha/conductor/engagement_reducer.py
# Pure, stateless reducer — the single source of truth for folding engagement-
# lifecycle events into EngagementRecord state.
#
# ADR §8o-1 / §12.11: state = projection of the append-only event stream.
# Follows the same pattern as graph/store.py rebuild_from_events.
#
# This module is intentionally side-effect-free: no store dependency, no I/O.
# It imports EngagementRecord and Scope (canonical types, anti-Lyndon #6) and
# AgentEvent (the canonical event type from events/store.py).

from __future__ import annotations

from typing import Iterable

from agent_alpha.conductor.models import EngagementRecord, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import AgentEvent


def _scope_from_payload(raw: dict[str, object]) -> Scope:
    """Reconstruct a Scope from a serialized payload dict.

    Expected shape: {"ip_ranges": [...], "domains": [...], "exclusions": [...],
    "verified": bool}.
    """
    return Scope(
        ip_ranges=list(raw.get("ip_ranges", [])),  # type: ignore[arg-type]
        domains=list(raw.get("domains", [])),  # type: ignore[arg-type]
        exclusions=list(raw.get("exclusions", [])),  # type: ignore[arg-type]
        verified=bool(raw.get("verified", False)),
    )


def _sow_hash_from_payload(raw: object) -> bytes | None:
    """Decode sow_hash from its payload representation.

    In the event payload, sow_hash is stored as a hex string for JSON
    serializability. This function handles both hex-string (durable path)
    and raw bytes (legacy/in-memory edge case).
    """
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        return bytes.fromhex(raw)
    return None


def apply_event(
    record: EngagementRecord | None,
    event: AgentEvent,
) -> EngagementRecord | None:
    """Fold a single event into the current engagement record.

    Pure function. Returns the new record state. Unknown event types are
    treated as no-ops (forward-compatible).

    If *record* is ``None`` and the event is not ``ENGAGEMENT_CREATED``,
    returns ``None`` (orphan event — skip).
    """
    payload = event.payload

    if event.event_type == EventType.ENGAGEMENT_CREATED:
        return EngagementRecord(
            engagement_id=event.engagement_id,
            client_id=str(payload.get("client_id", "")),
            target=str(payload.get("target", "")),
            state=int(payload.get("state", 0)),  # type: ignore[arg-type]
            scope=None,
            sow_hash=None,
            created_at=event.timestamp_utc,
            updated_at=event.timestamp_utc,
            stopped_reason=None,
            tenant_id=payload.get("tenant_id"),  # type: ignore[assignment]
        )

    # All remaining event types require an existing record.
    if record is None:
        return None

    if event.event_type == EventType.STATE_TRANSITIONED:
        record.state = int(payload.get("to_state", record.state))  # type: ignore[arg-type]
        record.updated_at = event.timestamp_utc

        # Scope — persisted in the recon transition payload (gate-critical).
        scope_raw = payload.get("scope")
        if scope_raw is not None and isinstance(scope_raw, dict):
            record.scope = _scope_from_payload(scope_raw)

        # sow_hash — persisted in the offensive transition payload.
        sow_raw = payload.get("sow_hash")
        if sow_raw is not None:
            record.sow_hash = _sow_hash_from_payload(sow_raw)

        return record

    if event.event_type == EventType.EMERGENCY_STOP:
        record.state = int(payload.get("to_state", record.state))  # type: ignore[arg-type]
        record.stopped_reason = payload.get("reason")  # type: ignore[assignment]
        record.updated_at = event.timestamp_utc
        return record

    # Unknown event type → no-op (forward-compatible).
    return record


def rebuild_engagement(
    events: Iterable[AgentEvent],
) -> EngagementRecord | None:
    """Fold all events into an EngagementRecord.

    Returns the final record, or ``None`` if no ``ENGAGEMENT_CREATED`` event
    was found in the stream.
    """
    record: EngagementRecord | None = None
    for event in events:
        record = apply_event(record, event)
    return record
