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

from collections.abc import Iterable

from agent_alpha.conductor.models import EngagementRecord, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import AgentEvent

# ── Typed payload helpers (no type: ignore needed) ────────────


def _opt_str(p: dict[str, object], key: str) -> str | None:
    """Optional string field — absent or non-str → None."""
    v = p.get(key)
    return v if isinstance(v, str) else None


def _req_int(p: dict[str, object], key: str) -> int:
    """Required int field — raises ValueError on wrong type."""
    v = p.get(key)
    if not isinstance(v, int):
        raise ValueError(f"{key} must be int, got {type(v).__name__}")
    return v


def _str_list(d: dict[str, object], key: str) -> list[str]:
    """Required list[str] field — raises ValueError on wrong shape."""
    v = d.get(key, [])
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError(f"{key} must be list[str]")
    return list(v)


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
            state=_req_int(payload, "state"),
            scope=None,
            sow_hash=None,
            created_at=event.timestamp_utc,
            updated_at=event.timestamp_utc,
            stopped_reason=None,
            tenant_id=_opt_str(payload, "tenant_id"),
        )

    # All remaining event types require an existing record.
    if record is None:
        return None

    if event.event_type == EventType.STATE_TRANSITIONED:
        record.state = _req_int(payload, "to_state")
        record.updated_at = event.timestamp_utc

        # Scope — persisted in the recon transition payload (gate-critical).
        scope_data = payload.get("scope")
        if isinstance(scope_data, dict):
            sc = Scope(
                ip_ranges=_str_list(scope_data, "ip_ranges"),
                domains=_str_list(scope_data, "domains"),
                exclusions=_str_list(scope_data, "exclusions"),
            )
            sc.verified = bool(scope_data.get("verified", False))
            record.scope = sc

        # sow_hash — hex string → bytes (optional).
        sow = payload.get("sow_hash")
        if isinstance(sow, str):
            record.sow_hash = bytes.fromhex(sow)

        return record

    if event.event_type == EventType.EMERGENCY_STOP:
        record.state = _req_int(payload, "to_state")
        record.stopped_reason = _opt_str(payload, "reason")
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
