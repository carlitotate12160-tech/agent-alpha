# agent_alpha/events/event_types.py
# Canonical event-type enum — the single source of truth for event_type
# strings used throughout the system.
#
# ADR §12.11: all event_type string comparisons MUST go through this enum,
# never raw strings.  New event types are added here and only here.

from __future__ import annotations

import enum


class EventType(enum.StrEnum):
    """Canonical event-type identifiers.

    Inherits from ``StrEnum`` so that ``EventType.SCRATCHPAD_SNAPSHOTTED``
    compares equal to the raw string ``"ScratchpadSnapshotted"`` — this
    keeps the EventStore (which stores plain ``str``) interoperable
    without explicit ``.value`` access everywhere.
    """

    # ── Phase 0 (authorization / lifecycle) ────────────────────
    ENGAGEMENT_CREATED = "EngagementCreated"
    STATE_TRANSITIONED = "StateTransitioned"
    EMERGENCY_STOP = "EmergencyStop"

    # ── Phase 1 (graph projection) ─────────────────────────────
    NODE_DISCOVERED = "NodeDiscovered"
    EDGE_DISCOVERED = "EdgeDiscovered"
    NODE_VERIFIED = "NodeVerified"

    # ── Phase 1 (engagement memory) ────────────────────────────
    SCRATCHPAD_SNAPSHOTTED = "ScratchpadSnapshotted"
    EXPLOIT_CONFIRMED = "ExploitConfirmed"
    EXPLOIT_FAILED = "ExploitFailed"
    PROOF_ARTIFACT_RECORDED = "ProofArtifactRecorded"
