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
    # ^ AuthorizationStateMachine.emergency_stop(): state machine flips to
    # EMERGENCY_STOP. Fires the instant the state changes — before any
    # Celery task revocation has actually run.

    # ── Phase 0 (emergency stop handler) ────────────────────────
    EMERGENCY_STOP_EXECUTED = "EmergencyStopExecuted"
    # ^ EmergencyStopHandler.execute(): kill-switch operational work
    # (task revocation) has completed. A real downstream consequence of
    # EMERGENCY_STOP, not a duplicate — the two are temporally distinct
    # and the gap between them is itself auditable (was revocation slow?
    # did it fail?). conductor/authorization.py emits EMERGENCY_STOP;
    # conductor/emergency.py emits EMERGENCY_STOP_EXECUTED. Never conflate
    # the two into one event type.

    # ── Phase 1 (graph projection) ─────────────────────────────
    NODE_DISCOVERED = "NodeDiscovered"
    EDGE_DISCOVERED = "EdgeDiscovered"
    NODE_VERIFIED = "NodeVerified"

    # ── Phase 1 (engagement memory) ────────────────────────────
    SCRATCHPAD_SNAPSHOTTED = "ScratchpadSnapshotted"
    EXPLOIT_CONFIRMED = "ExploitConfirmed"
    EXPLOIT_FAILED = "ExploitFailed"
    PROOF_ARTIFACT_RECORDED = "ProofArtifactRecorded"
