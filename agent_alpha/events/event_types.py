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

    # ── Phase 3 (run status) ───────────────────────────────────
    ENGAGEMENT_RUN_QUEUED = "EngagementRunQueued"
    ENGAGEMENT_RUN_STARTED = "EngagementRunStarted"
    ENGAGEMENT_RUN_COMPLETED = "EngagementRunCompleted"
    ENGAGEMENT_RUN_FAILED = "EngagementRunFailed"
    ENGAGEMENT_RUN_REFUSED = "EngagementRunRefused"

    # ── Phase 3 (fan-out dispatch, §12.13 / C5) ────────────────
    WORK_UNIT_QUEUED = "WorkUnitQueued"
    # ^ FanOutDispatcher: one event per bounded work unit the Conductor enqueued
    # for an engagement. Aggregating these into the single append-only stream is
    # the deterministic-aggregation invariant (§12.13 #3): all units of a fanned-
    # out phase land in ONE monotonic, gapless engagement sequence.

    # ── Phase 3 (Conductor handoff-consumer, audit A1) ───────────
    HANDOFF_READY = "HandoffReady"
    # ^ Agent task completion: signals Conductor to advance the kill chain.
    # Carries {from_agent, status, next_recommended, seq}.
    AGENT_DISPATCHED = "AgentDispatched"
    # ^ Conductor advance_engagement: enqueued the next agent task. Carries
    # {dispatched_agent, after_handoff_seq} for idempotency.
    AWAITING_APPROVAL = "AwaitingApproval"
    # ^ Conductor parked the engagement: auth gate not satisfied. Carries
    # {blocked_next_agent, reason, requires_human_approval}.
    CHAIN_COMPLETE = "ChainComplete"
    # ^ Conductor halted: no next agent recommended. Carries {reason}.

    # ── Phase 2.5 (passive recon — R2 subdomain discovery) ────────
    PASSIVE_DISCOVERY = "PassiveDiscovery"
    # ^ PassiveDiscovery.discover(): one event per passive crt.sh run.
    # Carries {discovered: [...], in_scope: [...], enumerated: [...]}.

    # ── Phase 3 (recon evidence — WAF discriminator §12.23) ──────
    WAF_BLOCKED = "WafBlocked"
    # ^ A recon probe received a 403 / challenge / block response. Recorded as
    # evidence so a WAF block is NEVER silently treated as "clean / not
    # vulnerable" (anti-false-negative). Carries {host, path, status_code}.

    # ── Phase 6 (governance — §12.36 signed authorization gate) ───
    OWNERSHIP_CHALLENGE_ISSUED = "OwnershipChallengeIssued"
    # ^ Conductor minted a DNS-TXT challenge token for a domain. The operator
    # places the TXT record before calling /authorize. Token is random
    # (secrets.token_urlsafe), NOT derived from the signing key.
    # Carries {domain, token}.

    ENGAGEMENT_AUTHORIZED = "EngagementAuthorized"
    # ^ authorize_engagement(): a signed EngagementProfile was constructed after
    # DNS-TXT ownership verification, consent acceptance, and guardrail check.
    # Carries {sha256, consent, verified_targets, authorization_level, capabilities}.

    ENGAGEMENT_PROFILE_SIGNED = "EngagementProfileSigned"
    # ^ The full signed envelope (profile dict + hmac) persisted so that
    # run_engagement_task can reload the EngagementProfile from the event
    # stream without touching the filesystem. Carries the output of
    # dump_signed_profile(). Distinct from ENGAGEMENT_AUTHORIZED which
    # carries only audit metadata.

    # ── Phase 2.5 (origin-direct reach — §12.33) ──────────────────
    ORIGIN_DIRECT_ATTEMPT = "OriginDirectAttempt"
    # ^ An origin-direct fetch was attempted: agent hit the origin IP directly,
    # bypassing the CDN/WAF front door.  Audit-sensitive because it bypasses the
    # client's WAF — requires signed authorized_origins consent (§12.36).
    # Carries {host, origin_ip, authorized, discovered_via}.

    # ── Phase 2.5 (TLS-impersonation reach — §12.33) ─────────────────
    TLS_IMPERSONATE_ATTEMPT = "TlsImpersonateAttempt"
    # ^ A TLS-impersonation fetch was attempted: agent re-fetched the front-door
    # URL with a real browser TLS/JA3 fingerprint (curl_cffi) to bypass a
    # WAF fingerprint block (403/503). Audit-sensitive because it actively
    # evades a WAF control — requires signed allow_evasion consent (§12.36).
    # Carries {host, technique, authorized}.

    # ── Phase 2.5 (origin-binding proof — §12.46) ────────────────────
    ORIGIN_BINDING_PROVEN = "OriginBindingProven"
    # ^ An origin IP was proven to serve the fronted_host's ownership token
    # via a well-known token fetch (IP-direct with Host header). The event is
    # the ONLY way an IP enters proven_origins (provenance). Carries
    # {engagement_id, fronted_host, origin_ip, proof_type}.
