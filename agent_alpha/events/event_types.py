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
    # GAP-189: recon ran but its OUTCOME was not a clean COMPLETE — a WAF-walled sweep
    # (a sellable defensive-validation result per GAP-045, NOT a failure). Layered on top
    # of ENGAGEMENT_RUN_COMPLETED (task-lifecycle/audit) so /run-status reports honestly.
    ENGAGEMENT_RUN_PARTIAL = "EngagementRunPartial"
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

    # ── Phase 4 (entry-selection observability — honest-seal) ───────
    STRIKE_ENTRY_SELECTED = "StrikeEntrySelected"
    # ^ Conductor selected Beta's strike entry_point (auth-surface ASSET) instead of
    # the default apex. Carries {selected_entry, matched_label, fallback_to_default,
    # candidates_considered}. Emitted BEFORE build_applicators + run_strike so the audit
    # precedes the action.

    # ── Phase 4 (GAP-035 multi-candidate entry-selection) ─────────
    STRIKE_CANDIDATE_ATTEMPTED = "StrikeCandidateAttempted"
    # ^ Conductor dispatched Beta at ONE ranked auth-surface candidate. Carries
    # {entry, host}. One event per in-scope candidate struck — this is the per-host
    # audit line proving the dispatch loop iterated (answers "agent repeats 2x").
    STRIKE_CANDIDATE_SKIPPED = "StrikeCandidateSkipped"
    # ^ Conductor skipped a ranked candidate that failed the per-host in-scope gate.

    # ── Phase 4 (GAP-116-B post-access authenticated crawl — §12.32) ──
    AUTHENTICATED_SURFACE_DISCOVERED = "AuthenticatedSurfaceDiscovered"
    # ^ The won session revealed an auth-only surface an unauthenticated request did NOT
    # (the §12.32 auth-vs-unauth diff). Carries {host, stack, surface, path, depth1,
    # auth_vs_unauth} — the SURFACE, never page content (no PII). Feeds the §12.43 oracle.
    AUTHENTICATED_CRAWL_COMPLETE = "AuthenticatedCrawlComplete"
    # ^ Coverage-honest terminator: emitted after the crawl even when 0 surfaces found
    # (anti-#3 — absence is recorded, not silent). Carries {host, surfaces_discovered}.
    AUTHENTICATED_CRAWL_SKIPPED = "AuthenticatedCrawlSkipped"
    # ^ Honest no-op: no won session (carrier absent) or no playbook for the detected
    # stack. Carries {host, reason, tech_stack?}.
    # Carries {entry, host, reason}. The authoritative scope gate stays in Conductor.

    # ── §12.64 Step 0 (recon coverage honesty — attempt instrumentation) ──
    RECON_TECHNIQUE_ATTEMPTED = "ReconTechniqueAttempted"
    # ^ Alpha dispatched a recon technique at a responding surface (regardless of finding).
    # Carries {host, technique_id}. The recon analog of StrikeCandidateAttempted: it marks a
    # coverage-catalog technique TESTED by IDENTITY (host, technique_id) so `not_run` stops
    # conflating "not attempted" with "attempted but not instrumented" (§12.64 / GAP-187b).

    # ── §12.67-S1 (fingerprint-flank origin service observation) ─────
    FINGERPRINT_FLANK_ATTEMPTED = "FingerprintFlankAttempted"
    # ^ Alpha attempted the origin-flank for service headers because the edge response
    # carried no version-bearing product. Emitted on EVERY exit (minted / no_new_service /
    # origin_unreachable / origin_unbound) so the event stream, not the graph alone, is the
    # machine-readable proof of the flank outcome (§12.64 / §8o-1). Carries
    # {host, outcome, origin_ip, products: [{name, version}]}.
    CVE_HYPOTHESIS_RAISED = "CveHypothesisRaised"

    # ── Phase 2.5 (passive recon — R2 subdomain discovery) ────────
    PASSIVE_DISCOVERY = "PassiveDiscovery"
    # ^ PassiveDiscovery.discover(): one event per passive crt.sh run.
    # Carries {discovered: [...], in_scope: [...], enumerated: [...]}.

    # ── Phase 4 (§12.48 passive-first recon — OSINT before touch) ─
    PASSIVE_INTEL_GATHERED = "PassiveIntelGathered"
    # ^ record_passive_intel(): unified PassiveIntelMap for one domain, appended
    # BEFORE any active recon event (§12.48). Slice-1 carries the crt.sh-derived
    # surface; later slices add VT/DNS fields. Payload = the full map.

    # ── Phase 3 (recon evidence — WAF discriminator §12.23) ──────
    WAF_BLOCKED = "WafBlocked"
    # ^ A recon probe received a 403 / challenge / block response. Recorded as
    # evidence so a WAF block is NEVER silently treated as "clean / not
    # vulnerable" (anti-false-negative). Carries {host, path, status_code}.

    # ── Phase 4 (dead-host short-circuit — GAP-029 instinct #2) ──
    HOST_ABANDONED = "HostAbandoned"
    EGRESS_BLOCKED = "EgressBlocked"
    # ^ A host's ROOT probe raised HttpClientError (transport-unreachable:
    # DNS failure, connection refused, timeout). All queued paths for that
    # host are pruned and future enqueues are refused for this run. Carries
    # {host, reason, trigger}. Append-only audit parity with WAF_BLOCKED so
    # the abandonment is replayable and never silently discarded.

    # ── Phase 4 (#51 slice-1 — engagement-level wall verdict) ─────
    ENGAGEMENT_WALLED = "EngagementWalled"
    # ^ derive_wall_verdict(): EVERY target of the engagement ended non-COMPLETE AND at
    # least one host emitted WAF_BLOCKED — the whole engagement is behind a WAF/CDN and
    # the per-host origin reach did not save it. Append-only audit-of-record so a walled
    # run is NEVER reported as "clean / nothing found" (anti-#3 false-success). The honest
    # trigger primitive a future active origin-hunt (slice-2) consumes. Carries
    # {blocked_hosts: [...], target_count, reason}.

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
    # Carries {host, origin_ip, authorized, discovered_via, path}. `path` is the
    # origin-direct request-target with query VALUES redacted (keys kept, e.g.
    # "/x?token=REDACTED") — never the raw query, since the store is append-only (GAP-196).

    # ── Phase 2.5 (TLS-impersonation reach — §12.33) ─────────────────
    TLS_IMPERSONATE_ATTEMPT = "TlsImpersonateAttempt"
    # ^ A TLS-impersonation fetch was attempted: agent re-fetched the front-door
    # URL with a real browser TLS/JA4 fingerprint (curl_cffi, chrome131) to bypass a
    # WAF fingerprint block (403/503). Audit-sensitive because it actively
    # evades a WAF control — requires signed allow_evasion consent (§12.36).
    # Carries {host, technique, authorized}.

    # ── Phase 2.5 (origin-binding proof — §12.46) ────────────────────
    ORIGIN_BINDING_PROVEN = "OriginBindingProven"
    # ^ An origin IP was proven to serve the fronted_host's ownership token
    # via a well-known token fetch (IP-direct with Host header). The event is
    # the ONLY way an IP enters proven_origins (provenance). Carries
    # {engagement_id, fronted_host, origin_ip, proof_type}.
