# agent_alpha/memory/engagement.py
# CQRS read-side projection: replays the append-only AgentEvent stream
# into a queryable EngagementMemoryRecord for post-engagement learning/audit.
#
# ADR §8o-1, §12.11: EngagementMemory is a pure projection of the event
# stream — never written to directly.  This module mirrors the
# AttackGraphProjector pattern (agent_alpha/events/projectors.py).
#
# No direct PostgreSQL/SQLAlchemy/asyncpg imports — EngagementMemoryStore
# is a Protocol only; the concrete DB-backed implementation lives in a
# separate follow-up file.

from __future__ import annotations

import dataclasses
import typing

from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import AgentEvent, EventStore

# ── Read-model record ────────────────────────────────────────────────


@dataclasses.dataclass(frozen=True)
class EngagementMemoryRecord:
    """Immutable post-engagement learning/audit snapshot.

    Every field is derived purely from the event stream by
    ``EngagementMemoryProjector.project()``.  Per ADR K3, §8c, §8j-2.
    """

    engagement_id: str
    confirmed_exploits: list[dict[str, object]]
    failed_attempts: list[dict[str, object]]
    time_to_exploit_per_phase: dict[str, float]
    tool_success_rates: dict[str, float]
    proof_artifacts: list[dict[str, object]]
    scratchpad_snapshot: dict[str, object]
    event_stream_id: str
    last_sequence_number: int


# ── Store protocol ───────────────────────────────────────────────────


@typing.runtime_checkable
class EngagementMemoryStore(typing.Protocol):
    """Read-model persistence interface for engagement memory.

    Mirrors ``graph/store.py``'s ``GraphStore`` Protocol in style.
    The only mutation entry point is ``upsert``; implementations MUST
    treat it as an idempotent overwrite (not an append).
    """

    def upsert(self, record: EngagementMemoryRecord) -> None:
        """Persist *record*, overwriting any prior record for the same
        ``engagement_id``."""
        ...

    def get(self, engagement_id: str) -> EngagementMemoryRecord | None:
        """Return the stored record, or ``None`` if not yet projected."""
        ...


# ── In-memory store (for testing) ────────────────────────────────────


class InMemoryEngagementMemoryStore:
    """Minimal dict-backed ``EngagementMemoryStore`` for unit tests.

    Mirrors how ``NetworkXGraphStore`` implements ``GraphStore`` — a
    lightweight, zero-dependency concrete store.
    """

    def __init__(self) -> None:
        self._records: dict[str, EngagementMemoryRecord] = {}

    def upsert(self, record: EngagementMemoryRecord) -> None:
        self._records[record.engagement_id] = record

    def get(self, engagement_id: str) -> EngagementMemoryRecord | None:
        return self._records.get(engagement_id)


# ── Projector ────────────────────────────────────────────────────────


class EngagementMemoryProjector:
    """Replays an ``EventStore`` stream into an ``EngagementMemoryStore``.

    This class is the glue between the write-side (``EventStore``) and
    the read-side (``EngagementMemoryStore``).  All derivation logic is
    a pure function of the event payloads — no side effects besides the
    final ``memory_store.upsert(record)``.
    """

    def __init__(
        self,
        event_store: EventStore,
        memory_store: EngagementMemoryStore,
    ) -> None:
        self._event_store = event_store
        self._memory_store = memory_store

    # ------------------------------------------------------------------
    # Full rebuild
    # ------------------------------------------------------------------

    def project(self, engagement_id: str) -> EngagementMemoryRecord:
        """Full replay: derive every field from the complete event stream.

        §12.11: "anything reconstructable from the event log MAY be
        volatile" — we always rebuild from scratch for correctness.
        """
        events: list[AgentEvent] = self._event_store.get_events(engagement_id)
        record = self._build_record(engagement_id, events)
        self._memory_store.upsert(record)
        return record

    # ------------------------------------------------------------------
    # Consistency verification
    # ------------------------------------------------------------------

    def verify_projection(
        self,
        engagement_id: str,
        fresh_store_factory: typing.Callable[[], EngagementMemoryStore],
    ) -> bool:
        """Replay-and-compare consistency check.

        Builds a **fresh** ``EngagementMemoryStore`` (via
        *fresh_store_factory*) and projects the full event stream into
        it, then compares against the record already in
        ``self._memory_store``.

        Returns ``True`` when the current projection is drift-free,
        ``False`` otherwise.  This is a read-only check — it does
        **not** replace ``self._memory_store``.

        The factory pattern keeps this class engine-agnostic: only the
        *caller* decides which concrete ``EngagementMemoryStore`` to
        construct.
        """
        fresh_store: EngagementMemoryStore = fresh_store_factory()
        events: list[AgentEvent] = self._event_store.get_events(engagement_id)
        fresh_record = self._build_record(engagement_id, events)
        fresh_store.upsert(fresh_record)

        existing_record = self._memory_store.get(engagement_id)
        if existing_record is None:
            return False

        return existing_record == fresh_record

    # ------------------------------------------------------------------
    # Internal derivation logic
    # ------------------------------------------------------------------

    @staticmethod
    def _build_record(
        engagement_id: str,
        events: list[AgentEvent],
    ) -> EngagementMemoryRecord:
        """Pure function: derive an ``EngagementMemoryRecord`` from an
        ordered event sequence.  No I/O, no side effects."""
        confirmed_exploits: list[dict[str, object]] = []
        failed_attempts: list[dict[str, object]] = []
        proof_artifacts: list[dict[str, object]] = []
        scratchpad_snapshot: dict[str, object] = {}
        scratchpad_max_seq: int = -1

        # Phase 1 derivation — tool_success_rates and
        # time_to_exploit_per_phase are left structurally correct
        # but will return {} until outcome-tagging events exist.
        time_to_exploit_per_phase: dict[str, float] = {}
        tool_success_rates: dict[str, float] = {}

        last_sequence_number: int = 0

        for event in events:
            last_sequence_number = max(last_sequence_number, event.sequence_number)

            if event.event_type == EventType.EXPLOIT_CONFIRMED:
                confirmed_exploits.append(dict(event.payload))

            elif event.event_type == EventType.EXPLOIT_FAILED:
                failed_attempts.append(dict(event.payload))

            elif event.event_type == EventType.PROOF_ARTIFACT_RECORDED:
                proof_artifacts.append(dict(event.payload))

            elif event.event_type == EventType.SCRATCHPAD_SNAPSHOTTED:
                if event.sequence_number > scratchpad_max_seq:
                    scratchpad_max_seq = event.sequence_number
                    scratchpad_snapshot = dict(event.payload)

            # TODO(Phase 2): populate time_to_exploit_per_phase and
            # tool_success_rates from OutcomeTag-tagged events once
            # agents emit them.  The iteration logic above already
            # processes the full event stream; add elif branches for
            # the Phase 2 outcome event types here.

        return EngagementMemoryRecord(
            engagement_id=engagement_id,
            confirmed_exploits=confirmed_exploits,
            failed_attempts=failed_attempts,
            time_to_exploit_per_phase=time_to_exploit_per_phase,
            tool_success_rates=tool_success_rates,
            proof_artifacts=proof_artifacts,
            scratchpad_snapshot=scratchpad_snapshot,
            event_stream_id=engagement_id,
            last_sequence_number=last_sequence_number,
        )
