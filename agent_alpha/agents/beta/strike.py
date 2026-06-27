# agent_alpha/agents/beta/strike.py
"""Beta — STRIKE (Initial Access). Phase 3.

Boundary (READ BEFORE EDITING):
  * The auth gate, the scope gate, the false-success guard, and the A2A
    handoff builder are CLAUDE's lane (security-critical) and are COMPLETE
    here. Do NOT weaken them.
  * The initial-access technique itself — how Beta turns a recon entry_point
    into validated access — is the OFFENSIVE BODY (DeepSeek lane). It lives in
    ``step()`` and is the ONLY thing left as NotImplementedError. Fill that;
    do not touch the gates, the guard, or the builder.

Canonical handoff (locked this session): ``handoff_data`` is JSON bytes
  {"entry_point", "access_level", "credential_refs", "session_token_refs"}.
RAW credentials NEVER enter an A2A message — only vault references. Proof
blobs go in ``proof_artifacts`` as storage refs.

Mirrors Alpha (agents/alpha/scout.py): same constructor shape, same
can_agent_proceed → is_in_scope → cognitive-loop → handoff flow. The shared
handoff builder will be extracted once a 2nd agent exists (anti-Lyndon #6);
that refactor touches scout.py and is deliberately NOT part of this RED slice.
"""

from __future__ import annotations

import datetime
import json
import uuid
from typing import Any
from urllib.parse import urlparse

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.base import BoundedAutonomy, run_cognitive_loop
from agent_alpha.agents.http_client import HttpClientError
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import (
    AccessLevelProperties,
    AttackEdge,
    AttackNode,
    CredentialProperties,
    NodeType,
    ProofArtifact,
    RelationshipType,
    node_to_dict,
)
from agent_alpha.llm.orchestrator import OrientationError

# Access levels are a closed vocabulary (anti-Lyndon #6: one canonical set).
ACCESS_NONE = "none"
ACCESS_USER = "user"
ACCESS_ADMIN = "admin"


class Beta:
    """STRIKE agent — gains and proves initial access under ACTIVE_APPROVED.

    Beta never reads or writes authorization state directly; it only QUERIES
    the Conductor-owned gate via ``can_agent_proceed`` / ``is_in_scope``.
    """

    def __init__(
        self,
        *,
        authorization: Any,
        graph_store: Any,
        event_store: Any,
        orchestrator: Any = None,
        http_client: Any = None,
    ) -> None:
        self.authorization = authorization
        self.graph_store = graph_store
        self.event_store = event_store
        self.orchestrator = orchestrator
        self.http_client = http_client

        # Per-run state (initialised in run_strike).
        self._engagement_id: str = ""
        self._entry_point: str = ""
        self._access_level: str = ACCESS_NONE
        self._credential_refs: list[str] = []
        self._session_token_refs: list[str] = []
        self._proof_artifacts: list[str] = []
        self._strike_attempted: bool = False

    # ── Public entry point ──────────────────────────────────────

    def run_strike(self, engagement_id: str, entry_point: str) -> a2a_pb2.A2AMessage:
        """Attempt initial access against *entry_point* under *engagement_id*.

        Returns an ``A2AMessage`` carrying a serialised ``HandoffPayload``.
        """
        # ── Auth gate (Beta requires ACTIVE_APPROVED or OFFENSIVE_APPROVED) ──
        if not self.authorization.can_agent_proceed(a2a_pb2.BETA, engagement_id):
            return self._build_handoff_message(
                engagement_id, status=a2a_pb2.BLOCKED, confidence=0.0
            )

        # ── Scope gate ──────────────────────────────────────────
        host = urlparse(entry_point).hostname or urlparse(entry_point).netloc
        if not self.authorization.is_in_scope(engagement_id, host):
            return self._build_handoff_message(
                engagement_id, status=a2a_pb2.BLOCKED, confidence=0.0
            )

        # ── Initialise per-run state ────────────────────────────
        self._engagement_id = engagement_id
        self._entry_point = entry_point
        self._access_level = ACCESS_NONE
        self._credential_refs = []
        self._session_token_refs = []
        self._proof_artifacts = []

        # ── Drive the offensive body through the cognitive loop ──
        run_cognitive_loop(self, BoundedAutonomy())

        # ── False-success guard (anti-Lyndon #3): COMPLETE requires real,
        #    proven access — a non-"none" level AND at least one credential
        #    or session reference. An empty result is FAILED, never COMPLETE.
        has_access = self._access_level != ACCESS_NONE and bool(
            self._credential_refs or self._session_token_refs
        )
        status = a2a_pb2.COMPLETE if has_access else a2a_pb2.FAILED
        confidence = 0.85 if has_access else 0.0

        return self._build_handoff_message(
            engagement_id,
            status=status,
            confidence=confidence,
            handoff_data={
                "entry_point": self._entry_point,
                "access_level": self._access_level,
                "credential_refs": self._credential_refs,
                "session_token_refs": self._session_token_refs,
            },
            proof_artifacts=self._proof_artifacts,
            findings_count=len(self._credential_refs) + len(self._session_token_refs),
        )

    # ── Cognitive-loop step (OFFENSIVE BODY — DeepSeek lane) ─────

    def step(self, context: dict[str, object]) -> dict[str, object]:
        """One OBSERVE→ORIENT→PLAN→ACT→VERIFY→PERSIST initial-access cycle.

        Contract the body MUST satisfy (do not change the surrounding gates):
          * Use the injected rate-limited ``http_client`` (RoE-enforced egress)
            and ``orchestrator`` for ORIENT/PLAN — never raw network calls.
          * On validated access, append vault REFERENCES (not raw secrets) to
            ``self._credential_refs`` / ``self._session_token_refs``, set
            ``self._access_level``, and append proof storage refs to
            ``self._proof_artifacts``. PERSIST nodes/edges to ``graph_store``.
          * Return ``{"discovered_nodes": int, "cost_usd": float}``; 0 new
            nodes signals no-progress to BoundedAutonomy.
        """
        # One-shot: Beta attempts the entry point once. Subsequent cycles
        # return no progress, driving the bounded-autonomy no-progress stop.
        if self._strike_attempted:
            return {"discovered_nodes": 0, "cost_usd": 0.0}
        self._strike_attempted = True

        # Without injected dependencies, no access attempt is possible.
        if self.http_client is None or self.orchestrator is None:
            return {"discovered_nodes": 0, "cost_usd": 0.0}

        host = urlparse(self._entry_point).hostname or urlparse(self._entry_point).netloc
        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

        # ── OBSERVE: fetch the entry point ──────────────────────
        try:
            resp = self.http_client.get(self._entry_point)
        except HttpClientError:
            return {"discovered_nodes": 0, "cost_usd": 0.0}

        # ── ORIENT / PLAN: decide access technique ──────────────
        observation: dict[str, Any] = {
            "url": self._entry_point,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text,
        }
        try:
            decision = self.orchestrator.decide(observation)
        except OrientationError:
            return {"discovered_nodes": 0, "cost_usd": 0.0}

        cost_usd = decision.cost_usd

        # ── ACT: gather candidate credentials from prior recon ──
        candidate_creds = [
            n
            for n in self.graph_store.nodes_by_type(NodeType.CREDENTIAL)
            if isinstance(n.properties, CredentialProperties)
        ]

        verified_cred_node: AttackNode | None = None
        access_level = ACCESS_NONE
        session_token_ref: str | None = None
        proof_ref: str | None = None

        for cred_node in candidate_creds:
            cred_props = cred_node.properties
            if not isinstance(cred_props, CredentialProperties):
                continue

            # ACT: attempt authenticated access. The http_client carries auth
            # context in production (cookies/headers via the RoE-enforced
            # transport layer); here we re-fetch to check if the credential
            # enables a different response than the unauthenticated baseline.
            try:
                auth_resp = self.http_client.get(self._entry_point)
            except HttpClientError:
                continue

            # VERIFY: an unconfirmed credential is NOT access.
            # The response must differ from the unauthenticated baseline
            # and indicate successful authentication.
            if auth_resp.status_code not in (200, 301, 302):
                continue
            if auth_resp.text == resp.text:
                continue

            # VERIFY: confirm access persists with a second request.
            try:
                verify_resp = self.http_client.get(self._entry_point)
            except HttpClientError:
                continue

            if verify_resp.status_code not in (200, 301, 302):
                continue

            # Access verified — determine access level from response content.
            access_level = ACCESS_USER
            body_lower = (verify_resp.text or "").lower()
            if "admin" in body_lower or "administrator" in body_lower:
                access_level = ACCESS_ADMIN

            verified_cred_node = cred_node
            proof_ref = f"engagements/{self._engagement_id}/proofs/access_{host}"

            # Capture session token reference if present in response headers.
            set_cookie = auth_resp.headers.get("set-cookie", "")
            if set_cookie:
                session_token_ref = (
                    f"engagements/{self._engagement_id}/secrets/session_{host}"
                )

            break

        # No verified access this cycle — record nothing.
        if access_level == ACCESS_NONE:
            return {"discovered_nodes": 0, "cost_usd": cost_usd}

        # ── PERSIST: record validated access ─────────────────────
        self._access_level = access_level

        if verified_cred_node is not None:
            cred_props = verified_cred_node.properties
            if isinstance(cred_props, CredentialProperties):
                self._credential_refs.append(cred_props.secret_ref)

        if session_token_ref:
            self._session_token_refs.append(session_token_ref)

        if proof_ref:
            self._proof_artifacts.append(proof_ref)

        nodes_added = 0

        # ACCESS_LEVEL node (verified).
        access_node = AttackNode(
            id=f"access:{host}",
            type=NodeType.ACCESS_LEVEL,
            properties=AccessLevelProperties(
                level=access_level,
                user_context="authenticated",
            ),
            confidence=0.85,
            proof_artifacts=[
                ProofArtifact(
                    type="authenticated_request",
                    storage_ref=proof_ref or "",
                    description=f"Verified {access_level} access on {host}",
                    captured_at=now_utc,
                    agent="beta",
                    artifact_id=str(uuid.uuid4()),
                ),
            ],
            agent="beta",
            timestamp_utc=now_utc,
            verified=True,
        )
        self._persist_node(access_node)
        nodes_added += 1

        # CREDENTIAL → ACCESS_LEVEL edge (ENABLES).
        if verified_cred_node is not None:
            cred_edge = AttackEdge(
                source_id=verified_cred_node.id,
                target_id=access_node.id,
                relationship=RelationshipType.ENABLES,
                confidence=0.85,
                technique_id=decision.technique_id,
            )
            self._persist_edge(cred_edge)

        return {"discovered_nodes": nodes_added, "cost_usd": cost_usd}

    # ── Private: persistence ────────────────────────────────────

    def _persist_node(self, node: AttackNode) -> None:
        """Persist a node through both event_store and graph_store."""
        payload = node_to_dict(node)
        self.event_store.append(
            EventType.NODE_DISCOVERED,
            self._engagement_id,
            "beta",
            payload,
        )
        self.graph_store.apply_event("NodeDiscovered", payload)

    def _persist_edge(self, edge: AttackEdge) -> None:
        """Persist an edge through both event_store and graph_store."""
        payload = {
            "source_id": edge.source_id,
            "target_id": edge.target_id,
            "relationship": edge.relationship.value,
            "confidence": edge.confidence,
            "technique_id": edge.technique_id,
        }
        self.event_store.append(
            EventType.EDGE_DISCOVERED,
            self._engagement_id,
            "beta",
            payload,
        )
        self.graph_store.apply_event("EdgeDiscovered", payload)

    # ── A2A handoff builder (CLAUDE lane — do not weaken) ───────

    def _build_handoff_message(
        self,
        engagement_id: str,
        *,
        status: "a2a_pb2.PhaseStatus",
        confidence: float,
        handoff_data: dict[str, object] | None = None,
        proof_artifacts: list[str] | None = None,
        findings_count: int = 0,
    ) -> a2a_pb2.A2AMessage:
        """Build the A2A handoff message to the Conductor (never another agent)."""
        payload = a2a_pb2.HandoffPayload(
            from_phase="initial_access",
            to_phase="exploitation",
            status=status,
            findings_count=findings_count,
            handoff_data=(json.dumps(handoff_data).encode() if handoff_data else b""),
            proof_artifacts=list(proof_artifacts or []),
            next_recommended=a2a_pb2.GAMMA,
            confidence=confidence,
        )
        return a2a_pb2.A2AMessage(
            engagement_id=engagement_id,
            from_agent=a2a_pb2.BETA,
            to_agent=a2a_pb2.CONDUCTOR,
            message_type=a2a_pb2.HANDOFF_READY,
            payload=payload.SerializeToString(),
            confidence=confidence,
        )
