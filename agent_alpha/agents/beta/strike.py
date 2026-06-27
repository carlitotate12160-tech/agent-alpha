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
        secrets_manager: Any = None,
    ) -> None:
        self.authorization = authorization
        self.graph_store = graph_store
        self.event_store = event_store
        self.orchestrator = orchestrator
        self.http_client = http_client
        self._secrets_manager = secrets_manager

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
        # One-shot: Beta attempts initial access once. Subsequent cycles
        # return no progress, driving the bounded-autonomy no-progress stop.
        if self._strike_attempted:
            return {"discovered_nodes": 0, "cost_usd": 0.0}
        self._strike_attempted = True

        host = urlparse(self._entry_point).hostname or urlparse(self._entry_point).netloc
        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

        # ── OBSERVE: fetch entry point unauthenticated (baseline) ──
        try:
            baseline_resp = self.http_client.get(self._entry_point)
        except HttpClientError:
            return {"discovered_nodes": 0, "cost_usd": 0.0}

        # ── ORIENT / PLAN ──────────────────────────────────────────
        observation: dict[str, Any] = {
            "url": self._entry_point,
            "status": baseline_resp.status_code,
            "headers": dict(baseline_resp.headers),
            "body": baseline_resp.text,
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
        proof_storage_ref: str | None = None
        failed_attempts = 0
        max_failures = 3  # lockout-aware: stop after small threshold

        for cred_node in candidate_creds:
            if failed_attempts >= max_failures:
                break

            cred_props = cred_node.properties
            if not isinstance(cred_props, CredentialProperties):
                continue

            # Resolve the credential: retrieve the real secret from the vault
            # via its secret_ref. If no secrets_manager is injected, use the
            # secret_ref as the credential value (fallback for test doubles).
            credential_value = cred_props.secret_ref
            if self._secrets_manager is not None:
                try:
                    credential_value = self._secrets_manager.retrieve(cred_props.secret_ref)
                except Exception:
                    failed_attempts += 1
                    continue

            # APPLY the credential through the authed transport — the credential
            # MUST reach the wire (anti-Lyndon #3: no proof-theatre).
            auth_headers = {"Authorization": f"Bearer {credential_value}"}
            try:
                auth_resp = self.http_client.post(
                    self._entry_point,
                    data={"username": cred_props.username, "password": credential_value},
                )
            except HttpClientError:
                failed_attempts += 1
                continue

            # VERIFY: authed response must differ from baseline AND indicate
            # success. Identical baseline vs authed ⇒ NO access (a credential
            # that changes nothing is not access).
            if auth_resp.status_code not in (200, 301, 302):
                failed_attempts += 1
                continue
            if auth_resp.text == baseline_resp.text:
                failed_attempts += 1
                continue

            # VERIFY: confirm with a second authed request.
            try:
                verify_resp = self.http_client.get(
                    self._entry_point,
                    headers=auth_headers,
                )
            except HttpClientError:
                failed_attempts += 1
                continue

            if verify_resp.status_code not in (200, 301, 302):
                failed_attempts += 1
                continue
            if verify_resp.text == baseline_resp.text:
                failed_attempts += 1
                continue

            # Access verified — determine access level from response content.
            access_level = ACCESS_USER
            body_lower = (verify_resp.text or "").lower()
            if "admin" in body_lower or "administrator" in body_lower:
                access_level = ACCESS_ADMIN

            verified_cred_node = cred_node

            # CAPTURE REAL PROOF: store the actual authenticated request/response
            # pair as a proof artifact via the event store. The event_id is a
            # real, retrievable storage_ref — no synthesized path strings.
            proof_data = {
                "entry_point": self._entry_point,
                "username": cred_props.username,
                "secret_ref": cred_props.secret_ref,
                "baseline_status": baseline_resp.status_code,
                "authed_status": auth_resp.status_code,
                "verify_status": verify_resp.status_code,
                "authed_body_excerpt": (auth_resp.text or "")[:500],
                "verify_body_excerpt": (verify_resp.text or "")[:500],
                "captured_at": now_utc,
            }
            proof_event = self.event_store.append(
                EventType.PROOF_ARTIFACT_RECORDED,
                self._engagement_id,
                "beta",
                proof_data,
            )
            proof_storage_ref = proof_event.event_id

            # Capture session token reference from set-cookie header.
            set_cookie = auth_resp.headers.get("set-cookie", "")
            if set_cookie:
                if self._secrets_manager is not None:
                    session_record = self._secrets_manager.store(
                        label=f"session:{host}",
                        value=set_cookie,
                        engagement_id=self._engagement_id,
                    )
                    session_token_ref = session_record.secret_id
                else:
                    session_token_ref = f"vault://session/{host}"

            break

        # No verified access — record nothing.
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

        if proof_storage_ref:
            self._proof_artifacts.append(proof_storage_ref)

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
                    storage_ref=proof_storage_ref or "",
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
        status: a2a_pb2.PhaseStatus,
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
