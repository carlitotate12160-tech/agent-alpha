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
from agent_alpha.llm.redaction import redact_secrets
from agent_alpha.tools.contracts import ResourceBudget, TargetContext
from agent_alpha.tools.internal.access.cred_reuse import CredReuseTool
from agent_alpha.tools.internal.access.default_creds import DefaultCredsTool

# Budget for the default-creds tool — generous enough for the full dictionary
# but bounded (anti-Lyndon #7: single source, not a magic number in step).
_DEFAULT_CREDS_MAX_REQUESTS = 30
_DEFAULT_CREDS_MAX_SECONDS = 120.0

# Access levels are a closed vocabulary (anti-Lyndon #6: one canonical set).
ACCESS_NONE = "none"
ACCESS_USER = "user"
ACCESS_ADMIN = "admin"


def _deep_redact(obj: Any) -> Any:
    """Recursively redact all strings in a nested dict/list structure.

    Unlike the flat ``redact_secrets`` call in the old code, this traverses
    into dict values and list elements so no raw header/cookie string
    survives in a nested structure (anti-Lyndon #45).
    """
    if isinstance(obj, str):
        return redact_secrets(obj)
    if isinstance(obj, dict):
        return {k: _deep_redact(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(_deep_redact(v) for v in obj)
    return obj


def _cookie_name_only(set_cookie: str) -> str:
    """Extract just the cookie NAME from a Set-Cookie header value.

    ``session=S3CR3T; Path=/; HttpOnly`` → ``session``.
    The VALUE is a secret — never persist it, even redacted.
    """
    if not set_cookie:
        return ""
    first_part = set_cookie.split(";", 1)[0].strip()
    if "=" not in first_part:
        return first_part or ""
    return first_part.split("=", 1)[0].strip()


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

        # ── Dep-precondition (Claude's lane) ─────────────────────
        if self.http_client is None or self.orchestrator is None:
            raise ValueError(
                "Beta.run_strike requires http_client and orchestrator "
                "— wiring bug, not access failure"
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

        Offensive-body author: GLM 5.2 High (NOT Claude).

        Contract the body satisfies (do not change the surrounding gates):
          * OBSERVE the entry_point, ORIENT via orchestrator.decide.
          * ACT: delegate to DefaultCredsTool(http_client=...).run(ctx, budget).
          * VERIFY via ToolResult.success (the type forbids empty success — #3).
          * PERSIST (single persistence owner — scout/Laravel #45 pattern):
            REDACT proof (SSOT), event_store.append → mint retrievable refs,
            build ACCESS_LEVEL + CREDENTIAL nodes + ENABLES edge.
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

        # ── ACT: ranked tool selection (seed of ToolRegistry — inline for 2
        #    tools, extract to registry.py when a 3rd tool/Gamma needs it) ──
        ctx = TargetContext(
            engagement_id=self._engagement_id,
            tenant_id=None,
            target=self._entry_point,
        )
        budget = ResourceBudget(
            max_requests=_DEFAULT_CREDS_MAX_REQUESTS,
            max_seconds=_DEFAULT_CREDS_MAX_SECONDS,
            max_cost_usd=0.0,  # no LLM cost for default-cred check
        )

        candidates = [
            CredReuseTool(
                http_client=self.http_client,
                graph_store=self.graph_store,
                secrets_manager=self._secrets_manager,
            ),
            DefaultCredsTool(http_client=self.http_client),
        ]

        result = None
        for tool in sorted(candidates, key=lambda t: t.applies_to(ctx), reverse=True):
            try:
                result = tool.run(ctx, budget)
            except NotImplementedError:
                continue
            if result.success:
                break

        # ── VERIFY: ToolResult.success (type forbids empty success — #3) ──
        if result is None or not result.success:
            return {"discovered_nodes": 0, "cost_usd": cost_usd}

        # ── PERSIST (single persistence owner — Beta.step mints refs
        #    from content, like scout/Laravel #45) ──────────────────
        finding = result.findings[0]
        access_level: str = finding["access_level"]

        # DEEP-REDACT proof before persisting — recursively redact all
        # strings in nested dicts/lists so no raw header/cookie value
        # survives (anti-Lyndon #45). The old flat redact missed dict
        # values like headers={"set-cookie": "session=SECRET; ..."}.
        proof_request = _deep_redact(finding["proof_request"])
        redacted_proof_response = _deep_redact(finding["proof_response"])

        # MINT proof_ref: event_store.append → event_id (retrievable).
        proof_event = self.event_store.append(
            EventType.PROOF_ARTIFACT_RECORDED,
            self._engagement_id,
            "beta",
            {
                "entry_point": self._entry_point,
                "proof_request": proof_request,
                "proof_response": redacted_proof_response,
                "captured_at": now_utc,
            },
        )
        proof_ref = proof_event.event_id

        # MINT credential_ref: event_store.append → event_id.
        # Only mint if we harvested a NEW credential (default_creds). If cred_reuse
        # succeeded, the credential was already harvested by Alpha and we don't
        # mint a new credential proof.
        credential_ref: str | None = None
        if "credential_node_id" not in finding:
            cred_event = self.event_store.append(
                EventType.PROOF_ARTIFACT_RECORDED,
                self._engagement_id,
                "beta",
                {
                    "type": "default_credential_validated",
                    "username": finding["username"],
                    "target": self._entry_point,
                    "access_level": access_level,
                    "captured_at": now_utc,
                },
            )
            credential_ref = cred_event.event_id

        # MINT session_token_ref if a session cookie was issued.
        session_token_ref: str | None = None
        if finding.get("session_cookie"):
            session_event = self.event_store.append(
                EventType.PROOF_ARTIFACT_RECORDED,
                self._engagement_id,
                "beta",
                {
                    "type": "session_token",
                    "target": self._entry_point,
                    "session_cookie_name": _cookie_name_only(finding["session_cookie"]),
                    "captured_at": now_utc,
                },
            )
            session_token_ref = session_event.event_id

        # Update per-run state with minted refs.
        self._access_level = access_level
        if credential_ref:
            self._credential_refs.append(credential_ref)
        elif "credential_node_id" in finding:
            # For cred_reuse, Beta.step's false-success guard expects self._credential_refs
            # to be non-empty. We'll store a placeholder or the reused node ID to signal success.
            self._credential_refs.append(finding["credential_node_id"])
        if session_token_ref:
            self._session_token_refs.append(session_token_ref)
        self._proof_artifacts.append(proof_ref)

        nodes_added = 0

        # CREDENTIAL node.
        # If finding has credential_node_id (cred_reuse), use the existing Alpha node.
        # Otherwise, mint a new CREDENTIAL node for default_creds.
        cred_node_id = finding.get("credential_node_id")
        if not cred_node_id:
            cred_node_id = f"cred:{host}:{finding['username']}"
            cred_node = AttackNode(
                id=cred_node_id,
                type=NodeType.CREDENTIAL,
                properties=CredentialProperties(
                    username=finding["username"],
                    secret_ref=credential_ref or "",
                    service="http",
                    access_level=access_level,
                ),
                confidence=result.confidence,
                agent="beta",
                timestamp_utc=now_utc,
                verified=True,
            )
            self._persist_node(cred_node)
            nodes_added += 1

        # ACCESS_LEVEL node (verified).
        access_node = AttackNode(
            id=f"access:{host}",
            type=NodeType.ACCESS_LEVEL,
            properties=AccessLevelProperties(
                level=access_level,
                user_context=finding["username"],
            ),
            confidence=result.confidence,
            proof_artifacts=[
                ProofArtifact(
                    type="authenticated_request",
                    storage_ref=proof_ref,
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
        cred_edge = AttackEdge(
            source_id=cred_node_id,
            target_id=access_node.id,
            relationship=RelationshipType.ENABLES,
            confidence=result.confidence,
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
