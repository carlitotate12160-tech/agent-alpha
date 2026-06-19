# agent_alpha/agents/alpha/scout.py
"""Alpha (SCOUT) — reconnaissance agent.

Reads an HTTP response, reaches a target-specific conclusion, persists
findings to the event-sourced AttackGraph, and hands off to the Conductor.

Drives its recon through ``run_cognitive_loop`` (anti-Lyndon #2).
Reconnaissance only (RECON_ONLY auth); no exploitation.

Reuses canonical types from ``agent_alpha.graph.nodes`` — never redeclares
any (anti-Lyndon #6).
"""

from __future__ import annotations

import datetime
import re
import uuid
from typing import Any
from urllib.parse import urlparse

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.base import BoundedAutonomy, run_cognitive_loop
from agent_alpha.agents.http_client import HttpClientError
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackEdge,
    AttackNode,
    NodeType,
    ProofArtifact,
    RelationshipType,
    VulnerabilityProperties,
    node_to_dict,
)


class Alpha:
    """Reconnaissance agent — the first to touch a target.

    Parameters are injected; Alpha never instantiates its own dependencies.
    """

    def __init__(
        self,
        authorization: Any,
        graph_store: Any,
        event_store: Any,
        orchestrator: Any,
        http_client: Any,
    ) -> None:
        self.authorization = authorization
        self.graph_store = graph_store
        self.event_store = event_store
        self.orchestrator = orchestrator
        self.http_client = http_client

        # Per-run state, initialised in run_recon().
        self._engagement_id: str = ""
        self._work_queue: list[str] = []
        self._probed: set[str] = set()
        self._findings: int = 0
        self._analyzable_probes: int = 0

    # ── Public entry point ──────────────────────────────────────

    def run_recon(self, engagement_id: str, target_url: str) -> a2a_pb2.A2AMessage:
        """Run reconnaissance on *target_url* under *engagement_id*.

        Returns an ``A2AMessage`` with a serialised ``HandoffPayload``.
        """
        # ── Auth gate ───────────────────────────────────────────
        if not self.authorization.can_agent_proceed(a2a_pb2.ALPHA, engagement_id):
            return self._build_handoff_message(
                engagement_id=engagement_id,
                status=a2a_pb2.BLOCKED,
                findings_count=0,
                confidence=0.0,
            )

        # ── Scope gate ──────────────────────────────────────────
        host = urlparse(target_url).hostname or urlparse(target_url).netloc
        if not self.authorization.is_in_scope(engagement_id, host):
            return self._build_handoff_message(
                engagement_id=engagement_id,
                status=a2a_pb2.BLOCKED,
                findings_count=0,
                confidence=0.0,
            )

        # ── Initialise per-run state ────────────────────────────
        self._engagement_id = engagement_id
        self._work_queue = [target_url]
        self._probed = set()
        self._findings = 0
        self._analyzable_probes = 0

        # ── Drive through the cognitive loop ────────────────────
        policy = BoundedAutonomy(
            no_progress_threshold=constants.ALPHA_RECON_NO_PROGRESS_ITERS,
        )
        run_cognitive_loop(self, policy)

        # ── Determine status ────────────────────────────────────
        if self._analyzable_probes == 0:
            # Nothing could be analysed — no silent success (anti-Lyndon #3).
            status = a2a_pb2.FAILED
        else:
            status = a2a_pb2.COMPLETE

        confidence = 0.85 if self._findings > 0 else 0.0

        return self._build_handoff_message(
            engagement_id=engagement_id,
            status=status,
            findings_count=self._findings,
            confidence=confidence,
        )

    # ── Cognitive-loop step ─────────────────────────────────────

    def step(self, context: dict[str, object]) -> dict[str, object]:
        """One OBSERVE→ORIENT→PLAN→ACT→VERIFY→PERSIST cycle."""

        # Pop an unprobed target; none left → no progress.
        url = self._pop_unprobed()
        if url is None:
            return {"discovered_nodes": 0, "cost_usd": 0.0}

        self._probed.add(url)

        # ── OBSERVE ─────────────────────────────────────────────
        # A transport failure (host down, DNS, connect/read timeout) is a
        # non-analysable probe — NOT a crash and NOT a finding. The bounded
        # loop continues; run_recon() then reports FAILED (anti-Lyndon #3).
        try:
            resp = self.http_client.get(url)
        except HttpClientError:
            return {"discovered_nodes": 0, "cost_usd": 0.0}

        # Empty/whitespace body → non-analysable probe.
        if not resp.text or not resp.text.strip():
            return {"discovered_nodes": 0, "cost_usd": 0.0}

        self._analyzable_probes += 1

        # ── ORIENT / PLAN ───────────────────────────────────────
        observation: dict[str, Any] = {
            "body": resp.text,
            "headers": dict(resp.headers),
        }
        decision = self.orchestrator.decide(observation)

        # ── ACT / VERIFY / PERSIST ──────────────────────────────
        nodes_added = 0

        if decision.tool == "laravel_debug_probe":
            nodes_added = self._handle_laravel_debug(resp, decision, url)
        else:
            # Generic probe: optionally record an ASSET node from headers,
            # but NEVER with "laravel" in tech_stack, and NEVER increment
            # findings.
            nodes_added = self._handle_generic_probe(resp, url)

        return {"discovered_nodes": nodes_added, "cost_usd": decision.cost_usd}

    # ── Private: tool handlers ──────────────────────────────────

    def _handle_laravel_debug(self, resp: Any, decision: Any, url: str) -> int:
        """Confirm Laravel debug exposure and persist findings."""
        body = resp.text

        # Confirm the detection: body must contain one of the signals.
        is_confirmed = (
            "Whoops" in body
            or "Illuminate\\" in body
            or re.search(r"Laravel v[0-9]", body) is not None
        )
        if not is_confirmed:
            return 0

        host = urlparse(url).hostname or urlparse(url).netloc
        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        nodes_added = 0

        # ── ASSET node ──────────────────────────────────────────
        asset_node = AttackNode(
            id=f"asset:{host}",
            type=NodeType.ASSET,
            properties=AssetProperties(
                host=host,
                tech_stack=["laravel"],
            ),
            confidence=0.95,
            agent="alpha",
            timestamp_utc=now_utc,
        )
        self._persist_node(asset_node)
        nodes_added += 1

        # ── VULNERABILITY node ──────────────────────────────────
        vuln_node = AttackNode(
            id=f"vuln:{host}:laravel_debug",
            type=NodeType.VULNERABILITY,
            properties=VulnerabilityProperties(
                affected_service="laravel",
                exploit_available=True,
            ),
            confidence=0.90,
            proof_artifacts=[
                ProofArtifact(
                    type="http_response",
                    storage_ref=(f"engagements/{self._engagement_id}/proofs/laravel_debug_{host}"),
                    description=("Laravel APP_DEBUG=true page leaking stack trace + environment"),
                    captured_at=now_utc,
                    agent="alpha",
                    artifact_id=str(uuid.uuid4()),
                ),
            ],
            agent="alpha",
            timestamp_utc=now_utc,
        )
        self._persist_node(vuln_node)
        nodes_added += 1

        # ── EDGE asset → vulnerability ──────────────────────────
        edge = AttackEdge(
            source_id=asset_node.id,
            target_id=vuln_node.id,
            relationship=RelationshipType.EXPLOITS,
            confidence=0.90,
            technique_id=decision.technique_id,
        )
        self._persist_edge(edge)

        self._findings += 1
        return nodes_added

    def _handle_generic_probe(self, resp: Any, url: str) -> int:
        """Record a single ASSET node from headers — never with 'laravel'."""
        host = urlparse(url).hostname or urlparse(url).netloc
        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

        # Derive tech_stack from headers, excluding "laravel".
        tech_stack: list[str] = []
        server = resp.headers.get("server", "")
        if server:
            tech_stack.append(server.lower())
        powered_by = resp.headers.get("x-powered-by", "")
        if powered_by:
            tech_stack.append(powered_by.lower())
        # NEVER include "laravel" in a generic probe.
        tech_stack = [t for t in tech_stack if "laravel" not in t]

        asset_node = AttackNode(
            id=f"asset:{host}",
            type=NodeType.ASSET,
            properties=AssetProperties(
                host=host,
                tech_stack=tech_stack,
            ),
            confidence=0.5,
            agent="alpha",
            timestamp_utc=now_utc,
        )
        self._persist_node(asset_node)
        return 1

    # ── Private: persistence ────────────────────────────────────

    def _persist_node(self, node: AttackNode) -> None:
        """Persist a node through both event_store and graph_store."""
        payload = node_to_dict(node)
        self.event_store.append(
            EventType.NODE_DISCOVERED,
            self._engagement_id,
            "alpha",
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
            "alpha",
            payload,
        )
        self.graph_store.apply_event("EdgeDiscovered", payload)

    # ── Private: helpers ────────────────────────────────────────

    def _pop_unprobed(self) -> str | None:
        """Pop the next URL from the work queue that hasn't been probed."""
        while self._work_queue:
            url = self._work_queue.pop(0)
            if url not in self._probed:
                return url
        return None

    @staticmethod
    def _build_handoff_message(
        engagement_id: str,
        status: a2a_pb2.PhaseStatus,
        findings_count: int,
        confidence: float,
    ) -> a2a_pb2.A2AMessage:
        """Build the A2A handoff message to the Conductor."""
        handoff = a2a_pb2.HandoffPayload(
            status=status,
            findings_count=findings_count,
            next_recommended=a2a_pb2.BETA,
            confidence=confidence,
        )
        return a2a_pb2.A2AMessage(
            engagement_id=engagement_id,
            from_agent=a2a_pb2.ALPHA,
            to_agent=a2a_pb2.CONDUCTOR,
            message_type=a2a_pb2.HANDOFF_READY,
            payload=handoff.SerializeToString(),
            confidence=confidence,
        )
