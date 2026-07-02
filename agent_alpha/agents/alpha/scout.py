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
import uuid
from typing import Any
from urllib.parse import urlparse

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.base import BoundedAutonomy, run_cognitive_loop
from agent_alpha.agents.http_client import HttpClientError
from agent_alpha.agents.monologue import MonologueSink, NullMonologueSink, ThoughtFrame
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackEdge,
    AttackNode,
    CredentialProperties,
    NodeType,
    ProofArtifact,
    RelationshipType,
    VulnerabilityProperties,
    node_to_dict,
)
from agent_alpha.llm.orchestrator import OrientationError
from agent_alpha.security.laravel_env import iter_env_leaks
from agent_alpha.tools.templates.cms.laravel_finding import LaravelFindingTemplate


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
        secrets_manager: Any = None,
        monologue: MonologueSink | None = None,
    ) -> None:
        self.authorization = authorization
        self.graph_store = graph_store
        self.event_store = event_store
        self.orchestrator = orchestrator
        self.http_client = http_client
        self._secrets_manager = secrets_manager
        self.monologue: MonologueSink = monologue or NullMonologueSink()

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
            self._emit("OBSERVE", f"{url} unreachable; probe is non-analyzable")
            return {"discovered_nodes": 0, "cost_usd": 0.0}

        # Empty/whitespace body → non-analyzable probe.
        if not resp.text or not resp.text.strip():
            self._emit("OBSERVE", f"Fetched {url} but the body was empty; non-analyzable")
            return {"discovered_nodes": 0, "cost_usd": 0.0}

        self._emit(
            "OBSERVE",
            f"Fetched {url} (HTTP {resp.status_code}); analyzing {len(resp.text)} bytes",
        )

        # ── ORIENT / PLAN ───────────────────────────────────────
        observation: dict[str, Any] = {
            "body": resp.text,
            "headers": dict(resp.headers),
        }
        # An LLM/decision failure (truncation, malformed output, API/network) is
        # a non-analyzable probe — NOT a crash. Mirrors the OBSERVE guard.
        try:
            decision = self.orchestrator.decide(observation)
        except OrientationError:
            self._emit(
                "ORIENT",
                f"Could not orient on {url}: LLM decision failed; non-analyzable",
            )
            return {"discovered_nodes": 0, "cost_usd": 0.0}

        self._analyzable_probes += 1
        self._emit(
            "ORIENT",
            f"Selected tool '{decision.tool}' via the {decision.tier} tier",
            reasoning=decision.reasoning,
        )

        # ── ACT / VERIFY / PERSIST ──────────────────────────────
        self._emit("ACT", f"Running {decision.tool} against {url}")
        nodes_added = 0

        if decision.tool == "laravel_debug_probe":
            nodes_added = self._handle_laravel_debug(resp, decision, url)
        else:
            # Generic probe: optionally record an ASSET node from headers,
            # but NEVER with "laravel" in tech_stack, and NEVER increment
            # findings.
            nodes_added = self._handle_generic_probe(resp, url)

        self._emit("PERSIST", f"Persisted {nodes_added} graph node(s) from {url}")
        return {"discovered_nodes": nodes_added, "cost_usd": decision.cost_usd}

    # ── Private: tool handlers ──────────────────────────────────

    def _handle_laravel_debug(self, resp: Any, decision: Any, url: str) -> int:
        """Confirm Laravel debug exposure via the tool-layer template and persist findings."""
        body = resp.text

        # Delegate detection + proof capture to the template (single canonical path).
        resp_dict = {
            "url": url,
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": body,
        }
        result = LaravelFindingTemplate().verify(resp_dict)
        if not result.success:
            return 0

        # Extract real captured, redacted evidence from the template result.
        evidence = (
            result.findings[0].get("redacted_snippet")
            or result.findings[0].get("evidence")
            or "Laravel debug exposure"
        )

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
            confidence=result.confidence,
            proof_artifacts=[
                ProofArtifact(
                    type="http_response",
                    storage_ref=(f"engagements/{self._engagement_id}/proofs/laravel_debug_{host}"),
                    description=evidence,
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

        # ── CREDENTIAL nodes from leaked env keys ────────────────
        nodes_added += self._extract_leaked_credentials(body, host, vuln_node.id)

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

    def _extract_leaked_credentials(self, body: str, host: str, vuln_node_id: str) -> int:
        """Scan *body* for leaked credential env keys, persist CREDENTIAL nodes.

        For each key in ``constants.LARAVEL_CREDENTIAL_ENV_KEYS`` found in the
        response body, creates one CREDENTIAL node and a VULNERABILITY →
        CREDENTIAL ``LEADS_TO`` edge.

        PAIRING (anti-fragmentation, anti-#3): when co-located username + secret
        keys (per ``constants.LARAVEL_CREDENTIAL_LOGIN_PAIRS``) are BOTH present,
        emits ONE paired login credential node with ``username=<ukey value>`` and
        ``secret_ref = vault(<skey value>)``. Username keys are NEVER emitted as
        standalone credential nodes — a username is not a secret, and vaulting it
        as one creates a false credential (Lyndon #3).

        ADDITIVE variant: the secret key (e.g. DB_PASSWORD) is ALSO emitted as a
        standalone fragment so the web cred_reuse chain (which depends on it with
        ``username=""``) continues to work. The paired login node is emitted FIRST
        so cred_reuse tries it before the fragment.

        REDACTION: the plaintext secret value is NEVER stored in any node,
        edge, event, or log. Only the *key name* and a ``secret_ref`` pointer
        to the proof artifact are persisted.

        Returns the number of CREDENTIAL nodes added.
        """
        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        nodes_added = 0

        leaked: dict[str, str] = dict(iter_env_leaks(body))

        # ── Paired login credentials (emitted first so cred_reuse tries them
        #    before standalone fragments) ──────────────────────────────────
        for service, (ukey, skey) in constants.LARAVEL_CREDENTIAL_LOGIN_PAIRS.items():
            if ukey not in leaked or skey not in leaked:
                continue
            uvalue = leaked[ukey]
            svalue = leaked[skey]

            if self._secrets_manager is not None:
                record = self._secrets_manager.store(
                    label=f"{service}:login",
                    value=svalue,
                    engagement_id=self._engagement_id,
                )
                secret_ref = record.secret_id
            else:
                secret_ref = f"engagements/{self._engagement_id}/proofs/laravel_debug_{host}#login"

            cred_node = AttackNode(
                id=f"cred:{host}:{service}:login",
                type=NodeType.CREDENTIAL,
                properties=CredentialProperties(
                    username=uvalue,
                    secret_ref=secret_ref,
                    service=service,
                    access_level="unverified",
                ),
                confidence=0.85,
                agent="alpha",
                timestamp_utc=now_utc,
            )
            self._persist_node(cred_node)
            nodes_added += 1

            cred_edge = AttackEdge(
                source_id=vuln_node_id,
                target_id=cred_node.id,
                relationship=RelationshipType.LEADS_TO,
                confidence=0.85,
            )
            self._persist_edge(cred_edge)

        # ── Standalone credential nodes for non-username keys ──────────
        for key, raw_value in leaked.items():
            # Skip username keys — they are NOT secrets (anti-#3: a username node
            # whose secret_ref resolves to the username string is a false credential).
            if key in constants.LARAVEL_CREDENTIAL_USERNAME_KEYS:
                continue

            # Determine the service label from the key prefix (SSOT).
            service = "unknown"
            for prefix, svc in constants.LARAVEL_CREDENTIAL_SERVICE_MAP.items():
                if key.startswith(prefix):
                    service = svc
                    break

            # VAULT the leaked secret (encrypted) so cred_reuse can retrieve it.
            # secret_ref becomes the vault id — never the value, never a proof path.
            if self._secrets_manager is not None:
                record = self._secrets_manager.store(
                    label=f"{service}:{key}",
                    value=raw_value,
                    engagement_id=self._engagement_id,
                )
                secret_ref = record.secret_id
            else:
                # No vault wired -> non-retrievable pointer (recon still records the
                # finding; cred_reuse simply can't reuse it). Fail-open for recon.
                secret_ref = f"engagements/{self._engagement_id}/proofs/laravel_debug_{host}#{key}"

            cred_node = AttackNode(
                id=f"cred:{host}:{key.lower()}",
                type=NodeType.CREDENTIAL,
                properties=CredentialProperties(
                    username="",
                    secret_ref=secret_ref,
                    service=service,
                    access_level="unverified",
                ),
                confidence=0.85,
                agent="alpha",
                timestamp_utc=now_utc,
            )
            self._persist_node(cred_node)
            nodes_added += 1

            # VULNERABILITY → CREDENTIAL edge.
            cred_edge = AttackEdge(
                source_id=vuln_node_id,
                target_id=cred_node.id,
                relationship=RelationshipType.LEADS_TO,
                confidence=0.85,
            )
            self._persist_edge(cred_edge)

        if nodes_added > 0:
            self._emit(
                "VERIFY",
                f"Credential disclosure: {nodes_added} credential(s) "
                f"leaked via Laravel debug page on {host}",
            )

        return nodes_added

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

    def _emit(self, phase: str, message: str, reasoning: str = "") -> None:
        """Emit one inner-monologue frame to the injected sink (real-time)."""
        self.monologue.emit(
            ThoughtFrame(
                engagement_id=self._engagement_id,
                agent="alpha",
                phase=phase,
                message=message,
                timestamp_utc=(
                    datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
                ),
                reasoning=reasoning,
            )
        )

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
