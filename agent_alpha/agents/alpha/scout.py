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
import hashlib
import inspect
import re
import uuid
from typing import Any
from urllib.parse import urljoin, urlparse

from agent_alpha.a2a import a2a_pb2
from agent_alpha.agents.base import BoundedAutonomy, run_cognitive_loop
from agent_alpha.agents.http_client import HttpClientError
from agent_alpha.agents.monologue import MonologueSink, NullMonologueSink, ThoughtFrame
from agent_alpha.agents.planner import Planner
from agent_alpha.agents.world_model import WorldModel
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
)
from agent_alpha.graph.persist import persist_edge, persist_node
from agent_alpha.llm.orchestrator import OrientationError
from agent_alpha.recon.capability_probe import capability_for_tool
from agent_alpha.recon.git_exposure_probe import _default_git_dumper
from agent_alpha.recon.path_probe import RecoverStrategy, process_path_hit, spec_for_tool
from agent_alpha.recon.response_classifier import (  # noqa: F401
    VOLATILE_HEADERS,
    Verdict,
    classify_response,
)
from agent_alpha.recon.surface_discovery import extract_api_surface
from agent_alpha.security.credential_assembly import assemble_leaked_credentials
from agent_alpha.security.laravel_env import iter_env_leaks
from agent_alpha.tools.templates.cms.laravel_finding import LaravelFindingTemplate

DEDUP_HEADER_KEYS: frozenset[str] = frozenset({"www-authenticate", "content-type", "location"})
"""Subset of decision-relevant headers hashed for deduplication.

Volatile headers deliberately excluded from the hash key: see
:data:`agent_alpha.recon.response_classifier.VOLATILE_HEADERS` (anti-#7:
single source of truth).  Hashing those would defeat Bug #20 entirely —
every request has a different CF-Ray / Date / Set-Cookie.
"""


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
        git_dumper: Any | None = None,
        session_store: Any | None = None,
    ) -> None:
        self.authorization = authorization
        self.graph_store = graph_store
        self._world_model = WorldModel(graph_store)
        self._planner = Planner()
        self.event_store = event_store
        self.orchestrator = orchestrator
        self.http_client = http_client
        self._secrets_manager = secrets_manager
        self.monologue: MonologueSink = monologue or NullMonologueSink()
        self._git_dumper = git_dumper or _default_git_dumper()
        self.session_store = session_store

        # Dispatch registry: tool_name -> handler(resp, decision, url) -> int.
        # Canonical dispatch (anti-Lyndon #8: no growing if-chain).
        self._dispatch_registry: dict[str, Any] = {
            "laravel_debug_probe": self._handle_laravel_debug,
            "wp_config_probe": self._handle_wp_config_probe,
            "js_secret_probe": self._handle_js_secret_probe,
            "odoo_dbmanager_probe": self._handle_odoo_dbmanager,
            "git_exposure_probe": self._handle_path_probe,
            "backup_file_probe": self._handle_path_probe,
            "actuator_probe": self._handle_path_probe,
            "tomcat_fingerprint": self._handle_capability_fingerprint,
            "http_basic_auth_fingerprint": self._handle_capability_fingerprint,
            "s3_bucket_fingerprint": self._handle_capability_fingerprint,
            "surface_discovery_probe": self._handle_surface_discovery,
            "graphql_fingerprint": self._handle_capability_fingerprint,
            "odoo_fingerprint": self._handle_capability_fingerprint,
        }

        # Per-run state, initialised in run_recon().
        self._engagement_id: str = ""
        self._work_queue: list[str] = []
        self._probed: set[str] = set()
        self._findings: int = 0
        self._analyzable_probes: int = 0
        self._ran_campaigns: set[str] = set()
        self._body_hashes: set[str] = set()
        self._current_objective: Any = None

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
        self._ran_campaigns = set()
        self._body_hashes = set()
        self._current_objective = None

        parsed = urlparse(target_url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        for path in getattr(constants, "WELL_KNOWN_LEAK_PATHS", ()):  # seed known leak paths
            self.enqueue_discovered_url(f"{root}{path}")
        for path in getattr(constants, "SURFACE_DISCOVERY_PATHS", ()):  # seed API-spec paths
            self.enqueue_discovered_url(f"{root}{path}")

        # ── Drive through the cognitive loop ────────────────────
        policy = BoundedAutonomy(
            no_progress_threshold=constants.ALPHA_RECON_NO_PROGRESS_ITERS,
        )
        run_cognitive_loop(
            self,
            policy,
            session_store=self.session_store,
            event_store=self.event_store,
            engagement_id=engagement_id,
        )

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
        """OBSERVE→…→PERSIST cycle, plus the frontier signal the driver needs.

        Reports ``work_remaining`` (un-probed frontier size) so run_cognitive_loop
        can tell a genuine stall from "more hosts are still queued" and not stop
        early on a noisy discovery surface. Pure pass-through otherwise.
        """
        out = self._step_once(context)
        out.setdefault("work_remaining", len(self._work_queue))
        return out

    def _decide(self, observation: dict[str, Any]) -> Any:
        """Full RULE→LLM decision (Bug #2/#6/#14 fix).

        Uses ``decide_excluding(observation, exclude_tools=self._ran_campaigns)``
        when the orchestrator supports it (real ``LLMOrchestrator`` does), so a
        RULE-tier rule for an already-run tool is skipped and the LLM tier gets
        a genuine look at pages that keep re-matching the same rule (e.g. an
        Odoo-fingerprint page hit AFTER ``odoo_dbmanager_probe`` already ran
        once this engagement). Falls back to plain ``decide()`` for test-stub
        orchestrators that only implement that method — zero behaviour change
        for them, same detection approach as :meth:`_rule_only_decision`.
        """
        decide_excluding = getattr(self.orchestrator, "decide_excluding", None)
        if (
            decide_excluding is not None
            and "exclude_tools" in inspect.signature(decide_excluding).parameters
        ):
            return decide_excluding(observation, exclude_tools=frozenset(self._ran_campaigns))
        return self.orchestrator.decide(observation)

    def _rule_only_decision(self, observation: dict[str, Any]) -> Any:
        """RULE-tier-only decision for a 404 body (F2: never escalate a missing path
        to the LLM). Uses the orchestrator's rule-only entrypoint when present; test
        stub orchestrators without one simply yield None -> the 404 is non-analyzable.

        Bug #2/#6/#14: passes ``exclude_tools=self._ran_campaigns`` when the
        orchestrator's ``decide_rule_only`` supports it (real ``LLMOrchestrator``
        does) so a rule for an already-run tool is skipped here too — a debug
        page leaking on a 404 is still worth a DIFFERENT rule's look, just not
        the same tool run twice. Detected via ``inspect.signature`` rather than
        try/except TypeError so a genuine bug inside a test stub's own
        ``decide_rule_only`` body still surfaces as itself, not as "unsupported".
        """
        rule_only = getattr(self.orchestrator, "decide_rule_only", None)
        if rule_only is None:
            return None
        if "exclude_tools" in inspect.signature(rule_only).parameters:
            return rule_only(observation, exclude_tools=frozenset(self._ran_campaigns))
        return rule_only(observation)

    def _step_once(self, context: dict[str, object]) -> dict[str, object]:
        """One OBSERVE→ORIENT→PLAN→ACT→VERIFY→PERSIST cycle."""
        scratchpad = context.get("scratchpad")
        sp: dict[str, Any] = dict(scratchpad) if isinstance(scratchpad, dict) else {}
        # Consume the CANONICAL objective the loop passes in context — do NOT
        # re-read an untyped scratchpad dict (single typed source of truth).
        self._current_objective = context.get("objective")
        obs = sp.setdefault("observations", [])
        if not isinstance(obs, list):
            obs = []
            sp["observations"] = obs

        def _finish(nodes: int, cost: float, note: str) -> dict[str, object]:
            obs.append(note)
            return {"discovered_nodes": nodes, "cost_usd": cost, "scratchpad": sp}

        # Pop an unprobed target; none left → no progress.
        url = self._pop_unprobed()
        if url is None:
            return _finish(0, 0.0, "No unprobed URLs remaining")

        self._probed.add(url)

        # ── OBSERVE ─────────────────────────────────────────────
        # A transport failure (host down, DNS, connect/read timeout) is a
        # non-analysable probe — NOT a crash and NOT a finding. The bounded
        # loop continues; run_recon() then reports FAILED (anti-Lyndon #3).
        try:
            resp = self.http_client.get(url)
        except HttpClientError:
            self._emit("OBSERVE", f"{url} unreachable; probe is non-analyzable")
            return _finish(0, 0.0, f"OBSERVE: {url} unreachable")

        # Classify the response through the ONE canonical classifier so a WAF/CF
        # block on ANY recon path is recorded as evidence and never dressed as
        # clean (anti-Lyndon #3, single source of truth — anti-#7).
        verdict = classify_response(
            status_code=resp.status_code, body=resp.text, headers=dict(resp.headers)
        )

        # A WAF/CF block is a non-analyzable probe, NOT a clean/no-progress
        # result. Record WAF_BLOCKED (reused event) and continue the loop
        # without ever calling the LLM.
        if verdict is Verdict.BLOCKED:
            host = urlparse(url).hostname or urlparse(url).netloc
            self._emit(
                "OBSERVE",
                f"{url} returned HTTP {resp.status_code}; WAF/CF block — non-analyzable",
            )
            self.event_store.append(
                EventType.WAF_BLOCKED,
                self._engagement_id,
                "alpha",
                {"host": host, "path": urlparse(url).path, "status_code": resp.status_code},
            )
            return _finish(0, 0.0, f"OBSERVE: {url} WAF blocked")

        if verdict is Verdict.CHALLENGE:
            host = urlparse(url).hostname or urlparse(url).netloc
            self._emit(
                "OBSERVE",
                f"{url} returned HTTP {resp.status_code}; CDN/WAF challenge — non-analyzable",
            )
            self.event_store.append(
                EventType.WAF_BLOCKED,
                self._engagement_id,
                "alpha",
                {
                    "host": host,
                    "path": urlparse(url).path,
                    "status_code": resp.status_code,
                    "signal": "cf_challenge",
                },
            )
            return _finish(0, 0.0, f"OBSERVE: {url} CDN challenge")

        # NOTE: Verdict.EMPTY no longer short-circuits here. An empty body
        # still cannot match a body rule, but a HEADER rule (e.g.
        # WWW-Authenticate: Basic) can — so EMPTY is routed through the
        # RULE-only tier alongside NOT_FOUND below.

        # HTTP 415 → origin content-negotiation rejection (Bug #10), NOT the
        # target's real content and NOT a WAF/CF block. Never escalated to the
        # LLM, and — unlike NOT_FOUND — never given to the RULE tier either:
        # the body is the origin's generic error page, so a rule match here
        # would reproduce Bug #2/#14's page-wide-marker false positive. No
        # frontier expansion (a 415 error page's links are not real hrefs).
        if verdict is Verdict.UNSUPPORTED_MEDIA_TYPE:
            self._emit(
                "OBSERVE",
                f"{url} returned HTTP 415 (unsupported media type); non-analyzable "
                "origin rejection, not the target's content",
            )
            return _finish(0, 0.0, f"OBSERVE: {url} unsupported media type")

        # ── ORIENT / PLAN ───────────────────────────────────────
        observation: dict[str, Any] = {
            "body": resp.text,
            "headers": dict(resp.headers),
        }

        if verdict is Verdict.OK:
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            subset_headers = []
            for key in sorted(DEDUP_HEADER_KEYS):
                if key in headers_lower:
                    val = headers_lower[key]
                    if key == "content-type":
                        val = val.split(";")[0].strip()
                    subset_headers.append(f"{key}:{val}")

            normalized_headers = "\n".join(subset_headers)
            key_content = f"{resp.text}\n{normalized_headers}"

            body_hash = hashlib.sha256(key_content.encode("utf-8")).hexdigest()
            if body_hash in self._body_hashes:
                self._emit(
                    "OBSERVE",
                    f"{url} returned HTTP {resp.status_code}; identical body skipped (dedup) — non-analyzable",
                )
                self.event_store.append(
                    EventType.PASSIVE_DISCOVERY,
                    self._engagement_id,
                    "alpha",
                    {"url": url, "reason": "identical_body", "hash": body_hash},
                )
                return _finish(0, 0.0, f"OBSERVE: {url} identical body skipped")
            self._body_hashes.add(body_hash)

        if verdict in (Verdict.NOT_FOUND, Verdict.EMPTY):
            # NOT_FOUND (404 with a body) and EMPTY (any status, blank body):
            # give the DETERMINISTIC rule tier a look — a debug page can leak
            # on a 404, and a header signal (WWW-Authenticate, Server) can
            # ride an empty body — but NEVER escalate to the LLM provider
            # (pure token burn on content that is not there — F2).
            decision = self._rule_only_decision(observation)
            if decision is None:
                self._emit(
                    "OBSERVE",
                    f"{url} returned HTTP {resp.status_code}; no rule match — "
                    "non-analyzable (LLM not consulted)",
                )
                return _finish(0, 0.0, f"OBSERVE: {url} no rule match")
            self._emit(
                "OBSERVE",
                f"{url} returned HTTP {resp.status_code}; a deterministic rule "
                "matched — analyzing without the LLM",
            )
        else:
            self._emit(
                "OBSERVE",
                f"Fetched {url} (HTTP {resp.status_code}); analyzing {len(resp.text)} bytes",
            )
            # An LLM/decision failure (truncation, malformed output, API/network) is
            # a non-analyzable probe — NOT a crash. Mirrors the OBSERVE guard.
            try:
                decision = self._decide(observation)
            except OrientationError:
                self._emit(
                    "ORIENT",
                    f"Could not orient on {url}: LLM decision failed; non-analyzable",
                )
                return _finish(0, 0.0, f"ORIENT: {url} LLM decision failed")

        self._analyzable_probes += 1
        self._emit(
            "ORIENT",
            f"Selected tool '{decision.tool}' via the {decision.tier} tier",
            reasoning=decision.reasoning,
        )

        # ── ACT / VERIFY / PERSIST ──────────────────────────────
        self._emit("ACT", f"Running {decision.tool} against {url}")
        nodes_added = 0

        handler = self._dispatch_registry.get(decision.tool)
        if handler is not None:
            nodes_added = handler(resp, decision, url)
        else:
            # Generic probe: optionally record an ASSET node from headers,
            # but NEVER with "laravel" in tech_stack, and NEVER increment
            # findings.
            nodes_added = self._handle_generic_probe(resp, url)

        self._emit("PERSIST", f"Persisted {nodes_added} graph node(s) from {url}")

        # ── FRONTIER EXPANSION (R1) ─────────────────────────────
        # Enqueue in-scope hrefs — ONLY for a real (OK) page. A 404 error page is
        # not a surface to crawl (its nav links are noise, and crawling them would
        # re-inflate the very probing F2 trims).
        if verdict is Verdict.OK:
            for href in self._extract_hrefs(resp.text, url):
                self.enqueue_discovered_url(href)

        return _finish(
            nodes_added, decision.cost_usd, f"ACT: {decision.tool} on {url} -> {nodes_added} nodes"
        )

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
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, asset_node, agent="alpha"
        )
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
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, vuln_node, agent="alpha"
        )
        nodes_added += 1

        # ── EDGE asset → vulnerability ──────────────────────────
        edge = AttackEdge(
            source_id=asset_node.id,
            target_id=vuln_node.id,
            relationship=RelationshipType.EXPLOITS,
            confidence=0.90,
            technique_id=decision.technique_id,
        )
        persist_edge(self.event_store, self.graph_store, self._engagement_id, edge, agent="alpha")

        # ── CREDENTIAL nodes from leaked env keys ────────────────
        nodes_added += self._extract_leaked_credentials(body, host, vuln_node.id)

        self._findings += 1
        return nodes_added

    def _handle_wp_config_probe(self, resp: Any, decision: Any, url: str) -> int:
        """Dispatch to the proven wp-config backup leak vector.

        Single-target: the vector probes only the current target host.
        Idempotency guard prevents re-run if step() fires multiple times
        (e.g. future endpoint-discovery enqueuing extra URLs).
        """
        if decision.tool in self._ran_campaigns:
            return 0
        self._ran_campaigns.add(decision.tool)

        host = urlparse(url).hostname
        if not host or not self.authorization.is_in_scope(self._engagement_id, host):
            return 0

        from agent_alpha.recon.wp_config_probe import verify_wp_config_leak

        creds_added = verify_wp_config_leak(
            engagement_id=self._engagement_id,
            auth=self.authorization,
            http_client=self.http_client,
            scope_hosts=[host],
            graph_store=self.graph_store,
            event_store=self.event_store,
            secrets_manager=self._secrets_manager,
        )
        if creds_added > 0:
            self._findings += 1
        return creds_added

    def _handle_path_probe(self, resp: Any, decision: Any, url: str) -> int:  # noqa: ARG002
        """Dispatch a data-driven path-probe (git_exposure / backup_file / ...).

        ONE handler for every catalog vector (anti-#6/#7). PER-RESPONSE: processes the
        response the loop already fetched (no re-sweep -- F1 closed). No tool-level
        idempotency guard: each seeded path hit is processed on its own so multiple
        leaked files on one host each contribute their distinct credentials; the
        engine is idempotent at the graph level (deterministic node ids).
        """
        spec = spec_for_tool(decision.tool)
        if spec is None:
            return 0

        host = urlparse(url).hostname
        if not host or not self.authorization.is_in_scope(self._engagement_id, host):
            return 0

        dumper = self._git_dumper if spec.recover is RecoverStrategy.DUMP else None

        creds_added = process_path_hit(
            spec,
            resp=resp,
            url=url,
            engagement_id=self._engagement_id,
            auth=self.authorization,
            graph_store=self.graph_store,
            event_store=self.event_store,
            secrets_manager=self._secrets_manager,
            dumper=dumper,
        )
        if creds_added > 0:
            self._findings += 1
        return creds_added

    def _handle_js_secret_probe(self, resp: Any, decision: Any, url: str) -> int:
        """Dispatch to the proven JS-bundle secret leak vector.

        Single-target: the vector probes only the current target host.
        Idempotency guard prevents re-run if step() fires multiple times.
        """
        if decision.tool in self._ran_campaigns:
            return 0
        self._ran_campaigns.add(decision.tool)

        host = urlparse(url).hostname
        if not host or not self.authorization.is_in_scope(self._engagement_id, host):
            return 0

        from agent_alpha.recon.js_secret_probe import verify_js_secret_leak

        creds_added = verify_js_secret_leak(
            engagement_id=self._engagement_id,
            auth=self.authorization,
            http_client=self.http_client,
            scope_targets=[host],
            graph_store=self.graph_store,
            event_store=self.event_store,
            secrets_manager=self._secrets_manager,
        )
        if creds_added > 0:
            self._findings += 1
        return creds_added

    def _handle_odoo_dbmanager(self, resp: Any, decision: Any, url: str) -> int:
        """Dispatch to the Odoo database-manager exposure vector (recon).

        Single-target: probes only the current target host. Idempotency guard
        prevents re-run if step() fires multiple times.
        """
        if decision.tool in self._ran_campaigns:
            return 0
        self._ran_campaigns.add(decision.tool)

        host = urlparse(url).hostname
        if not host or not self.authorization.is_in_scope(self._engagement_id, host):
            return 0

        from agent_alpha.recon.odoo_dbmanager_probe import process_odoo_dbmanager_hit

        exposures = process_odoo_dbmanager_hit(
            resp=resp,
            url=url,
            engagement_id=self._engagement_id,
            auth=self.authorization,
            graph_store=self.graph_store,
            event_store=self.event_store,
        )
        if exposures > 0:
            self._findings += 1
        return exposures

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
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, asset_node, agent="alpha"
        )
        return 1

    def _handle_capability_fingerprint(self, resp: Any, decision: Any, url: str) -> int:  # noqa: ARG002
        """Persist a header-fingerprinted capability as a labeled ASSET node.

        DETECT only (Header-matcher slice-1). A fingerprint is not a payable
        finding: this records a labeled ASSET node (feeding the attack graph) and
        seeds any follow-up surface into the frontier through the SAME in-scope
        guard as every other discovery -- it never mints a credential and never
        increments ``self._findings`` (anti-Lyndon #3: fingerprint != finding).
        Acting on a seeded surface is a gated Gamma concern (ADR §12.26).
        """
        if decision.tool in self._ran_campaigns:
            return 0
        self._ran_campaigns.add(decision.tool)

        spec = capability_for_tool(decision.tool)
        if spec is None:
            return 0

        host = urlparse(url).hostname
        if not host or not self.authorization.is_in_scope(self._engagement_id, host):
            return 0

        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        asset_id = f"asset:{host}"

        # Merge tech_stack to prevent sequential fingerprints (e.g. tomcat then basic_auth)
        # from clobbering each other.
        existing = self.graph_store.get_node(asset_id)
        if existing is not None and hasattr(existing.properties, "tech_stack"):
            merged = list(dict.fromkeys([*existing.properties.tech_stack, spec.label]))
        else:
            merged = [spec.label]

        asset_node = AttackNode(
            id=asset_id,
            type=NodeType.ASSET,
            properties=AssetProperties(host=host, tech_stack=merged),
            confidence=spec.confidence,
            agent="alpha",
            timestamp_utc=now_utc,
        )
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, asset_node, agent="alpha"
        )

        for seed in spec.frontier_seeds:
            self.enqueue_discovered_url(urljoin(url, seed))

        return 1

    def _handle_surface_discovery(self, resp: Any, decision: Any, url: str) -> int:  # noqa: ARG002
        """Enumerate an exposed API spec into frontier endpoints (surface-discovery).

        DETECT/enumerate only. Parses the already-fetched OpenAPI/Swagger body and
        enqueues each declared endpoint through the SAME in-scope guard as every
        other discovery -- discovered URLs cannot expand recon outside client scope.
        Persists ONE ASSET node recording the API surface; it never mints a
        credential nor increments ``self._findings`` (a surface is reach, not a
        payable finding). Acting on a discovered endpoint stays gated (ADR §12.26).
        """
        host = urlparse(url).hostname
        if not host or not self.authorization.is_in_scope(self._engagement_id, host):
            return 0

        endpoints = extract_api_surface(resp.text, url)
        if not endpoints:
            return 0

        for endpoint in endpoints:
            self.enqueue_discovered_url(endpoint)
        self._emit(
            "PLAN",
            f"OpenAPI surface at {url}: seeded {len(endpoints)} endpoint(s) into the recon frontier",
        )

        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        asset_node = AttackNode(
            id=f"asset:{host}",
            type=NodeType.ASSET,
            properties=AssetProperties(host=host, tech_stack=["openapi"]),
            confidence=0.8,
            agent="alpha",
            timestamp_utc=now_utc,
        )
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, asset_node, agent="alpha"
        )
        return 1

    def _extract_leaked_credentials(self, body: str, host: str, vuln_node_id: str) -> int:
        """Scan *body* for leaked credential env keys, persist CREDENTIAL nodes.

        Delegates the generic pairing + standalone + vault logic to
        ``assemble_leaked_credentials`` (shared seam, anti-#6).  The Laravel-
        specific extraction (``iter_env_leaks``) and key maps
        (``LARAVEL_CREDENTIAL_*``) are passed in; the assembly is stack-agnostic.

        Returns the number of CREDENTIAL nodes added.
        """
        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"

        leaked: dict[str, str] = dict(iter_env_leaks(body))

        # Laravel secret keys = all env keys minus username keys (anti-#3 +
        # anti-metadata: DB_HOST / DB_NAME are not in LARAVEL_CREDENTIAL_ENV_KEYS
        # so they never enter leaked in the first place).
        laravel_secret_keys = (
            constants.LARAVEL_CREDENTIAL_ENV_KEYS - constants.LARAVEL_CREDENTIAL_USERNAME_KEYS
        )

        nodes, edges = assemble_leaked_credentials(
            leaked,
            host=host,
            vuln_node_id=vuln_node_id,
            login_pairs=constants.LARAVEL_CREDENTIAL_LOGIN_PAIRS,
            username_keys=constants.LARAVEL_CREDENTIAL_USERNAME_KEYS,
            secret_keys=laravel_secret_keys,
            service_map=constants.LARAVEL_CREDENTIAL_SERVICE_MAP,
            secrets_manager=self._secrets_manager,
            engagement_id=self._engagement_id,
            now_utc=now_utc,
            leak_source="laravel_debug",
        )

        nodes_added = 0
        for node in nodes:
            persist_node(
                self.event_store, self.graph_store, self._engagement_id, node, agent="alpha"
            )
            nodes_added += 1
        for edge in edges:
            persist_edge(
                self.event_store, self.graph_store, self._engagement_id, edge, agent="alpha"
            )

        if nodes_added > 0:
            self._emit(
                "VERIFY",
                f"Credential disclosure: {nodes_added} credential(s) "
                f"leaked via Laravel debug page on {host}",
            )

        return nodes_added

    # ── Private: frontier expansion (R1) ───────────────────────

    def _extract_hrefs(self, html: str, base_url: str) -> list[str]:
        """Extract absolute same-origin hrefs from *html*.

        Resolves relative paths against *base_url*, skips anchors/mailto/
        javascript/tel, and filters to the same scheme+host as *base_url*.
        Scope-gate (``authorization.is_in_scope``) is applied separately in
        ``enqueue_discovered_url`` — this is the HTML-level same-origin filter.
        """
        base = urlparse(base_url)
        base_origin = (base.scheme, base.hostname or "")

        hrefs: list[str] = []
        for match in re.finditer(r'<a\s[^>]*href=["\']([^"\'#][^"\']*)["\']', html, re.IGNORECASE):
            raw = match.group(1).strip()
            if not raw or raw.startswith(("mailto:", "javascript:", "tel:")):
                continue
            absolute = urljoin(base_url, raw)
            parsed = urlparse(absolute)
            if (parsed.scheme, parsed.hostname or "") == base_origin:
                hrefs.append(absolute)
        return hrefs

    def enqueue_discovered_url(self, url: str) -> None:
        """Add *url* to ``_work_queue`` if in-scope and not already seen.

        Scope is validated through the authorisation gate — the same gate that
        guards ``run_recon`` — so discovered hrefs cannot expand recon outside
        client scope regardless of what a target page links to.  Dedup against
        both ``_probed`` (already executed) and ``_work_queue`` (already
        scheduled) prevents re-scan loops on link-cycle pages.

        CDN-infrastructure paths (e.g., /cdn-cgi/*) are excluded before scope
        check to prevent crawl loops on Cloudflare-injected paths that link to
        each other indefinitely.
        """
        parsed = urlparse(url)
        # Exclude CDN-infrastructure paths before scope/dedup check
        for prefix in constants.CDN_INFRA_EXCLUDE_PREFIXES:
            if parsed.path.startswith(prefix):
                return
        host = parsed.hostname or parsed.netloc
        if (
            self.authorization.is_in_scope(self._engagement_id, host)
            and url not in self._probed
            and url not in self._work_queue
        ):
            self._work_queue.append(url)

    # ── Private: helpers ────────────────────────────────────────

    def _pop_unprobed(self) -> str | None:
        """Pop the next URL from the work queue that hasn't been probed."""
        objective = getattr(self, "_current_objective", None)

        if objective is None:
            # Fast-path FIFO (byte-for-byte backward-compat)
            while self._work_queue:
                url = self._work_queue.pop(0)
                if url not in self._probed:
                    return url
            return None

        # Objective-based MAX-scoring (deterministic)
        unprobed = [u for u in self._work_queue if u not in self._probed]
        if not unprobed:
            self._work_queue.clear()
            return None

        best_url = max(
            unprobed,
            key=lambda u: (
                self._planner.score(u, self._world_model, objective),
                -self._work_queue.index(u),
            ),
        )
        self._work_queue.remove(best_url)
        return best_url

    def _emit(self, phase: str, message: str, reasoning: str = "") -> None:
        """Emit one inner-monologue frame to the injected sink (real-time)."""
        import sys

        print(f"  [ALPHA/{phase}] {message}", file=sys.stderr)
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
