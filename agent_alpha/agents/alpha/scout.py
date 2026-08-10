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
import json
import re
import uuid
from types import SimpleNamespace
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
    AttackEdge,
    AttackNode,
    NodeType,
    ProofArtifact,
    RelationshipType,
    UserProperties,
    VerificationTier,
    VulnerabilityProperties,
)
from agent_alpha.graph.persist import merge_asset_node, persist_edge, persist_node
from agent_alpha.llm.orchestrator import OrientationError
from agent_alpha.recon.auth_surface import detect_auth_surface_labels
from agent_alpha.recon.capability_probe import capability_for_tool
from agent_alpha.recon.compromise_catalog import SEO_INJECTION_SPEC, detect_seo_injection
from agent_alpha.recon.git_exposure_probe import _default_git_dumper
from agent_alpha.recon.origin_binding import resolve_and_bind_origin
from agent_alpha.recon.passive_intel import passive_intel_signal_for_host
from agent_alpha.recon.path_probe import RecoverStrategy, process_path_hit, spec_for_tool
from agent_alpha.recon.plugin_cve_catalog import lookup as cve_lookup
from agent_alpha.recon.reach_strategy import ReachStrategy, choose_reach, is_cloudflare_ip
from agent_alpha.recon.reach_transport import (
    is_tls_impersonate_available,
    origin_direct_fetch,
    tls_impersonate_fetch,
)
from agent_alpha.recon.response_classifier import (  # noqa: F401
    VOLATILE_HEADERS,
    Verdict,
    classify_response,
    is_json_response,
    is_reload_shell,
)
from agent_alpha.recon.surface_discovery import extract_api_surface
from agent_alpha.recon.transport_resilience import classify_mitigation
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


class _ReachResponse:
    """Adapter so origin-direct / browser_solve results feed into the existing
    OBSERVE→ORIENT→ACT flow which expects ``.status_code`` / ``.text`` / ``.headers``.

    NOT a reimplementation of reach (anti-#6) — just a response-shaped wrapper
    so the rest of ``_step_once`` can consume the reach result unchanged.
    """

    __slots__ = ("status_code", "text", "headers")

    def __init__(self, status_code: int, body: str, headers: dict[str, str]) -> None:
        self.status_code = status_code
        self.text = body
        self.headers = headers


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
        try_harder_enabled: bool = True,
        origin_discovery: Any | None = None,
        browser_solve: Any | None = None,
        engagement_profile: Any | None = None,
        browser_solve_viable: bool = False,
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
        self._try_harder_enabled = try_harder_enabled

        # Reach deps (Phase 2.5 — §12.33). All default None/False → reach
        # unavailable → honest WAF-blocked outcome (anti-#3). Injected, never
        # self-instantiated (anti-#6). The runner / tests inject real instances.
        self._origin_discovery = origin_discovery
        self._browser_solve = browser_solve
        self._engagement_profile = engagement_profile
        self._browser_solve_viable = browser_solve_viable

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
            "odoo_fingerprint": self._handle_odoo_fingerprint,
            "wp_fingerprint": self._handle_capability_fingerprint,
            "wp_rest_routes": self._handle_wp_rest_routes,
            "wp_rest_users": self._handle_wp_rest_users,
            "woocommerce": self._handle_woocommerce,
            "wp_version": self._handle_wp_version,
            "wp_plugins": self._handle_wp_plugins,
        }

        # Per-run state, initialised in run_recon().
        self._engagement_id: str = ""
        self._work_queue: list[str] = []
        self._probed: set[str] = set()
        self._findings: int = 0
        self._seo_analyzed_hosts: set[str] = set()
        self._analyzable_probes: int = 0
        self._ran_campaigns: set[str] = set()
        self._body_hashes: set[str] = set()
        self._current_objective: Any = None
        self._try_harder_fired: bool = False
        self._reach_attempted: set[str] = set()
        self._reach_class: dict[str, str] = {}
        self._reach_body_cache: dict[str, Any] = {}
        # Per-host resolved origin (crt.sh + binding is identical for every blocked
        # path on a host — resolve ONCE, reuse incl. the empty negative case).
        self._bound_origin: dict[str, list[str]] = {}
        # host -> set of tech_stack labels fingerprinted THIS run (R2 selective
        # crawl). Local to Alpha, NOT read from graph_store/world_model — keeps
        # the gate pure/synchronous and avoids a graph query on every discovered
        # href. Tagged at the END of _handle_capability_fingerprint (after its
        # deterministic frontier_seeds are already enqueued), so catalog seeds
        # are never subject to this gate — only hrefs parsed from page HTML are.
        self._host_stack: dict[str, set[str]] = {}
        self._organic_crawl_count: dict[str, int] = {}
        # Instinct #2 (GAP-029): hosts whose ROOT raised HttpClientError this run.
        # All queued/future paths for these hosts are skipped — avoids N*seed_paths
        # unreachable probes for dead subdomains (field: 19 × 12 = 118, ~25 min).
        # ROOT-failure ONLY (R1): a non-root transport error (e.g. WAF RST on /.env
        # while the homepage is 200) must NOT kill a live host.
        # Known tradeoff: a single root timeout marks the host dead for this run;
        # cost of one skipped live host << 12× waste per dead host. No retries here.
        # The challenge-skip instinct (anti #6/#7) will populate this SAME set later.
        self._dead_hosts: set[str] = set()

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
        self._seo_analyzed_hosts = set()
        self._analyzable_probes = 0
        self._ran_campaigns = set()
        self._body_hashes = set()
        self._current_objective = None
        self._try_harder_fired = False
        self._reach_attempted = set()
        self._reach_class = {}
        self._reach_body_cache = {}
        self._bound_origin = {}
        self._host_stack = {}
        self._organic_crawl_count = {}
        self._dead_hosts = set()

        parsed = urlparse(target_url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        # Stack-gated initial seed (was: raw WELL_KNOWN_LEAK_PATHS union fired
        # unconditionally at every host — 9 WP-config + 2 actuator paths that
        # can only ever match one stack each, sent to 100% of targets before
        # a single fingerprint response comes back; this is what tripped
        # WAF/CF breadth-anomaly detection even at a throttled rps).
        # labels=[] because nothing is fingerprinted yet at run start — this
        # correctly resolves to the same universal + DEFAULT_LEAK_PATHS
        # fallback try_harder already used for unknown hosts (§ Planner
        # .select_leak_paths). Stack-specific paths (WP-config, actuator)
        # arrive later via CapabilitySpec.frontier_seeds the moment
        # _handle_capability_fingerprint confirms that stack — see
        # capability_probe.py patch.
        # Bug #26 consumer: read this host's passive-intel signal (domain-scoped)
        # from the PASSIVE_INTEL_GATHERED stream to steer probe selection.
        intel_signal = passive_intel_signal_for_host(
            self.event_store, engagement_id, parsed.hostname or parsed.netloc
        )
        # Layer 5 — WAF/CDN detected (protection_detected) → suppress the blind
        # DEFAULT_LEAK_PATHS spray on this unfingerprinted host; probe stack-specific
        # only AFTER a fingerprint, avoiding the 404 breadth-anomaly that trips the WAF.
        suppress_blind = intel_signal.protection_detected is not None
        for path in self._planner.select_leak_paths(labels=[], suppress_default=suppress_blind):
            self.enqueue_discovered_url(f"{root}{path}")
        # Layer 1 — enqueue paths the site historically served (OTX historical_paths):
        # real paths beat blind guesses and generate no 404 noise.
        for path in intel_signal.historical_paths:
            self.enqueue_discovered_url(f"{root}{path}")
        for path in getattr(
            constants, "SURFACE_DISCOVERY_PATHS", ()
        ):  # unchanged: universal, cheap (ADR §12.26)
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

    def _tool_applies(self, tool: str, resp: Any) -> bool:
        """A JSON-body tool is inapplicable to a non-JSON response. Every
        other tool (header/regex/generic) has no body-shape precondition."""
        if tool not in constants.JSON_BODY_TOOLS:
            return True
        return is_json_response(resp.headers.get("content-type", ""), resp.text)

    def _step_once(self, context: dict[str, object]) -> dict[str, object]:  # noqa: C901
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

        # Pop an unprobed target; none left → try harder, then dead-end.
        url = self._pop_unprobed()
        if url is None:
            if self._try_harder_enabled:
                url = self._try_harder_recovery()
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
            host = urlparse(url).hostname or urlparse(url).netloc
            # R1: mark dead ONLY on a root/homepage transport failure. A non-root
            # failure (e.g. WAF RST on /.env while the homepage is 200) must NOT
            # kill a live host — false-negatives drop payable surface (anti-#3).
            if urlparse(url).path in ("", "/"):
                self._dead_hosts.add(host)
                # R2: prune queued paths for this host NOW in one pass so that
                # _pop_unprobed stays untouched and work_remaining stays accurate.
                self._work_queue = [
                    u
                    for u in self._work_queue
                    if (urlparse(u).hostname or urlparse(u).netloc) != host
                ]
                # S1: append-only audit event (parity with WAF_BLOCKED) + monologue.
                self._persist_host_abandoned_event(host)
                self._emit("OBSERVE", f"{host} root unreachable → abandon its queue")
            else:
                self._emit("OBSERVE", f"{url} unreachable; probe is non-analyzable")
            return _finish(0, 0.0, f"OBSERVE: {url} unreachable")

        # Classify the response through the ONE canonical classifier so a WAF/CF
        # block on ANY recon path is recorded as evidence and never dressed as
        # clean (anti-Lyndon #3, single source of truth — anti-#7).
        verdict = classify_response(
            status_code=resp.status_code, body=resp.text, headers=dict(resp.headers)
        )

        # ── Per-host reach-class (ADR §12.41) ─────────────────
        # Decide ONCE per host whether to route via browser reach.
        reach_result = self._apply_host_reach_class(url, verdict, resp)
        if reach_result is not None:
            return reach_result
        resp, verdict = self._maybe_swap_reach_body(url, resp, verdict)

        # A WAF/CF block is a non-analyzable probe, NOT a clean/no-progress
        # result. Attempt reach (capability-gated, bounded), then record
        # WAF_BLOCKED if reach is unavailable or still blocked (anti-#3).
        if verdict in (Verdict.BLOCKED, Verdict.CHALLENGE):
            reach_resp = self._attempt_reach(url, resp)
            if reach_resp is not None:
                # Re-OBSERVE with the reached response — classify again
                # so a successful origin-direct / browser_solve flows into
                # the normal ORIENT→PLAN→ACT path.
                resp = reach_resp
                verdict = classify_response(
                    status_code=resp.status_code,
                    body=resp.text,
                    headers=dict(resp.headers),
                )

            if verdict in (Verdict.BLOCKED, Verdict.CHALLENGE):
                return self._handle_waf_block(url, resp, verdict, obs, sp)

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
        if handler is not None and not self._tool_applies(decision.tool, resp):
            # Deterministic tool/content mismatch. NOT a silent 0 (anti-#3):
            # record the mismatch as evidence, then fall back ONCE to the
            # header-only generic probe, which is applicable to any body.
            self._emit(
                "ORIENT",
                f"{decision.tool} requires a JSON body; {url} returned "
                f"{resp.headers.get('content-type', 'unknown')} — "
                "re-routing to generic_http_probe",
            )
            self.event_store.append(
                EventType.PASSIVE_DISCOVERY,
                self._engagement_id,
                "alpha",
                {
                    "url": url,
                    "reason": "tool_content_mismatch",
                    "selected_tool": decision.tool,
                },
            )
            nodes_added = self._handle_generic_probe(resp, url)
        elif handler is not None:
            nodes_added = handler(resp, decision, url)
        else:
            # Generic probe: optionally record an ASSET node from headers,
            # but NEVER with "laravel" in tech_stack, and NEVER increment
            # findings.
            nodes_added = self._handle_generic_probe(resp, url)

        # Universal auth-surface detection (anti per-target #11): ANY reachable
        # login/auth surface becomes a first-class finding, whatever tool ran.
        nodes_added += self._detect_auth_surface(resp, url)

        self._emit("PERSIST", f"Persisted {nodes_added} graph node(s) from {url}")

        # ── FRONTIER EXPANSION (R1) ─────────────────────────────
        # Enqueue in-scope hrefs — ONLY for a real (OK) page. A 404 error page is
        # not a surface to crawl (its nav links are noise, and crawling them would
        # re-inflate the very probing F2 trims).
        if verdict is Verdict.OK:
            nodes_added += self._handle_content_analysis(resp, url)
            for href in self._extract_hrefs(resp.text, url):
                if self._frontier_expansion_allowed(href) and self.enqueue_discovered_url(href):
                    h = urlparse(href).hostname or urlparse(href).netloc
                    self._organic_crawl_count[h] = self._organic_crawl_count.get(h, 0) + 1

        return _finish(
            nodes_added, decision.cost_usd, f"ACT: {decision.tool} on {url} -> {nodes_added} nodes"
        )

    # ── Private: WAF/CF block handling ───────────────────────────

    def _handle_waf_block(
        self,
        url: str,
        resp: Any,
        verdict: Verdict,
        obs: list[str],
        sp: dict[str, Any],
    ) -> dict[str, object]:
        """Record a WAF/CF block as WAF_BLOCKED event and return a _finish result."""
        host = urlparse(url).hostname or urlparse(url).netloc
        is_challenge = verdict is Verdict.CHALLENGE
        self._emit(
            "OBSERVE",
            f"{url} returned HTTP {resp.status_code}; "
            + ("CDN/WAF challenge" if is_challenge else "WAF/CF block")
            + " — non-analyzable",
        )
        waf_payload: dict[str, Any] = {
            "host": host,
            "path": urlparse(url).path,
            "status_code": resp.status_code,
        }
        if is_challenge:
            waf_payload["signal"] = "cf_challenge"
        self.event_store.append(
            EventType.WAF_BLOCKED,
            self._engagement_id,
            "alpha",
            waf_payload,
        )
        obs.append(
            f"OBSERVE: {url} " + ("CDN challenge" if is_challenge else "WAF blocked"),
        )
        return {"discovered_nodes": 0, "cost_usd": 0.0, "scratchpad": sp}

    # ── Private: per-host reach-class helpers (ADR §12.41) ──────────

    def _apply_host_reach_class(
        self,
        url: str,
        verdict: Verdict,
        resp: Any,
    ) -> dict[str, object] | None:
        """Classify the host's reach on first contact, or upgrade if a later
        path shows new evidence. Returns a _finish dict only for honest
        INCONCLUSIVE skips; None to fall through to normal analysis."""
        host = urlparse(url).hostname or ""
        if host and host not in self._reach_class:
            cost_gate = verdict in (Verdict.BLOCKED, Verdict.CHALLENGE) or (
                verdict is Verdict.OK and is_reload_shell(resp.text)
            )
            if cost_gate:
                self._reach_class[host] = self._classify_host_reach(url, resp)
            else:
                self._reach_class[host] = "clear"
        elif host and self._reach_class.get(host) == "clear":
            # Upgrade: a later path shows shell or block evidence that the
            # entry path did not. Re-probe to upgrade "clear" → "challenged".
            upgrade_gate = verdict in (Verdict.BLOCKED, Verdict.CHALLENGE) or (
                verdict is Verdict.OK and is_reload_shell(resp.text)
            )
            if upgrade_gate:
                self._reach_class[host] = self._classify_host_reach(url, resp)

        cls = self._reach_class.get(host, "clear")
        if cls == "blocked":
            # Browser probe failed. If the current body is a shell, honest
            # skip — we can't reach real content. If it's NOT a shell, fall
            # through to normal analysis (FP-safe: don't discard real content).
            if is_reload_shell(resp.text) or verdict in (Verdict.BLOCKED, Verdict.CHALLENGE):
                # Origin-direct can still bypass CF even when browser_solve failed.
                # Fall through to _attempt_reach if we have authorized origins.
                # §12.46: fall through to _attempt_reach when EITHER pre-signed
                # origins exist OR origin discovery is consented (the binding path
                # can prove-and-hit a discovered origin, bypassing the WAF).
                has_reach_path = self._engagement_profile is not None and (
                    getattr(self._engagement_profile, "authorized_origins", None)
                    or getattr(self._engagement_profile, "allow_origin_discovery", False)
                )
                if self._origin_discovery is not None and has_reach_path:
                    return None  # fall through to _attempt_reach
                return {
                    "discovered_nodes": 0,
                    "cost_usd": 0.0,
                    "scratchpad": {
                        "observations": [
                            f"OBSERVE: {url} host reach-blocked; skipped (INCONCLUSIVE)"
                        ]
                    },
                }
            return None
        if cls == "challenged" and host not in self._reach_body_cache:
            # Entry body already consumed; without a cf_clearance session we
            # cannot fetch deeper paths' real content — honest skip (slice-2
            # recovers via per-path browser or session replay).
            return {
                "discovered_nodes": 0,
                "cost_usd": 0.0,
                "scratchpad": {
                    "observations": [
                        f"OBSERVE: {url} challenged-host subsequent path; "
                        "skipped (INCONCLUSIVE, no session lane)"
                    ]
                },
            }
        return None

    def _maybe_swap_reach_body(
        self,
        url: str,
        resp: Any,
        verdict: Verdict,
    ) -> tuple[Any, Verdict]:
        """If the host is challenged and a browser body is cached, swap in
        the browser response and re-classify. Otherwise return unchanged."""
        host = urlparse(url).hostname or ""
        cls = self._reach_class.get(host, "clear")
        if cls == "challenged":
            rb = self._reach_body_cache.pop(host, None)
            if rb is None:
                return resp, verdict
            resp = _ReachResponse(
                status_code=rb.status_code,
                body=rb.body,
                headers=dict(rb.headers),
            )
            verdict = classify_response(
                status_code=resp.status_code,
                body=resp.text,
                headers=dict(resp.headers),
            )
        return resp, verdict

    # ── Private: per-host reach-class (ADR §12.41) ───────────────

    def _classify_host_reach(self, url: str, httpx_resp: Any) -> str:
        """Empirically classify a host's reach via a single browser probe.

        Returns ``"clear"``, ``"challenged"``, ``"blocked"``, or
        ``"unresolved"``.  Consent-gated: if browser_solve is not viable
        (no consent, no transport), returns ``"unresolved"`` so the caller
        falls through to normal analysis (FP-safe — no content discarded).
        """
        # Consent gate: reuse the same gate as _attempt_reach
        browser_solve_viable = (
            self._browser_solve is not None
            and self._browser_solve_viable
            and getattr(self._engagement_profile, "allow_evasion", False)
        )
        if not browser_solve_viable or self._browser_solve is None:
            return "unresolved"

        host = urlparse(url).hostname or ""
        browser_solve = self._browser_solve

        try:
            r = browser_solve.solve_and_fetch(
                url,
                engagement_id=self._engagement_id,
            )
        except RuntimeError:
            return "blocked"

        # challenge_encountered + challenge_solved are the authoritative
        # signals from our own browser.
        # - No challenge encountered → "clear" (legit page, browser confirms)
        # - Challenge encountered and solved → "challenged" (use browser body)
        # - Challenge encountered but NOT solved → "blocked" (can't reach)
        if r.challenge_solved:
            self._reach_body_cache[host] = r
            return "challenged"
        if r.challenge_encountered:
            return "blocked"
        return "clear"

    # ── Private: reach strategy (Phase 2.5 — §12.33) ──────────────

    def _attempt_reach(self, url: str, resp: Any) -> Any | None:
        """Attempt a reach strategy for a blocked/challenged URL.

        Reuses classify_mitigation → choose_reach → origin_direct_fetch /
        browser_solve (anti-#6). Capability-gated: ORIGIN_DIRECT requires an
        authorized origin in the signed profile; EVASION requires
        ``allow_evasion``. Bounded: at most one attempt per URL.

        Returns a ``_ReachResponse`` if reach succeeds, or ``None`` if reach
        is not available / not authorized / already attempted / failed (honest
        block — anti-#3).
        """
        # Bounded: at most one reach attempt per blocked resource
        if url in self._reach_attempted:
            return None
        self._reach_attempted.add(url)

        # No engagement profile → no reach deps → honest block
        if self._engagement_profile is None:
            return None

        host = urlparse(url).hostname or urlparse(url).netloc
        path = urlparse(url).path

        # 1. Classify the mitigation (granular class drives strategy — anti-#11)
        mitigation = classify_mitigation(
            status_code=resp.status_code,
            body=resp.text,
            headers=dict(resp.headers),
            path=path,
        )

        # 2. Resolve authorized origin: discovery candidates filtered against
        #    signed authorized_origins (C9: candidate ≠ authorization)
        #    AND filter out Cloudflare edge IPs — hitting CF edge with Host header
        #    is NOT origin-direct (it still hits CF WAF).
        # PER-HOST cache (perf + opsec): origin discovery (crt.sh, 30s timeout when
        # down) + token-canary binding are IDENTICAL for every blocked path on the
        # same host. Resolve ONCE per host and reuse the result — INCLUDING the empty
        # "tried, nothing authorized" negative case — for all subsequent paths. Was
        # re-run per URL (~15x/host = ~15x 30s crt.sh re-fetch + a repeated-fetch
        # fingerprint). Mirrors the per-host _reach_class cache.
        cached_origins = self._bound_origin.get(host)
        if cached_origins is not None:
            authorized_origins_list = cached_origins
        else:
            authorized_origins_list = []
            if self._origin_discovery is not None and getattr(
                self._engagement_profile, "authorized_origins", None
            ):
                # Static/cooperative path: client pre-signed the origin IPs.
                candidates = self._origin_discovery.candidates(host)
                authorized_origins_list = [
                    ip
                    for ip in candidates
                    if ip in self._engagement_profile.authorized_origins
                    and not is_cloudflare_ip(ip)  # CF edge IPs are not valid origins
                ]

            # §12.46 discovery path: no pre-signed origin, but the signed profile
            # consented to allow_origin_discovery → discover candidates and PROVE-bind
            # one (ownership-token canary). resolve_and_bind_origin emits
            # ORIGIN_BINDING_PROVEN for the proven IP; the composed gate below then
            # authorizes it. Fail-closed: None (no reach) when nothing binds.
            if (
                not authorized_origins_list
                and self._origin_discovery is not None
                and getattr(self._engagement_profile, "allow_origin_discovery", False)
            ):
                bound_ip = resolve_and_bind_origin(
                    fronted_host=host,
                    profile=self._engagement_profile,
                    event_store=self.event_store,
                    engagement_id=self._engagement_id,
                    discovery=self._origin_discovery,
                )
                if bound_ip is not None:
                    authorized_origins_list = [bound_ip]

            self._bound_origin[host] = authorized_origins_list

        authorized_origin = authorized_origins_list[0] if authorized_origins_list else None

        # 3. Capability gate: browser_solve viable only if transport is
        #    injected AND profile authorizes evasion (§12.36)
        browser_solve_viable = (
            self._browser_solve is not None
            and self._browser_solve_viable
            and getattr(self._engagement_profile, "allow_evasion", False)
        )

        # 3b. TLS-impersonate gate: curl_cffi importable AND profile authorizes
        #     evasion (§12.36). Datacenter-viable — needs NO browser, NO injected
        #     browser_solve. Separate from browser_solve_viable (different transport).
        tls_impersonate_viable = is_tls_impersonate_available() and getattr(
            self._engagement_profile, "allow_evasion", False
        )

        # 4. Choose reach strategy (differential — mitigation class → strategy)
        strategy = choose_reach(
            mitigation,
            browser_solve_viable=browser_solve_viable,
            authorized_origin=authorized_origin,
            tls_impersonate_viable=tls_impersonate_viable,
        )

        # 5. Dispatch
        if strategy is ReachStrategy.ORIGIN_DIRECT and authorized_origin is not None:
            from agent_alpha.conductor.engagement_profile import (
                assert_origin_authorized_or_bound,
            )

            last_response: _ReachResponse | None = None
            for origin_ip in authorized_origins_list:
                # §12.46 composed gate — fail-closed. Authorizes iff the IP is in
                # the signed authorized_origins OR (allow_origin_discovery AND an
                # ORIGIN_BINDING_PROVEN event exists for this IP + fronted host).
                assert_origin_authorized_or_bound(
                    origin_ip,
                    host,
                    self._engagement_profile,
                    self.event_store,
                    self._engagement_id,
                )

                self._emit(
                    "OBSERVE",
                    f"Reach: ORIGIN_DIRECT for {url} via {origin_ip}",
                )

                # Audit event (origin-direct bypasses WAF — audit-sensitive)
                self.event_store.append(
                    EventType.ORIGIN_DIRECT_ATTEMPT,
                    self._engagement_id,
                    "alpha",
                    {
                        "host": host,
                        "origin_ip": origin_ip,
                        "authorized": True,
                        "discovered_via": "origin_discovery",
                    },
                )

                try:
                    result = origin_direct_fetch(host, origin_ip, path)
                except RuntimeError:
                    self._emit(
                        "OBSERVE",
                        f"Reach: origin_direct_fetch failed for {url} via {origin_ip}",
                    )
                    continue

                candidate = _ReachResponse(
                    status_code=result.status_code,
                    body=result.body,
                    headers=dict(result.headers),
                )
                last_response = candidate

                origin_verdict = classify_response(
                    status_code=candidate.status_code,
                    body=candidate.text,
                    headers=dict(candidate.headers),
                )

                # Useful = real content, not a WAF block, not a redirect/not-found
                if origin_verdict not in (Verdict.BLOCKED, Verdict.CHALLENGE) and (
                    candidate.status_code not in (301, 302, 303, 307, 308, 404)
                ):
                    return candidate

            # No origin returned useful content — return the last response seen
            # (honest: caller re-classifies; a 404/redirect is still non-block
            # evidence) or None if every origin raised.
            return last_response

        if strategy is ReachStrategy.EVASION and self._browser_solve is not None:
            self._emit(
                "OBSERVE",
                f"Reach: EVASION (browser_solve) for {url}",
            )

            try:
                result = self._browser_solve.solve_and_fetch(url, engagement_id=self._engagement_id)
            except RuntimeError:
                self._emit(
                    "OBSERVE",
                    f"Reach: browser_solve failed for {url}",
                )
                return None

            if not result.challenge_solved:
                self._emit(
                    "OBSERVE",
                    f"Reach: browser_solve did not solve challenge for {url}",
                )
                return None

            return _ReachResponse(
                status_code=result.status_code,
                body=result.body,
                headers=dict(result.headers),
            )

        if strategy is ReachStrategy.TLS_IMPERSONATE:
            self._emit(
                "OBSERVE",
                f"Reach: TLS_IMPERSONATE for {url}",
            )

            # Audit event (TLS impersonation evades WAF fingerprint — audit-sensitive)
            self.event_store.append(
                EventType.TLS_IMPERSONATE_ATTEMPT,
                self._engagement_id,
                "alpha",
                {
                    "host": host,
                    "technique": "tls_impersonate",
                    "authorized": True,
                },
            )

            try:
                result = tls_impersonate_fetch(url)
            except RuntimeError:
                self._emit(
                    "OBSERVE",
                    f"Reach: tls_impersonate_fetch failed for {url}",
                )
                return None

            return _ReachResponse(
                status_code=result.status_code,
                body=result.body,
                headers=dict(result.headers),
            )

        # DIRECT: no authorized plan B → honest block (anti-#3)
        self._emit(
            "OBSERVE",
            f"Reach: no authorized strategy for {url} (mitigation={mitigation})",
        )
        return None

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
        asset_node = merge_asset_node(
            self.graph_store,
            host,
            tech_stack_add=["laravel"],
            confidence=0.95,
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
            scheme=urlparse(url).scheme or "https",
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

        Bug fix: the LLM tier can pick ``odoo_dbmanager_probe`` for a non-manager
        page (e.g. homepage with 214-byte CF challenge body).  If the body does
        NOT carry Odoo DB-manager markers, we return 0 WITHOUT burning the
        idempotency guard, so the tool can still fire on the real
        /web/database/manager page later.
        """
        if decision.tool in self._ran_campaigns:
            return 0

        from agent_alpha.recon.odoo_dbmanager_probe import EXPOSED, classify_odoo_dbmanager

        body = resp.text if hasattr(resp, "text") else str(resp)
        if classify_odoo_dbmanager(body) != EXPOSED:
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

    def _handle_odoo_fingerprint(self, resp: Any, decision: Any, url: str) -> int:
        """Thin wrapper over _handle_capability_fingerprint for Odoo Version Disclosure.

        Explicitly checks _ran_campaigns (run-once) BEFORE delegating, guaranteeing
        anti-#2 (no LLM starvation on subsequent pages).
        """
        if decision.tool in self._ran_campaigns:
            return 0

        # 1. Delegate generic label + seed behavior (it adds to _ran_campaigns for us)
        added = self._handle_capability_fingerprint(resp, decision, url)

        # 2. Check for version disclosure
        from agent_alpha.recon.odoo_dbmanager_probe import verify_odoo_version

        v_added = verify_odoo_version(
            http_client=self.http_client,
            url=url,
            engagement_id=self._engagement_id,
            auth=self.authorization,
            graph_store=self.graph_store,
            event_store=self.event_store,
        )

        if v_added > 0:
            self._findings += 1

        return added + v_added

    def _detect_auth_surface(self, resp: Any, url: str) -> int:
        """Universal auth-surface persistence (anti per-target #11). Records ANY
        reachable login/auth surface as a first-class ASSET finding so the router
        (has_web_auth_surface) can route the access phase to it - independent of
        whether a framework-specific vuln probe fired. Idempotent via
        merge_asset_node + deterministic asset:{host} node id."""
        host = urlparse(url).hostname or urlparse(url).netloc
        if not host:
            return 0
        labels = detect_auth_surface_labels(
            status_code=resp.status_code,
            headers=resp.headers,
            body=getattr(resp, "text", "") or "",
        )
        if not labels:
            return 0
        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        asset_node = merge_asset_node(
            self.graph_store,
            host,
            tech_stack_add=labels,
            confidence=0.7,
            timestamp_utc=now_utc,
        )
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, asset_node, agent="alpha"
        )
        return 1

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

        asset_node = merge_asset_node(
            self.graph_store,
            host,
            tech_stack_add=tech_stack,
            confidence=0.5,
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

        # merge_asset_node UNIONs tech_stack and preserves every prior property
        # (ip / open_ports / rest_routes / ...) so sequential fingerprints (e.g.
        # tomcat then basic_auth) never clobber each other or an earlier profile.
        asset_node = merge_asset_node(
            self.graph_store,
            host,
            tech_stack_add=[spec.label],
            confidence=spec.confidence,
            timestamp_utc=now_utc,
        )
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, asset_node, agent="alpha"
        )

        for seed in spec.frontier_seeds:
            self.enqueue_discovered_url(urljoin(url, seed))

        for follow_tool in spec.follow_up_tools:
            handler = self._dispatch_registry.get(follow_tool)
            if handler is not None:
                handler(resp, SimpleNamespace(tool=follow_tool), url)

        # R2 selective crawl (tag AFTER seeds/follow-ups above so this
        # fingerprint's OWN deterministic seeds are never gated by it).
        self._host_stack.setdefault(host, set()).add(spec.label)

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
        asset_node = merge_asset_node(
            self.graph_store,
            host,
            tech_stack_add=["openapi"],
            confidence=0.8,
            timestamp_utc=now_utc,
        )
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, asset_node, agent="alpha"
        )
        return 1

    # ── WordPress recon-depth battery (fingerprint-keyed playbooks) ──────
    # Each handler mirrors an existing precedent: DETECT-only surface mirrors
    # _handle_surface_discovery (asset property, zero findings); the FINDING
    # handlers mirror the wp_config leak path (VULNERABILITY + ASSET + EXPLOITS
    # edge, +1 finding) and require a confirmed BODY signature — status 200 alone
    # is never a finding (WordPress soft-404 returns 200 with an HTML body).

    def _handle_wp_rest_routes(self, resp: Any, decision: Any, url: str) -> int:
        """DETECT-only: enumerate the WordPress ``/wp-json/`` route index.

        Persists ONE asset node carrying the route inventory as
        ``AssetProperties.rest_routes`` (capped at ``WP_REST_ROUTES_CAP`` with
        ``rest_routes_truncated`` + ``rest_routes_total_count`` recording the real
        size). A route surface is reach, NOT a payable finding: this never touches
        ``self._findings``. Only routes in ``constants.WP_REST_INTERESTING_ROUTES``
        are escalated (enqueued) through the same in-scope guard as every other
        discovery; the rest sit inert on the asset (anti-#3 over-probe).
        """
        host = urlparse(url).hostname
        if not host or not self.authorization.is_in_scope(self._engagement_id, host):
            return 0

        try:
            data = json.loads(resp.text)
        except (ValueError, TypeError):
            return 0
        if not isinstance(data, dict):
            return 0
        routes_obj = data.get("routes")
        if not isinstance(routes_obj, dict) or not routes_obj:
            return 0

        route_keys = [str(k) for k in routes_obj]
        total = len(route_keys)
        cap = constants.WP_REST_ROUTES_CAP
        stored = route_keys[:cap]
        truncated = total > cap

        spec = capability_for_tool(decision.tool)
        label = spec.label if spec is not None else constants.STACK_WP
        confidence = spec.confidence if spec is not None else 0.9

        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        # rest_routes* are the observed fields for THIS handler; merge_asset_node
        # unions the WP label and preserves any prior profile (ip/open_ports/...).
        asset_node = merge_asset_node(
            self.graph_store,
            host,
            tech_stack_add=[label],
            confidence=confidence,
            timestamp_utc=now_utc,
            rest_routes=stored,
            rest_routes_total_count=total,
            rest_routes_truncated=truncated,
        )
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, asset_node, agent="alpha"
        )

        # ── Plugin namespace prober (unauthenticated access detection) ──────────
        # The /wp-json/ index "namespaces" list is free from the existing response.
        # For each namespace present in the curated dangerous list, attempt ONE
        # inline GET. A 200 with a non-WP-error body = unauthenticated access
        # confirmed = VULNERABILITY. A 401/403/404 = auth-gated or absent = no finding.
        nodes_added = 1  # the asset node persisted above
        probe_campaign_key = f"wp_rest_plugin_probe:{host}"
        if probe_campaign_key not in self._ran_campaigns:
            self._ran_campaigns.add(probe_campaign_key)
            detected_namespaces: set[str] = set(data.get("namespaces", []))
            for ns, (
                probe_path,
                affected_service,
                cvss,
            ) in constants.WP_PLUGIN_DANGEROUS_NAMESPACES.items():
                if ns not in detected_namespaces:
                    continue
                # Normalize: url is the /wp-json/ index root; probe_path is absolute
                # starting with /wp-json/, so we build from scheme+host only.
                parsed_root = urlparse(url)
                probe_url = f"{parsed_root.scheme}://{parsed_root.netloc}{probe_path}"
                try:
                    probe_resp = self.http_client.get(probe_url, allow_redirects=False)
                except HttpClientError:
                    continue  # transport failure = not provably accessible
                if probe_resp.status_code != 200:
                    continue  # auth-gated (401/403) or absent (404) = no finding
                # Reject WP-standard error envelope {"code":..., "data":{"status":...}}
                try:
                    probe_json = json.loads(probe_resp.text)
                    if (
                        isinstance(probe_json, dict)
                        and "code" in probe_json
                        and "data" in probe_json
                    ):
                        continue  # WP error response — not accessible
                except (ValueError, TypeError):
                    pass  # non-JSON 200 is fine (some plugins return HTML); still accessible
                if not probe_resp.text.strip():
                    continue  # empty body = not meaningful
                artifact_id_ns = str(uuid.uuid4())
                evidence_ns = (
                    f"WordPress plugin namespace '{ns}' detected in REST index at {url} "
                    f"and endpoint {probe_url} returned HTTP 200 without authentication. "
                    f"Affected plugin: {affected_service}. Response preview: "
                    f"{probe_resp.text[:300]!r}"
                )
                vuln_id_ns = f"vuln:{host}:{affected_service}_unauthenticated_rest"
                vuln_ns = AttackNode(
                    id=vuln_id_ns,
                    type=NodeType.VULNERABILITY,
                    properties=VulnerabilityProperties(
                        affected_service=affected_service,
                        cvss_score=cvss,
                        exploit_available=False,
                    ),
                    confidence=0.9,
                    agent="alpha",
                    timestamp_utc=now_utc,
                    proof_artifacts=[
                        ProofArtifact(
                            artifact_id=artifact_id_ns,
                            type="http_response",
                            storage_ref=f"engagements/{self._engagement_id}/proofs/{artifact_id_ns}",
                            description=evidence_ns,
                            captured_at=now_utc,
                            agent="alpha",
                            target=probe_url,
                        )
                    ],
                )
                persist_node(
                    self.event_store,
                    self.graph_store,
                    self._engagement_id,
                    vuln_ns,
                    agent="alpha",
                )
                nodes_added += 1
                self._persist_wp_asset(host, vuln_id_ns, now_utc)
                self._findings += 1

        # Escalate ONLY allowlisted routes through the in-scope guard.
        for key in route_keys:
            full = "/wp-json" + key if key.startswith("/") else "/wp-json/" + key
            if full in constants.WP_REST_INTERESTING_ROUTES:
                self.enqueue_discovered_url(urljoin(url, full))
        return nodes_added

    def _handle_wp_rest_users(self, resp: Any, decision: Any, url: str) -> int:
        """FINDING: WordPress REST username disclosure (``/wp-json/wp/v2/users``).

        A finding is minted ONLY when the body parses as the user JSON shape (an
        array of objects each carrying ``id`` + ``slug``). A 200 HTML soft-404 or
        any other shape yields zero findings. Discovered slugs are persisted as
        USER nodes — the cred-reuse INPUT (a username to pair with harvested
        secrets downstream), never a credential.
        """
        if decision.tool in self._ran_campaigns:
            return 0
        self._ran_campaigns.add(decision.tool)

        host = urlparse(url).hostname
        if not host or not self.authorization.is_in_scope(self._engagement_id, host):
            return 0

        slugs = self._parse_wp_rest_user_slugs(resp.text)
        if not slugs:
            return 0  # anti-#3: no body signature (soft-404 / wrong shape) = not a finding

        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        artifact_id_users = str(uuid.uuid4())
        evidence_users = (
            f"WordPress REST API user enumeration confirmed at {url}; "
            f"{len(slugs)} account(s) disclosed: {', '.join(slugs)}. "
            "No authentication required to retrieve username list."
        )
        vuln_id = f"vuln:{host}:wp_rest_user_disclosure"
        vuln_node = AttackNode(
            id=vuln_id,
            type=NodeType.VULNERABILITY,
            properties=VulnerabilityProperties(
                affected_service="web",
                cvss_score=5.3,
                exploit_available=False,
            ),
            confidence=0.9,
            agent="alpha",
            timestamp_utc=now_utc,
            proof_artifacts=[
                ProofArtifact(
                    artifact_id=artifact_id_users,
                    type="http_response",
                    storage_ref=f"engagements/{self._engagement_id}/proofs/{artifact_id_users}",
                    description=evidence_users,
                    captured_at=now_utc,
                    agent="alpha",
                    target=url,
                )
            ],
        )
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, vuln_node, agent="alpha"
        )
        nodes_added = 1
        nodes_added += self._persist_wp_asset(host, vuln_id, now_utc)

        for slug in slugs:
            user_node = AttackNode(
                id=f"user:{host}:{slug}",
                type=NodeType.USER,
                properties=UserProperties(username=slug, source="wp_rest_users"),
                confidence=0.9,
                agent="alpha",
                timestamp_utc=now_utc,
            )
            persist_node(
                self.event_store, self.graph_store, self._engagement_id, user_node, agent="alpha"
            )
            nodes_added += 1

        self._findings += 1
        return nodes_added

    def _handle_woocommerce(self, resp: Any, decision: Any, url: str) -> int:
        """FINDING when the body confirms a WooCommerce ``wc/v3`` shape.

        A ``/wp-json/`` index with no ``wc/*`` route is INSUFFICIENT DATA — not an
        error, not a finding (returns 0). The finding requires the wc/v3 body
        signature (anti-#3).
        """
        if decision.tool in self._ran_campaigns:
            return 0
        self._ran_campaigns.add(decision.tool)

        host = urlparse(url).hostname
        if not host or not self.authorization.is_in_scope(self._engagement_id, host):
            return 0

        if not self._confirms_woocommerce(resp.text):
            return 0  # InsufficientData — WooCommerce not present

        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        artifact_id_wc = str(uuid.uuid4())
        evidence_wc = (
            f"WooCommerce REST API (wc/v3) registered and namespace-enumerable at {url}; "
            "wc/v3 namespace present in wp-json REST index (installation detectable, "
            "version enumeration enabled)."
        )
        vuln_id = f"vuln:{host}:woocommerce_exposed"
        vuln_node = AttackNode(
            id=vuln_id,
            type=NodeType.VULNERABILITY,
            properties=VulnerabilityProperties(
                affected_service="woocommerce",
                cvss_score=5.3,
                exploit_available=False,
            ),
            confidence=0.85,
            agent="alpha",
            timestamp_utc=now_utc,
            proof_artifacts=[
                ProofArtifact(
                    artifact_id=artifact_id_wc,
                    type="http_response",
                    storage_ref=f"engagements/{self._engagement_id}/proofs/{artifact_id_wc}",
                    description=evidence_wc,
                    captured_at=now_utc,
                    agent="alpha",
                    target=url,
                )
            ],
        )
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, vuln_node, agent="alpha"
        )
        nodes_added = 1 + self._persist_wp_asset(host, vuln_id, now_utc)
        self._findings += 1
        return nodes_added

    def _handle_wp_version(self, resp: Any, decision: Any, url: str) -> int:
        """FINDING (low sev): WordPress version disclosure.

        Two requests: the readme.html body that triggered this handler plus a
        corroborating GET of the site root for the ``<meta generator>`` banner.
        The version is taken from the body SIGNATURE (readme ``Version x.y`` or the
        generator meta) — status 200 alone is never a finding.
        """
        if decision.tool in self._ran_campaigns:
            return 0
        self._ran_campaigns.add(decision.tool)

        host = urlparse(url).hostname
        if not host or not self.authorization.is_in_scope(self._engagement_id, host):
            return 0

        version = self._extract_wp_version_readme(resp.text)

        # Second request: <meta generator> on the site root (corroboration).
        # allow_redirects=False mirrors the A1 mitigation probe's off-scope guard
        # (a1_validation_runner): a 3xx to another host must NOT be followed and its
        # body must NOT be read for the generator banner (an off-scope page cannot
        # corroborate THIS host's version). On any 3xx we fall back to the readme
        # signature alone (or None → not a finding).
        parsed = urlparse(url)
        root = f"{parsed.scheme}://{parsed.netloc}/"
        try:
            root_resp = self.http_client.get(root, allow_redirects=False)
        except HttpClientError:
            root_resp = None
        if root_resp is not None and not 300 <= getattr(root_resp, "status_code", 0) < 400:
            meta_version = self._extract_wp_version_meta(getattr(root_resp, "text", "") or "")
            version = version or meta_version

        if version is None:
            return 0  # no body signature — not a finding

        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        artifact_id_ver = str(uuid.uuid4())
        evidence_ver = (
            f"WordPress {version} version disclosed via readme.html / meta generator tag at {url}."
        )
        vuln_id = f"vuln:{host}:wp_version_disclosure"
        vuln_node = AttackNode(
            id=vuln_id,
            type=NodeType.VULNERABILITY,
            properties=VulnerabilityProperties(
                affected_service=f"WordPress {version}",
                cvss_score=3.1,
                exploit_available=False,
            ),
            confidence=0.8,
            agent="alpha",
            timestamp_utc=now_utc,
            proof_artifacts=[
                ProofArtifact(
                    artifact_id=artifact_id_ver,
                    type="http_response",
                    storage_ref=f"engagements/{self._engagement_id}/proofs/{artifact_id_ver}",
                    description=evidence_ver,
                    captured_at=now_utc,
                    agent="alpha",
                    target=url,
                )
            ],
        )
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, vuln_node, agent="alpha"
        )
        nodes_added = 1 + self._persist_wp_asset(host, vuln_id, now_utc)
        self._findings += 1
        return nodes_added

    def _handle_wp_plugins(self, resp: Any, decision: Any, url: str) -> int:
        """FINDING: vulnerable WordPress plugin detection from page HTML.

        Regex-extracts plugin slug + version from asset paths in the already-fetched
        body (no new HTTP). Each (slug, version) is checked against the CVE catalogue;
        a hit mints a SELF_VERIFIED VULNERABILITY node. version=None or a patched
        version -> NOT a finding (anti-#3).
        """
        if decision.tool in self._ran_campaigns:
            return 0
        self._ran_campaigns.add(decision.tool)

        host = urlparse(url).hostname
        if not host or not self.authorization.is_in_scope(self._engagement_id, host):
            return 0

        body = getattr(resp, "text", "") or ""
        pattern = r"/wp-content/plugins/([a-z0-9\-]+)/[^\"']*?[?&]ver=([0-9][0-9.]*)"
        seen_slugs: dict[str, str] = {}
        for match in re.finditer(pattern, body, re.IGNORECASE):
            slug = match.group(1)
            version = match.group(2)
            if slug not in seen_slugs:
                seen_slugs[slug] = version

        nodes_added = 0
        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        for slug, version in seen_slugs.items():
            hit = cve_lookup(slug, version)
            if hit is None:
                continue
            vuln_id = f"vuln:{host}:plugin:{slug}"
            vuln_node = AttackNode(
                id=vuln_id,
                type=NodeType.VULNERABILITY,
                properties=VulnerabilityProperties(
                    cve_id=hit.cve_id,
                    cvss_score=hit.cvss,
                    affected_service=f"WordPress plugin {slug} {version}",
                    exploit_available=True,
                ),
                confidence=0.9,
                agent="alpha",
                timestamp_utc=now_utc,
                verification=VerificationTier.SELF_VERIFIED,
            )
            persist_node(
                self.event_store, self.graph_store, self._engagement_id, vuln_node, agent="alpha"
            )
            nodes_added += 1 + self._persist_wp_asset(host, vuln_id, now_utc)
            self._findings += 1

        return nodes_added

    def _persist_wp_asset(self, host: str, vuln_node_id: str, now_utc: str) -> int:
        """Persist (or merge) the WordPress ASSET node and its EXPLOITS edge to a
        vulnerability, mirroring the wp_config leak path's graph coherence.

        Returns the number of NODES added (1 for the asset; edges are not counted).
        """
        asset_id = f"asset:{host}"
        # merge_asset_node preserves rest_routes discovered by an earlier
        # _handle_wp_rest_routes pass on the same host (CodeRabbit #274): a users/
        # woocommerce/version finding here re-persists asset:{host} and must not
        # drop the route inventory (or ip/open_ports) it did not re-observe.
        asset_node = merge_asset_node(
            self.graph_store,
            host,
            tech_stack_add=[constants.STACK_WP],
            confidence=0.85,
            timestamp_utc=now_utc,
        )
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, asset_node, agent="alpha"
        )
        persist_edge(
            self.event_store,
            self.graph_store,
            self._engagement_id,
            AttackEdge(
                source_id=asset_id,
                target_id=vuln_node_id,
                relationship=RelationshipType.EXPLOITS,
                confidence=0.85,
            ),
            agent="alpha",
        )
        return 1

    @staticmethod
    def _parse_wp_rest_user_slugs(body: str) -> list[str]:
        """Return slugs iff *body* is the WP REST users shape (array of {id, slug}).

        Any parse failure or non-conforming shape (e.g. a 200 HTML soft-404, or a
        plugin route returning a dict) returns ``[]`` — the finding gate.
        """
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return []
        if not isinstance(data, list) or not data:
            return []
        slugs: list[str] = []
        for item in data:
            if not isinstance(item, dict) or "id" not in item or "slug" not in item:
                return []
            slug = item.get("slug")
            if not isinstance(slug, str) or not slug:
                return []
            slugs.append(slug)
        return slugs

    @staticmethod
    def _confirms_woocommerce(body: str) -> bool:
        """True iff *body* confirms a WooCommerce ``wc/v3`` REST shape."""
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return False
        if not isinstance(data, dict):
            return False
        if data.get("namespace") == "wc/v3":
            return True
        namespaces = data.get("namespaces")
        if isinstance(namespaces, list) and "wc/v3" in namespaces:
            return True
        return False

    _WP_README_VERSION_RE = re.compile(r"Version\s+(\d+\.\d+(?:\.\d+)?)")
    _WP_META_GENERATOR_RE = re.compile(
        r"""<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+(\d+\.\d+(?:\.\d+)?)""",
        re.IGNORECASE,
    )

    @classmethod
    def _extract_wp_version_readme(cls, body: str) -> str | None:
        match = cls._WP_README_VERSION_RE.search(body or "")
        return match.group(1) if match else None

    @classmethod
    def _extract_wp_version_meta(cls, body: str) -> str | None:
        match = cls._WP_META_GENERATOR_RE.search(body or "")
        return match.group(1) if match else None

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

    # ── Private: frontier expansion (R1/R2) ─────────────────────

    def _frontier_expansion_allowed(self, url: str) -> bool:
        """R2 selective-crawl gate for ORGANICALLY-discovered hrefs only.

        Called exclusively from the ``_extract_hrefs`` loop in ``_step_once``
        — never from deterministic catalog seeding (``WELL_KNOWN_LEAK_PATHS``,
        ``SURFACE_DISCOVERY_PATHS``, ``wp_fingerprint.frontier_seeds``,
        ``WP_REST_INTERESTING_ROUTES`` escalation, try_harder recovery), all of
        which call ``enqueue_discovered_url`` directly and stay unfiltered —
        those are already-curated security surface, not organic crawl.

        A stack-agnostic per-host organic-crawl budget
        (``MAX_ORGANIC_CRAWL_PER_HOST``) is checked FIRST, before the WP
        allowlist. Once the budget is exhausted for a host, no further organic
        hrefs are enqueued for that host — but catalog seeds still pass through
        ``enqueue_discovered_url`` directly (uncounted).

        Unknown/unfingerprinted hosts are PERMISSIVE (current FIFO behaviour,
        byte-for-byte backward compatible — anti-#3: absence of a catalog
        entry is never a silent reject). Once a host is tagged ``STACK_WP`` by
        ``_handle_capability_fingerprint``, only ``WP_CRAWL_ALLOW_PATH_PREFIXES``
        survive — content pages (product/blog/category/about/contact) never
        reach the frontier, so they never burn an LLM-tier probe.
        """
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc
        if self._organic_crawl_count.get(host, 0) >= constants.MAX_ORGANIC_CRAWL_PER_HOST:
            return False
        if constants.STACK_WP not in self._host_stack.get(host, ()):
            return True
        path = parsed.path.lower()
        return any(path.startswith(p) for p in constants.WP_CRAWL_ALLOW_PATH_PREFIXES)

    def _handle_content_analysis(self, resp: Any, url: str) -> int:
        """§12.40: scan an OK HTML body for compromise indicators (injected SEO/gambling
        spam) — the "looks fine outside, already owned inside" case. Deterministic, no LLM
        (anti-#3). Mints ONE finding per host (run-once). A NEGATIVE is NOT a clean bill of
        health (§12.45) — only a positive is a proven indicator."""
        host = urlparse(url).hostname
        if not host or host in self._seo_analyzed_hosts:
            return 0
        result = detect_seo_injection(resp.text or "")
        if result is None:
            return 0
        self._seo_analyzed_hosts.add(host)  # mint once per host
        now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
        artifact_id = str(uuid.uuid4())
        evidence = (
            f"Compromise indicator at {url}: injected SEO/gambling spam — "
            f"{result.spam_anchor_count} spam anchor(s)"
            + (", cloaked hidden block" if result.hidden_block else "")
            + f"; terms: {', '.join(result.matched_terms[:8])}. "
            "Site appears ALREADY COMPROMISED (parasite hosting / injection)."
        )
        vuln_node = AttackNode(
            id=f"vuln:{host}:{SEO_INJECTION_SPEC.vuln_id_suffix}",
            type=NodeType.VULNERABILITY,
            properties=VulnerabilityProperties(
                affected_service="web",
                cvss_score=SEO_INJECTION_SPEC.cvss,
                exploit_available=False,
            ),
            confidence=0.9,
            agent="alpha",
            timestamp_utc=now_utc,
            proof_artifacts=[
                ProofArtifact(
                    artifact_id=artifact_id,
                    type="http_response",
                    storage_ref=f"engagements/{self._engagement_id}/proofs/{artifact_id}",
                    description=evidence,
                    captured_at=now_utc,
                    agent="alpha",
                    target=url,
                )
            ],
            verification=VerificationTier.SELF_VERIFIED,
        )
        persist_node(
            self.event_store, self.graph_store, self._engagement_id, vuln_node, agent="alpha"
        )
        self._findings += 1
        return 1

    def _extract_hrefs(self, html: str, base_url: str) -> list[str]:
        """Extract absolute same-origin hrefs from *html*.

        Matches ``href`` on ``<a>`` and ``src`` on ``<frame>``/``<iframe>``
        (frameset and framed-content sites carry their navigation there, not
        in ``<a>`` tags).  Resolves relative paths against *base_url*, skips
        mailto/javascript/tel, and filters to the same scheme+host as *base_url*.
        Scope-gate (``authorization.is_in_scope``) is applied separately in
        ``enqueue_discovered_url`` — this is the HTML-level same-origin filter.
        """
        base = urlparse(base_url)
        base_origin = (base.scheme, base.hostname or "")

        hrefs: list[str] = []
        for match in re.finditer(
            r'<(?:a\s[^>]*href|i?frame\s[^>]*src)=["\']([^"\'#][^"\']*)["\']',
            html,
            re.IGNORECASE,
        ):
            raw = match.group(1).strip()
            if not raw or raw.startswith(("mailto:", "javascript:", "tel:")):
                continue
            absolute = urljoin(base_url, raw)
            parsed = urlparse(absolute)
            if (parsed.scheme, parsed.hostname or "") == base_origin:
                hrefs.append(absolute)
        return hrefs

    def enqueue_discovered_url(self, url: str) -> bool:
        """Add *url* to ``_work_queue`` if in-scope and not already seen.

        Returns True if the URL was enqueued, False otherwise (out-of-scope,
        already probed, already queued, or CDN-excluded).

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
                return False
        host = parsed.hostname or parsed.netloc
        # Instinct #2 (GAP-029): refuse to enqueue paths for a host whose root
        # already raised HttpClientError this run (host is transport-unreachable).
        if host in self._dead_hosts:
            return False
        if (
            self.authorization.is_in_scope(self._engagement_id, host)
            and url not in self._probed
            and url not in self._work_queue
        ):
            self._work_queue.append(url)
            return True
        return False

    # ── Private: helpers ────────────────────────────────────────

    def _persist_host_abandoned_event(self, host: str) -> None:
        """Append-only audit: host abandoned (root transport-unreachable).

        Mirrors ``_handle_waf_block``'s ``EventType.WAF_BLOCKED`` emission —
        same event_store path, same engagement_id. Parity ensures the
        abandonment is replayable and auditable (S1 — anti-#3, anti-#7).
        """
        self.event_store.append(
            EventType.HOST_ABANDONED,
            self._engagement_id,
            "alpha",
            {
                "host": host,
                "reason": "transport_unreachable",
                "trigger": "root_probe",
            },
        )

    def _try_harder_recovery(self) -> str | None:
        """Try-Harder dead-end recovery (D2-b).

        Deterministically recall un-probed well-known paths on hosts
        discovered LATE (which ``run_recon`` never seeded). Fires ONCE per
        run to guarantee termination. Returns a recovered URL or ``None``.
        """
        if self._try_harder_fired:
            return None
        self._try_harder_fired = True
        candidates = self._planner.try_harder(
            self._world_model,
            self._current_objective,
            self._probed,
        )
        new = 0
        for c in candidates:
            before = len(self._work_queue)
            self.enqueue_discovered_url(c)  # scope-gated + dedup
            if len(self._work_queue) > before:
                new += 1
        if new > 0:
            return self._pop_unprobed()  # retry ONCE
        return None

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
            next_recommended=a2a_pb2.CONDUCTOR,
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
