# agent_alpha/recon/js_secret_probe.py
"""Generic JS-bundle secret + API-endpoint recon for ANY in-scope web target.

Phase 3 recon vector, parallel to wp_config_probe. RECON_ONLY (passive GET of
pages + their JS bundles, scope-gated). No creds used. No client/host hardcoding
(#4) — operates on any in-scope target from the engagement scope.

DISCOVERY (``discover_js_bundles``): extract <script src=...> URLs from HTML,
resolve relative→absolute, return ONLY same-origin / in-scope bundle URLs.

SCANNING (``scan_js_for_secrets``): apply ``JS_SECRET_PATTERNS`` + validate via
``_looks_like_secret()``. Value NEVER returned raw beyond a masked preview
(first4****last4). This is detection (gitleaks/trufflehog-style), not exploit.

EXTRACTION (``extract_api_endpoints``): find fetch()/axios/baseURL/REST/GraphQL
paths. Secondary output (attack-surface intel), persisted as events, not creds.

VERIFIER (``verify_js_secret_leak``): tier≥RECON fail-closed → is_in_scope →
GET page → discover in-scope bundles → GET each (403/429/503 → WAF_BLOCKED,
not "clean") → scan → VAULT + persist each VALIDATED secret as a CREDENTIAL
node + LEADS_TO edge; persist endpoints as intel events.
"""

from __future__ import annotations

import datetime
import math
import re
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urljoin, urlparse

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import STATE_RANK
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackEdge,
    AttackNode,
    CredentialProperties,
    NodeType,
    RelationshipType,
    VulnerabilityProperties,
    node_to_dict,
)
from agent_alpha.recon.response_classifier import Verdict, classify_response

# ── Protocol (mirrors wp_config_probe.HttpClientProtocol) ───────────────────


@runtime_checkable
class HttpClientProtocol(Protocol):
    """Minimal HTTP client interface for recon GET requests."""

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> Any: ...


# ── SecretHit dataclass ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class SecretHit:
    """A validated secret found in a JS bundle. Value is NEVER stored raw."""

    kind: str
    service: str
    value_preview: str  # masked: first4****last4
    confidence: float
    _raw_value: str  # private, never serialized

    def __str__(self) -> str:
        return f"SecretHit(kind={self.kind}, service={self.service}, preview={self.value_preview})"


# ── Anti-#3: _looks_like_secret discriminator ───────────────────────────────


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _looks_like_secret(value: str) -> bool:
    """Anti-#3 discriminator: reject placeholders, low-entropy noise, short strings.

    A "token"-looking string is NOT a finding. This is the difference between
    a payable finding and scanner noise.
    """
    if len(value) < constants.JS_SECRET_MIN_LENGTH:
        return False
    lower = value.lower()
    for placeholder in constants.JS_SECRET_PLACEHOLDER_DENYLIST:
        if placeholder in lower:
            return False
    if _shannon_entropy(value) < constants.JS_SECRET_MIN_ENTROPY:
        return False
    # All-same-char check
    if len(set(value)) == 1:
        return False
    return True


def _mask(value: str) -> str:
    """Mask a secret value: first4****last4."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}****{value[-4:]}"


# ── Bundle discovery ────────────────────────────────────────────────────────

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_MODULE_PRELOAD_RE = re.compile(
    r'<link[^>]+rel=["\']modulepreload["\'][^>]+href=["\']([^"\']+)["\']', re.IGNORECASE
)


def discover_js_bundles(html: str, base_url: str) -> list[str]:
    """Extract JS bundle URLs from HTML, return ONLY same-origin / in-scope URLs.

    Parses <script src=...> and <link rel=modulepreload href=...>. Resolves
    relative URLs to absolute. Filters out cross-origin (CDN) scripts.
    """
    base_origin = urlparse(base_url)
    urls: list[str] = []

    for pattern in (_SCRIPT_SRC_RE, _MODULE_PRELOAD_RE):
        for match in pattern.finditer(html):
            raw_src = match.group(1)
            absolute = urljoin(base_url, raw_src)
            parsed = urlparse(absolute)
            # Same-origin only — a 3rd-party CDN script is out of scope.
            if parsed.scheme in ("http", "https") and parsed.netloc == base_origin.netloc:
                if absolute not in urls:
                    urls.append(absolute)

    return urls


# ── Secret scanning ─────────────────────────────────────────────────────────

# Pre-compile patterns from constants
_COMPILED_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (name, re.compile(pattern), service) for name, pattern, service in constants.JS_SECRET_PATTERNS
]


def scan_js_for_secrets(body: str) -> list[SecretHit]:
    """Scan a JS bundle body for validated secrets.

    Applies JS_SECRET_PATTERNS + _looks_like_secret() discriminator. The
    generic_assign pattern captures a value that MUST pass validation.
    High-confidence provider patterns (AWS, Stripe, etc.) are trusted by
    their format but still checked against the placeholder denylist.
    """
    hits: list[SecretHit] = []
    seen_values: set[str] = set()

    for name, regex, service in _COMPILED_PATTERNS:
        for match in regex.finditer(body):
            # generic_assign has a capture group for the value; others match the whole pattern.
            if name == "generic_assign":
                value = match.group(2)
                if not _looks_like_secret(value):
                    continue
            else:
                value = match.group(0)
                # Still reject obvious placeholders even for provider patterns.
                lower = value.lower()
                if any(p in lower for p in constants.JS_SECRET_PLACEHOLDER_DENYLIST):
                    continue

            if value in seen_values:
                continue
            seen_values.add(value)

            hits.append(
                SecretHit(
                    kind=name,
                    service=service,
                    value_preview=_mask(value),
                    confidence=0.90 if name != "generic_assign" else 0.75,
                    _raw_value=value,
                )
            )

    return hits


# ── API endpoint extraction ─────────────────────────────────────────────────

_API_ENDPOINT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"""(?:fetch|axios\.get|axios\.post|axios\.put|axios\.delete)\s*\(\s*['"`]([^'"`]+)['"`]"""
    ),
    re.compile(r"""(?:baseURL|BASE_URL|apiUrl|API_URL)\s*[:=]\s*['"`]([^'"`]+)['"`]"""),
    re.compile(r"""['"`](/api/[^'"`]+)['"`]"""),
    re.compile(r"""['"`](/graphql)['"`]""", re.IGNORECASE),
]


def extract_api_endpoints(body: str) -> list[str]:
    """Extract API endpoint paths from a JS bundle body.

    Returns unique paths (fetch/axios/baseURL/REST/GraphQL). These are
    attack-surface intel, persisted as events, not as credentials.
    """
    endpoints: list[str] = []
    seen: set[str] = set()

    for pattern in _API_ENDPOINT_PATTERNS:
        for match in pattern.finditer(body):
            ep = match.group(1)
            if ep not in seen:
                seen.add(ep)
                endpoints.append(ep)

    return endpoints


# ── Verifier (Claude gate) ──────────────────────────────────────────────────


def verify_js_secret_leak(
    *,
    engagement_id: str,
    auth: Any,
    http_client: HttpClientProtocol,
    scope_targets: list[str],
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any | None = None,
    timeout_s: float = 10.0,
) -> int:
    """Probe in-scope web targets for JS-bundle secret leaks.

    For each target in *scope_targets*:
      1. Tier gate: engagement state >= RECON_ONLY (fail-closed).
      2. Scope gate: ``auth.is_in_scope(engagement_id, host)`` — never a co-tenant.
      3. GET the page HTML.
      4. Discover same-origin JS bundles.
      5. GET each bundle (403/429/503 → EventType.WAF_BLOCKED, not "clean").
      6. Scan for validated secrets → VAULT + persist as CREDENTIAL nodes.
      7. Extract API endpoints → persist as intel events.

    Returns the number of validated secret CREDENTIAL nodes added.
    """
    # ── Tier gate: fail-closed below RECON_ONLY ────────────────────────────
    current_state = auth.get_state(engagement_id)
    if STATE_RANK.get(current_state, 0) < STATE_RANK[a2a_pb2.RECON_ONLY]:
        return 0

    creds_added = 0

    for target in scope_targets:
        # ── Scope gate: never probe an out-of-scope host ───────────────────
        if not auth.is_in_scope(engagement_id, target):
            continue

        page_url = f"https://{target}/"

        # ── GET the page HTML ──────────────────────────────────────────────
        try:
            resp = http_client.get(page_url)
        except Exception:
            continue

        status = getattr(resp, "status_code", 0)
        body = getattr(resp, "text", "")

        # WAF discriminator on the page itself (canonical classifier, anti-#7)
        if classify_response(status_code=status, body=body) is Verdict.BLOCKED:
            event_store.append(
                EventType.WAF_BLOCKED,
                engagement_id,
                "alpha",
                {"host": target, "path": "/", "status_code": status},
            )
            continue

        if status != 200:
            continue

        # ── Discover in-scope JS bundles ───────────────────────────────────
        bundle_urls = discover_js_bundles(body, page_url)

        for bundle_url in bundle_urls:
            # ── GET the bundle ──────────────────────────────────────────────
            try:
                bresp = http_client.get(bundle_url)
            except Exception:
                continue

            bstatus = getattr(bresp, "status_code", 0)
            bbody = getattr(bresp, "text", "")

            # WAF discriminator on the bundle (canonical classifier, anti-#7)
            if classify_response(status_code=bstatus, body=bbody) is Verdict.BLOCKED:
                event_store.append(
                    EventType.WAF_BLOCKED,
                    engagement_id,
                    "alpha",
                    {"host": target, "path": urlparse(bundle_url).path, "status_code": bstatus},
                )
                continue

            if bstatus != 200:
                continue

            # ── Scan for validated secrets ──────────────────────────────────
            hits = scan_js_for_secrets(bbody)
            if not hits:
                # Still extract API endpoints as intel
                endpoints = extract_api_endpoints(bbody)
                for ep in endpoints:
                    event_store.append(
                        EventType.NODE_DISCOVERED,
                        engagement_id,
                        "alpha",
                        {
                            "type": "api_endpoint",
                            "host": target,
                            "endpoint": ep,
                            "source": bundle_url,
                        },
                    )
                continue

            # ── Persist asset + vulnerability + credential nodes ──────────────
            now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
            vuln_node_id = f"vuln:{target}:js_secret_leak"

            # ── ASSET node (graph coherence — matches scout._handle_laravel_debug) ─
            asset_node = AttackNode(
                id=f"asset:{target}",
                type=NodeType.ASSET,
                properties=AssetProperties(
                    host=target,
                    tech_stack=["javascript"],
                ),
                confidence=0.85,
                agent="alpha",
                timestamp_utc=now_utc,
            )
            _persist_node(event_store, graph_store, engagement_id, asset_node)

            vuln_node = AttackNode(
                id=vuln_node_id,
                type=NodeType.VULNERABILITY,
                properties=VulnerabilityProperties(
                    affected_service="web",
                    exploit_available=False,
                ),
                confidence=0.85,
                agent="alpha",
                timestamp_utc=now_utc,
            )
            _persist_node(event_store, graph_store, engagement_id, vuln_node)

            # ── EDGE asset → vulnerability ──────────────────────────────────
            asset_edge = AttackEdge(
                source_id=asset_node.id,
                target_id=vuln_node.id,
                relationship=RelationshipType.EXPLOITS,
                confidence=0.85,
            )
            _persist_edge(event_store, graph_store, engagement_id, asset_edge)

            for hit in hits:
                # ── Vault the raw secret ────────────────────────────────────
                if secrets_manager is not None:
                    record = secrets_manager.store(
                        label=f"{hit.service}:{hit.kind}",
                        value=hit._raw_value,
                        engagement_id=engagement_id,
                    )
                    secret_ref = record.secret_id
                else:
                    secret_ref = f"engagements/{engagement_id}/proofs/js_secret_{target}#{hit.kind}"

                cred_node = AttackNode(
                    id=f"cred:{target}:{hit.kind}",
                    type=NodeType.CREDENTIAL,
                    properties=CredentialProperties(
                        username="",
                        secret_ref=secret_ref,
                        service=hit.service,
                        access_level="unverified",
                    ),
                    confidence=hit.confidence,
                    agent="alpha",
                    timestamp_utc=now_utc,
                )
                _persist_node(event_store, graph_store, engagement_id, cred_node)
                creds_added += 1

                edge = AttackEdge(
                    source_id=vuln_node_id,
                    target_id=cred_node.id,
                    relationship=RelationshipType.LEADS_TO,
                    confidence=hit.confidence,
                    technique_id="T1552.001",
                )
                _persist_edge(event_store, graph_store, engagement_id, edge)

            # ── Persist API endpoints as intel ──────────────────────────────
            endpoints = extract_api_endpoints(bbody)
            for ep in endpoints:
                event_store.append(
                    EventType.NODE_DISCOVERED,
                    engagement_id,
                    "alpha",
                    {"type": "api_endpoint", "host": target, "endpoint": ep, "source": bundle_url},
                )

    return creds_added


# ── Persistence helpers (mirror wp_config_probe) ────────────────────────────


def _persist_node(
    event_store: Any,
    graph_store: Any,
    engagement_id: str,
    node: AttackNode,
) -> None:
    """Persist a node through both event_store and graph_store."""
    payload = node_to_dict(node)
    event_store.append(
        EventType.NODE_DISCOVERED,
        engagement_id,
        "alpha",
        payload,
    )
    graph_store.apply_event("NodeDiscovered", payload)


def _persist_edge(
    event_store: Any,
    graph_store: Any,
    engagement_id: str,
    edge: AttackEdge,
) -> None:
    """Persist an edge through both event_store and graph_store."""
    payload = {
        "source_id": edge.source_id,
        "target_id": edge.target_id,
        "relationship": edge.relationship.value,
        "confidence": edge.confidence,
        "technique_id": edge.technique_id,
    }
    event_store.append(
        EventType.EDGE_DISCOVERED,
        engagement_id,
        "alpha",
        payload,
    )
    graph_store.apply_event("EdgeDiscovered", payload)
