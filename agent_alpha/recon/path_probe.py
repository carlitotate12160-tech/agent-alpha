"""ONE data-driven path-probe engine (Phase 4 breadth consolidation).

Replaces the near-identical ``git_exposure_probe.verify_git_exposure`` and
``backup_file_probe.verify_backup_file`` (anti-Lyndon #6/#7 probe sprawl) with a
single catalog + a single PER-RESPONSE processor.

WHY per-response (closes the double-fetch, F1): the cognitive loop in
``scout._step_once`` already GETs every seeded well-known path once. The old
verifiers then RE-SWEPT the same paths with their own GETs (git 1x, backup 11x).
This engine takes NO http client -- it processes the response the loop ALREADY
fetched, so it is *structurally incapable* of re-fetching. The frontier IS the
sweep.

Two recover strategies (the ONLY real axis of variation between stacks):
  * DIRECT -- a 200 body IS the recovered content ({logical_path: body}). backup_file.
  * DUMP   -- reconstruct via an injected ``dumper.dump(base_url)``. git_exposure.

Everything else (tier gate, scope gate, WAF classify, extract_secrets,
ASSET+VULNERABILITY persist, assemble_leaked_credentials, vault) is shared, exactly
as the two probes had it -- no new credential type, no new vault path, no new
classifier.
"""

from __future__ import annotations

import datetime
import enum
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import STATE_RANK
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import (
    AssetProperties,
    AttackEdge,
    AttackNode,
    NodeType,
    RelationshipType,
    VulnerabilityProperties,
    node_to_dict,
)
from agent_alpha.recon.response_classifier import Verdict, classify_response
from agent_alpha.security.credential_assembly import assemble_leaked_credentials
from agent_alpha.security.leak_extraction import extract_secrets


class RecoverStrategy(enum.StrEnum):
    """How the recovered content is obtained from a path hit."""

    DIRECT = "direct"  # the 200 body IS the content -> {logical_path: body}
    DUMP = "dump"  # reconstruct via an injected dumper.dump(base_url) -> {path: content}


@dataclass(frozen=True)
class PathProbeSpec:
    """One catalog entry. Pure data (signature is substrings, not a callable) so the
    catalog can migrate to YAML/IntelligenceBase later (ADR §12.25) unchanged."""

    name: str
    tool: str  # dispatch tool name emitted by the playbook rule
    paths: tuple[str, ...]  # SINGLE source: frontier seed AND the logical path set
    recover: RecoverStrategy
    vuln_suffix: str  # -> vuln:{host}:{vuln_suffix}
    tech_stack: tuple[str, ...]
    leak_source: str
    # Pre-recover confirm (mainly to gate the expensive DUMP). Empty = no gate
    # (DIRECT relies on extract_secrets yielding a secret as its own gate, anti-#3).
    signature_substrings: tuple[str, ...] = ()
    # Credential key maps default to the WP_CREDENTIAL_* SSOT; override per stack.
    login_pairs: dict[str, tuple[str, str]] = field(
        default_factory=lambda: constants.WP_CREDENTIAL_LOGIN_PAIRS
    )
    username_keys: frozenset[str] = field(
        default_factory=lambda: constants.WP_CREDENTIAL_USERNAME_KEYS
    )
    secret_keys: frozenset[str] = field(default_factory=lambda: constants.WP_CREDENTIAL_SECRET_KEYS)
    service_map: dict[str, str] = field(default_factory=lambda: constants.WP_CREDENTIAL_SERVICE_MAP)


# The catalog is the SINGLE source of truth. Each spec's `paths` reuses the same
# constants that seed constants.WELL_KNOWN_LEAK_PATHS, so there is no second copy
# of any path list (anti-#7).
PATH_PROBE_CATALOG: tuple[PathProbeSpec, ...] = (
    PathProbeSpec(
        name="git_exposure",
        tool="git_exposure_probe",
        paths=constants.GIT_LEAK_PATHS,
        recover=RecoverStrategy.DUMP,
        vuln_suffix="git_exposure",
        tech_stack=("git",),
        leak_source="git_exposure",
        signature_substrings=("[core]",),
    ),
    PathProbeSpec(
        name="backup_file",
        tool="backup_file_probe",
        paths=constants.BACKUP_FILE_PATHS,
        recover=RecoverStrategy.DIRECT,
        vuln_suffix="backup_file_leak",
        tech_stack=("web",),
        leak_source="backup_file",
    ),
)

_CATALOG_BY_TOOL: dict[str, PathProbeSpec] = {spec.tool: spec for spec in PATH_PROBE_CATALOG}


def spec_for_tool(tool: str) -> PathProbeSpec | None:
    """Resolve the catalog entry a dispatched tool name maps to (None if unknown)."""
    return _CATALOG_BY_TOOL.get(tool)


def _logical_path(path: str) -> str:
    """Normalise a backup suffix to the logical file name so extract_secrets can
    recognise the format (``/.env.bak`` -> ``/.env``)."""
    lower = path.lower()
    for suffix in (".bak", ".old", ".save", ".orig", "~"):
        if lower.endswith(suffix):
            return lower[: -len(suffix)]
    return lower


def _persist_node(event_store: Any, graph_store: Any, engagement_id: str, node: AttackNode) -> None:
    payload = node_to_dict(node)
    event_store.append(EventType.NODE_DISCOVERED, engagement_id, "alpha", payload)
    graph_store.apply_event("NodeDiscovered", payload)


def _persist_edge(event_store: Any, graph_store: Any, engagement_id: str, edge: AttackEdge) -> None:
    payload = {
        "source_id": edge.source_id,
        "target_id": edge.target_id,
        "relationship": edge.relationship.value,
        "confidence": edge.confidence,
        "technique_id": edge.technique_id,
    }
    event_store.append(EventType.EDGE_DISCOVERED, engagement_id, "alpha", payload)
    graph_store.apply_event("EdgeDiscovered", payload)


def _recover(spec: PathProbeSpec, *, url: str, body: str, dumper: Any | None) -> dict[str, str]:
    """Turn a single path hit into a ``{path: content}`` dict per the spec strategy.

    Never performs an HTTP GET -- DIRECT reuses the body the loop already fetched;
    DUMP delegates to the injected dumper (which does its own read-only recovery).
    """
    if spec.recover is RecoverStrategy.DIRECT:
        return {_logical_path(urlparse(url).path): body}
    # DUMP
    if dumper is None:
        return {}
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}/"
    try:
        result: dict[str, str] = dumper.dump(base_url)
        return result
    except Exception:
        return {}


def process_path_hit(
    spec: PathProbeSpec,
    *,
    resp: Any,
    url: str,
    engagement_id: str,
    auth: Any,
    graph_store: Any,
    event_store: Any,
    secrets_manager: Any | None = None,
    dumper: Any | None = None,
) -> int:
    """Process the ONE response the cognitive loop already fetched for *url*.

    Returns the number of CREDENTIAL nodes minted. No HTTP is performed here
    (the engine takes no http client -- F1 double-fetch is closed by construction).
    """
    # Tier gate: fail-closed below RECON_ONLY.
    if STATE_RANK.get(auth.get_state(engagement_id), 0) < STATE_RANK[a2a_pb2.RECON_ONLY]:
        return 0

    host = urlparse(url).hostname or urlparse(url).netloc
    # Scope gate: defence-in-depth (the loop already gates, but never assume).
    if not host or not auth.is_in_scope(engagement_id, host):
        return 0

    status = getattr(resp, "status_code", 0)
    body = getattr(resp, "text", "")

    verdict = classify_response(status_code=status, body=body)
    if verdict is Verdict.BLOCKED:
        event_store.append(
            EventType.WAF_BLOCKED,
            engagement_id,
            "alpha",
            {"host": host, "path": urlparse(url).path, "status_code": status},
        )
        return 0  # block is evidence, never "clean"
    if verdict is not Verdict.OK:
        return 0

    # Signature gate (mainly to guard the expensive DUMP).
    if spec.signature_substrings and not any(s in body for s in spec.signature_substrings):
        return 0

    recovered = _recover(spec, url=url, body=body, dumper=dumper)
    leaked = extract_secrets(recovered)
    if not leaked:
        return 0  # exposure/backup without a recoverable secret is not payable (anti-#3)

    now_utc = datetime.datetime.now(datetime.UTC).replace(tzinfo=None).isoformat() + "Z"
    vuln_node_id = f"vuln:{host}:{spec.vuln_suffix}"

    vuln_node = AttackNode(
        id=vuln_node_id,
        type=NodeType.VULNERABILITY,
        properties=VulnerabilityProperties(affected_service="web", exploit_available=False),
        confidence=0.85,
        agent="alpha",
        timestamp_utc=now_utc,
    )
    _persist_node(event_store, graph_store, engagement_id, vuln_node)

    asset_node = AttackNode(
        id=f"asset:{host}",
        type=NodeType.ASSET,
        properties=AssetProperties(host=host, tech_stack=list(spec.tech_stack)),
        confidence=0.85,
        agent="alpha",
        timestamp_utc=now_utc,
    )
    _persist_node(event_store, graph_store, engagement_id, asset_node)

    _persist_edge(
        event_store,
        graph_store,
        engagement_id,
        AttackEdge(
            source_id=asset_node.id,
            target_id=vuln_node.id,
            relationship=RelationshipType.EXPLOITS,
            confidence=0.85,
        ),
    )

    nodes, edges = assemble_leaked_credentials(
        leaked,
        host=host,
        vuln_node_id=vuln_node_id,
        login_pairs=spec.login_pairs,
        username_keys=spec.username_keys,
        secret_keys=spec.secret_keys,
        service_map=spec.service_map,
        secrets_manager=secrets_manager,
        engagement_id=engagement_id,
        now_utc=now_utc,
        leak_source=spec.leak_source,
    )

    creds_added = 0
    for node in nodes:
        _persist_node(event_store, graph_store, engagement_id, node)
        creds_added += 1
    for edge in edges:
        _persist_edge(event_store, graph_store, engagement_id, edge)

    return creds_added
