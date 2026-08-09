# agent_alpha/conductor/router.py
"""Kill-chain routing — SINGLE source of truth for "which agent runs next" (#6/#7).

Pure function of the AttackGraph state. No I/O, no side effects, no vault calls.
The Conductor calls ``route_next`` after each agent completes (or fails); it
proposes the next agent, which ``decide_advance`` then validates against the
auth gate and blast gate before dispatching.

Routing PROPOSES; the auth/blast gates DISPOSE.  Never auto-promote tier.

CONSTRAINT — this module routes ALPHA→{BETA,OMEGA} and BETA→{GAMMA,OMEGA} only.
ALPHA→GAMMA (skip-Beta) is NOT built here — that requires Gamma's
exploit-reachability oracle (see adr_alpha_to_gamma_skip_beta.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

from agent_alpha.a2a import a2a_pb2
from agent_alpha.config import constants
from agent_alpha.graph.nodes import NodeType, RelationshipType

# Semantic auth-surface label set — authentication ENTRY POINTS a Beta
# credential-applicator can bind to.  Single source of truth for routing (#7).
#
# NOT the planner's scoring tuple (planner.py:170-185): that includes
# recon-surface labels ("openapi", "graphql", "db") that are NOT login surfaces.
# Coupling routing to a scoring list would be wrong (different purpose).
#
# Labels confirmed via recon/capability_probe.py CAPABILITY_CATALOG and
# scout._handle_capability_fingerprint:
#   "tomcat"         — CapabilitySpec(tool="tomcat_fingerprint", label="tomcat")
#   "http_basic_auth"— CapabilitySpec(tool="http_basic_auth_fingerprint", label="http_basic_auth")
#   "odoo"           — CapabilitySpec(tool="odoo_fingerprint", label="odoo")
#   "laravel"        — scout._handle_laravel_detection hardcodes tech_stack=["laravel"]
#   "login-form"     — not in catalog yet; planner uses it as a scoring label
#   "admin"          — not in catalog yet; planner uses it as a scoring label
#
# NO "http"/"https" SERVICE fallback — every web recon produces an http service
# node, which would make this predicate VACUOUS (always true) and collapse the
# ALPHA→BETA vs ALPHA→OMEGA routing distinction.
_AUTH_SURFACE_LABELS: frozenset[str] = frozenset(
    {
        constants.STACK_WP,
        "odoo",
        "login-form",
        "http_basic_auth",
        "admin",
        "tomcat",
        "laravel",
    }
)


@dataclass(frozen=True)
class StrikeEntrySelection:
    """Result of select_strike_entry — URL + observability metadata."""

    selected_entry: str
    matched_label: str | None
    fallback_to_default: bool
    candidates_considered: tuple[str, ...]


# ── Graph predicates (pure reads, no side effects) ─────────────────────────────


def has_harvested_credential(graph_store: Any) -> bool:
    """True iff the graph contains at least one CREDENTIAL node whose
    ``secret_ref`` starts with ``"secret_"`` — the vaulted-credential
    convention (see wp_chain_runner._edge_from_harvested_cred).

    Routing does NOT call ``secrets_manager.retrieve()`` — the secret_ref
    prefix is sufficient signal that Alpha vaulted a real credential.
    """
    for node in graph_store.nodes_by_type(NodeType.CREDENTIAL):
        ref = getattr(node.properties, "secret_ref", "")
        if ref.startswith("secret_"):
            return True
    return False


def has_web_auth_surface(graph_store: Any) -> bool:
    """True iff the graph contains at least one ASSET node whose ``tech_stack``
    includes a label that denotes a web authentication surface Beta can bind to.

    Uses ``_AUTH_SURFACE_LABELS`` — a semantic set of login-surface labels,
    NOT the planner's broader scoring tuple.
    """
    for node in graph_store.nodes_by_type(NodeType.ASSET):
        tech = getattr(node.properties, "tech_stack", None) or []
        if _AUTH_SURFACE_LABELS.intersection(tech):
            return True
    return False


def select_strike_entry(graph_store: Any, *, default_target: str) -> StrikeEntrySelection:
    parsed_default = urlparse(default_target)
    label_priority = tuple(sorted(_AUTH_SURFACE_LABELS))
    rank_by_label = {label: idx for idx, label in enumerate(label_priority)}
    candidates: list[tuple[int, str, str, str | None]] = []

    for node in graph_store.nodes_by_type(NodeType.ASSET):
        tech = getattr(node.properties, "tech_stack", None) or []
        matched_label = None
        priority = None
        for label in tech:
            if label in rank_by_label:
                if priority is None or rank_by_label[label] < priority:
                    priority = rank_by_label[label]
                    matched_label = label

        host = getattr(node.properties, "host", "") or ""
        if priority is None or not host:
            continue
        candidates.append(
            (
                priority,
                host,
                urlunparse((parsed_default.scheme, host, "/", "", "", "")),
                matched_label,
            )
        )

    if not candidates:
        return StrikeEntrySelection(
            selected_entry=default_target,
            matched_label=None,
            fallback_to_default=True,
            candidates_considered=(),
        )

    candidates.sort(key=lambda item: (item[0], item[1]))
    winner = candidates[0]
    return StrikeEntrySelection(
        selected_entry=winner[2],
        matched_label=winner[3],
        fallback_to_default=False,
        candidates_considered=tuple(c[1] for c in candidates),
    )


def has_access_from_harvested_cred(graph_store: Any) -> bool:
    """True iff an ENABLES edge connects a vaulted CREDENTIAL (secret_ref
    starts with ``"secret_"``) to an ACCESS_LEVEL node.

    Same structural predicate as ``wp_chain_runner._edge_from_harvested_cred``
    but WITHOUT ``secrets_manager.retrieve()`` — routing needs no vault I/O;
    the edge existing proves Beta proved access.
    """
    access_ids = {n.id for n in graph_store.nodes_by_type(NodeType.ACCESS_LEVEL)}
    if not access_ids:
        return False
    cred_by_id = {
        n.id: n
        for n in graph_store.nodes_by_type(NodeType.CREDENTIAL)
        if getattr(n.properties, "secret_ref", "").startswith("secret_")
    }
    if not cred_by_id:
        return False
    for edge in graph_store.edges_by_relationship(RelationshipType.ENABLES):
        if edge.source_id in cred_by_id and edge.target_id in access_ids:
            return True
    return False


# ── Route decision ─────────────────────────────────────────────────────────────


def route_next(
    graph_store: Any,
    *,
    from_agent: int,
    status: int,
    gamma_authorized: bool,
) -> int | None:
    """Decide the next agent as a pure function of the AttackGraph state.

    Returns an ``AgentRole`` int (the PROPOSED next agent) or ``None``
    (chain complete).  The caller (``advance_engagement``) feeds this into
    ``decide_advance`` which validates auth-tier + blast-gate before dispatch.

    ``gamma_authorized`` is ``auth.can_agent_proceed(GAMMA, engagement_id)``
    — routing PROPOSES Gamma only when the tier is already granted.  The
    decide_advance auth-check is still the authoritative gate (defense in depth).
    """
    # Bug #22: FAILED/BLOCKED → OMEGA for an honest partial report.
    if status in (a2a_pb2.FAILED, a2a_pb2.BLOCKED):
        return a2a_pb2.OMEGA

    if from_agent == a2a_pb2.ALPHA:
        # Auth surface = attack it (Beta's STRIKE charter). A login is actionable
        # WITHOUT a pre-harvested credential: Beta tries default/derived creds to GET
        # the first one; a harvested cred merely ADDS CredReuse to the roster. (Was
        # `AND has_harvested_credential` - the deadlock: you needed a credential to
        # attack the very login that produces one. Beta still gated by ACTIVE_APPROVED
        # in decide_advance - tier auth is NOT bypassed here.)
        if has_web_auth_surface(graph_store):
            return a2a_pb2.BETA
        return a2a_pb2.OMEGA  # recon-only report

    if from_agent == a2a_pb2.BETA:
        if has_access_from_harvested_cred(graph_store):
            return a2a_pb2.GAMMA if gamma_authorized else a2a_pb2.OMEGA
        return a2a_pb2.OMEGA

    # GAMMA/DELTA/EPSILON and anything else → OMEGA (report always producible).
    return a2a_pb2.OMEGA
