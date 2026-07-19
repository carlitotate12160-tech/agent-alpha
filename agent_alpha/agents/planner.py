# agent_alpha/agents/planner.py
"""Planner — deterministic, NO-LLM planning decisions.

Extracted from ``scout._score_frontier_url`` (GAP-004 D2-a) so that
planning logic lives in its OWN module and scout SHRINKS.

**PURE**: the Planner never mutates agent state, never calls agents or
the Conductor, never does I/O or tool execution.  It DECIDES only.

**D2 extension points (NOT built here — this slice is D2-a only):**

* Executor (D2-b): multi-step plan execution will be added HERE.
* Lookahead / replan (D2-c): HTN-style look-ahead will be added HERE.

Neither of those belong in scout (anti-Lyndon #1 / #8).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from agent_alpha.config import constants

if TYPE_CHECKING:
    from agent_alpha.agents.world_model import WorldModel

from agent_alpha.graph.nodes import NodeType


class Planner:
    """Deterministic frontier scorer — f(graph, objective) → int.

    Stateless and side-effect-free.  Instantiate once, call ``score()``
    for every candidate URL.
    """

    __slots__ = ()

    # ── D2-b: dead-end recovery ─────────────────────────────────

    def try_harder(
        self,
        world_model: WorldModel,
        objective: Any,  # noqa: ARG002 — reserved for D2-c scoring
        probed: set[str],
    ) -> list[str]:
        """Recall un-probed well-known URLs on hosts known to the graph.

        For every distinct host in ``world_model.all_beliefs()`` (via
        ``node.properties.host``), build ``https://{host}{path}`` for every
        path in ``constants.WELL_KNOWN_LEAK_PATHS`` +
        ``constants.SURFACE_DISCOVERY_PATHS`` and return those NOT in
        *probed*.  De-duplicated, stable insertion order.

        **PURE**: no I/O, no mutation, no LLM.

        Scope: recovers hosts that produced a graph node. WAF'd/non-analyzable
        roots that mint no node are out of scope here — handled by §12.33
        (adaptive evasion), not D2-b.
        """
        # Collect distinct hosts from the graph (stable insertion order).
        hosts: dict[str, None] = {}
        for node in world_model.all_beliefs():
            host = getattr(node.properties, "host", None)
            if host and host not in hosts:
                hosts[host] = None

        # Build candidate URLs from the TWO canonical path catalogs.
        paths: tuple[str, ...] = (
            *constants.WELL_KNOWN_LEAK_PATHS,
            *constants.SURFACE_DISCOVERY_PATHS,
        )

        seen: dict[str, None] = {}
        for host in hosts:
            for path in paths:
                url = f"https://{host}{path}"
                if url not in probed and url not in seen:
                    seen[url] = None

        return list(seen)

    def score(self, url: str, world_model: WorldModel, objective: Any) -> int:
        """Deterministic, NO-LLM frontier score = f(graph, objective).

        Higher score = this URL's host graph-context advances the engagement
        objective (reaching an access level in ``target_access_levels``).

        PURE and REPRODUCIBLE: no hashing, no randomness, no LLM. Ties between
        equal scores are broken by FIFO enqueue order in ``_pop_unprobed`` — NOT
        here. The score is an explainable, objective-aware signal and MUST NOT
        contain injected noise that could permute meaningful ranking
        (anti-Lyndon #11 / #3: a differential passes because the SEMANTICS
        changed, never because a hash did).
        """
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc
        path = parsed.path.lower()
        if not host:
            return 0

        targets = _objective_targets(objective)
        score = 0

        # URL-only lead: an access surface advances ANY access objective. Kept
        # below target-specific graph evidence so "we already hold a credential
        # to the target on host X" outranks "host Y merely has a login page".
        if any(kw in path for kw in ("login", "admin", "auth", "signin", "dashboard", "setup")):
            score += 80

        for node in world_model.all_beliefs():
            node_host = getattr(node.properties, "host", None)
            if not (node_host == host or host in str(node.id)):
                continue

            if node.type == NodeType.ACCESS_LEVEL:
                level = getattr(node.properties, "level", None)
                # Objective-aware: reaching the TARGET level is the whole point.
                score += 300 if level in targets else 40
            elif node.type == NodeType.CREDENTIAL:
                cred_level = getattr(node.properties, "access_level", None)
                # A credential that ENABLES the target level is close to impact.
                score += 150 if cred_level in targets else 50
            elif node.type == NodeType.VULNERABILITY:
                score += 40
            elif node.type == NodeType.SERVICE:
                score += 20
            elif node.type == NodeType.ASSET:
                score += 10
                tech = getattr(node.properties, "tech_stack", []) or []
                if any(
                    t in tech
                    for t in (
                        "admin",
                        "db",
                        "odoo",
                        "laravel",
                        "wp",
                        "tomcat",
                        "basic_auth",
                        "openapi",
                        "graphql",
                        "login-form",
                    )
                ):
                    score += 15

        return score


def _objective_targets(objective: Any) -> frozenset[str]:
    """target_access_levels from an objective that may be a dict (scratchpad
    JSON/Redis form) or an EngagementObjective dataclass."""
    if objective is None:
        return frozenset()
    if isinstance(objective, dict):
        raw = objective.get("target_access_levels") or ()
    else:
        raw = getattr(objective, "target_access_levels", ()) or ()
    return frozenset(raw)
