# agent_alpha/coverage/predicates.py
"""Closed predicate vocabulary for the precondition/effect model (ADR §12.66, Slice-1).

A technique in ``techniques.yaml`` declares ``requires`` / ``produces`` as predicate STRINGS from
this CLOSED vocabulary. Each predicate is ``<kind>`` or ``<kind>:<arg>``; every ``kind`` maps to ONE
resolver ``f(graph, arg) -> bool`` that reads the AttackGraph projection (§ event stream is truth,
graph is the reasoning projection). This is the single source that lets goal-backward scoring
(Slice-2) and chain-seeking (Slice-3) reason "have X (graph), need Y (objective), technique T
produces Y and requires Z".

SCOPE (Slice-1): DATA + registry ONLY. No scoring here (that is Slice-2 in ``planner.score``). The
integrity gate (``tests/governance/test_coverage_catalog_integrity.py``) asserts every predicate in
``techniques.yaml`` is registered here — pinning the catalog to ``graph/nodes.py`` so the two cannot
silently drift (anti-Lyndon #7). Adding a predicate KIND is an explicit change here, never ad hoc in
the YAML.

The vocabulary models the NODE-graph chain (leak -> credential -> reuse -> access). Reach (E1/E2,
§12.61) and DNS compose on separate axes and are intentionally out of this vocabulary for now.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agent_alpha.graph.nodes import NodeType, RelationshipType

# Access-level ranking for `access:<level>` (>= semantics: admin satisfies a user requirement).
_ACCESS_RANK: dict[str, int] = {"user": 1, "admin": 2}

# Bare auth-mechanism tokens (mirrors recon.auth_surface / GAP-074). `auth_surface:<mech>` gates a
# mechanism-specific surface; bare `auth_surface` = any fingerprinted auth surface.
_MECHANISMS = frozenset({"form_post", "http_basic", "json_rpc", "jwt", "saml", "oauth"})


def _props(node: Any) -> Any:
    return getattr(node, "properties", None)


def _stack_of(node: Any) -> list[str]:
    return [str(s).lower() for s in (getattr(_props(node), "tech_stack", None) or [])]


def _has_credential(graph: Any, arg: str) -> bool:
    return bool(graph.nodes_by_type(NodeType.CREDENTIAL))


def _has_access(graph: Any, arg: str) -> bool:
    want = _ACCESS_RANK.get(arg, 1)
    for n in graph.nodes_by_type(NodeType.ACCESS_LEVEL):
        level = str(getattr(_props(n), "level", "") or "").lower()
        if _ACCESS_RANK.get(level, 0) >= want:
            return True
    return False


def _has_enables_cred_access(graph: Any, arg: str) -> bool:
    for e in graph.all_edges():
        if e.relationship != RelationshipType.ENABLES:
            continue
        src = graph.get_node(e.source_id)
        tgt = graph.get_node(e.target_id)
        if src and tgt and src.type == NodeType.CREDENTIAL and tgt.type == NodeType.ACCESS_LEVEL:
            return True
    return False


def _has_stack(graph: Any, arg: str) -> bool:
    label = arg.lower()
    return any(label in _stack_of(a) for a in graph.nodes_by_type(NodeType.ASSET))


def _has_auth_surface(graph: Any, arg: str) -> bool:
    # `auth_surface:<mech>` -> that mechanism's mech_* label; bare `auth_surface` = any mech_* label.
    want = f"mech_{arg}" if arg else None
    for a in graph.nodes_by_type(NodeType.ASSET):
        stack = _stack_of(a)
        if want is not None:
            if want in stack:
                return True
        elif any(s.startswith("mech_") for s in stack):
            return True
    return False


def _has_user(graph: Any, arg: str) -> bool:
    return bool(graph.nodes_by_type(NodeType.USER))


def _has_fronted_host(graph: Any, arg: str) -> bool:
    return any(
        bool(getattr(_props(a), "cf_protected", False)) for a in graph.nodes_by_type(NodeType.ASSET)
    )


# kind -> (resolver, arg_validator). arg_validator(arg) is True iff `arg` is well-formed for `kind`.
_REGISTRY: dict[str, tuple[Callable[[Any, str], bool], Callable[[str], bool]]] = {
    "credential": (_has_credential, lambda a: a == ""),
    "access": (_has_access, lambda a: a in _ACCESS_RANK),
    "enables_cred_access": (_has_enables_cred_access, lambda a: a == ""),
    "stack": (_has_stack, lambda a: a != ""),
    "auth_surface": (_has_auth_surface, lambda a: a == "" or a in _MECHANISMS),
    "user_enumerated": (_has_user, lambda a: a == ""),
    "fronted_host": (_has_fronted_host, lambda a: a == ""),
}


def _split(predicate: str) -> tuple[str, str]:
    kind, _, arg = predicate.partition(":")
    return kind, arg


def is_registered(predicate: str) -> bool:
    """True iff ``predicate`` is a known KIND with a well-formed arg. The integrity gate for
    techniques.yaml (Slice-1) — an unregistered/malformed predicate must fail CI, not silently
    resolve to False and mislead goal-backward scoring."""
    kind, arg = _split(predicate)
    entry = _REGISTRY.get(kind)
    return entry is not None and entry[1](arg)


def resolve(predicate: str, graph: Any) -> bool:
    """Evaluate ``predicate`` against the AttackGraph projection. Raises on an unregistered kind or a
    malformed arg — callers MUST have passed the integrity gate (``is_registered``) first, so a raise
    here is a programming error, never a runtime branch."""
    kind, arg = _split(predicate)
    entry = _REGISTRY.get(kind)
    if entry is None:
        raise KeyError(f"unregistered predicate kind: {predicate!r}")
    resolver, validator = entry
    if not validator(arg):
        raise ValueError(f"malformed predicate arg: {predicate!r}")
    return resolver(graph, arg)


def registered_kinds() -> frozenset[str]:
    """The closed vocabulary of predicate kinds (for tests / introspection)."""
    return frozenset(_REGISTRY)
