"""OMEGA-GOV: techniques.yaml single-source integrity (anti-#7 drift).

Cheap tripwires so the coverage denominator cannot silently rot:
  * every catalog run_event is a REAL EventType (a typo'd run_event would pin a
    capable technique to `not_run` forever = a false "not tested" in the client report);
  * every capability_absent entry links a gap_ref (roadmap traceability);
  * technique ids are unique;
  * (ADR §12.66 Slice-1) every requires/produces predicate resolves to the closed vocabulary,
    and every capable node-technique declares its effect (else it is invisible to composition).
FOLLOW-UP (not v1): a playbook `coverage_technique:` field to bind each rule to a
playbook id — today playbook technique_ids are scan-level MITRE, the catalog is
outcome-level, so a direct MITRE-subset check is the wrong abstraction.
"""

from __future__ import annotations

import pathlib

import yaml

from agent_alpha.events.event_types import EventType

_CATALOG = pathlib.Path("agent_alpha/coverage/techniques.yaml")


def _techniques() -> list[dict]:
    return yaml.safe_load(_CATALOG.read_text())["techniques"]


def test_run_events_are_real_event_types() -> None:
    valid = {e.value for e in EventType}
    for t in _techniques():
        ev = t.get("run_event")
        assert ev is None or ev in valid, f"{t['id']}: phantom run_event {ev!r}"


def test_capability_absent_links_a_gap() -> None:
    for t in _techniques():
        if not t["capability_present"]:
            assert t.get("gap_ref"), f"{t['id']}: capability_absent without gap_ref"


def test_technique_ids_unique() -> None:
    ids = [t["id"] for t in _techniques()]
    assert len(ids) == len(set(ids))


def test_catalog_tool_is_a_real_recon_tool() -> None:
    """§12.64 Step 0: every catalog `tool:` must be a sanctioned recon tool (no typo). A
    phantom tool would silently never emit RECON_TECHNIQUE_ATTEMPTED, pinning its technique
    to permanent `not_run` — the exact false 'not tested' this instrumentation removes."""
    from agent_alpha.config import constants

    valid = set(constants.RECON_TOOL_CATALOG)
    for t in _techniques():
        tool = t.get("tool")
        assert tool is None or tool in valid, f"{t['id']}: phantom tool {tool!r}"


def test_no_duplicate_catalog_tools() -> None:
    """§12.64 Step 0 (Greptile/Sourcery): a tool maps to at most ONE technique. A duplicate
    would silently collapse (last-wins) in tool_to_technique and drop a technique into
    permanent `not_run`. Caught here in CI before the import-time build would raise."""
    tools = [t["tool"] for t in _techniques() if t.get("tool")]
    assert len(tools) == len(set(tools)), f"duplicate tool in techniques.yaml: {sorted(tools)}"


# ── ADR §12.66 Slice-1: precondition/effect model integrity ────────────────────────────────

_NODE_SURFACES = {"host", "auth_surface"}  # surfaces whose techniques yield graph nodes


def test_requires_produces_predicates_resolve() -> None:
    """Every requires/produces predicate MUST be a REGISTERED predicate in the closed vocabulary
    (agent_alpha.coverage.predicates). An unregistered/typo'd predicate would let techniques.yaml
    drift from graph/nodes.py (anti-#7) and goal-backward scoring (Slice-2) would silently ignore
    an unknown precondition/effect — a false 'can't chain'."""
    from agent_alpha.coverage.predicates import is_registered

    for t in _techniques():
        for key in ("requires", "produces"):
            for pred in t.get(key) or []:
                assert is_registered(pred), f"{t['id']}: unregistered {key} predicate {pred!r}"


def test_capable_node_technique_declares_effect() -> None:
    """A capable technique on a node-producing surface (host/auth_surface) MUST declare `produces`.
    Without it the technique is invisible to chain composition — goal-backward scoring cannot chain
    toward an effect it never declared. Reach (fronted_host) and DNS surfaces compose on a separate
    axis (§12.61) and are exempt."""
    for t in _techniques():
        if t.get("capability_present") and t["surface"] in _NODE_SURFACES:
            assert t.get("produces"), f"{t['id']}: capable node-technique with no `produces`"
