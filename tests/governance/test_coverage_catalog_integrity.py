"""OMEGA-GOV: techniques.yaml single-source integrity (anti-#7 drift).

Cheap tripwires so the coverage denominator cannot silently rot:
  * every catalog run_event is a REAL EventType (a typo'd run_event would pin a
    capable technique to `not_run` forever = a false "not tested" in the client report);
  * every capability_absent entry links a gap_ref (roadmap traceability);
  * technique ids are unique.
FOLLOW-UP (not v1): a playbook `coverage_technique:` field to bind each rule to a
catalog id — today playbook technique_ids are scan-level MITRE, the catalog is
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
