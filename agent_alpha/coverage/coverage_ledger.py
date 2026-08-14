"""Coverage ledger — engagement-scope coverage projection (Claude lane, pure read).

The ENGAGEMENT-SCOPE generalization of §12.45 (per-credential methodology caveat):
project every discovered surface against the canonical technique catalog and classify
each applicable cell, so Omega can state what WAS and WAS NOT tested — and never emit
"secure" from an absence. Pure projection over the event stream + techniques.yaml; no
I/O beyond loading the static catalog. Independent of GAP-050 and the strategic layer.

Buckets (applicable cells only; non-applicable technique/surface pairs are excluded):
  tested            — a run_event fired for this technique on this surface's host
  not_run           — capable + applicable but no run event (RUNTIME wiring-gate: catches
                      Lyndon #2 dead-code, e.g. an applicator that never fired)
  blocked           — a defense stopped the surface (WafBlocked / HostAbandoned) (+ GAP-073 mode)
  capability_absent — applicable but the tool cannot do it yet (roadmap; the honest "we do
                      NOT test SQLi here")
  out_of_scope      — excluded by SOW/RoE
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import yaml

from agent_alpha.recon.auth_surface import bare_mechanisms

_AUTH_LABELS = frozenset({"http_basic_auth", "login-form", "spa-login-form"})
_BLOCK_EVENTS = frozenset({"WafBlocked", "HostAbandoned"})
_CATALOG_PATH = pathlib.Path(__file__).with_name("techniques.yaml")


@dataclass(frozen=True)
class Technique:
    id: str
    mitre: str
    surface: str
    capability_present: bool
    run_event: str | None = None
    gap_ref: str | None = None
    auth_mechanism: tuple[str, ...] = ()


@dataclass(frozen=True)
class Surface:
    surface_id: str  # the host (v1)
    surface_type: str  # host | auth_surface
    mechanisms: frozenset[str] = frozenset()  # GAP-074 2b: bare auth-mechanism tokens
    #   present on this host (form_post/json_rpc/http_basic/...). Empty = mechanism UNKNOWN.
    #   Only meaningful for auth_surface; gates mechanism-specific techniques (see project_coverage).


@dataclass(frozen=True)
class CoverageCell:
    surface_id: str
    surface_type: str
    technique_id: str
    bucket: str
    detail: str = ""


@dataclass(frozen=True)
class CoverageReport:
    cells: tuple[CoverageCell, ...]
    not_assessed: tuple[str, ...]  # engagement-scope capability_absent technique ids


def load_catalog(path: pathlib.Path | None = None) -> tuple[Technique, ...]:
    data = yaml.safe_load((path or _CATALOG_PATH).read_text())
    out: list[Technique] = []
    for t in data["techniques"]:
        out.append(
            Technique(
                id=t["id"],
                mitre=t["mitre"],
                surface=t["surface"],
                capability_present=bool(t["capability_present"]),
                run_event=t.get("run_event"),
                gap_ref=t.get("gap_ref"),
                auth_mechanism=tuple(t.get("auth_mechanism", ())),
            )
        )
    return tuple(out)


def _event_host(payload: dict[str, Any]) -> str:
    """Extract host from an event payload — handles both flat and nested (NodeDiscovered)."""
    # NodeDiscovered events nest properties under "properties" (node_to_dict format).
    props = payload.get("properties")
    if isinstance(props, dict):
        host = props.get("host")
        if host:
            return str(host)
    # Flat payloads (WafBlocked, StrikeCandidateAttempted, etc.) carry host at top level.
    host = payload.get("host") or payload.get("entry_host") or ""
    return str(host) if host else ""


def _event_tech_stack(payload: dict[str, Any]) -> list[str]:
    """Extract tech_stack/labels from an event payload — handles nested NodeDiscovered."""
    props = payload.get("properties")
    if isinstance(props, dict):
        stack = props.get("tech_stack") or props.get("labels") or []
        if isinstance(stack, list):
            return [str(s) for s in stack]
    stack = payload.get("tech_stack") or payload.get("labels") or []
    if isinstance(stack, list):
        return [str(s) for s in stack]
    return []


def _surfaces(events: Iterable[Any]) -> list[Surface]:
    hosts: set[str] = set()
    auth_hosts: set[str] = set()
    stack_by_host: dict[str, set[str]] = {}
    for e in events:
        if getattr(e, "event_type", None) != "NodeDiscovered":
            continue
        p = getattr(e, "payload", None) or {}
        host = _event_host(p)
        if not host:
            continue
        hosts.add(host)
        tech_stack = _event_tech_stack(p)
        # Union tech_stack across every NodeDiscovered for this host — the mech_* label may
        # ride a different re-emission than the auth-type label (merge_asset_node accumulates).
        stack_by_host.setdefault(host, set()).update(tech_stack)
        if _AUTH_LABELS.intersection(tech_stack):
            auth_hosts.add(host)
    surfaces = [Surface(h, "host") for h in sorted(hosts)]
    surfaces += [
        # GAP-074 2b: attach the host's bare auth-mechanism tokens so mechanism-specific
        # techniques are counted applicable ONLY on a matching surface (precise denominator).
        Surface(h, "auth_surface", bare_mechanisms(stack_by_host.get(h, set())))
        for h in sorted(auth_hosts)
    ]
    return surfaces


def project_coverage(
    events: Iterable[Any],
    catalog: tuple[Technique, ...] | None = None,
    *,
    excluded_techniques: frozenset[str] = frozenset(),
) -> CoverageReport:
    events = list(events)
    catalog = catalog if catalog is not None else load_catalog()
    surfaces = _surfaces(events)

    blocked_hosts: set[str] = set()
    ran: set[tuple[str, str]] = set()  # (event_type, host)
    for e in events:
        et = getattr(e, "event_type", None)
        p = getattr(e, "payload", None) or {}
        host = _event_host(p)
        # STRIKE_CANDIDATE_ATTEMPTED carries the entry host under 'host'
        if et in _BLOCK_EVENTS and host:
            blocked_hosts.add(host)
        if et and host:
            ran.add((str(et), host))

    cells: list[CoverageCell] = []
    for s in surfaces:
        for t in catalog:
            if t.surface != s.surface_type:
                continue  # not_applicable → excluded
            # GAP-074 2b: mechanism precision. When the surface's auth mechanism is KNOWN
            # (s.mechanisms non-empty) and the technique is mechanism-specific
            # (t.auth_mechanism non-empty), the technique is applicable ONLY if the sets
            # overlap — no "we didn't test JSON-RPC login" on a form-only surface. Mechanism
            # UNKNOWN (empty s.mechanisms) → fail-open, technique stays applicable (mirrors 2a).
            if s.mechanisms and t.auth_mechanism and not (set(t.auth_mechanism) & s.mechanisms):
                continue  # mechanism mismatch → not applicable → excluded from denominator
            cells.append(_classify(s, t, blocked_hosts, ran, excluded_techniques))

    not_assessed = tuple(t.id for t in catalog if not t.capability_present)
    return CoverageReport(cells=tuple(cells), not_assessed=not_assessed)


def _classify(
    s: Surface,
    t: Technique,
    blocked_hosts: set[str],
    ran: set[tuple[str, str]],
    excluded: frozenset[str],
) -> CoverageCell:
    def cell(bucket: str, detail: str = "") -> CoverageCell:
        return CoverageCell(s.surface_id, s.surface_type, t.id, bucket, detail)

    if t.id in excluded:
        return cell("out_of_scope", "excluded by RoE/SOW")
    if not t.capability_present:
        return cell("capability_absent", f"not built ({t.gap_ref or 'roadmap'})")
    if s.surface_id in blocked_hosts:
        return cell("blocked", "defense stopped the surface (WAF/abandoned)")
    if t.run_event and (t.run_event, s.surface_id) in ran:
        return cell("tested")
    return cell("not_run", "capable but no run event (wiring/self-audit)")
