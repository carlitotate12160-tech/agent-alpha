"""Fingerprint-first recon seed (ADR §12.65 / GAP-169).

An operator OBSERVES before it ACTS: fetch the root ONCE, fingerprint what the target
actually IS, then seed leak-path probes from the REAL stack labels — never a blind
`DEFAULT_LEAK_PATHS` spray on an unfingerprinted host (the 404 breadth-anomaly that trips a
WAF, the exact scanner tell APT29/Volt Typhoon/APT41 avoid). This REORDERS the existing
machinery (`PlaybookEngine` rule tier + `CAPABILITY_CATALOG` + `Planner.select_leak_paths`) —
it builds NO new selector and NO new fingerprint engine (anti-#6/#7).

Extracted from `Alpha.run_recon` so scout.py stays under the GAP-161 size ratchet; the
orchestrator operates on the Alpha recon context through its existing seam (http_client,
planner, enqueue_discovered_url, the `_prefetched` prime, dead-host abandonment).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from agent_alpha.agents.http_client import HttpClientError
from agent_alpha.recon.capability_probe import capability_for_tool


def fingerprint_all(observation: dict[str, Any], playbook: Any) -> tuple[str, ...]:
    """Multi-label header+body fingerprint over the root observation (GAP-169 Decision C).

    Runs EVERY matching RULE-tier rule (``playbook.match_all``) and resolves each capability
    fingerprint tool to its canonical ``tech_stack`` label via ``capability_for_tool``. A root
    can be multi-stack (WordPress behind Tomcat), so a single top-1 match under-seeds — this
    returns ALL matched stacks, deduped, in priority order.

    PURE: reuses the PlaybookEngine rule tier + CAPABILITY_CATALOG (no new fingerprint engine).
    Non-capability tools (action rules) resolve to ``None`` and are skipped — only a capability
    fingerprint yields a stack label. ``playbook is None`` (a test-stub orchestrator with no
    ``.playbook``) → ``()``, i.e. an unfingerprinted host → the honest DEFAULT baseline downstream
    (zero behaviour change for those callers)."""
    if playbook is None:
        return ()
    labels: list[str] = []
    for tool in playbook.match_all(observation):
        spec = capability_for_tool(tool)
        if spec is not None and spec.label not in labels:
            labels.append(spec.label)
    return tuple(labels)


def seed_fingerprint_first(alpha: Any, target_url: str, root: str, intel_signal: Any) -> None:
    """Fingerprint-first initial leak-path seed for ``target_url`` (ADR §12.65 Decisions A–D).

    Replaces the pre-fetch blind ``select_leak_paths(labels=[])`` seed. ``target_url`` is already
    the first item in ``alpha._work_queue`` (``_reset_target_state`` seeds ``[target_url]``), so we
    do NOT enqueue it again — we PRIME its response so the loop's first pop reuses it with NO
    second GET (Decision D). The bare homepage was always OODA-processed as that first queue item;
    169 only moves the fingerprint AHEAD of the seed so the seed is label-driven, not blind.

    Decision B: no labels (cold/unknown stack) → ``select_leak_paths([])`` still seeds the honest
    stack-agnostic ``DEFAULT_LEAK_PATHS`` baseline (unless WAF-suppressed) — priority, not exclusion.
    Decision D-2: a transport-dead root is abandoned (prune its pre-seeded queue entry so the loop
    does not pop it and raise again); a WAF/CF-blocked root yields no labels and is primed for the
    loop's existing ``_attempt_reach`` to handle — no special-casing (``suppress_blind`` already
    holds via ``protection_detected``).
    """
    suppress_blind = intel_signal.protection_detected is not None
    try:
        # Fetch the EXACT url the loop seeded (_work_queue == [target_url]) so the prime key
        # matches the pop; using a constructed "root/" would double-fetch a distinct URL.
        root_resp = alpha.http_client.get(target_url)
    except HttpClientError:
        # D-2: root front-door transport-dead. §12.61 origin-flank — the timeout is the
        # origin-direct PRECONDITION, not an abort (the niagamas lesson). Try the
        # discovered origin BEFORE abandoning; reuse the SAME reach path as _step_once
        # (no 2nd path, #6). Fail-closed: None → mirror the original mark-dead + prune.
        host = urlparse(target_url).hostname or urlparse(target_url).netloc
        # Origin-flank is a HOST-level decision keyed on a ROOT front-door timeout —
        # mirror _step_once R1's `path in ("", "/")` guard so a non-root transport-dead
        # seed is NOT origin-flanked (it is just non-analyzable). Keeps the two
        # transport-dead call-sites symmetric (Sourcery bug_risk).
        reach = (
            alpha._attempt_reach_transport_dead(target_url)
            if urlparse(target_url).path in ("", "/")
            else None
        )
        if reach is None:
            alpha._dead_hosts.add(host)
            alpha._work_queue = [
                u for u in alpha._work_queue if (urlparse(u).hostname or urlparse(u).netloc) != host
            ]
            alpha._persist_host_abandoned_event(host)
            return
        # Origin-flank reached surface → fingerprint the origin body and seed stack-gated
        # leak paths from it, exactly as the live-front-door path below.
        root_resp = reach

    observation = {"body": root_resp.text, "headers": dict(root_resp.headers)}
    labels = fingerprint_all(observation, getattr(alpha.orchestrator, "playbook", None))
    # Real labels instead of []: WP→wp paths, Odoo→odoo paths; DEFAULT only when labels == []
    # (Decision B). suppress_default gated by WAF (suppress_blind) OR by a positive fingerprint
    # (bool(labels)) — a fingerprinted host probes its stack paths, not the blind universal spray.
    for path in alpha._planner.select_leak_paths(
        list(labels), suppress_default=suppress_blind or bool(labels)
    ):
        alpha.enqueue_discovered_url(f"{root}{path}")
    # Prime the already-queued homepage response so the loop's first pop reuses it (no 2nd GET).
    alpha._prefetched[target_url] = root_resp
