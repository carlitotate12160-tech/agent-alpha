"""§12.64 Step 0 — recon-technique attempt emission (the WRITE side of coverage honesty).

Producer of ``RECON_TECHNIQUE_ATTEMPTED``, the counterpart to ``coverage_ledger.project_coverage``
(the consumer). Lives OUTSIDE scout: the Alpha god-object is size-frozen (GAP-161 / Lyndon #8),
so Alpha CALLS this at every dispatch site instead of growing a method — the ratchet's
"extract capability into a module" directive.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from agent_alpha.coverage.coverage_ledger import default_tool_to_technique
from agent_alpha.events.event_types import EventType


def emit_recon_technique_attempt(event_store: Any, engagement_id: str, tool: str, url: str) -> None:
    """Append ``RECON_TECHNIQUE_ATTEMPTED{host, technique_id}`` for a dispatched recon tool.

    No-op unless *tool* maps to a coverage technique (``default_tool_to_technique()``, derived
    from techniques.yaml — the single-source join). Emitted on DISPATCH, not on a positive
    finding, so ``not_run`` is a strictly shrinking set and 187b's re-seed terminates.
    ``project_coverage`` matches by IDENTITY (host, technique_id), so an attempt of one
    technique never false-marks a sibling on the same host.
    """
    tech_id = default_tool_to_technique().get(tool)
    if tech_id is None:
        return
    # A coverage attempt is keyed by host; a hostless (malformed) URL cannot be attributed
    # to a surface — the ledger would ignore it (its `and host` guard) so skip the noise (Qodo).
    host = urlparse(url).hostname or ""
    if not host:
        return
    event_store.append(
        EventType.RECON_TECHNIQUE_ATTEMPTED,
        engagement_id,
        "alpha",
        {"host": host, "technique_id": tech_id},
    )
