"""GAP-034: per-host reachability read-model over the event store.

A pure projection — NO field is added to the sealed ``AssetProperties`` canonical
type (anti-Lyndon #6). ``select_strike_entry`` consumes this to rank reachable
auth-surfaces above strike-dead ones, so the bounded strike budget
(``MAX_STRIKE_CANDIDATES``) is never spent on a host Alpha already abandoned.

DESIGN DECISION (product-critical): ONLY ``HOST_ABANDONED`` marks a host
strike-dead. ``WAF_BLOCKED`` does NOT — a WAF/CF-blocked host is precisely an
origin-exposure-bypass target (Agent-Alpha's moat), so demoting it would sabotage
the core value. See docs/Session_Handoff.md GAP-034.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from agent_alpha.events.event_types import EventType


def unreachable_hosts(events: Iterable[Any]) -> frozenset[str]:
    """Return the set of hosts marked strike-dead (``HOST_ABANDONED``) this engagement.

    Append-only + idempotent: re-seeing the same HOST_ABANDONED host is a no-op.
    A host is NEVER un-abandoned within a run (Alpha marks dead on root-transport
    failure / egress block; it does not resurrect mid-run — see scout GAP-029/037).
    """
    dead: set[str] = set()
    for event in events:
        if getattr(event, "event_type", None) != EventType.HOST_ABANDONED:
            continue
        host = (getattr(event, "payload", None) or {}).get("host")
        if host:
            dead.add(str(host))
    return frozenset(dead)
