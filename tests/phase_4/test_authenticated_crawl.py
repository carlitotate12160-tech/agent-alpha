"""GAP-116-B — post-access authenticated crawl (§12.32). Contract:

* CONSUMES the won session (116-A) → auth-only surface DETECTION (retires 116-A dead-state).
* RECON_ONLY: GET-only (never POST/DELETE) AND never follows a state-changing GET link (a GET is
  NOT always safe — WP puts destructive actions behind GET); mints the SURFACE, not page content.
* auth-vs-unauth diff: a marker present WITH the session and ABSENT without it (anti soft-200/#3).
* stack-gated by the REAL label — WordPress is tagged constants.STACK_WP == "wp" (NOT "wordpress");
  a substring match would skip every WP host = false success (#3).
* coverage-honest: emits COMPLETE even at 0 surfaces; SKIPPED (honest no-op) with no session / stack.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse

from agent_alpha.agents.beta.authenticated_crawl import (
    _load_playbook,
    _stack_entries,
    run_authenticated_crawl,
)
from agent_alpha.config.constants import STACK_WP
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import AccessLevelProperties, AttackNode, NodeType, VerificationTier
from agent_alpha.graph.persist import persist_node

HOST = "wp.lab.invalid"
ROOT = f"http://{HOST}"
NOW = "2026-08-17T00:00:00Z"
ENG = "eng1"

# Playbook key is the REAL fingerprint label ("wp"), not "wordpress".
PLAYBOOK = {
    "wp": {
        "admin_link_pattern": "/wp-admin/",
        "endpoints": [
            {"path": "/wp-admin/", "surface": "wp_admin_dashboard", "marker": "DASH_MARK"},
            {"path": "/wp-admin/users.php", "surface": "wp_user_admin", "marker": "USERS_MARK"},
        ],
    }
}

# Authed bodies keyed by path; the dashboard links a custom admin page (depth-1 target).
AUTHED = {
    "/wp-admin/": 'DASH_MARK <a href="/wp-admin/custom-plugin.php">panel</a>',
    "/wp-admin/users.php": "USERS_MARK admin@client.example listed",
    "/wp-admin/custom-plugin.php": "custom /wp-admin/ plugin control panel",
}


class _Resp:
    def __init__(self, text: str, status: int = 200) -> None:
        self.text = text
        self.status_code = status
        self.headers: dict[str, str] = {}


class _Http:
    """Routes by session: with cookies → authed body; without → empty (no marker).
    Records every method so a test can prove GET-only + which URLs were touched."""

    _BODIES = AUTHED

    def __init__(self) -> None:
        self.methods: list[tuple[str, str, bool]] = []

    def get(self, url: str, *, cookies: Any = None, headers: Any = None) -> _Resp:
        self.methods.append(("GET", url, bool(cookies)))
        return _Resp(self._BODIES.get(urlparse(url).path, "")) if cookies else _Resp("")

    def post(self, *a: Any, **k: Any) -> _Resp:  # must NEVER be called by the crawl
        self.methods.append(("POST", "", False))
        return _Resp("")


def _beta() -> tuple[SimpleNamespace, InMemoryEventStore, NetworkXGraphStore, _Http]:
    events, graph, http = InMemoryEventStore(), NetworkXGraphStore(), _Http()
    persist_node(
        events,
        graph,
        ENG,
        AttackNode(
            id=f"access:{HOST}",
            type=NodeType.ACCESS_LEVEL,
            properties=AccessLevelProperties(level="admin", user_context="admin"),
            confidence=0.9,
            agent="beta",
            timestamp_utc=NOW,
            verification=VerificationTier.SELF_VERIFIED,
        ),
        agent="beta",
    )
    beta = SimpleNamespace(http_client=http, event_store=events, graph_store=graph)
    return beta, events, graph, http


def _types(events: InMemoryEventStore) -> list[str]:
    return [e.event_type for e in events.get_events(ENG)]


def _crawl(beta: Any, **over: Any) -> int:
    kw: dict[str, Any] = dict(
        engagement_id=ENG,
        host=HOST,
        root=ROOT,
        session_cookies={"wordpress_logged_in_x": "v"},
        tech_stack=[STACK_WP],
        now_utc=NOW,
        playbook=PLAYBOOK,
    )
    kw.update(over)
    return run_authenticated_crawl(beta, **kw)


def test_won_session_reveals_auth_only_surfaces_and_is_get_only() -> None:
    beta, events, graph, http = _beta()
    minted = _crawl(beta)
    # dashboard + users + depth-1 custom-plugin = 3 auth-only surfaces.
    assert minted == 3
    surfaces = [e for e in _types(events) if e == EventType.AUTHENTICATED_SURFACE_DISCOVERED]
    assert len(surfaces) == 3
    # Auth-only surfaces are SERVICE nodes (endpoints), NOT ASSET — ASSET stays host-only.
    minted_ids = {n.id for n in graph.nodes_by_type(NodeType.SERVICE)}
    assert f"service:{HOST}:authsurface:wp_admin_dashboard" in minted_ids
    assert not graph.nodes_by_type(NodeType.ASSET), (
        "auth-surfaces must not pollute the host ASSET space"
    )
    assert all(m[0] == "GET" for m in http.methods), "authenticated crawl must be GET-only"


def test_real_wp_label_matches_playbook_not_the_word_wordpress() -> None:
    # The live label is "wp"; a "wordpress" tech_stack would NOT occur — guard the #3 regression.
    beta, _, _, _ = _beta()
    assert _crawl(beta, tech_stack=[STACK_WP]) == 3
    assert STACK_WP == "wp"  # if this constant ever changes, the playbook key must follow
    # And a host NOT fingerprinted as wp is honestly skipped, never silently "done".
    beta2, events2, _, _ = _beta()
    assert _crawl(beta2, tech_stack=["nginx"]) == 0
    assert EventType.AUTHENTICATED_CRAWL_SKIPPED in _types(events2)


def test_depth1_refuses_state_changing_get_links() -> None:
    # A GET is not always safe: WP action links (?action=delete, admin-ajax.php) must NEVER be
    # followed — triggering them is EXPLOITATION = Gamma (DETECT-never-ACT).
    beta, _, _, _ = _beta()

    class _Danger(_Http):
        _BODIES = {
            "/wp-admin/": (
                "DASH_MARK "
                '<a href="/wp-admin/users.php?action=delete&user=1">delete user</a>'
                '<a href="/wp-admin/admin-ajax.php?action=trash_post">ajax</a>'
                '<a href="/wp-admin/network-settings.php">safe page</a>'
            ),
            "/wp-admin/network-settings.php": "custom /wp-admin/ settings panel",
        }

    http = _Danger()
    beta.http_client = http
    pb = {
        "wp": {
            "admin_link_pattern": "/wp-admin/",
            "endpoints": [{"path": "/wp-admin/", "surface": "dash", "marker": "DASH_MARK"}],
        }
    }
    _crawl(beta, playbook=pb)

    fetched = [u for _, u, _ in http.methods]
    assert not any("action=delete" in u for u in fetched), "must not GET a destructive action link"
    assert not any("admin-ajax.php" in u for u in fetched), "must not GET an action endpoint"
    # the benign param-less admin page IS followed (value preserved).
    assert any("network-settings.php" in u for u in fetched)
    assert all(m[0] == "GET" for m in http.methods)


def test_no_session_is_honest_skip_no_surface() -> None:
    beta, events, _, http = _beta()
    assert _crawl(beta, session_cookies=None) == 0
    assert EventType.AUTHENTICATED_CRAWL_SKIPPED in _types(events)
    assert EventType.AUTHENTICATED_SURFACE_DISCOVERED not in _types(events)
    assert not http.methods  # no requests at all without a session


def test_stack_gated_no_playbook_for_detected_stack_skips() -> None:
    beta, events, _, _ = _beta()
    assert _crawl(beta, tech_stack=["nginx"]) == 0
    assert EventType.AUTHENTICATED_CRAWL_SKIPPED in _types(events)


def test_coverage_honest_complete_even_when_zero_surfaces() -> None:
    beta, events, _, _ = _beta()
    pb = {
        "wp": {
            "admin_link_pattern": "/wp-admin/",
            "endpoints": [{"path": "/nope", "surface": "x", "marker": "ABSENT_MARK"}],
        }
    }
    assert _crawl(beta, playbook=pb) == 0
    assert EventType.AUTHENTICATED_CRAWL_COMPLETE in _types(events)  # absence recorded, not silent


def test_marker_present_in_both_is_not_auth_only() -> None:
    # A marker that also appears unauthenticated (soft-200) must NOT mint (anti-#3).
    beta, _, _, _ = _beta()

    class _Both(_Http):
        def get(self, url: str, *, cookies: Any = None, headers: Any = None) -> _Resp:
            self.methods.append(("GET", url, bool(cookies)))
            return _Resp("DASH_MARK everywhere")  # marker present with AND without session

    beta.http_client = _Both()
    assert _crawl(beta) == 0, "a marker present unauthenticated is not an auth-only surface"


def test_shipped_playbook_parses_and_is_stack_gated() -> None:
    pb = _load_playbook()
    assert {"wp", "odoo", "laravel"} <= set(pb)
    # Only the DETECTED stack fires — anti-Lyndon #11 (no blind pipeline); real "wp" label matches.
    assert [name for name, _ in _stack_entries(pb, [STACK_WP])] == ["wp"]
    assert [name for name, _ in _stack_entries(pb, ["odoo"])] == ["odoo"]
