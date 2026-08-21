"""Authenticated crawl (GAP-116-B / ADR §12.32) — post-access re-recon.

After Beta wins a session (116-A propagates ``_won_session_cookies``), an operator does NOT
random-crawl: it goes straight to the high-value admin endpoints for the FINGERPRINTED stack
(APT41 victim-tailored; Turla/Lazarus hit ``/wp-admin/users.php`` directly, not a blind spider).
This module fetches each playbook endpoint for the DETECTED stack twice — an unauthenticated
baseline and one carrying the won session — and mints an AUTH-ONLY surface node when the session
reveals a ``marker`` the unauthenticated request does NOT (the §12.32 auth-vs-unauth diff). The
diff is emitted for the §12.43 oracle (GAP-118); this module DISCOVERS, it does not promote to
``cross_verified``.

BOUNDARY (RECON_ONLY — DETECT, never ACT):
  * GET-only. This module NEVER issues POST/PUT/DELETE. Reaching ``theme-editor.php`` proves the
    RCE SURFACE is reachable; WRITING a file through it is EXPLOITATION = Gamma (OFFENSIVE_APPROVED).
  * No PII persisted: it mints the SURFACE (path + reachable + marker matched), never the page
    content — user emails / config values stay out of the event store.
  * Stack-gated DATA (``authenticated_endpoints.yaml``), fired only for a DETECTED stack — not a
    blind fixed pipeline (anti-Lyndon #11).

Extracted as its own module (not appended to strike.py) per §12.47; operates on the Beta context
through its existing seam (http_client, event_store, graph_store, persist_node) — the same pattern
as recon/fingerprint.py operating on Alpha.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import yaml

from agent_alpha.agents.http_client import HttpClientError
from agent_alpha.events.event_types import EventType
from agent_alpha.graph.nodes import (
    AttackEdge,
    AttackNode,
    NodeType,
    ProofArtifact,
    RelationshipType,
    ServiceProperties,
    VerificationTier,
)
from agent_alpha.graph.persist import persist_edge, persist_node

_PLAYBOOK_PATH = pathlib.Path(__file__).with_name("authenticated_endpoints.yaml")
_DEPTH1_LINK_CAP = 10
_HREF_RE = re.compile(r"""href=["']([^"']+)["']""", re.IGNORECASE)
# RECON_ONLY (DETECT-never-ACT): a GET is NOT always safe. Many admin UIs put destructive
# actions behind GET links (WP `admin-ajax.php?action=...`, `?action=delete`, nonce action URLs).
# depth-1 follows ONLY param-less navigational admin PAGES; any query string or destructive/action
# token is refused — triggering an action is EXPLOITATION = Gamma, never this module.
_ACTION_ENDPOINTS = ("admin-ajax.php", "admin-post.php")
_DESTRUCTIVE_TOKENS = (
    "action=",
    "delete",
    "remove",
    "trash",
    "deactivate",
    "activate",
    "install",
    "update",
    "upgrade",
    "drop",
    "reset",
    "revoke",
    "purge",
    "logout",
    "nonce",
    "_wpnonce",
)


def _is_safe_get_surface(absolute: str) -> bool:
    """A depth-1 link is a safe DETECT target ONLY if it is a param-less navigational page with no
    action/destructive token — never an action endpoint whose GET mutates server state."""
    parsed = urlparse(absolute)
    if parsed.query:  # any query string may carry an action (?action=delete, ?id=1) — refuse
        return False
    low = absolute.lower()
    if any(ep in low for ep in _ACTION_ENDPOINTS):
        return False
    return not any(tok in low for tok in _DESTRUCTIVE_TOKENS)


def _load_playbook(path: pathlib.Path | None = None) -> dict[str, Any]:
    """Load the stack->endpoints playbook DATA. Static path (no user input); read_text over the
    canonical file (PTC-W6004: no unsafe/traversal open)."""
    return yaml.safe_load((path or _PLAYBOOK_PATH).read_text(encoding="utf-8")) or {}


def _stack_entries(
    playbook: dict[str, Any], tech_stack: list[str]
) -> list[tuple[str, dict[str, Any]]]:
    """Stack-GATED selection (anti-#11): return (stack_name, spec) ONLY for a stack Alpha actually
    fingerprinted. Match is EXACT on the canonical label (case-insensitive), NOT a substring test —
    the playbook key MUST equal the real ASSET.tech_stack label. WordPress is tagged
    ``constants.STACK_WP == "wp"`` (NOT "wordpress"): a substring test (`"wp" in "wordpress"`) is
    False, so a "wordpress" key would silently skip every WP host — false success (#3). Each spec
    may list extra ``aliases`` for other labels the same stack surfaces under."""
    labels = {label.lower() for label in tech_stack}
    entries: list[tuple[str, dict[str, Any]]] = []
    for stack_name, spec in playbook.items():
        keys = {stack_name.lower(), *(a.lower() for a in spec.get("aliases", []))}
        if keys & labels:
            entries.append((stack_name, spec))
    return entries


def _auth_only_diff(
    beta: Any, url: str, session_cookies: dict[str, str], marker: str
) -> tuple[bool, str]:
    """GET ``url`` unauthenticated AND with the won session (GET-ONLY). Return
    ``(is_auth_only, authed_body)``: auth-only iff the marker is present WITH the session and
    ABSENT without it (the §12.32 auth-vs-unauth diff — a marker present in BOTH is not auth-gated,
    a soft-200/cached page; anti-#3)."""
    try:
        unauth = beta.http_client.get(url)
        authed = beta.http_client.get(url, cookies=session_cookies)
    except HttpClientError:
        return (False, "")
    m = marker.lower()
    authed_body = authed.text or ""
    unauth_has = m in (unauth.text or "").lower()
    authed_has = m in authed_body.lower()
    return (authed_has and not unauth_has, authed_body)


def _mint_surface(
    beta: Any,
    *,
    engagement_id: str,
    host: str,
    stack_name: str,
    surface: str,
    path: str,
    now_utc: str,
    enabling_cred_id: str,
    access_level: str,
    depth1: bool = False,
) -> None:
    """Mint an AUTH-ONLY endpoint surface as a SERVICE node (SELF_VERIFIED — Beta's own crawl; the
    §12.43 oracle upgrades to cross_verified) + a leads_to edge from the access node. Persists the
    SURFACE only, never the page content (no PII).

    The ``auth_vs_unauth_diff`` proof artifact is the §12.43 independent oracle signal: computed by
    ``_auth_only_diff`` (a DIFFERENT code path from the login tool), it binds the enabling
    credential (``subject_ref``) and access level so the attestor can cross-verify independently.

    SERVICE (not ASSET): an auth-only endpoint is an endpoint/surface, NOT a host root. Minting it
    as ASSET would pollute ``nodes_by_type(ASSET)`` — which callers (``_project_target_context``,
    the tech_stack lookup) iterate assuming each ASSET is a host — so ASSET stays host-only here.
    ``banner`` carries the path; ``name`` the surface label (a dedicated AUTH_SURFACE node type is
    a future schema slice, GAP-116-F)."""
    node_id = f"service:{host}:authsurface:{surface}"
    node = AttackNode(
        id=node_id,
        type=NodeType.SERVICE,
        properties=ServiceProperties(name=surface, protocol="http", banner=path),
        confidence=0.6 if depth1 else 0.7,
        proof_artifacts=[
            ProofArtifact(
                artifact_id=str(__import__("uuid").uuid4()),
                type="auth_vs_unauth_diff",
                storage_ref="",
                description=f"auth-only marker present w/ session, absent w/o — {surface}",
                captured_at=now_utc,
                agent="beta",
                subject_ref=enabling_cred_id,
                target=host,
                access_level=access_level,
            ),
        ],
        agent="beta",
        timestamp_utc=now_utc,
        verification=VerificationTier.SELF_VERIFIED,
    )
    persist_node(beta.event_store, beta.graph_store, engagement_id, node, agent="beta")
    persist_edge(
        beta.event_store,
        beta.graph_store,
        engagement_id,
        AttackEdge(
            source_id=f"access:{host}",
            target_id=node_id,
            relationship=RelationshipType.LEADS_TO,
            confidence=node.confidence,
        ),
        agent="beta",
    )
    beta.event_store.append(
        EventType.AUTHENTICATED_SURFACE_DISCOVERED,
        engagement_id,
        "beta",
        {
            "host": host,
            "stack": stack_name,
            "surface": surface,
            "path": path,
            "depth1": depth1,
            # the §12.32 diff outcome, for the §12.43 oracle — NOT the page content (no PII).
            "auth_vs_unauth": "marker_present_authed_absent_unauth",
        },
    )


def _depth1_admin_links(authed_body: str, root: str, host: str, link_pattern: str) -> list[str]:
    """Extract SAME-HOST links from the authenticated page whose path matches the admin pattern —
    catches custom admin pages absent from the playbook WITHOUT a public-page crawl explosion."""
    if not link_pattern:
        return []
    out: list[str] = []
    for href in _HREF_RE.findall(authed_body):
        absolute = urljoin(root + "/", href)
        parsed = urlparse(absolute)
        if (parsed.hostname or "") != host:
            continue  # same-host only (scope / anti-SSRF)
        if link_pattern not in parsed.path or absolute in out:
            continue
        if not _is_safe_get_surface(absolute):
            continue  # refuse action/destructive GETs (DETECT-never-ACT)
        out.append(absolute)
    return out


def run_authenticated_crawl(
    beta: Any,
    *,
    engagement_id: str,
    host: str,
    root: str,
    session_cookies: dict[str, str] | None,
    tech_stack: list[str],
    now_utc: str,
    enabling_cred_id: str,
    access_level: str,
    playbook: dict[str, Any] | None = None,
) -> int:
    """Post-access authenticated crawl. Returns the count of auth-only surface nodes minted.

    ``engagement_id``, ``enabling_cred_id``, and ``access_level`` are passed explicitly (no
    reach into Beta's protected state — PYL-W0212). ``enabling_cred_id`` and ``access_level``
    are REQUIRED (keyword-only, no default) — a missing cred must fail loudly, not silently
    skip the diff (anti-Lyndon #3, mirrors GAP-118 c422271's keyword-only-required contract).

    Honest no-ops (emit AUTHENTICATED_CRAWL_SKIPPED, anti-#3 coverage-honesty):
      * no won session (single-cookie carrier not present for this stack) → skip;
      * no playbook entry for any DETECTED stack → skip.
    """
    eng = engagement_id
    if not session_cookies:
        beta.event_store.append(
            EventType.AUTHENTICATED_CRAWL_SKIPPED,
            eng,
            "beta",
            {"host": host, "reason": "no_session"},
        )
        return 0

    pb = playbook if playbook is not None else _load_playbook()
    entries = _stack_entries(pb, tech_stack)
    if not entries:
        beta.event_store.append(
            EventType.AUTHENTICATED_CRAWL_SKIPPED,
            eng,
            "beta",
            {"host": host, "reason": "no_playbook_for_stack", "tech_stack": list(tech_stack)},
        )
        return 0

    seen: set[str] = set()
    minted = 0
    for stack_name, spec in entries:
        link_pattern = str(spec.get("admin_link_pattern", ""))
        for ep in spec.get("endpoints", []):
            path = str(ep["path"])
            url = f"{root}{path}"
            if url in seen:
                continue
            seen.add(url)
            is_auth_only, authed_body = _auth_only_diff(
                beta, url, session_cookies, str(ep["marker"])
            )
            if not is_auth_only:
                continue
            _mint_surface(
                beta,
                engagement_id=eng,
                host=host,
                stack_name=stack_name,
                surface=str(ep["surface"]),
                path=path,
                now_utc=now_utc,
                enabling_cred_id=enabling_cred_id,
                access_level=access_level,
            )
            minted += 1
            # depth-1 admin-filtered extension (bounded) — custom admin pages off the playbook.
            for link in _depth1_admin_links(authed_body, root, host, link_pattern)[
                :_DEPTH1_LINK_CAP
            ]:
                if link in seen:
                    continue
                seen.add(link)
                child_auth_only, _ = _auth_only_diff(beta, link, session_cookies, link_pattern)
                if not child_auth_only:
                    continue
                _mint_surface(
                    beta,
                    engagement_id=eng,
                    host=host,
                    stack_name=stack_name,
                    surface=f"custom_admin:{urlparse(link).path}",
                    path=urlparse(link).path,
                    now_utc=now_utc,
                    enabling_cred_id=enabling_cred_id,
                    access_level=access_level,
                    depth1=True,
                )
                minted += 1

    beta.event_store.append(
        EventType.AUTHENTICATED_CRAWL_COMPLETE,
        eng,
        "beta",
        {"host": host, "surfaces_discovered": minted},
    )
    return minted
