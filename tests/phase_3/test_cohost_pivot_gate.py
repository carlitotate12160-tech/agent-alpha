"""Phase 3 close — cohost_pivot default-DENY safety gate (ADR §12.22 Decision 2.1).

Fail-closed contract for AuthorizationStateMachine.assert_pivot_target — the
gate Epsilon (Phase 5 lateral movement) MUST pass before pivoting to any
co-hosted / lateral target. Landed AHEAD of Epsilon on purpose: a fail-closed
safety gate must exist BEFORE the offensive consumer, not scrambled in during
Phase 5.

THE CO-HOST TRAP (the reason this gate exists): a co-hosted domain shares the
compromised host's IP, which may already be inside the engagement's ip_ranges —
but it has a DIFFERENT owner and is out of SOW. A domain must be authorized ONLY
by explicit scope.domains membership, NEVER by its IP falling in an in-scope
range. Touching a co-host not in SOW = unauthorized third-party access.

Run on Oracle ARM64:
    .venv312/bin/python3 -m pytest tests/phase_3/test_cohost_pivot_gate.py -v
"""

from __future__ import annotations

from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.conductor.models import Scope
from agent_alpha.events.store import InMemoryEventStore

SHARED_RANGE = "203.0.113.0/24"  # the shared-hosting IP range, in scope
SHARED_IP = "203.0.113.10"  # an IP inside that range
OWNED = "owned.example"  # client's owned domain, in scope.domains
COHOST = "cohost.example"  # a co-tenant on the SAME shared IP, NOT owned
EXCLUDED = "excluded.example"


def _sm() -> AuthorizationStateMachine:
    return AuthorizationStateMachine(event_store=InMemoryEventStore())


def _engagement(sm: AuthorizationStateMachine) -> str:
    rec = sm.create_engagement("client_a", SHARED_RANGE)
    sm.enable_recon(
        rec.engagement_id,
        Scope(
            ip_ranges=[SHARED_RANGE],
            domains=[OWNED, EXCLUDED],
            exclusions=[EXCLUDED],
        ),
    )
    return rec.engagement_id


# ── allow paths ────────────────────────────────────────────────────────
def test_owned_domain_in_scope_is_allowed() -> None:
    sm = _sm()
    eid = _engagement(sm)
    assert sm.assert_pivot_target(eid, OWNED) is True


def test_owned_domain_url_form_allowed_hostname_extracted() -> None:
    sm = _sm()
    eid = _engagement(sm)
    assert sm.assert_pivot_target(eid, f"https://{OWNED}/admin?x=1") is True


def test_internal_ip_in_range_allowed_for_lateral_pivot() -> None:
    """Bare-IP pivot to an in-scope internal host = legitimate lateral movement."""
    sm = _sm()
    eid = _engagement(sm)
    assert sm.assert_pivot_target(eid, SHARED_IP) is True


# ── THE CO-HOST TRAP (money test) ──────────────────────────────────────
def test_cohost_domain_on_in_scope_ip_is_denied() -> None:
    """Co-host domain shares an IP that IS in scope, yet the domain is NOT in
    scope.domains → DENY. A shared in-scope IP must never authorize a co-tenant
    domain (different owner, out of SOW)."""
    sm = _sm()
    eid = _engagement(sm)
    # Prove the shared IP is genuinely in scope...
    assert sm.is_in_scope(eid, SHARED_IP) is True
    # ...yet the co-host domain riding that same IP is denied.
    assert sm.assert_pivot_target(eid, COHOST) is False
    assert sm.assert_pivot_target(eid, f"http://{COHOST}/") is False


# ── deny paths (fail-closed) ───────────────────────────────────────────
def test_out_of_scope_ip_denied() -> None:
    sm = _sm()
    eid = _engagement(sm)
    assert sm.assert_pivot_target(eid, "198.51.100.7") is False


def test_excluded_domain_denied_exclusions_take_precedence() -> None:
    sm = _sm()
    eid = _engagement(sm)
    assert sm.assert_pivot_target(eid, EXCLUDED) is False


def test_empty_target_denied() -> None:
    sm = _sm()
    eid = _engagement(sm)
    assert sm.assert_pivot_target(eid, "") is False


def test_garbage_target_denied() -> None:
    sm = _sm()
    eid = _engagement(sm)
    assert sm.assert_pivot_target(eid, "not a host !!") is False


def test_unverified_engagement_denied() -> None:
    """Engagement created but scope never enabled → fail closed."""
    sm = _sm()
    rec = sm.create_engagement("client_a", SHARED_RANGE)
    assert sm.assert_pivot_target(rec.engagement_id, OWNED) is False


def test_unknown_engagement_denied_and_never_raises() -> None:
    sm = _sm()
    assert sm.assert_pivot_target("eng_does_not_exist", OWNED) is False
