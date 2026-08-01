"""Contract: user_derived_creds turns Alpha-enumerated usernames into a SMALL,
context-derived candidate set (GAP-015, the Alpha→Beta moat) — derive, never spray.

RED before the tool exists:
  - ``from agent_alpha.tools.internal.access.user_derived_creds import ...`` → ImportError.

Lyndon checks:
  #3 no static password (payability: a hardcoded guess is not a credible finding).
  #4 derive-not-spray: candidates bounded + context-derived, no wordlist file.
  #6 no duplication of default_creds' well-known defaults.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_4/test_user_derived_creds.py -v
"""

from __future__ import annotations

import inspect
from typing import Any

from agent_alpha.config import constants
from agent_alpha.graph.nodes import AttackNode, NodeType, UserProperties
from agent_alpha.tools.contracts import ResourceBudget, TargetContext
from agent_alpha.tools.internal.access import user_derived_creds as mod
from agent_alpha.tools.internal.access.applicator import AuthResult
from agent_alpha.tools.internal.access.user_derived_creds import (
    UserDerivedCredsTool,
    derive_login_candidates,
)


def test_domain_stem_uses_public_suffix_list() -> None:
    """PSL-backed stem: multi-level ccTLDs resolve to the brand, not the suffix."""
    assert mod._domain_stem("bernofarm.com") == "bernofarm"
    assert mod._domain_stem("www.foo.co.id") == "foo"
    assert mod._domain_stem("portal.acme.co.uk") == "acme"


def test_derive_is_context_only_no_static_password() -> None:
    """Every candidate is derived from username or domain stem — NO static password.
    'password'/'admin123'-style constants must never appear (payability + #3)."""
    pairs = derive_login_candidates("editor", "bernofarm.com")
    passwords = [pw for _, pw in pairs]
    assert passwords == ["editor", "editor123", "bernofarm", "bernofarm123"]
    assert "password" not in passwords
    # the username on every pair is the enumerated account, unchanged
    assert {u for u, _ in pairs} == {"editor"}


def test_derive_is_bounded_no_spray() -> None:
    """Candidate count never exceeds the single-source cap (derive-not-spray)."""
    pairs = derive_login_candidates("admin", "example.com")
    assert len(pairs) <= constants.USER_DERIVED_MAX_CANDIDATES_PER_USER


def test_derive_dedupes_when_username_equals_stem() -> None:
    """username == domain stem collapses duplicates instead of padding the list."""
    pairs = derive_login_candidates("bernofarm", "bernofarm.com")
    passwords = [pw for _, pw in pairs]
    assert passwords == ["bernofarm", "bernofarm123"]  # not doubled


def test_no_wordlist_file_imported() -> None:
    """Anti-spray structural guard: the module reads no external wordlist file."""
    src = inspect.getsource(mod)
    assert "open(" not in src and ".txt" not in src


# ── applies_to reads Alpha's USER nodes (the Alpha→Beta seam) ────────────────


class _FakeGraph:
    def __init__(self, users: list[str]) -> None:
        self._users = [
            AttackNode(
                id=f"user:h:{u}",
                type=NodeType.USER,
                properties=UserProperties(username=u, source="wp_rest_users"),
                confidence=0.9,
            )
            for u in users
        ]

    def nodes_by_type(self, node_type: Any) -> list[AttackNode]:
        return self._users if node_type is NodeType.USER else []


def _ctx(prior: tuple[str, ...] = ()) -> TargetContext:
    return TargetContext(
        engagement_id="eng", tenant_id=None, target="https://bernofarm.com", prior_findings=prior
    )


def test_applies_high_when_users_enumerated() -> None:
    """Relevance is meaningful only once Alpha has enumerated usernames."""
    tool = UserDerivedCredsTool(graph_store=_FakeGraph(["admin", "editor"]))
    assert tool.applies_to(_ctx()) == 0.75


def test_applies_zero_without_enumerated_users() -> None:
    """No USER nodes → this tool is irrelevant (agent doesn't guess, registry ranks)."""
    tool = UserDerivedCredsTool(graph_store=_FakeGraph([]))
    assert tool.applies_to(_ctx()) == 0.0


def test_applies_low_when_credential_already_harvested() -> None:
    """A harvested credential outranks guessing — cred_reuse takes over."""
    tool = UserDerivedCredsTool(graph_store=_FakeGraph(["admin"]))
    assert tool.applies_to(_ctx(prior=("credential leaked",))) == 0.1


# ── run(): compose derived candidates through the governed applicator roster ─────

_BUDGET = ResourceBudget(max_requests=50, max_seconds=5, max_cost_usd=0.0)


class _FakeApplicator:
    """Records every (username, password) that reaches the wire; 'succeeds' only for
    the pairs in *wins*."""

    def __init__(self, wins: set[tuple[str, str]]) -> None:
        self.wins = wins
        self.calls: list[tuple[str, str]] = []

    def applies_to(self, credential_service: str, target: str) -> bool:  # noqa: ARG002
        return True

    def apply(self, *, username: str, secret: str, target: str, budget: Any) -> AuthResult:  # noqa: ARG002
        self.calls.append((username, secret))
        ok = (username, secret) in self.wins
        return AuthResult(
            success=ok,
            access_level="admin" if ok else "",
            service="http",
            confidence=0.9 if ok else 0.0,
            proof_request={},
            proof_response={},
            session_cookie_name="session" if ok else None,
        )


class _FakeBound:
    def __init__(self, applicator: Any, target: str) -> None:
        self.applicator = applicator
        self.target = target


def _tool(users: list[str], applicator: Any) -> UserDerivedCredsTool:
    return UserDerivedCredsTool(
        graph_store=_FakeGraph(users),
        http_client=object(),  # non-None; wire is the fake applicator
        applicators=[_FakeBound(applicator, "https://bernofarm.com")],
    )


def test_run_returns_predictable_credential_finding_on_success() -> None:
    """A derived guess that works yields a success ToolResult tagged
    finding_class='predictable_credential' (so Beta.step mints the accurate node)."""
    app = _FakeApplicator(wins={("editor", "editor123")})
    result = _tool(["editor"], app).run(_ctx(), _BUDGET)

    assert result.success is True
    finding = result.findings[0]
    assert finding["username"] == "editor"
    assert finding["password"] == "editor123"
    assert finding["access_level"] == "admin"
    assert finding["finding_class"] == "predictable_credential"


def test_run_only_tries_derived_candidates_no_spray() -> None:
    """Every submission is a context-derived candidate — no external wordlist, bounded
    to the 4 derivations of the username + domain stem."""
    app = _FakeApplicator(wins=set())  # nothing works → exhausts the derived set
    _tool(["editor"], app).run(_ctx(), _BUDGET)

    tried = {pw for _, pw in app.calls}
    assert tried <= {"editor", "editor123", "bernofarm", "bernofarm123"}
    assert all(u == "editor" for u, _ in app.calls)


def test_run_no_enumerated_users_is_failure() -> None:
    """Without USER nodes the tool has no input — honest failure, no wire touched."""
    app = _FakeApplicator(wins=set())
    result = _tool([], app).run(_ctx(), _BUDGET)
    assert result.success is False
    assert app.calls == []


def test_run_never_submits_on_ungoverned_wire() -> None:
    """Safety: with NO governed applicator injected, nothing is submitted — derived
    guessing must never run off an ungoverned wire (no standalone fallback)."""
    tool = UserDerivedCredsTool(
        graph_store=_FakeGraph(["editor"]), http_client=object(), applicators=[]
    )
    result = tool.run(_ctx(), _BUDGET)
    assert result.success is False
