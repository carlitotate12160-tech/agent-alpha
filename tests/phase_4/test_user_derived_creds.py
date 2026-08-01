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
from agent_alpha.tools.contracts import TargetContext
from agent_alpha.tools.internal.access import user_derived_creds as mod
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
