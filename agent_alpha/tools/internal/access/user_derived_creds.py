# agent_alpha/tools/internal/access/user_derived_creds.py
"""user_derived_creds — internal Beta (STRIKE) tool: GAP-015, the Alpha→Beta moat.

Alpha enumerates usernames (e.g. WordPress REST slugs → USER nodes). This tool turns
each enumerated username into a SMALL, context-DERIVED set of login candidates and
proves reuse — "we enumerated 3 users, one reused <domain_stem>123, we reached admin".
That proven chain is what a scanner (Nuclei et al.) cannot assemble.

DERIVE-NOT-SPRAY (design contract, anti-Lyndon #4/#3, and Natanael's rule "no hardcoded
password lists"): candidates are derived ONLY from the username and the registrable
domain stem — NO static password ("password"/"admin123") lives here. Well-known defaults
are `default_creds`' job (separate tool, #6 no duplication). Bounded to
`USER_DERIVED_MAX_CANDIDATES_PER_USER` per account so there is no combinatorial blow-up.

SAFETY: every submission MUST pass the shared CredentialLockoutGovernor (§12.22 D2) so a
client's real accounts are never driven into lockout. required_auth = ACTIVE_APPROVED —
the Conductor gate enforces the tier; this tool only DECLARES it.

Boundary (READ BEFORE EDITING):
  * Claude owns: name / phase / required_auth / mitre, applies_to(), the injected-deps
    shape, and `derive_login_candidates()` (deterministic derivation — non-offensive).
  * Offensive-body author (GLM/DeepSeek — NOT Claude) owns: run() — for each USER node,
    apply each derived candidate via the injected CredentialApplicator roster, GATED by
    the GovernedApplicator seam (lockout-gated at the roster), verify with an INDEPENDENT
    signal (attestation, §12.43 — never body-diff self-report), return CONTENT.
    NotImplementedError until authored + wiring-debt registered.

Conforms to agent_alpha.tools.contracts.Tool (single canonical contract, #6).
"""

from __future__ import annotations

from typing import Any

from publicsuffix2 import get_sld

from agent_alpha.config import constants
from agent_alpha.graph.nodes import NodeType
from agent_alpha.tools.contracts import ResourceBudget, TargetContext, ToolResult


def _domain_stem(host: str) -> str:
    """Registrable-domain stem via the Public Suffix List (offline, deterministic).

    ``bernofarm.com`` → ``bernofarm``; ``www.foo.co.id`` → ``foo``;
    ``portal.acme.co.uk`` → ``acme``. Empty string for an empty/invalid host.
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""
    sld = get_sld(h) or h
    return sld.split(".")[0]


def derive_login_candidates(
    username: str,
    host: str,
    *,
    max_candidates: int = constants.USER_DERIVED_MAX_CANDIDATES_PER_USER,
) -> list[tuple[str, str]]:
    """Derive up to ``max_candidates`` ``(username, password)`` guesses for ONE
    enumerated account — context-derived only, NO static password, deduped, bounded.

    Password candidates, in priority order: the username itself, username+"123",
    the domain stem, the domain stem+"123". Duplicates (e.g. username == stem) collapse;
    empties drop. This is the whole candidate space per account — there is no wordlist
    file and no combinatorial expansion (derive-not-spray).
    """
    stem = _domain_stem(host)
    ordered = [username, f"{username}123", stem, f"{stem}123"]
    seen: set[str] = set()
    passwords: list[str] = []
    for pw in ordered:
        if pw and pw not in seen:
            seen.add(pw)
            passwords.append(pw)
    return [(username, pw) for pw in passwords[:max_candidates]]


class UserDerivedCredsTool:
    """Prove credential reuse from Alpha-enumerated usernames (GAP-015)."""

    name = "user_derived_creds"
    phase = "access"
    required_auth = "ACTIVE_APPROVED"
    mitre_technique = "T1110.001"  # Brute Force: Password Guessing (bounded, derived)

    def __init__(
        self,
        *,
        graph_store: Any = None,
        http_client: Any = None,
        applicators: list[Any] | None = None,
    ) -> None:
        self._graph_store = graph_store
        self._http_client = http_client
        self._applicators = applicators or []

    def applies_to(self, ctx: TargetContext) -> float:
        """High when Alpha has enumerated usernames (USER nodes) AND no harvested
        credential already exists (cred_reuse outranks this — real secret > guess).
        Zero without a graph or without enumerated users. Registry ranks, agent
        doesn't guess (K11)."""
        if self._graph_store is None:
            return 0.0
        if any("credential" in f.lower() for f in ctx.prior_findings):
            return 0.1
        users = self._graph_store.nodes_by_type(NodeType.USER)
        # 0.75: below cred_reuse (0.9, harvested secret), above blind default_creds
        # (0.7 auth-surface) — enumerated usernames make this MORE targeted than blind.
        return 0.75 if users else 0.0

    def run(self, ctx: TargetContext, budget: ResourceBudget) -> ToolResult:
        """OFFENSIVE body — GLM/DeepSeek lane, NotImplementedError until authored.

        Contract for the author: for each USER node, call
        ``derive_login_candidates(username, host)``; submit each via an injected
        CredentialApplicator — already GovernedApplicator-wrapped by the factory, so
        every submission is lockout-gated at the seam (§12.22 D2, no per-tool gate);
        VERIFY with an INDEPENDENT auth signal (attestation §12.43, not the tool's own
        self-report); return CONTENT (no raw secret), Beta.step persists + mints refs.
        """
        raise NotImplementedError(
            "user_derived_creds.run is the GLM/DeepSeek offensive lane; author the "
            "apply+attestation loop before wiring this into a live engagement "
            "(lockout is enforced at the GovernedApplicator seam)."
        )
