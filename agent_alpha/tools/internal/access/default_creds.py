# agent_alpha/tools/internal/access/default_creds.py
"""default_creds — internal Beta (STRIKE) tool: check KNOWN DEFAULT credentials
against a detected auth surface. Phase 3, trimmed-internal (tool #2).

This is Beta.step()'s ACT: Beta delegates initial access to this tool rather
than carrying credential logic in the agent (one credential-attack body, one
place — anti-Lyndon #6). It tries a built-in default-credential dictionary
(admin/admin, root/root, per platform) — NOT recon-harvested credentials;
cred-reuse over harvested CredentialProperties is a SEPARATE later tool.

Boundary (READ BEFORE EDITING):
  * Claude owns: name / phase / required_auth, applies_to(), the injected-deps
    shape, and the ToolResult finding contract below. All non-offensive.
  * Offensive-body author (GLM 5.2 High — NOT Claude) owns: run() — apply each
    default credential via form POST, verify with a positive auth signal
    (session cookie / redirect / login-form gone), confirm via session cookie.
    Returns CONTENT, not refs — Beta.step() is the single persistence owner
    and mints retrievable refs from the content (scout/Laravel #45 pattern).

Conforms to agent_alpha.tools.contracts.Tool (single canonical contract, #6).
required_auth = ACTIVE_APPROVED: an active auth attempt, never recon — the
Conductor/agent gate enforces the tier; the tool only DECLARES it.

run() returns a ToolResult whose findings (on success) carry raw content for
Beta.step() to persist + mint refs:
    {
      "username": str,                     # the default username that worked
      "password": str,                     # public default password (not a secret)
      "access_level": "user" | "admin",
      "proof_request": dict,               # raw POST request metadata
      "proof_response": dict,              # raw authed response metadata
      "session_cookie_name": str | None,   # the name of the session cookie if issued
    }
The tool never writes to any store. Beta.step() redacts + persists.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from agent_alpha.config import constants
from agent_alpha.tools.contracts import ResourceBudget, TargetContext, ToolResult


def _cookie_name_only(set_cookie: str) -> str:
    if not set_cookie:
        return ""
    first_part = set_cookie.split(";", 1)[0].strip()
    if "=" not in first_part:
        return first_part or ""
    return first_part.split("=", 1)[0].strip()


# Signals that an authenticated surface worth a default-cred check exists.
_AUTH_PORTS = frozenset({21, 22, 3306, 3389, 5432, 5900})
_AUTH_TECH_HINTS = (constants.STACK_WP, "joomla", "phpmyadmin", "tomcat", "jenkins", "grafana")

# ── Data-driven default credential dictionary (data, not logic) ────────────
# Keyed by platform; "generic" always included. Per-platform entries selected
# from ctx.tech_stack.  Public knowledge — not secrets.
_DEFAULT_CREDENTIALS: dict[str, list[tuple[str, str]]] = {
    "generic": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "admin123"),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
        ("user", "user"),
        ("guest", "guest"),
    ],
    constants.STACK_WP: [
        ("admin", "admin"),
        ("admin", "password"),
    ],
    "tomcat": [
        ("tomcat", "tomcat"),
        ("admin", "admin"),
        ("manager", "manager"),
    ],
    "jenkins": [
        ("admin", "admin"),
    ],
    "phpmyadmin": [
        ("root", ""),
        ("root", "root"),
    ],
    "grafana": [
        ("admin", "admin"),
    ],
    "joomla": [
        ("admin", "admin"),
    ],
}


def _build_credential_list(tech_stack: dict[str, str]) -> list[tuple[str, str]]:
    """Assemble a deduplicated credential list: generic + platform-specific."""
    creds: list[tuple[str, str]] = list(_DEFAULT_CREDENTIALS["generic"])
    tech_blob = " ".join(tech_stack.values()).lower()
    for platform, platform_creds in _DEFAULT_CREDENTIALS.items():
        if platform != "generic" and platform in tech_blob:
            creds.extend(platform_creds)
    # Deduplicate, preserving order.
    return list(dict.fromkeys(creds))


def _parse_set_cookie(header: str) -> dict[str, str]:
    """Extract cookie name=value from a Set-Cookie header value.

    Handles the common format: ``name=value; Path=/; HttpOnly``.
    Returns an empty dict if the header is empty or unparseable.
    """
    if not header:
        return {}
    first_part = header.split(";", 1)[0].strip()
    if "=" not in first_part:
        return {}
    name, value = first_part.split("=", 1)
    return {name.strip(): value.strip()}


def _has_login_form(text: str) -> bool:
    """Heuristic: the page contains a password input (login form present)."""
    lower = (text or "").lower()
    return 'type="password"' in lower or "type='password'" in lower


@dataclasses.dataclass(frozen=True)
class _LocalBound:
    """Fallback bound-applicator shape for callers that construct this tool
    standalone (no injected roster) — same duck-typed (applicator, target)
    shape as conductor.applicator_factory.BoundApplicator, defined locally
    to avoid importing conductor/ from tools/ (layering: tools never import
    conductor)."""

    applicator: Any
    target: str


# Session cookie allowlist (SSOT, anti-#7)
SESSION_COOKIE_NAMES = frozenset(
    {"session_id", "sessionid", "sid", "session", "auth", "token", "connect.sid"}
)


def _has_positive_auth_signal(
    auth_resp: Any,
    baseline_resp: Any,
) -> bool:
    """Return True only when the auth response carries a POSITIVE authentication
    signal — not merely 'text differs from baseline' (a failed-login error page
    also differs and must NOT be treated as access).

    Positive signals:
      1. A session cookie was issued (Set-Cookie header present).
      2. A redirect into an authenticated area (301/302).
      3. The login form disappeared (baseline had a password field, response does not).
    """
    # 1. STATUS GATE first: an error status is a rejection, never access.
    #    (e.g., Odoo 400 Bad Request still sets frontend_lang).
    if auth_resp.status_code >= 400:
        return False

    # Signal 1: session cookie issued.
    #   Odoo sets frontend_lang (language cookie) on EVERY response.
    #   We enforce a default-deny allowlist based on cookie NAME so
    #   non-auth cookies (frontend_lang, csrf, lang, locale, _ga) are ignored.
    set_cookie = auth_resp.headers.get("set-cookie")
    if set_cookie:
        cookie_name = _cookie_name_only(set_cookie).lower()
        if cookie_name in SESSION_COOKIE_NAMES:
            return True

    # Signal 2: redirect to authenticated area.
    if auth_resp.status_code in (301, 302):
        return True
    # Signal 3: login form disappeared.
    if _has_login_form(baseline_resp.text) and not _has_login_form(auth_resp.text):
        return True
    return False


class DefaultCredsTool:
    """Default-credential check across a detected auth surface."""

    name = "default_creds"
    phase = "access"
    required_auth = "ACTIVE_APPROVED"
    mitre_technique = "T1078.001"  # Valid Accounts: Default Accounts (built-in admin/admin)

    def __init__(
        self,
        *,
        applicators: list[Any] | None = None,
        http_client: Any = None,
    ) -> None:
        # Injected so run() can reach the wire (Tool.run(ctx, budget) carries no
        # transport). None is allowed for applies_to()/conformance use; run()
        # requires a real client.
        self._http_client = http_client
        # Engagement-scoped roster from conductor.applicator_factory (same one
        # cred_reuse uses — #6, one credential-application transport). None/[]
        # falls back to a bare HttpFormApplicator bound to ctx.target (see
        # run()) so standalone/unit-test construction keeps today's behaviour.
        self._applicators = applicators

    def applies_to(self, ctx: TargetContext) -> float:
        """Relevance 0..1 from context — registry ranks, agent doesn't guess (K11).
        High when an auth surface (auth ports or a known login platform) is present;
        minimal once credentials for this target already exist."""
        if any("credential" in f.lower() for f in ctx.prior_findings):
            return 0.1
        score = 0.2
        if set(ctx.open_ports) & _AUTH_PORTS:
            score = 0.7
        tech_blob = " ".join(ctx.tech_stack.values()).lower()
        if any(hint in tech_blob for hint in _AUTH_TECH_HINTS):
            score = max(score, 0.7)
        return score

    def run(self, ctx: TargetContext, budget: ResourceBudget) -> ToolResult:
        """Try each built-in default credential via the injected
        ``CredentialApplicator`` roster (WP-aware ``WpLoginApplicator`` +
        generic ``HttpFormApplicator``, same roster ``cred_reuse`` uses — one
        credential-application transport, #6). VERIFY is owned by the
        applicator (positive auth signal, never body-diff).

        Returns **content**, not refs — Beta.step() persists + mints refs.
        """
        if self._http_client is None:
            raise ValueError("DefaultCredsTool.run requires an injected http_client")

        # Deferred import: applicator.py imports FROM this module at top
        # level (_has_positive_auth_signal / _parse_set_cookie) — a top-level
        # import here would be circular. Safe at call time; both modules are
        # fully loaded by then.
        from agent_alpha.tools.internal.access.applicator import HttpFormApplicator

        creds = _build_credential_list(ctx.tech_stack)

        # Engagement-scoped roster (WP-specific tried before generic — opsec,
        # mirrors beta_web_applicators() ordering) when injected; otherwise a
        # single bare HttpFormApplicator bound to ctx.target (byte-for-byte
        # the prior standalone behaviour).
        bound_applicators = self._applicators or [
            _LocalBound(HttpFormApplicator(http_client=self._http_client), ctx.target)
        ]

        requests_used = 0
        for username, password in creds:
            if requests_used >= budget.max_requests:
                break

            result = None
            for bound in bound_applicators:
                if requests_used >= budget.max_requests:
                    break
                if not bound.applicator.applies_to("http", bound.target):
                    continue
                # APPLY the credential — it MUST reach the wire (anti-Lyndon
                # #3: no proof-theatre). Unguarded, matching cred_reuse.py's
                # own call to the same method: apply() already catches its
                # own expected (network/transport) failures internally and
                # returns AuthResult(success=False) — anything that still
                # raises here is a genuine bug and must propagate, not be
                # silently absorbed into "tried, no access" (which would be
                # indistinguishable from a real negative result).
                result = bound.applicator.apply(
                    username=username,
                    secret=password,
                    target=bound.target,
                    budget=budget,
                )
                requests_used += 3  # baseline + auth + confirm (upper bound)
                if result.success:
                    break

            if result is None or not result.success:
                continue

            # ── Access verified — build finding with raw content (tool
            #    returns content, Beta.step() persists + mints refs) ──────
            finding: dict[str, Any] = {
                "username": username,
                "password": password,  # public default, not a secret
                "access_level": result.access_level,
                "proof_request": result.proof_request,
                "proof_response": result.proof_response,
                "session_cookie_name": result.session_cookie_name,
            }

            return ToolResult(
                tool=self.name,
                success=True,
                confidence=result.confidence,
                findings=(finding,),
            )

        # ── No default credential produced a positive auth signal ───
        return ToolResult(
            tool=self.name,
            success=False,
            confidence=0.0,
            error="no default credential produced a positive auth signal",
        )
