# agent_alpha/tools/internal/access/applicator.py
"""CredentialApplicator seam — "apply a harvested secret against a service".

Phase-3 Step 1 (Claude lane, non-offensive). cred_reuse.run was HTTP-shaped: it
embedded form-login transport directly. Adding a DB transport inside it would make a
two-transport god-tool (Lyndon #10/#4/#8). This seam splits "WHICH credential to try /
where it came from" (cred_reuse orchestration) from "HOW to apply it to a given service"
(an applicator). One concept per applicator; selection by service.

* Claude owns: this protocol, AuthResult, select_applicator, and HttpFormApplicator
  (a behaviour-preserving EXTRACTION of the already-proven form-login path — NOT a new
  offensive body).
* OFFENSIVE bodies (e.g. MySqlApplicator.apply connecting to 3306 and proving data
  access) → GLM/Kimi, in their own modules, conforming to this protocol. They declare
  required_auth="OFFENSIVE_APPROVED"; the Conductor scope gate (Step 4) enforces it.

Invariant: an AuthResult NEVER carries the raw secret. proof_request/proof_response hold
safe fields only (data_keys / header_names / bounded body excerpts); Beta.step still
deep-redacts before persisting.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Protocol, runtime_checkable

from agent_alpha.tools.contracts import ResourceBudget
from agent_alpha.tools.internal.access.default_creds import (
    _has_positive_auth_signal,
    _parse_set_cookie,
)

_PROOF_BODY_LIMIT = 500


@dataclasses.dataclass(frozen=True)
class AuthResult:
    """Outcome of applying one credential against one service.

    ``success`` means VERIFIED access (a positive auth signal was observed), never
    merely "the request did not raise" (anti-Lyndon #3). Carries only safe proof
    fields — the raw secret is never included.
    """

    success: bool
    access_level: str  # "" | "user" | "admin" | "db_user" | "db_root"
    service: str  # "http" | "mysql" | ...
    confidence: float
    proof_request: dict[str, Any]
    proof_response: dict[str, Any]
    session_cookie_name: str | None = None
    error: str = ""


@runtime_checkable
class CredentialApplicator(Protocol):
    """Applies a harvested secret against a specific service and verifies access."""

    service: str
    required_auth: str

    def applies_to(self, credential_service: str, target: str) -> bool:
        """True when this applicator should handle a credential of
        ``credential_service`` against ``target``."""
        ...

    def apply(
        self, *, username: str, secret: str, target: str, budget: ResourceBudget
    ) -> AuthResult:
        """Apply (username, secret) to ``target``; return a verified AuthResult.

        success=True ONLY on a confirmed positive auth signal. Never return the raw
        secret in the result."""
        ...


def select_applicator(
    applicators: list[CredentialApplicator],
    *,
    credential_service: str,
    target: str,
) -> CredentialApplicator | None:
    """Return the first applicator that handles ``credential_service`` for ``target``,
    or ``None`` when no transport matches (caller skips the credential)."""
    for applicator in applicators:
        if applicator.applies_to(credential_service, target):
            return applicator
    return None


class HttpFormApplicator(CredentialApplicator):
    """Reuse a credential against an HTTP form login.

    Behaviour-preserving extraction of the proven cred_reuse form-login path:
    baseline GET -> POST {username, password} -> positive-auth-signal check ->
    optional session-cookie confirm -> access-level classification. Web-login reuse
    is an ACTIVE_APPROVED action (not the more invasive direct-DB tier).
    """

    service = "http"
    required_auth = "ACTIVE_APPROVED"

    def __init__(self, *, http_client: Any) -> None:
        self._http_client = http_client

    def applies_to(self, credential_service: str, target: str) -> bool:
        # HTTP is the default web transport: handle http creds and http(s) targets.
        return credential_service in ("", "http", "https") or target.startswith("http")

    def apply(
        self, *, username: str, secret: str, target: str, budget: ResourceBudget
    ) -> AuthResult:
        def _fail(error: str) -> AuthResult:
            return AuthResult(
                success=False,
                access_level="",
                service=self.service,
                confidence=0.0,
                proof_request={},
                proof_response={},
                error=error,
            )

        # ── Baseline (unauthenticated GET) ──────────────────────────
        try:
            baseline = self._http_client.get(target)
        except Exception:
            return _fail("baseline request failed")

        # ── APPLY the credential via POST — it MUST reach the wire ──
        try:
            auth_resp = self._http_client.post(
                target, data={"username": username, "password": secret}
            )
        except Exception:
            return _fail("auth request failed")

        # ── VERIFY: a positive auth signal is required ──────────────
        if not _has_positive_auth_signal(auth_resp, baseline):
            return _fail("no positive auth signal")

        # ── Confirm via session cookie (if one was issued) ──────────
        set_cookie = auth_resp.headers.get("set-cookie", "")
        cookies = _parse_set_cookie(set_cookie)
        confirm_resp = auth_resp  # fallback: redirect / form-gone signalled access
        if cookies:
            try:
                confirm_resp = self._http_client.get(target, cookies=cookies)
            except Exception:
                return _fail("confirm request failed")
            if confirm_resp.text == baseline.text:
                return _fail("confirm response matched unauthenticated baseline")

        # ── Access verified — classify level ────────────────────────
        body_lower = (confirm_resp.text or "").lower()
        access_level = (
            "admin" if ("admin" in body_lower or "administrator" in body_lower) else "user"
        )

        # ── Session cookie NAME only (never the value) ──────────────
        session_cookie_name: str | None = None
        if set_cookie:
            first_part = set_cookie.split(";", 1)[0].strip()
            if "=" in first_part:
                session_cookie_name = first_part.split("=", 1)[0].strip()

        return AuthResult(
            success=True,
            access_level=access_level,
            service=self.service,
            confidence=0.9,
            proof_request={
                "method": "POST",
                "url": target,
                "data_keys": ["username", "password"],
            },
            proof_response={
                "status_code": auth_resp.status_code,
                "header_names": list(auth_resp.headers.keys()),
                "body_excerpt": (auth_resp.text or "")[:_PROOF_BODY_LIMIT],
                "confirm_status_code": confirm_resp.status_code,
                "confirm_body_excerpt": (confirm_resp.text or "")[:_PROOF_BODY_LIMIT],
            },
            session_cookie_name=session_cookie_name,
        )


class WpLoginApplicator(CredentialApplicator):
    """WordPress-aware login reuse — POSTs log/pwd (not username/password) to wp-login.php
    and verifies success via 302→/wp-admin/ redirect or wordpress_logged_in_* cookie.

    Sibling to HttpFormApplicator (same CredentialApplicator seam, same service/tier).
    Does NOT modify HttpFormApplicator (#6). Success = real WP auth signal, NOT body-diff (#3).
    """

    service = "http"
    required_auth = "ACTIVE_APPROVED"

    def __init__(self, *, http_client: Any) -> None:
        self._http_client = http_client

    def applies_to(self, credential_service: str, target: str) -> bool:
        return target.rstrip("/").endswith("wp-login.php")

    def apply(
        self, *, username: str, secret: str, target: str, budget: ResourceBudget
    ) -> AuthResult:
        def _fail(error: str) -> AuthResult:
            return AuthResult(
                success=False,
                access_level="",
                service=self.service,
                confidence=0.0,
                proof_request={},
                proof_response={},
                error=error,
            )

        if not username:
            return _fail("refusing empty-username WP login (fragment node, not a login credential)")

        # ── Baseline GET (capture any Set-Cookie / wordpress_test_cookie flow) ──
        try:
            self._http_client.get(target)
        except Exception:
            return _fail("baseline request failed")

        # ── POST with WordPress field names (log/pwd, NOT username/password) ────
        origin = target.rsplit("/", 3)[0]  # https://host from https://host/wp-login.php
        cookies = {"wordpress_test_cookie": "WP Cookie check"}
        try:
            resp = self._http_client.post(
                target,
                data={
                    "log": username,
                    "pwd": secret,
                    "wp-submit": "Log In",
                    "redirect_to": f"{origin}/wp-admin/",
                    "testcookie": "1",
                },
                cookies=cookies,
            )
        except Exception:
            return _fail("auth request failed")

        # ── VERIFY: 302→/wp-admin/ OR wordpress_logged_in cookie (NOT body-diff) ──
        status = resp.status_code
        location = resp.headers.get("location", "")
        set_cookie = resp.headers.get("set-cookie", "")

        is_redirect_to_admin = status in (301, 302, 303) and "/wp-admin" in location
        has_login_cookie = "wordpress_logged_in" in set_cookie

        if not (is_redirect_to_admin or has_login_cookie):
            return _fail("no WP auth signal (no wp-admin redirect, no wordpress_logged_in cookie)")

        # ── Session cookie NAME only (never the value) ──────────────────────────
        session_cookie_name: str | None = None
        if "wordpress_logged_in" in set_cookie:
            first_part = set_cookie.split(";", 1)[0].strip()
            if "=" in first_part:
                session_cookie_name = first_part.split("=", 1)[0].strip()

        # TODO: refine user-vs-admin via a capability probe (GET /wp-admin/ with session).
        # For now, wp-login success grants dashboard access → "admin".
        return AuthResult(
            success=True,
            access_level="admin",
            service=self.service,
            confidence=0.9,
            proof_request={
                "method": "POST",
                "url": target,
                "data_keys": ["log", "pwd", "wp-submit", "redirect_to", "testcookie"],
            },
            proof_response={
                "status_code": status,
                "location_path": location,
                "header_names": list(resp.headers.keys()),
            },
            session_cookie_name=session_cookie_name,
        )
