"""Slice-B: SpaLoginApplicator — JSON-API login reuse (offensive body, DeepSeek lane).

Hardened per CodeRabbit PR#402 review:
  * #2 HTTPS-ONLY: refuses any non-https login/protected URL (no cleartext creds/token).
  * #3 SINGLE login POST per apply() — deterministic body shape by username form — so the
    engagement lockout governor's per-attempt budget is not silently doubled.
  * #4 cross-verify requires STRICT 2xx on the Bearer replay (not merely non-401/403) AND
    a body that differs from the unauthenticated baseline.
  * #5 replay_body_excerpt is redacted at the source; the raw secret/token never appear.

success=True ONLY when cross_verified (Independent Verification Axiom). Token presence
alone is INSUFFICIENT (anti-#3 cardinal). required_auth=ACTIVE_APPROVED — the Conductor
factory gate enforces the tier; the login_url is resolved by recon/login_endpoints.py.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from agent_alpha.llm.redaction import redact_secrets
from agent_alpha.tools.contracts import ResourceBudget
from agent_alpha.tools.internal.access.applicator import AuthResult

_PROOF_BODY_LIMIT = 500
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_TOKEN_KEYS: tuple[str, ...] = ("access_token", "accessToken", "id_token", "jwt", "token")
_ADMIN_MARKERS: tuple[str, ...] = ("admin", "administrator")
_DEFAULT_PROTECTED_PATH = "/api/me"


def _extract_jwt(body: dict[str, Any]) -> tuple[str | None, str]:
    """Return (token, key) — first JWT-shaped value under a known token key, else (None,'')."""
    for key in _TOKEN_KEYS:
        value = body.get(key)
        if isinstance(value, str) and _JWT_RE.match(value.strip()):
            return value.strip(), key
    return None, ""


class SpaLoginApplicator:
    """Apply a harvested credential against a SPA's JSON login API (cross-verified)."""

    service = "spa"
    required_auth = "ACTIVE_APPROVED"

    def __init__(
        self, *, http_client: Any, login_url: str, protected_url: str | None = None
    ) -> None:
        self._http = http_client
        self._login_url = login_url  # the strike target (https, from the read-model)
        self._protected_url = protected_url  # cross-verify oracle (https or None)

    def applies_to(self, credential_service: str, target: str) -> bool:  # noqa: ARG002
        # Only runs when a login endpoint was resolved AND it is https (#2).
        return (
            credential_service in ("", "http", "https")
            and isinstance(self._login_url, str)
            and self._login_url.startswith("https://")
        )

    def apply(
        self, *, username: str, secret: str, target: str, budget: ResourceBudget
    ) -> AuthResult:  # noqa: ARG002
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

        login_url = self._login_url
        if not login_url.startswith("https://"):  # #2 fail-closed
            return _fail("refuse: login endpoint is not https (cleartext)")

        origin = f"https://{urlparse(login_url).netloc}"
        protected_url = self._protected_url
        if not protected_url or not protected_url.startswith("https://"):
            protected_url = origin + _DEFAULT_PROTECTED_PATH

        try:
            baseline = self._http.get(protected_url)
        except Exception:  # noqa: BLE001
            return _fail("baseline GET of protected_url failed")

        # #3 SINGLE POST — shape chosen deterministically by username form.
        is_email = "@" in username
        key_name = "email" if is_email else "username"
        body = {key_name: username, "password": secret}
        try:
            resp = self._http.post(login_url, json=body)
        except Exception:  # noqa: BLE001
            return _fail("login POST failed")
        login_status = getattr(resp, "status_code", 0)
        if not (200 <= login_status < 300):
            return _fail(f"login returned non-2xx ({login_status})")
        try:
            json_body = resp.json() if hasattr(resp, "json") else {}
        except Exception:  # noqa: BLE001
            return _fail("login response is not JSON")
        if not isinstance(json_body, dict):
            return _fail("login response JSON is not an object")
        token, token_key = _extract_jwt(json_body)
        if not token:
            return _fail(f"no JWT-shaped token in login response (key form: {key_name})")

        # #4 cross-verify: STRICT 2xx + body differs from unauthenticated baseline.
        try:
            authed = self._http.get(protected_url, headers={"Authorization": f"Bearer {token}"})
        except Exception:  # noqa: BLE001
            return _fail("Bearer replay against protected_url failed")
        authed_status = getattr(authed, "status_code", 0)
        if not (200 <= authed_status < 300):
            return _fail(
                f"cross-verify failed: protected_url returned {authed_status} "
                "(token presence does NOT imply access)"
            )
        authed_body = authed.text or ""
        if authed_body == (baseline.text or ""):
            return _fail("cross-verify failed: authed body == unauthenticated baseline")

        access_level = "admin" if any(m in authed_body.lower() for m in _ADMIN_MARKERS) else "user"
        return AuthResult(
            success=True,
            access_level=access_level,
            service=self.service,
            confidence=0.85,
            proof_request={
                "method": "POST",
                "url": login_url,
                "data_keys": [key_name, "password"],  # never the raw secret
                "content_type": "application/json",
            },
            proof_response={
                "login_status_code": login_status,
                "bearer_header_name": "Authorization",  # #5 never the token value
                "protected_url": protected_url,
                "replay_status_code": authed_status,
                # #5: explicitly strip the KNOWN bearer token (redact_secrets alone does
                # not recognise an arbitrary JWT), THEN generic-redact other secrets.
                "replay_body_excerpt": redact_secrets(
                    authed_body[:_PROOF_BODY_LIMIT].replace(token, "<redacted-bearer-token>")
                ),
                "token_key_found": token_key,
            },
        )
