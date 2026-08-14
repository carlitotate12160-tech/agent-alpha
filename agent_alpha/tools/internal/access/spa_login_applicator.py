"""Slice-B: SpaLoginApplicator — JSON-API login reuse (DeepSeek/GLM offensive body).

Protocol lane boundary (§12.15):
  * Claude owns: class skeleton, service/required_auth, applies_to(), _PROOF_BODY_LIMIT,
    _JWT_RE, _TOKEN_KEYS, docstrings, test contract, and the _fail() helper shape.
  * GLM/DeepSeek owns: apply() — the two-stage offensive body (JSON POST → JWT extract
    → Bearer replay cross-verify). No HTML form POST, no cookie flow. Pure JSON-API.

Invariant (inherited from CredentialApplicator seam):
  * success=True ONLY when cross_verified (Bearer replay oracle differs from unauthenticated
    baseline AND is non-401/403). Token presence alone is INSUFFICIENT (anti-#3 cardinal).
  * AuthResult NEVER contains the raw secret or the raw token. proof_request/proof_response
    hold data_keys / header_names / bounded body excerpts only. Beta.step deep-redacts too.

Authorization tier: ACTIVE_APPROVED (web-login reuse, same as HttpFormApplicator). The
Conductor factory gate (build_applicators_for_engagement) enforces this — not this class.

Fail-closed contract:
  * No login endpoint resolved by the read-model → factory does NOT instantiate this class.
  * Exception in any stage / no token extracted / replay 401-403 → AuthResult(success=False).
  * protected_url=None → fall back to canonical me/user/profile probes before failing.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from agent_alpha.tools.contracts import ResourceBudget
from agent_alpha.tools.internal.access.applicator import AuthResult

# ── Proof body limit (shared constant, mirrors applicator.py) ────────────────
_PROOF_BODY_LIMIT = 500

# ── JWT shape detector (3-part base64url, per RFC 7519) ─────────────────────
# Matches header.payload.signature; used ONLY to confirm the token LOOKS like a JWT.
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

# ── Token keys (priority order: most specific first) ─────────────────────────
_TOKEN_KEYS: tuple[str, ...] = ("access_token", "accessToken", "id_token", "jwt", "token")

# ── Canonical protected-URL fallbacks when protected_url is not harvested ────
_PROTECTED_URL_PROBES: tuple[str, ...] = ("/api/me", "/api/user", "/api/profile")

# ── Admin markers (case-insensitive, checked against authed response body) ───
_ADMIN_MARKERS: frozenset[str] = frozenset({"admin", "administrator"})


def _extract_jwt(body: dict[str, Any]) -> str | None:
    """Extract a JWT-shaped token value from a JSON response body dict.

    Iterates ``_TOKEN_KEYS`` in priority order. Returns the first value that
    matches ``_JWT_RE`` (looks like a real JWT), or None when nothing found.
    Never raises: missing/wrong-type values are silently skipped.
    """
    for key in _TOKEN_KEYS:
        value = body.get(key)
        if isinstance(value, str) and _JWT_RE.match(value.strip()):
            return value.strip()
    return None


class SpaLoginApplicator:
    """Apply a harvested credential against a SPA's JSON login API.

    Two-stage cross-verified access probe:

    STAGE 1 — self_verified (WEAK):
        POST JSON body(ies) to ``target`` (the login endpoint resolved by the
        read-model). Extract a JWT from the 2xx JSON response under a recognised
        token key. No token found → FAIL immediately (no bearer to replay).

    STAGE 2 — cross_verified (REQUIRED for success=True):
        Replay ``Authorization: Bearer <token>`` against ``protected_url``.
        Success ONLY when:
          a. replay response is non-401/403, AND
          b. replay body DIFFERS from an unauthenticated baseline GET of the
             same protected_url (independent oracle — different failure mode
             from stage-1, per the Independent Verification Axiom).

    access_level: "admin" if admin/administrator markers found in the
    authenticated replay body; otherwise "user".

    Fail-closed in every branch: exception / no token / 401-replay → False.
    The raw secret and raw token NEVER appear in the returned AuthResult.
    """

    service = "spa"
    required_auth = "ACTIVE_APPROVED"

    def __init__(self, *, http_client: Any, protected_url: str | None = None) -> None:
        self._http_client = http_client
        self._protected_url = protected_url

    def applies_to(self, credential_service: str, target: str) -> bool:
        """True for http/https credentials against an http(s) target URL."""
        return credential_service in ("", "http", "https") and (
            target.startswith("http://") or target.startswith("https://")
        )

    def apply(
        self, *, username: str, secret: str, target: str, budget: ResourceBudget
    ) -> AuthResult:
        """Two-stage JSON-API login reuse. success=True ONLY on cross_verified."""

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

        # ── Resolve protected_url ───────────────────────────────────────────
        # Use harvested api_endpoint if available, else probe the canonical
        # fallback paths against the same scheme+host as the login target.
        parsed_target = urlparse(target)
        base_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

        if self._protected_url:
            protected_url = self._protected_url
        else:
            # Try each fallback probe; use the first one that returns non-401/403
            # to the unauthenticated baseline (i.e. the endpoint exists).
            protected_url = base_origin + _PROTECTED_URL_PROBES[0]
            for probe_path in _PROTECTED_URL_PROBES:
                probe = base_origin + probe_path
                try:
                    probe_resp = self._http_client.get(probe)
                    if probe_resp.status_code not in (404, 405, 410):
                        protected_url = probe
                        break
                except Exception:  # noqa: BLE001
                    continue

        # ── Unauthenticated baseline GET of protected_url (Stage-2 oracle) ──
        try:
            baseline = self._http_client.get(protected_url)
        except Exception:  # noqa: BLE001
            return _fail("baseline GET of protected_url failed")

        # ── STAGE 1: POST JSON → extract JWT ───────────────────────────────
        token: str | None = None
        matched_token_key: str = ""
        login_status: int = 0
        tried_bodies: list[str] = []

        body_shapes: list[dict[str, str]] = [
            {"email": username, "password": secret},
            {"username": username, "password": secret},
        ]

        for body_shape in body_shapes:
            key_name = "email" if "email" in body_shape else "username"
            tried_bodies.append(key_name)
            try:
                resp = self._http_client.post(target, json=body_shape)
            except Exception:  # noqa: BLE001
                continue

            login_status = resp.status_code

            if resp.status_code < 200 or resp.status_code >= 300:
                continue

            # Parse JSON body for a JWT-shaped token value
            try:
                json_body: dict[str, Any] = resp.json() if hasattr(resp, "json") else {}
            except Exception:  # noqa: BLE001
                continue

            token = _extract_jwt(json_body)
            if token:
                # Record which key held the token (safe metadata for proof)
                for tk in _TOKEN_KEYS:
                    v = json_body.get(tk)
                    if isinstance(v, str) and _JWT_RE.match(v.strip()):
                        matched_token_key = tk
                        break
                break  # Got a JWT — move to stage 2

        if not token:
            return _fail(
                f"no JWT-shaped token in 2xx JSON response "
                f"(tried body keys: {tried_bodies}; last status: {login_status})"
            )

        # ── STAGE 2: Bearer replay cross-verification ───────────────────────
        try:
            authed_resp = self._http_client.get(
                protected_url,
                headers={"Authorization": f"Bearer {token}"},
            )
        except Exception:  # noqa: BLE001
            return _fail("Bearer replay request against protected_url failed")

        authed_status = authed_resp.status_code
        authed_body = authed_resp.text or ""

        # a. Must not be 401/403 (token rejected)
        if authed_status in (401, 403):
            return _fail(
                f"cross-verify failed: protected_url returned {authed_status} "
                f"with Bearer token (token presence does NOT imply access)"
            )

        # b. Authed body MUST differ from unauthenticated baseline (independent oracle).
        baseline_body = baseline.text or ""
        if authed_body == baseline_body:
            return _fail(
                "cross-verify failed: authenticated response body matches "
                "unauthenticated baseline (no real access granted)"
            )

        # ── Cross-verified: classify access level ───────────────────────────
        authed_body_lower = authed_body.lower()
        access_level = (
            "admin" if any(marker in authed_body_lower for marker in _ADMIN_MARKERS) else "user"
        )

        return AuthResult(
            success=True,
            access_level=access_level,
            service=self.service,
            confidence=0.85,
            proof_request={
                "method": "POST",
                "url": target,
                # NEVER include the raw secret — data_keys only
                "data_keys": tried_bodies + ["password"],
                "content_type": "application/json",
            },
            proof_response={
                "login_status_code": login_status,
                # NEVER include the raw token — header_names only
                "bearer_header_name": "Authorization",
                "protected_url": protected_url,
                "replay_status_code": authed_status,
                "replay_body_excerpt": authed_body[:_PROOF_BODY_LIMIT],
                "baseline_status_code": baseline.status_code,
                # Safe metadata: which JSON key held the JWT (not the value)
                "token_key_found": matched_token_key,
            },
        )
