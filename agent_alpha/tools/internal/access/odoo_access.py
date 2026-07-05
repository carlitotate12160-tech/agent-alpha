# agent_alpha/tools/internal/access/odoo_access.py
"""odoo_access — internal Beta (STRIKE) tool: validate credentials against an
Odoo application over XML-RPC. Phase 4 (Odoo breadth arc, slice 1c), trimmed-internal.

This is the THIRD real access tool. Alongside cred_reuse + default_creds it is what
finally exercises ``ToolRegistry.ranked`` with a genuinely different fingerprint:
Odoo speaks XML-RPC (POST XML to ``/xmlrpc/2/common``/``/xmlrpc/2/db``), NOT an HTML
form login — so it is not a duplicate of default_creds' form-POST body (#6).

Proof model (READ BEFORE EDITING — this is the tier boundary):
  * The ONLY thing this tool proves is a VALID application credential, via a
    NON-DESTRUCTIVE signal: ``authenticate(db, login, password)`` returns an integer
    ``uid`` on success, ``False`` on failure. Reaching the wire is required (anti-#3:
    no proof-theatre), but nothing on the target changes.
  * required_auth = ACTIVE_APPROVED (initial access, not offensive). The run() body
    MUST NOT invoke any state-changing DB-manager action (create / duplicate / backup
    / restore / drop) and MUST NOT attempt the master-password. Those are DESTRUCTIVE,
    they require OFFENSIVE_APPROVED + blast-radius + human approval (Gamma/ANCHOR), and
    they are a SEPARATE slice — building them here would be a false-tier (#3) and would
    cross the Conductor's offensive gate. A `uid` is the ceiling of this tool.

Boundary (model routing, §12.15):
  * Claude owns: name / phase / required_auth / mitre_technique, applies_to(), the
    injected-deps shape, and the ToolResult finding contract below. All non-offensive.
  * Offensive-body author (DeepSeek — K21 lane, NOT Claude) owns: run() — discover the
    database (XML-RPC ``db.list()`` when list_db is on, else the ctx-supplied db),
    apply each candidate credential via ``authenticate``, VERIFY on a real integer uid,
    return CONTENT. NotImplementedError until authored.

Conforms to agent_alpha.tools.contracts.Tool (single canonical contract, #6). Returns
CONTENT, not refs — Beta.step() is the single persistence owner and mints retrievable
refs + REDACTS (scout/Laravel #45 pattern). The raw password is never re-exposed.

run() finding shape (on success):
    {
      "database": str,                 # the Odoo db the credential authenticated against
      "username": str,                 # login that authenticated
      "uid": int,                      # Odoo user id returned by authenticate (> 0)
      "access_level": "user" | "admin",# admin iff uid resolves to an admin group
      "credential_source": "default" | "reused",  # default dict vs Alpha-harvested
      "credential_node_id": str | None,# CREDENTIAL node id when source == "reused" (edge src)
      "proof_request": dict,           # safe fields only: endpoint + method + db + login
      "proof_response": dict,          # safe fields only: uid + server_version; NO secrets
    }
"""

from __future__ import annotations

from typing import Any

from agent_alpha.tools.contracts import ResourceBudget, TargetContext, ToolResult

# ── Single-source markers for THIS tool (defined once; not a #7 dup) ───────
# An Odoo target is the trigger. Mirrors the recon probe's fingerprint vocab
# without importing it (that module is RECON-tier; this is an ACCESS tool).
_ODOO_TECH_MARKERS: tuple[str, ...] = ("odoo",)

# XML-RPC surfaces the offensive body speaks to (data, not logic — single source).
ODOO_XMLRPC_COMMON_PATH = "/xmlrpc/2/common"
ODOO_XMLRPC_DB_PATH = "/xmlrpc/2/db"


def _is_odoo(ctx: TargetContext) -> bool:
    """True when the projected tech_stack fingerprints Odoo (asset tech_stack=['odoo']
    from the recon probe → projected into ctx.tech_stack)."""
    tech_blob = " ".join(ctx.tech_stack.values()).lower()
    return any(marker in tech_blob for marker in _ODOO_TECH_MARKERS)


def _odoo_access_already_proven(ctx: TargetContext) -> bool:
    """True when a prior finding already established Odoo access — don't re-auth."""
    return any("odoo" in f.lower() and "uid" in f.lower() for f in ctx.prior_findings)


class OdooAccessTool:
    """Validate application credentials against an Odoo target over XML-RPC."""

    name = "odoo_access"
    phase = "access"
    required_auth = "ACTIVE_APPROVED"
    # Valid Accounts (parent): the credential source is mixed — default Odoo logins
    # AND Alpha-harvested creds — and the novelty is the XML-RPC application surface,
    # not the account *type*. A single technique id for this tool (anti-#7).
    mitre_technique = "T1078"

    def __init__(
        self,
        *,
        http_client: Any = None,
        graph_store: Any = None,
        secrets_manager: Any = None,
    ) -> None:
        # Injected so run() can reach the wire + resolve reused creds. None is allowed
        # for applies_to()/conformance use; run() requires a real http_client.
        self._http_client = http_client
        self._graph_store = graph_store
        self._secrets_manager = secrets_manager

    def applies_to(self, ctx: TargetContext) -> float:
        """Relevance 0..1 from context — the registry ranks, the agent never guesses
        (K11). High on an Odoo target (this is THE Odoo-specific access vector, ranked
        above the generic default_creds form-POST there); minimal off-Odoo (so on a
        non-Odoo target the registry keeps default_creds/cred_reuse ahead of it);
        near-zero once Odoo access is already proven."""
        if not _is_odoo(ctx):
            return 0.15
        if _odoo_access_already_proven(ctx):
            return 0.1
        return 0.85

    def run(self, ctx: TargetContext, budget: ResourceBudget) -> ToolResult:
        """OFFENSIVE BODY — DeepSeek (K21 lane, NOT Claude).

        Validate application credentials against the Odoo target over XML-RPC:

          1. DISCOVER the database. If ``db.list()`` (POST XML to ODOO_XMLRPC_DB_PATH)
             is enabled, enumerate; otherwise use a ctx-supplied / single db. Never
             assume — an empty/failed list is a failure, not a silent success (#3).
          2. APPLY each candidate credential via ``authenticate(db, login, password)``
             (POST XML to ODOO_XMLRPC_COMMON_PATH). Candidates = built-in Odoo defaults
             (e.g. admin/admin) AND — when graph_store holds CREDENTIAL nodes — creds
             resolved from the vault via secrets_manager.retrieve(). Stay within
             ``budget.max_requests``.
          3. VERIFY on a real integer ``uid`` (> 0). ``False``/``0``/fault → not access.
             This is the ONLY proof; do NOT call any DB-manager create/duplicate/backup/
             restore/drop action and do NOT attempt the master password — those exceed
             required_auth (ACTIVE_APPROVED) and are a separate OFFENSIVE slice.
          4. Return CONTENT per the module-docstring finding shape (raw password NEVER
             returned). Beta.step() persists + mints refs + redacts.

        success=True only on a verified uid; otherwise ToolResult(success=False).
        """
        if self._http_client is None:
            raise ValueError("OdooAccessTool.run requires an injected http_client")
        raise NotImplementedError(
            "OdooAccessTool.run offensive body is authored by DeepSeek (K21 lane), "
            "not Claude — see the run() docstring spec above."
        )
