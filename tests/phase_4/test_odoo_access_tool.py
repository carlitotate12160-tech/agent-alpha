"""Contract: OdooAccessTool — validate Odoo credentials over XML-RPC (slice 1c).

Locks the NON-offensive surface (Claude's lane) before the body is written:
  * conforms to the canonical Tool protocol (no parallel type, #6)
  * phase=access + required_auth=ACTIVE_APPROVED (initial access, NOT offensive —
    the destructive master-password / DB-manager path is a separate OFFENSIVE slice)
  * applies_to() is HIGH on an Odoo target, LOW off-Odoo, near-zero once proven
  * run() requires an injected http_client (ValueError guard)

Slice-1c centrepiece — the DIFFERENTIAL that proves ToolRegistry.ranked orders by
CONTEXT (not a static sequence, K11): with three REAL tools registered, an Odoo
target ranks odoo_access first, while a non-Odoo auth surface ranks default_creds
ahead of it. This is the first time .ranked() is exercised by a genuine 3rd tool.

The single RED frontier is run()'s XML-RPC body (authenticate → uid) — DeepSeek's
K21 lane; its success/failure finding-shape tests land WITH that body (the
default_creds pattern), pinned by deepseek_prompt_odoo_access.md.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.tools.contracts import ResourceBudget, TargetContext, Tool
from agent_alpha.tools.internal.access.cred_reuse import CredReuseTool
from agent_alpha.tools.internal.access.default_creds import DefaultCredsTool
from agent_alpha.tools.internal.access.odoo_access import (
    ODOO_XMLRPC_COMMON_PATH,
    ODOO_XMLRPC_DB_PATH,
    JsonRpcOdooTransport,
    OdooAccessTool,
    OdooLoginResult,
    XmlRpcOdooTransport,
)
from agent_alpha.tools.registry import ToolRegistry


def _odoo_ctx(**overrides: object) -> TargetContext:
    defaults: dict[str, object] = {
        "engagement_id": "e",
        "tenant_id": None,
        "target": "https://odoo.lab-target.invalid",
        "tech_stack": {"framework": "Odoo 16.0"},
    }
    defaults.update(overrides)
    return TargetContext(**defaults)  # type: ignore[arg-type]


def _non_odoo_auth_ctx() -> TargetContext:
    return TargetContext(
        engagement_id="e",
        tenant_id=None,
        target="http://lab-target.invalid/wp-login.php",
        tech_stack={"cms": "WordPress 6.5"},
        open_ports=(22, 80),
    )


# ── A. Protocol conformance (no parallel type, #6) ───────────────


def test_conforms_to_canonical_tool_protocol() -> None:
    assert isinstance(OdooAccessTool(), Tool)


def test_declares_access_phase_and_active_tier() -> None:
    tool = OdooAccessTool()
    assert tool.phase == "access"
    # NOT OFFENSIVE_APPROVED — the destructive DB-manager/master-password path is a
    # separate slice; a uid over XML-RPC is non-destructive initial access.
    assert tool.required_auth == "ACTIVE_APPROVED"


# ── B. applies_to relevance scoring ──────────────────────────────


def test_applies_high_on_odoo_target() -> None:
    assert OdooAccessTool().applies_to(_odoo_ctx()) >= 0.8


def test_applies_low_off_odoo() -> None:
    assert OdooAccessTool().applies_to(_non_odoo_auth_ctx()) < 0.5


def test_applies_near_zero_when_access_already_proven() -> None:
    ctx = _odoo_ctx(prior_findings=("Odoo access via XML-RPC: uid=2 (admin)",))
    assert OdooAccessTool().applies_to(ctx) <= 0.15


# ── C. run() requires the injected transport ─────────────────────


def test_run_requires_http_client() -> None:
    budget = ResourceBudget(max_requests=20, max_seconds=30.0, max_cost_usd=0.0)
    with pytest.raises(ValueError, match="http_client"):
        OdooAccessTool().run(_odoo_ctx(), budget)


# ── D. ToolRegistry.ranked differential — the slice-1c centrepiece ─
#     Three REAL tools; ordering is a function of context, never static (K11).


def _three_tools() -> list[Tool]:
    return [
        CredReuseTool(graph_store=NetworkXGraphStore()),  # empty graph → low
        DefaultCredsTool(),
        OdooAccessTool(),
    ]


def test_ranked_puts_odoo_access_first_on_odoo_target() -> None:
    ranked = ToolRegistry(_three_tools()).ranked(_odoo_ctx())
    assert ranked[0].name == "odoo_access"


def test_ranked_prefers_default_creds_on_non_odoo_auth_surface() -> None:
    ranked = ToolRegistry(_three_tools()).ranked(_non_odoo_auth_ctx())
    names = [t.name for t in ranked]
    # Same three tools, different target → different order: this is the proof that
    # .ranked() is context-driven, not a fixed pipeline.
    assert names[0] == "default_creds"
    assert names.index("odoo_access") > names.index("default_creds")


# ── E. run() offensive body — XML-RPC credential validation ──────

from dataclasses import dataclass, field  # noqa: E402


@dataclass
class _FakeResp:
    status_code: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)


def _xmlrpc_response_int(value: int) -> str:
    return (
        '<?xml version="1.0"?>'
        "<methodResponse><params><param>"
        f"<value><int>{value}</int></value>"
        "</param></params></methodResponse>"
    )


def _xmlrpc_response_bool(value: bool) -> str:
    return (
        '<?xml version="1.0"?>'
        "<methodResponse><params><param>"
        f"<value><boolean>{1 if value else 0}</boolean></value>"
        "</param></params></methodResponse>"
    )


def _xmlrpc_response_list(items: list[str]) -> str:
    vals = "".join(f"<value><string>{d}</string></value>" for d in items)
    return (
        '<?xml version="1.0"?>'
        "<methodResponse><params><param>"
        f"<value><array><data>{vals}</data></array></value>"
        "</param></params></methodResponse>"
    )


def _xmlrpc_response_struct(d: dict[str, str]) -> str:
    members = "".join(
        f"<member><name>{k}</name><value><string>{v}</string></value></member>"
        for k, v in d.items()
    )
    return (
        '<?xml version="1.0"?>'
        "<methodResponse><params><param>"
        f"<value><struct>{members}</struct></value>"
        "</param></params></methodResponse>"
    )


def _xmlrpc_fault() -> str:
    return (
        '<?xml version="1.0"?>'
        "<methodResponse><fault><value><struct>"
        "<member><name>faultCode</name><value><int>1</int></value></member>"
        "<member><name>faultString</name><value><string>AccessDenied</string></value></member>"
        "</struct></value></fault></methodResponse>"
    )


class _FakeHttp:
    """Routes POST by URL substring to canned responses."""

    def __init__(self, routes: dict[str, _FakeResp]) -> None:
        self._routes = routes
        self.calls: list[str] = []

    def post(
        self,
        url: str,
        data: str = "",
        headers: dict | None = None,
        json_body: dict | None = None,
    ) -> _FakeResp:
        self.calls.append(url)
        for pattern, resp in self._routes.items():
            if pattern in url:
                return resp
        return _FakeResp(404, "Not Found")

    def get(self, url: str, **kw: Any) -> _FakeResp:
        return _FakeResp(404, "")


def _budget() -> ResourceBudget:
    return ResourceBudget(max_requests=20, max_seconds=30.0, max_cost_usd=0.0)


def test_run_success_admin_admin_returns_uid_and_access_level() -> None:
    """authenticate(admin/admin) → uid=2 → success, admin, default source, no password in proof."""
    db_resp = _FakeResp(200, _xmlrpc_response_list(["erp"]))
    auth_resp = _FakeResp(200, _xmlrpc_response_int(2))

    # version + authenticate both hit /xmlrpc/2/common; the fake can't split by
    # body, so it returns the uid response for all common calls (server_version
    # simply projects through as None — the proof shape stays valid).
    http = _FakeHttp(
        {
            ODOO_XMLRPC_DB_PATH: db_resp,
            ODOO_XMLRPC_COMMON_PATH: auth_resp,
        }
    )

    tool = OdooAccessTool(http_client=http)
    result = tool.run(_odoo_ctx(), _budget())

    assert result.success is True
    assert result.confidence == 0.9
    finding = result.findings[0]
    assert finding["uid"] == 2
    assert finding["access_level"] == "admin"
    assert finding["credential_source"] == "default"
    assert finding["credential_node_id"] is None
    assert finding["database"] == "erp"
    assert finding["username"] == "admin"
    # Anti-leak (structural, non-tautological): the proof dicts expose only a safe
    # allowlist of keys and never a "password" key. NOTE: admin/admin makes a
    # value-level leak check impossible (password == login), so the RIGOROUS
    # value-level non-leak proof lives in test_run_reused_credential_when_defaults_fail
    # where the password ("s3cr3t") is distinct from the login.
    assert set(finding["proof_request"]) == {
        "endpoint",
        "method",
        "database",
        "database_source",
        "login",
    }
    assert set(finding["proof_response"]) == {"uid", "server_version"}
    assert "password" not in finding["proof_request"]
    assert "password" not in finding["proof_response"]
    # db.list() returned ["erp"] -> provenance is honestly "enumerated"
    assert finding["proof_request"]["database_source"] == "enumerated"


def test_run_all_false_returns_failure() -> None:
    """authenticate always returns False → success=False, no findings."""
    http = _FakeHttp(
        {
            ODOO_XMLRPC_DB_PATH: _FakeResp(200, _xmlrpc_response_list(["erp"])),
            ODOO_XMLRPC_COMMON_PATH: _FakeResp(200, _xmlrpc_response_bool(False)),
        }
    )
    tool = OdooAccessTool(http_client=http)
    result = tool.run(_odoo_ctx(), _budget())

    assert result.success is False
    assert result.findings == ()
    assert "no candidate" in (result.error or "").lower()


def test_run_db_list_fault_no_derivable_db_returns_failure() -> None:
    """db.list() faults AND no host label is derivable → success=False, no findings.

    Anti-#3 (no-silent-success) guard on the discovery branch. To actually REACH
    `if not db_names: return failure`, the host must yield an empty first label — a
    leading-dot host (".invalid" → split('.')[0] == '') does that (verified via
    urlparse). Even though authenticate WOULD return uid=2, the tool must fail
    because it never resolved a database to authenticate against.
    """
    http = _FakeHttp(
        {
            ODOO_XMLRPC_DB_PATH: _FakeResp(200, _xmlrpc_fault()),
            ODOO_XMLRPC_COMMON_PATH: _FakeResp(200, _xmlrpc_response_int(2)),
        }
    )
    ctx = TargetContext(
        engagement_id="e",
        tenant_id=None,
        target="https://.invalid",  # host ".invalid" -> first label "" -> no db derivable
        tech_stack={"framework": "Odoo 16.0"},
    )
    tool = OdooAccessTool(http_client=http)
    result = tool.run(ctx, _budget())

    assert result.success is False
    assert result.findings == ()
    assert "database" in (result.error or "").lower()


def test_run_db_list_fault_falls_back_to_host_label() -> None:
    """db.list() faults but a host label IS derivable → fall back, authenticate on it.

    Honest counterpart to the failure test above; documents the fallback heuristic
    `host.split('.')[0]`. Host "lab-target.invalid" -> derived db "lab-target";
    authenticate returns uid=2 so the tool succeeds against the guessed db.
    (DESIGN FLAG in delivery notes: this heuristic makes the no-db failure branch
    reachable only on malformed hosts.)
    """
    http = _FakeHttp(
        {
            ODOO_XMLRPC_DB_PATH: _FakeResp(200, _xmlrpc_fault()),
            ODOO_XMLRPC_COMMON_PATH: _FakeResp(200, _xmlrpc_response_int(2)),
        }
    )
    ctx = TargetContext(
        engagement_id="e",
        tenant_id=None,
        target="https://lab-target.invalid",
        tech_stack={"framework": "Odoo 16.0"},
    )
    tool = OdooAccessTool(http_client=http)
    result = tool.run(ctx, _budget())

    assert result.success is True
    assert result.findings[0]["database"] == "lab-target"
    # db.list() faulted -> fell back to host label -> provenance is "guessed"
    assert result.findings[0]["proof_request"]["database_source"] == "guessed"


def test_run_defaults_take_precedence_over_reused_creds() -> None:
    """Graph creds present, but a built-in default authenticates FIRST → source="default".

    Honest rewrite of the old `_reused_credential_authenticates` (which asserted only
    uid==2 and proved nothing about the source). Documents real precedence: default
    candidates are tried before harvested creds, so when admin/admin works the source
    is "default". The genuine reused-cred proof is the next test.
    """
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    graph = NetworkXGraphStore()
    graph.apply_event(
        "NodeDiscovered",
        {
            "id": "cred:1",
            "type": "credential",
            "properties": {
                "username": "admin",
                "secret_ref": "vault:secret:1",
                "service": "odoo",
                "access_level": "user",
            },
            "confidence": 0.8,
            "agent": "alpha",
            "timestamp_utc": "2026-07-05T00:00:00Z",
        },
    )

    class _FakeVault:
        def retrieve(self, secret_ref: str) -> str:
            if secret_ref == "vault:secret:1":
                return "unused-because-default-wins"
            raise KeyError(secret_ref)

    http = _FakeHttp(
        {
            ODOO_XMLRPC_DB_PATH: _FakeResp(200, _xmlrpc_response_list(["erp"])),
            ODOO_XMLRPC_COMMON_PATH: _FakeResp(200, _xmlrpc_response_int(2)),
        }
    )
    tool = OdooAccessTool(
        http_client=http,
        graph_store=graph,
        secrets_manager=_FakeVault(),
    )
    result = tool.run(_odoo_ctx(), _budget())

    assert result.success is True
    finding = result.findings[0]
    assert finding["credential_source"] == "default"
    assert finding["credential_node_id"] is None
    assert finding["uid"] == 2


def test_run_reused_credential_when_defaults_fail() -> None:
    """Defaults fail, but a harvested credential authenticates → credential_source=reused."""
    from agent_alpha.graph.networkx_store import NetworkXGraphStore

    graph = NetworkXGraphStore()
    graph.apply_event(
        "NodeDiscovered",
        {
            "id": "cred:1",
            "type": "credential",
            "properties": {
                "username": "admin",
                "secret_ref": "vault:secret:1",
                "service": "odoo",
                "access_level": "user",
            },
            "confidence": 0.8,
            "agent": "alpha",
            "timestamp_utc": "2026-07-05T00:00:00Z",
        },
    )

    class _FakeVault:
        def retrieve(self, secret_ref: str) -> str:
            if secret_ref == "vault:secret:1":
                return "s3cr3t"
            raise KeyError(secret_ref)

    # Track call count to return False for defaults, uid=2 for the reused cred
    call_count = [0]

    class _SelectiveHttp:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def post(self, url: str, data: str = "", headers: dict | None = None) -> _FakeResp:
            self.calls.append(url)
            if ODOO_XMLRPC_DB_PATH in url:
                return _FakeResp(200, _xmlrpc_response_list(["erp"]))
            # Common path: version + authenticate calls
            call_count[0] += 1
            # First call = version, second = admin/admin, third = admin/password,
            # fourth = admin/s3cr3t (reused)
            if call_count[0] == 1:
                return _FakeResp(200, _xmlrpc_response_struct({"server_version": "16.0"}))
            elif call_count[0] in (2, 3):
                return _FakeResp(200, _xmlrpc_response_bool(False))
            else:
                return _FakeResp(200, _xmlrpc_response_int(2))

        def get(self, url: str, **kw: Any) -> _FakeResp:
            return _FakeResp(404, "")

    http = _SelectiveHttp()
    tool = OdooAccessTool(
        http_client=http,
        graph_store=graph,
        secrets_manager=_FakeVault(),
    )
    result = tool.run(_odoo_ctx(), _budget())

    assert result.success is True
    finding = result.findings[0]
    assert finding["credential_source"] == "reused"
    assert finding["credential_node_id"] == "cred:1"
    assert finding["uid"] == 2
    assert finding["username"] == "admin"
    # RIGOROUS anti-leak: the distinct password "s3cr3t" (!= login) must NOT appear
    # anywhere in the persisted proof dicts. This is the real non-leak proof the
    # admin/admin success test structurally cannot give (there password == login).
    proof_blob = str(finding["proof_request"]) + str(finding["proof_response"])
    assert "s3cr3t" not in proof_blob
    assert "password" not in finding["proof_request"]
    assert "password" not in finding["proof_response"]


# ── GAP-067: transport fallback seam (Odoo JSON-RPC fallback when XML-RPC blocked) ──
#
# The JSON-RPC transport BODY is the DeepSeek/offensive lane; these tests exercise the
# CLAUDE-lane orchestration with a fake transport standing in for it, proving: (1) a
# BLOCKED transport falls back to the next; (2) a WRONG credential does NOT (fallback is
# for endpoint-blocks, not auth failures); (3) the XML-RPC transport reports blocked on a
# WAF status. The finding's proof_request.endpoint distinguishes which transport won.


class _FakeTransport:
    """Stand-in OdooTransport for the fallback orchestration tests."""

    def __init__(
        self,
        name: str,
        *,
        blocked_discovery: bool = False,
        blocked_auth: bool = False,
        uid: int | None = None,
        dbs: tuple[str, ...] = ("erp",),
    ) -> None:
        self.name = name
        self.auth_endpoint = f"/{name}/authenticate"
        self._blocked_discovery = blocked_discovery
        self._blocked_auth = blocked_auth
        self._uid = uid
        self._dbs = list(dbs)
        self.auth_calls = 0

    def discover_databases(
        self, base_url: str, max_reqs: int, used: int
    ) -> tuple[list[str], str, bool, int]:
        if self._blocked_discovery:
            return [], "", True, used
        return self._dbs, "enumerated", False, used

    def server_version(self, base_url: str, max_reqs: int, used: int) -> tuple[str | None, int]:
        return "16.0", used

    def authenticate(
        self, base_url: str, db: str, login: str, password: str, used: int
    ) -> OdooLoginResult:
        self.auth_calls += 1
        if self._blocked_auth:
            return OdooLoginResult(uid=None, blocked=True, requests_used=used + 1)
        return OdooLoginResult(uid=self._uid, blocked=False, requests_used=used + 1)


def test_fallback_to_next_transport_when_first_blocked_at_discovery() -> None:
    """CARDINAL: XML-RPC blocked at discovery → fall back to the JSON-RPC transport."""
    xmlrpc = _FakeTransport("xmlrpc", blocked_discovery=True)
    json_rpc = _FakeTransport("json_rpc", uid=2)
    tool = OdooAccessTool(http_client=object(), transports=[xmlrpc, json_rpc])

    result = tool.run(_odoo_ctx(), _budget())

    assert result.success is True
    assert result.findings[0]["uid"] == 2
    assert result.findings[0]["proof_request"]["endpoint"] == "/json_rpc/authenticate"
    assert json_rpc.auth_calls == 1


def test_fallback_when_first_transport_blocked_at_authenticate() -> None:
    """A mid-loop endpoint block (403 on authenticate) also falls back to the next transport."""
    xmlrpc = _FakeTransport("xmlrpc", blocked_auth=True)  # discovery ok, auth endpoint blocked
    json_rpc = _FakeTransport("json_rpc", uid=2)
    tool = OdooAccessTool(http_client=object(), transports=[xmlrpc, json_rpc])

    result = tool.run(_odoo_ctx(), _budget())

    assert result.success is True
    assert result.findings[0]["proof_request"]["endpoint"] == "/json_rpc/authenticate"


def test_no_fallback_on_wrong_credentials() -> None:
    """CARDINAL guard: a WRONG credential (endpoint answered, uid absent) must NOT fall
    back — the second transport is never tried (fallback is for endpoint-blocks only,
    else we double the lockout/request budget on a target where creds are simply wrong)."""
    xmlrpc = _FakeTransport("xmlrpc", uid=None)  # endpoint answers, creds wrong, blocked=False
    json_rpc = _FakeTransport("json_rpc", uid=2)
    tool = OdooAccessTool(http_client=object(), transports=[xmlrpc, json_rpc])

    result = tool.run(_odoo_ctx(), _budget())

    assert result.success is False
    assert json_rpc.auth_calls == 0  # NEVER tried — no fallback on auth failure


def test_all_transports_blocked_reports_blocked_reason() -> None:
    """Every transport blocked → honest failure naming the block (not a false 'no db')."""
    tool = OdooAccessTool(
        http_client=object(),
        transports=[_FakeTransport("xmlrpc", blocked_discovery=True)],
    )
    result = tool.run(_odoo_ctx(), _budget())
    assert result.success is False
    assert "blocked" in (result.error or "").lower()


def test_xmlrpc_transport_reports_blocked_on_waf_status() -> None:
    """XmlRpcOdooTransport maps a WAF/CDN block status (403) to blocked=True — the seam
    signal that distinguishes an endpoint block from a wrong credential."""
    http = _FakeHttp({ODOO_XMLRPC_COMMON_PATH: _FakeResp(403, "")})
    result = XmlRpcOdooTransport(http).authenticate("https://x.invalid", "erp", "admin", "admin", 0)
    assert result.blocked is True
    assert result.uid is None


def test_xmlrpc_transport_reports_blocked_on_waf_status_db_list() -> None:
    """XmlRpcOdooTransport maps a WAF/CDN block status on db.list (403) to blocked=True
    and does not attempt hostname fallback."""
    http = _FakeHttp({ODOO_XMLRPC_DB_PATH: _FakeResp(403, "")})
    dbs, db_source, blocked, _ = XmlRpcOdooTransport(http).discover_databases(
        "https://x.invalid", 10, 0
    )
    assert dbs == []
    assert db_source == ""
    assert blocked is True


def test_xmlrpc_transport_wrong_creds_is_not_blocked() -> None:
    """A 200 that yields no positive uid is a wrong credential, NOT a block (no fallback)."""
    http = _FakeHttp({ODOO_XMLRPC_COMMON_PATH: _FakeResp(200, _xmlrpc_response_bool(False))})
    result = XmlRpcOdooTransport(http).authenticate("https://x.invalid", "erp", "admin", "x", 0)
    assert result.blocked is False
    assert result.uid is None


def test_fallback_allowed_when_first_transport_used_guessed_db() -> None:
    """If the first transport failed on a GUESSED db name, fallback to the next transport
    is allowed so a transport with better DB discovery can still succeed."""
    xmlrpc = _FakeTransport("xmlrpc", dbs=("guessed_db",), uid=None)
    # simulate db_source = "guessed"
    xmlrpc.discover_databases = lambda base_url, max_reqs, used: (
        ["guessed_db"],
        "guessed",
        False,
        used,
    )  # type: ignore[method-assign]
    json_rpc = _FakeTransport("json_rpc", uid=2)
    tool = OdooAccessTool(http_client=object(), transports=[xmlrpc, json_rpc])

    result = tool.run(_odoo_ctx(), _budget())
    assert result.success is True
    assert json_rpc.auth_calls == 1


# ── GAP-067: JsonRpcOdooTransport unit tests ─────────────────────────────────
#
# Mirror the XmlRpcOdooTransport tests above, proving the JSON-RPC fallback body:
# (T1) success auth, (T2) wrong cred not blocked, (T3) WAF block, (T4) discovery
# success, (T5) discovery block, (T6) raw secret never in returned fields.


def _jsonrpc_resp(result: Any) -> str:
    """Build a JSON-RPC 2.0 response body wrapping ``result``."""
    import json

    return json.dumps({"jsonrpc": "2.0", "id": None, "result": result})


def test_jsonrpc_transport_authenticate_success() -> None:
    """T1: 200 + {"result":{"uid":2}} → OdooLoginResult(uid=2, blocked=False)."""
    body = _jsonrpc_resp({"uid": 2, "session_id": "abc"})
    http = _FakeHttp({"/web/session/authenticate": _FakeResp(200, body)})
    result = JsonRpcOdooTransport(http).authenticate(
        "https://x.invalid", "erp", "admin", "admin", 0
    )
    assert result.uid == 2
    assert result.blocked is False
    assert result.requests_used == 1


def test_jsonrpc_transport_wrong_creds_not_blocked() -> None:
    """T2: 200 + {"result":false} → OdooLoginResult(uid=None, blocked=False).
    Wrong credential is NOT a block — no fallback."""
    body = _jsonrpc_resp(False)
    http = _FakeHttp({"/web/session/authenticate": _FakeResp(200, body)})
    result = JsonRpcOdooTransport(http).authenticate(
        "https://x.invalid", "erp", "admin", "wrong", 0
    )
    assert result.uid is None
    assert result.blocked is False


def test_jsonrpc_transport_waf_block_on_authenticate() -> None:
    """T3: 403 → OdooLoginResult(uid=None, blocked=True) — WAF block triggers fallback."""
    http = _FakeHttp({"/web/session/authenticate": _FakeResp(403, "")})
    result = JsonRpcOdooTransport(http).authenticate(
        "https://x.invalid", "erp", "admin", "admin", 0
    )
    assert result.uid is None
    assert result.blocked is True


def test_jsonrpc_transport_discover_databases_success() -> None:
    """T4: 200 + {"result":["erp"]} → (["erp"], "enumerated", False, used)."""
    body = _jsonrpc_resp(["erp"])
    http = _FakeHttp({"/web/database/list": _FakeResp(200, body)})
    dbs, db_source, blocked, used = JsonRpcOdooTransport(http).discover_databases(
        "https://x.invalid", 10, 0
    )
    assert dbs == ["erp"]
    assert db_source == "enumerated"
    assert blocked is False
    assert used == 1


def test_jsonrpc_transport_discover_databases_waf_block() -> None:
    """T5: 503 on /web/database/list → ([], "", True, used) — WAF block."""
    http = _FakeHttp({"/web/database/list": _FakeResp(503, "")})
    dbs, db_source, blocked, used = JsonRpcOdooTransport(http).discover_databases(
        "https://x.invalid", 10, 0
    )
    assert dbs == []
    assert db_source == ""
    assert blocked is True


def test_jsonrpc_transport_never_leaks_raw_password() -> None:
    """T6: the raw password NEVER appears in any OdooLoginResult field."""
    secret_password = "not_a_real_password_123"
    body = _jsonrpc_resp({"uid": 2, "session_id": "abc"})
    http = _FakeHttp({"/web/session/authenticate": _FakeResp(200, body)})
    result = JsonRpcOdooTransport(http).authenticate(
        "https://x.invalid", "erp", "admin", secret_password, 0
    )
    # OdooLoginResult only carries uid, blocked, requests_used — no password field.
    assert secret_password not in str(result)
    assert result.uid == 2
    # Verify the dataclass fields explicitly.
    assert not hasattr(result, "password")
    assert not hasattr(result, "secret")


def test_tool_run_fallback_from_xmlrpc_to_jsonrpc() -> None:
    """End-to-end test verifying OdooAccessTool default transport chain falls back
    from XML-RPC to JSON-RPC when XML-RPC is WAF-blocked."""
    # XML-RPC returns 403 (blocked) on db list
    # JSON-RPC returns 200 with DB on db list, and 200 with uid=2 on authenticate
    http = _FakeHttp(
        {
            ODOO_XMLRPC_DB_PATH: _FakeResp(403, ""),
            "/web/database/list": _FakeResp(200, _jsonrpc_resp(["erp"])),
            "/web/session/authenticate": _FakeResp(
                200, _jsonrpc_resp({"uid": 2, "session_id": "abc"})
            ),
        }
    )

    # tool initialized with NO transports injected, so it builds the default chain
    tool = OdooAccessTool(http_client=http)

    result = tool.run(_odoo_ctx(), _budget())

    assert result.success is True
    # The tool must have tried both endpoints
    assert any(ODOO_XMLRPC_DB_PATH in c for c in http.calls)
    assert any("/web/database/list" in c for c in http.calls)
    assert any("/web/session/authenticate" in c for c in http.calls)
