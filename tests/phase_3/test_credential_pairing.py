"""RED→GREEN: Alpha must assemble ONE usable DB login credential from co-located
DB_USERNAME + DB_PASSWORD, vault the PASSWORD (not the username), and never
fabricate or cross-service-mispair a login.

Pairing fix (anti-fragmentation, anti-Lyndon #3):
  - When BOTH DB_USERNAME and DB_PASSWORD are co-located on one debug page, emit
    ONE paired login node: username=<DB_USERNAME>, secret_ref=vault(<DB_PASSWORD>).
  - DB_USERNAME is NEVER emitted as a standalone credential (it is not a secret;
    vaulting it creates a false credential whose secret_ref resolves to the username).
  - DB_PASSWORD is ALSO emitted as a standalone fragment (additive variant) so the
    web cred_reuse chain (which depends on it with username="") still works.
  - The paired login node is emitted FIRST so cred_reuse tries it before fragments.
"""

from __future__ import annotations

import pathlib

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.applicator_factory import BoundApplicator
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.live_fire.db_chain_runner import _db_credential_is_usable
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.contracts import ResourceBudget, TargetContext
from agent_alpha.tools.internal.access.cred_reuse import CredReuseTool
from agent_alpha.tools.internal.access.mysql_applicator import MySqlApplicator
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(__file__).parent.parent / "phase_2" / "fixtures" / "playbooks"

_TARGET_URL = "https://lab-target.invalid/trigger-error"
_HOST = "lab-target.invalid"


# ── Test helpers ──────────────────────────────────────────────


class _StubProvider:
    model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object):
        return type(
            "R",
            (),
            {
                "text": '{"tool": "generic_http_probe"}',
                "usage_cost_usd": 0.0,
                "model": "deepseek-v4-pro",
            },
        )()


class _FakeResponse:
    def __init__(
        self, status_code: int, text: str, headers: dict[str, str] | None = None, url: str = ""
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url


class _FakeHttpClient:
    def __init__(self, body: str) -> None:
        self._body = body
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> _FakeResponse:
        self.calls.append(url)
        return _FakeResponse(500, self._body, {"server": "nginx"}, url)

    def post(
        self, url: str, *, data=None, json_body=None, headers=None, cookies=None
    ) -> _FakeResponse:
        return _FakeResponse(404, "", {}, url)


def _debug_page(**kv: str) -> str:
    rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in kv.items())
    return (
        "<!DOCTYPE html><html><head><title>Whoops! There was an error.</title></head>"
        "<body><div class='exception'>Illuminate\\Database\\QueryException</div>"
        f"<table>{rows}</table>"
        "<footer>Laravel v10.3.1 (PHP v8.2.4)</footer></body></html>"
    )


class _AlphaCtx:
    def __init__(self) -> None:
        self.secrets = SecretsManager()
        self.graph = NetworkXGraphStore()
        self.event_store = InMemoryEventStore()
        self.auth = AuthorizationStateMachine(event_store=self.event_store)
        rec = self.auth.create_engagement(client_id="pair_lab", target=_HOST)
        self.auth.enable_recon(
            rec.engagement_id,
            Scope(ip_ranges=["10.0.0.0/30"], domains=[_HOST], exclusions=[]),
        )
        self.engagement_id = rec.engagement_id
        self.orchestrator = LLMOrchestrator(
            playbook=PlaybookEngine.from_directory(PLAYBOOK_DIR),
            provider=_StubProvider(),
        )


def _run_recon(ctx: _AlphaCtx, body: str) -> None:
    http = _FakeHttpClient(body)
    alpha = Alpha(
        authorization=ctx.auth,
        graph_store=ctx.graph,
        event_store=ctx.event_store,
        orchestrator=ctx.orchestrator,
        http_client=http,
        secrets_manager=ctx.secrets,
    )
    alpha.run_recon(ctx.engagement_id, _TARGET_URL)


def _db_login(graph: NetworkXGraphStore, secrets: SecretsManager) -> tuple[str, str] | None:
    """Return (username, secret) for the first usable DB login credential, or None."""
    for n in graph.nodes_by_type(NodeType.CREDENTIAL):
        p = n.properties
        if p.service in ("database", "mysql", "mariadb") and p.username:
            try:
                return p.username, secrets.retrieve(p.secret_ref)
            except Exception:
                continue
    return None


# ── Pairing tests ─────────────────────────────────────────────


def test_pair_uses_password_as_secret_not_username() -> None:
    """Both keys present → (username=root, secret=<password>), NOT (root, root)."""
    ctx = _AlphaCtx()
    _run_recon(ctx, _debug_page(DB_USERNAME="root", DB_PASSWORD="s3cret", APP_KEY="base64:x"))
    assert _db_login(ctx.graph, ctx.secrets) == ("root", "s3cret")


def test_password_only_yields_no_usable_login() -> None:
    """Password without username → no fabricated login (anti-#3)."""
    ctx = _AlphaCtx()
    _run_recon(ctx, _debug_page(DB_PASSWORD="s3cret"))
    assert _db_login(ctx.graph, ctx.secrets) is None


def test_no_cross_service_mispair() -> None:
    """DB_USERNAME + REDIS_PASSWORD (no DB_PASSWORD) → redis must NOT become the DB secret."""
    ctx = _AlphaCtx()
    _run_recon(ctx, _debug_page(DB_USERNAME="root", REDIS_PASSWORD="rpw"))
    assert _db_login(ctx.graph, ctx.secrets) is None


def test_exactly_one_usable_db_login_amid_noise() -> None:
    """Full env noise → exactly one usable login, secret = DB_PASSWORD value."""
    ctx = _AlphaCtx()
    _run_recon(
        ctx,
        _debug_page(
            DB_USERNAME="root",
            DB_PASSWORD="dbpw",
            REDIS_PASSWORD="rpw",
            MAIL_PASSWORD="mpw",
            APP_KEY="k",
        ),
    )
    assert _db_login(ctx.graph, ctx.secrets) == ("root", "dbpw")


def test_db_credential_is_usable_true_after_paired_leak() -> None:
    """The db_chain_runner usability check returns True after a paired leak."""
    ctx = _AlphaCtx()
    _run_recon(ctx, _debug_page(DB_USERNAME="root", DB_PASSWORD="s3cret"))
    assert _db_credential_is_usable(ctx.graph) is True


def test_db_credential_is_usable_false_when_only_password() -> None:
    """Without a paired login, the usability check returns False (username="" fragment)."""
    ctx = _AlphaCtx()
    _run_recon(ctx, _debug_page(DB_PASSWORD="s3cret"))
    assert _db_credential_is_usable(ctx.graph) is False


# ── Consumption: MySqlApplicator receives the paired credentials ──────


class _RecordingConn:
    def __init__(self) -> None:
        self.received: dict[str, str] = {}

    def databases(self) -> list[str]:
        return ["information_schema", "clientdb"]

    def has_superuser_grant(self) -> bool:
        return True

    def server_version(self) -> str:
        return "8.4.10"

    def close(self) -> None:
        pass


class _RecordingConnector:
    def __init__(self) -> None:
        self.conn = _RecordingConn()

    def connect(self, *, host: str, port: int, username: str, secret: str, timeout_s: float):
        if not username:
            raise Exception("Access denied for user ''@host")
        self.conn.received = {"username": username, "secret": secret}
        return self.conn


def test_mysql_applicator_receives_paired_credentials() -> None:
    """The fake MySqlApplicator connector receives apply(username='root', secret=<password>),
    NOT ('root', 'root') or ('', <password>)."""
    ctx = _AlphaCtx()
    _run_recon(ctx, _debug_page(DB_USERNAME="root", DB_PASSWORD="dbpw"))

    connector = _RecordingConnector()
    applicator = MySqlApplicator(connector=connector)
    bound = [BoundApplicator(applicator, "10.0.0.1:3306")]

    ctx.auth.enable_active(ctx.engagement_id)
    tool = CredReuseTool(
        applicators=bound,
        http_client=object(),
        graph_store=ctx.graph,
        secrets_manager=ctx.secrets,
    )
    result = tool.run(
        TargetContext(engagement_id=ctx.engagement_id, tenant_id=None, target="10.0.0.1:3306"),
        ResourceBudget(max_requests=10, max_seconds=15.0, max_cost_usd=0.0),
    )

    assert result.success is True
    assert connector.conn.received["username"] == "root"
    assert connector.conn.received["secret"] == "dbpw"
