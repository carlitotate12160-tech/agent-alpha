# Unit contract for the backup_file catalog vector — MIGRATED to the ONE path_probe
# engine (process_path_hit, per-response, DIRECT recover — no dumper). Previously
# drove the deleted verify_backup_file self-sweeper; vector logic unchanged, only the
# entry point (the loop-fetched response is passed in — no re-fetch).
#
#   B1 real .env.bak with a secret -> vaulted CREDENTIAL.
#   B2 404 (path absent) -> nothing minted.
#   B3 200 HTML soft-404 -> nothing minted (presence != payable, anti-#3).
#   B4 WAF block (403) -> WAF_BLOCKED event, nothing minted.
#   B5 out-of-scope host -> nothing minted (scope gate).
#   B6 below RECON_ONLY -> fail-closed, nothing minted.
#
# Run on Oracle ARM64 only.

from __future__ import annotations

from dataclasses import dataclass, field

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.recon.path_probe import process_path_hit, spec_for_tool
from agent_alpha.security.secrets import SecretsManager

_HOST = "vuln.example"
_COTENANT = "cotenant.example"
_ENV_BAK_URL = f"https://{_HOST}/.env.bak"
_COTENANT_URL = f"https://{_COTENANT}/.env.bak"

_ENV_BAK_BODY = "APP_ENV=production\nDB_USER=appuser\nDB_PASSWORD=sup3rs3cret\nDB_HOST=db.internal\n"
_HTML_BODY = "<!doctype html><html><body>Page not found</body></html>"

_SPEC = spec_for_tool("backup_file_probe")


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""


def _recon_engagement(
    store: InMemoryEventStore,
    *,
    domains: list[str] | None = None,
    state: a2a_pb2.PhaseStatus = a2a_pb2.RECON_ONLY,
) -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="backup_lab", target=_HOST)
    if state == a2a_pb2.RECON_ONLY:
        auth.enable_recon(
            rec.engagement_id,
            Scope(ip_ranges=[], domains=domains or [_HOST], exclusions=[], db_endpoints=[]),
        )
    return auth, rec.engagement_id


@dataclass
class Ctx:
    store: InMemoryEventStore = field(default_factory=InMemoryEventStore)
    graph: NetworkXGraphStore = field(default_factory=NetworkXGraphStore)
    secrets: SecretsManager = field(default_factory=SecretsManager)


def _run(ctx: Ctx, auth: AuthorizationStateMachine, eid: str, *, resp: FakeResponse,
         url: str = _ENV_BAK_URL) -> int:
    return process_path_hit(
        _SPEC, resp=resp, url=url, engagement_id=eid, auth=auth,
        graph_store=ctx.graph, event_store=ctx.store, secrets_manager=ctx.secrets,
    )


def _creds(ctx: Ctx) -> list:
    return list(ctx.graph.nodes_by_type(NodeType.CREDENTIAL))


def _waf(ctx: Ctx, eid: str) -> list:
    return [e for e in ctx.store.get_events(eid) if e.event_type == EventType.WAF_BLOCKED]


def test_b1_env_backup_with_secret_mints_vaulted_credential() -> None:
    ctx = Ctx()
    auth, eid = _recon_engagement(ctx.store)
    added = _run(ctx, auth, eid, resp=FakeResponse(200, _ENV_BAK_BODY))
    assert added >= 1
    creds = _creds(ctx)
    assert len(creds) >= 1
    ref = getattr(creds[0].properties, "secret_ref", "")
    assert ref.startswith("secret_")
    assert ctx.secrets.retrieve(ref)


def test_b2_no_backup_mints_nothing() -> None:
    ctx = Ctx()
    auth, eid = _recon_engagement(ctx.store)
    added = _run(ctx, auth, eid, resp=FakeResponse(404, ""))
    assert added == 0
    assert _creds(ctx) == []


def test_b3_html_body_is_not_a_credential() -> None:
    ctx = Ctx()
    auth, eid = _recon_engagement(ctx.store)
    added = _run(ctx, auth, eid, resp=FakeResponse(200, _HTML_BODY))
    assert added == 0
    assert _creds(ctx) == []


def test_b4_waf_block_is_recorded() -> None:
    ctx = Ctx()
    auth, eid = _recon_engagement(ctx.store)
    added = _run(ctx, auth, eid, resp=FakeResponse(403, "Forbidden"))
    assert added == 0
    assert _creds(ctx) == []
    assert len(_waf(ctx, eid)) >= 1


def test_b5_out_of_scope_host_never_probed() -> None:
    ctx = Ctx()
    auth, eid = _recon_engagement(ctx.store, domains=[_HOST])  # cotenant NOT in scope
    added = _run(ctx, auth, eid, resp=FakeResponse(200, _ENV_BAK_BODY), url=_COTENANT_URL)
    assert added == 0
    assert _creds(ctx) == []


def test_b6_below_recon_tier_fails_closed() -> None:
    ctx = Ctx()
    auth, eid = _recon_engagement(ctx.store, state=a2a_pb2.CREATED)
    added = _run(ctx, auth, eid, resp=FakeResponse(200, _ENV_BAK_BODY))
    assert added == 0
    assert _creds(ctx) == []
