# Unit contract for the git_exposure catalog vector — MIGRATED to the ONE
# path_probe engine (process_path_hit, per-response). Previously drove the deleted
# verify_git_exposure self-sweeper; the vector logic is unchanged, only the entry
# point (a response the loop already fetched is passed in — no re-fetch).
#
#   G1 exposed /.git config + dumper carrying a secret -> vaulted CREDENTIAL.
#   G2 body is not a git config (signature gate) -> no dump, nothing minted.
#   G3 exposed but dumper recovers no secret -> nothing minted (anti-#3).
#   G4 WAF block (403) -> WAF_BLOCKED event, no dump, nothing minted.
#   G5 out-of-scope host -> nothing minted (scope gate, defence-in-depth).
#   G6 below RECON_ONLY -> fail-closed, nothing minted.
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
_COTENANT = "cotenant.example"  # resolves same IP, NOT in scope.domains → default-DENY
_CONFIG_URL = f"https://{_HOST}/.git/config"
_COTENANT_URL = f"https://{_COTENANT}/.git/config"

_GIT_CONFIG_BODY = '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = x\n'
_NOT_GIT_BODY = "<!doctype html><html><body>hello</body></html>"

_RECOVERED_WITH_SECRET = {
    "config/database.yml": (
        "production:\n  adapter: postgresql\n  database: app_prod\n"
        "  username: appuser\n  password: sup3rs3cret\n  host: db.internal\n"
    ),
}
_RECOVERED_NO_SECRET = {"README.md": "# hello world\nnothing sensitive here\n"}

_SPEC = spec_for_tool("git_exposure_probe")


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""


class FakeGitDumper:
    def __init__(self, recovered: dict[str, str]) -> None:
        self._recovered = recovered
        self.dump_calls: list[str] = []

    def dump(self, base_url: str) -> dict[str, str]:
        self.dump_calls.append(base_url)
        return dict(self._recovered)


def _recon_engagement(
    event_store: InMemoryEventStore,
    *,
    domains: list[str] | None = None,
    state: a2a_pb2.PhaseStatus = a2a_pb2.RECON_ONLY,
) -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="git_lab", target=_HOST)
    if state == a2a_pb2.RECON_ONLY:
        auth.enable_recon(
            rec.engagement_id,
            Scope(ip_ranges=[], domains=domains or [_HOST], exclusions=[], db_endpoints=[]),
        )
    return auth, rec.engagement_id


@dataclass
class GitCtx:
    event_store: InMemoryEventStore = field(default_factory=InMemoryEventStore)
    graph_store: NetworkXGraphStore = field(default_factory=NetworkXGraphStore)
    secrets: SecretsManager = field(default_factory=SecretsManager)


def _run(
    ctx: GitCtx,
    auth: AuthorizationStateMachine,
    eid: str,
    *,
    resp: FakeResponse,
    dumper: FakeGitDumper,
    url: str = _CONFIG_URL,
) -> int:
    return process_path_hit(
        _SPEC,
        resp=resp,
        url=url,
        engagement_id=eid,
        auth=auth,
        graph_store=ctx.graph_store,
        event_store=ctx.event_store,
        secrets_manager=ctx.secrets,
        dumper=dumper,
    )


def _cred_nodes(graph_store: NetworkXGraphStore) -> list:
    return list(graph_store.nodes_by_type(NodeType.CREDENTIAL))


def _waf_events(event_store: InMemoryEventStore, eid: str) -> list:
    return [e for e in event_store.get_events(eid) if e.event_type == EventType.WAF_BLOCKED]


def test_g1_exposed_git_with_secret_mints_vaulted_credential() -> None:
    ctx = GitCtx()
    auth, eid = _recon_engagement(ctx.event_store)
    dumper = FakeGitDumper(_RECOVERED_WITH_SECRET)
    added = _run(ctx, auth, eid, resp=FakeResponse(200, _GIT_CONFIG_BODY), dumper=dumper)
    assert added >= 1
    assert dumper.dump_calls == [f"https://{_HOST}/"]
    creds = _cred_nodes(ctx.graph_store)
    assert len(creds) >= 1
    ref = getattr(creds[0].properties, "secret_ref", "")
    assert ref.startswith("secret_")
    assert ctx.secrets.retrieve(ref)


def test_g2_not_git_config_skips_dump_and_mints_nothing() -> None:
    ctx = GitCtx()
    auth, eid = _recon_engagement(ctx.event_store)
    dumper = FakeGitDumper(_RECOVERED_WITH_SECRET)
    added = _run(ctx, auth, eid, resp=FakeResponse(200, _NOT_GIT_BODY), dumper=dumper)
    assert added == 0
    assert dumper.dump_calls == []  # signature gate blocked the expensive dump
    assert _cred_nodes(ctx.graph_store) == []


def test_g3_exposed_without_secret_mints_no_credential() -> None:
    ctx = GitCtx()
    auth, eid = _recon_engagement(ctx.event_store)
    dumper = FakeGitDumper(_RECOVERED_NO_SECRET)
    added = _run(ctx, auth, eid, resp=FakeResponse(200, _GIT_CONFIG_BODY), dumper=dumper)
    assert added == 0
    assert dumper.dump_calls  # dumped, but no payable secret recovered
    assert _cred_nodes(ctx.graph_store) == []


def test_g4_waf_block_is_recorded_and_halts() -> None:
    ctx = GitCtx()
    auth, eid = _recon_engagement(ctx.event_store)
    dumper = FakeGitDumper(_RECOVERED_WITH_SECRET)
    added = _run(ctx, auth, eid, resp=FakeResponse(403, "Forbidden"), dumper=dumper)
    assert added == 0
    assert dumper.dump_calls == []
    assert len(_waf_events(ctx.event_store, eid)) >= 1


def test_g5_out_of_scope_host_never_probed() -> None:
    ctx = GitCtx()
    auth, eid = _recon_engagement(ctx.event_store, domains=[_HOST])  # cotenant NOT in scope
    dumper = FakeGitDumper(_RECOVERED_WITH_SECRET)
    added = _run(
        ctx, auth, eid, resp=FakeResponse(200, _GIT_CONFIG_BODY), dumper=dumper, url=_COTENANT_URL
    )
    assert added == 0
    assert dumper.dump_calls == []  # scope gate stops before any recovery
    assert _cred_nodes(ctx.graph_store) == []


def test_g6_below_recon_tier_fails_closed() -> None:
    ctx = GitCtx()
    auth, eid = _recon_engagement(ctx.event_store, state=a2a_pb2.CREATED)
    dumper = FakeGitDumper(_RECOVERED_WITH_SECRET)
    added = _run(ctx, auth, eid, resp=FakeResponse(200, _GIT_CONFIG_BODY), dumper=dumper)
    assert added == 0
    assert dumper.dump_calls == []
    assert _cred_nodes(ctx.graph_store) == []
