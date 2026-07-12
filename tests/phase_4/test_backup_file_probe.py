# RED test for exposed backup-file leak-source recon — verify_backup_file.
#
# TARGET PATH:  tests/phase_4/test_backup_file_probe.py
# AUTHORED BY:  Claude (test/gate lane). Bodies under test (path sweep, backup-suffix
#               normalisation, secret extraction reuse, credential mint) are the
#               IDE/infra lane.
#
# DESIGN (how backup_file differs from git_exposure):
#   * DIRECT, no dumper: a 200 on a backup path IS the recovered content (env / php /
#     yml). No git-dumper reconstruction step.
#   * Backup-suffix normalisation: /.env.bak → logical ".env", /wp-config.php.bak →
#     "wp-config.php", so the SHARED extractor (hoisted from git_exposure into a
#     neutral module — anti-#6/#7, ONE extractor, two callers) recognises the format.
#   * Slice-1 scope = CONFIG backups (.env / .php / .yml). db.sql (SQL dumps →
#     password-hash harvesting, a different finding-type) is a LATER slice.
#
# CANONICAL REUSE (anti-#6 / #7):
#   Same verify_* signature + the SAME shared extractor + assemble_leaked_credentials
#   + secrets_manager vault + response_classifier as git_exposure / wp_config. No new
#   credential type, no second vault path, no second block classifier.
#
# PINS:
#   B1  200 real .env.bak with DB creds → >=1 VAULTED CREDENTIAL (secret_ref resolves).
#   B2  no backup present (all 404) → 0 credentials.
#   B3  200 but an HTML/non-backup body → 0 credentials (presence != payable; anti-#3).
#   B4  403 on a backup path → WAF_BLOCKED event, 0 creds, NOT treated as clean.
#   B5  out-of-scope co-tenant host → never probed (scope gate).
#   B6  below RECON_ONLY tier → fail-closed, nothing probed.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_backup_file_probe.py -v

from __future__ import annotations

from dataclasses import dataclass, field

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.recon.backup_file_probe import verify_backup_file  # RED: module absent
from agent_alpha.security.secrets import SecretsManager

_HOST = "vuln.example"
_COTENANT = "cotenant.example"

# A real leaked .env backup — the payable content.
_ENV_BAK_BODY = "APP_ENV=production\nDB_USER=appuser\nDB_PASSWORD=sup3rs3cret\nDB_HOST=db.internal\n"
# A 200 that is NOT a real backup (server returned its HTML 404 page with status 200).
_HTML_BODY = "<!doctype html><html><body>Page not found</body></html>"


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""


class FakeHttpClient:
    """Serves a body for any URL ending in .env.bak (mode-dependent), else 404.
    Matches by suffix so the test does not couple to the exact BACKUP_FILE_PATHS entry."""

    def __init__(self, mode: str) -> None:
        self.mode = mode  # "env_secret" | "html" | "waf" | "absent"
        self.get_calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.get_calls.append(url)
        if self.mode == "waf":
            return FakeResponse(403, "Forbidden")
        if url.endswith(".env.bak"):
            if self.mode == "env_secret":
                return FakeResponse(200, _ENV_BAK_BODY)
            if self.mode == "html":
                return FakeResponse(200, _HTML_BODY)
        return FakeResponse(404, "")


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


def _run(ctx: Ctx, auth: AuthorizationStateMachine, eid: str, http: FakeHttpClient) -> int:
    return verify_backup_file(
        engagement_id=eid,
        auth=auth,
        http_client=http,
        scope_hosts=[_HOST],
        graph_store=ctx.graph,
        event_store=ctx.store,
        secrets_manager=ctx.secrets,
    )


def _creds(ctx: Ctx) -> list:
    return list(ctx.graph.nodes_by_type(NodeType.CREDENTIAL))


def _waf(ctx: Ctx, eid: str) -> list:
    return [e for e in ctx.store.get_events(eid) if e.event_type == EventType.WAF_BLOCKED]


# ── B1: real .env.bak with a secret → vaulted credential ──
def test_b1_env_backup_with_secret_mints_vaulted_credential() -> None:
    ctx = Ctx()
    auth, eid = _recon_engagement(ctx.store)
    added = _run(ctx, auth, eid, FakeHttpClient("env_secret"))

    assert added >= 1
    creds = _creds(ctx)
    assert len(creds) >= 1
    ref = getattr(creds[0].properties, "secret_ref", "")
    assert ref.startswith("secret_")
    assert ctx.secrets.retrieve(ref)  # payable = vaulted / reusable


# ── B2: no backup present → nothing minted ──
def test_b2_no_backup_mints_nothing() -> None:
    ctx = Ctx()
    auth, eid = _recon_engagement(ctx.store)
    added = _run(ctx, auth, eid, FakeHttpClient("absent"))
    assert added == 0
    assert _creds(ctx) == []


# ── B3: 200 HTML (soft-404) is NOT a payable backup ──
def test_b3_html_body_is_not_a_credential() -> None:
    ctx = Ctx()
    auth, eid = _recon_engagement(ctx.store)
    added = _run(ctx, auth, eid, FakeHttpClient("html"))
    assert added == 0
    assert _creds(ctx) == []


# ── B4: WAF block recorded, not clean ──
def test_b4_waf_block_is_recorded() -> None:
    ctx = Ctx()
    auth, eid = _recon_engagement(ctx.store)
    added = _run(ctx, auth, eid, FakeHttpClient("waf"))
    assert added == 0
    assert _creds(ctx) == []
    assert len(_waf(ctx, eid)) >= 1


# ── B5: out-of-scope host never probed ──
def test_b5_out_of_scope_host_never_probed() -> None:
    ctx = Ctx()
    auth, eid = _recon_engagement(ctx.store, domains=[_HOST])  # cotenant NOT in scope
    http = FakeHttpClient("env_secret")
    added = verify_backup_file(
        engagement_id=eid, auth=auth, http_client=http, scope_hosts=[_COTENANT],
        graph_store=ctx.graph, event_store=ctx.store, secrets_manager=ctx.secrets,
    )
    assert added == 0
    assert all(_COTENANT not in url for url in http.get_calls)


# ── B6: below RECON_ONLY fails closed ──
def test_b6_below_recon_tier_fails_closed() -> None:
    ctx = Ctx()
    auth, eid = _recon_engagement(ctx.store, state=a2a_pb2.CREATED)
    http = FakeHttpClient("env_secret")
    added = _run(ctx, auth, eid, http)
    assert added == 0
    assert http.get_calls == []
