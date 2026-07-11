# RED test for exposed-.git leak-source recon — verify_git_exposure.
#
# TARGET PATH:  tests/phase_4/test_git_exposure_probe.py
# AUTHORED BY:  Claude (test/gate lane). Bodies under test (exposure detection,
#               the WRAPPED git-dumper, secret scan → credential mint) are the
#               IDE/infra lane. git-dumper is COMMODITY → WRAP (ADR §12.22),
#               do NOT build a reconstructor.
#
# WHY THIS IS PAYABLE, NOT A FINGERPRINT (charter bar; anti-Lyndon #3):
#   An exposed /.git/ returning 200 is EXPOSURE, not a payable finding. Payable =
#   a real secret RECOVERED from the repo, minted as a VAULTED credential that can
#   feed the sealed cred-reuse / direct-DB chain (same moat as wp-config leak).
#   So bare exposure with no recoverable secret mints ZERO credentials.
#
# CANONICAL REUSE (anti-#6 / #7):
#   Same verify_* signature + the SAME credential-assembly + secrets_manager vault
#   path as verify_wp_config_leak. Same response_classifier for the block verdict.
#   No new credential type, no second vault path, no second block classifier.
#
# PINS (the contract the bodies MUST honour):
#   G1  exposed /.git/config + dumper recovers a file with DB creds → >=1 VAULTED
#       CREDENTIAL node (secret_ref resolves via secrets_manager). The payable proof.
#   G2  no /.git/ (config 404) → 0 credentials; dumper is NEVER invoked (cheap-first:
#       do not dump a host that is not exposed).
#   G3  exposed /.git/ but recovered files carry NO secret → 0 CREDENTIAL nodes
#       (exposure alone is never dressed as a credential; anti-#3).
#   G4  /.git/config returns 403 → WAF_BLOCKED event, dumper NOT invoked, 0 creds,
#       NOT treated as clean (anti-#3, classifier is the single source anti-#7).
#   G5  out-of-scope co-tenant host → never probed (scope gate).
#   G6  below RECON_ONLY tier → fail-closed, nothing probed, dumper never invoked.
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest tests/phase_4/test_git_exposure_probe.py -v

from __future__ import annotations

from dataclasses import dataclass, field

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.recon.git_exposure_probe import verify_git_exposure  # RED: module absent
from agent_alpha.security.secrets import SecretsManager

_HOST = "vuln.example"
_COTENANT = "cotenant.example"  # resolves same IP, NOT in scope.domains → default-DENY
_CONFIG_URL = f"https://{_HOST}/.git/config"

_GIT_CONFIG_BODY = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = x\n"

# A recovered tracked file that carries a real DB credential (the payable secret).
_RECOVERED_WITH_SECRET = {
    "config/database.yml": (
        "production:\n"
        "  adapter: postgresql\n"
        "  database: app_prod\n"
        "  username: appuser\n"
        "  password: sup3rs3cret\n"
        "  host: db.internal\n"
    ),
}
# A recovered repo with NO secret — exposure without payable content.
_RECOVERED_NO_SECRET = {"README.md": "# hello world\nnothing sensitive here\n"}


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""


class FakeHttpClient:
    """Records every URL probed; returns canned responses (404 for the unknown)."""

    def __init__(self, responses: dict[str, FakeResponse | Exception] | None = None) -> None:
        self._responses = responses or {}
        self.get_calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.get_calls.append(url)
        r = self._responses.get(url)
        if isinstance(r, Exception):
            raise r
        if r is None:
            return FakeResponse(status_code=404, text="")
        return r


class FakeGitDumper:
    """Injected stand-in for the WRAPPED commodity git-dumper. Records whether it
    was invoked and against which base, so G2/G4/G6 can assert cheap-first / gates."""

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


def _cred_nodes(graph_store: NetworkXGraphStore) -> list:
    return list(graph_store.nodes_by_type(NodeType.CREDENTIAL))


def _waf_events(event_store: InMemoryEventStore, eid: str) -> list:
    return [e for e in event_store.get_events(eid) if e.event_type == EventType.WAF_BLOCKED]


# ── G1: exposed + recoverable secret → vaulted credential (the payable proof) ──
def test_g1_exposed_git_with_secret_mints_vaulted_credential() -> None:
    ctx = GitCtx()
    auth, eid = _recon_engagement(ctx.event_store)
    http = FakeHttpClient({_CONFIG_URL: FakeResponse(200, _GIT_CONFIG_BODY)})
    dumper = FakeGitDumper(_RECOVERED_WITH_SECRET)

    added = verify_git_exposure(
        engagement_id=eid,
        auth=auth,
        http_client=http,
        scope_hosts=[_HOST],
        graph_store=ctx.graph_store,
        event_store=ctx.event_store,
        secrets_manager=ctx.secrets,
        dumper=dumper,
    )

    assert added >= 1
    creds = _cred_nodes(ctx.graph_store)
    assert len(creds) >= 1
    # Payable = the secret is VAULTED (feeds cred-reuse), not left inline.
    ref = getattr(creds[0].properties, "secret_ref", "")
    assert ref.startswith("secret_")
    assert ctx.secrets.retrieve(ref)  # resolves → the recovered secret is in the vault
    assert dumper.dump_calls == [f"https://{_HOST}/"]


# ── G2: not exposed → cheap-first, dumper never runs, zero credentials ──
def test_g2_not_exposed_skips_dump_and_mints_nothing() -> None:
    ctx = GitCtx()
    auth, eid = _recon_engagement(ctx.event_store)
    http = FakeHttpClient({_CONFIG_URL: FakeResponse(404, "")})
    dumper = FakeGitDumper(_RECOVERED_WITH_SECRET)

    added = verify_git_exposure(
        engagement_id=eid, auth=auth, http_client=http, scope_hosts=[_HOST],
        graph_store=ctx.graph_store, event_store=ctx.event_store,
        secrets_manager=ctx.secrets, dumper=dumper,
    )

    assert added == 0
    assert _cred_nodes(ctx.graph_store) == []
    assert dumper.dump_calls == []  # never dump a host that is not exposed


# ── G3: exposed but no recoverable secret → exposure ≠ payable credential ──
def test_g3_exposed_without_secret_mints_no_credential() -> None:
    ctx = GitCtx()
    auth, eid = _recon_engagement(ctx.event_store)
    http = FakeHttpClient({_CONFIG_URL: FakeResponse(200, _GIT_CONFIG_BODY)})
    dumper = FakeGitDumper(_RECOVERED_NO_SECRET)

    added = verify_git_exposure(
        engagement_id=eid, auth=auth, http_client=http, scope_hosts=[_HOST],
        graph_store=ctx.graph_store, event_store=ctx.event_store,
        secrets_manager=ctx.secrets, dumper=dumper,
    )

    assert added == 0
    assert _cred_nodes(ctx.graph_store) == []


# ── G4: WAF/CF block on /.git/config → recorded, not clean, dumper not invoked ──
def test_g4_waf_block_is_recorded_and_halts() -> None:
    ctx = GitCtx()
    auth, eid = _recon_engagement(ctx.event_store)
    http = FakeHttpClient({_CONFIG_URL: FakeResponse(403, "Forbidden")})
    dumper = FakeGitDumper(_RECOVERED_WITH_SECRET)

    added = verify_git_exposure(
        engagement_id=eid, auth=auth, http_client=http, scope_hosts=[_HOST],
        graph_store=ctx.graph_store, event_store=ctx.event_store,
        secrets_manager=ctx.secrets, dumper=dumper,
    )

    assert added == 0
    assert _cred_nodes(ctx.graph_store) == []
    assert dumper.dump_calls == []
    assert len(_waf_events(ctx.event_store, eid)) == 1  # block is evidence, not "clean"


# ── G5: out-of-scope co-tenant host → never probed ──
def test_g5_out_of_scope_host_never_probed() -> None:
    ctx = GitCtx()
    auth, eid = _recon_engagement(ctx.event_store, domains=[_HOST])  # cotenant NOT in scope
    http = FakeHttpClient({_CONFIG_URL: FakeResponse(200, _GIT_CONFIG_BODY)})
    dumper = FakeGitDumper(_RECOVERED_WITH_SECRET)

    added = verify_git_exposure(
        engagement_id=eid, auth=auth, http_client=http, scope_hosts=[_COTENANT],
        graph_store=ctx.graph_store, event_store=ctx.event_store,
        secrets_manager=ctx.secrets, dumper=dumper,
    )

    assert added == 0
    assert all(_COTENANT not in url for url in http.get_calls)
    assert dumper.dump_calls == []


# ── G6: below RECON_ONLY tier → fail-closed, nothing probed ──
def test_g6_below_recon_tier_fails_closed() -> None:
    ctx = GitCtx()
    auth, eid = _recon_engagement(ctx.event_store, state=a2a_pb2.CREATED)  # not enabled
    http = FakeHttpClient({_CONFIG_URL: FakeResponse(200, _GIT_CONFIG_BODY)})
    dumper = FakeGitDumper(_RECOVERED_WITH_SECRET)

    added = verify_git_exposure(
        engagement_id=eid, auth=auth, http_client=http, scope_hosts=[_HOST],
        graph_store=ctx.graph_store, event_store=ctx.event_store,
        secrets_manager=ctx.secrets, dumper=dumper,
    )

    assert added == 0
    assert http.get_calls == []
    assert dumper.dump_calls == []
