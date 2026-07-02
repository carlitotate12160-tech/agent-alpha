# RED test for WP wp-config backup leak recon — verify_wp_config_leak + parse_wp_config.
#
# TARGET PATH:  tests/phase_3/test_wp_config_leak.py
# AUTHORED BY:  Claude (test/gate lane). Bodies under test (parse_wp_config,
#               verify_wp_config_leak gating+writes) are the IDE/infra lane.
#
# PINS (the contract the bodies MUST honour):
#   T1  parse_wp_config extracts DB_USER + DB_PASSWORD (and DB_NAME, DB_HOST).
#   T2  parse returns {} when no DB creds (anti-#3: 200 page ≠ finding).
#   T3  leak at in-scope backup path → paired database:login credential assembled.
#   T4  HTTP 200 but unparseable body → no credential node (anti-#3).
#   T5  WAF block (403) → WAF_BLOCKED event emitted, no credential, NOT treated as clean.
#   T6  out-of-scope co-tenant host → never probed (scope gate).
#   T7  below RECON_ONLY tier → fail-closed, nothing probed.

from __future__ import annotations

from dataclasses import dataclass

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.recon.wp_config_probe import parse_wp_config, verify_wp_config_leak
from agent_alpha.security.secrets import SecretsManager

_HOST = "client-target.com"
_WP_CONFIG_BODY = (
    "<?php\n"
    "define('DB_NAME', 'wp_client-target');\n"
    "define('DB_USER', 'wpuser');\n"
    "define('DB_PASSWORD', 's3cret');\n"
    "define('DB_HOST', 'localhost');\n"
    "define('AUTH_KEY', 'saltsaltsalt');\n"
    "define('NONCE_SALT', 'moresaltsalt');\n"
)


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""


class FakeHttpClient:
    """Records every URL probed; returns canned responses."""

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


def _recon_engagement(
    event_store: InMemoryEventStore,
    *,
    domains: list[str] | None = None,
    state: a2a_pb2.PhaseStatus = a2a_pb2.RECON_ONLY,
) -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="wp_lab", target=_HOST)
    if state == a2a_pb2.RECON_ONLY:
        auth.enable_recon(
            rec.engagement_id,
            Scope(
                ip_ranges=["206.189.93.100/32"],
                domains=domains or [_HOST],
                exclusions=[],
                db_endpoints=[],
            ),
        )
    return auth, rec.engagement_id


@dataclass
class WpCtx:
    """Test context — holds all the wiring for a single verify call."""

    auth: AuthorizationStateMachine
    engagement_id: str
    http: FakeHttpClient
    graph: NetworkXGraphStore
    event_store: InMemoryEventStore
    secrets: SecretsManager

    @property
    def args(self) -> dict:
        return dict(
            engagement_id=self.engagement_id,
            auth=self.auth,
            http_client=self.http,
            scope_hosts=[_HOST],
            graph_store=self.graph,
            event_store=self.event_store,
            secrets_manager=self.secrets,
        )


@pytest.fixture
def wp_ctx() -> WpCtx:
    event_store = InMemoryEventStore()
    auth, eid = _recon_engagement(event_store)
    graph = NetworkXGraphStore()
    secrets = SecretsManager()
    http = FakeHttpClient()
    return WpCtx(
        auth=auth,
        engagement_id=eid,
        http=http,
        graph=graph,
        event_store=event_store,
        secrets=secrets,
    )


def _db_login(graph: NetworkXGraphStore, secrets: SecretsManager) -> tuple[str, str]:
    """Extract the (username, password) from a paired database:login credential node."""
    cred_nodes = graph.nodes_by_type(NodeType.CREDENTIAL)
    for node in cred_nodes:
        props = node.properties
        if props.service == "database" and props.username:
            password = secrets.retrieve(props.secret_ref)
            return props.username, password
    return "", ""


def _events(event_store: InMemoryEventStore, engagement_id: str) -> list:
    """Return all events for an engagement from the store."""
    return event_store.get_events(engagement_id)


# ── T1: parse_wp_config extracts DB_USER + DB_PASSWORD ──────────────────────


def test_parse_wp_config_extracts_db_user_and_password():
    body = (
        "<?php define('DB_NAME','wp'); define('DB_USER','wpuser'); "
        "define('DB_PASSWORD','s3cret'); define('DB_HOST','localhost');"
    )
    assert parse_wp_config(body) == {
        "DB_NAME": "wp",
        "DB_USER": "wpuser",
        "DB_PASSWORD": "s3cret",
        "DB_HOST": "localhost",
    }


# ── T2: parse returns {} when no DB creds (anti-#3) ──────────────────────────


def test_parse_returns_empty_when_no_db_creds():
    assert parse_wp_config("<html>200 OK, cached by Varnish</html>") == {}
    assert parse_wp_config("<?php define('AUTH_KEY','saltsaltsalt'); ?>") == {}


# ── T3: leak at in-scope backup path → paired database:login credential ─────


def test_leak_at_in_scope_backup_path_assembles_paired_login(wp_ctx: WpCtx):
    url = f"https://{_HOST}/wp-config.php.bak"
    wp_ctx.http._responses[url] = FakeResponse(status_code=200, text=_WP_CONFIG_BODY)
    verify_wp_config_leak(**wp_ctx.args)
    assert _db_login(wp_ctx.graph, wp_ctx.secrets) == ("wpuser", "s3cret")


# ── T4: HTTP 200 but unparseable → no credential (anti-#3) ──────────────────


def test_http_200_but_unparseable_writes_no_credential(wp_ctx: WpCtx):
    url = f"https://{_HOST}/wp-config.php.bak"
    wp_ctx.http._responses[url] = FakeResponse(status_code=200, text="<html>home page</html>")
    verify_wp_config_leak(**wp_ctx.args)
    assert not wp_ctx.graph.nodes_by_type(NodeType.CREDENTIAL)


# ── T5: WAF block (403) → WAF_BLOCKED event, no credential, NOT clean ───────


def test_waf_block_recorded_not_treated_clean(wp_ctx: WpCtx):
    url = f"https://{_HOST}/wp-config.php.bak"
    wp_ctx.http._responses[url] = FakeResponse(status_code=403, text="Request blocked")
    verify_wp_config_leak(**wp_ctx.args)
    assert any(
        e.event_type == EventType.WAF_BLOCKED
        for e in _events(wp_ctx.event_store, wp_ctx.engagement_id)
    )
    assert not wp_ctx.graph.nodes_by_type(NodeType.CREDENTIAL)


# ── T6: out-of-scope co-tenant host → never probed (scope gate) ─────────────


def test_out_of_scope_cotenant_host_never_probed(wp_ctx: WpCtx):
    args = wp_ctx.args
    args["scope_hosts"] = ["sibling.cloudwaysapps.com"]
    verify_wp_config_leak(**args)
    assert wp_ctx.http.get_calls == []


# ── T7: below RECON_ONLY tier → fail-closed ─────────────────────────────────


def test_below_recon_tier_fails_closed():
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="wp_lab", target=_HOST)
    # Do NOT enable_recon — engagement stays at CREATED
    graph = NetworkXGraphStore()
    http = FakeHttpClient()
    result = verify_wp_config_leak(
        engagement_id=rec.engagement_id,
        auth=auth,
        http_client=http,
        scope_hosts=[_HOST],
        graph_store=graph,
        event_store=event_store,
        secrets_manager=SecretsManager(),
    )
    assert result == 0
    assert http.get_calls == []
