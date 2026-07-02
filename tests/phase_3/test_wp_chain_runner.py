"""Contract: WP chain runner — verify_wp_config_leak is invoked by a runnable path,
leak → paired credential → web cred-reuse consumption, cohost gate on bare-IP entry_point,
and honest chain_proven (leak without web access = NOT proven).

Mirrors test_chain_runner.py: a fake HTTP server that serves a wp-config.php.bak
backup file with DB_USER + DB_PASSWORD, and a WP login that grants access ONLY
to the leaked password value (models password reuse).
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from typing import Any

import agent_alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire import wp_chain_runner
from agent_alpha.live_fire.beta_runner import _NoLLMProvider
from agent_alpha.live_fire.wp_chain_runner import WpChainConfig, run_wp_chain_live_fire
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

PLAYBOOK_DIR = pathlib.Path(agent_alpha.__file__).parent / "tools" / "playbooks"
RECON_URL = "http://localhost:9201/"
ENTRY_POINT = "http://localhost:9201/wp-login.php"
WP_BACKUP_URL = "https://localhost/wp-config.php.bak"
LEAKED_USER = "wpuser"
LEAKED_PASS = "s3cret-wp-x7q2"

WP_CONFIG_BODY = (
    "<?php\n"
    f"define('DB_NAME', 'wp_lab');\n"
    f"define('DB_USER', '{LEAKED_USER}');\n"
    f"define('DB_PASSWORD', '{LEAKED_PASS}');\n"
    f"define('DB_HOST', 'localhost');\n"
)
LOGIN_PAGE = '<html><form><input type="text" name="log"><input type="password" name="pwd"></form> wp-login</html>'
DASHBOARD = "<html>wp-admin dashboard, welcome administrator</html>"


@dataclass
class _R:
    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ""

    @property
    def body(self) -> str:
        return self.text


class _WpChainFake:
    """Fake HTTP: serves wp-config.php.bak + WP login that grants access ONLY to leaked password."""

    def __init__(self, *, login_fails: bool = False, backup_status: int = 200) -> None:
        self._login_fails = login_fails
        self._backup_status = backup_status

    def get(
        self, url: str, *, headers: Any = None, cookies: Any = None, timeout: float = 10.0
    ) -> _R:
        # Alpha generic recon on root
        if url == RECON_URL or url == "http://localhost:9201/":
            return _R(200, "<html>WordPress site</html>", {"server": "apache"}, url)
        # WP config backup probe (verify_wp_config_leak uses https://host/path)
        if "wp-config.php.bak" in url:
            if self._backup_status != 200:
                return _R(self._backup_status, "", {}, url)
            return _R(200, WP_CONFIG_BODY, {}, url)
        # Other backup paths → 404
        if "wp-config" in url:
            return _R(404, "", {}, url)
        # Login page baseline GET
        if "wp-login" in url:
            return _R(200, LOGIN_PAGE, {}, url)
        # Confirm step (session cookie)
        if cookies:
            return _R(200, DASHBOARD, {}, url)
        return _R(404, "", {}, url)

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Any = None,
        cookies: Any = None,
    ) -> _R:
        if "wp-login" in url:
            if self._login_fails:
                return _R(200, LOGIN_PAGE, {}, url)
            password = (data or {}).get("pwd", "")
            if password == LEAKED_PASS:
                return _R(
                    200, DASHBOARD, {"set-cookie": "session=wpabc123def456; Path=/; HttpOnly"}, url
                )
            return _R(200, LOGIN_PAGE, {}, url)
        return _R(404, "", {}, url)


def _orchestrator() -> LLMOrchestrator:
    return LLMOrchestrator(PlaybookEngine.from_directory(PLAYBOOK_DIR), _NoLLMProvider())


def _config() -> WpChainConfig:
    return WpChainConfig(
        client_id="wp_chain_lab",
        scope_ip_ranges=["127.0.0.1/32"],
        scope_domains=["localhost"],
        scope_exclusions=[],
        recon_url=RECON_URL,
        entry_point=ENTRY_POINT,
    )


def _deps(**overrides: Any) -> dict:
    deps = dict(
        auth=AuthorizationStateMachine(event_store=InMemoryEventStore()),
        http_client=_WpChainFake(),
        orchestrator=_orchestrator(),
        graph_store=NetworkXGraphStore(),
        event_store=InMemoryEventStore(),
        secrets_manager=SecretsManager(),
    )
    deps.update(overrides)
    return deps


def _db_login(graph: NetworkXGraphStore, secrets: SecretsManager) -> tuple[str, str]:
    cred_nodes = graph.nodes_by_type(
        __import__("agent_alpha.graph.nodes", fromlist=["NodeType"]).NodeType.CREDENTIAL
    )
    for node in cred_nodes:
        props = node.properties
        if props.service == "database" and props.username:
            password = secrets.retrieve(props.secret_ref)
            return props.username, password
    return "", ""


# ── T1: runner invokes verify_wp_config_leak (anti-#2) ──────────────────────


def test_runner_invokes_verify_wp_config_leak(monkeypatch) -> None:
    called = {"n": 0}
    real = wp_chain_runner.verify_wp_config_leak

    def spy(**kw):
        called["n"] += 1
        return real(**kw)

    monkeypatch.setattr(wp_chain_runner, "verify_wp_config_leak", spy)
    run_wp_chain_live_fire(_config(), **_deps())
    assert called["n"] == 1


# ── T2: served wp-config.php.bak → paired database:login credential ─────────


def test_wp_backup_leak_produces_paired_credential_in_run() -> None:
    deps = _deps()
    run_wp_chain_live_fire(_config(), **deps)
    assert _db_login(deps["graph_store"], deps["secrets_manager"]) == (LEAKED_USER, LEAKED_PASS)


# ── T3: bare-IP entry_point → cohost gate rejects, nothing proven ────────────


def test_entry_point_must_be_owned_domain_not_bare_ip() -> None:
    config = _config()
    # Use a dataclass replace to override entry_point with bare IP
    config = WpChainConfig(
        client_id=config.client_id,
        scope_ip_ranges=config.scope_ip_ranges,
        scope_domains=config.scope_domains,
        scope_exclusions=config.scope_exclusions,
        recon_url=config.recon_url,
        entry_point="https://127.0.0.1/wp-login.php",
    )
    deps = _deps()
    res = run_wp_chain_live_fire(config, **deps)
    assert res.web_access_level == ""
    assert res.chain_proven is False


# ── T4: leak without verified web login → chain_proven False (anti-#3) ───────


def test_chain_not_proven_without_web_access() -> None:
    deps = _deps(http_client=_WpChainFake(login_fails=True))
    res = run_wp_chain_live_fire(_config(), **deps)
    assert res.leak_creds_added > 0
    assert res.chain_proven is False


# ── T5: WAF block (403) surfaces in result, not as "clean" ──────────────────


def test_waf_block_surfaces_in_result_not_as_clean() -> None:
    deps = _deps(http_client=_WpChainFake(backup_status=403))
    res = run_wp_chain_live_fire(_config(), **deps)
    assert res.waf_blocked is True
    assert res.leak_creds_added == 0
    assert res.chain_proven is False
