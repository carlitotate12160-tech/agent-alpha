"""slice-1d: the AUTONOMOUS Conductor path proves a CROSS_VERIFIED WordPress cred-reuse
chain end-to-end — run_engagement_task → advance → run_agent_task(Beta) → advance(+verify)
→ run_agent_task(Omega) — WITHOUT wp_chain_runner. One WP fake serves both the recon leg
(wp-config.php.bak leak) and the strike leg (wp-login success). Eager Celery runs the whole
chain from one trigger. This is the RUNNER-SEAL != AUTONOMOUS-WIRED closure for niagamas.

TEST-ONLY: zero production edits. Fakes are monkeypatched at module symbols — the same
pattern the existing Alpha test (test_async_kill_chain) uses.
"""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass, field
from typing import Any

os.environ.setdefault("AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-32chars-min")
os.environ.setdefault("DEEPSEEK_API_KEY", "test-key-for-eager-dispatch")

import agent_alpha
from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor import main as m
from agent_alpha.conductor import recon_runner
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.conductor.reporting import build_engagement_report
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType, VerificationTier
from agent_alpha.live_fire.beta_runner import _NoLLMProvider
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.tools.playbook import PlaybookEngine

# Real playbooks so the WP fingerprint + wp_config_probe rules fire at RULE tier (no LLM).
PLAYBOOK_DIR = pathlib.Path(agent_alpha.__file__).parent / "tools" / "playbooks"

LEAKED_USER = "wpuser"
LEAKED_PASS = "s3cret-wp-x7q2"
WP_CONFIG_BODY = (
    "<?php\n"
    "define('DB_NAME', 'wp_lab');\n"
    f"define('DB_USER', '{LEAKED_USER}');\n"
    f"define('DB_PASSWORD', '{LEAKED_PASS}');\n"
    "define('DB_HOST', 'localhost');\n"
)
LOGIN_PAGE = (
    '<html><form><input type="text" name="log">'
    '<input type="password" name="pwd"></form> wp-login</html>'
)
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


class _WpAutonomousFake:
    """One fake for BOTH legs. Substring-matched (scheme/host-robust) so it serves whatever
    URL autonomous recon or the applicator constructs. Mirrors _WpChainFake in
    test_wp_chain_runner.py + tracks .calls (anti-#3: prove the agents actually read)."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get(
        self,
        url: str,
        *,
        headers: Any = None,
        cookies: Any = None,
        timeout: float = 10.0,
        allow_redirects: bool = True,
        **_kwargs: Any,  # absorb OriginAwareClient pass-throughs (verify, …) like a real client
    ) -> _R:
        self.calls.append(url)
        if "wp-config.php.bak" in url:
            return _R(200, WP_CONFIG_BODY, {}, url)
        if "wp-config" in url:  # other backup variants → 404
            return _R(404, "", {}, url)
        if "wp-login" in url:  # login page baseline GET
            return _R(200, LOGIN_PAGE, {}, url)
        if cookies:  # applicator session-confirm step
            return _R(200, DASHBOARD, {}, url)
        # root / any other recon page → matches wp_config playbook (body_contains: "wp-content")
        return _R(
            200,
            "<html>WordPress site <link href='/wp-content/themes/style.css'></html>",
            {"server": "apache", "x-powered-by": "PHP/8.2"},
            url,
        )

    def post(
        self,
        url: str,
        *,
        data: Any = None,
        json_body: Any = None,
        headers: Any = None,
        cookies: Any = None,
        allow_redirects: bool = True,
        **_kwargs: Any,  # absorb OriginAwareClient pass-throughs (verify, …) like a real client
    ) -> _R:
        self.calls.append(url)
        if "wp-login" in url:
            if (data or {}).get("pwd", "") == LEAKED_PASS:  # WpLoginApplicator posts log/pwd
                return _R(
                    200,
                    DASHBOARD,
                    {"set-cookie": "wordpress_logged_in_abc=1; Path=/; HttpOnly"},
                    url,
                )
            return _R(200, LOGIN_PAGE, {}, url)  # generic/wrong creds → fail
        return _R(404, "", {}, url)


class _StubProvider:
    model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": self.model})()


def _project(event_store: Any, engagement_id: str) -> NetworkXGraphStore:
    from agent_alpha.conductor.execute_agent import rebuild_graph_from_events

    return rebuild_graph_from_events(event_store, engagement_id)


def test_autonomous_conductor_chain_produces_cross_verified_wp_finding(
    celery_eager_config: None,
    monkeypatch: Any,
) -> None:
    host = "wp.lab.invalid"
    root = f"https://{host}/"
    fake = _WpAutonomousFake()

    # 1) Engagement authorized to ACTIVE_APPROVED (Beta needs ACTIVE; Alpha still allowed).
    store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement("wp_client", root, tenant_id="tenant_wp")
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[host], exclusions=[]))
    auth.enable_active(rec.engagement_id)  # Beta gate = ACTIVE_APPROVED
    m.store_provider._stores["tenant_wp"] = store  # route the worker's tenant store

    # §12.36 fail-closed: the authorized worker path now requires a signed profile.
    from agent_alpha.conductor.engagement_profile import EngagementProfile, dump_signed_profile
    from agent_alpha.events.event_types import EventType
    from agent_alpha.security.secrets import get_profile_signing_key

    store.append(
        event_type=EventType.ENGAGEMENT_PROFILE_SIGNED,
        engagement_id=rec.engagement_id,
        agent="CONDUCTOR",
        payload=dump_signed_profile(
            EngagementProfile(
                engagement_id=rec.engagement_id, client_id="wp_client", targets=frozenset({host})
            ),
            key=get_profile_signing_key(),
        ),
    )

    # 2) Alpha leg — real Alpha over the WP fake (build_recon_pipeline seam, like the async test).
    graph = NetworkXGraphStore()
    orchestrator = LLMOrchestrator(PlaybookEngine.from_directory(PLAYBOOK_DIR), _NoLLMProvider())

    def fake_build(
        engagement_id: str,
        tenant_id: str | None,
        auth_: object,
        store_: object,
        secrets_manager: object = None,
        publisher: object = None,
        session_store: object = None,
        *,
        policy: object = None,
        origin_discovery: object = None,
        browser_solve: object = None,
        engagement_profile: object = None,
        browser_solve_viable: bool = False,
    ) -> recon_runner.ReconPipeline:
        alpha = Alpha(
            authorization=auth_,
            graph_store=graph,
            event_store=store_,
            orchestrator=orchestrator,
            http_client=fake,
            secrets_manager=secrets_manager,
            session_store=session_store,
        )
        return recon_runner.ReconPipeline(alpha=alpha, graph_store=graph)

    monkeypatch.setattr(recon_runner, "build_recon_pipeline", fake_build)
    monkeypatch.setattr(recon_runner, "resolve_recon_targets", lambda record: [root])

    # 3) Beta/Omega leg — patch the two module constructors run_agent_task builds (same technique).
    monkeypatch.setattr(m, "HttpClient", lambda **kw: fake)
    monkeypatch.setattr(m, "resolve_reasoning_provider", lambda **kw: _StubProvider())

    # 4) One trigger → eager cascade Alpha→advance→Beta→advance(+verify)→Omega.
    m.run_engagement_task(rec.engagement_id, "tenant_wp")

    # 5) The AUTONOMOUS proof.
    result_graph = _project(store, rec.engagement_id)
    access = list(result_graph.nodes_by_type(NodeType.ACCESS_LEVEL))
    assert access, "no ACCESS_LEVEL — Beta cred-reuse did not run on the autonomous path"
    assert access[0].verification == VerificationTier.CROSS_VERIFIED, (
        "access not cross_verified — run_verification_pass (slice-1c) not firing on the live path"
    )
    kinds = [str(getattr(e, "event_type", "")) for e in store.get_events(rec.engagement_id)]
    assert any("NodeVerified" in k for k in kinds), "no NodeVerified audit event"
    report = build_engagement_report(result_graph, store, rec.engagement_id, style="technical")
    assert report.chain_finding is not None, "Omega produced no cred-reuse chain finding"
