"""Offline CI guard for the try-harder field-prove (D2-b).

Mirrors the two-run differential from live_fire/recon_tryhard_field_prove.py
but runs entirely offline using a FakeHttpClient and a deterministic
stub orchestrator.

Asserts:
- A misses late-leak
- B finds+vaults it
- decoy/waf/dead/hardened behave as ground-truth
"""

from __future__ import annotations

import pathlib

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.base import BoundedAutonomy, run_cognitive_loop
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.config import constants
from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.live_fire.field_prove_common import credential_vaulted
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

from .conftest import FakeHttpClient, FakeHttpResponse


class _DeterministicStubProvider:
    """A deterministic stub provider for the orchestrator."""

    model = "deepseek-v4-pro"

    def complete(self, *a: object, **k: object):
        """Mock completion yielding a deterministic generic_http_probe response."""
        # Always return generic_http_probe for boring roots to avoid LLM calls
        return type(
            "R",
            (),
            {
                "text": '{"tool": "generic_http_probe", "reasoning": "stub"}',
                "usage_cost_usd": 0.0,
                "model": "deepseek-v4-pro",
            },
        )()


def test_recon_tryhard_differential() -> None:
    """Offline CI guard for Try-Harder dead-end recovery."""

    # ── Configuration ────────────────────────────────────────────
    client_id = "ci_test_client"
    scope_domains = [
        "apex.recon.lab",
        "late.recon.lab",
        "waf.recon.lab",
        "decoy.recon.lab",
        "dead.recon.lab",
        "hardened.recon.lab",
    ]
    recon_url = "https://apex.recon.lab"
    seed_hosts = [
        "https://late.recon.lab/",
        "https://waf.recon.lab/",
        "https://decoy.recon.lab/",
        "https://dead.recon.lab/",
        "https://hardened.recon.lab/",
    ]

    # ── Synthetic Network ────────────────────────────────────────
    fake_env_body = "DB_USERNAME=admin\nDB_PASSWORD=supersecret\n"
    fake_cf_challenge = "<html><body>cf-browser-verification</body></html>"

    routes = {
        "https://late.recon.lab/": FakeHttpResponse(
            status_code=200, text="boring root", headers={}, url="https://late.recon.lab/"
        ),
        "https://late.recon.lab/.env.bak": FakeHttpResponse(
            status_code=200, text=fake_env_body, headers={}, url="https://late.recon.lab/.env.bak"
        ),
        "https://decoy.recon.lab/.env.bak": FakeHttpResponse(
            status_code=200, text="", headers={}, url="https://decoy.recon.lab/.env.bak"
        ),
        "https://waf.recon.lab/": FakeHttpResponse(
            status_code=200,
            text=fake_cf_challenge,
            headers={"server": "cloudflare"},
            url="https://waf.recon.lab/",
        ),
        "https://dead.recon.lab/": FakeHttpResponse(
            status_code=503, text="Service Unavailable", headers={}, url="https://dead.recon.lab/"
        ),
        "https://hardened.recon.lab/": FakeHttpResponse(
            status_code=200, text="clean", headers={}, url="https://hardened.recon.lab/"
        ),
        "https://apex.recon.lab/": FakeHttpResponse(
            status_code=200, text="apex root", headers={}, url="https://apex.recon.lab/"
        ),
    }

    # PlaybookEngine
    playbook_dir = (
        pathlib.Path(__file__).resolve().parent.parent.parent
        / "agent_alpha"
        / "tools"
        / "playbooks"
    )
    orchestrator = LLMOrchestrator(
        playbook=PlaybookEngine.from_directory(playbook_dir), provider=_DeterministicStubProvider()
    )

    def _run_pass(try_harder_enabled: bool):
        """Run Alpha through a single pass with isolated state."""
        event_store = InMemoryEventStore()
        auth = AuthorizationStateMachine(event_store=event_store)
        secrets_manager = SecretsManager()
        graph_store = NetworkXGraphStore()
        http_client = FakeHttpClient(routes)

        rec = auth.create_engagement(client_id=client_id, target=recon_url)
        auth.enable_recon(
            rec.engagement_id, Scope(ip_ranges=[], domains=scope_domains, exclusions=[])
        )

        alpha = Alpha(
            authorization=auth,
            graph_store=graph_store,
            event_store=event_store,
            orchestrator=orchestrator,
            http_client=http_client,
            secrets_manager=secrets_manager,
            try_harder_enabled=try_harder_enabled,
        )

        alpha._engagement_id = rec.engagement_id
        alpha._work_queue = []
        alpha._probed = set()
        alpha._findings = 0
        alpha._analyzable_probes = 0
        alpha._ran_campaigns = set()
        alpha._body_hashes = set()
        alpha._current_objective = None
        alpha._try_harder_fired = False

        for host_url in seed_hosts:
            alpha.enqueue_discovered_url(host_url)

        policy = BoundedAutonomy(no_progress_threshold=constants.ALPHA_RECON_NO_PROGRESS_ITERS)
        run_cognitive_loop(alpha, policy, event_store=event_store, engagement_id=rec.engagement_id)

        cred_nodes = list(graph_store.nodes_by_type(NodeType.CREDENTIAL))
        late_creds = [
            n
            for n in cred_nodes
            if "late.recon.lab" in str(n.id)
            or "late.recon.lab" in getattr(n.properties, "host", "")
        ]
        is_vaulted = credential_vaulted(graph_store, secrets_manager)

        return len(late_creds), is_vaulted, graph_store, event_store, rec.engagement_id

    # ── Run A (OFF) ──────────────────────────────────────────────
    a_creds, _, _, _, _ = _run_pass(try_harder_enabled=False)
    assert a_creds == 0, "Run A (greedy) should miss late.recon.lab/.env.bak"

    # ── Run B (ON) ───────────────────────────────────────────────
    b_creds, b_vaulted, b_graph, b_events, b_engagement_id = _run_pass(try_harder_enabled=True)
    assert b_creds > 0, "Run B (planner) should find late.recon.lab/.env.bak"
    assert b_vaulted, "Run B credential should be vaulted"

    # ── Additional Assertions ────────────────────────────────────
    b_all_creds = list(b_graph.nodes_by_type(NodeType.CREDENTIAL))

    decoy_creds = len(
        [
            n
            for n in b_all_creds
            if "decoy.recon.lab" in str(n.id)
            or "decoy.recon.lab" in getattr(n.properties, "host", "")
        ]
    )
    assert decoy_creds == 0, "decoy.recon.lab should mint 0 credentials"

    hardened_creds = len(
        [
            n
            for n in b_all_creds
            if "hardened.recon.lab" in str(n.id)
            or "hardened.recon.lab" in getattr(n.properties, "host", "")
        ]
    )
    assert hardened_creds == 0, "hardened.recon.lab should mint 0 credentials"

    dead_creds = len(
        [
            n
            for n in b_all_creds
            if "dead.recon.lab" in str(n.id)
            or "dead.recon.lab" in getattr(n.properties, "host", "")
        ]
    )
    assert dead_creds == 0, "dead.recon.lab should mint 0 credentials"
    events = b_events.get_events(b_engagement_id)

    waf_events = [
        e
        for e in events
        if e.event_type == EventType.WAF_BLOCKED and e.payload.get("host") == "waf.recon.lab"
    ]
    assert len(waf_events) > 0, "waf.recon.lab should trigger WAF_BLOCKED"
    assert any(e.payload.get("signal") == "cf_challenge" for e in waf_events), (
        "waf.recon.lab should emit cf_challenge signal"
    )

    dead_events = [
        e
        for e in events
        if e.event_type == EventType.WAF_BLOCKED and e.payload.get("host") == "dead.recon.lab"
    ]
    assert len(dead_events) > 0, (
        "dead.recon.lab 503 should be classified as BLOCKED (non-analyzable)"
    )
