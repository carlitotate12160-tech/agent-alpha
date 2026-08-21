# CodeIgniter config-leak field-prove test (Phase 4 slice-1c-1).
#
# Validates the CodeIgniter leak vector end-to-end on the self-owned lab:
# Alpha.run_recon → fingerprint 'codeigniter' → derive /application/config/database.php
# → dispatch codeigniter_config_probe → parse DB credentials → vault → mint.
#
# Lab must be up on Oracle ARM64:
#   cd codeigniter_lab && sudo ./seed.sh
#
# Run on Oracle ARM64 only:
#   python -m pytest tests/phase_4/test_codeigniter_field_prove.py -v

from __future__ import annotations

import pathlib

import httpx
import pytest

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.agents.http_client import HttpClient
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.llm.orchestrator import LLMOrchestrator
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")
_VULN_HOST = "vuln.codeigniter.lab"
_HARDENED_HOST = "hardened.codeigniter.lab"
_VULN_ROOT = f"https://{_VULN_HOST}:8444/"
_HARDENED_ROOT = f"https://{_HARDENED_HOST}:8444/"
_EXPECTED_USER = "ci_lab_user"
_EXPECTED_PASSWORD = "CiLabPassword123"


class _NoLLMProvider:
    model = "noop"

    @staticmethod
    def complete(*a: object, **k: object) -> object:
        return type("R", (), {"text": "{}", "usage_cost_usd": 0.0, "model": "noop"})()


def _alpha(*, host: str, graph_store: NetworkXGraphStore, event_store: InMemoryEventStore) -> Alpha:
    auth = AuthorizationStateMachine(event_store=event_store)
    rec = auth.create_engagement(client_id="codeigniter-lab", target=host)
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=[], domains=[host], exclusions=[]),
    )
    return Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=LLMOrchestrator(
            PlaybookEngine.from_directory(_PLAYBOOK_DIR),
            _NoLLMProvider(),
        ),
        http_client=HttpClient(
            engagement_id=rec.engagement_id,
            transport=httpx.HTTPTransport(verify=False),  # force plain httpx, not curl_cffi, for self-signed lab cert
        ),
        secrets_manager=SecretsManager(),
    ), rec.engagement_id


def _lab_reachable() -> bool:
    client = HttpClient(
        engagement_id="reachability-check",
        transport=httpx.HTTPTransport(verify=False),
    )
    try:
        resp = client.get(_VULN_ROOT)
        return resp.status_code == 200 and "csrf_test_name" in resp.text
    except Exception:
        return False


@pytest.mark.skipif(not _lab_reachable(), reason="codeigniter_lab not reachable — run codeigniter_lab/seed.sh")
def test_vuln_codeigniter_leaks_database_credentials() -> None:
    """Full live path: fingerprint CI → derive config path → extract DB creds."""
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    alpha, eid = _alpha(host=_VULN_HOST, graph_store=graph, event_store=store)

    alpha.run_recon(eid, _VULN_ROOT)

    creds = list(graph.nodes_by_type(NodeType.CREDENTIAL))
    assert len(creds) >= 1, "no CREDENTIAL minted — codeigniter config was not extracted"

    # Verify the EXACT planted secret was vaulted.
    secret = alpha._secrets_manager.retrieve(creds[0].properties.secret_ref)
    assert secret == _EXPECTED_PASSWORD, f"vaulted secret {secret!r} != planted {_EXPECTED_PASSWORD!r}"

    # Vuln node present and CVSS is HIGH.
    vulns = [n for n in graph.nodes_by_type(NodeType.VULNERABILITY) if "ci_config" in n.id]
    assert len(vulns) >= 1, "no ci_config_leak vulnerability node persisted"
    assert vulns[0].properties.cvss_score >= 7.0


@pytest.mark.skipif(not _lab_reachable(), reason="codeigniter_lab not reachable — run codeigniter_lab/seed.sh")
def test_hardened_codeigniter_yields_zero_credentials() -> None:
    """Negative control: a host without CI markers / exposed config leaks nothing."""
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    alpha, eid = _alpha(host=_HARDENED_HOST, graph_store=graph, event_store=store)

    alpha.run_recon(eid, _HARDENED_ROOT)

    creds = list(graph.nodes_by_type(NodeType.CREDENTIAL))
    assert not creds, f"hardened host minted unexpected credentials: {creds}"
