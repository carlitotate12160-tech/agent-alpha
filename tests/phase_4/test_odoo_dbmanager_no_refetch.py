# RED tests — Odoo DB-manager NO-REFETCH core (mirror test_path_probe_no_refetch).
#
# TODAY _handle_odoo_dbmanager delegates to verify_odoo_dbmanager_exposure, which
# performs its OWN https GET of /web/database/manager per host — a second fetch of
# the page the cognitive loop already retrieved (double-recon, the F1 smell the
# path_probe engine already closed for git/backup/actuator). The fix introduces
# process_odoo_dbmanager_hit: a PER-RESPONSE core that classifies the ALREADY-
# FETCHED body and takes NO http client, so it is structurally incapable of
# re-fetching. This file pins that guarantee two ways.
#
#   N1  process_odoo_dbmanager_hit's signature has NO http/client parameter.
#   N2a DIRECT: given ONE injected FakeResponse, the core persists the exposure
#       from THAT body (no collaborator it holds performs a GET).
#   N2b HANDLER: driven through the real scout dispatch with an http client that
#       RAISES on any .get, the handler persists the exposure and never calls .get
#       (proves the double-fetch is gone at the wiring seam, not just the core).
#
# Expected RED (production not written yet): N1/N2a error on the missing
# process_odoo_dbmanager_hit symbol; N2b fails because the current re-fetching
# handler calls the raising client (swallowed -> no exposure persisted).
#
# Run on Oracle ARM64 only:
#   .venv312/bin/python3 -m pytest \
#     tests/phase_4/test_odoo_dbmanager_no_refetch.py -v

from __future__ import annotations

import inspect
from dataclasses import dataclass, field

from agent_alpha.agents.alpha.scout import Alpha
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.recon.odoo_dbmanager_probe import (
    ODOO_DBMANAGER_ACTION_MARKERS,
    ODOO_DBMANAGER_MIN_ACTION_MARKERS,
    ODOO_DBMANAGER_PATH,
    process_odoo_dbmanager_hit,
)
from agent_alpha.tools.playbook import PlaybookDecision

_HOST = "odoo.example"
_MANAGER_URL = f"https://{_HOST}{ODOO_DBMANAGER_PATH}"
_VULN_ID = f"vuln:{_HOST}:odoo_dbmanager_exposed"

# EXPOSED body reused from the probe's SSOT markers (anti-#7).
_ACTION_MARKERS = ODOO_DBMANAGER_ACTION_MARKERS[:ODOO_DBMANAGER_MIN_ACTION_MARKERS]
_EXPOSED_MANAGER_BODY = (
    "<html><body>master_pwd list_db " + " ".join(_ACTION_MARKERS) + "</body></html>"
)


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)


class _RaisingHttpClient:
    """Any .get is a double-fetch violation. Records the attempt (so the assertion
    reports it) and raises — the current verifier swallows this and yields no
    finding, which is exactly the RED signal for the re-fetch regression."""

    def __init__(self) -> None:
        self.get_calls: list[str] = []

    def get(self, url: str) -> FakeResponse:
        self.get_calls.append(url)
        raise AssertionError(f"no HTTP re-fetch permitted (F1 double-recon guard): GET {url}")


class _InertOrchestrator:
    """Unused by the handler path under test; present only to satisfy Alpha()."""

    def decide(self, observation: dict[str, object]) -> None:  # pragma: no cover - never called
        raise AssertionError("orchestrator must not be consulted in the no-refetch handler test")


def _recon(store: InMemoryEventStore) -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="odoo_lab", target=_HOST)
    auth.enable_recon(rec.engagement_id, Scope(ip_ranges=[], domains=[_HOST], exclusions=[]))
    return auth, rec.engagement_id


def test_n1_core_takes_no_http_client() -> None:
    params = set(inspect.signature(process_odoo_dbmanager_hit).parameters)
    assert not (params & {"http_client", "http", "client", "session"}), (
        "process_odoo_dbmanager_hit must not accept an HTTP client "
        f"(no re-fetch by construction). params={params}"
    )


def test_n2a_direct_persists_exposure_from_injected_body() -> None:
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    auth, eid = _recon(store)

    added = process_odoo_dbmanager_hit(
        resp=FakeResponse(200, _EXPOSED_MANAGER_BODY),
        url=_MANAGER_URL,
        engagement_id=eid,
        auth=auth,
        graph_store=graph,
        event_store=store,
    )

    assert added >= 1, "an EXPOSED manager body must persist at least the exposure node"
    vuln_ids = {n.id for n in graph.nodes_by_type(NodeType.VULNERABILITY)}
    assert _VULN_ID in vuln_ids, "the exposure VULNERABILITY is minted purely from the injected body"


def test_n2b_handler_persists_without_refetching() -> None:
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    auth, eid = _recon(store)
    raising = _RaisingHttpClient()

    alpha = Alpha(
        authorization=auth,
        graph_store=graph,
        event_store=store,
        orchestrator=_InertOrchestrator(),
        http_client=raising,
    )
    # Minimal per-run state the dispatch handler reads (run_recon would set these).
    alpha._engagement_id = eid
    alpha._ran_campaigns = set()
    alpha._findings = 0

    decision = PlaybookDecision(
        tool="odoo_dbmanager_probe", tier="rule", technique_id="T1595.002"
    )
    # The handler is handed the response the loop ALREADY fetched; it must classify
    # THAT body and never reach back to the network.
    alpha._handle_odoo_dbmanager(FakeResponse(200, _EXPOSED_MANAGER_BODY), decision, _MANAGER_URL)

    assert raising.get_calls == [], (
        "the DB-manager handler re-fetched the page instead of classifying the "
        f"already-fetched body (double-recon regression): {raising.get_calls}"
    )
    vuln_ids = {n.id for n in graph.nodes_by_type(NodeType.VULNERABILITY)}
    assert _VULN_ID in vuln_ids, "the exposure must be persisted from the handed-in response"
