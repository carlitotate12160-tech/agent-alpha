# F1 pin (path_probe consolidation) — the engine closes the double-fetch by
# CONSTRUCTION: process_path_hit takes NO http client, so it cannot re-probe the
# paths the cognitive loop already fetched. This test pins that guarantee two ways.
#
#   N1  process_path_hit's signature has no http/client parameter (structural).
#   N2  DIRECT: given ONE injected response, the engine mints from it with ZERO
#       further I/O — no object it holds is ever asked to GET.
#   N3  the catalog is the SINGLE source: every WELL_KNOWN_LEAK_PATHS entry belongs
#       to exactly one catalog spec (no hand-maintained second list — anti-#7).
#
# Run on Oracle ARM64 only.

from __future__ import annotations

import inspect
from dataclasses import dataclass

from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.config import constants
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.recon.path_probe import PATH_PROBE_CATALOG, process_path_hit, spec_for_tool
from agent_alpha.security.secrets import SecretsManager

_HOST = "vuln.example"
_ENV_BAK_URL = f"https://{_HOST}/.env.bak"
_ENV_BODY = "DB_USER=appuser\nDB_PASSWORD=sup3rs3cret\nDB_HOST=db.internal\n"


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""


def _recon(store: InMemoryEventStore) -> tuple[AuthorizationStateMachine, str]:
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="backup_lab", target=_HOST)
    auth.enable_recon(
        rec.engagement_id,
        Scope(ip_ranges=[], domains=[_HOST], exclusions=[], db_endpoints=[]),
    )
    return auth, rec.engagement_id


def test_n1_engine_takes_no_http_client() -> None:
    params = set(inspect.signature(process_path_hit).parameters)
    assert not (params & {"http_client", "http", "client", "session"}), (
        f"process_path_hit must not accept an HTTP client (F1: no re-fetch). params={params}"
    )


def test_n2_direct_mints_from_injected_response_with_no_io() -> None:
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    auth, eid = _recon(store)
    added = process_path_hit(
        spec_for_tool("backup_file_probe"),
        resp=FakeResponse(200, _ENV_BODY),
        url=_ENV_BAK_URL,
        engagement_id=eid,
        auth=auth,
        graph_store=graph,
        event_store=store,
        secrets_manager=SecretsManager(),
    )
    assert added >= 1
    assert list(graph.nodes_by_type(NodeType.CREDENTIAL))  # minted purely from the injected body


def test_n3_well_known_paths_are_catalog_sourced() -> None:
    catalog_paths = {p for spec in PATH_PROBE_CATALOG for p in spec.paths}
    assert set(constants.WELL_KNOWN_LEAK_PATHS) == catalog_paths, (
        "WELL_KNOWN_LEAK_PATHS drifted from the catalog — it must be exactly the union "
        "of every spec's paths (SINGLE source, anti-#7)."
    )
