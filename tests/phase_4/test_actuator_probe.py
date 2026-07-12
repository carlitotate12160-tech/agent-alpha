# Slice C (rule-of-three) — the path_probe catalog absorbs a 3rd stack (Spring Boot
# Actuator /env) as PURE DATA: one PathProbeSpec + one leak_extraction format + one
# playbook rule + constants. The ENGINE (process_path_hit) is NOT modified — actuator
# is DIRECT recover like backup_file. If this needs an engine change, the abstraction
# leaked; it does not.
#
#   A1 unmasked datasource creds in /actuator/env (2.x shape) -> vaulted CREDENTIAL.
#   A2 MASKED password (******) -> 0 creds (Spring masks by default; presence != payable, anti-#3).
#   A3 JSON that is not an actuator env dump -> 0 creds.
#   A4 flat 1.x actuator shape -> vaulted CREDENTIAL (robustness).
#   A5 playbook selects actuator_probe for an actuator body.
#   A6 rule-of-three structural pin: actuator is a DIRECT spec in the catalog (no new
#      RecoverStrategy = no engine change).
#
# Run on Oracle ARM64 only.

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.graph.nodes import NodeType
from agent_alpha.recon.path_probe import (
    PATH_PROBE_CATALOG,
    RecoverStrategy,
    process_path_hit,
    spec_for_tool,
)
from agent_alpha.security.secrets import SecretsManager
from agent_alpha.tools.playbook import PlaybookEngine

_HOST = "vuln.example"
_ENV_URL = f"https://{_HOST}/actuator/env"
_PLAYBOOK_DIR = pathlib.Path("agent_alpha/tools/playbooks")
_SPEC = spec_for_tool("actuator_probe")


def _env_2x(password: str = "S3cretPw") -> str:
    return json.dumps(
        {
            "activeProfiles": ["prod"],
            "propertySources": [
                {"name": "systemProperties", "properties": {"java.version": {"value": "17"}}},
                {
                    "name": "applicationConfig",
                    "properties": {
                        "spring.datasource.username": {"value": "appuser"},
                        "spring.datasource.password": {"value": password},
                        "spring.datasource.url": {
                            "value": "jdbc:postgresql://db.internal:5432/app_prod"
                        },
                    },
                },
            ],
        }
    )


_ENV_1X = json.dumps(
    {
        "applicationConfig: [classpath:/application.properties]": {
            "spring.datasource.username": "appuser",
            "spring.datasource.password": "S3cretPw",
        }
    }
)


@dataclass
class FakeResponse:
    status_code: int
    text: str = ""


def _recon(store: InMemoryEventStore, *, state=a2a_pb2.RECON_ONLY):
    auth = AuthorizationStateMachine(event_store=store)
    rec = auth.create_engagement(client_id="spring_lab", target=_HOST)
    if state == a2a_pb2.RECON_ONLY:
        auth.enable_recon(
            rec.engagement_id,
            Scope(ip_ranges=[], domains=[_HOST], exclusions=[], db_endpoints=[]),
        )
    return auth, rec.engagement_id


def _run(resp: FakeResponse):
    store = InMemoryEventStore()
    graph = NetworkXGraphStore()
    secrets = SecretsManager()
    auth, eid = _recon(store)
    added = process_path_hit(
        _SPEC,
        resp=resp,
        url=_ENV_URL,
        engagement_id=eid,
        auth=auth,
        graph_store=graph,
        event_store=store,
        secrets_manager=secrets,
    )
    creds = list(graph.nodes_by_type(NodeType.CREDENTIAL))
    return added, creds, secrets


def test_a1_unmasked_actuator_env_mints_vaulted_credential() -> None:
    added, creds, secrets = _run(FakeResponse(200, _env_2x()))
    assert added >= 1
    ref = getattr(creds[0].properties, "secret_ref", "")
    assert ref.startswith("secret_")
    assert secrets.retrieve(ref) == "S3cretPw"


def test_a2_masked_password_mints_nothing() -> None:
    added, creds, _ = _run(FakeResponse(200, _env_2x(password="******")))
    assert added == 0
    assert creds == []


def test_a3_non_actuator_json_mints_nothing() -> None:
    added, creds, _ = _run(FakeResponse(200, json.dumps({"status": "UP"})))
    assert added == 0
    assert creds == []


def test_a4_flat_1x_actuator_shape_mints_credential() -> None:
    added, creds, _ = _run(FakeResponse(200, _ENV_1X))
    assert added >= 1


def test_a5_playbook_selects_actuator_probe() -> None:
    engine = PlaybookEngine.from_directory(_PLAYBOOK_DIR)
    decision = engine.match({"body": _env_2x(), "headers": {}})
    assert decision is not None
    assert decision.tool == "actuator_probe"


def test_a6_actuator_is_a_direct_catalog_spec_no_engine_change() -> None:
    spec = spec_for_tool("actuator_probe")
    assert spec is not None
    assert spec.recover is RecoverStrategy.DIRECT  # reuses backup's strategy → no new engine path
    assert spec in PATH_PROBE_CATALOG
