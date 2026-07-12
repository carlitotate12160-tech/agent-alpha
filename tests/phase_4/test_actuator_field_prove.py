"""RED (slice-1c) — actuator field-prove runner VERDICT logic + shared vault gate."""

from __future__ import annotations

import pathlib
import types

import pytest

from agent_alpha.graph.nodes import NodeType
from agent_alpha.live_fire.actuator_field_prove import (
    ActuatorResult,
    load_actuator_config,
)
from agent_alpha.live_fire.field_prove_common import credential_vaulted
from agent_alpha.security.secrets import SecretNotFoundError


def _result(**over: object) -> ActuatorResult:
    base: dict[str, object] = {
        "creds_added": 1,
        "credential_vaulted": True,
        "leak_detected": True,
    }
    base.update(over)
    return ActuatorResult(**base)  # type: ignore[arg-type]


# ── chain_proven clause matrix (every clause REQUIRED — anti-#3) ───────────────
def test_all_clauses_true_is_proven() -> None:
    assert _result().chain_proven is True


def test_no_credential_is_not_proven() -> None:
    assert _result(creds_added=0).chain_proven is False


def test_unvaulted_credential_is_not_proven() -> None:
    assert _result(credential_vaulted=False).chain_proven is False


def test_no_real_leak_is_not_proven() -> None:
    assert _result(leak_detected=False).chain_proven is False


# ── shared credential_vaulted helper (anti-#6 hoist): CREDENTIAL node whose
#    secret_ref resolves in the vault. SAME gate git_exposure uses. ────────────
class _Node:
    def __init__(self, secret_ref: str) -> None:
        self.properties = types.SimpleNamespace(secret_ref=secret_ref)


class _Graph:
    def __init__(self, creds: list[_Node]) -> None:
        self._creds = creds

    def nodes_by_type(self, node_type: object) -> list[_Node]:
        return self._creds if node_type == NodeType.CREDENTIAL else []


class _Vault:
    def __init__(self, resolvable: set[str]) -> None:
        self._resolvable = resolvable

    def retrieve(self, ref: str) -> str:
        if ref in self._resolvable:
            return "recovered-secret-value"
        raise SecretNotFoundError(ref)


def test_credential_vaulted_true_when_ref_resolves() -> None:
    assert credential_vaulted(_Graph([_Node("secret_abc123")]), _Vault({"secret_abc123"})) is True


def test_credential_vaulted_false_for_inline_pointer() -> None:
    assert credential_vaulted(_Graph([_Node("inline:appuser")]), _Vault(set())) is False


def test_credential_vaulted_false_when_ref_unresolvable() -> None:
    assert credential_vaulted(_Graph([_Node("secret_missing")]), _Vault(set())) is False


def test_credential_vaulted_false_on_empty_graph() -> None:
    assert credential_vaulted(_Graph([]), _Vault(set())) is False


# ── config loader guards the payable contract (self-owned lab only) ───────────
def test_config_loader_rejects_missing_key(tmp_path: object) -> None:
    p = pathlib.Path(str(tmp_path)) / "bad.yaml"
    p.write_text("client_id: x\n")
    with pytest.raises(ValueError):
        load_actuator_config(p)
