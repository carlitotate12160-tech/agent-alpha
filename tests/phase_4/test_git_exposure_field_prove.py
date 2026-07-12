"""RED (slice-1c-ii) — git_exposure field-prove runner VERDICT logic."""

from __future__ import annotations

import pathlib
import types

import pytest

from agent_alpha.graph.nodes import NodeType
from agent_alpha.live_fire.git_exposure_field_prove import (
    GitExposureResult,
    _credential_vaulted,
    load_git_exposure_config,
)
from agent_alpha.security.secrets import SecretNotFoundError


def _result(**over: object) -> GitExposureResult:
    base: dict[str, object] = {
        "creds_added": 1,
        "credential_vaulted": True,
        "exposure_detected": True,
    }
    base.update(over)
    return GitExposureResult(**base)  # type: ignore[arg-type]


# ── chain_proven clause matrix (every clause is REQUIRED — anti-#3) ────────────
def test_all_clauses_true_is_proven() -> None:
    assert _result().chain_proven is True


def test_no_credential_is_not_proven() -> None:
    assert _result(creds_added=0).chain_proven is False


def test_unvaulted_credential_is_not_proven() -> None:
    assert _result(credential_vaulted=False).chain_proven is False


def test_no_real_exposure_is_not_proven() -> None:
    assert _result(exposure_detected=False).chain_proven is False


# ── _credential_vaulted helper: a CREDENTIAL node whose secret_ref resolves ────
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
    graph = _Graph([_Node("secret_abc123")])
    vault = _Vault({"secret_abc123"})
    assert _credential_vaulted(graph, vault) is True


def test_credential_vaulted_false_for_inline_pointer() -> None:
    graph = _Graph([_Node("inline:appuser")])
    vault = _Vault(set())
    assert _credential_vaulted(graph, vault) is False


def test_credential_vaulted_false_when_ref_unresolvable() -> None:
    graph = _Graph([_Node("secret_missing")])
    vault = _Vault(set())
    assert _credential_vaulted(graph, vault) is False


def test_credential_vaulted_false_on_empty_graph() -> None:
    assert _credential_vaulted(_Graph([]), _Vault(set())) is False


# ── config loader guards the payable contract (self-owned lab only) ───────────
def test_config_loader_rejects_missing_key(tmp_path: object) -> None:
    p = pathlib.Path(str(tmp_path)) / "bad.yaml"
    p.write_text("client_id: x\n")
    with pytest.raises(ValueError):
        load_git_exposure_config(p)
