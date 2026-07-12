"""Tests for the Git Exposure chain runner logic (Phase 4)."""

from __future__ import annotations

import textwrap
from typing import Any

import pytest

from agent_alpha.conductor.authorization import AuthorizationStateMachine
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore
from agent_alpha.live_fire.git_exposure_chain_runner import (
    GitExposureChainConfig,
    run_git_exposure_chain_live_fire,
)
from agent_alpha.security.secrets import SecretsManager


class FakeHttpClient:
    def __init__(self) -> None:
        self.responses: dict[str, tuple[int, str]] = {}

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> FakeResponse:
        if url in self.responses:
            code, text = self.responses[url]
            return FakeResponse(code, text)
        return FakeResponse(404, "Not Found")


class FakeResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


class FakeGitDumper:
    def __init__(self) -> None:
        self.dumps: dict[str, dict[str, str]] = {}

    def dump(self, base_url: str) -> dict[str, str]:
        if base_url in self.dumps:
            return self.dumps[base_url]
        raise RuntimeError("Fake GitDumper failed")


@pytest.fixture
def fake_env() -> tuple[
    InMemoryEventStore,
    AuthorizationStateMachine,
    NetworkXGraphStore,
    SecretsManager,
    FakeHttpClient,
    FakeGitDumper,
]:
    event_store = InMemoryEventStore()
    auth = AuthorizationStateMachine(event_store=event_store)
    graph_store = NetworkXGraphStore()

    def clear_all() -> None:
        graph_store._graph.clear()
    graph_store.clear_all = clear_all  # type: ignore

    secrets = SecretsManager()
    http = FakeHttpClient()
    dumper = FakeGitDumper()
    return event_store, auth, graph_store, secrets, http, dumper


def test_git_exposure_runner_vuln_yields_proven_chain(fake_env: tuple[Any, ...]) -> None:
    event_store, auth, graph_store, secrets, http, dumper = fake_env

    # Setup Fake environment for vuln.git.lab
    config = GitExposureChainConfig(
        client_id="test-client",
        scope_ip_ranges=["127.0.0.1/32"],
        scope_domains=["vuln.git.lab"],
        scope_exclusions=[],
    )

    # Mock the HTTP response for /.git/config to trigger GitDumper
    http.responses["https://vuln.git.lab/.git/config"] = (
        200,
        textwrap.dedent(
            """
            [core]
                repositoryformatversion = 0
                filemode = true
                bare = false
            """
        ),
    )

    # Mock GitDumper returning a credential file
    dumper.dumps["https://vuln.git.lab/"] = {
        "config/database.yml": textwrap.dedent(
            """
            host: localhost
            username: db_user
            password: SuperSecretPassword123
            database: app_prod
            """
        )
    }

    results = run_git_exposure_chain_live_fire(
        config,
        auth=auth,
        http_client=http,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets,
        dumper=dumper,
    )

    assert "vuln.git.lab" in results
    res = results["vuln.git.lab"]
    assert res.leak_creds_added > 0
    assert res.edge_from_harvested_cred is True
    assert res.chain_proven is True


def test_git_exposure_runner_hardened_yields_zero_creds(fake_env: tuple[Any, ...]) -> None:
    event_store, auth, graph_store, secrets, http, dumper = fake_env

    config = GitExposureChainConfig(
        client_id="test-client",
        scope_ip_ranges=["127.0.0.1/32"],
        scope_domains=["hardened.git.lab"],
        scope_exclusions=[],
    )

    # Hardened returns 404 for .git/config
    http.responses["https://hardened.git.lab/.git/config"] = (404, "Not Found")

    results = run_git_exposure_chain_live_fire(
        config,
        auth=auth,
        http_client=http,
        graph_store=graph_store,
        event_store=event_store,
        secrets_manager=secrets,
        dumper=dumper,
    )

    assert "hardened.git.lab" in results
    res = results["hardened.git.lab"]
    assert res.leak_creds_added == 0
    assert res.edge_from_harvested_cred is False
    assert res.chain_proven is False
