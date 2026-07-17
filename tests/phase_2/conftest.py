"""Phase 2 shared fixtures.

All fixtures are hermetic (no live network) EXCEPT those explicitly marked
`live`, which hit api.deepseek.com and skip when DEEPSEEK_API_KEY is absent.

Canonical Phase 0/1 types are imported directly — Phase 2 must never
re-declare a concept that already exists (anti-Lyndon #6).
"""

from __future__ import annotations

import dataclasses
import os

import pytest

from agent_alpha.a2a import a2a_pb2
from agent_alpha.conductor.authorization import AuthorizationStateMachine, Scope
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.graph.networkx_store import NetworkXGraphStore


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "live: hits live DeepSeek API; needs DEEPSEEK_API_KEY")


# ── Canned HTTP responses (no live network) ───────────────────────────


@dataclasses.dataclass(frozen=True)
class FakeHttpResponse:
    """Minimal response contract Alpha consumes. The real HttpClient
    Protocol lives in agent_alpha/agents/base.py and must match this shape."""

    status_code: int
    text: str
    headers: dict[str, str]
    url: str


# A Laravel app with APP_DEBUG=true renders the "Whoops" page on an
# unhandled exception, leaking the stack trace + env. This is the single
# detectable signal the first playbook keys on.
LARAVEL_DEBUG_BODY = (
    "<!DOCTYPE html><html><head><title>Whoops! There was an error.</title></head>"
    "<body><div class='exception'>Illuminate\\Database\\QueryException</div>"
    "<div>SQLSTATE[HY000] [1045] Access refused for user 'forge'@'localhost'</div>"
    "<table><tr><td>APP_ENV</td><td>production</td></tr>"
    "<tr><td>APP_DEBUG</td><td>true</td></tr>"
    "<tr><td>DB_PASSWORD</td><td>s3cr3t-leaked</td></tr></table>"
    "<footer>Laravel v10.3.1 (PHP v8.2.4)</footer></body></html>"
)

# A hardened target: same probe, no debug leak, generic 500.
HARDENED_BODY = "<html><body><h1>Server Error</h1></body></html>"


class FakeHttpClient:
    """Deterministic HttpClient double. Maps url -> FakeHttpResponse.

    `calls` records every requested URL so tests can assert Alpha actually
    *read* the target rather than fabricating a conclusion (anti-Lyndon #3).
    """

    def __init__(self, routes: dict[str, FakeHttpResponse]) -> None:
        self._routes = routes
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 10.0) -> FakeHttpResponse:
        self.calls.append(url)
        try:
            return self._routes[url]
        except KeyError:
            return FakeHttpResponse(status_code=404, text="", headers={}, url=url)


@pytest.fixture
def laravel_target_url() -> str:
    return "https://lab-target.invalid/trigger-error"


@pytest.fixture
def hardened_target_url() -> str:
    return "https://hardened.invalid/trigger-error"


@pytest.fixture
def http_client(laravel_target_url: str, hardened_target_url: str) -> FakeHttpClient:
    return FakeHttpClient(
        {
            laravel_target_url: FakeHttpResponse(
                status_code=500,
                text=LARAVEL_DEBUG_BODY,
                headers={"server": "nginx", "x-powered-by": "PHP/8.2.4"},
                url=laravel_target_url,
            ),
            hardened_target_url: FakeHttpResponse(
                status_code=500,
                text=HARDENED_BODY,
                headers={"server": "nginx"},
                url=hardened_target_url,
            ),
        }
    )


# ── Phase 0/1 wiring an Alpha needs to run ────────────────────────────


@pytest.fixture
def event_store() -> InMemoryEventStore:
    return InMemoryEventStore()


@pytest.fixture
def graph_store() -> NetworkXGraphStore:
    return NetworkXGraphStore()


@pytest.fixture
def recon_engagement(event_store: InMemoryEventStore):
    """An engagement legally cleared to RECON_ONLY — the minimum auth state
    in which Alpha may proceed (authorization.can_agent_proceed(ALPHA, ...))."""
    auth = AuthorizationStateMachine(event_store=event_store)
    record = auth.create_engagement(client_id="client_lab", target="lab-target.invalid")
    auth.enable_recon(
        record.engagement_id,
        Scope(
            ip_ranges=["10.0.0.0/30"],
            # nothing-here.invalid is IN scope but returns 404/empty — it exercises
            # the "authorized but unreachable -> FAILED" path. Out-of-scope hosts
            # (e.g. out-of-scope.invalid) are a separate concern -> BLOCKED.
            domains=["lab-target.invalid", "hardened.invalid", "nothing-here.invalid"],
            exclusions=[],
        ),
    )
    assert auth.get_state(record.engagement_id) == a2a_pb2.RECON_ONLY
    assert auth.can_agent_proceed(a2a_pb2.ALPHA, record.engagement_id) is True
    return auth, record.engagement_id


@pytest.fixture
def deepseek_api_key() -> str:
    key = os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        pytest.skip("DEEPSEEK_API_KEY not set — live DeepSeek tier skipped (NOT passed)")
    return key
