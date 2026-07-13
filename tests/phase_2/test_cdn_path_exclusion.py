"""Contract: CDN-infrastructure paths are excluded from frontier crawl.

Cloudflare and other CDNs inject /cdn-cgi/* paths that link to each other indefinitely,
causing a crawl loop that burns DeepSeek reasoning tokens for zero recon value.
This filter fires BEFORE scope/dedup check to prevent the loop.

Run on Oracle ARM64 only:
    .venv312/bin/python3 -m pytest tests/phase_2/test_cdn_path_exclusion.py -v
"""

from __future__ import annotations

from unittest.mock import MagicMock

from agent_alpha.agents.alpha.scout import Alpha


class _MockAuthorization:
    """Mock authorization that always returns in_scope=True for testing."""

    def __init__(self) -> None:
        self.engagement_id = "test_engagement"

    def is_in_scope(self, engagement_id: str, host: str) -> bool:
        return True


def test_cdn_email_protection_path_is_excluded() -> None:
    """CDN /cdn-cgi/l/email-protection paths are never enqueued."""
    auth = _MockAuthorization()
    graph_store = MagicMock()
    event_store = MagicMock()
    http_client = MagicMock()
    orchestrator = MagicMock()
    secrets_manager = MagicMock()

    agent = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    agent._engagement_id = "test_engagement"

    # CDN path should be ignored
    agent.enqueue_discovered_url("https://target.tld/cdn-cgi/l/email-protection#abc123")
    assert len(agent._work_queue) == 0
    assert "cdn-cgi" not in str(agent._work_queue)


def test_cdn_content_path_is_excluded() -> None:
    """CDN /cdn-cgi/content paths are never enqueued."""
    auth = _MockAuthorization()
    graph_store = MagicMock()
    event_store = MagicMock()
    http_client = MagicMock()
    orchestrator = MagicMock()
    secrets_manager = MagicMock()

    agent = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    agent._engagement_id = "test_engagement"

    # CDN content path should be ignored
    agent.enqueue_discovered_url("https://target.tld/cdn-cgi/content?id=test-123&version=1.2.3")
    assert len(agent._work_queue) == 0
    assert "cdn-cgi" not in str(agent._work_queue)


def test_normal_application_path_is_enqueued() -> None:
    """Normal application paths (not /cdn-cgi/*) are enqueued as before."""
    auth = _MockAuthorization()
    graph_store = MagicMock()
    event_store = MagicMock()
    http_client = MagicMock()
    orchestrator = MagicMock()
    secrets_manager = MagicMock()

    agent = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    agent._engagement_id = "test_engagement"

    # Normal path should be enqueued
    agent.enqueue_discovered_url("https://target.tld/research-and-development")
    assert len(agent._work_queue) == 1
    assert "research-and-development" in agent._work_queue[0]


def test_cdn_path_excluded_before_dedup() -> None:
    """CDN filter fires before dedup check, so duplicate CDN paths never hit queue."""
    auth = _MockAuthorization()
    graph_store = MagicMock()
    event_store = MagicMock()
    http_client = MagicMock()
    orchestrator = MagicMock()
    secrets_manager = MagicMock()

    agent = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    agent._engagement_id = "test_engagement"

    # Call twice on same CDN path — filter fires before dedup, queue stays empty
    agent.enqueue_discovered_url("https://target.tld/cdn-cgi/content?id=abc")
    agent.enqueue_discovered_url("https://target.tld/cdn-cgi/content?id=abc")
    assert len(agent._work_queue) == 0


def test_normal_path_dedup_still_works() -> None:
    """Dedup logic for normal (non-CDN) paths is preserved."""
    auth = _MockAuthorization()
    graph_store = MagicMock()
    event_store = MagicMock()
    http_client = MagicMock()
    orchestrator = MagicMock()
    secrets_manager = MagicMock()

    agent = Alpha(
        authorization=auth,
        graph_store=graph_store,
        event_store=event_store,
        orchestrator=orchestrator,
        http_client=http_client,
        secrets_manager=secrets_manager,
    )
    agent._engagement_id = "test_engagement"

    # Same normal path twice — dedup prevents duplicate
    agent.enqueue_discovered_url("https://target.tld/api/users")
    agent.enqueue_discovered_url("https://target.tld/api/users")
    assert len(agent._work_queue) == 1
    assert agent._work_queue[0] == "https://target.tld/api/users"
