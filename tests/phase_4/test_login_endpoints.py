"""Slice-B read-model: login endpoint resolution (HTTPS-only) from api_endpoint intel."""

from __future__ import annotations

from agent_alpha.events.event_types import EventType
from agent_alpha.events.store import InMemoryEventStore
from agent_alpha.recon.login_endpoints import (
    first_non_login_api_endpoint,
    login_endpoint_candidates,
)

_HOST = "app.example.com"


def _seed(store: InMemoryEventStore, host: str, *eps: str) -> None:
    for ep in eps:
        store.append(
            EventType.NODE_DISCOVERED,
            "e",
            "alpha",
            {"type": "api_endpoint", "host": host, "endpoint": ep},
        )


def test_filters_to_login_paths_only() -> None:
    s = InMemoryEventStore()
    _seed(s, _HOST, "/api/v1/auth/login", "/api/products", "/graphql")
    assert login_endpoint_candidates(s.get_events("e"), _HOST) == (
        "https://app.example.com/api/v1/auth/login",
    )


def test_ranks_more_specific_first() -> None:
    s = InMemoryEventStore()
    _seed(s, _HOST, "/login", "/api/auth/login", "/signin")
    assert (
        login_endpoint_candidates(s.get_events("e"), _HOST)[0]
        == "https://app.example.com/api/auth/login"
    )


def test_http_endpoint_is_upgraded_to_https() -> None:
    """CodeRabbit #2: an http:// login endpoint must be returned as https (no cleartext)."""
    s = InMemoryEventStore()
    _seed(s, _HOST, "http://app.example.com/api/auth/login")
    r = login_endpoint_candidates(s.get_events("e"), _HOST)
    assert r == ("https://app.example.com/api/auth/login",)
    assert all(u.startswith("https://") for u in r)


def test_forgot_password_and_substring_not_matched() -> None:
    s = InMemoryEventStore()
    _seed(s, _HOST, "/api/forgot-password", "/api/bloglogin-widget")
    assert login_endpoint_candidates(s.get_events("e"), _HOST) == ()


def test_cross_host_dropped() -> None:
    s = InMemoryEventStore()
    _seed(s, _HOST, "https://evil.other.com/login")
    assert login_endpoint_candidates(s.get_events("e"), _HOST) == ()


def test_no_endpoint_fail_closed() -> None:
    s = InMemoryEventStore()
    _seed(s, _HOST, "/api/products")
    assert login_endpoint_candidates(s.get_events("e"), _HOST) == ()


def test_protected_oracle_is_non_login_https() -> None:
    s = InMemoryEventStore()
    _seed(s, _HOST, "/api/auth/login", "http://app.example.com/api/me")
    assert (
        first_non_login_api_endpoint(s.get_events("e"), _HOST) == "https://app.example.com/api/me"
    )
