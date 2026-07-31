"""Unit tests for origin_resolver — subdomain DNS diffing pipeline.

No real network I/O: crt.sh is injected via FakeHttpClient,
DNS is mocked, origin probe uses a fake.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from unittest.mock import patch

from agent_alpha.recon.origin_resolver import (
    _probe_as_origin,
    discover_origin_ips,
)


@dataclass
class _FakeResp:
    status_code: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class _FakeHttp:
    def __init__(self, text: str) -> None:
        self._text = text

    def get(self, url: str, **_: object) -> _FakeResp:
        return _FakeResp(200, self._text)


def _crtsh_json(names: list[str]) -> str:
    return json.dumps([{"name_value": n} for n in names])


class _OkAuth:
    def can_agent_proceed(self, agent_id: object, engagement_id: str) -> bool:
        return True

    def is_in_scope(self, engagement_id: str, domain: str) -> bool:
        return True


class _DenyAuth:
    def can_agent_proceed(self, agent_id: object, engagement_id: str) -> bool:
        return False

    def is_in_scope(self, engagement_id: str, domain: str) -> bool:
        return True


class _OutOfScopeAuth:
    def can_agent_proceed(self, agent_id: object, engagement_id: str) -> bool:
        return True

    def is_in_scope(self, engagement_id: str, domain: str) -> bool:
        return False


def test_discover_returns_empty_when_no_subdomains() -> None:
    """crt.sh with no results → [] (anti-#3: not a finding)."""
    http = _FakeHttp("[]")
    result = discover_origin_ips("eng-1", "bernofarm.com", http, _OkAuth())
    assert result == []


def test_discover_filters_cf_ips() -> None:
    """Subdomains resolving to CF IPs are filtered out."""
    # 172.66.166.211 is CF (172.64.0.0/13) — should be excluded
    http = _FakeHttp(_crtsh_json(["mail.example.com"]))
    with patch(
        "agent_alpha.recon.origin_resolver._resolve_ipv4",
        return_value=["172.66.166.211"],
    ):
        result = discover_origin_ips("eng-1", "example.com", http, _OkAuth())
    assert result == []


def test_discover_confirms_non_cf_origin() -> None:
    """Non-CF IP that passes origin probe is returned."""
    http = _FakeHttp(_crtsh_json(["mail.example.com"]))

    def fake_probe(ip: str, host: str) -> bool:
        return ip == "198.51.100.42"  # non-CF test IP

    with (
        patch("agent_alpha.recon.origin_resolver._resolve_ipv4", return_value=["198.51.100.42"]),
        patch("agent_alpha.recon.origin_resolver._probe_as_origin", side_effect=fake_probe),
    ):
        result = discover_origin_ips("eng-1", "example.com", http, _OkAuth())
    assert result == ["198.51.100.42"]


def test_discover_crtsh_failure_returns_empty() -> None:
    """crt.sh fetch exception → [] (anti-#3: no crash, honest result)."""
    class _BrokenHttp:
        def get(self, *_: object, **__: object) -> None:
            from agent_alpha.agents.http_client import HttpClientError
            raise HttpClientError("network unreachable")

    result = discover_origin_ips("eng-1", "example.com", _BrokenHttp(), _OkAuth())
    assert result == []


def test_probe_rejects_cloudflare_server_header() -> None:
    """IP returning server:cloudflare is NOT a real origin."""
    from agent_alpha.recon.reach_transport import OriginDirectResult
    fake_result = OriginDirectResult(
        status_code=200,
        body="...",
        headers={"server": "cloudflare"},
    )
    with patch(
        "agent_alpha.recon.origin_resolver.origin_direct_fetch",
        return_value=fake_result,
    ):
        assert _probe_as_origin("104.20.17.247", "bernofarm.com") is False


def test_probe_confirms_real_origin_200() -> None:
    """IP returning 200 without cloudflare header = confirmed origin."""
    from agent_alpha.recon.reach_transport import OriginDirectResult
    fake_result = OriginDirectResult(
        status_code=200,
        body="<html>real site</html>",
        headers={"server": "nginx"},
    )
    with patch(
        "agent_alpha.recon.origin_resolver.origin_direct_fetch",
        return_value=fake_result,
    ):
        assert _probe_as_origin("198.51.100.42", "example.com") is True


def test_discover_blocked_when_recon_not_enabled() -> None:
    http = _FakeHttp(_crtsh_json(["sub.example.com"]))
    assert discover_origin_ips("eng-1", "example.com", http, _DenyAuth()) == []


def test_discover_blocked_when_domain_out_of_scope() -> None:
    http = _FakeHttp(_crtsh_json(["sub.example.com"]))
    assert discover_origin_ips("eng-1", "example.com", http, _OutOfScopeAuth()) == []


def test_discover_negative_max_candidates_returns_empty() -> None:
    http = _FakeHttp(_crtsh_json(["sub.example.com"]))
    assert discover_origin_ips("eng-1", "example.com", http, _OkAuth(), max_probe_candidates=-1) == []


def test_max_probe_candidates_bounds_probes() -> None:
    """max_probe_candidates caps how many IPs are probed (anti-#5)."""
    http = _FakeHttp(_crtsh_json([f"sub{i}.example.com" for i in range(20)]))

    def unique_resolve(hostname: str) -> list[str]:
        idx = hostname.replace("sub", "").split(".")[0]
        return [f"198.51.100.{int(idx) + 1}"]

    with (
        patch(
            "agent_alpha.recon.origin_resolver._resolve_ipv4",
            side_effect=unique_resolve,
        ),
        patch(
            "agent_alpha.recon.origin_resolver._probe_as_origin",
            return_value=True,
        ) as mock_probe,
    ):
        res = discover_origin_ips("eng-1", "example.com", http, _OkAuth(), max_probe_candidates=3)

    assert len(res) == 3
    assert mock_probe.call_count == 3
