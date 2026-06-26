"""Contract: the monologue WebSocket endpoint — auth boundary + real-time delivery.

Seals the Phase-2 "streamed to user in real time" criterion at the USER edge. The
transport behind it is proven in test_monologue_pubsub (real Redis); this pins the
FastAPI endpoint itself: a bad/missing token is rejected, and an authorized tenant
receives the frames published to ITS channel — and only its channel.

RED until (a) main.py mounts the router (app.include_router(monologue_router)) and
(b) routes_monologue exposes a `subscriber_factory` seam this test can override.
Mirrors test_api_auth.py's token/TestClient pattern.
"""

from __future__ import annotations

import json
import os
import typing

import pytest

os.environ.setdefault(
    "AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-at-least-32-bytes!!"
)

jwt = pytest.importorskip("jwt")
pytest.importorskip("fastapi.testclient")

from fastapi import WebSocketDisconnect  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from agent_alpha.agents.monologue_stream import channel_for  # noqa: E402
from agent_alpha.conductor import routes_monologue  # noqa: E402
from agent_alpha.conductor.main import app  # noqa: E402

_SECRET = os.environ["AGENT_ALPHA_JWT_SECRET"]
client = TestClient(app)


def _token(tenant_id: str, sub: str = "tester") -> str:
    return jwt.encode({"tenant_id": tenant_id, "sub": sub}, _SECRET, algorithm="HS256")


def _frame_json(engagement_id: str, message: str) -> str:
    return json.dumps(
        {
            "engagement_id": engagement_id,
            "agent": "alpha",
            "phase": "ACT",
            "message": message,
            "timestamp_utc": "2026-06-26T00:00:00Z",
            "reasoning": "",
        }
    )


class _FakeSubscriber:
    def __init__(self, by_channel: dict[str, list[str]]) -> None:
        self._by_channel = by_channel

    def listen(self, channel: str) -> typing.Iterator[str]:
        yield from self._by_channel.get(channel, [])


def test_ws_rejects_missing_token() -> None:
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/engagements/eng_1/monologue/ws") as ws:
            ws.receive_json()


def test_ws_rejects_invalid_token() -> None:
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            "/engagements/eng_1/monologue/ws?token=not-a-jwt"
        ) as ws:
            ws.receive_json()


def test_ws_delivers_frames_to_authorized_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSubscriber(
        {
            channel_for("t1", "eng_1"): [
                _frame_json("eng_1", "probing target"),
                _frame_json("eng_1", "laravel debug exposure confirmed"),
            ]
        }
    )
    monkeypatch.setattr(routes_monologue, "subscriber_factory", lambda: fake)

    with client.websocket_connect(
        f"/engagements/eng_1/monologue/ws?token={_token('t1')}"
    ) as ws:
        first = ws.receive_json()
        second = ws.receive_json()

    assert first["message"] == "probing target"
    assert second["message"] == "laravel debug exposure confirmed"


def test_ws_other_tenant_receives_no_frames(monkeypatch: pytest.MonkeyPatch) -> None:
    # Frames exist ONLY on t1's channel. A t2 token subscribes to t2's channel,
    # finds nothing, and the server closes — no cross-tenant leak.
    fake = _FakeSubscriber(
        {channel_for("t1", "eng_1"): [_frame_json("eng_1", "t1-only secret op")]}
    )
    monkeypatch.setattr(routes_monologue, "subscriber_factory", lambda: fake)

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            f"/engagements/eng_1/monologue/ws?token={_token('t2')}"
        ) as ws:
            ws.receive_json()
