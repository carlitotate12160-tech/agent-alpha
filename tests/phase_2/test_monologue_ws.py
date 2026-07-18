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

os.environ.setdefault("AGENT_ALPHA_JWT_SECRET", "test-frontdoor-secret-at-least-32-bytes!!")

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
        with client.websocket_connect("/engagements/eng_1234/monologue/ws") as ws:
            ws.receive_json()


def test_ws_rejects_invalid_token() -> None:
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/engagements/eng_1234/monologue/ws?token=not-a-jwt") as ws:
            ws.receive_json()


def test_ws_delivers_frames_to_authorized_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeSubscriber(
        {
            channel_for("t1", "eng_1234"): [
                _frame_json("eng_1234", "probing target"),
                _frame_json("eng_1234", "laravel debug exposure confirmed"),
            ]
        }
    )
    monkeypatch.setattr(routes_monologue, "subscriber_factory", lambda: fake)

    with client.websocket_connect(f"/engagements/eng_1234/monologue/ws?token={_token('t1')}") as ws:
        first = ws.receive_json()
        second = ws.receive_json()

    assert first["message"] == "probing target"
    assert second["message"] == "laravel debug exposure confirmed"


def test_ws_subscribes_to_callers_tenant_channel_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # BOTH tenants have a frame queued. A t2 token must receive ONLY its own channel
    # (monologue:t2:eng_1234) and NEVER t1's — proving the endpoint keys the channel on
    # the caller's JWT tenant (the isolation mechanism). Receiving its own frame keeps
    # the test deterministic (no dependency on server-close timing — that path blocks
    # legitimately in prod, where a live stream stays open waiting for frames).
    fake = _FakeSubscriber(
        {
            channel_for("t1", "eng_1234"): [_frame_json("eng_1234", "TENANT-ONE-SECRET")],
            channel_for("t2", "eng_1234"): [_frame_json("eng_1234", "tenant-two-own-frame")],
        }
    )
    monkeypatch.setattr(routes_monologue, "subscriber_factory", lambda: fake)

    with client.websocket_connect(f"/engagements/eng_1234/monologue/ws?token={_token('t2')}") as ws:
        got = ws.receive_json()

    assert got["message"] == "tenant-two-own-frame"  # got its OWN tenant's frame
    assert "TENANT-ONE-SECRET" not in json.dumps(got)  # never the other tenant's
