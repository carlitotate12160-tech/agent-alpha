# agent_alpha/conductor/routes_monologue.py
"""WebSocket delivery of the inner monologue to the authorized user (real-time).

Kept OUT of main.py on purpose: main.py is the composition root, feature routes live
in their own modules (anti-Lyndon #8 — stop main.py becoming a god-module). Auth is
per-connection: the JWT tenant claim selects the channel, so a caller can only ever
read monologue:{their_tenant}:{engagement_id} — tenant isolation by construction.
"""

from __future__ import annotations

import dataclasses

import anyio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from typing import Annotated

from agent_alpha.agents.monologue_stream import stream_monologue
from agent_alpha.conductor.api_auth import principal_from_token, valid_engagement_id
from agent_alpha.conductor.monologue_transport import build_monologue_subscriber

router = APIRouter()

# Seam for testing: override this to inject a fake subscriber.
subscriber_factory = build_monologue_subscriber


@router.websocket("/engagements/{engagement_id}/monologue/ws")
async def monologue_ws(websocket: WebSocket, engagement_id: Annotated[str, Depends(valid_engagement_id)]) -> None:
    # Browsers can't set Authorization on a WS handshake → token via query param.
    try:
        principal = principal_from_token(websocket.query_params.get("token", ""))
    except Exception:
        await websocket.close(code=4401)  # unauthorized
        return

    await websocket.accept()
    frames = stream_monologue(subscriber_factory(), principal.tenant_id, engagement_id)
    try:
        while True:
            # listen() blocks on Redis → pull each frame OFF the event loop.
            frame = await anyio.to_thread.run_sync(lambda: next(frames, None))
            if frame is None:
                break
            await websocket.send_json(dataclasses.asdict(frame))
    except WebSocketDisconnect:
        return
