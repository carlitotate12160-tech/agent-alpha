# agent_alpha/conductor/monologue_transport.py
"""Operational Redis pub/sub adapters for inner-monologue delivery.

Implements the MonologuePublisher / MonologueSubscriber seams from
agent_alpha.agents.monologue_stream over redis-py, using the SAME broker URL as
Celery (AGENT_ALPHA_REDIS_URL — single source, anti-Lyndon #7). Verified on Oracle
against a live Redis (the hermetic suite tests the core logic with fakes instead).

ASYNC NOTE: `RedisSubscriber.listen()` is a BLOCKING generator. The WebSocket
endpoint must drain it off the event loop (anyio.to_thread / run_in_executor) or
switch to redis.asyncio — never block FastAPI's loop. See main.py.
"""

from __future__ import annotations

import os
import typing

import redis

_REDIS_URL = os.environ.get("AGENT_ALPHA_REDIS_URL", "redis://localhost:6379/0")


class RedisPublisher:
    """Publishes a payload to a channel (worker side)."""

    def __init__(self, client: redis.Redis) -> None:
        self._client = client

    def publish(self, channel: str, payload: str) -> None:
        self._client.publish(channel, payload)


class RedisSubscriber:
    """Yields payloads published to a channel, in arrival order (API side)."""

    def __init__(self, client: redis.Redis) -> None:
        self._client = client

    def listen(self, channel: str) -> typing.Iterator[str]:
        pubsub = self._client.pubsub()
        pubsub.subscribe(channel)
        try:
            for message in pubsub.listen():
                if message.get("type") != "message":  # skip the 'subscribe' ack
                    continue
                data = message["data"]
                yield data.decode() if isinstance(data, bytes) else str(data)
        finally:
            pubsub.close()


def build_monologue_publisher(url: str = _REDIS_URL) -> RedisPublisher:
    return RedisPublisher(redis.Redis.from_url(url))


def build_monologue_subscriber(url: str = _REDIS_URL) -> RedisSubscriber:
    return RedisSubscriber(redis.Redis.from_url(url))
